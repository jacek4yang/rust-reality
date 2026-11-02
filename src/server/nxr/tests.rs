use std::{io, net::Ipv4Addr, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time,
};

use super::{NxrAuthenticator, NxrLandingHandler, NxrReplayCache, NxrReplayError};
use crate::{
    protocol::{
        nxr::{NxrKey, encode_request},
        vless::{Address, Destination},
    },
    transport::tcp_relay::{TcpRelay, TcpRelayConfig},
};

#[test]
fn replay_cache_is_bounded_and_expires_monotonically() {
    let cache =
        NxrReplayCache::new(1, Duration::from_millis(100)).expect("cache policy must compile");
    let now = std::time::Instant::now();
    cache
        .reserve_at([1; 16], now)
        .expect("first nonce must reserve");
    assert_eq!(
        cache.reserve_at([1; 16], now),
        Err(NxrReplayError::Duplicate)
    );
    assert_eq!(
        cache.reserve_at([2; 16], now),
        Err(NxrReplayError::Capacity)
    );
    cache
        .reserve_at([2; 16], now + Duration::from_millis(101))
        .expect("expired nonce must release capacity");
    assert_eq!(cache.entry_count(), 1);
}

#[test]
fn authenticator_rejects_nonce_reuse_before_returning_destination() {
    let key = NxrKey::new([0x11; 32]);
    let cache = NxrReplayCache::new(8, Duration::from_secs(60)).expect("cache policy must compile");
    let authenticator = NxrAuthenticator::new(key.clone(), cache, 5);
    let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);
    let mut request = Vec::new();
    encode_request(&destination, 100, [0x22; 16], &key, &mut request).expect("request must encode");

    assert_eq!(
        authenticator
            .authenticate(&request, 100)
            .expect("first request must authenticate"),
        destination
    );
    assert!(authenticator.authenticate(&request, 100).is_err());
}

#[tokio::test(start_paused = true)]
async fn first_byte_enters_short_deadline_without_reserving_replay() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("landing must bind");
    let address = listener.local_addr().expect("landing address");
    let cache = NxrReplayCache::new(8, Duration::from_secs(60)).expect("cache policy must compile");
    let mut handler = NxrLandingHandler::new(
        NxrAuthenticator::new(NxrKey::new([0x33; 32]), cache.clone(), 5),
        Duration::from_secs(1),
        Duration::from_secs(1),
        TcpRelay::new(
            TcpRelayConfig::for_test(),
            crate::transport::FdBudget::new(4_096),
        )
        .expect("relay policy must compile"),
        Duration::from_secs(1),
    );
    handler.pre_auth_idle_timeout = Duration::from_secs(60);
    let client = TcpStream::connect(address);
    let accepted = listener.accept();
    let (client, accepted) = tokio::join!(client, accepted);
    let mut client = client.expect("client must connect");
    let (server, _) = accepted.expect("landing must accept");
    let task = tokio::spawn(async move { handler.handle(server).await });

    client.write_all(b"N").await.expect("first byte");
    tokio::task::yield_now().await;
    time::advance(Duration::from_secs(1)).await;
    assert!(matches!(
        task.await.expect("handler must join"),
        Err(super::NxrLandingError::Timeout)
    ));
    assert_eq!(cache.entry_count(), 0, "slowloris must reserve no nonce");
}

#[tokio::test(start_paused = true)]
async fn valid_nxr_authenticates_across_the_pre_auth_idle_age_matrix() {
    let key = NxrKey::new([0x34; 32]);
    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 9);
    for (index, idle_age) in [0, 1, 5, 15, 30, 59].into_iter().enumerate() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("landing must bind");
        let address = listener.local_addr().expect("landing address");
        let cache =
            NxrReplayCache::new(8, Duration::from_secs(60)).expect("cache policy must compile");
        let handler = NxrLandingHandler::new(
            NxrAuthenticator::new(key.clone(), cache, 5),
            Duration::from_secs(1),
            Duration::from_secs(1),
            TcpRelay::new(
                TcpRelayConfig::for_test(),
                crate::transport::FdBudget::new(4_096),
            )
            .expect("relay policy must compile"),
            Duration::from_secs(1),
        );
        let client = TcpStream::connect(address);
        let accepted = listener.accept();
        let (client, accepted) = tokio::join!(client, accepted);
        let mut client = client.expect("client must connect");
        let (server, _) = accepted.expect("landing must accept");
        let mut nonce = [0x45; 16];
        nonce[0] = u8::try_from(index).expect("small matrix index");
        let mut request = Vec::new();
        encode_request(
            &destination,
            super::request::unix_seconds().expect("clock must be valid"),
            nonce,
            &key,
            &mut request,
        )
        .expect("request must encode");
        let task = tokio::spawn(async move { handler.handle(server).await });
        tokio::task::yield_now().await;
        time::advance(Duration::from_secs(idle_age)).await;
        assert!(
            !task.is_finished(),
            "valid NXR idle age {idle_age}s must remain accepted"
        );
        client.write_all(&request).await.expect("request write");
        assert!(matches!(
            task.await.expect("handler must join"),
            Err(super::NxrLandingError::Destination(_))
        ));
    }
}

#[tokio::test(start_paused = true)]
async fn unused_nxr_socket_expires_without_replay_state() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("landing must bind");
    let address = listener.local_addr().expect("landing address");
    let cache = NxrReplayCache::new(8, Duration::from_secs(60)).expect("cache policy must compile");
    let mut handler = NxrLandingHandler::new(
        NxrAuthenticator::new(NxrKey::new([0x36; 32]), cache.clone(), 5),
        Duration::from_secs(1),
        Duration::from_secs(1),
        TcpRelay::new(
            TcpRelayConfig::for_test(),
            crate::transport::FdBudget::new(4_096),
        )
        .expect("relay policy must compile"),
        Duration::from_secs(1),
    );
    handler.pre_auth_idle_timeout = Duration::from_secs(60);
    let client = TcpStream::connect(address);
    let accepted = listener.accept();
    let (_client, accepted) = tokio::join!(client, accepted);
    let (server, _) = accepted.expect("landing must accept");
    let task = tokio::spawn(async move { handler.handle(server).await });
    tokio::task::yield_now().await;
    time::advance(Duration::from_secs(60)).await;
    assert!(matches!(
        task.await.expect("handler must join"),
        Err(super::NxrLandingError::Timeout)
    ));
    assert_eq!(cache.entry_count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn replay_is_rejected_on_preestablished_nxr_sockets() {
    let landing_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("landing must bind");
    let landing_address = landing_listener.local_addr().expect("landing address");
    let key = NxrKey::new([0x35; 32]);
    let cache = NxrReplayCache::new(8, Duration::from_secs(60)).expect("cache policy must compile");
    let handler = NxrLandingHandler::new(
        NxrAuthenticator::new(key.clone(), cache, 5),
        Duration::from_secs(1),
        Duration::from_secs(1),
        TcpRelay::new(
            TcpRelayConfig::for_test(),
            crate::transport::FdBudget::new(4_096),
        )
        .expect("relay policy must compile"),
        Duration::from_secs(1),
    );
    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 9);
    let mut request = Vec::new();
    encode_request(
        &destination,
        super::request::unix_seconds().expect("clock must be valid"),
        [0x47; 16],
        &key,
        &mut request,
    )
    .expect("request must encode");

    let landing = async {
        let (first, _) = landing_listener.accept().await?;
        let (second, _) = landing_listener.accept().await?;
        let first_handler = handler.clone();
        let (first, second) = tokio::join!(first_handler.handle(first), handler.handle(second));
        Ok::<_, io::Error>([first, second])
    };
    let line = async {
        let mut streams = [
            TcpStream::connect(landing_address).await?,
            TcpStream::connect(landing_address).await?,
        ];
        tokio::task::yield_now().await;
        for stream in &mut streams {
            stream.write_all(&request).await?;
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;
            assert!(response.is_empty(), "rejections stay silent");
        }
        Ok::<_, io::Error>(())
    };
    let (landing, line) = time::timeout(Duration::from_secs(3), async {
        tokio::join!(landing, line)
    })
    .await
    .expect("replay test must not stall");
    line.expect("line exchange must succeed");
    let outcomes = landing.expect("landing exchange must succeed");
    assert!(matches!(
        outcomes[0],
        Err(super::NxrLandingError::Destination(_))
    ));
    assert!(matches!(
        outcomes[1],
        Err(super::NxrLandingError::Authentication(
            super::NxrAuthenticationError::Replay(super::NxrReplayError::Duplicate)
        ))
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn landing_relays_raw_payload_and_preserves_half_close() {
    const REQUEST: &[u8] = b"request after auth";
    const RESPONSE: &[u8] = b"response after half-close";

    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("target must bind");
    let target_address = target_listener.local_addr().expect("target address");
    let landing_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("landing must bind");
    let landing_address = landing_listener.local_addr().expect("landing address");
    let key = NxrKey::new([0x33; 32]);
    let cache = NxrReplayCache::new(8, Duration::from_secs(60)).expect("cache policy must compile");
    let handler = NxrLandingHandler::new(
        NxrAuthenticator::new(key.clone(), cache, 5),
        Duration::from_secs(1),
        Duration::from_secs(1),
        TcpRelay::new(
            TcpRelayConfig::for_test(),
            crate::transport::FdBudget::new(4_096),
        )
        .expect("relay policy must compile"),
        Duration::from_secs(1),
    );
    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), target_address.port());
    let now = super::request::unix_seconds().expect("test clock must be valid");
    let mut authentication = Vec::new();
    encode_request(&destination, now, [0x44; 16], &key, &mut authentication)
        .expect("request must encode");

    let exchange = async {
        let landing = async {
            let (stream, _) = landing_listener.accept().await?;
            handler.handle(stream).await.map_err(io::Error::other)
        };
        let line = async {
            let mut stream = TcpStream::connect(landing_address).await?;
            stream.set_nodelay(true)?;
            stream.write_all(&authentication).await?;
            stream.write_all(REQUEST).await?;
            stream.shutdown().await?;
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;
            Ok::<_, io::Error>(response)
        };
        let target = async {
            let (mut stream, _) = target_listener.accept().await?;
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await?;
            stream.write_all(RESPONSE).await?;
            stream.shutdown().await?;
            Ok::<_, io::Error>(request)
        };
        tokio::join!(landing, line, target)
    };

    let (landing, line, target) = time::timeout(Duration::from_secs(3), exchange)
        .await
        .expect("NXR loopback must not time out");
    let stats = landing.expect("landing relay must succeed");
    assert_eq!(line.expect("line client must succeed"), RESPONSE);
    assert_eq!(target.expect("target must succeed"), REQUEST);
    assert_eq!(stats.inbound_to_outbound_bytes(), REQUEST.len() as u64);
    assert_eq!(stats.outbound_to_inbound_bytes(), RESPONSE.len() as u64);
}
