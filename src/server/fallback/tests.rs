use crate::config::node::network::NetworkConfig;
use crate::runtime::policy::{ResourceGovernorPolicy, WarmConnectionPolicy};
use std::{io, net::Ipv4Addr, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use super::{FallbackError, RealityFallback};
use crate::{
    network::NetworkEnvironment,
    protocol::reality::{ClientHello, SESSION_ID_LEN, X25519_GROUP, client_hello_fixtures},
    runtime::{PressureGauge, ResourceGovernor, ResourcePressure},
    server::warm_pool::WarmPoolAuthority,
    transport::{FdBudget, TcpRelay, TcpRelayConfig},
};

const PREFIX: &[u8] = b"exact-fragmented-client-hello-prefix";
const SUFFIX: &[u8] = b"bytes-read-after-fallback-connect";
const RESPONSE: &[u8] = b"cover-response";

fn test_fallback(target: String, config: &ResourceGovernorPolicy) -> RealityFallback {
    let relay = TcpRelay::new(TcpRelayConfig::for_test(), FdBudget::new(4_096))
        .expect("test relay must build");
    RealityFallback::new(target, ResourceGovernor::new(config), config, relay)
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_mirror_consumes_preestablished_socket_byte_exactly() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("cover listener must bind");
    let target = listener
        .local_addr()
        .expect("cover address must exist")
        .to_string();
    let resource = ResourceGovernorPolicy::default();
    let warm = WarmConnectionPolicy {
        min_ready: 1,
        max_ready: 2,
        max_connecting: 1,
        refill_batch: 1,
        idle_timeout_ms: 1_000,
        max_lifetime_ms: 2_000,
        shrink_delay_ms: 1_000,
    };
    let relay = TcpRelay::new(TcpRelayConfig::for_test(), FdBudget::new(64))
        .expect("test relay must build");
    let pressure = PressureGauge::new();
    let fallback = RealityFallback::with_warm_pool(
        target,
        ResourceGovernor::new(&resource),
        &resource,
        relay,
        &NetworkConfig::default(),
        NetworkEnvironment::detect(),
        31,
        WarmPoolAuthority::new(&warm, 1, pressure),
        &warm,
    );
    fallback.activate();
    let (mut cover, _) = timeout(Duration::from_secs(1), listener.accept())
        .await
        .expect("pool warmup must remain bounded")
        .expect("cover must accept the pre-established TCP socket");
    timeout(Duration::from_secs(1), async {
        while fallback
            .warm_pool_snapshot()
            .is_none_or(|snapshot| snapshot.ready != 1)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("pre-established socket must become ready");

    let mirror = fallback
        .mirror(PREFIX)
        .await
        .expect("authenticated mirror must check out the warm socket");
    let mut observed = vec![0_u8; PREFIX.len()];
    cover
        .read_exact(&mut observed)
        .await
        .expect("exact ClientHello prefix must reach the cover");
    assert_eq!(observed, PREFIX);
    let snapshot = fallback
        .warm_pool_snapshot()
        .expect("warm pool must be configured");
    assert_eq!(snapshot.generation, 31);
    assert_eq!(snapshot.checkout_total, 1);
    assert_eq!(snapshot.checkout_hit, 1);
    assert_eq!(snapshot.checkout_miss, 0);
    assert_eq!(snapshot.in_use, 1);
    assert_eq!(snapshot.cold_fallback, 0);

    drop(mirror);
    fallback.deactivate();
    assert_eq!(
        fallback
            .warm_pool_snapshot()
            .expect("warm pool must be configured")
            .in_use,
        0
    );
}

#[tokio::test(flavor = "current_thread")]
async fn resource_pressure_discards_speculative_socket_before_cold_fallback() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("cover listener must bind");
    let target = listener
        .local_addr()
        .expect("cover address must exist")
        .to_string();
    let resource = ResourceGovernorPolicy::default();
    let warm = WarmConnectionPolicy {
        min_ready: 1,
        max_ready: 1,
        max_connecting: 1,
        refill_batch: 1,
        idle_timeout_ms: 1_000,
        max_lifetime_ms: 2_000,
        shrink_delay_ms: 1_000,
    };
    let relay = TcpRelay::new(TcpRelayConfig::for_test(), FdBudget::new(64))
        .expect("test relay must build");
    let pressure = PressureGauge::new();
    let fallback = RealityFallback::with_warm_pool(
        target,
        ResourceGovernor::new(&resource),
        &resource,
        relay,
        &NetworkConfig::default(),
        NetworkEnvironment::detect(),
        32,
        WarmPoolAuthority::new(&warm, 1, pressure.clone()),
        &warm,
    );
    fallback.activate();
    let (stale, _) = timeout(Duration::from_secs(1), listener.accept())
        .await
        .expect("pool warmup must remain bounded")
        .expect("cover must accept the pre-established socket");
    timeout(Duration::from_secs(1), async {
        while fallback
            .warm_pool_snapshot()
            .is_none_or(|snapshot| snapshot.ready != 1)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("pre-established socket must become ready");
    pressure.set(ResourcePressure::Pressure);
    timeout(Duration::from_secs(1), async {
        while fallback
            .warm_pool_snapshot()
            .is_some_and(|snapshot| snapshot.ready != 0)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("pressure must promptly yield speculative descriptor capacity");

    let (mirror, cold_cover, observed) = timeout(Duration::from_secs(2), async {
        let mirror = fallback
            .mirror(PREFIX)
            .await
            .expect("cold fallback must recover the cover transaction");
        let (mut cover, _) = listener.accept().await?;
        let mut observed = vec![0_u8; PREFIX.len()];
        cover.read_exact(&mut observed).await?;
        Ok::<_, io::Error>((mirror, cover, observed))
    })
    .await
    .expect("pressure fallback must remain bounded")
    .expect("cold cover must receive the prefix");
    assert_eq!(observed, PREFIX);
    let snapshot = fallback
        .warm_pool_snapshot()
        .expect("warm pool must be configured");
    assert_eq!(snapshot.stale_discard, 0);
    assert!(snapshot.checkout_miss >= 1);
    assert_eq!(snapshot.cold_fallback, 1);

    drop((mirror, cold_cover, stale));
    fallback.deactivate();
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("pair listener must bind");
    let client = TcpStream::connect(listener.local_addr().expect("pair address must exist"))
        .await
        .expect("pair client must connect");
    let (server, _) = listener.accept().await.expect("pair must accept");
    (client, server)
}

#[tokio::test(flavor = "current_thread")]
async fn forwards_consumed_prefix_byte_exactly_before_live_bytes() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("cover listener must bind");
    let target = listener
        .local_addr()
        .expect("cover listener address must exist")
        .to_string();
    let config = ResourceGovernorPolicy::default();
    let fallback = test_fallback(target, &config);
    let (mut client, inbound) = tcp_pair().await;

    let exchange = async {
        let fallback_io = fallback.relay(inbound, PREFIX);
        let client_io = async {
            client.write_all(SUFFIX).await?;
            client.shutdown().await?;
            let mut response = Vec::new();
            client.read_to_end(&mut response).await?;
            Ok::<_, io::Error>(response)
        };
        let cover_io = async {
            let (mut cover, _) = listener.accept().await?;
            let mut request = Vec::new();
            cover.read_to_end(&mut request).await?;
            cover.write_all(RESPONSE).await?;
            cover.shutdown().await?;
            Ok::<_, io::Error>(request)
        };
        tokio::join!(fallback_io, client_io, cover_io)
    };
    let (fallback_result, client_result, cover_result) = timeout(Duration::from_secs(2), exchange)
        .await
        .expect("fallback exchange must finish");

    let stats = fallback_result.expect("fallback must succeed");
    let response = client_result.expect("client I/O must succeed");
    let request = cover_result.expect("cover I/O must succeed");
    let mut expected = PREFIX.to_vec();
    expected.extend_from_slice(SUFFIX);
    assert_eq!(request, expected);
    assert_eq!(response, RESPONSE);
    assert_eq!(stats.forwarded_prefix_bytes(), PREFIX.len() as u64);
    assert_eq!(stats.returned_prefix_bytes(), 0);
    assert_eq!(
        stats.relay().inbound_to_outbound_bytes(),
        SUFFIX.len() as u64
    );
    assert_eq!(
        stats.relay().outbound_to_inbound_bytes(),
        RESPONSE.len() as u64
    );
}

#[tokio::test(flavor = "current_thread")]
async fn coalesced_flight_prefix_rejoins_its_unread_body_byte_exactly() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("cover listener must bind");
    let target = listener
        .local_addr()
        .expect("cover listener address must exist")
        .to_string();
    let config = ResourceGovernorPolicy::default();
    let fallback = test_fallback(target, &config);
    let client_hello = client_hello();
    let mut target_flight = target_server_hello_record();
    target_flight.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
    target_flight.extend_from_slice(&opaque_record(23, 600, 0xa5));
    let minimum_inspected_prefix_len = target_server_hello_record().len() + 6 + 6;
    let (mut client, inbound) = tcp_pair().await;

    let exchange = async {
        let fallback_io = async {
            let mut connection = fallback
                .connect(PREFIX)
                .await
                .expect("cover connection must open");
            let flight = connection
                .read_server_flight(&client_hello, Duration::from_secs(1))
                .await
                .expect("coalesced cover flight must be classified");
            let (_, _, inspected_prefix) = flight.into_parts();
            assert!(target_flight.starts_with(&inspected_prefix));
            assert!(inspected_prefix.len() >= minimum_inspected_prefix_len);
            connection.relay(inbound, &inspected_prefix).await
        };
        let client_io = async {
            client.write_all(SUFFIX).await?;
            client.shutdown().await?;
            let mut response = Vec::new();
            client.read_to_end(&mut response).await?;
            Ok::<_, io::Error>(response)
        };
        let cover_io = async {
            let (mut cover, _) = listener.accept().await?;
            let mut prefix = vec![0_u8; PREFIX.len()];
            cover.read_exact(&mut prefix).await?;
            cover.write_all(&target_flight).await?;
            cover.write_all(RESPONSE).await?;
            let mut suffix = Vec::new();
            cover.read_to_end(&mut suffix).await?;
            cover.shutdown().await?;
            Ok::<_, io::Error>((prefix, suffix))
        };
        tokio::join!(fallback_io, client_io, cover_io)
    };
    let (fallback_result, client_result, cover_result) = timeout(Duration::from_secs(2), exchange)
        .await
        .expect("coalesced fallback exchange must finish");

    let stats = fallback_result.expect("same cover connection must relay");
    let response = client_result.expect("client I/O must succeed");
    let (prefix, suffix) = cover_result.expect("cover I/O must succeed");
    let mut expected_response = target_flight.clone();
    expected_response.extend_from_slice(RESPONSE);
    assert_eq!(prefix, PREFIX);
    assert_eq!(suffix, SUFFIX);
    assert_eq!(response, expected_response);
    assert!(
        stats.returned_prefix_bytes()
            >= u64::try_from(minimum_inspected_prefix_len)
                .expect("test prefix length must fit u64")
    );
    assert!(
        stats.returned_prefix_bytes()
            <= u64::try_from(target_flight.len()).expect("test flight length must fit u64")
    );
    assert_eq!(
        stats
            .returned_prefix_bytes()
            .checked_add(stats.relay().outbound_to_inbound_bytes())
            .expect("test byte count must not overflow"),
        u64::try_from(target_flight.len() + RESPONSE.len())
            .expect("test response length must fit u64")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn partial_positional_record_rejoins_after_shape_timeout() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("cover listener must bind");
    let target = listener
        .local_addr()
        .expect("cover listener address must exist")
        .to_string();
    let config = ResourceGovernorPolicy::default();
    let fallback = test_fallback(target, &config);
    let client_hello = client_hello();
    let mut initial = target_server_hello_record();
    initial.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
    initial.extend_from_slice(&opaque_record(23, 32, 0x11));
    let second = opaque_record(23, 64, 0x22);
    initial.extend_from_slice(&second[..8]);
    let mut remainder = second[8..].to_vec();
    remainder.extend_from_slice(&opaque_record(23, 48, 0x33));
    remainder.extend_from_slice(&opaque_record(23, 40, 0x44));
    let (mut client, inbound) = tcp_pair().await;

    let exchange = async {
        let fallback_io = async {
            let mut connection = fallback
                .connect(PREFIX)
                .await
                .expect("cover connection must open");
            let error = connection
                .read_server_flight(&client_hello, Duration::from_millis(10))
                .await
                .expect_err("partial positional record must time out");
            let (_, inspected_prefix) = error.into_parts();
            assert_eq!(inspected_prefix, initial);
            connection.relay(inbound, &inspected_prefix).await
        };
        let client_io = async {
            client.write_all(SUFFIX).await?;
            client.shutdown().await?;
            let mut response = Vec::new();
            client.read_to_end(&mut response).await?;
            Ok::<_, io::Error>(response)
        };
        let cover_io = async {
            let (mut cover, _) = listener.accept().await?;
            let mut prefix = vec![0_u8; PREFIX.len()];
            cover.read_exact(&mut prefix).await?;
            cover.write_all(&initial).await?;
            tokio::time::sleep(Duration::from_millis(30)).await;
            cover.write_all(&remainder).await?;
            cover.write_all(RESPONSE).await?;
            let mut suffix = Vec::new();
            cover.read_to_end(&mut suffix).await?;
            cover.shutdown().await?;
            Ok::<_, io::Error>((prefix, suffix))
        };
        tokio::join!(fallback_io, client_io, cover_io)
    };
    let (fallback_result, client_result, cover_result) = timeout(Duration::from_secs(2), exchange)
        .await
        .expect("partial positional fallback exchange must finish");

    let stats = fallback_result.expect("same cover connection must relay");
    let response = client_result.expect("client I/O must succeed");
    let (prefix, suffix) = cover_result.expect("cover I/O must succeed");
    let mut expected_response = initial.clone();
    expected_response.extend_from_slice(&remainder);
    expected_response.extend_from_slice(RESPONSE);
    assert_eq!(prefix, PREFIX);
    assert_eq!(suffix, SUFFIX);
    assert_eq!(response, expected_response);
    assert_eq!(stats.returned_prefix_bytes(), initial.len() as u64);
    assert_eq!(
        stats.relay().outbound_to_inbound_bytes(),
        (remainder.len() + RESPONSE.len()) as u64
    );
}

#[tokio::test(flavor = "current_thread")]
async fn inspected_target_response_can_rejoin_same_fallback_connection() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("cover listener must bind");
    let target = listener
        .local_addr()
        .expect("cover listener address must exist")
        .to_string();
    let config = ResourceGovernorPolicy::default();
    let fallback = test_fallback(target, &config);
    let client_hello = client_hello();
    let target_record = target_server_hello_record();
    let (mut client, inbound) = tcp_pair().await;

    let exchange = async {
        let fallback_io = async {
            let mut connection = fallback
                .connect(PREFIX)
                .await
                .expect("cover connection must open");
            let target_hello = connection
                .read_server_hello(&client_hello, Duration::from_secs(1))
                .await
                .expect("target ServerHello must be compatible");
            connection.relay(inbound, target_hello.wire_record()).await
        };
        let client_io = async {
            client.write_all(SUFFIX).await?;
            client.shutdown().await?;
            let mut response = Vec::new();
            client.read_to_end(&mut response).await?;
            Ok::<_, io::Error>(response)
        };
        let cover_io = async {
            let (mut cover, _) = listener.accept().await?;
            let mut prefix = vec![0_u8; PREFIX.len()];
            cover.read_exact(&mut prefix).await?;
            cover.write_all(&target_record).await?;
            let mut suffix = Vec::new();
            cover.read_to_end(&mut suffix).await?;
            cover.write_all(RESPONSE).await?;
            cover.shutdown().await?;
            Ok::<_, io::Error>((prefix, suffix))
        };
        tokio::join!(fallback_io, client_io, cover_io)
    };
    let (fallback_result, client_result, cover_result) = timeout(Duration::from_secs(2), exchange)
        .await
        .expect("inspected fallback exchange must finish");

    let stats = fallback_result.expect("same cover connection must relay");
    let response = client_result.expect("client I/O must succeed");
    let (prefix, suffix) = cover_result.expect("cover I/O must succeed");
    let mut expected_response = target_record.clone();
    expected_response.extend_from_slice(RESPONSE);
    assert_eq!(prefix, PREFIX);
    assert_eq!(suffix, SUFFIX);
    assert_eq!(response, expected_response);
    assert_eq!(stats.forwarded_prefix_bytes(), PREFIX.len() as u64);
    assert_eq!(stats.returned_prefix_bytes(), target_record.len() as u64);
    assert_eq!(
        stats.relay().inbound_to_outbound_bytes(),
        SUFFIX.len() as u64
    );
    assert_eq!(
        stats.relay().outbound_to_inbound_bytes(),
        RESPONSE.len() as u64
    );
}

#[tokio::test(flavor = "current_thread")]
async fn timeout_releases_fallback_admission_permit() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("cover listener must bind");
    let mut config = ResourceGovernorPolicy {
        max_fallbacks: 1,
        fallback_timeout_ms: 10,
        ..ResourceGovernorPolicy::default()
    };
    config.connect_timeout_ms = 100;
    let fallback = test_fallback(
        listener
            .local_addr()
            .expect("cover listener address must exist")
            .to_string(),
        &config,
    );

    for _ in 0..2 {
        let (_client, inbound) = tcp_pair().await;
        assert!(matches!(
            fallback.relay(inbound, &[]).await,
            Err(FallbackError::SessionTimeout)
        ));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn refused_cover_target_fails_closed_and_releases_capacity() {
    // Reserve a port and drop the listener so cover connects are refused.
    let refused_target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("probe listener must bind")
        .local_addr()
        .expect("probe address must exist")
        .to_string();
    let config = ResourceGovernorPolicy::default();
    let fallback = test_fallback(refused_target, &config);

    // Two attempts: the second proves the refused first attempt released
    // its fallback admission permit instead of leaking capacity.
    for _ in 0..2 {
        let (_client, inbound) = tcp_pair().await;
        let error = fallback
            .relay(inbound, PREFIX)
            .await
            .expect_err("a refused cover target must fail the fallback");
        match error {
            FallbackError::Io(error) => assert_eq!(
                error.kind(),
                io::ErrorKind::ConnectionRefused,
                "a refused cover target must surface the connect refusal"
            ),
            other => panic!("expected a fallback I/O error, got {other}"),
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn target_mirror_acquires_fallback_capacity_only_when_relaying() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("cover listener must bind");
    let config = ResourceGovernorPolicy {
        max_fallbacks: 0,
        ..ResourceGovernorPolicy::default()
    };
    let fallback = test_fallback(
        listener
            .local_addr()
            .expect("cover listener address must exist")
            .to_string(),
        &config,
    );

    let connection = fallback
        .mirror(PREFIX)
        .await
        .expect("short target mirror must not consume fallback capacity");
    let (mut cover, _) = listener.accept().await.expect("mirror must connect");
    let mut received = vec![0_u8; PREFIX.len()];
    cover
        .read_exact(&mut received)
        .await
        .expect("mirror prefix must arrive");
    assert_eq!(received, PREFIX);

    let (_client, inbound) = tcp_pair().await;
    assert!(matches!(
        connection.relay(inbound, &[]).await,
        Err(FallbackError::Admission(_))
    ));
}

fn client_hello() -> ClientHello {
    ClientHello::parse_message(&client_hello_fixtures::client_hello_with_key_share(
        [0x44; 32],
        &[0x11; SESSION_ID_LEN],
        "www.example.com",
        &[b"h2"],
        X25519_GROUP,
        &[0x22; 32],
    ))
    .expect("test ClientHello must parse")
}

fn target_server_hello_record() -> Vec<u8> {
    let mut extensions = Vec::new();
    push_extension(&mut extensions, 0x002b, &0x0304_u16.to_be_bytes());
    let mut key_share = Vec::new();
    key_share.extend_from_slice(&X25519_GROUP.to_be_bytes());
    key_share.extend_from_slice(&32_u16.to_be_bytes());
    key_share.extend_from_slice(&[0x55; 32]);
    push_extension(&mut extensions, 0x0033, &key_share);

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303_u16.to_be_bytes());
    body.extend_from_slice(&[0x33; 32]);
    body.push(u8::try_from(SESSION_ID_LEN).expect("test session ID must fit"));
    body.extend_from_slice(&[0x11; SESSION_ID_LEN]);
    body.extend_from_slice(&0x1301_u16.to_be_bytes());
    body.push(0);
    body.extend_from_slice(
        &u16::try_from(extensions.len())
            .expect("test extensions must fit")
            .to_be_bytes(),
    );
    body.extend_from_slice(&extensions);

    let mut message = vec![2];
    let message_len = u32::try_from(body.len()).expect("test ServerHello body must fit");
    message.extend_from_slice(&message_len.to_be_bytes()[1..]);
    message.extend_from_slice(&body);

    let mut record = vec![22, 3, 3];
    record.extend_from_slice(
        &u16::try_from(message.len())
            .expect("test record must fit")
            .to_be_bytes(),
    );
    record.extend_from_slice(&message);
    record
}

fn opaque_record(content_type: u8, body_len: usize, fill: u8) -> Vec<u8> {
    let mut record = vec![content_type, 3, 3];
    record.extend_from_slice(
        &u16::try_from(body_len)
            .expect("test record body must fit")
            .to_be_bytes(),
    );
    record.resize(5 + body_len, fill);
    record
}

fn push_extension(output: &mut Vec<u8>, extension_type: u16, value: &[u8]) {
    output.extend_from_slice(&extension_type.to_be_bytes());
    output.extend_from_slice(
        &u16::try_from(value.len())
            .expect("test extension must fit")
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
}
