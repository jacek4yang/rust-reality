use std::{
    collections::BTreeMap,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::mpsc,
};

use super::{
    BUILTIN_OUTBOUND_COUNT, OutboundConnectError, OutboundConnectOutcome, OutboundIndex,
    OutboundRegistry, SOCKS_CONNECT, SOCKS_NO_AUTH, SOCKS_USERNAME_PASSWORD, SOCKS_VERSION,
    SORTED_OUTBOUND_LIMIT, Socks5ProtocolError,
};
use crate::{
    config::node::network::NetworkConfig,
    config::{
        SecretString,
        node::outbound::{NxrOutboundConfig, OutboundConfig, Socks5Config},
    },
    network::NetworkEnvironment,
    protocol::{
        nxr::{NxrKey, REQUEST_HEADER_LEN, decode_authenticated_request, request_len_from_header},
        vless::{Address, Destination},
    },
    runtime::policy::{DirectBarrierPolicy, WarmConnectionPolicy},
    runtime::{AdmissionDenied, DirectBarrier, PressureGauge, ResourcePressure},
    server::warm_pool::WarmPoolAuthority,
    transport::FdBudget,
};

#[test]
fn outbound_index_uses_the_measured_cardinality_boundary() {
    let socks = |_index: usize| {
        OutboundConfig::Socks5(Socks5Config {
            address: "10.0.0.1".to_owned(),
            port: 1080,
            username: None,
            password: None,
            warm_tcp: Some(false),
        })
    };
    let _ = &socks;
    // Names are zero-padded so the sorted map order matches the numeric
    // order the assertions below read.
    let configs: BTreeMap<String, OutboundConfig> = (0..=SORTED_OUTBOUND_LIMIT)
        .map(|index| (format!("socks-{index:03}"), socks(index)))
        .collect();
    let connector = super::DestinationConnector::new(Duration::from_secs(1));
    let fd_budget = FdBudget::new(4_096);
    let small = OutboundIndex::from_config(
        &configs
            .iter()
            .take(SORTED_OUTBOUND_LIMIT - BUILTIN_OUTBOUND_COUNT)
            .map(|(name, outbound)| (name.clone(), outbound.clone()))
            .collect(),
        &connector,
        &fd_budget,
        None,
    );
    assert!(matches!(small, OutboundIndex::Sorted(_)));
    assert!(small.contains("socks-001"));
    assert!(!small.contains("missing"));

    let large = OutboundIndex::from_config(&configs, &connector, &fd_budget, None);
    assert!(matches!(large, OutboundIndex::Hashed(_)));
    assert!(large.contains("socks-004"));
}

/// Builds the declared section from one named outbound.
fn named(name: &str, outbound: OutboundConfig) -> BTreeMap<String, OutboundConfig> {
    BTreeMap::from([(name.to_owned(), outbound)])
}

fn direct_registry(barrier: &DirectBarrier, connect_timeout: Duration) -> OutboundRegistry {
    OutboundRegistry::with_barrier(
        &BTreeMap::new(),
        barrier.clone(),
        connect_timeout,
        crate::transport::FdBudget::new(4_096),
    )
}

fn warm_policy() -> WarmConnectionPolicy {
    WarmConnectionPolicy {
        min_ready: 1,
        max_ready: 4,
        max_connecting: 1,
        refill_batch: 1,
        idle_timeout_ms: 30_000,
        max_lifetime_ms: 60_000,
        shrink_delay_ms: 30_000,
    }
}

async fn wait_for_one_ready(registry: &OutboundRegistry) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if registry
                .warm_pool_snapshots()
                .first()
                .is_some_and(|snapshot| snapshot.pool.ready == 1)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("warm pool must become ready");
}

async fn serve_one_no_auth_socks_connect(listener: &TcpListener) -> io::Result<()> {
    for _ in 0..4 {
        let (mut stream, _) = listener.accept().await?;
        let mut greeting = [0_u8; 3];
        match tokio::time::timeout(Duration::from_millis(100), stream.read_exact(&mut greeting))
            .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        }
        if greeting != [SOCKS_VERSION, 1, SOCKS_NO_AUTH] {
            return Err(io::Error::other("unexpected SOCKS greeting"));
        }
        stream.write_all(&[SOCKS_VERSION, SOCKS_NO_AUTH]).await?;
        let mut request = [0_u8; 10];
        stream.read_exact(&mut request).await?;
        if request[..4] != [SOCKS_VERSION, SOCKS_CONNECT, 0, 1] {
            return Err(io::Error::other("unexpected SOCKS CONNECT request"));
        }
        stream
            .write_all(&[SOCKS_VERSION, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .await?;
        return Ok(());
    }
    Err(io::Error::other(
        "SOCKS protocol did not begin on a bounded candidate",
    ))
}

#[tokio::test(flavor = "current_thread")]
async fn warm_nxr_sends_no_protocol_bytes_before_checkout_and_uses_fresh_nonce() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("NXR landing must bind");
    let address = listener.local_addr().expect("NXR landing address");
    let key_bytes = [0x62; 32];
    let key = NxrKey::new(key_bytes);
    let (accepted_tx, mut accepted_rx) = mpsc::channel(2);
    let server = tokio::spawn(async move {
        let mut nonces = Vec::new();
        for expected_payload in [b"one".as_slice(), b"two".as_slice()] {
            let (mut stream, _) = listener.accept().await?;
            let mut probe = [0_u8; 1];
            assert!(
                matches!(stream.try_read(&mut probe), Err(ref error) if error.kind() == io::ErrorKind::WouldBlock)
            );
            accepted_tx.send(()).await.map_err(io::Error::other)?;
            let mut header = [0_u8; REQUEST_HEADER_LEN];
            stream.read_exact(&mut header).await?;
            let total = request_len_from_header(&header).map_err(io::Error::other)?;
            let mut request = vec![0_u8; total];
            request[..REQUEST_HEADER_LEN].copy_from_slice(&header);
            stream
                .read_exact(&mut request[REQUEST_HEADER_LEN..])
                .await?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_secs();
            let authenticated =
                decode_authenticated_request(&request, &key, now, 30).map_err(io::Error::other)?;
            nonces.push(*authenticated.nonce());
            let mut payload = vec![0_u8; expected_payload.len()];
            stream.read_exact(&mut payload).await?;
            assert_eq!(payload, expected_payload);
        }
        Ok::<_, io::Error>(nonces)
    });

    let policy = warm_policy();
    let pressure = PressureGauge::new();
    let fd_budget = FdBudget::new(4_096);
    let registry = OutboundRegistry::with_warm_pools(
        &named(
            "nxr",
            OutboundConfig::Nxr(NxrOutboundConfig {
                address: address.ip().to_string(),
                port: address.port(),
                psk: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(key_bytes)),
                warm_tcp: Some(true),
            }),
        ),
        DirectBarrier::new(&DirectBarrierPolicy::default()),
        Duration::from_secs(2),
        fd_budget,
        &NetworkConfig::default(),
        NetworkEnvironment::detect(),
        7,
        WarmPoolAuthority::new(&policy, 1, pressure),
        &policy,
    );
    registry.activate_warm_pools();
    let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);
    for payload in [b"one".as_slice(), b"two".as_slice()] {
        accepted_rx
            .recv()
            .await
            .expect("warm dial must reach landing");
        wait_for_one_ready(&registry).await;
        let OutboundConnectOutcome::Connected(connection) = registry
            .connect("nxr", &destination)
            .await
            .expect("warm NXR checkout must connect")
        else {
            panic!("NXR cannot blackhole");
        };
        let (mut stream, permit) = connection.into_parts();
        stream.write_all(payload).await.expect("raw payload");
        drop(stream);
        drop(permit);
    }
    registry.deactivate_warm_pools();
    let nonces = server
        .await
        .expect("server must join")
        .expect("server result");
    assert_ne!(nonces[0], nonces[1], "every warm flow needs a fresh nonce");
    let snapshot = registry.warm_pool_snapshots().remove(0).pool;
    assert_eq!(snapshot.checkout_hit, 2);
    assert_eq!(snapshot.cold_fallback, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn stale_warm_nxr_socket_is_discarded_before_cold_fallback() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("NXR landing must bind");
    let address = listener.local_addr().expect("NXR landing address");
    let key_bytes = [0x63; 32];
    let policy = warm_policy();
    let registry = OutboundRegistry::with_warm_pools(
        &named(
            "nxr",
            OutboundConfig::Nxr(NxrOutboundConfig {
                address: address.ip().to_string(),
                port: address.port(),
                psk: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(key_bytes)),
                warm_tcp: Some(true),
            }),
        ),
        DirectBarrier::new(&DirectBarrierPolicy::default()),
        Duration::from_secs(2),
        FdBudget::new(4_096),
        &NetworkConfig::default(),
        NetworkEnvironment::detect(),
        8,
        WarmPoolAuthority::new(&policy, 1, PressureGauge::new()),
        &policy,
    );
    registry.activate_warm_pools();
    let (mut stale_peer, _) = listener.accept().await.expect("warm peer must connect");
    wait_for_one_ready(&registry).await;
    stale_peer
        .shutdown()
        .await
        .expect("peer FIN must be observable");
    drop(stale_peer);
    tokio::time::sleep(Duration::from_millis(10)).await;

    let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);
    let OutboundConnectOutcome::Connected(connection) = registry
        .connect("nxr", &destination)
        .await
        .expect("cold fallback must submit a fresh authenticated request")
    else {
        panic!("NXR cannot blackhole");
    };
    drop(connection);
    let snapshot = registry.warm_pool_snapshots().remove(0).pool;
    assert_eq!(snapshot.checkout_hit, 0);
    assert_eq!(snapshot.checkout_miss, 1);
    assert_eq!(snapshot.cold_fallback, 1);
    assert_eq!(snapshot.stale_discard, 1);
    registry.deactivate_warm_pools();
}

#[tokio::test(flavor = "current_thread")]
async fn warm_socks5_stays_protocol_unprivileged_until_checkout() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("SOCKS server must bind");
    let address = listener.local_addr().expect("SOCKS address");
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut probe = [0_u8; 1];
        assert!(
            matches!(stream.try_read(&mut probe), Err(ref error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        accepted_tx
            .send(())
            .map_err(|()| io::Error::other("receiver closed"))?;
        let mut greeting = [0_u8; 3];
        stream.read_exact(&mut greeting).await?;
        assert_eq!(greeting, [SOCKS_VERSION, 1, SOCKS_NO_AUTH]);
        stream.write_all(&[SOCKS_VERSION, SOCKS_NO_AUTH]).await?;
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await?;
        assert_eq!(request, [SOCKS_VERSION, SOCKS_CONNECT, 0, 3]);
        let mut length = [0_u8; 1];
        stream.read_exact(&mut length).await?;
        let mut domain = vec![0_u8; usize::from(length[0])];
        stream.read_exact(&mut domain).await?;
        assert_eq!(domain, b"example.com");
        let mut port = [0_u8; 2];
        stream.read_exact(&mut port).await?;
        assert_eq!(u16::from_be_bytes(port), 443);
        stream
            .write_all(&[SOCKS_VERSION, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .await?;
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"data");
        Ok::<_, io::Error>(())
    });

    let policy = warm_policy();
    let pressure = PressureGauge::new();
    let registry = OutboundRegistry::with_warm_pools(
        &named(
            "socks",
            OutboundConfig::Socks5(Socks5Config {
                address: address.ip().to_string(),
                port: address.port(),
                username: None,
                password: None,
                warm_tcp: Some(true),
            }),
        ),
        DirectBarrier::new(&DirectBarrierPolicy::default()),
        Duration::from_secs(2),
        FdBudget::new(4_096),
        &NetworkConfig::default(),
        NetworkEnvironment::detect(),
        9,
        WarmPoolAuthority::new(&policy, 1, pressure),
        &policy,
    );
    registry.activate_warm_pools();
    accepted_rx.await.expect("warm TCP must reach SOCKS server");
    wait_for_one_ready(&registry).await;
    let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);
    let OutboundConnectOutcome::Connected(connection) = registry
        .connect("socks", &destination)
        .await
        .expect("warm SOCKS checkout must negotiate")
    else {
        panic!("SOCKS cannot blackhole");
    };
    let (mut stream, permit) = connection.into_parts();
    stream.write_all(b"data").await.expect("relay payload");
    drop(stream);
    drop(permit);
    registry.deactivate_warm_pools();
    server
        .await
        .expect("server must join")
        .expect("server result");
    let snapshot = registry.warm_pool_snapshots().remove(0).pool;
    assert_eq!(snapshot.checkout_hit, 1);
    assert_eq!(snapshot.cold_fallback, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn socks5_upstream_close_while_ready_discards_then_cold_falls_back() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("SOCKS server must bind");
    let address = listener.local_addr().expect("SOCKS address");
    let policy = warm_policy();
    let registry = OutboundRegistry::with_warm_pools(
        &named(
            "socks",
            OutboundConfig::Socks5(Socks5Config {
                address: address.ip().to_string(),
                port: address.port(),
                username: None,
                password: None,
                warm_tcp: Some(true),
            }),
        ),
        DirectBarrier::new(&DirectBarrierPolicy::default()),
        Duration::from_secs(2),
        FdBudget::new(4_096),
        &NetworkConfig::default(),
        NetworkEnvironment::detect(),
        11,
        WarmPoolAuthority::new(&policy, 1, PressureGauge::new()),
        &policy,
    );
    registry.activate_warm_pools();
    let (mut stale_peer, _) = listener.accept().await.expect("warm peer must connect");
    wait_for_one_ready(&registry).await;
    stale_peer
        .shutdown()
        .await
        .expect("peer FIN must be observable");
    drop(stale_peer);
    tokio::time::sleep(Duration::from_millis(10)).await;
    let server = tokio::spawn(async move { serve_one_no_auth_socks_connect(&listener).await });

    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 443);
    let OutboundConnectOutcome::Connected(connection) = registry
        .connect("socks", &destination)
        .await
        .expect("cold SOCKS fallback must negotiate")
    else {
        panic!("SOCKS cannot blackhole");
    };
    drop(connection);
    let snapshot = registry.warm_pool_snapshots().remove(0).pool;
    assert_eq!(snapshot.checkout_hit, 0);
    assert_eq!(snapshot.checkout_miss, 1);
    assert_eq!(snapshot.cold_fallback, 1);
    assert_eq!(snapshot.stale_discard, 1);
    registry.deactivate_warm_pools();
    server
        .await
        .expect("SOCKS server must join")
        .expect("SOCKS server result");
}

#[tokio::test(flavor = "current_thread")]
async fn socks5_upstream_close_immediately_after_checkout_recovers_before_connect() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("SOCKS server must bind");
    let address = listener.local_addr().expect("SOCKS address");
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut checked_out, _) = listener.accept().await?;
        accepted_tx
            .send(())
            .map_err(|()| io::Error::other("receiver closed"))?;
        let mut greeting = [0_u8; 3];
        checked_out.read_exact(&mut greeting).await?;
        assert_eq!(greeting, [SOCKS_VERSION, 1, SOCKS_NO_AUTH]);
        drop(checked_out);
        serve_one_no_auth_socks_connect(&listener).await
    });
    let policy = warm_policy();
    let registry = OutboundRegistry::with_warm_pools(
        &named(
            "socks",
            OutboundConfig::Socks5(Socks5Config {
                address: address.ip().to_string(),
                port: address.port(),
                username: None,
                password: None,
                warm_tcp: Some(true),
            }),
        ),
        DirectBarrier::new(&DirectBarrierPolicy::default()),
        Duration::from_secs(2),
        FdBudget::new(4_096),
        &NetworkConfig::default(),
        NetworkEnvironment::detect(),
        12,
        WarmPoolAuthority::new(&policy, 1, PressureGauge::new()),
        &policy,
    );
    registry.activate_warm_pools();
    accepted_rx.await.expect("warm TCP must reach SOCKS server");
    wait_for_one_ready(&registry).await;

    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 443);
    let OutboundConnectOutcome::Connected(connection) = registry
        .connect("socks", &destination)
        .await
        .expect("bounded pre-CONNECT retry must recover")
    else {
        panic!("SOCKS cannot blackhole");
    };
    drop(connection);
    let snapshot = registry.warm_pool_snapshots().remove(0).pool;
    assert!(snapshot.checkout_hit >= 1);
    assert_eq!(snapshot.stale_discard, 1);
    assert!(snapshot.checkout_total <= 2);
    assert!(snapshot.cold_fallback <= 1);
    registry.deactivate_warm_pools();
    server
        .await
        .expect("SOCKS server must join")
        .expect("SOCKS server result");
}

#[tokio::test(flavor = "current_thread")]
async fn stalled_warm_socks_attempt_does_not_consume_retry_deadline() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("SOCKS server must bind");
    let address = listener.local_addr().expect("SOCKS address");
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stalled, _) = listener.accept().await?;
        accepted_tx
            .send(())
            .map_err(|()| io::Error::other("receiver closed"))?;
        let mut greeting = [0_u8; 3];
        stalled.read_exact(&mut greeting).await?;
        assert_eq!(greeting, [SOCKS_VERSION, 1, SOCKS_NO_AUTH]);

        // Keep the checked-out socket open without replying until its
        // per-attempt deadline fires. Refill may establish the one bounded
        // alternate in the listener backlog meanwhile.
        serve_one_no_auth_socks_connect(&listener).await?;
        drop(stalled);
        Ok::<_, io::Error>(())
    });
    let policy = warm_policy();
    let registry = OutboundRegistry::with_warm_pools(
        &named(
            "socks",
            OutboundConfig::Socks5(Socks5Config {
                address: address.ip().to_string(),
                port: address.port(),
                username: None,
                password: None,
                warm_tcp: Some(true),
            }),
        ),
        DirectBarrier::new(&DirectBarrierPolicy::default()),
        Duration::from_millis(25),
        FdBudget::new(4_096),
        &NetworkConfig::default(),
        NetworkEnvironment::detect(),
        13,
        WarmPoolAuthority::new(&policy, 1, PressureGauge::new()),
        &policy,
    );
    registry.activate_warm_pools();
    accepted_rx.await.expect("warm TCP must reach SOCKS server");
    wait_for_one_ready(&registry).await;

    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 443);
    let OutboundConnectOutcome::Connected(connection) = registry
        .connect("socks", &destination)
        .await
        .expect("bounded alternate must receive a fresh deadline")
    else {
        panic!("SOCKS cannot blackhole");
    };
    drop(connection);
    let snapshot = registry.warm_pool_snapshots().remove(0).pool;
    assert_eq!(snapshot.stale_discard, 1);
    assert!(snapshot.checkout_total <= 2);
    registry.deactivate_warm_pools();
    server
        .await
        .expect("SOCKS server must join")
        .expect("SOCKS server result");
}

#[tokio::test]
async fn socks5_connect_encodes_ipv4_ipv6_and_domain_destinations() {
    let destinations = [
        (
            Destination::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)), 443),
            vec![SOCKS_VERSION, SOCKS_CONNECT, 0, 1, 192, 0, 2, 1, 1, 187],
        ),
        (
            Destination::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 53),
            [
                vec![SOCKS_VERSION, SOCKS_CONNECT, 0, 4],
                vec![0; 15],
                vec![1, 0, 53],
            ]
            .concat(),
        ),
        (
            Destination::new(Address::Domain("example.com".to_owned()), 80),
            [
                vec![SOCKS_VERSION, SOCKS_CONNECT, 0, 3, 11],
                b"example.com".to_vec(),
                vec![0, 80],
            ]
            .concat(),
        ),
    ];
    for (destination, expected) in destinations {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("test listener must bind");
        let address = listener.local_addr().expect("test listener address");
        let writer = tokio::net::TcpStream::connect(address);
        let reader = listener.accept();
        let (writer, reader) = tokio::join!(writer, reader);
        let mut writer = writer.expect("writer must connect");
        let (mut reader, _) = reader.expect("reader must accept");
        super::write_connect_request(
            &mut writer,
            &destination,
            tokio::time::Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect("SOCKS CONNECT must encode");
        let mut actual = vec![0_u8; expected.len()];
        reader.read_exact(&mut actual).await.expect("encoded bytes");
        assert_eq!(actual, expected);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn warm_socks5_credentials_are_isolated_between_outbound_pools() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("SOCKS server must bind");
    let address = listener.local_addr().expect("SOCKS address");
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut streams = Vec::new();
        for _ in 0..2 {
            streams.push(listener.accept().await?.0);
        }
        accepted_tx
            .send(())
            .map_err(|()| io::Error::other("receiver closed"))?;
        let mut credentials = Vec::new();
        for mut stream in streams {
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await?;
            assert_eq!(greeting, [SOCKS_VERSION, 1, SOCKS_USERNAME_PASSWORD]);
            stream
                .write_all(&[SOCKS_VERSION, SOCKS_USERNAME_PASSWORD])
                .await?;

            let mut auth_header = [0_u8; 2];
            stream.read_exact(&mut auth_header).await?;
            assert_eq!(auth_header[0], 1);
            let mut username = vec![0_u8; usize::from(auth_header[1])];
            stream.read_exact(&mut username).await?;
            let mut password_length = [0_u8; 1];
            stream.read_exact(&mut password_length).await?;
            let mut password = vec![0_u8; usize::from(password_length[0])];
            stream.read_exact(&mut password).await?;
            credentials.push((username, password));
            stream.write_all(&[1, 0]).await?;

            let mut connect = [0_u8; 4];
            stream.read_exact(&mut connect).await?;
            assert_eq!(connect, [SOCKS_VERSION, SOCKS_CONNECT, 0, 1]);
            let mut destination = [0_u8; 6];
            stream.read_exact(&mut destination).await?;
            stream
                .write_all(&[SOCKS_VERSION, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await?;
        }
        credentials.sort();
        Ok::<_, io::Error>(credentials)
    });

    let policy = warm_policy();
    let registry = OutboundRegistry::with_warm_pools(
        &BTreeMap::from([
            (
                "socks-a".to_owned(),
                OutboundConfig::Socks5(Socks5Config {
                    address: address.ip().to_string(),
                    port: address.port(),
                    username: Some(SecretString::new("alice".to_owned())),
                    password: Some(SecretString::new("alpha".to_owned())),
                    warm_tcp: Some(true),
                }),
            ),
            (
                "socks-b".to_owned(),
                OutboundConfig::Socks5(Socks5Config {
                    address: address.ip().to_string(),
                    port: address.port(),
                    username: Some(SecretString::new("bob".to_owned())),
                    password: Some(SecretString::new("bravo".to_owned())),
                    warm_tcp: Some(true),
                }),
            ),
        ]),
        DirectBarrier::new(&DirectBarrierPolicy::default()),
        Duration::from_secs(2),
        FdBudget::new(4_096),
        &NetworkConfig::default(),
        NetworkEnvironment::detect(),
        10,
        WarmPoolAuthority::new(&policy, 2, PressureGauge::new()),
        &policy,
    );
    registry.activate_warm_pools();
    accepted_rx.await.expect("both warm sockets must connect");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if registry
                .warm_pool_snapshots()
                .iter()
                .all(|snapshot| snapshot.pool.ready == 1)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both pools must become ready");

    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 443);
    for tag in ["socks-a", "socks-b"] {
        let OutboundConnectOutcome::Connected(connection) = registry
            .connect(tag, &destination)
            .await
            .expect("isolated warm SOCKS connection")
        else {
            panic!("SOCKS cannot blackhole");
        };
        drop(connection);
    }
    registry.deactivate_warm_pools();
    let credentials = server
        .await
        .expect("server must join")
        .expect("server result");
    assert_eq!(
        credentials,
        vec![
            (b"alice".to_vec(), b"alpha".to_vec()),
            (b"bob".to_vec(), b"bravo".to_vec())
        ]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn outbound_descriptor_unit_is_exact_and_released_with_the_connection() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("target listener must bind");
    let address = listener.local_addr().expect("target address must exist");
    let budget = crate::transport::FdBudget::new(4_096);
    let registry = OutboundRegistry::new(
        &BTreeMap::new(),
        &DirectBarrierPolicy::default(),
        Duration::from_secs(1),
        budget.clone(),
    );
    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), address.port());
    let baseline = budget.in_use();

    let outcome = registry
        .connect("direct", &destination)
        .await
        .expect("connect must succeed");
    let OutboundConnectOutcome::Connected(connection) = outcome else {
        panic!("a direct route must connect");
    };
    let in_flight = budget.in_use() - baseline;
    assert_eq!(
        in_flight,
        u64::from(crate::transport::UNITS_OUTBOUND_SOCKET),
        "one outbound connection accounts exactly one descriptor"
    );
    let (_stream, permit) = connection.into_parts();
    drop(permit);
    assert_eq!(
        budget.in_use(),
        baseline,
        "dropping the connection permit returns the unit"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn outbound_connect_declines_when_the_descriptor_budget_is_exhausted() {
    let budget = crate::transport::FdBudget::new(4_096);
    let _reservation = budget
        .try_acquire(4_096)
        .expect("the whole budget must be acquirable for the test");
    let registry = OutboundRegistry::new(
        &BTreeMap::new(),
        &DirectBarrierPolicy::default(),
        Duration::from_secs(1),
        budget,
    );
    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 9);
    let error = registry
        .connect("direct", &destination)
        .await
        .expect_err("an exhausted budget must deny the outbound connect");
    assert!(
        matches!(error, super::OutboundConnectError::DescriptorBudget),
        "expected DescriptorBudget, got {error}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn negotiates_authenticated_socks5_domain_connect() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("SOCKS listener must bind");
    let address = listener.local_addr().expect("SOCKS address must exist");
    let registry = OutboundRegistry::new(
        &named(
            "socks",
            OutboundConfig::Socks5(Socks5Config {
                address: address.ip().to_string(),
                port: address.port(),
                username: Some(SecretString::new("user")),
                password: Some(SecretString::new("pass")),
                warm_tcp: Some(false),
            }),
        ),
        &DirectBarrierPolicy::default(),
        Duration::from_secs(1),
        crate::transport::FdBudget::new(4_096),
    );
    let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

    let proxy = async {
        let (mut stream, _) = listener.accept().await?;
        let mut greeting = [0_u8; 3];
        stream.read_exact(&mut greeting).await?;
        assert_eq!(greeting, [5, 1, 2]);
        stream.write_all(&[5, 2]).await?;
        let mut auth = [0_u8; 11];
        stream.read_exact(&mut auth).await?;
        assert_eq!(
            auth,
            [1, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's']
        );
        stream.write_all(&[1, 0]).await?;
        let mut connect = [0_u8; 18];
        stream.read_exact(&mut connect).await?;
        assert_eq!(&connect[..5], &[5, 1, 0, 3, 11]);
        assert_eq!(&connect[5..16], b"example.com");
        assert_eq!(&connect[16..], &443_u16.to_be_bytes());
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x12, 0x34])
            .await?;
        Ok::<_, std::io::Error>(())
    };
    let connect = registry.connect("socks", &destination);
    let (proxy_result, connect_result) = tokio::join!(proxy, connect);

    proxy_result.expect("SOCKS exchange must succeed");
    assert!(matches!(
        connect_result.expect("SOCKS connection must succeed"),
        OutboundConnectOutcome::Connected(_)
    ));
}

fn socks5_registry(
    address: std::net::SocketAddr,
    credentials: Option<(&str, &str)>,
    connect_timeout: Duration,
) -> OutboundRegistry {
    let (username, password) = match credentials {
        Some((username, password)) => (
            Some(SecretString::new(username)),
            Some(SecretString::new(password)),
        ),
        None => (None, None),
    };
    OutboundRegistry::new(
        &named(
            "socks",
            OutboundConfig::Socks5(Socks5Config {
                address: address.ip().to_string(),
                port: address.port(),
                username,
                password,
                warm_tcp: Some(false),
            }),
        ),
        &DirectBarrierPolicy::default(),
        connect_timeout,
        crate::transport::FdBudget::new(4_096),
    )
}

fn socks_protocol_error(error: OutboundConnectError) -> Socks5ProtocolError {
    match error {
        OutboundConnectError::SocksProtocol(error) => error,
        other => panic!("expected a SOCKS protocol error, got {other}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn socks5_method_rejection_maps_to_unexpected_method() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("SOCKS listener must bind");
    let address = listener.local_addr().expect("SOCKS address must exist");
    let registry = socks5_registry(address, None, Duration::from_secs(1));
    let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

    let proxy = async {
        let (mut stream, _) = listener.accept().await?;
        let mut greeting = [0_u8; 3];
        stream.read_exact(&mut greeting).await?;
        assert_eq!(greeting, [5, 1, 0]);
        // 0xFF: no acceptable authentication methods.
        stream.write_all(&[5, 0xff]).await?;
        Ok::<_, std::io::Error>(())
    };
    let connect = registry.connect("socks", &destination);
    let (proxy_result, connect_result) = tokio::join!(proxy, connect);

    proxy_result.expect("SOCKS exchange must succeed");
    assert_eq!(
        socks_protocol_error(connect_result.expect_err("a method rejection must fail the connect")),
        Socks5ProtocolError::UnexpectedMethod {
            expected: 0,
            received: 0xff,
        }
    );
}

#[tokio::test(flavor = "current_thread")]
async fn socks5_username_password_failure_maps_to_authentication_failed() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("SOCKS listener must bind");
    let address = listener.local_addr().expect("SOCKS address must exist");
    let registry = socks5_registry(address, Some(("user", "pass")), Duration::from_secs(1));
    let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

    let proxy = async {
        let (mut stream, _) = listener.accept().await?;
        let mut greeting = [0_u8; 3];
        stream.read_exact(&mut greeting).await?;
        assert_eq!(greeting, [5, 1, 2]);
        stream.write_all(&[5, 2]).await?;
        let mut auth = [0_u8; 11];
        stream.read_exact(&mut auth).await?;
        assert_eq!(
            auth,
            [1, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's']
        );
        // Status 1: the credentials were rejected.
        stream.write_all(&[1, 1]).await?;
        Ok::<_, std::io::Error>(())
    };
    let connect = registry.connect("socks", &destination);
    let (proxy_result, connect_result) = tokio::join!(proxy, connect);

    proxy_result.expect("SOCKS exchange must succeed");
    assert_eq!(
        socks_protocol_error(connect_result.expect_err("a rejected login must fail the connect")),
        Socks5ProtocolError::AuthenticationFailed(1)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn socks5_connect_failure_codes_map_to_connect_failed() {
    for code in [5_u8, 4_u8] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("SOCKS listener must bind");
        let address = listener.local_addr().expect("SOCKS address must exist");
        let registry = socks5_registry(address, None, Duration::from_secs(1));
        let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

        let proxy = async {
            let (mut stream, _) = listener.accept().await?;
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await?;
            stream.write_all(&[5, 0]).await?;
            let mut connect = [0_u8; 18];
            stream.read_exact(&mut connect).await?;
            // Failure codes: 0x05 connection refused, 0x04 host unreachable.
            stream
                .write_all(&[5, code, 0, 1, 127, 0, 0, 1, 0x12, 0x34])
                .await?;
            Ok::<_, std::io::Error>(())
        };
        let connect = registry.connect("socks", &destination);
        let (proxy_result, connect_result) = tokio::join!(proxy, connect);

        proxy_result.expect("SOCKS exchange must succeed");
        assert_eq!(
            socks_protocol_error(
                connect_result.expect_err("a failure reply code must fail the connect")
            ),
            Socks5ProtocolError::ConnectFailed(code),
            "reply code {code:#04x} must map to ConnectFailed"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn socks5_malformed_connect_replies_map_to_invalid_reply() {
    let garbage_headers: [[u8; 10]; 3] = [
        // Wrong SOCKS version in the reply header.
        [4, 0, 0, 1, 127, 0, 0, 1, 0x12, 0x34],
        // Non-zero reserved byte in the reply header.
        [5, 0, 1, 1, 127, 0, 0, 1, 0x12, 0x34],
        // Unknown address type in the reply header.
        [5, 0, 0, 9, 127, 0, 0, 1, 0x12, 0x34],
    ];
    for garbage in garbage_headers {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("SOCKS listener must bind");
        let address = listener.local_addr().expect("SOCKS address must exist");
        let registry = socks5_registry(address, None, Duration::from_secs(1));
        let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

        let proxy = async {
            let (mut stream, _) = listener.accept().await?;
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await?;
            stream.write_all(&[5, 0]).await?;
            let mut connect = [0_u8; 18];
            stream.read_exact(&mut connect).await?;
            stream.write_all(&garbage).await?;
            Ok::<_, std::io::Error>(())
        };
        let connect = registry.connect("socks", &destination);
        let (proxy_result, connect_result) = tokio::join!(proxy, connect);

        proxy_result.expect("SOCKS exchange must succeed");
        assert_eq!(
            socks_protocol_error(
                connect_result.expect_err("a malformed reply must fail the connect")
            ),
            Socks5ProtocolError::InvalidReply,
            "garbage reply {garbage:02x?} must map to InvalidReply"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn socks5_garbage_method_reply_maps_to_unexpected_method() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("SOCKS listener must bind");
    let address = listener.local_addr().expect("SOCKS address must exist");
    let registry = socks5_registry(address, None, Duration::from_secs(1));
    let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

    let proxy = async {
        let (mut stream, _) = listener.accept().await?;
        let mut greeting = [0_u8; 3];
        stream.read_exact(&mut greeting).await?;
        // Not a SOCKS5 method selection reply at all.
        stream.write_all(b"NO").await?;
        Ok::<_, std::io::Error>(())
    };
    let connect = registry.connect("socks", &destination);
    let (proxy_result, connect_result) = tokio::join!(proxy, connect);

    proxy_result.expect("SOCKS exchange must succeed");
    assert_eq!(
        socks_protocol_error(
            connect_result.expect_err("a garbage method reply must fail the connect")
        ),
        Socks5ProtocolError::UnexpectedMethod {
            expected: 0,
            received: b'O',
        }
    );
}

#[tokio::test(flavor = "current_thread")]
async fn socks5_truncated_reply_fails_instead_of_hanging() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("SOCKS listener must bind");
    let address = listener.local_addr().expect("SOCKS address must exist");
    let registry = socks5_registry(address, None, Duration::from_secs(1));
    let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

    let proxy = async {
        let (mut stream, _) = listener.accept().await?;
        let mut greeting = [0_u8; 3];
        stream.read_exact(&mut greeting).await?;
        stream.write_all(&[5, 0]).await?;
        let mut connect = [0_u8; 18];
        stream.read_exact(&mut connect).await?;
        // Half a reply header, then an abrupt close: the client must see an
        // I/O failure, not a panic or a hang.
        stream.write_all(&[5, 0]).await?;
        Ok::<_, std::io::Error>(())
    };
    let connect = registry.connect("socks", &destination);
    let (proxy_result, connect_result) = tokio::join!(proxy, connect);

    proxy_result.expect("SOCKS exchange must succeed");
    assert!(
        matches!(
            connect_result.expect_err("a truncated reply must fail the connect"),
            OutboundConnectError::SocksConnect(_)
        ),
        "a truncated reply must surface as a SOCKS connect I/O error"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn socks5_silent_server_fails_within_the_connect_timeout() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("SOCKS listener must bind");
    let address = listener.local_addr().expect("SOCKS address must exist");
    let registry = socks5_registry(address, None, Duration::from_millis(100));
    let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

    let proxy = async {
        let (mut stream, _) = listener.accept().await?;
        let mut greeting = [0_u8; 3];
        stream.read_exact(&mut greeting).await?;
        // Never answer: the client deadline must bound the wait.
        let mut byte = [0_u8; 1];
        let _ = stream.read(&mut byte).await;
        Ok::<_, std::io::Error>(())
    };
    let connect = registry.connect("socks", &destination);
    let (proxy_result, connect_result) = tokio::time::timeout(Duration::from_secs(2), async move {
        tokio::join!(proxy, connect)
    })
    .await
    .expect("a silent server must be bounded by the connect timeout");

    proxy_result.expect("SOCKS exchange must succeed");
    assert!(
        matches!(
            connect_result.expect_err("a silent server must fail the connect"),
            OutboundConnectError::SocksTimeout
        ),
        "a silent server must hit the SOCKS timeout"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn blackhole_never_opens_a_destination_stream() {
    let registry = OutboundRegistry::new(
        &BTreeMap::new(),
        &DirectBarrierPolicy::default(),
        Duration::from_secs(1),
        crate::transport::FdBudget::new(4_096),
    );
    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 9);

    assert!(matches!(
        registry
            .connect("block", &destination)
            .await
            .expect("blackhole route must complete"),
        OutboundConnectOutcome::Blocked
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn nxr_writes_one_authentication_request_then_raw_payload() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("NXR listener must bind");
    let address = listener.local_addr().expect("NXR address must exist");
    let key_bytes = [0x5a; 32];
    let registry = OutboundRegistry::new(
        &named(
            "landing",
            OutboundConfig::Nxr(NxrOutboundConfig {
                address: address.ip().to_string(),
                port: address.port(),
                psk: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(key_bytes)),
                warm_tcp: Some(false),
            }),
        ),
        &DirectBarrierPolicy::default(),
        Duration::from_secs(1),
        crate::transport::FdBudget::new(4_096),
    );
    let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

    let landing = async {
        let (mut stream, _) = listener.accept().await?;
        let mut header = [0_u8; REQUEST_HEADER_LEN];
        stream.read_exact(&mut header).await?;
        let total = request_len_from_header(&header).expect("header must be bounded");
        let mut request = Vec::with_capacity(total);
        request.extend_from_slice(&header);
        request.resize(total, 0);
        stream
            .read_exact(&mut request[REQUEST_HEADER_LEN..])
            .await?;
        let timestamp = u64::from_be_bytes(
            header[10..18]
                .try_into()
                .expect("timestamp field must be fixed"),
        );
        let authenticated =
            decode_authenticated_request(&request, &NxrKey::new(key_bytes), timestamp, 0)
                .expect("NXR request must authenticate");
        assert_eq!(authenticated.destination(), &destination);
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"ping");
        Ok::<_, std::io::Error>(())
    };
    let line = async {
        let outcome = registry
            .connect("landing", &destination)
            .await
            .expect("NXR outbound must connect");
        let OutboundConnectOutcome::Connected(connection) = outcome else {
            panic!("NXR route must connect");
        };
        let (mut stream, _permit) = connection.into_parts();
        stream.write_all(b"ping").await
    };
    let (landing_result, line_result) = tokio::join!(landing, line);

    landing_result.expect("landing exchange must succeed");
    line_result.expect("raw payload write must succeed");
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_dial_limit_denies_a_second_in_flight_dial() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("target listener must bind");
    let address = listener.local_addr().expect("target address must exist");
    let barrier = DirectBarrier::new(&DirectBarrierPolicy {
        max_concurrent: 1,
        max_per_second: 1_000,
    });
    // A permit held by another task is exactly the state of one dial in
    // flight; the second dial must be refused until it resolves.
    let in_flight = barrier
        .try_acquire()
        .expect("the first dial permit must be available");
    let registry = direct_registry(&barrier, Duration::from_secs(1));
    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), address.port());

    let error = registry
        .connect("direct", &destination)
        .await
        .expect_err("a dial at the concurrency ceiling must be denied");
    assert!(
        matches!(
            error,
            OutboundConnectError::Admission(AdmissionDenied::DirectConcurrency)
        ),
        "expected DirectConcurrency, got {error}"
    );

    drop(in_flight);
    assert!(
        matches!(
            registry
                .connect("direct", &destination)
                .await
                .expect("the dial must proceed once the in-flight dial resolves"),
            OutboundConnectOutcome::Connected(_)
        ),
        "a direct route must connect once capacity is free"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_completed_dial_releases_its_permit_while_the_session_stays_open() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("target listener must bind");
    let address = listener.local_addr().expect("target address must exist");
    let barrier = DirectBarrier::new(&DirectBarrierPolicy {
        max_concurrent: 1,
        max_per_second: 1_000,
    });
    let registry = direct_registry(&barrier, Duration::from_secs(1));
    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), address.port());

    let first = registry
        .connect("direct", &destination)
        .await
        .expect("the first dial must connect");
    let OutboundConnectOutcome::Connected(first) = first else {
        panic!("a direct route must connect");
    };

    // The dial resolved, so the concurrency permit is already free even
    // though the established session above is still open.
    let probe = barrier
        .try_acquire()
        .expect("a completed dial must not hold its barrier permit");
    drop(probe);
    assert!(
        matches!(
            registry
                .connect("direct", &destination)
                .await
                .expect("a second dial must fit under the barrier"),
            OutboundConnectOutcome::Connected(_)
        ),
        "an open session must not consume the dial concurrency limit"
    );

    // Drain the backlog so both sessions are fully accepted before close.
    let _accepted = listener.accept().await.expect("first peer must accept");
    let _accepted = listener.accept().await.expect("second peer must accept");
    drop(first);
}

#[tokio::test(flavor = "current_thread")]
async fn an_established_session_relays_while_the_concurrency_limit_is_exhausted() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("target listener must bind");
    let address = listener.local_addr().expect("target address must exist");
    let barrier = DirectBarrier::new(&DirectBarrierPolicy {
        max_concurrent: 1,
        max_per_second: 1_000,
    });
    let registry = direct_registry(&barrier, Duration::from_secs(1));
    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), address.port());

    let outcome = registry
        .connect("direct", &destination)
        .await
        .expect("the session dial must connect");
    let OutboundConnectOutcome::Connected(connection) = outcome else {
        panic!("a direct route must connect");
    };
    let (mut stream, session_permit) = connection.into_parts();
    // Exhaust the concurrency limit again, standing in for another dial in
    // flight: the established session must be unaffected either way.
    let _in_flight = barrier
        .try_acquire()
        .expect("the established session must not hold the concurrency permit");

    let echo = async {
        let (mut peer, _) = listener.accept().await?;
        let mut payload = [0_u8; 4];
        peer.read_exact(&mut payload).await?;
        peer.write_all(&payload).await
    };
    let exchange = async {
        stream.write_all(b"ping").await?;
        let mut echoed = [0_u8; 4];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(&echoed, b"ping");
        Ok::<_, std::io::Error>(())
    };
    let (echo_result, exchange_result) = tokio::join!(echo, exchange);
    echo_result.expect("echo peer must succeed");
    exchange_result.expect("the established session must still relay bytes");
    drop(session_permit);
}

#[tokio::test(flavor = "current_thread")]
async fn a_failed_dial_releases_its_permit() {
    // Reserve a port and drop the listener so connects are refused fast.
    let refused_port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("probe listener must bind")
        .local_addr()
        .expect("probe address must exist")
        .port();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("target listener must bind");
    let good_port = listener
        .local_addr()
        .expect("target address must exist")
        .port();
    let barrier = DirectBarrier::new(&DirectBarrierPolicy {
        max_concurrent: 1,
        max_per_second: 1_000,
    });
    let registry = direct_registry(&barrier, Duration::from_secs(1));

    let refused = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), refused_port);
    let error = registry
        .connect("direct", &refused)
        .await
        .expect_err("a refused destination must fail the dial");
    assert!(
        matches!(error, OutboundConnectError::Direct(_)),
        "expected a direct connect error, got {error}"
    );

    let good = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), good_port);
    assert!(
        matches!(
            registry
                .connect("direct", &good)
                .await
                .expect("the failed dial must have released its permit"),
            OutboundConnectOutcome::Connected(_)
        ),
        "a good dial must succeed after a failure under a barrier of one"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn the_rate_limit_applies_to_new_dials_after_a_permit_is_released() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("target listener must bind");
    let address = listener.local_addr().expect("target address must exist");
    let barrier = DirectBarrier::new(&DirectBarrierPolicy {
        max_concurrent: 8,
        max_per_second: 1,
    });
    let registry = direct_registry(&barrier, Duration::from_secs(1));
    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), address.port());

    assert!(
        matches!(
            registry
                .connect("direct", &destination)
                .await
                .expect("the first dial must connect"),
            OutboundConnectOutcome::Connected(_)
        ),
        "a direct route must connect"
    );
    // The first dial's concurrency permit is already released, so only the
    // rate gate can refuse an immediate second dial.
    let error = registry
        .connect("direct", &destination)
        .await
        .expect_err("the rate limit must deny an immediate second dial");
    assert!(
        matches!(
            error,
            OutboundConnectError::Admission(AdmissionDenied::DirectRate)
        ),
        "expected DirectRate, got {error}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn critical_pressure_blocks_new_dials_but_not_established_relays() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("target listener must bind");
    let address = listener.local_addr().expect("target address must exist");
    let gauge = crate::runtime::PressureGauge::new();
    let barrier = DirectBarrier::with_pressure(
        &DirectBarrierPolicy {
            max_concurrent: 4,
            max_per_second: 1_000,
        },
        gauge.clone(),
    );
    let registry = direct_registry(&barrier, Duration::from_secs(1));
    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), address.port());

    let outcome = registry
        .connect("direct", &destination)
        .await
        .expect("the session dial must connect under normal pressure");
    let OutboundConnectOutcome::Connected(connection) = outcome else {
        panic!("a direct route must connect");
    };
    let (mut stream, session_permit) = connection.into_parts();

    gauge.set(ResourcePressure::Critical);
    let error = registry
        .connect("direct", &destination)
        .await
        .expect_err("critical pressure must pause new dials");
    assert!(
        matches!(
            error,
            OutboundConnectError::Admission(AdmissionDenied::DirectPressure)
        ),
        "expected DirectPressure, got {error}"
    );

    let echo = async {
        let (mut peer, _) = listener.accept().await?;
        let mut payload = [0_u8; 4];
        peer.read_exact(&mut payload).await?;
        peer.write_all(&payload).await
    };
    let exchange = async {
        stream.write_all(b"ping").await?;
        let mut echoed = [0_u8; 4];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(&echoed, b"ping");
        Ok::<_, std::io::Error>(())
    };
    let (echo_result, exchange_result) = tokio::join!(echo, exchange);
    echo_result.expect("echo peer must succeed");
    exchange_result.expect("critical pressure must not interrupt an established relay");
    drop(session_permit);
}

#[tokio::test(flavor = "current_thread")]
async fn socks5_dials_never_consume_direct_barrier_permits() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("SOCKS listener must bind");
    let address = listener.local_addr().expect("SOCKS address must exist");
    let barrier = DirectBarrier::new(&DirectBarrierPolicy {
        max_concurrent: 1,
        max_per_second: 1,
    });
    // Fill the barrier completely: the one concurrency permit and the one
    // rate token. A SOCKS5 dial must not touch either.
    let _in_flight = barrier
        .try_acquire()
        .expect("the barrier must be fillable for the test");
    let registry = OutboundRegistry::with_barrier(
        &named(
            "socks",
            OutboundConfig::Socks5(Socks5Config {
                address: address.ip().to_string(),
                port: address.port(),
                username: None,
                password: None,
                warm_tcp: Some(false),
            }),
        ),
        barrier,
        Duration::from_secs(1),
        crate::transport::FdBudget::new(4_096),
    );
    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 443);

    let proxy = async {
        let (mut stream, _) = listener.accept().await?;
        let mut greeting = [0_u8; 3];
        stream.read_exact(&mut greeting).await?;
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).await?;
        let mut connect = [0_u8; 10];
        stream.read_exact(&mut connect).await?;
        assert_eq!(&connect[..8], &[5, 1, 0, 1, 127, 0, 0, 1]);
        assert_eq!(&connect[8..], &443_u16.to_be_bytes());
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x12, 0x34])
            .await?;
        Ok::<_, std::io::Error>(())
    };
    let connect = registry.connect("socks", &destination);
    let (proxy_result, connect_result) = tokio::join!(proxy, connect);

    proxy_result.expect("SOCKS exchange must succeed");
    assert!(
        matches!(
            connect_result.expect("a full barrier must not block a SOCKS5 dial"),
            OutboundConnectOutcome::Connected(_)
        ),
        "a SOCKS5 route must connect"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn nxr_dials_never_consume_direct_barrier_permits() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("NXR listener must bind");
    let address = listener.local_addr().expect("NXR address must exist");
    let key_bytes = [0x5a; 32];
    let barrier = DirectBarrier::new(&DirectBarrierPolicy {
        max_concurrent: 1,
        max_per_second: 1,
    });
    // Fill the barrier completely: the one concurrency permit and the one
    // rate token. An NXR dial must not touch either.
    let _in_flight = barrier
        .try_acquire()
        .expect("the barrier must be fillable for the test");
    let registry = OutboundRegistry::with_barrier(
        &named(
            "landing",
            OutboundConfig::Nxr(NxrOutboundConfig {
                address: address.ip().to_string(),
                port: address.port(),
                psk: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(key_bytes)),
                warm_tcp: Some(false),
            }),
        ),
        barrier,
        Duration::from_secs(1),
        crate::transport::FdBudget::new(4_096),
    );
    let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

    let landing = async {
        let (mut stream, _) = listener.accept().await?;
        let mut header = [0_u8; REQUEST_HEADER_LEN];
        stream.read_exact(&mut header).await?;
        let total = request_len_from_header(&header).expect("header must be bounded");
        let mut request = Vec::with_capacity(total);
        request.extend_from_slice(&header);
        request.resize(total, 0);
        stream
            .read_exact(&mut request[REQUEST_HEADER_LEN..])
            .await?;
        let timestamp = u64::from_be_bytes(
            header[10..18]
                .try_into()
                .expect("timestamp field must be fixed"),
        );
        let authenticated =
            decode_authenticated_request(&request, &NxrKey::new(key_bytes), timestamp, 0)
                .expect("NXR request must authenticate");
        assert_eq!(authenticated.destination(), &destination);
        Ok::<_, std::io::Error>(())
    };
    let connect = registry.connect("landing", &destination);
    let (landing_result, connect_result) = tokio::join!(landing, connect);

    landing_result.expect("landing exchange must succeed");
    assert!(
        matches!(
            connect_result.expect("a full barrier must not block an NXR dial"),
            OutboundConnectOutcome::Connected(_)
        ),
        "an NXR route must connect"
    );
}

fn nxr_landing_handler(key_bytes: [u8; 32]) -> crate::server::nxr::NxrLandingHandler {
    use crate::{
        protocol::nxr::NxrKey,
        server::nxr::{NxrAuthenticator, NxrLandingHandler, NxrReplayCache},
        transport::tcp_relay::{TcpRelay, TcpRelayConfig},
    };
    let cache = NxrReplayCache::new(8, Duration::from_secs(60)).expect("cache policy must compile");
    NxrLandingHandler::new(
        NxrAuthenticator::new(NxrKey::new(key_bytes), cache, 5),
        Duration::from_secs(1),
        Duration::from_secs(1),
        TcpRelay::new(TcpRelayConfig::for_test(), FdBudget::new(4_096))
            .expect("relay policy must compile"),
        Duration::from_secs(1),
    )
}

fn assert_nxr_connect_refused(error: OutboundConnectError) {
    match error {
        OutboundConnectError::NxrConnect(source) => {
            assert_eq!(source.kind(), io::ErrorKind::ConnectionRefused);
            assert_eq!(
                source.raw_os_error(),
                Some(111),
                "Linux ECONNREFUSED errno must be 111"
            );
        }
        other => panic!("expected NxrConnect ECONNREFUSED, got {other}"),
    }
}

/// #253 P2 — listen-only LANDING outage on the real NXR LINE→LANDING path.
///
/// Closing only the landing listener (the landing handler and accepted
/// session stay alive) refuses new [`OutboundRegistry`] dials with
/// ECONNREFUSED while an already-authenticated session still relays. This
/// does not claim field RCA for #253 and does not change the QEMU campaign
/// contract. A listen-fd close inside `ProductionServer::run_until` is not
/// used here because that supervisor treats listener-task exit as a full
/// shutdown and drains established connections.
#[tokio::test(flavor = "current_thread")]
async fn listen_only_nxr_landing_outage_refuses_new_dials_established_session_survives() {
    const REQUEST: &[u8] = b"ping";
    const RESPONSE: &[u8] = b"pong";

    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("target must bind");
    let target_address = target_listener.local_addr().expect("target address");
    let landing_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("landing must bind");
    let landing_address = landing_listener.local_addr().expect("landing address");
    let key_bytes = [0x53; 32];
    let handler = nxr_landing_handler(key_bytes);
    let registry = OutboundRegistry::new(
        &named(
            "nxr",
            OutboundConfig::Nxr(NxrOutboundConfig {
                address: landing_address.ip().to_string(),
                port: landing_address.port(),
                psk: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(key_bytes)),
                warm_tcp: Some(false),
            }),
        ),
        &DirectBarrierPolicy::default(),
        Duration::from_secs(2),
        FdBudget::new(4_096),
    );
    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), target_address.port());

    let (accepted, connected) = tokio::join!(
        landing_listener.accept(),
        registry.connect("nxr", &destination)
    );
    let (inbound, _) = accepted.expect("landing must accept the established dial");
    let OutboundConnectOutcome::Connected(connection) =
        connected.expect("LINE must connect to the live landing listener")
    else {
        panic!("NXR cannot blackhole");
    };
    drop(landing_listener);

    let landing = handler.handle(inbound);
    let line = async {
        let (mut stream, permit) = connection.into_parts();
        stream.write_all(REQUEST).await?;
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await?;
        assert_eq!(
            &response, RESPONSE,
            "established NXR session must still relay"
        );

        assert_nxr_connect_refused(
            registry
                .connect("nxr", &destination)
                .await
                .expect_err("new dials must be refused after listen-only outage"),
        );

        stream.shutdown().await?;
        drop(permit);
        Ok::<_, io::Error>(())
    };
    let target = async {
        let (mut stream, _) = target_listener.accept().await?;
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await?;
        assert_eq!(&request, REQUEST);
        stream.write_all(RESPONSE).await?;
        stream.shutdown().await?;
        Ok::<_, io::Error>(())
    };

    let (landing, line, target) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(landing, line, target)
    })
    .await
    .expect("listen-only NXR exchange must not stall");
    landing.expect("established landing handler must survive listen drop");
    line.expect("established LINE session must still relay");
    target.expect("target I/O must succeed");
}

/// Listen-only outage leaves an already-accepted idle warm NXR socket usable
/// (not a stale-discard). A later cold dial is ECONNREFUSED. Contrasts with
/// [`stale_warm_nxr_socket_is_discarded_before_cold_fallback`].
#[tokio::test(flavor = "current_thread")]
async fn listen_only_nxr_landing_outage_keeps_idle_warm_socket_usable() {
    const REQUEST: &[u8] = b"ping";
    const RESPONSE: &[u8] = b"pong";

    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("target must bind");
    let target_address = target_listener.local_addr().expect("target address");
    let landing_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("landing must bind");
    let landing_address = landing_listener.local_addr().expect("landing address");
    let key_bytes = [0x63; 32];
    let handler = nxr_landing_handler(key_bytes);
    let policy = warm_policy();
    let registry = OutboundRegistry::with_warm_pools(
        &named(
            "nxr",
            OutboundConfig::Nxr(NxrOutboundConfig {
                address: landing_address.ip().to_string(),
                port: landing_address.port(),
                psk: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(key_bytes)),
                warm_tcp: Some(true),
            }),
        ),
        DirectBarrier::new(&DirectBarrierPolicy::default()),
        Duration::from_secs(2),
        FdBudget::new(4_096),
        &NetworkConfig::default(),
        NetworkEnvironment::detect(),
        8,
        WarmPoolAuthority::new(&policy, 1, PressureGauge::new()),
        &policy,
    );
    registry.activate_warm_pools();
    let (warm_inbound, _) = landing_listener
        .accept()
        .await
        .expect("warm peer must connect");
    wait_for_one_ready(&registry).await;
    drop(landing_listener);

    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), target_address.port());
    let landing = handler.handle(warm_inbound);
    let line = async {
        let OutboundConnectOutcome::Connected(connection) = registry
            .connect("nxr", &destination)
            .await
            .expect("idle warm NXR socket must still authenticate after listen drop")
        else {
            panic!("NXR cannot blackhole");
        };
        let (mut stream, permit) = connection.into_parts();
        stream.write_all(REQUEST).await?;
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await?;
        assert_eq!(&response, RESPONSE);

        let snapshot = registry.warm_pool_snapshots().remove(0).pool;
        assert_eq!(snapshot.checkout_hit, 1);
        assert_eq!(snapshot.stale_discard, 0);

        assert_nxr_connect_refused(
            registry
                .connect("nxr", &destination)
                .await
                .expect_err("cold dials must be refused after listen-only outage"),
        );

        stream.shutdown().await?;
        drop(permit);
        Ok::<_, io::Error>(())
    };
    let target = async {
        let (mut stream, _) = target_listener.accept().await?;
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await?;
        assert_eq!(&request, REQUEST);
        stream.write_all(RESPONSE).await?;
        stream.shutdown().await?;
        Ok::<_, io::Error>(())
    };

    let (landing, line, target) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(landing, line, target)
    })
    .await
    .expect("listen-only NXR warm exchange must not stall");
    landing.expect("landing handler must serve the warm checkout");
    line.expect("warm checkout must relay after listen drop");
    target.expect("target I/O must succeed");
    registry.deactivate_warm_pools();
}

async fn bind_loopback_again(address: SocketAddr) -> TcpListener {
    let mut last = None;
    for _ in 0..50 {
        match TcpListener::bind(address).await {
            Ok(listener) => return listener,
            Err(error) => {
                last = Some(error);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
    panic!("could not re-bind landing {address}: {last:?}");
}

/// After a listen-only NXR outage, the same [`OutboundRegistry`] must be
/// able to dial again once a listener returns on that landing address.
/// Complements the #474 refuse-new-dials tests. Does not claim field RCA
/// for #253 and does not change production or campaign contracts.
#[tokio::test(flavor = "current_thread")]
async fn listen_only_nxr_landing_outage_recovers_when_listener_returns() {
    const REQUEST: &[u8] = b"ping";
    const RESPONSE: &[u8] = b"pong";

    let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("target must bind");
    let target_address = target_listener.local_addr().expect("target address");
    let landing_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("landing must bind");
    let landing_address = landing_listener.local_addr().expect("landing address");
    let key_bytes = [0x71; 32];
    let handler = nxr_landing_handler(key_bytes);
    let registry = OutboundRegistry::new(
        &named(
            "nxr",
            OutboundConfig::Nxr(NxrOutboundConfig {
                address: landing_address.ip().to_string(),
                port: landing_address.port(),
                psk: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(key_bytes)),
                warm_tcp: Some(false),
            }),
        ),
        &DirectBarrierPolicy::default(),
        Duration::from_secs(2),
        FdBudget::new(4_096),
    );
    let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), target_address.port());

    drop(landing_listener);
    assert_nxr_connect_refused(
        registry
            .connect("nxr", &destination)
            .await
            .expect_err("new dials must be refused while the landing listener is down"),
    );

    let landing_listener = bind_loopback_again(landing_address).await;
    let recovered = async {
        let (inbound, _) = landing_listener
            .accept()
            .await
            .expect("recovered landing must accept the new dial");
        handler.handle(inbound).await
    };
    let line = async {
        let OutboundConnectOutcome::Connected(connection) = registry
            .connect("nxr", &destination)
            .await
            .expect("the same registry must connect after the landing listener returns")
        else {
            panic!("NXR cannot blackhole");
        };
        let (mut stream, permit) = connection.into_parts();
        stream.write_all(REQUEST).await?;
        let mut response = [0_u8; 4];
        stream.read_exact(&mut response).await?;
        assert_eq!(&response, RESPONSE, "recovered NXR session must relay");
        stream.shutdown().await?;
        drop(permit);
        Ok::<_, io::Error>(())
    };
    let target = async {
        let (mut stream, _) = target_listener.accept().await?;
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await?;
        assert_eq!(&request, REQUEST);
        stream.write_all(RESPONSE).await?;
        stream.shutdown().await?;
        Ok::<_, io::Error>(())
    };

    let (recovered, line, target) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(recovered, line, target)
    })
    .await
    .expect("NXR recovery exchange must not stall");
    recovered.expect("recovered landing handler must serve the new dial");
    line.expect("recovered LINE session must relay");
    target.expect("target I/O must succeed");
}
