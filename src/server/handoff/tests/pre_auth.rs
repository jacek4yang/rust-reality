//! Warm-carrier checkout and pre-authentication deadline tests.

use super::*;

#[tokio::test(flavor = "current_thread")]
async fn warm_handoff_sends_no_transfer_bytes_before_checkout() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("landing must bind");
    let address = listener.local_addr().expect("landing address");
    let policy = WarmConnectionPolicy {
        min_ready: 1,
        max_ready: 2,
        max_connecting: 1,
        refill_batch: 1,
        idle_timeout_ms: 30_000,
        max_lifetime_ms: 60_000,
        shrink_delay_ms: 30_000,
    };
    let fd_budget = FdBudget::new(4_096);
    let pressure = PressureGauge::new();
    let landing_public = StaticX25519Key::new(&LANDING_SECRET).public_key();
    let line = HandoffLine::from_settings_with_warm_pool(
        &HandoffOutboundConfig {
            address: address.ip().to_string(),
            port: address.port(),
            psk: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(PSK)),
            landing_public_key: BASE64_URL_SAFE_NO_PAD.encode(landing_public),
            connect_timeout_ms: Some(2_000),
            first_byte_timeout_ms: Some(2_000),
            warm_tcp: Some(true),
        },
        DestinationConnector::new(Duration::from_secs(2)),
        &fd_budget,
        Some((11, WarmPoolAuthority::new(&policy, 1, pressure), &policy)),
    )
    .expect("line settings must compile");
    let pool = line.warm_pool().expect("warm pool must exist").clone();
    let _activated = pool.activate();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let landing = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut probe = [0_u8; 1];
        assert!(
            matches!(stream.try_read(&mut probe), Err(ref error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        accepted_tx
            .send(())
            .map_err(|()| io::Error::other("receiver closed"))?;
        let mut header = [0_u8; HEADER_LEN];
        stream.read_exact(&mut header).await?;
        let total = message_len_from_header(&header).map_err(io::Error::other)?;
        let mut remainder = vec![0_u8; total - HEADER_LEN];
        stream.read_exact(&mut remainder).await?;
        Ok::<_, io::Error>(())
    });
    accepted_rx.await.expect("warm TCP must reach landing");
    timeout(Duration::from_secs(2), async {
        while pool.snapshot().ready != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("pool must become ready");
    let state = test_state(Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 443));
    let (stream, permit) = line
        .transfer(&fd_budget, &state, [0x42; 32])
        .await
        .expect("warm transfer must write");
    drop(stream);
    drop(permit);
    landing
        .await
        .expect("landing must join")
        .expect("landing result");
    assert_eq!(pool.snapshot().checkout_hit, 1);
    assert_eq!(pool.snapshot().cold_fallback, 0);
    let _deactivated = pool.deactivate();
}

#[tokio::test(flavor = "current_thread")]
async fn stale_warm_handoff_socket_is_discarded_before_cold_fallback() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("landing must bind");
    let address = listener.local_addr().expect("landing address");
    let policy = WarmConnectionPolicy {
        min_ready: 1,
        max_ready: 1,
        max_connecting: 1,
        refill_batch: 1,
        idle_timeout_ms: 30_000,
        max_lifetime_ms: 60_000,
        shrink_delay_ms: 30_000,
    };
    let fd_budget = FdBudget::new(4_096);
    let landing_public = StaticX25519Key::new(&LANDING_SECRET).public_key();
    let line = HandoffLine::from_settings_with_warm_pool(
        &HandoffOutboundConfig {
            address: address.ip().to_string(),
            port: address.port(),
            psk: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(PSK)),
            landing_public_key: BASE64_URL_SAFE_NO_PAD.encode(landing_public),
            connect_timeout_ms: Some(2_000),
            first_byte_timeout_ms: Some(2_000),
            warm_tcp: Some(true),
        },
        DestinationConnector::new(Duration::from_secs(2)),
        &fd_budget,
        Some((
            12,
            WarmPoolAuthority::new(&policy, 1, PressureGauge::new()),
            &policy,
        )),
    )
    .expect("line settings must compile");
    let pool = line.warm_pool().expect("warm pool must exist").clone();
    assert!(pool.activate());
    let (mut stale_peer, _) = listener.accept().await.expect("warm peer must connect");
    timeout(Duration::from_secs(2), async {
        while pool.snapshot().ready != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("pool must become ready");
    stale_peer
        .shutdown()
        .await
        .expect("peer FIN must be observable");
    drop(stale_peer);
    tokio::time::sleep(Duration::from_millis(10)).await;

    let state = test_state(Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 443));
    let (stream, permit) = line
        .transfer(&fd_budget, &state, [0x43; 32])
        .await
        .expect("cold fallback must submit a fresh transfer");
    drop(stream);
    drop(permit);
    let snapshot = pool.snapshot();
    assert_eq!(snapshot.checkout_hit, 0);
    assert_eq!(snapshot.checkout_miss, 1);
    assert_eq!(snapshot.cold_fallback, 1);
    assert_eq!(snapshot.stale_discard, 1);
    pool.deactivate();
}

#[tokio::test(flavor = "current_thread")]
async fn silent_warm_carrier_times_out_without_replaying_a_committed_transfer() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("fault listener");
    let budget = FdBudget::new(64);
    let handler = handoff_vision_handler_with_warm(
        listener.local_addr().expect("address"),
        true,
        budget.clone(),
    );
    handler.outbounds().activate_warm_pools();
    let (mut blackhole, _) = timeout(TEST_TIMEOUT, listener.accept())
        .await
        .expect("warm dial deadline")
        .expect("warm dial");
    timeout(TEST_TIMEOUT, async {
        while handler.outbounds().warm_pool_snapshots()[0].pool.ready != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("warm READY barrier");
    let (mut client, server) = tcp_pair().await;
    let (tls, mut client_write, _client_read) = tls_states();
    let established = RealityEstablished::from_test_parts(TlsApplicationIo::new(server, tls), USER);
    let request = vision_request(443, b"one logical request");
    let mut record = Vec::new();
    client_write
        .seal_into(ContentType::ApplicationData, &request, 0, &mut record)
        .expect("seal request");
    client.write_all(&record).await.expect("send request");
    // The fault consumes the *complete* transfer, acknowledging TCP bytes
    // but withholding all protocol downlink. A safe retry is impossible:
    // a real peer could already have acted on these authenticated bytes.
    let consume = async {
        let mut header = [0_u8; HEADER_LEN];
        blackhole
            .read_exact(&mut header)
            .await
            .expect("transfer header");
        let length = message_len_from_header(&header).expect("bounded transfer");
        let mut remainder = vec![0_u8; length - HEADER_LEN];
        blackhole
            .read_exact(&mut remainder)
            .await
            .expect("complete transfer");
        // Keep the socket open in the enclosing scope until the deadline.
        length
    };
    let (result, length) = timeout(TEST_TIMEOUT, async {
        tokio::join!(handler.handle(established), consume)
    })
    .await
    .expect("silent warm flow must fail within the first-byte bound");
    assert!(length > HEADER_LEN);
    assert!(matches!(
        result,
        Err(VisionSessionError::HandoffLine(
            HandoffLineError::LandingRejected
        ))
    ));
    let error = timeout(TEST_TIMEOUT, client.read(&mut [0_u8; 1]))
        .await
        .expect("client reset deadline")
        .expect_err("failed transferred session must reset");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    let snapshot = handler.outbounds().warm_pool_snapshots()[0].pool;
    assert_eq!(snapshot.checkout_total, 1);
    assert_eq!(snapshot.checkout_hit, 1);
    assert_eq!(
        snapshot.cold_fallback, 0,
        "complete transfer must never be cold-replayed"
    );
    assert_eq!(
        snapshot.in_use, 0,
        "failed flow releases its checkout permit"
    );
    // Refilling TCP is allowed; replaying protocol bytes on that socket is
    // not. Observe the sole replacement without changing socket policy.
    let (mut replacement, _) = timeout(TEST_TIMEOUT, listener.accept())
        .await
        .expect("refill deadline")
        .expect("refill TCP");
    assert!(
        timeout(Duration::from_millis(30), replacement.read(&mut [0_u8; 1]))
            .await
            .is_err(),
        "refill must remain protocol-unprivileged"
    );
    handler.outbounds().deactivate_warm_pools();
    drop(blackhole);
    drop(replacement);
    timeout(TEST_TIMEOUT, async {
        while budget.in_use() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("every warm and checked-out descriptor permit returns");
    assert_eq!(budget.underflows(), 0);
}

#[tokio::test(start_paused = true)]
async fn first_handoff_byte_enters_the_short_authentication_deadline() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("landing must bind");
    let address = listener.local_addr().expect("landing address");
    let client = TcpStream::connect(address);
    let accepted = listener.accept();
    let (client, accepted) = tokio::join!(client, accepted);
    let mut client = client.expect("client must connect");
    let (server, _) = accepted.expect("landing must accept");
    let handler = test_landing_handler();
    let task = tokio::spawn(async move { handler.handle(server).await });

    client.write_all(b"H").await.expect("first byte");
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(matches!(
        task.await.expect("handler must join"),
        Err(HandoffLandingError::Timeout)
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn mixed_continuation_versions_close_without_response_or_destination_dial() {
    let destination =
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("destination must bind");
    destination
        .set_nonblocking(true)
        .expect("nonblocking destination");
    let state = test_state(Destination::new(
        Address::Ipv4(Ipv4Addr::LOCALHOST),
        destination
            .local_addr()
            .expect("destination address")
            .port(),
    ));
    for state_version in [0, 1, CONTINUATION_STATE_VERSION + 1] {
        for include_body in [false, true] {
            let (mut line, landing) = tcp_pair().await;
            let handler = Arc::new(test_landing_handler());
            let accepted_handler = handler.clone();
            let task = tokio::spawn(async move { accepted_handler.handle(landing).await });
            let mut message = Vec::new();
            seal_transfer(
                &state,
                &HandoffPsk::new(PSK),
                &StaticX25519Key::new(&LANDING_SECRET).public_key(),
                [0x44; 32],
                unix_seconds().expect("clock"),
                &mut message,
            )
            .expect("transfer fixture");
            message[5] = state_version;
            let sent = if include_body {
                &message[..]
            } else {
                &message[..HEADER_LEN]
            };
            line.write_all(sent).await.expect("mixed-version transfer");
            assert!(matches!(
                timeout(TEST_TIMEOUT, task)
                    .await
                    .expect("rejection deadline")
                    .expect("handler join"),
                Err(HandoffLandingError::Protocol(HandoffError::Version))
            ));
            let mut response = [0_u8; 1];
            let closed = timeout(TEST_TIMEOUT, line.read(&mut response))
                .await
                .expect("silent close deadline");
            assert!(
                matches!(&closed, Ok(0))
                    || matches!(&closed, Err(error) if error.kind() == io::ErrorKind::ConnectionReset),
                "mixed-version rejection must expose no response bytes"
            );
            assert_eq!(handler.replay.entry_count(), 0);
            assert!(
                matches!(destination.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock),
                "version rejection must not reach destination connect"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn valid_handoff_authenticates_across_the_pre_auth_idle_age_matrix() {
    let state = test_state(Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 9));
    let landing_public = StaticX25519Key::new(&LANDING_SECRET).public_key();
    for (index, idle_age) in [0, 1, 5, 15, 30, 59].into_iter().enumerate() {
        let (mut client, server) = tcp_pair().await;
        let handler = test_landing_handler();
        let mut message = Vec::new();
        seal_transfer(
            &state,
            &HandoffPsk::new(PSK),
            &landing_public,
            [u8::try_from(index).expect("small matrix index"); 32],
            unix_seconds().expect("clock must be valid"),
            &mut message,
        )
        .expect("transfer must seal");
        let task = tokio::spawn(async move { handler.handle(server).await });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(idle_age)).await;
        assert!(
            !task.is_finished(),
            "valid Handoff idle age {idle_age}s must remain accepted"
        );
        client.write_all(&message).await.expect("transfer write");
        assert!(matches!(
            task.await.expect("handler must join"),
            Err(HandoffLandingError::Destination(_))
        ));
    }
}

#[tokio::test(start_paused = true)]
async fn unused_handoff_socket_expires_at_pre_auth_idle_deadline() {
    let (_client, server) = tcp_pair().await;
    let handler = test_landing_handler();
    let task = tokio::spawn(async move { handler.handle(server).await });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(60)).await;
    assert!(matches!(
        task.await.expect("handler must join"),
        Err(HandoffLandingError::Timeout)
    ));
}
