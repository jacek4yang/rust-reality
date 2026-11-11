//! LINE-to-LANDING session transfer, egress and failure-path tests.

use super::*;

#[tokio::test(flavor = "current_thread")]
async fn landing_rejects_an_unauthenticated_datagram_silently() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("landing must bind");
    let address = listener.local_addr().expect("landing address must exist");
    let handler = test_landing_handler();

    let exchange = async {
        let landing = async {
            let (stream, _) = listener.accept().await?;
            handler.handle(stream).await.map_err(io::Error::other)
        };
        let peer = async {
            let mut stream = TcpStream::connect(address).await?;
            stream.write_all(b"not a handoff transfer at all").await?;
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;
            Ok::<_, io::Error>(response)
        };
        tokio::join!(landing, peer)
    };
    let (landing, peer) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("rejection must not stall");
    landing.expect_err("garbage must fail closed");
    assert_eq!(
        peer.expect("peer exchange must succeed"),
        b"",
        "a rejected transfer must receive zero response bytes"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn landing_rejects_a_replayed_transfer_on_preestablished_sockets() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("landing must bind");
    let address = listener.local_addr().expect("landing address must exist");
    let handler = test_landing_handler();
    let landing_public = StaticX25519Key::new(&LANDING_SECRET).public_key();
    // Port 9 is the discard sink: nothing listens, so an authenticated
    // transfer fails at the destination dial — proving it passed every
    // authentication step.
    let state = test_state(Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 9));
    let mut message = Vec::new();
    seal_transfer(
        &state,
        &HandoffPsk::new(PSK),
        &landing_public,
        [0x44; 32],
        unix_seconds().expect("test clock must be valid"),
        &mut message,
    )
    .expect("test state must seal");

    let exchange = async {
        let landing = async {
            let (first, _) = listener.accept().await?;
            let (second, _) = listener.accept().await?;
            let first_handler = handler.clone();
            let (first, second) = tokio::join!(first_handler.handle(first), handler.handle(second));
            Ok::<_, io::Error>([first, second])
        };
        let peer = async {
            let mut streams = [
                TcpStream::connect(address).await?,
                TcpStream::connect(address).await?,
            ];
            tokio::task::yield_now().await;
            for stream in &mut streams {
                stream.write_all(&message).await?;
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await?;
                assert_eq!(response, b"", "failures must stay silent");
            }
            Ok::<_, io::Error>(())
        };
        tokio::join!(landing, peer)
    };
    let (landing, peer) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("replay rejection must not stall");
    peer.expect("peer exchange must succeed");
    let outcomes = landing.expect("landing task must succeed");
    assert!(
        matches!(outcomes[0], Err(HandoffLandingError::Destination(_))),
        "the first delivery must authenticate and fail only at the dial"
    );
    assert!(
        matches!(
            outcomes[1],
            Err(HandoffLandingError::Protocol(
                crate::protocol::handoff::HandoffError::Replay
            ))
        ),
        "the replayed delivery must be rejected by the nonce cache"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn line_to_landing_moves_a_full_vision_session_byte_exactly() {
    run_line_to_landing_full_vision_session(false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn line_to_landing_resumes_after_cover_shaped_server_sequence_one() {
    run_line_to_landing_full_vision_session(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_landing_serves_eight_independent_lines_concurrently() {
    let listener = Arc::new(
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("shared landing"),
    );
    let handler = test_landing_handler();
    let budget = handler.relay.fd_budget().clone();
    let mut sessions = tokio::task::JoinSet::new();
    for index in 0..8 {
        sessions.spawn(run_shared_landing_session(
            index % 2 != 0,
            Arc::clone(&listener),
            handler.clone(),
        ));
    }
    timeout(Duration::from_secs(10), async {
        while let Some(result) = sessions.join_next().await {
            result.expect("every independent LINE must finish byte-exactly");
        }
    })
    .await
    .expect("shared LANDING fan-in must remain bounded");
    assert_eq!(
        handler
            .governor
            .in_flight(crate::runtime::AdmissionKind::Handshake),
        0
    );
    assert_eq!(
        handler
            .governor
            .in_flight(crate::runtime::AdmissionKind::PreAuthIdle),
        0
    );
    drop(handler);
    assert_eq!(
        budget.in_use(),
        0,
        "all session and retained relay resources are released"
    );
    assert_eq!(budget.underflows(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn line_splices_post_transfer_uplink_records_to_landing() {
    let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("destination must bind");
    let destination_address = destination_listener
        .local_addr()
        .expect("destination address must exist");
    let landing_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("landing must bind");
    let landing_address = landing_listener
        .local_addr()
        .expect("landing address must exist");
    let landing_handler = test_landing_handler();
    let line_handler = handoff_vision_handler(landing_address);
    let (mut client, server) = tcp_pair().await;
    let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
    let established =
        RealityEstablished::from_test_parts(TlsApplicationIo::new(server, established_tls), USER);
    let request = vision_request(destination_address.port(), b"ping");

    let exchange = async {
        let line = line_handler.handle(established);
        let landing = async {
            let (stream, _) = landing_listener.accept().await?;
            landing_handler
                .handle(stream)
                .await
                .map_err(io::Error::other)
        };
        let client_io = async {
            let mut record = Vec::new();
            client_write_records
                .seal_into(ContentType::ApplicationData, &request, 0, &mut record)
                .map_err(io::Error::other)?;
            client.write_all(&record).await?;

            // The first downlink record (response header + opening frame)
            // proves the transfer landed; everything sent afterwards must
            // travel the raw splice, never LINE's TLS state.
            let mut first = read_tls_record(&mut client, TEST_TIMEOUT)
                .await
                .map_err(io::Error::other)?
                .into_wire();
            let opened = client_read_records
                .open_in_place(&mut first)
                .map_err(io::Error::other)?;
            let mut decoder = VisionDecoder::new(USER);
            let mut decoded = Vec::new();
            let mut response = Vec::new();
            {
                let plaintext = opened.plaintext();
                if opened.content_type() != ContentType::ApplicationData
                    || plaintext.get(..2) != Some([VERSION, 0].as_slice())
                {
                    return Err(io::Error::other("missing resumed response header"));
                }
                let _ = decoder
                    .decode(&plaintext[2..], &mut decoded)
                    .map_err(io::Error::other)?;
                response.extend_from_slice(&decoded);
            }
            let mut more = Vec::new();
            client_write_records
                .seal_into(ContentType::ApplicationData, b"-more", 0, &mut more)
                .map_err(io::Error::other)?;
            client.write_all(&more).await?;
            let mut close_record = Vec::new();
            client_write_records
                .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                .map_err(io::Error::other)?;
            client.write_all(&close_record).await?;

            loop {
                let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                    .await
                    .map_err(io::Error::other)?
                    .into_wire();
                let opened = client_read_records
                    .open_in_place(&mut record)
                    .map_err(io::Error::other)?;
                match opened.content_type() {
                    ContentType::ApplicationData => {
                        let _ = decoder
                            .decode(opened.plaintext(), &mut decoded)
                            .map_err(io::Error::other)?;
                        response.extend_from_slice(&decoded);
                    }
                    ContentType::Alert if opened.plaintext() == [1, 0] => break,
                    _ => return Err(io::Error::other("unexpected outer TLS content")),
                }
            }
            client.shutdown().await?;
            Ok::<_, io::Error>(response)
        };
        let destination_io = async {
            let (mut destination, _) = destination_listener.accept().await?;
            let mut received = Vec::new();
            destination.read_to_end(&mut received).await?;
            destination.write_all(b"pong").await?;
            destination.shutdown().await?;
            Ok::<_, io::Error>(received)
        };
        tokio::join!(line, landing, client_io, destination_io)
    };
    let (line, landing, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("spliced uplink exchange must not time out");
    let line_stats = line.expect("LINE handler must succeed");
    landing.expect("LANDING handler must succeed");

    assert_eq!(
        destination_result.expect("destination I/O must succeed"),
        b"ping-more"
    );
    assert_eq!(client_result.expect("client I/O must succeed"), b"pong");
    assert!(
        line_stats.uplink_bytes() > 0,
        "post-transfer records must move through the raw splice"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn landing_serves_a_transferred_session_through_a_socks5_egress() {
    let socks_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("SOCKS stub must bind");
    let socks_address = socks_listener
        .local_addr()
        .expect("SOCKS stub address must exist");
    let landing_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("landing must bind");
    let landing_address = landing_listener
        .local_addr()
        .expect("landing address must exist");
    // Reserve a destination port and drop its listener: nothing accepts a
    // direct dial, so the session can only succeed through the egress hop.
    let destination_port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("probe listener must bind")
        .local_addr()
        .expect("probe address must exist")
        .port();
    let landing_handler = test_landing_handler().with_egress(
        egress_registry(
            "socks",
            OutboundConfig::Socks5(Socks5Config {
                address: socks_address.ip().to_string(),
                port: socks_address.port(),
                username: None,
                password: None,
                warm_tcp: Some(false),
            }),
        ),
        "socks",
    );
    let line_handler = handoff_vision_handler(landing_address);
    let (mut client, server) = tcp_pair().await;
    let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
    let established =
        RealityEstablished::from_test_parts(TlsApplicationIo::new(server, established_tls), USER);
    let request = vision_request(destination_port, b"ping");

    let exchange = async {
        let line = line_handler.handle(established);
        let landing = async {
            let (stream, _) = landing_listener.accept().await?;
            landing_handler
                .handle(stream)
                .await
                .map_err(io::Error::other)
        };
        let client_io = async {
            let mut burst = Vec::new();
            client_write_records
                .seal_into(ContentType::ApplicationData, &request, 0, &mut burst)
                .map_err(io::Error::other)?;
            let mut more = Vec::new();
            client_write_records
                .seal_into(ContentType::ApplicationData, b"-more", 0, &mut more)
                .map_err(io::Error::other)?;
            burst.extend_from_slice(&more);
            let mut close_record = Vec::new();
            client_write_records
                .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                .map_err(io::Error::other)?;
            burst.extend_from_slice(&close_record);
            client.write_all(&burst).await?;

            let mut decoder = VisionDecoder::new(USER);
            let mut decoded = Vec::new();
            let mut response = Vec::new();
            let mut response_header = true;
            loop {
                let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                    .await
                    .map_err(io::Error::other)?
                    .into_wire();
                let opened = client_read_records
                    .open_in_place(&mut record)
                    .map_err(io::Error::other)?;
                match opened.content_type() {
                    ContentType::ApplicationData => {
                        let plaintext = opened.plaintext();
                        let vision = if response_header {
                            response_header = false;
                            if plaintext.get(..2) != Some([VERSION, 0].as_slice()) {
                                return Err(io::Error::other("invalid VLESS response header"));
                            }
                            &plaintext[2..]
                        } else {
                            plaintext
                        };
                        let _ = decoder
                            .decode(vision, &mut decoded)
                            .map_err(io::Error::other)?;
                        response.extend_from_slice(&decoded);
                    }
                    ContentType::Alert if opened.plaintext() == [1, 0] => break,
                    _ => return Err(io::Error::other("unexpected outer TLS content")),
                }
            }
            client.shutdown().await?;
            Ok::<_, io::Error>(response)
        };
        // A minimal no-auth SOCKS5 peer: negotiate, verify the CONNECT
        // carries the transferred destination byte-exactly, then serve as
        // the destination without ever dialing it.
        let socks_io = async {
            let (mut stream, _) = socks_listener.accept().await?;
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await?;
            if greeting != [5, 1, 0] {
                return Err(io::Error::other("unexpected SOCKS greeting"));
            }
            stream.write_all(&[5, 0]).await?;
            let mut header = [0_u8; 4];
            stream.read_exact(&mut header).await?;
            let mut address = [0_u8; 4];
            stream.read_exact(&mut address).await?;
            let mut port = [0_u8; 2];
            stream.read_exact(&mut port).await?;
            if header != [5, 1, 0, 1]
                || address != Ipv4Addr::LOCALHOST.octets()
                || u16::from_be_bytes(port) != destination_port
            {
                return Err(io::Error::other(
                    "the CONNECT request must carry the transferred destination",
                ));
            }
            stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await?;
            stream.write_all(b"pong").await?;
            stream.shutdown().await?;
            Ok::<_, io::Error>(received)
        };
        tokio::join!(line, landing, client_io, socks_io)
    };
    let (line, landing, client_result, socks_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("egress exchange must not time out");
    line.expect("LINE handler must succeed");
    let landing_stats = landing.expect("LANDING handler must succeed");

    assert_eq!(
        socks_result.expect("SOCKS stub I/O must succeed"),
        b"ping-more",
        "the session payload must reach the egress hop byte-exactly"
    );
    assert_eq!(
        client_result.expect("client I/O must succeed"),
        b"pong",
        "the egress hop's downlink must decrypt byte-exactly at the client"
    );
    assert_eq!(landing_stats.inbound_to_outbound_bytes(), 9);
    assert_eq!(landing_stats.outbound_to_inbound_bytes(), 4);
}

#[tokio::test(flavor = "current_thread")]
async fn landing_ends_a_transferred_session_silently_when_the_egress_blackholes() {
    let landing_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("landing must bind");
    let landing_address = landing_listener
        .local_addr()
        .expect("landing address must exist");
    // `block` is a built-in outbound, so an empty declaration set already
    // resolves it.
    let landing_handler = test_landing_handler().with_egress(
        OutboundRegistry::new(
            &std::collections::BTreeMap::new(),
            &DirectBarrierPolicy::default(),
            Duration::from_secs(1),
            FdBudget::new(4_096),
        ),
        "block",
    );
    let line_handler = handoff_vision_handler(landing_address);
    let (mut client, server) = tcp_pair().await;
    let (established_tls, mut client_write_records, _client_read_records) = tls_states();
    let established =
        RealityEstablished::from_test_parts(TlsApplicationIo::new(server, established_tls), USER);
    // Port 9 is the discard sink: if the landing dialed despite the
    // blackhole, the session would fail with a destination error instead
    // of ending cleanly.
    let request = vision_request(9, b"ping");

    let exchange = async {
        let line = line_handler.handle(established);
        let landing = async {
            let (stream, _) = landing_listener.accept().await?;
            landing_handler
                .handle(stream)
                .await
                .map_err(io::Error::other)
        };
        let client_io = async {
            let mut record = Vec::new();
            client_write_records
                .seal_into(ContentType::ApplicationData, &request, 0, &mut record)
                .map_err(io::Error::other)?;
            client.write_all(&record).await?;
            // The blackholed session never produces downlink, so LINE's
            // first-byte deadline classifies the silent close as a
            // rejection and resets the client socket.
            let mut byte = [0_u8; 1];
            let error = client
                .read(&mut byte)
                .await
                .expect_err("a blackholed transfer must reset the client, never FIN it");
            assert_eq!(
                error.kind(),
                io::ErrorKind::ConnectionReset,
                "the rejection abort must reach the client as RST"
            );
            Ok::<_, io::Error>(())
        };
        tokio::join!(line, landing, client_io)
    };
    let (line, landing, client_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("blackhole exchange must not time out");
    let landing_stats = landing.expect("a blackholed egress must end the session without an error");
    assert_eq!(landing_stats.inbound_to_outbound_bytes(), 0);
    assert_eq!(landing_stats.outbound_to_inbound_bytes(), 0);
    client_result.expect("client I/O must succeed");
    let error = line.expect_err("LINE must fail the session, never serve it locally");
    assert!(
        matches!(
            error,
            VisionSessionError::HandoffLine(HandoffLineError::LandingRejected)
        ),
        "a blackholed landing close must read as a rejection: {error}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn line_aborts_the_client_when_landing_rejects_the_transfer() {
    // A landing node with the WRONG psk: every transfer fails
    // authentication and closes silently.
    let wrong_psk_handler = {
        let replay = HandoffReplayCache::new(1_024, Duration::from_secs(120))
            .expect("test replay cache must compile");
        HandoffLandingHandler::new(
            HandoffLandingKeys::single(
                HandoffPsk::new([0x66; 32]),
                StaticX25519Key::new(&LANDING_SECRET),
            ),
            replay,
            30,
            Duration::from_secs(1),
            Duration::from_secs(1),
            test_relay(),
            Duration::from_secs(1),
        )
    };
    let landing_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("landing must bind");
    let landing_address = landing_listener
        .local_addr()
        .expect("landing address must exist");
    let line_handler = handoff_vision_handler(landing_address);
    let (mut client, server) = tcp_pair().await;
    let (established_tls, mut client_write_records, _client_read_records) = tls_states();
    let established =
        RealityEstablished::from_test_parts(TlsApplicationIo::new(server, established_tls), USER);
    let request = vision_request(9, b"ping");

    let exchange = async {
        let line = line_handler.handle(established);
        let landing = async {
            let (stream, _) = landing_listener.accept().await?;
            wrong_psk_handler
                .handle(stream)
                .await
                .map_err(io::Error::other)
        };
        let client_io = async {
            let mut record = Vec::new();
            client_write_records
                .seal_into(ContentType::ApplicationData, &request, 0, &mut record)
                .map_err(io::Error::other)?;
            client.write_all(&record).await?;
            // The client stays open like any patient client: LINE must
            // detect the silent rejection at its own first-byte deadline —
            // far inside TEST_TIMEOUT — and reset this socket. A clean
            // FIN (Ok(0)) or any read byte is a failure of the spec's
            // failure semantics, not a race to tolerate.
            let mut byte = [0_u8; 1];
            let error = client
                .read(&mut byte)
                .await
                .expect_err("a rejected transfer must reset the client, never FIN it");
            assert_eq!(
                error.kind(),
                io::ErrorKind::ConnectionReset,
                "the rejection abort must reach the client as RST"
            );
            Ok::<_, io::Error>(())
        };
        tokio::join!(line, landing, client_io)
    };
    let (line, landing, client_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("rejection exchange must not time out");
    assert!(landing.is_err(), "the wrong psk must fail authentication");
    client_result.expect("client I/O must succeed");
    let error = line.expect_err("LINE must fail the session, never serve it locally");
    assert!(
        matches!(
            error,
            VisionSessionError::HandoffLine(HandoffLineError::LandingRejected)
        ),
        "a landing close without downlink must read as a rejection: {error}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn line_transfer_failure_on_unreachable_landing_fails_the_session() {
    // Reserve a port and drop the listener so connects are refused fast.
    let refused_port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("probe listener must bind")
        .local_addr()
        .expect("probe address must exist")
        .port();
    let landing_address = std::net::SocketAddr::new(Ipv4Addr::LOCALHOST.into(), refused_port);
    let line_handler = handoff_vision_handler(landing_address);
    let (mut client, server) = tcp_pair().await;
    let (established_tls, mut client_write_records, _client_read_records) = tls_states();
    let established =
        RealityEstablished::from_test_parts(TlsApplicationIo::new(server, established_tls), USER);
    let request = vision_request(9, b"ping");

    let exchange = async {
        let line = line_handler.handle(established);
        let client_io = async {
            let mut record = Vec::new();
            client_write_records
                .seal_into(ContentType::ApplicationData, &request, 0, &mut record)
                .map_err(io::Error::other)?;
            client.write_all(&record).await
        };
        tokio::join!(line, client_io)
    };
    let (line, client_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("dial failure must not stall");
    client_result.expect("the request write must succeed");
    let error = line.expect_err("an unreachable landing must fail the session");
    assert!(
        matches!(
            error,
            VisionSessionError::HandoffLine(HandoffLineError::Connect(_))
        ),
        "a refused landing dial must surface as a connect failure: {error}"
    );
}

#[test]
fn handoff_line_rejects_undecodable_settings() {
    assert!(
        HandoffLine::from_settings(&HandoffOutboundConfig {
            udp_port: None,
            udp_mtu: None,
            address: "127.0.0.1".to_owned(),
            port: 443,
            psk: SecretString::new("not-base64!"),
            landing_public_key: BASE64_URL_SAFE_NO_PAD.encode([0x77; 32]),
            connect_timeout_ms: Some(1_000),
            first_byte_timeout_ms: Some(1_000),
            warm_tcp: Some(false),
        })
        .is_none()
    );
    assert!(
        HandoffLine::from_settings(&HandoffOutboundConfig {
            udp_port: None,
            udp_mtu: None,
            address: "127.0.0.1".to_owned(),
            port: 443,
            psk: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(PSK)),
            landing_public_key: BASE64_URL_SAFE_NO_PAD.encode([0x77; 16]),
            connect_timeout_ms: Some(1_000),
            first_byte_timeout_ms: Some(1_000),
            warm_tcp: Some(false),
        })
        .is_none()
    );
}

#[test]
fn debug_output_never_reveals_key_material() {
    let line = handoff_line(std::net::SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443));
    let rendered = format!("{line:?}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains("VVVV"), "the base64 PSK must not appear");
}

#[tokio::test(flavor = "current_thread")]
async fn first_downlink_byte_classification() {
    // Session downlink begins with a sealed application-data record and
    // the probe must not consume it.
    let (mut peer, mut stream) = tcp_pair().await;
    peer.write_all(&[0x17, 0x03, 0x03, 0x00, 0x01, 0xaa])
        .await
        .expect("peer write must succeed");
    assert!(
        super::super::first_downlink_landed(&stream, TEST_TIMEOUT).await,
        "a TLS application-data first byte must classify as landed"
    );
    drop(peer);
    let mut rest = Vec::new();
    stream
        .read_to_end(&mut rest)
        .await
        .expect("the peeked bytes must remain for the raw relay");
    assert_eq!(rest, [0x17, 0x03, 0x03, 0x00, 0x01, 0xaa]);

    // A silent close and a mid-flight reset both read as rejection.
    let (peer, stream) = tcp_pair().await;
    drop(peer);
    assert!(
        !super::super::first_downlink_landed(&stream, TEST_TIMEOUT).await,
        "a silent close must classify as rejected"
    );
    let (peer, stream) = tcp_pair().await;
    rr_linux::socket::abort_linger(&peer).expect("abort linger must apply");
    drop(peer);
    assert!(
        !super::super::first_downlink_landed(&stream, TEST_TIMEOUT).await,
        "a reset must classify as rejected"
    );

    // A REALITY cover target mirroring the transfer would answer with a
    // handshake or alert record, never session application data.
    let (mut peer, stream) = tcp_pair().await;
    peer.write_all(&[0x16, 0x03, 0x01])
        .await
        .expect("peer write must succeed");
    assert!(
        !super::super::first_downlink_landed(&stream, TEST_TIMEOUT).await,
        "non-application-data bytes must classify as rejected"
    );
    drop(peer);

    // A landing that holds the connection without answering trips the
    // deadline, not the session idle timeout.
    let (_peer, stream) = tcp_pair().await;
    let started = std::time::Instant::now();
    assert!(
        !super::super::first_downlink_landed(&stream, Duration::from_millis(50)).await,
        "a stalled landing must classify as rejected at the deadline"
    );
    assert!(
        started.elapsed() < TEST_TIMEOUT,
        "the deadline must bound the wait, not the idle timeout"
    );
}

/// #253 P2 — listen-only LANDING outage on the real Handoff LINE→LANDING path.
///
/// Dropping only the landing listener after the transfer is accepted refuses
/// new [`HandoffLine::transfer`] dials with ECONNREFUSED while the established
/// Vision session still splices uplink and receives downlink. This does not
/// claim field RCA for #253 and does not change the QEMU campaign contract.
#[tokio::test(flavor = "current_thread")]
async fn listen_only_handoff_landing_outage_refuses_new_dials_established_session_survives() {
    let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("destination must bind");
    let destination_address = destination_listener
        .local_addr()
        .expect("destination address must exist");
    let landing_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("landing must bind");
    let landing_address = landing_listener
        .local_addr()
        .expect("landing address must exist");
    let landing_handler = test_landing_handler();
    let line_handler = handoff_vision_handler(landing_address);
    let (mut client, server) = tcp_pair().await;
    let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
    let established =
        RealityEstablished::from_test_parts(TlsApplicationIo::new(server, established_tls), USER);
    let request = vision_request(destination_address.port(), b"ping");

    let exchange = async {
        let line = line_handler.handle(established);
        let landing = async {
            let (stream, _) = landing_listener.accept().await?;
            drop(landing_listener);
            landing_handler
                .handle(stream)
                .await
                .map_err(io::Error::other)
        };
        let client_io = async {
            let mut record = Vec::new();
            client_write_records
                .seal_into(ContentType::ApplicationData, &request, 0, &mut record)
                .map_err(io::Error::other)?;
            client.write_all(&record).await?;

            let mut first = read_tls_record(&mut client, TEST_TIMEOUT)
                .await
                .map_err(io::Error::other)?
                .into_wire();
            let opened = client_read_records
                .open_in_place(&mut first)
                .map_err(io::Error::other)?;
            let mut decoder = VisionDecoder::new(USER);
            let mut decoded = Vec::new();
            let mut response = Vec::new();
            {
                let plaintext = opened.plaintext();
                if opened.content_type() != ContentType::ApplicationData
                    || plaintext.get(..2) != Some([VERSION, 0].as_slice())
                {
                    return Err(io::Error::other("missing resumed response header"));
                }
                let _ = decoder
                    .decode(&plaintext[2..], &mut decoded)
                    .map_err(io::Error::other)?;
                response.extend_from_slice(&decoded);
            }

            let refused = match handoff_line(landing_address)
                .transfer(
                    &FdBudget::new(4_096),
                    &test_state(Destination::new(
                        Address::Ipv4(Ipv4Addr::LOCALHOST),
                        destination_address.port(),
                    )),
                    [0x46; 32],
                )
                .await
            {
                Err(error) => error,
                Ok(_) => panic!("new handoff transfers must be refused after listen-only outage"),
            };
            match refused {
                HandoffLineError::Connect(source) => {
                    assert_eq!(source.kind(), io::ErrorKind::ConnectionRefused);
                    assert_eq!(
                        source.raw_os_error(),
                        Some(111),
                        "Linux ECONNREFUSED errno must be 111"
                    );
                }
                other => panic!("expected HandoffLineError::Connect ECONNREFUSED, got {other}"),
            }

            let mut more = Vec::new();
            client_write_records
                .seal_into(ContentType::ApplicationData, b"-more", 0, &mut more)
                .map_err(io::Error::other)?;
            client.write_all(&more).await?;
            let mut close_record = Vec::new();
            client_write_records
                .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                .map_err(io::Error::other)?;
            client.write_all(&close_record).await?;

            loop {
                let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                    .await
                    .map_err(io::Error::other)?
                    .into_wire();
                let opened = client_read_records
                    .open_in_place(&mut record)
                    .map_err(io::Error::other)?;
                match opened.content_type() {
                    ContentType::ApplicationData => {
                        let _ = decoder
                            .decode(opened.plaintext(), &mut decoded)
                            .map_err(io::Error::other)?;
                        response.extend_from_slice(&decoded);
                    }
                    ContentType::Alert if opened.plaintext() == [1, 0] => break,
                    _ => return Err(io::Error::other("unexpected outer TLS content")),
                }
            }
            client.shutdown().await?;
            Ok::<_, io::Error>(response)
        };
        let destination_io = async {
            let (mut destination, _) = destination_listener.accept().await?;
            let mut received = Vec::new();
            destination.read_to_end(&mut received).await?;
            destination.write_all(b"pong").await?;
            destination.shutdown().await?;
            Ok::<_, io::Error>(received)
        };
        tokio::join!(line, landing, client_io, destination_io)
    };
    let (line, landing, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("listen-only Handoff exchange must not time out");
    let line_stats = line.expect("established LINE session must survive listen drop");
    landing.expect("established LANDING handler must survive listen drop");

    assert_eq!(
        destination_result.expect("destination I/O must succeed"),
        b"ping-more"
    );
    assert_eq!(client_result.expect("client I/O must succeed"), b"pong");
    assert!(
        line_stats.uplink_bytes() > 0,
        "post-outage records must still move through the raw splice"
    );
}

async fn bind_loopback_again(address: std::net::SocketAddr) -> TcpListener {
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

/// After a listen-only Handoff outage, the same [`HandoffLine`] must be
/// able to transfer again once a listener returns on that landing address.
/// Complements the #474 refuse-new-transfer tests. Does not claim field RCA
/// for #253 and does not change production or campaign contracts.
#[tokio::test(flavor = "current_thread")]
async fn listen_only_handoff_landing_outage_recovers_when_listener_returns() {
    let landing_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("landing must bind");
    let landing_address = landing_listener
        .local_addr()
        .expect("landing address must exist");
    let fd_budget = FdBudget::new(4_096);
    let line = handoff_line(landing_address);
    let state = test_state(Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 9));

    drop(landing_listener);
    let refused = match line.transfer(&fd_budget, &state, [0x49; 32]).await {
        Err(error) => error,
        Ok(_) => panic!("new handoff transfers must be refused while the landing listener is down"),
    };
    match refused {
        HandoffLineError::Connect(source) => {
            assert_eq!(source.kind(), io::ErrorKind::ConnectionRefused);
            assert_eq!(
                source.raw_os_error(),
                Some(111),
                "Linux ECONNREFUSED errno must be 111"
            );
        }
        other => panic!("expected HandoffLineError::Connect ECONNREFUSED, got {other}"),
    }

    let landing_listener = bind_loopback_again(landing_address).await;
    let landing = async {
        let (stream, _) = landing_listener.accept().await?;
        let mut header = [0_u8; HEADER_LEN];
        let mut stream = stream;
        stream.read_exact(&mut header).await?;
        let total = message_len_from_header(&header).map_err(io::Error::other)?;
        let mut remainder = vec![0_u8; total - HEADER_LEN];
        stream.read_exact(&mut remainder).await?;
        Ok::<_, io::Error>(())
    };
    let recovered = async {
        let (stream, permit) = line
            .transfer(&fd_budget, &state, [0x4a; 32])
            .await
            .expect("the same HandoffLine must transfer after the landing listener returns");
        drop(stream);
        drop(permit);
    };

    let (landing, ()) = timeout(TEST_TIMEOUT, async { tokio::join!(landing, recovered) })
        .await
        .expect("Handoff recovery exchange must not time out");
    landing.expect("recovered landing must consume the new transfer");
}
