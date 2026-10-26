//! Vision session integration and unit tests.
//!
//! Kept in a dedicated file so production orchestration stays readable.

use crate::runtime::policy::{DirectBarrierPolicy, ResourceGovernorPolicy};
use std::{io, net::Ipv4Addr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Instant, timeout},
};

use super::{
    BoundaryBytes, NestedTlsDetector, PaddingDecision, SessionContext, VisionHandler,
    VisionSessionError, is_benign_teardown, length_u64, run_directional,
};
use crate::{
    config::node::{routing::RoutingConfig, user::UserConfig},
    protocol::{
        reality::tls13::{
            CipherSuite, ContentType, EstablishedTls, Tls13RecordLayer, TlsApplicationIo,
            TrafficSecret, read_tls_record,
        },
        vless::{
            Command, UserId, VERSION, VISION_FLOW, VISION_FRAME_SIZE, VisionCommand, VisionDecoder,
            VisionEncoder, VisionMode,
        },
    },
    server::{
        direct::{DirectHandoff, Direction},
        outbound::OutboundRegistry,
        reality::RealityEstablished,
        routing::{EmptyAssetMatcher, RoutingTable},
    },
    transport::{FdBudget, RelayBackend, TcpRelay, TcpRelayConfig},
};

const TEST_TIMEOUT: Duration = Duration::from_secs(2);
const USER: UserId = UserId::new([0x33; 16]);

#[tokio::test(flavor = "current_thread")]
async fn successful_handoff_reunite_preserves_graceful_carrier_close() {
    let (client, _client_peer) = tcp_pair().await;
    let (landing, mut landing_peer) = tcp_pair().await;
    let (reader, writer) = client.into_split();
    let _client = super::handoff_resume::reunite_handoff_client(reader, writer, &landing)
        .expect("matching client halves must reunite");
    drop(landing);
    let mut byte = [0_u8; 1];
    let read = timeout(TEST_TIMEOUT, landing_peer.read(&mut byte))
        .await
        .expect("carrier close must be observable")
        .expect("successful reunification must not arm an abortive carrier close");
    assert_eq!(read, 0, "healthy carrier teardown must deliver FIN");
}

#[tokio::test(flavor = "current_thread")]
async fn failed_handoff_reunite_still_aborts_carrier() {
    let (first, _first_peer) = tcp_pair().await;
    let (second, _second_peer) = tcp_pair().await;
    let (landing, mut landing_peer) = tcp_pair().await;
    let (reader, _first_writer) = first.into_split();
    let (_second_reader, writer) = second.into_split();
    let error = super::handoff_resume::reunite_handoff_client(reader, writer, &landing)
        .expect_err("unrelated client halves must fail closed");
    assert!(matches!(
        error,
        VisionSessionError::HandoffLine(crate::server::handoff::HandoffLineError::Reunite)
    ));
    drop(landing);
    let mut byte = [0_u8; 1];
    let error = timeout(TEST_TIMEOUT, landing_peer.read(&mut byte))
        .await
        .expect("carrier abort must be observable")
        .expect_err("failed reunification must reset the carrier");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
}

#[tokio::test(flavor = "current_thread")]
async fn resumed_framed_session_survives_both_asymmetries_and_sparse_alternation() {
    let (mut client, inbound) = tcp_pair().await;
    let (destination, mut target) = tcp_pair().await;
    let (tls, mut client_write, mut client_read) = tls_states();
    let (reader, writer) = TlsApplicationIo::new(inbound, tls).into_owned_split();
    let relay = TcpRelay::new(TcpRelayConfig::for_test(), FdBudget::new(4_096)).expect("relay");
    let mut encoder = VisionEncoder::with_padding_seed(USER, &[0x5a; 44]);
    let mut initial = Vec::new();
    encoder
        .encode(b"request", VisionCommand::Continue, false, &mut initial)
        .expect("initial frame");
    let session = super::run_resumed_session(
        reader,
        writer,
        destination,
        USER,
        initial,
        &relay,
        Duration::from_millis(20),
    );
    let traffic = async {
        let mut request = [0; 7];
        target.read_exact(&mut request).await?;
        assert_eq!(&request, b"request");
        let mut decoder = VisionDecoder::new(USER);
        let mut first = true;
        let mut decoded = Vec::new();
        let mut wire = Vec::new();
        for phase in 0..3 {
            for tick in 0..8 {
                // The successful receive synchronizes each progress event.
                // One direction is silent for 120ms with a 20ms old window.
                tokio::time::sleep(Duration::from_millis(15)).await;
                if phase == 1 || (phase == 2 && tick % 2 == 0) {
                    let mut frame = Vec::new();
                    encoder
                        .encode(b"U", VisionCommand::Continue, false, &mut frame)
                        .map_err(io::Error::other)?;
                    wire.clear();
                    client_write
                        .seal_into(ContentType::ApplicationData, &frame, 0, &mut wire)
                        .map_err(io::Error::other)?;
                    client.write_all(&wire).await?;
                    let mut byte = [0];
                    target.read_exact(&mut byte).await?;
                    assert_eq!(&byte, b"U");
                } else {
                    // The origin remains open and waits for receipt before
                    // its next write: short replies must not wait for FIN.
                    target.write_all(b"ack").await?;
                    let mut response = Vec::new();
                    while response.len() < 3 {
                        let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                            .await
                            .map_err(io::Error::other)?
                            .into_wire();
                        let opened = client_read
                            .open_in_place(&mut record)
                            .map_err(io::Error::other)?;
                        let payload = if first {
                            first = false;
                            &opened.plaintext()[2..]
                        } else {
                            opened.plaintext()
                        };
                        decoder
                            .decode(payload, &mut decoded)
                            .map_err(io::Error::other)?;
                        response.extend_from_slice(&decoded);
                    }
                    assert_eq!(response, b"ack");
                }
            }
        }
        wire.clear();
        client_write
            .seal_into(ContentType::Alert, &[1, 0], 0, &mut wire)
            .map_err(io::Error::other)?;
        client.write_all(&wire).await?;
        assert_eq!(target.read(&mut [0]).await?, 0, "uplink FIN");
        // A framed half-close also permits delayed downlink draining.
        tokio::time::sleep(Duration::from_millis(80)).await;
        target.write_all(b"tail!").await?;
        target.shutdown().await?;
        let mut tail = Vec::new();
        loop {
            let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                .await
                .map_err(io::Error::other)?
                .into_wire();
            let opened = client_read
                .open_in_place(&mut record)
                .map_err(io::Error::other)?;
            if opened.content_type() == ContentType::Alert {
                assert_eq!(opened.plaintext(), &[1, 0]);
                break;
            }
            decoder
                .decode(opened.plaintext(), &mut decoded)
                .map_err(io::Error::other)?;
            tail.extend_from_slice(&decoded);
        }
        assert_eq!(tail, b"tail!");
        Ok::<_, io::Error>(())
    };
    let (stats, traffic) = timeout(TEST_TIMEOUT, async { tokio::join!(session, traffic) })
        .await
        .expect("bounded regression");
    traffic.expect("both directions remain byte-exact");
    let stats = stats.expect("healthy asymmetric session");
    assert_eq!(stats.uplink_bytes(), 19);
    assert_eq!(stats.downlink_bytes(), 41);
    assert!(!stats.uplink_direct());
    assert!(!stats.downlink_direct());
}

#[tokio::test(flavor = "current_thread")]
async fn relays_non_tls_vision_session_inside_reality_records() {
    let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("destination must bind");
    let destination_address = destination_listener
        .local_addr()
        .expect("destination address must exist");
    let (mut client, server) = tcp_pair().await;
    let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
    let established =
        RealityEstablished::from_test_parts(TlsApplicationIo::new(server, established_tls), USER);
    let governor = ResourceGovernorPolicy {
        connect_timeout_ms: 1_000,
        handshake_timeout_ms: 1_000,
        fallback_timeout_ms: 1_000,
        ..ResourceGovernorPolicy::default()
    };
    let handler = direct_handler(&governor);
    let request = vision_request(destination_address.port(), b"ping");

    let exchange = async {
        let handle = handler.handle(established);
        let client_io = async {
            let mut request_record = Vec::new();
            client_write_records
                .seal_into(
                    ContentType::ApplicationData,
                    &request,
                    0,
                    &mut request_record,
                )
                .map_err(io::Error::other)?;
            client.write_all(&request_record).await?;
            let mut close_record = Vec::new();
            client_write_records
                .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                .map_err(io::Error::other)?;
            client.write_all(&close_record).await?;

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
            Ok::<_, io::Error>((response, decoder.mode()))
        };
        let destination_io = async {
            let (mut destination, _) = destination_listener.accept().await?;
            let mut request = Vec::new();
            destination.read_to_end(&mut request).await?;
            destination.write_all(b"pong").await?;
            destination.shutdown().await?;
            Ok::<_, io::Error>(request)
        };
        tokio::join!(handle, client_io, destination_io)
    };
    let (stats, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("Vision exchange must not time out");
    let stats = stats.expect("Vision handler must succeed");
    let (response, mode) = client_result.expect("client I/O must succeed");

    assert_eq!(
        destination_result.expect("destination I/O must succeed"),
        b"ping"
    );
    assert_eq!(response, b"pong");
    assert_eq!(mode, VisionMode::Raw);
    assert_eq!(stats.uplink_bytes(), 4);
    assert_eq!(stats.downlink_bytes(), 4);
    assert!(!stats.uplink_direct());
    assert!(!stats.downlink_direct());
}

#[tokio::test(flavor = "current_thread")]
async fn switches_both_directions_only_after_authenticated_direct_boundaries() {
    let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("destination must bind");
    let destination_address = destination_listener
        .local_addr()
        .expect("destination address must exist");
    let (mut client, server) = tcp_pair().await;
    let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
    let established =
        RealityEstablished::from_test_parts(TlsApplicationIo::new(server, established_tls), USER);
    let governor = ResourceGovernorPolicy {
        connect_timeout_ms: 1_000,
        handshake_timeout_ms: 1_000,
        fallback_timeout_ms: 1_000,
        ..ResourceGovernorPolicy::default()
    };
    let handler = direct_handler(&governor);
    let request = vision_request_with_command(
        destination_address.port(),
        b"up-framed",
        VisionCommand::Direct,
    );
    let nested_server_hello = record(22, &server_hello(0x1301, true));
    let nested_application = record(23, b"encrypted-handshake");

    let exchange = async {
        let handle = handler.handle(established);
        let client_io = async {
            let mut request_record = Vec::new();
            client_write_records
                .seal_into(
                    ContentType::ApplicationData,
                    &request,
                    0,
                    &mut request_record,
                )
                .map_err(io::Error::other)?;
            client.write_all(&request_record).await?;
            client.write_all(b"up-raw").await?;
            client.shutdown().await?;

            let mut decoder = VisionDecoder::new(USER);
            let mut decoded = Vec::new();
            let mut framed_response = Vec::new();
            let mut response_header = true;
            while decoder.mode() != VisionMode::Direct {
                let mut outer_record = read_tls_record(&mut client, TEST_TIMEOUT)
                    .await
                    .map_err(io::Error::other)?
                    .into_wire();
                let opened = client_read_records
                    .open_in_place(&mut outer_record)
                    .map_err(io::Error::other)?;
                if opened.content_type() != ContentType::ApplicationData {
                    return Err(io::Error::other("expected outer application record"));
                }
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
                framed_response.extend_from_slice(&decoded);
            }
            let mut raw_response = Vec::new();
            client.read_to_end(&mut raw_response).await?;
            Ok::<_, io::Error>((framed_response, raw_response))
        };
        let server_hello = nested_server_hello.clone();
        let application = nested_application.clone();
        let destination_io = async move {
            let (mut destination, _) = destination_listener.accept().await?;
            let mut request = Vec::new();
            destination.read_to_end(&mut request).await?;
            destination.write_all(&server_hello).await?;
            destination.write_all(&application).await?;
            destination.write_all(b"down-raw").await?;
            destination.shutdown().await?;
            Ok::<_, io::Error>(request)
        };
        tokio::join!(handle, client_io, destination_io)
    };
    let (stats, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("direct Vision exchange must not time out");
    let stats = stats.expect("direct Vision handler must succeed");
    let (framed_response, raw_response) = client_result.expect("client I/O must succeed");
    let mut expected_framed = nested_server_hello;
    expected_framed.extend_from_slice(&nested_application);

    assert_eq!(
        destination_result.expect("destination I/O must succeed"),
        b"up-framedup-raw"
    );
    assert_eq!(framed_response, expected_framed);
    assert_eq!(raw_response, b"down-raw");
    assert_eq!(
        stats.uplink_bytes(),
        length_u64(b"up-framed".len() + b"up-raw".len())
    );
    assert_eq!(
        stats.downlink_bytes(),
        length_u64(expected_framed.len() + b"down-raw".len())
    );
    assert!(stats.uplink_direct());
    assert!(stats.downlink_direct());
    // The uplink reaches its Direct boundary while the downlink is still
    // framed, so each direction relays independently rather than waiting
    // to form a pair.
    assert_eq!(stats.relay_backend(), None);
    assert_eq!(stats.uplink_backend(), Some(RelayBackend::Buffered));
    assert_eq!(stats.downlink_backend(), Some(RelayBackend::Buffered));
    assert_eq!(
        stats.uplink_direct_at_bytes(),
        length_u64(b"up-framed".len())
    );
    assert_eq!(
        stats.downlink_direct_at_bytes(),
        length_u64(expected_framed.len())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn one_way_direct_relays_the_direction_independently() {
    let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("destination must bind");
    let destination_address = destination_listener
        .local_addr()
        .expect("destination address must exist");
    let (mut client, server) = tcp_pair().await;
    let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
    let established =
        RealityEstablished::from_test_parts(TlsApplicationIo::new(server, established_tls), USER);
    let governor = ResourceGovernorPolicy {
        connect_timeout_ms: 1_000,
        handshake_timeout_ms: 1_000,
        fallback_timeout_ms: 1_000,
        ..ResourceGovernorPolicy::default()
    };
    let mut handler = direct_handler(&governor);
    handler.io_timeout = Duration::from_millis(20);
    let request = vision_request_with_command(
        destination_address.port(),
        b"up-framed",
        VisionCommand::Direct,
    );
    // The destination never speaks TLS, so the downlink can never reach a
    // Direct boundary. The uplink must therefore relay its raw direction
    // independently — reporting a backend — while the downlink continues
    // framed outer TLS undisturbed.
    let uplink_raw = vec![0x5a_u8; 96 * 1024];
    let downlink_part_one = b"plain-http-part-one";
    let downlink_part_two = b"plain-http-part-two";

    let expected_uplink = uplink_raw.clone();
    let exchange = async {
        let handle = handler.handle(established);
        let raw = uplink_raw.clone();
        let client_io = async {
            let mut request_record = Vec::new();
            client_write_records
                .seal_into(
                    ContentType::ApplicationData,
                    &request,
                    0,
                    &mut request_record,
                )
                .map_err(io::Error::other)?;
            client.write_all(&request_record).await?;
            tokio::time::sleep(Duration::from_millis(80)).await;
            client.write_all(&raw).await?;
            client.shutdown().await?;

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
            Ok::<_, io::Error>(response)
        };
        let destination_io = async move {
            let (mut destination, _) = destination_listener.accept().await?;
            destination.write_all(downlink_part_one).await?;
            // `read_to_end` only completes once the directional uplink
            // relay propagated the client EOF as a write-side shutdown of
            // the destination socket. Writing *after* that EOF proves the
            // half-close left the peer direction fully operational.
            let mut request = Vec::new();
            destination.read_to_end(&mut request).await?;
            tokio::time::sleep(Duration::from_millis(80)).await;
            destination.write_all(downlink_part_two).await?;
            destination.shutdown().await?;
            Ok::<_, io::Error>(request)
        };
        tokio::join!(handle, client_io, destination_io)
    };
    let (stats, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("one-way direct exchange must not time out");
    let stats = stats.expect("one-way direct handler must succeed");
    let response = client_result.expect("client I/O must succeed");
    let mut expected = b"up-framed".to_vec();
    expected.extend_from_slice(&expected_uplink);
    let mut expected_downlink = downlink_part_one.to_vec();
    expected_downlink.extend_from_slice(downlink_part_two);

    assert_eq!(
        destination_result.expect("destination I/O must succeed"),
        expected,
        "every raw uplink byte must reach the destination in order"
    );
    assert_eq!(
        response, expected_downlink,
        "the framed downlink must survive the directional uplink's half-close"
    );
    assert!(
        stats.uplink_direct(),
        "the uplink authenticated a Direct command"
    );
    assert!(
        !stats.downlink_direct(),
        "a non-TLS destination must never reach a Direct boundary"
    );
    assert_eq!(stats.uplink_bytes(), length_u64(expected.len()));
    assert_eq!(stats.downlink_bytes(), length_u64(expected_downlink.len()));
    assert_eq!(
        stats.uplink_backend(),
        Some(RelayBackend::Buffered),
        "the directional uplink relay must report the backend that moved its bytes"
    );
    assert_eq!(stats.downlink_backend(), None);
    assert_eq!(
        stats.relay_backend(),
        None,
        "no bilateral handoff happened for a one-way Direct session"
    );
    assert_eq!(
        stats.uplink_direct_at_bytes(),
        length_u64(b"up-framed".len()),
        "the boundary byte count excludes the raw phase"
    );
    assert_eq!(stats.downlink_direct_at_bytes(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn bilateral_direct_handoff_transfers_large_payloads_byte_exactly() {
    let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("destination must bind");
    let destination_address = destination_listener
        .local_addr()
        .expect("destination address must exist");
    let (mut client, server) = tcp_pair().await;
    let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
    let established =
        RealityEstablished::from_test_parts(TlsApplicationIo::new(server, established_tls), USER);
    let governor = ResourceGovernorPolicy {
        connect_timeout_ms: 2_000,
        handshake_timeout_ms: 2_000,
        fallback_timeout_ms: 2_000,
        ..ResourceGovernorPolicy::default()
    };
    let handler = direct_handler(&governor);
    // The client's first frame continues; the client follows with its own
    // Direct frame only after the server sent its Direct frame, which is
    // the real Vision flow. The downlink therefore reaches its boundary
    // first and is still at `RawReady` when the uplink arrives, so the
    // uplink commits to the pair and the downlink — resuming while the
    // peer is `PairPending` — deposits last and runs the bilateral relay.
    let mut addons = vec![0x0a, 0x10];
    addons.extend_from_slice(VISION_FLOW.as_bytes());
    let mut request = Vec::new();
    request.push(VERSION);
    request.extend_from_slice(USER.as_bytes());
    request.push(u8::try_from(addons.len()).unwrap_or(u8::MAX));
    request.extend_from_slice(&addons);
    request.push(Command::Tcp.as_byte());
    request.extend_from_slice(&destination_address.port().to_be_bytes());
    request.push(1);
    request.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
    let mut uplink_encoder = VisionEncoder::with_padding_seed(USER, &[0x5a; 44]);
    let mut first_frame = Vec::new();
    uplink_encoder
        .encode(
            b"up-framed",
            VisionCommand::Continue,
            false,
            &mut first_frame,
        )
        .expect("Vision payload must encode");
    request.extend_from_slice(&first_frame);
    let nested_server_hello = record(22, &server_hello(0x1301, true));
    let nested_application = record(23, b"encrypted-handshake");
    let uplink_raw: Vec<u8> = (0..512_u32 * 1024).map(|value| value as u8).collect();
    let downlink_raw: Vec<u8> = (0..512_u32 * 1024)
        .map(|value| (value >> 3) as u8)
        .collect();

    let expected_down = downlink_raw.clone();
    let exchange = async {
        let handle = handler.handle(established);
        let raw = uplink_raw.clone();
        let client_io = async {
            let mut request_record = Vec::new();
            client_write_records
                .seal_into(
                    ContentType::ApplicationData,
                    &request,
                    0,
                    &mut request_record,
                )
                .map_err(io::Error::other)?;
            client.write_all(&request_record).await?;

            let mut decoder = VisionDecoder::new(USER);
            let mut decoded = Vec::new();
            let mut framed = Vec::new();
            let mut response_header = true;
            while decoder.mode() != VisionMode::Direct {
                let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                    .await
                    .map_err(io::Error::other)?
                    .into_wire();
                let opened = client_read_records
                    .open_in_place(&mut record)
                    .map_err(io::Error::other)?;
                let plaintext = opened.plaintext();
                let vision = if response_header {
                    response_header = false;
                    &plaintext[2..]
                } else {
                    plaintext
                };
                let _ = decoder
                    .decode(vision, &mut decoded)
                    .map_err(io::Error::other)?;
                framed.extend_from_slice(&decoded);
            }

            let mut direct_frame = Vec::new();
            uplink_encoder
                .encode(b"", VisionCommand::Direct, false, &mut direct_frame)
                .map_err(io::Error::other)?;
            let mut direct_record = Vec::new();
            client_write_records
                .seal_into(
                    ContentType::ApplicationData,
                    &direct_frame,
                    0,
                    &mut direct_record,
                )
                .map_err(io::Error::other)?;
            client.write_all(&direct_record).await?;

            let (mut reader, mut writer) = client.into_split();
            let send = async move {
                writer.write_all(&raw).await?;
                writer.shutdown().await?;
                Ok::<_, io::Error>(())
            };
            let receive = async move {
                let mut received = Vec::new();
                reader.read_to_end(&mut received).await?;
                Ok::<_, io::Error>(received)
            };
            let (sent, received) = tokio::join!(send, receive);
            sent?;
            Ok::<_, io::Error>((framed, received?))
        };
        let server_hello_record = nested_server_hello.clone();
        let application_record = nested_application.clone();
        let down = downlink_raw.clone();
        let destination_io = async move {
            let (destination, _) = destination_listener.accept().await?;
            let (mut reader, mut writer) = destination.into_split();
            let send = async move {
                writer.write_all(&server_hello_record).await?;
                writer.write_all(&application_record).await?;
                writer.write_all(&down).await?;
                writer.shutdown().await?;
                Ok::<_, io::Error>(())
            };
            let receive = async move {
                let mut received = Vec::new();
                reader.read_to_end(&mut received).await?;
                Ok::<_, io::Error>(received)
            };
            let (sent, received) = tokio::join!(send, receive);
            sent?;
            received
        };
        tokio::join!(handle, client_io, destination_io)
    };
    let (stats, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("bilateral direct exchange must not time out");
    let stats = stats.expect("bilateral direct handler must succeed");
    let (framed, raw_response) = client_result.expect("client I/O must succeed");
    let received_up = destination_result.expect("destination I/O must succeed");
    let mut expected_framed = nested_server_hello;
    expected_framed.extend_from_slice(&nested_application);
    let mut expected_up = b"up-framed".to_vec();
    expected_up.extend_from_slice(&uplink_raw);
    assert_eq!(framed, expected_framed);
    assert_eq!(
        received_up.len(),
        expected_up.len(),
        "the handed-off relay must transfer every uplink byte"
    );
    assert_eq!(received_up, expected_up);
    assert_eq!(
        raw_response.len(),
        expected_down.len(),
        "the handed-off relay must transfer every downlink byte"
    );
    assert_eq!(raw_response, expected_down);
    assert!(stats.uplink_direct());
    assert!(stats.downlink_direct());
    assert_eq!(stats.uplink_bytes(), length_u64(expected_up.len()));
    assert_eq!(
        stats.downlink_bytes(),
        length_u64(expected_framed.len() + expected_down.len())
    );
    assert_eq!(
        stats.relay_backend(),
        Some(RelayBackend::Buffered),
        "both directions paired, so the pair relay moved the raw bytes"
    );
    assert_eq!(stats.uplink_backend(), Some(RelayBackend::Buffered));
    assert_eq!(stats.downlink_backend(), Some(RelayBackend::Buffered));
    assert_eq!(
        stats.uplink_direct_at_bytes(),
        length_u64(b"up-framed".len())
    );
    assert_eq!(
        stats.downlink_direct_at_bytes(),
        length_u64(expected_framed.len())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn one_way_direct_downlink_relays_independently() {
    let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("destination must bind");
    let destination_address = destination_listener
        .local_addr()
        .expect("destination address must exist");
    let (mut client, server) = tcp_pair().await;
    let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
    let established =
        RealityEstablished::from_test_parts(TlsApplicationIo::new(server, established_tls), USER);
    let governor = ResourceGovernorPolicy {
        connect_timeout_ms: 1_000,
        handshake_timeout_ms: 1_000,
        fallback_timeout_ms: 1_000,
        ..ResourceGovernorPolicy::default()
    };
    let handler = direct_handler(&governor);
    // The client ends its Vision flow (`End`), so the uplink stays in
    // framed pass-through and never reaches a Direct boundary. The
    // destination speaks TLS 1.3, so the downlink goes Direct alone and
    // must relay its direction independently.
    let request =
        vision_request_with_command(destination_address.port(), b"up-ping", VisionCommand::End);
    let nested_server_hello = record(22, &server_hello(0x1301, true));
    let nested_application = record(23, b"encrypted-handshake");

    let exchange = async {
        let handle = handler.handle(established);
        let client_io = async {
            let mut request_record = Vec::new();
            client_write_records
                .seal_into(
                    ContentType::ApplicationData,
                    &request,
                    0,
                    &mut request_record,
                )
                .map_err(io::Error::other)?;
            client.write_all(&request_record).await?;
            let mut more_record = Vec::new();
            client_write_records
                .seal_into(
                    ContentType::ApplicationData,
                    b"up-more",
                    0,
                    &mut more_record,
                )
                .map_err(io::Error::other)?;
            client.write_all(&more_record).await?;
            let mut close_record = Vec::new();
            client_write_records
                .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                .map_err(io::Error::other)?;
            client.write_all(&close_record).await?;

            let mut decoder = VisionDecoder::new(USER);
            let mut decoded = Vec::new();
            let mut framed = Vec::new();
            let mut response_header = true;
            while decoder.mode() != VisionMode::Direct {
                let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                    .await
                    .map_err(io::Error::other)?
                    .into_wire();
                let opened = client_read_records
                    .open_in_place(&mut record)
                    .map_err(io::Error::other)?;
                let plaintext = opened.plaintext();
                let vision = if response_header {
                    response_header = false;
                    &plaintext[2..]
                } else {
                    plaintext
                };
                let _ = decoder
                    .decode(vision, &mut decoded)
                    .map_err(io::Error::other)?;
                framed.extend_from_slice(&decoded);
            }
            let mut raw_response = Vec::new();
            client.read_to_end(&mut raw_response).await?;
            Ok::<_, io::Error>((framed, raw_response))
        };
        let server_hello_record = nested_server_hello.clone();
        let application_record = nested_application.clone();
        let destination_io = async move {
            let (mut destination, _) = destination_listener.accept().await?;
            destination.write_all(&server_hello_record).await?;
            destination.write_all(&application_record).await?;
            destination.write_all(b"down-raw").await?;
            destination.shutdown().await?;
            let mut received = Vec::new();
            destination.read_to_end(&mut received).await?;
            Ok::<_, io::Error>(received)
        };
        tokio::join!(handle, client_io, destination_io)
    };
    let (stats, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("downlink direct exchange must not time out");
    let stats = stats.expect("downlink direct handler must succeed");
    let (framed, raw_response) = client_result.expect("client I/O must succeed");
    let mut expected_framed = nested_server_hello;
    expected_framed.extend_from_slice(&nested_application);

    assert_eq!(
        destination_result.expect("destination I/O must succeed"),
        b"up-pingup-more",
        "the framed uplink pass-through must stay undisturbed"
    );
    assert_eq!(framed, expected_framed);
    assert_eq!(raw_response, b"down-raw");
    assert!(
        !stats.uplink_direct(),
        "an End flow never reaches an uplink Direct boundary"
    );
    assert!(stats.downlink_direct());
    assert_eq!(
        stats.uplink_bytes(),
        length_u64(b"up-ping".len() + b"up-more".len())
    );
    assert_eq!(
        stats.downlink_bytes(),
        length_u64(expected_framed.len() + b"down-raw".len())
    );
    assert_eq!(stats.relay_backend(), None);
    assert_eq!(stats.uplink_backend(), None);
    assert_eq!(
        stats.downlink_backend(),
        Some(RelayBackend::Buffered),
        "the directional downlink relay must report its backend"
    );
    assert_eq!(stats.uplink_direct_at_bytes(), 0);
    assert_eq!(
        stats.downlink_direct_at_bytes(),
        length_u64(expected_framed.len())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn packs_multiple_vision_frames_into_one_outer_record() {
    let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("destination must bind");
    let destination_address = destination_listener
        .local_addr()
        .expect("destination address must exist");
    let (mut client, server) = tcp_pair().await;
    let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
    let established =
        RealityEstablished::from_test_parts(TlsApplicationIo::new(server, established_tls), USER);
    let governor = ResourceGovernorPolicy {
        connect_timeout_ms: 1_000,
        handshake_timeout_ms: 1_000,
        fallback_timeout_ms: 1_000,
        ..ResourceGovernorPolicy::default()
    };
    let handler = direct_handler(&governor);
    let request = vision_request(destination_address.port(), b"up-ping");
    let nested_server_hello = record(22, &server_hello(0x1301, true));
    // A maximum-sized nested handshake record is framed as three Vision
    // frames; the two full frames carry no padding and must share one
    // maximum-sized outer record.
    let nested_certificate = record(22, &[0x5a_u8; 16_384]);
    let nested_application = record(23, b"encrypted-handshake");

    let exchange = async {
        let handle = handler.handle(established);
        let client_io = async {
            let mut request_record = Vec::new();
            client_write_records
                .seal_into(
                    ContentType::ApplicationData,
                    &request,
                    0,
                    &mut request_record,
                )
                .map_err(io::Error::other)?;
            client.write_all(&request_record).await?;
            let mut close_record = Vec::new();
            client_write_records
                .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                .map_err(io::Error::other)?;
            client.write_all(&close_record).await?;

            let mut decoder = VisionDecoder::new(USER);
            let mut decoded = Vec::new();
            let mut framed = Vec::new();
            let mut outer_records = 0_usize;
            let mut saw_packed_record = false;
            let mut response_header = true;
            while decoder.mode() != VisionMode::Direct {
                let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                    .await
                    .map_err(io::Error::other)?
                    .into_wire();
                let opened = client_read_records
                    .open_in_place(&mut record)
                    .map_err(io::Error::other)?;
                if opened.content_type() != ContentType::ApplicationData {
                    return Err(io::Error::other("expected outer application record"));
                }
                let plaintext = opened.plaintext();
                outer_records += 1;
                saw_packed_record |= plaintext.len() > VISION_FRAME_SIZE;
                let vision = if response_header {
                    response_header = false;
                    &plaintext[2..]
                } else {
                    plaintext
                };
                let _ = decoder
                    .decode(vision, &mut decoded)
                    .map_err(io::Error::other)?;
                framed.extend_from_slice(&decoded);
            }
            let mut raw_response = Vec::new();
            client.read_to_end(&mut raw_response).await?;
            Ok::<_, io::Error>((framed, raw_response, outer_records, saw_packed_record))
        };
        let server_hello_record = nested_server_hello.clone();
        let certificate_record = nested_certificate.clone();
        let application_record = nested_application.clone();
        let destination_io = async move {
            let (mut destination, _) = destination_listener.accept().await?;
            destination.write_all(&server_hello_record).await?;
            destination.write_all(&certificate_record).await?;
            destination.write_all(&application_record).await?;
            destination.write_all(b"down-raw").await?;
            destination.shutdown().await?;
            let mut received = Vec::new();
            destination.read_to_end(&mut received).await?;
            Ok::<_, io::Error>(received)
        };
        tokio::join!(handle, client_io, destination_io)
    };
    let (stats, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("packed Vision exchange must not time out");
    let stats = stats.expect("packed Vision handler must succeed");
    let (framed, raw_response, outer_records, saw_packed_record) =
        client_result.expect("client I/O must succeed");
    let mut expected_framed = nested_server_hello;
    expected_framed.extend_from_slice(&nested_certificate);
    expected_framed.extend_from_slice(&nested_application);

    assert_eq!(
        destination_result.expect("destination I/O must succeed"),
        b"up-ping"
    );
    assert_eq!(
        framed, expected_framed,
        "frames packed into shared outer records must decode byte-exactly"
    );
    assert_eq!(raw_response, b"down-raw");
    // Preamble, ServerHello frame, two records for the three certificate
    // frames, and the Direct frame: five records where unpacked framing
    // needed six.
    assert_eq!(outer_records, 5, "full frames must share outer records");
    assert!(
        saw_packed_record,
        "one outer record must carry more than one Vision frame"
    );
    assert!(stats.downlink_direct());
    assert_eq!(
        stats.downlink_bytes(),
        length_u64(expected_framed.len() + b"down-raw".len())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn uplink_direct_drains_pipelined_raw_bytes_ahead_of_the_raw_relay() {
    let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("destination must bind");
    let destination_address = destination_listener
        .local_addr()
        .expect("destination address must exist");
    let (mut client, server) = tcp_pair().await;
    let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
    let established =
        RealityEstablished::from_test_parts(TlsApplicationIo::new(server, established_tls), USER);
    let governor = ResourceGovernorPolicy {
        connect_timeout_ms: 1_000,
        handshake_timeout_ms: 1_000,
        fallback_timeout_ms: 1_000,
        ..ResourceGovernorPolicy::default()
    };
    let handler = direct_handler(&governor);
    let request = vision_request_with_command(
        destination_address.port(),
        b"up-framed",
        VisionCommand::Direct,
    );

    let exchange = async {
        let handle = handler.handle(established);
        let client_io = async {
            let mut burst = Vec::new();
            client_write_records
                .seal_into(ContentType::ApplicationData, &request, 0, &mut burst)
                .map_err(io::Error::other)?;
            // The over-read regression shape: the boundary outer record and
            // the post-boundary raw bytes arrive in ONE socket burst, so the
            // buffered reader must drain them to the destination in order.
            burst.extend_from_slice(b"up-raw-pipelined");
            client.write_all(&burst).await?;
            client.shutdown().await?;

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
            Ok::<_, io::Error>(response)
        };
        let destination_io = async {
            let (mut destination, _) = destination_listener.accept().await?;
            let mut request = Vec::new();
            destination.read_to_end(&mut request).await?;
            destination.write_all(b"pong").await?;
            destination.shutdown().await?;
            Ok::<_, io::Error>(request)
        };
        tokio::join!(handle, client_io, destination_io)
    };
    let (stats, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("pipelined direct exchange must not time out");
    let stats = stats.expect("pipelined direct handler must succeed");

    assert_eq!(
        destination_result.expect("destination I/O must succeed"),
        b"up-framedup-raw-pipelined",
        "the drained pending bytes must reach the destination in order, after the framed prefix"
    );
    assert_eq!(client_result.expect("client I/O must succeed"), b"pong");
    assert!(stats.uplink_direct());
    assert_eq!(
        stats.uplink_bytes(),
        length_u64(b"up-framed".len() + b"up-raw-pipelined".len()),
        "pending bytes count toward the uplink total exactly once"
    );
    assert_eq!(
        stats.uplink_direct_at_bytes(),
        length_u64(b"up-framed".len()),
        "the boundary byte count excludes the raw phase, drained or relayed"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn downlink_direct_drains_pipelined_raw_bytes_ahead_of_the_raw_relay() {
    let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("destination must bind");
    let destination_address = destination_listener
        .local_addr()
        .expect("destination address must exist");
    let (mut client, server) = tcp_pair().await;
    let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
    let established =
        RealityEstablished::from_test_parts(TlsApplicationIo::new(server, established_tls), USER);
    let governor = ResourceGovernorPolicy {
        connect_timeout_ms: 1_000,
        handshake_timeout_ms: 1_000,
        fallback_timeout_ms: 1_000,
        ..ResourceGovernorPolicy::default()
    };
    let handler = direct_handler(&governor);
    let request =
        vision_request_with_command(destination_address.port(), b"up-ping", VisionCommand::End);
    let nested_server_hello = record(22, &server_hello(0x1301, true));
    let nested_application = record(23, b"encrypted-handshake");

    let exchange = async {
        let handle = handler.handle(established);
        let client_io = async {
            let mut request_record = Vec::new();
            client_write_records
                .seal_into(
                    ContentType::ApplicationData,
                    &request,
                    0,
                    &mut request_record,
                )
                .map_err(io::Error::other)?;
            client.write_all(&request_record).await?;
            let mut close_record = Vec::new();
            client_write_records
                .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                .map_err(io::Error::other)?;
            client.write_all(&close_record).await?;

            let mut decoder = VisionDecoder::new(USER);
            let mut decoded = Vec::new();
            let mut framed = Vec::new();
            let mut response_header = true;
            while decoder.mode() != VisionMode::Direct {
                let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                    .await
                    .map_err(io::Error::other)?
                    .into_wire();
                let opened = client_read_records
                    .open_in_place(&mut record)
                    .map_err(io::Error::other)?;
                let plaintext = opened.plaintext();
                let vision = if response_header {
                    response_header = false;
                    &plaintext[2..]
                } else {
                    plaintext
                };
                let _ = decoder
                    .decode(vision, &mut decoded)
                    .map_err(io::Error::other)?;
                framed.extend_from_slice(&decoded);
            }
            let mut raw_response = Vec::new();
            client.read_to_end(&mut raw_response).await?;
            Ok::<_, io::Error>((framed, raw_response))
        };
        let server_hello_record = nested_server_hello.clone();
        let application_record = nested_application.clone();
        let destination_io = async move {
            let (mut destination, _) = destination_listener.accept().await?;
            // One burst: the classification flight, the boundary record, and
            // the post-boundary raw bytes land in the nested reader's buffer
            // together, so the Direct drain must forward them in order.
            let mut burst = server_hello_record;
            burst.extend_from_slice(&application_record);
            burst.extend_from_slice(b"down-raw-pipelined");
            destination.write_all(&burst).await?;
            destination.shutdown().await?;
            let mut received = Vec::new();
            destination.read_to_end(&mut received).await?;
            Ok::<_, io::Error>(received)
        };
        tokio::join!(handle, client_io, destination_io)
    };
    let (stats, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("pipelined downlink exchange must not time out");
    let stats = stats.expect("pipelined downlink handler must succeed");
    let (framed, raw_response) = client_result.expect("client I/O must succeed");
    let mut expected_framed = nested_server_hello;
    expected_framed.extend_from_slice(&nested_application);

    assert_eq!(
        destination_result.expect("destination I/O must succeed"),
        b"up-ping"
    );
    assert_eq!(framed, expected_framed);
    assert_eq!(
        raw_response, b"down-raw-pipelined",
        "the drained pending bytes must reach the client after the framed records, in order"
    );
    assert!(stats.downlink_direct());
    assert_eq!(
        stats.downlink_bytes(),
        length_u64(expected_framed.len() + b"down-raw-pipelined".len())
    );
    assert_eq!(
        stats.downlink_direct_at_bytes(),
        length_u64(expected_framed.len())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn outer_downlink_forwards_bytes_buffered_by_classification() {
    let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("destination must bind");
    let destination_address = destination_listener
        .local_addr()
        .expect("destination address must exist");
    let (mut client, server) = tcp_pair().await;
    let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
    let established =
        RealityEstablished::from_test_parts(TlsApplicationIo::new(server, established_tls), USER);
    let governor = ResourceGovernorPolicy {
        connect_timeout_ms: 1_000,
        handshake_timeout_ms: 1_000,
        fallback_timeout_ms: 1_000,
        ..ResourceGovernorPolicy::default()
    };
    let handler = direct_handler(&governor);
    let request = vision_request(destination_address.port(), b"ping");
    // A non-TLS payload larger than the five classification bytes: the
    // classification read buffers the whole burst, returns the header
    // prefix as unframed, and the outer downlink must forward the rest
    // from the buffer before touching the socket again.
    let payload: Vec<u8> = (0..16 * 1024_u32)
        .map(|value| 0x61 + (value % 26) as u8)
        .collect();

    let exchange = async {
        let handle = handler.handle(established);
        let client_io = async {
            let mut request_record = Vec::new();
            client_write_records
                .seal_into(
                    ContentType::ApplicationData,
                    &request,
                    0,
                    &mut request_record,
                )
                .map_err(io::Error::other)?;
            client.write_all(&request_record).await?;
            let mut close_record = Vec::new();
            client_write_records
                .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                .map_err(io::Error::other)?;
            client.write_all(&close_record).await?;

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
            Ok::<_, io::Error>(response)
        };
        let downlink = payload.clone();
        let destination_io = async move {
            let (mut destination, _) = destination_listener.accept().await?;
            let mut request = Vec::new();
            destination.read_to_end(&mut request).await?;
            destination.write_all(&downlink).await?;
            destination.shutdown().await?;
            Ok::<_, io::Error>(request)
        };
        tokio::join!(handle, client_io, destination_io)
    };
    let (stats, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("outer downlink exchange must not time out");
    let stats = stats.expect("outer downlink handler must succeed");
    let response = client_result.expect("client I/O must succeed");

    assert_eq!(
        destination_result.expect("destination I/O must succeed"),
        b"ping"
    );
    assert_eq!(
        response, payload,
        "bytes buffered by classification must be forwarded, never lost"
    );
    assert!(!stats.downlink_direct());
    assert_eq!(stats.downlink_bytes(), length_u64(payload.len()));
}

#[tokio::test(flavor = "current_thread")]
async fn short_non_tls_response_progresses_without_origin_eof() {
    for response in [
        b"x".as_slice(),
        b"ok",
        b"xxx",
        b"pong",
        &[22, 4],
        &[22, 3, 5],
    ] {
        let (mut origin, server) = tcp_pair().await;
        let (read_half, _write_half) = server.into_split();
        let mut reader = super::NestedRecordReader::new(read_half);
        reader
            .idle
            .set_activity(Arc::new(crate::io_activity::SessionActivity::default()));
        origin.write_all(response).await.expect("origin response");
        let observed = timeout(TEST_TIMEOUT, reader.next(TEST_TIMEOUT))
            .await
            .expect("response must progress while origin stays open")
            .expect("classification succeeds");
        match observed {
            super::NestedRead::Unframed(bytes) => assert_eq!(bytes, response),
            _ => panic!("plain response must be forwarded as unframed"),
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn short_resumed_response_precedes_origin_fin_with_or_without_uplink_fin() {
    for half_close in [false, true] {
        let (mut client, inbound) = tcp_pair().await;
        let (destination, mut target) = tcp_pair().await;
        let (tls, mut client_write, mut client_read) = tls_states();
        let (reader, writer) = TlsApplicationIo::new(inbound, tls).into_owned_split();
        let relay = TcpRelay::new(TcpRelayConfig::for_test(), FdBudget::new(4_096)).expect("relay");
        let mut encoder = VisionEncoder::with_padding_seed(USER, &[0x5a; 44]);
        let mut initial = Vec::new();
        encoder
            .encode(b"request", VisionCommand::Continue, false, &mut initial)
            .expect("request");
        let session = super::run_resumed_session(
            reader,
            writer,
            destination,
            USER,
            initial,
            &relay,
            TEST_TIMEOUT,
        );
        let traffic = async {
            let mut request = [0; 7];
            target.read_exact(&mut request).await?;
            assert_eq!(&request, b"request");
            let mut wire = Vec::new();
            if half_close {
                client_write
                    .seal_into(ContentType::Alert, &[1, 0], 0, &mut wire)
                    .map_err(io::Error::other)?;
                client.write_all(&wire).await?;
                assert_eq!(target.read(&mut [0]).await?, 0);
            }
            target.write_all(b"pong").await?;
            let mut first = true;
            let mut decoder = VisionDecoder::new(USER);
            let mut decoded = Vec::new();
            let mut response = Vec::new();
            // FIN is deliberately withheld until the complete payload is received.
            while response.len() < 4 {
                let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                    .await
                    .map_err(io::Error::other)?
                    .into_wire();
                let opened = client_read
                    .open_in_place(&mut record)
                    .map_err(io::Error::other)?;
                let payload = if first {
                    first = false;
                    &opened.plaintext()[2..]
                } else {
                    opened.plaintext()
                };
                decoder
                    .decode(payload, &mut decoded)
                    .map_err(io::Error::other)?;
                response.extend_from_slice(&decoded);
            }
            assert_eq!(response, b"pong");
            target.shutdown().await?;
            if !half_close {
                wire.clear();
                client_write
                    .seal_into(ContentType::Alert, &[1, 0], 0, &mut wire)
                    .map_err(io::Error::other)?;
                client.write_all(&wire).await?;
                assert_eq!(target.read(&mut [0]).await?, 0);
            }
            let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                .await
                .map_err(io::Error::other)?
                .into_wire();
            let opened = client_read
                .open_in_place(&mut record)
                .map_err(io::Error::other)?;
            assert_eq!(opened.content_type(), ContentType::Alert);
            Ok::<_, io::Error>(())
        };
        let (stats, traffic) = timeout(TEST_TIMEOUT, async { tokio::join!(session, traffic) })
            .await
            .expect("bounded response");
        traffic.expect("response precedes FIN");
        let stats = stats.expect("healthy session");
        assert_eq!(stats.downlink_bytes(), 4);
        assert!(!stats.downlink_direct());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn plausible_tls_prefix_survives_a_pending_read() {
    let (mut origin, server) = tcp_pair().await;
    let (read_half, _write_half) = server.into_split();
    let mut reader = super::NestedRecordReader::new(read_half);
    reader
        .idle
        .set_activity(Arc::new(crate::io_activity::SessionActivity::default()));
    let hello = record(22, &server_hello(0x1301, true));
    for byte in &hello[..4] {
        origin.write_all(&[*byte]).await.expect("fragment");
        assert!(
            timeout(Duration::from_millis(10), reader.next(TEST_TIMEOUT))
                .await
                .is_err(),
            "a plausible incomplete header must not be downgraded"
        );
    }
    origin
        .write_all(&hello[4..])
        .await
        .expect("remaining record");
    match reader
        .next(TEST_TIMEOUT)
        .await
        .expect("complete TLS record")
    {
        super::NestedRead::Record(bytes) => assert_eq!(bytes, hello),
        _ => panic!("fragmentation must preserve TLS classification"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn nested_reader_classifies_fragmented_records_and_clean_eof() {
    let (mut client, server) = tcp_pair().await;
    let (destination, _) = server.into_split();
    let mut reader = super::NestedRecordReader::new(destination);
    let hello = record(22, &server_hello(0x1301, true));

    client
        .write_all(&hello[..3])
        .await
        .expect("fragment must be written");
    client
        .write_all(&hello[3..])
        .await
        .expect("fragment must be written");
    match reader
        .next(TEST_TIMEOUT)
        .await
        .expect("record must classify")
    {
        super::NestedRead::Record(bytes) => assert_eq!(bytes, hello.as_slice()),
        _ => panic!("fragmented record must classify as a record"),
    }

    client.shutdown().await.expect("client must half-close");
    assert!(matches!(
        reader.next(TEST_TIMEOUT).await.expect("EOF must classify"),
        super::NestedRead::Eof
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn nested_reader_reports_truncated_records_and_partial_headers() {
    let (mut client, server) = tcp_pair().await;
    let (destination, _) = server.into_split();
    let mut reader = super::NestedRecordReader::new(destination);
    let mut truncated = vec![23, 0x03, 0x03, 0, 100];
    truncated.extend_from_slice(&[0x5a; 10]);
    client
        .write_all(&truncated)
        .await
        .expect("truncated record must be written");
    client.shutdown().await.expect("client must half-close");
    assert!(matches!(
        reader.next(TEST_TIMEOUT).await,
        Err(super::VisionSessionError::DestinationTruncatedTlsRecord)
    ));

    let (mut client, server) = tcp_pair().await;
    let (destination, _) = server.into_split();
    let mut reader = super::NestedRecordReader::new(destination);
    client
        .write_all(&[0x16, 0x03, 0x01])
        .await
        .expect("partial header must be written");
    client.shutdown().await.expect("client must half-close");
    match reader.next(TEST_TIMEOUT).await.expect("partial header") {
        super::NestedRead::Unframed(bytes) => assert_eq!(bytes, &[0x16, 0x03, 0x01]),
        _ => panic!("a partial header at EOF must classify as unframed bytes"),
    }
}

#[test]
fn recognizes_tls13_server_hello_then_direct_application_record() {
    let server_hello = server_hello(0x1301, true);
    assert!(super::nested::is_tls13_server_hello(&server_hello));
    let mut detector = NestedTlsDetector::new();
    let handshake_record = record(22, &server_hello);
    let application_record = record(23, b"encrypted handshake");

    assert_eq!(
        detector.observe(&handshake_record),
        PaddingDecision::Continue
    );
    assert_eq!(
        detector.observe(&application_record),
        PaddingDecision::Direct
    );
}

#[test]
fn rejects_ccm8_and_tls12_for_direct_transition() {
    let mut ccm8 = NestedTlsDetector::new();
    assert_eq!(
        ccm8.observe(&record(22, &server_hello(0x1305, true))),
        PaddingDecision::End
    );
    let mut tls12 = NestedTlsDetector::new();
    assert_eq!(
        tls12.observe(&record(22, &server_hello(0x1301, false))),
        PaddingDecision::End
    );
}

#[test]
fn assembles_fragmented_server_hello_across_records() {
    let hello = server_hello(0x1301, true);
    let split = 30;
    let mut detector = NestedTlsDetector::new();

    assert_eq!(
        detector.observe(&record(22, &hello[..split])),
        PaddingDecision::Continue
    );
    assert_eq!(
        detector.observe(&record(22, &hello[split..])),
        PaddingDecision::Continue
    );
    assert_eq!(
        detector.observe(&record(23, b"ciphertext")),
        PaddingDecision::Direct
    );
}

#[test]
fn assembles_fragmented_handshake_header_across_records() {
    let hello = server_hello(0x1301, true);
    let mut detector = NestedTlsDetector::new();

    assert_eq!(
        detector.observe(&record(22, &hello[..2])),
        PaddingDecision::Continue
    );
    assert_eq!(
        detector.observe(&record(22, &hello[2..])),
        PaddingDecision::Continue
    );
    assert_eq!(
        detector.observe(&record(23, b"ciphertext")),
        PaddingDecision::Direct
    );
}

fn server_hello(cipher_suite: u16, tls13: bool) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x11; 32]);
    body.push(0);
    body.extend_from_slice(&cipher_suite.to_be_bytes());
    body.push(0);
    if tls13 {
        body.extend_from_slice(&[0, 6, 0, 43, 0, 2, 0x03, 0x04]);
    } else {
        body.extend_from_slice(&[0, 0]);
    }
    let mut message = vec![2, 0, 0, u8::try_from(body.len()).unwrap_or(u8::MAX)];
    message.extend_from_slice(&body);
    message
}

fn record(content_type: u8, body: &[u8]) -> Vec<u8> {
    let mut record = vec![content_type, 0x03, 0x03];
    record.extend_from_slice(&u16::try_from(body.len()).unwrap_or(u16::MAX).to_be_bytes());
    record.extend_from_slice(body);
    record
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("outer listener must bind");
    let client = TcpStream::connect(listener.local_addr().expect("address must exist"))
        .await
        .expect("outer client must connect");
    let (server, _) = listener.accept().await.expect("outer server must accept");
    (client, server)
}

fn vision_request(destination_port: u16, payload: &[u8]) -> Vec<u8> {
    vision_request_with_command(destination_port, payload, VisionCommand::End)
}

fn vision_request_with_command(
    destination_port: u16,
    payload: &[u8],
    command: VisionCommand,
) -> Vec<u8> {
    let mut addons = vec![0x0a, 0x10];
    addons.extend_from_slice(VISION_FLOW.as_bytes());
    let mut request = Vec::new();
    request.push(VERSION);
    request.extend_from_slice(USER.as_bytes());
    request.push(u8::try_from(addons.len()).unwrap_or(u8::MAX));
    request.extend_from_slice(&addons);
    request.push(Command::Tcp.as_byte());
    request.extend_from_slice(&destination_port.to_be_bytes());
    request.push(1);
    request.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
    let mut encoder = VisionEncoder::with_padding_seed(USER, &[0x5a; 44]);
    let mut frame = Vec::new();
    encoder
        .encode(payload, command, false, &mut frame)
        .expect("Vision payload must encode");
    request.extend_from_slice(&frame);
    request
}

fn tls_states() -> (EstablishedTls, Tls13RecordLayer, Tls13RecordLayer) {
    let suite = CipherSuite::Aes128GcmSha256;
    let client_layer = || {
        let secret = TrafficSecret::from_bytes(suite.hash(), &[0x31; 32])
            .expect("client secret must import");
        Tls13RecordLayer::from_traffic_secret(suite, secret)
            .expect("client record layer must initialize")
    };
    let server_layer = || {
        let secret = TrafficSecret::from_bytes(suite.hash(), &[0x32; 32])
            .expect("server secret must import");
        Tls13RecordLayer::from_traffic_secret(suite, secret)
            .expect("server record layer must initialize")
    };
    (
        EstablishedTls::from_test_records(suite, client_layer(), server_layer()),
        client_layer(),
        server_layer(),
    )
}

fn direct_handler(governor: &ResourceGovernorPolicy) -> VisionHandler {
    let barrier = DirectBarrierPolicy {
        max_concurrent: 8,
        max_per_second: 8,
    };
    let outbounds = OutboundRegistry::new(
        &std::collections::BTreeMap::new(),
        &barrier,
        Duration::from_millis(governor.connect_timeout_ms),
        crate::transport::FdBudget::new(4_096),
    );
    let routing = RoutingTable::compile(
        &RoutingConfig {
            default: "direct".to_owned(),
            strategy: None,
            rules: None,
            policies: None,
        },
        &[UserConfig {
            id: "33333333-3333-3333-3333-333333333333".to_owned(),
            short_ids: vec!["0123456789abcdef".to_owned()],
            label: None,
            policy: None,
        }],
        Arc::new(EmptyAssetMatcher),
        crate::runtime::ResourceGovernor::new(
            &crate::runtime::policy::ResourceGovernorPolicy::default(),
        ),
    )
    .expect("test routing must compile");
    let relay = crate::transport::TcpRelay::new(
        crate::transport::TcpRelayConfig {
            buffer_bytes: 32 * 1024,
            max_pooled_buffers: 8,
            max_splice_relays: 0,
            splice: false,
            pipe_pool: true,
            max_pooled_pipes: 8,
        },
        crate::transport::FdBudget::new(4_096),
    )
    .expect("test relay policy must compile");
    VisionHandler::new(outbounds, routing, relay, governor)
}

fn handler_with_block_cidr(governor: &ResourceGovernorPolicy, blocked_cidr: &str) -> VisionHandler {
    let barrier = DirectBarrierPolicy {
        max_concurrent: 8,
        max_per_second: 8,
    };
    let outbounds = OutboundRegistry::new(
        &std::collections::BTreeMap::new(),
        &barrier,
        Duration::from_millis(governor.connect_timeout_ms),
        crate::transport::FdBudget::new(4_096),
    );
    let routing = RoutingTable::compile(
        &RoutingConfig {
            default: "direct".to_owned(),
            strategy: None,
            rules: Some(vec![crate::config::node::routing::RouteRule {
                name: Some("xudp-keep-block".to_owned()),
                outbound: "block".to_owned(),
                ip: Some(vec![blocked_cidr.to_owned()]),
                ..crate::config::node::routing::RouteRule::default()
            }]),
            policies: None,
        },
        &[UserConfig {
            id: "33333333-3333-3333-3333-333333333333".to_owned(),
            short_ids: vec!["0123456789abcdef".to_owned()],
            label: None,
            policy: None,
        }],
        Arc::new(EmptyAssetMatcher),
        crate::runtime::ResourceGovernor::new(
            &crate::runtime::policy::ResourceGovernorPolicy::default(),
        ),
    )
    .expect("test routing must compile");
    let relay = crate::transport::TcpRelay::new(
        crate::transport::TcpRelayConfig {
            buffer_bytes: 32 * 1024,
            max_pooled_buffers: 8,
            max_splice_relays: 0,
            splice: false,
            pipe_pool: true,
            max_pooled_pipes: 8,
        },
        crate::transport::FdBudget::new(4_096),
    )
    .expect("test relay policy must compile");
    VisionHandler::new(outbounds, routing, relay, governor)
}

#[tokio::test(flavor = "current_thread")]
async fn xudp_keep_rewrite_direct_then_block_fails_closed() {
    use crate::protocol::vless::{Address, Destination};
    use crate::server::xudp::{XudpEgressCapability, XudpOutboundUnsupported};

    let governor = ResourceGovernorPolicy::default();
    // Block 10.0.0.0/8; default remains Direct.
    let handler = handler_with_block_cidr(&governor, "10.0.0.0/8");
    let green = Destination::new(Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 9);
    let red = Destination::new(Address::Ipv4(Ipv4Addr::new(10, 1, 2, 3)), 9);

    let (capability, authorized, tag) = handler
        .authorize_xudp_destination(USER, "public-reality", &green)
        .await
        .expect("Direct destination must remain GREEN");
    assert_eq!(capability, XudpEgressCapability::Direct);
    assert_eq!(authorized.port(), 9);
    assert_eq!(tag, "direct");

    let err = handler
        .authorize_xudp_destination(USER, "public-reality", &red)
        .await
        .expect_err("Keep rewrite to Block must fail closed (RED)");
    match err {
        VisionSessionError::Xudp(crate::server::xudp::XudpSessionError::Outbound(
            XudpOutboundUnsupported::Block,
        )) => {}
        other => panic!("expected Block outbound rejection, got {other}"),
    }
}

/// Reproduces the abort-authority lifetime question from #195.
///
/// The client sends its whole request and closes the inner TLS stream, so
/// the uplink direction completes and `try_join!` drops its future — which
/// owns the client read half and the destination write half. The
/// destination then aborts, so the downlink direction fails. At that point
/// the downlink future owns the *last* halves of both sockets, and the
/// question is whether the abort guard can still reach a live socket.
///
/// The ordering is a happens-before chain, not a sleep:
///
/// 1. `read_to_end` on the destination returns only after the uplink
///    shut the destination write half down, which it does immediately
///    before returning `Ok`;
/// 2. the client decodes a downlink record, which the session can only
///    have produced after the uplink future became `Ready` and was
///    dropped in that same poll;
/// 3. only then does the client release the destination, which resets.
///
/// The peer-visible contract is what is asserted: a truncated transfer
/// must reach the client as a reset, never as a clean end of stream that
/// a client could mistake for a complete response.
#[tokio::test(flavor = "current_thread")]
async fn a_downlink_abort_after_the_uplink_finished_resets_the_client() {
    let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("destination must bind");
    let destination_address = destination_listener
        .local_addr()
        .expect("destination address must exist");
    let (mut client, server) = tcp_pair().await;
    let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
    let established =
        RealityEstablished::from_test_parts(TlsApplicationIo::new(server, established_tls), USER);
    let governor = ResourceGovernorPolicy {
        connect_timeout_ms: 1_000,
        handshake_timeout_ms: 1_000,
        fallback_timeout_ms: 1_000,
        ..ResourceGovernorPolicy::default()
    };
    let handler = direct_handler(&governor);
    let request = vision_request(destination_address.port(), b"ping");
    let (downlink_seen, downlink_wait) = tokio::sync::oneshot::channel::<()>();

    let exchange = async {
        let handle = handler.handle(established);
        let client_io = async {
            let mut request_record = Vec::new();
            client_write_records
                .seal_into(
                    ContentType::ApplicationData,
                    &request,
                    0,
                    &mut request_record,
                )
                .map_err(io::Error::other)?;
            client.write_all(&request_record).await?;
            // Closing the inner stream is what ends the uplink direction.
            let mut close_record = Vec::new();
            client_write_records
                .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                .map_err(io::Error::other)?;
            client.write_all(&close_record).await?;

            // Barrier 2: one decoded downlink record proves the session
            // progressed past the uplink's completion.
            let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                .await
                .map_err(io::Error::other)?
                .into_wire();
            let opened = client_read_records
                .open_in_place(&mut record)
                .map_err(io::Error::other)?;
            assert_eq!(opened.content_type(), ContentType::ApplicationData);
            let _ = downlink_seen.send(());

            // How the transport ends is the whole assertion.
            let mut sink = [0_u8; 4_096];
            loop {
                match client.read(&mut sink).await {
                    Ok(0) => return Ok::<_, io::Error>(None),
                    Ok(_) => {}
                    Err(error) => return Ok(Some(error.kind())),
                }
            }
        };
        let destination_io = async {
            let (mut destination, _) = destination_listener.accept().await?;
            // Barrier 1: returns only once the uplink shut this half down.
            let mut request = Vec::new();
            destination.read_to_end(&mut request).await?;
            destination.write_all(b"partial").await?;
            let _ = downlink_wait.await;
            // Truncate the response mid-transfer, the way a dying origin does.
            rr_linux::socket::abort_linger(&destination).expect("arm the reset");
            drop(destination);
            Ok::<_, io::Error>(request)
        };
        tokio::join!(handle, client_io, destination_io)
    };
    let (session, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("the exchange must not time out");
    assert_eq!(
        destination_result.expect("destination I/O must succeed"),
        b"ping"
    );
    assert!(
        session.is_err(),
        "a truncated downlink must fail the session, not report a clean close"
    );
    let ending = client_result.expect("client I/O must not fail structurally");
    assert_eq!(
        ending,
        Some(io::ErrorKind::ConnectionReset),
        "an aborted transfer must reach the client as a reset; a clean end of \
             stream lets a truncated response look complete"
    );
}

/// The counterpart to the two abort regressions: arming a reset on every
/// failure must not leak into the graceful path.
///
/// A session that completes normally has to close with FIN so the client
/// can tell a finished response from a truncated one. Over-aborting would
/// be a worse defect than the one #195 fixed, because it would corrupt
/// every healthy session rather than a failing one.
#[tokio::test(flavor = "current_thread")]
async fn a_completed_session_closes_the_client_cleanly() {
    let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("destination must bind");
    let destination_address = destination_listener
        .local_addr()
        .expect("destination address must exist");
    let (mut client, server) = tcp_pair().await;
    let (established_tls, mut client_write_records, _client_read_records) = tls_states();
    let established =
        RealityEstablished::from_test_parts(TlsApplicationIo::new(server, established_tls), USER);
    let governor = ResourceGovernorPolicy {
        connect_timeout_ms: 1_000,
        handshake_timeout_ms: 1_000,
        fallback_timeout_ms: 1_000,
        ..ResourceGovernorPolicy::default()
    };
    let handler = direct_handler(&governor);
    let request = vision_request(destination_address.port(), b"ping");

    let exchange = async {
        let handle = handler.handle(established);
        let client_io = async {
            let mut request_record = Vec::new();
            client_write_records
                .seal_into(
                    ContentType::ApplicationData,
                    &request,
                    0,
                    &mut request_record,
                )
                .map_err(io::Error::other)?;
            client.write_all(&request_record).await?;
            let mut close_record = Vec::new();
            client_write_records
                .seal_into(ContentType::Alert, &[1, 0], 0, &mut close_record)
                .map_err(io::Error::other)?;
            client.write_all(&close_record).await?;

            let mut sink = [0_u8; 4_096];
            loop {
                match client.read(&mut sink).await {
                    Ok(0) => return Ok::<_, io::Error>(None),
                    Ok(_) => {}
                    Err(error) => return Ok(Some(error.kind())),
                }
            }
        };
        let destination_io = async {
            let (mut destination, _) = destination_listener.accept().await?;
            let mut request = Vec::new();
            destination.read_to_end(&mut request).await?;
            destination.write_all(b"pong").await?;
            destination.shutdown().await?;
            Ok::<_, io::Error>(request)
        };
        tokio::join!(handle, client_io, destination_io)
    };
    let (session, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("the exchange must not time out");
    assert_eq!(
        destination_result.expect("destination I/O must succeed"),
        b"ping"
    );
    session.expect("a complete session must succeed");
    assert_eq!(
        client_result.expect("client I/O must not fail structurally"),
        None,
        "a graceful session must end with FIN; resetting a healthy session \
             would be a worse defect than the abort it protects against"
    );
}

/// The cancellation half of #195.
///
/// Here the client keeps its stream open, so the uplink direction is alive
/// and parked on a read when the downlink fails. `try_join!` then cancels
/// the uplink future *while it owns the client read half and the
/// destination write half*. Both guards must still deliver a reset, and
/// neither may let a FIN reach the client first.
///
/// The barrier is the destination observing the relayed payload, which
/// only happens after the session is fully established and both directions
/// are running.
#[tokio::test(flavor = "current_thread")]
async fn a_downlink_abort_resets_the_client_while_the_uplink_is_cancelled() {
    let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("destination must bind");
    let destination_address = destination_listener
        .local_addr()
        .expect("destination address must exist");
    let (mut client, server) = tcp_pair().await;
    let (established_tls, mut client_write_records, mut client_read_records) = tls_states();
    let established =
        RealityEstablished::from_test_parts(TlsApplicationIo::new(server, established_tls), USER);
    let governor = ResourceGovernorPolicy {
        connect_timeout_ms: 1_000,
        handshake_timeout_ms: 1_000,
        fallback_timeout_ms: 1_000,
        ..ResourceGovernorPolicy::default()
    };
    let handler = direct_handler(&governor);
    let request = vision_request(destination_address.port(), b"ping");

    let exchange = async {
        let handle = handler.handle(established);
        let client_io = async {
            let mut request_record = Vec::new();
            client_write_records
                .seal_into(
                    ContentType::ApplicationData,
                    &request,
                    0,
                    &mut request_record,
                )
                .map_err(io::Error::other)?;
            client.write_all(&request_record).await?;
            // No close_notify: the uplink direction stays alive and parked
            // on a read for the whole test, so cancelling it is what the
            // downlink failure below has to do.

            // Consume the downlink preamble so the assertion below observes
            // the end of the transport, not the response.
            let mut record = read_tls_record(&mut client, TEST_TIMEOUT)
                .await
                .map_err(io::Error::other)?
                .into_wire();
            let opened = client_read_records
                .open_in_place(&mut record)
                .map_err(io::Error::other)?;
            assert_eq!(opened.content_type(), ContentType::ApplicationData);

            let mut sink = [0_u8; 4_096];
            loop {
                match client.read(&mut sink).await {
                    Ok(0) => return Ok::<_, io::Error>(None),
                    Ok(_) => {}
                    Err(error) => return Ok(Some(error.kind())),
                }
            }
        };
        let destination_io = async {
            let (mut destination, _) = destination_listener.accept().await?;
            // Barrier: the relayed payload proves both directions are live.
            let mut relayed = [0_u8; 4];
            destination.read_exact(&mut relayed).await?;
            rr_linux::socket::abort_linger(&destination).expect("arm the reset");
            drop(destination);
            Ok::<_, io::Error>(relayed)
        };
        tokio::join!(handle, client_io, destination_io)
    };
    let (session, client_result, destination_result) = timeout(TEST_TIMEOUT, exchange)
        .await
        .expect("the exchange must not time out");
    assert_eq!(
        destination_result.expect("destination I/O must succeed"),
        *b"ping"
    );
    assert!(
        session.is_err(),
        "an aborted destination must fail the session"
    );
    assert_eq!(
        client_result.expect("client I/O must not fail structurally"),
        Some(io::ErrorKind::ConnectionReset),
        "cancelling a live direction must still reset the client, never FIN it"
    );
}

#[test]
fn an_idle_timeout_is_a_benign_teardown() {
    assert!(is_benign_teardown(&io::Error::new(
        io::ErrorKind::TimedOut,
        "raw relay idle timeout"
    )));
    assert!(is_benign_teardown(&io::Error::new(
        io::ErrorKind::ConnectionReset,
        "reset"
    )));
    assert!(!is_benign_teardown(&io::Error::other("boom")));
}

#[tokio::test(flavor = "current_thread")]
async fn a_quiet_raw_direction_waits_for_fin_with_its_stats() {
    let relay = TcpRelay::new(TcpRelayConfig::for_test(), FdBudget::new(4_096))
        .expect("relay policy must compile");
    let handoff = DirectHandoff::new();
    let activity = Arc::new(super::SessionActivity::default());
    let (mut sender, source) = tcp_pair().await;
    let (sink, mut receiver) = tcp_pair().await;
    let (source_reader, _source_writer) = source.into_split();
    let (_sink_reader, sink_writer) = sink.into_split();
    let context = SessionContext {
        activity: &activity,
        timeout: Duration::from_millis(10),
        handoff: &handoff,
        relay: &relay,
    };
    let relaying = run_directional(
        &context,
        Direction::Uplink,
        source_reader,
        sink_writer,
        BoundaryBytes {
            total: 3,
            direct_at: 3,
        },
        Instant::now(),
    );
    tokio::pin!(relaying);
    assert!(
        timeout(Duration::from_millis(50), &mut relaying)
            .await
            .is_err(),
        "a quiet raw direction must remain open"
    );
    sender.shutdown().await.expect("FIN");
    let stats = timeout(TEST_TIMEOUT, relaying)
        .await
        .expect("FIN deadline")
        .expect("clean FIN");
    assert_eq!(receiver.read(&mut [0]).await.expect("EOF"), 0);
    assert!(stats.direct);
    assert_eq!(stats.bytes, 3);
}

#[tokio::test(flavor = "current_thread")]
async fn a_write_stall_after_moved_bytes_fails_the_session() {
    let relay = TcpRelay::new(TcpRelayConfig::for_test(), FdBudget::new(4_096))
        .expect("relay policy must compile");
    let handoff = DirectHandoff::new();
    let activity = Arc::new(super::SessionActivity::default());
    let (mut sender, source) = tcp_pair().await;
    let (sink, _receiver) = tcp_pair().await;
    let (source_reader, _source_writer) = source.into_split();
    let (_sink_reader, sink_writer) = sink.into_split();
    let context = SessionContext {
        activity: &activity,
        timeout: Duration::from_millis(50),
        handoff: &handoff,
        relay: &relay,
    };
    let result = timeout(TEST_TIMEOUT, async {
        let mut flood = tokio::io::repeat(0x55);
        tokio::select! {
            result = run_directional(
                &context, Direction::Uplink, source_reader, sink_writer,
                BoundaryBytes { total: 3, direct_at: 3 }, Instant::now(),
            ) => result,
            result = tokio::io::copy(&mut flood, &mut sender) =>
                panic!("source must not finish before write stall: {result:?}"),
        }
    })
    .await
    .expect("stalled write must be bounded");
    let error = result.err().expect("write stall must fail closed");
    let VisionSessionError::Relay(source) = &error else {
        panic!("expected relay error: {error}");
    };
    assert_eq!(source.kind(), io::ErrorKind::ConnectionAborted);
}

/// Release-blocking real-time proof. Paused clocks cannot satisfy it.
///
/// SSE is a quiet uplink with continuing downlink. WebSocket is sparse
/// traffic in both directions. Both last 600 seconds. A delayed response
/// begins after 190 seconds, and half-close drains after crossing 120
/// seconds. A blocked pending write must still fail on the production
/// 120-second stall, not because the opposite direction is quiet.
///
/// Uses `current_thread` like the other non-ignored Vision proofs: the
/// accumulation is sequential, and multi-thread Tokio I/O registration
/// trips ThreadSanitizer inside `ScheduledIo` (ADR 0057). Ignored
/// multi-thread diagnostics and the 600s matrix keep their flavors.
#[tokio::test(flavor = "current_thread")]
async fn three_downlink_chunks_accumulate() {
    let mut session = open_framed(b"SSE", 0x11).await;
    let mut request = [0; 3];
    session.target.read_exact(&mut request).await.unwrap();
    let mut decoder = VisionDecoder::new(USER);
    let mut decoded = Vec::new();
    let mut first = true;
    let mut expected = Vec::new();
    for tick in 0..3_u8 {
        let chunk = [b'S', tick];
        session.target.write_all(&chunk).await.unwrap();
        let need = decoded.len() + chunk.len();
        read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, need)
            .await
            .unwrap();
        expected.extend_from_slice(&chunk);
    }
    assert_eq!(decoded, expected);
    finish_both(session, expected.len() as u64).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "diagnostic: three 30s quiet downlink chunks"]
async fn three_quiet_downlink_chunks_survive() {
    let mut session = open_framed(b"SSE", 0x11).await;
    let mut request = [0; 3];
    session.target.read_exact(&mut request).await.unwrap();
    let mut decoder = VisionDecoder::new(USER);
    let mut decoded = Vec::new();
    let mut first = true;
    let mut expected = Vec::new();
    for tick in 0..3_u8 {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let chunk = [b'S', tick];
        session.target.write_all(&chunk).await.unwrap();
        let need = decoded.len() + chunk.len();
        if let Err(error) =
            read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, need).await
        {
            session.task.abort();
            panic!("chunk {tick} was not relayed: {error}");
        }
        expected.extend_from_slice(&chunk);
    }
    assert_eq!(decoded, expected);
    finish_both(session, expected.len() as u64).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "diagnostic: 120s pending write beside one quiet downlink"]
async fn quiet_downlink_survives_a_parallel_pending_write() {
    let stall = tokio::spawn(pending_write_stalls_at_120s());
    let mut session = open_framed(b"SSE", 0x11).await;
    let mut request = [0; 3];
    session.target.read_exact(&mut request).await.unwrap();
    tokio::time::sleep(Duration::from_secs(30)).await;
    session.target.write_all(b"AB").await.unwrap();
    let mut decoder = VisionDecoder::new(USER);
    let mut decoded = Vec::new();
    let mut first = true;
    let read = tokio::time::timeout(
        Duration::from_secs(60),
        read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, 2),
    )
    .await;
    if !matches!(read, Ok(Ok(()))) || decoded != b"AB" {
        session.task.abort();
        panic!("parallel pending write hid the downlink chunk: {read:?} {decoded:?}");
    }
    let stall = stall.await.unwrap();
    assert!(
        stall.is_ok(),
        "parallel stall did not stay bounded: {stall:?}"
    );
    finish_both(session, 2).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "diagnostic: one downlink chunk after 30s quiet"]
async fn one_downlink_chunk_survives_a_quiet_30s() {
    let mut session = open_framed(b"SSE", 0x11).await;
    let mut request = [0; 3];
    session.target.read_exact(&mut request).await.unwrap();
    tokio::time::sleep(Duration::from_secs(30)).await;
    session.target.write_all(b"AB").await.unwrap();
    let mut decoder = VisionDecoder::new(USER);
    let mut decoded = Vec::new();
    let mut first = true;
    let read = tokio::time::timeout(
        Duration::from_secs(5),
        read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, 2),
    )
    .await;
    match read {
        Ok(Ok(())) => assert_eq!(decoded, b"AB"),
        other => {
            session.task.abort();
            panic!("downlink chunk was not relayed: {other:?}");
        }
    }
    finish_both(session, 2).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "release qualification: real 600s authenticated connection matrix"]
async fn authenticated_connections_survive_quiet_directions_for_600s() {
    let started = std::time::Instant::now();
    let (sse, websocket, quiet_downlink, delayed, half_close, stall) = tokio::join!(
        sse_downlink_for_600s(),
        websocket_for_600s(),
        quiet_downlink_for_600s(),
        delayed_response_after_180s(),
        half_close_after_crossing_120s(),
        pending_write_stalls_at_120s(),
    );
    sse.expect("SSE quiet uplink must survive 600s");
    websocket.expect("WebSocket session must survive 600s");
    quiet_downlink.expect("quiet downlink must survive 600s");
    delayed.expect("a response after 180s must not be a timeout");
    half_close.expect("half-close must drain the opposite direction");
    stall.expect("a pending write must hit the 120s stall bound");
    assert!(
        started.elapsed() >= Duration::from_secs(600),
        "the matrix must actually cross 600 elapsed seconds"
    );
}

struct LiveSession {
    client: TcpStream,
    client_write: Tls13RecordLayer,
    client_read: Tls13RecordLayer,
    encoder: VisionEncoder,
    target: TcpStream,
    task: tokio::task::JoinHandle<Result<super::VisionRelayStats, VisionSessionError>>,
}

async fn open_framed(initial: &[u8], seed: u8) -> LiveSession {
    let (client, inbound) = tcp_pair().await;
    let (destination, target) = tcp_pair().await;
    let (tls, client_write, client_read) = tls_states();
    let (reader, writer) = TlsApplicationIo::new(inbound, tls).into_owned_split();
    let relay = TcpRelay::new(TcpRelayConfig::for_test(), FdBudget::new(4_096))
        .expect("relay policy must compile");
    let mut encoder = VisionEncoder::with_padding_seed(USER, &[seed; 44]);
    let mut request = Vec::new();
    encoder
        .encode(initial, VisionCommand::Continue, false, &mut request)
        .expect("initial frame");
    let task = tokio::spawn(async move {
        super::run_resumed_session(
            reader,
            writer,
            destination,
            USER,
            request,
            &relay,
            crate::io_activity::WRITE_STALL_TIMEOUT,
        )
        .await
    });
    LiveSession {
        client,
        client_write,
        client_read,
        encoder,
        target,
        task,
    }
}

async fn read_exact_payload(
    session: &mut LiveSession,
    decoder: &mut VisionDecoder,
    decoded: &mut Vec<u8>,
    first: &mut bool,
    need: usize,
) -> io::Result<()> {
    while decoded.len() < need {
        let mut record = read_tls_record(&mut session.client, Duration::from_secs(60))
            .await
            .map_err(|error| io::Error::other(error.to_string()))?
            .into_wire();
        let opened = session
            .client_read
            .open_in_place(&mut record)
            .map_err(|error| io::Error::other(error.to_string()))?;
        if opened.content_type() == ContentType::Alert {
            return Err(io::Error::other("alert before the expected payload"));
        }
        let payload = if *first {
            *first = false;
            opened
                .plaintext()
                .get(2..)
                .ok_or_else(|| io::Error::other("missing VLESS response header"))?
        } else {
            opened.plaintext()
        };
        // `decode` clears the caller's buffer. Accumulated chunks must
        // survive the next record.
        decoder
            .decode_append(payload, decoded)
            .map_err(|error| io::Error::other(error.to_string()))?;
    }
    Ok(())
}

fn seal_uplink(session: &mut LiveSession, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut frame = Vec::new();
    session
        .encoder
        .encode(payload, VisionCommand::Continue, false, &mut frame)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut wire = Vec::new();
    session
        .client_write
        .seal_into(ContentType::ApplicationData, &frame, 0, &mut wire)
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(wire)
}

async fn finish_both(mut session: LiveSession, downlink: u64) -> io::Result<()> {
    let mut alert = Vec::new();
    session
        .client_write
        .seal_into(ContentType::Alert, &[1, 0], 0, &mut alert)
        .map_err(|error| io::Error::other(error.to_string()))?;
    session.client.write_all(&alert).await?;
    let mut ignored = [0; 64];
    let _ = session.target.read(&mut ignored).await?;
    session.target.shutdown().await?;
    loop {
        let mut record = read_tls_record(&mut session.client, Duration::from_secs(30))
            .await
            .map_err(|error| io::Error::other(error.to_string()))?
            .into_wire();
        let opened = session
            .client_read
            .open_in_place(&mut record)
            .map_err(|error| io::Error::other(error.to_string()))?;
        if opened.content_type() == ContentType::Alert {
            break;
        }
    }
    let stats = session
        .task
        .await
        .map_err(|error| io::Error::other(error.to_string()))?
        .map_err(|error| io::Error::other(error.to_string()))?;
    if stats.downlink_bytes() != downlink || stats.uplink_direct() || stats.downlink_direct() {
        return Err(io::Error::other(format!(
            "unexpected stats uplink={} downlink={} expected_downlink={downlink}",
            stats.uplink_bytes(),
            stats.downlink_bytes()
        )));
    }
    Ok(())
}

async fn sse_downlink_for_600s() -> io::Result<()> {
    let mut session = open_framed(b"SSE", 0x11).await;
    let mut request = [0; 3];
    session.target.read_exact(&mut request).await?;
    if &request != b"SSE" {
        session.task.abort();
        return Err(io::Error::other("SSE request was corrupted"));
    }
    let started = std::time::Instant::now();
    let mut decoder = VisionDecoder::new(USER);
    let mut decoded = Vec::new();
    let mut first = true;
    let mut expected = Vec::new();
    let mut tick = 0_u8;
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let chunk = [b'S', tick];
        tick = tick.wrapping_add(1);
        session.target.write_all(&chunk).await?;
        let need = decoded.len() + chunk.len();
        read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, need).await?;
        expected.extend_from_slice(&chunk);
        if started.elapsed() >= Duration::from_secs(600) {
            break;
        }
    }
    if decoded != expected {
        session.task.abort();
        return Err(io::Error::other("SSE payload or duration failed"));
    }
    finish_both(session, expected.len() as u64).await
}

async fn websocket_for_600s() -> io::Result<()> {
    let mut session = open_framed(b"WS", 0x22).await;
    let mut request = [0; 2];
    session.target.read_exact(&mut request).await?;
    if &request != b"WS" {
        session.task.abort();
        return Err(io::Error::other("WebSocket request was corrupted"));
    }
    let started = std::time::Instant::now();
    let mut decoder = VisionDecoder::new(USER);
    let mut decoded = Vec::new();
    let mut first = true;
    let mut expected_down = Vec::new();
    let mut tick = 0_u8;
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let up = [b'u', tick];
        let down = [b'd', tick];
        tick = tick.wrapping_add(1);
        let wire = seal_uplink(&mut session, &up)?;
        session.client.write_all(&wire).await?;
        let mut got = [0; 2];
        session.target.read_exact(&mut got).await?;
        if got != up {
            session.task.abort();
            return Err(io::Error::other("WebSocket uplink was corrupted"));
        }
        session.target.write_all(&down).await?;
        let need = decoded.len() + down.len();
        read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, need).await?;
        expected_down.extend_from_slice(&down);
        if started.elapsed() >= Duration::from_secs(600) {
            break;
        }
    }
    if decoded != expected_down {
        session.task.abort();
        return Err(io::Error::other("WebSocket payload or duration failed"));
    }
    finish_both(session, expected_down.len() as u64).await
}

async fn quiet_downlink_for_600s() -> io::Result<()> {
    let mut session = open_framed(b"UP", 0x33).await;
    let mut request = [0; 2];
    session.target.read_exact(&mut request).await?;
    if &request != b"UP" {
        session.task.abort();
        return Err(io::Error::other("uplink request was corrupted"));
    }
    let started = std::time::Instant::now();
    let mut tick = 0_u8;
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let up = [b'q', tick];
        tick = tick.wrapping_add(1);
        let wire = seal_uplink(&mut session, &up)?;
        session.client.write_all(&wire).await?;
        let mut got = [0; 2];
        session.target.read_exact(&mut got).await?;
        if got != up {
            session.task.abort();
            return Err(io::Error::other("quiet-downlink uplink was corrupted"));
        }
        if started.elapsed() >= Duration::from_secs(600) {
            break;
        }
    }
    session.target.write_all(b"DONE").await?;
    let mut decoder = VisionDecoder::new(USER);
    let mut decoded = Vec::new();
    let mut first = true;
    read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, 4).await?;
    if decoded != b"DONE" {
        session.task.abort();
        return Err(io::Error::other("delayed opposite payload was corrupted"));
    }
    finish_both(session, 4).await
}

async fn delayed_response_after_180s() -> io::Result<()> {
    let mut session = open_framed(b"WAIT", 0x44).await;
    let mut request = [0; 4];
    session.target.read_exact(&mut request).await?;
    if &request != b"WAIT" {
        session.task.abort();
        return Err(io::Error::other("delayed request was corrupted"));
    }
    let started = std::time::Instant::now();
    tokio::time::sleep(Duration::from_secs(190)).await;
    if started.elapsed() < Duration::from_secs(180) {
        session.task.abort();
        return Err(io::Error::other("delay did not cross 180s"));
    }
    session.target.write_all(b"LATE").await?;
    let mut decoder = VisionDecoder::new(USER);
    let mut decoded = Vec::new();
    let mut first = true;
    read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, 4).await?;
    if decoded != b"LATE" {
        session.task.abort();
        return Err(io::Error::other("late response was corrupted"));
    }
    finish_both(session, 4).await
}

async fn half_close_after_crossing_120s() -> io::Result<()> {
    let mut session = open_framed(b"HALF", 0x55).await;
    let mut request = [0; 4];
    session.target.read_exact(&mut request).await?;
    if &request != b"HALF" {
        session.task.abort();
        return Err(io::Error::other("half-close request was corrupted"));
    }
    session.target.write_all(b"ping").await?;
    let mut decoder = VisionDecoder::new(USER);
    let mut decoded = Vec::new();
    let mut first = true;
    read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, 4).await?;
    let started = std::time::Instant::now();
    tokio::time::sleep(Duration::from_secs(130)).await;
    if started.elapsed() < Duration::from_secs(120) || decoded != b"ping" {
        session.task.abort();
        return Err(io::Error::other("half-close did not cross 120s intact"));
    }
    let mut alert = Vec::new();
    session
        .client_write
        .seal_into(ContentType::Alert, &[1, 0], 0, &mut alert)
        .map_err(|error| io::Error::other(error.to_string()))?;
    session.client.write_all(&alert).await?;
    let mut ignored = [0; 8];
    let end = session.target.read(&mut ignored).await?;
    if end != 0 {
        session.task.abort();
        return Err(io::Error::other(
            "uplink half-close did not reach the origin",
        ));
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    session.target.write_all(b"TAIL!").await?;
    session.target.shutdown().await?;
    read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, 9).await?;
    if &decoded[4..] != b"TAIL!" {
        session.task.abort();
        return Err(io::Error::other("opposite drain was corrupted"));
    }
    loop {
        let mut record = read_tls_record(&mut session.client, Duration::from_secs(30))
            .await
            .map_err(|error| io::Error::other(error.to_string()))?
            .into_wire();
        let opened = session
            .client_read
            .open_in_place(&mut record)
            .map_err(|error| io::Error::other(error.to_string()))?;
        if opened.content_type() == ContentType::Alert {
            break;
        }
    }
    let stats = session
        .task
        .await
        .map_err(|error| io::Error::other(error.to_string()))?
        .map_err(|error| io::Error::other(error.to_string()))?;
    if stats.downlink_bytes() != 9 {
        return Err(io::Error::other("half-close downlink count mismatch"));
    }
    Ok(())
}

async fn pending_write_stalls_at_120s() -> io::Result<()> {
    let mut session = open_framed(b"STALL", 0x66).await;
    let mut request = [0; 5];
    session.target.read_exact(&mut request).await?;
    if &request != b"STALL" {
        session.task.abort();
        return Err(io::Error::other("stall request was corrupted"));
    }
    session.target.write_all(b"X").await?;
    let mut decoder = VisionDecoder::new(USER);
    let mut decoded = Vec::new();
    let mut first = true;
    read_exact_payload(&mut session, &mut decoder, &mut decoded, &mut first, 1).await?;
    if decoded != b"X" {
        session.task.abort();
        return Err(io::Error::other("stall prefix was corrupted"));
    }
    let started = std::time::Instant::now();
    let mut target = session.target;
    let task = session.task;
    let _flood = tokio::spawn(async move {
        // Larger than this host's 32 MiB TCP receive autotune plus the
        // 4 MiB send buffer, so the pending write actually blocks.
        let payload = vec![0x5a; 64 * 1024 * 1024];
        let _ = target.write_all(&payload).await;
    });
    let result = tokio::time::timeout(Duration::from_secs(170), task)
        .await
        .map_err(|_| io::Error::other("write stall exceeded 170s"))?
        .map_err(|error| io::Error::other(error.to_string()))?;
    let elapsed = started.elapsed();
    if elapsed < Duration::from_secs(115) {
        return Err(io::Error::other(format!(
            "write stall fired too early: {elapsed:?}"
        )));
    }
    match result {
        Err(VisionSessionError::Tls(
            crate::protocol::reality::tls13::TlsApplicationIoError::Timeout,
        )) => Ok(()),
        Err(VisionSessionError::Timeout) => Ok(()),
        other => Err(io::Error::other(format!(
            "pending write did not fail as a stall: {other:?}"
        ))),
    }
}
