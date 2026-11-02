//! Handoff LINE/LANDING unit tests.
//!
//! Kept in a dedicated module tree so production modules stay readable;
//! shared fixtures live here and test groups live in submodules.

mod pre_auth;
mod resume;
mod session;
mod teardown;

use crate::runtime::policy::{DirectBarrierPolicy, ResourceGovernorPolicy, WarmConnectionPolicy};
use std::{io, net::Ipv4Addr, sync::Arc, time::Duration};

use crate::crypto::StaticX25519Key;
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

use super::landing::{resume_tls, unix_seconds};
use super::{HandoffLandingError, HandoffLandingHandler, HandoffLine, HandoffLineError};
use crate::{
    config::{
        SecretString,
        node::{
            outbound::{HandoffOutboundConfig, OutboundConfig, Socks5Config},
            routing::RoutingConfig,
            user::UserConfig,
        },
    },
    protocol::{
        handoff::{
            CONTINUATION_STATE_VERSION, ContinuationState, HEADER_LEN, HandoffError,
            HandoffLandingKeys, HandoffPolicySnapshot, HandoffPsk, HandoffReplayCache, SessionKind,
            message_len_from_header, open_transfer, seal_transfer,
        },
        reality::tls13::{
            CipherSuite, ContentType, EstablishedTls, ExportedRecordState, Tls13RecordLayer,
            TlsApplicationIo, TrafficSecret, read_tls_record, resume_application_halves,
        },
        vless::{
            Address, Command, Destination, UserId, VERSION, VISION_FLOW, VisionCommand,
            VisionDecoder, VisionEncoder,
        },
    },
    runtime::PressureGauge,
    server::{
        connector::DestinationConnector,
        outbound::OutboundRegistry,
        reality::RealityEstablished,
        routing::{EmptyAssetMatcher, RoutingTable},
        vision::{VisionHandler, VisionSessionError},
        warm_pool::WarmPoolAuthority,
    },
    transport::{FdBudget, TcpRelay, TcpRelayConfig},
};

const TEST_TIMEOUT: Duration = Duration::from_secs(3);
const USER: UserId = UserId::new([0x33; 16]);
const PSK: [u8; 32] = [0x55; 32];
const LANDING_SECRET: [u8; 32] = [0x77; 32];

fn test_relay() -> TcpRelay {
    TcpRelay::new(TcpRelayConfig::for_test(), FdBudget::new(4_096))
        .expect("test relay policy must compile")
}

fn test_landing_handler() -> HandoffLandingHandler {
    let replay = HandoffReplayCache::new(1_024, Duration::from_secs(120))
        .expect("test replay cache must compile");
    HandoffLandingHandler::new(
        HandoffLandingKeys::single(HandoffPsk::new(PSK), StaticX25519Key::new(&LANDING_SECRET)),
        replay,
        30,
        Duration::from_secs(1),
        Duration::from_secs(1),
        test_relay(),
        Duration::from_secs(1),
    )
}

fn handoff_line(address: std::net::SocketAddr) -> HandoffLine {
    let landing_public = StaticX25519Key::new(&LANDING_SECRET).public_key();
    HandoffLine::from_settings(&HandoffOutboundConfig {
        address: address.ip().to_string(),
        port: address.port(),
        psk: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(PSK)),
        landing_public_key: BASE64_URL_SAFE_NO_PAD.encode(landing_public),
        connect_timeout_ms: Some(1_000),
        first_byte_timeout_ms: Some(1_000),
        warm_tcp: Some(false),
    })
    .expect("test handoff settings must compile")
}

fn test_state(destination: Destination) -> ContinuationState {
    test_state_with_server_sequence(destination, 0)
}

fn test_state_with_server_sequence(
    destination: Destination,
    server_sequence: u64,
) -> ContinuationState {
    let suite = CipherSuite::ChaCha20Poly1305Sha256;
    let policy = HandoffPolicySnapshot::tcp_placeholder(destination.clone());
    ContinuationState::new(
        suite,
        TrafficSecret::from_bytes(suite.hash(), &[0x11; 32]).expect("client secret"),
        1,
        TrafficSecret::from_bytes(suite.hash(), &[0x12; 32]).expect("server secret"),
        server_sequence,
        false,
        SessionKind::Tcp,
        [0x33; 16],
        "public-reality",
        destination,
        Vec::new(),
        Vec::new(),
        policy,
    )
    .expect("test state must be valid")
}

fn tls_states() -> (EstablishedTls, Tls13RecordLayer, Tls13RecordLayer) {
    let suite = CipherSuite::Aes128GcmSha256;
    let layer = || {
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
        EstablishedTls::from_test_records(suite, layer(), server_layer()),
        layer(),
        server_layer(),
    )
}

fn tls_states_after_cover_shaped_fake_ticket()
-> (EstablishedTls, Tls13RecordLayer, Tls13RecordLayer) {
    let (mut established, client_write_records, mut client_read_records) = tls_states();
    assert_eq!(established.server_records_mut().records_used(), 0);
    assert_eq!(client_read_records.records_used(), 0);

    // The cover-shaped fake NewSessionTicket is an empty application-data
    // record under the server application key. It consumes sequence zero
    // before authenticated Vision traffic begins, exactly as production
    // `build_server_flight_with_shape` does.
    let mut fake_ticket = Vec::new();
    established
        .server_records_mut()
        .seal_into(ContentType::ApplicationData, b"", 117, &mut fake_ticket)
        .expect("cover-shaped fake ticket must seal at sequence zero");
    // 5-byte record header + 1-byte inner type + 117-byte padding + 16-byte tag.
    assert_eq!(fake_ticket.len(), 139);
    let opened = client_read_records
        .open_in_place(&mut fake_ticket)
        .expect("client must authenticate the cover-shaped fake ticket");
    assert_eq!(opened.content_type(), ContentType::ApplicationData);
    assert!(opened.plaintext().is_empty());
    assert_eq!(established.server_records_mut().records_used(), 1);
    assert_eq!(client_read_records.records_used(), 1);

    (established, client_write_records, client_read_records)
}

fn vision_request(destination_port: u16, payload: &[u8]) -> Vec<u8> {
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
        .encode(payload, VisionCommand::End, false, &mut frame)
        .expect("Vision payload must encode");
    request.extend_from_slice(&frame);
    request
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener must bind");
    let client = TcpStream::connect(listener.local_addr().expect("address must exist"))
        .await
        .expect("client must connect");
    let (server, _) = listener.accept().await.expect("server must accept");
    (client, server)
}

fn handoff_vision_handler(landing_address: std::net::SocketAddr) -> VisionHandler {
    handoff_vision_handler_with_warm(landing_address, false, FdBudget::new(4_096))
}

fn handoff_vision_handler_with_warm(
    landing_address: std::net::SocketAddr,
    warm: bool,
    budget: FdBudget,
) -> VisionHandler {
    let policy = WarmConnectionPolicy {
        min_ready: 1,
        max_ready: 1,
        max_connecting: 1,
        refill_batch: 1,
        ..WarmConnectionPolicy::default()
    };
    let barrier = DirectBarrierPolicy {
        max_concurrent: 8,
        max_per_second: 8,
    };
    let landing_public = StaticX25519Key::new(&LANDING_SECRET).public_key();
    let outbounds = OutboundRegistry::with_warm_pools(
        &std::collections::BTreeMap::from([(
            "handoff".to_owned(),
            OutboundConfig::Handoff(HandoffOutboundConfig {
                address: landing_address.ip().to_string(),
                port: landing_address.port(),
                psk: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(PSK)),
                landing_public_key: BASE64_URL_SAFE_NO_PAD.encode(landing_public),
                connect_timeout_ms: Some(if warm { 200 } else { 1_000 }),
                first_byte_timeout_ms: Some(if warm { 400 } else { 2_000 }),
                warm_tcp: Some(warm),
            }),
        )]),
        crate::runtime::DirectBarrier::new(&barrier),
        Duration::from_secs(1),
        budget,
        &crate::config::node::network::NetworkConfig::default(),
        crate::network::NetworkEnvironment::detect(),
        1,
        WarmPoolAuthority::new(&policy, 1, PressureGauge::new()),
        &policy,
    );
    let routing = RoutingTable::compile(
        &RoutingConfig {
            default: "handoff".to_owned(),
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
        crate::runtime::ResourceGovernor::new(&ResourceGovernorPolicy::default()),
    )
    .expect("test routing must compile");
    let governor = ResourceGovernorPolicy {
        connect_timeout_ms: 1_000,
        handshake_timeout_ms: 1_000,
        fallback_timeout_ms: 1_000,
        ..ResourceGovernorPolicy::default()
    };
    VisionHandler::new(outbounds, routing, test_relay(), &governor)
}

async fn run_line_to_landing_full_vision_session(consume_cover_shaped_fake_ticket: bool) {
    let listener = Arc::new(
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("landing must bind"),
    );
    run_shared_landing_session(
        consume_cover_shaped_fake_ticket,
        listener,
        test_landing_handler(),
    )
    .await;
}

async fn run_shared_landing_session(
    consume_cover_shaped_fake_ticket: bool,
    landing_listener: Arc<TcpListener>,
    landing_handler: HandoffLandingHandler,
) {
    let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("destination must bind");
    let destination_address = destination_listener
        .local_addr()
        .expect("destination address must exist");
    let landing_address = landing_listener
        .local_addr()
        .expect("landing address must exist");
    let line_handler = handoff_vision_handler(landing_address);
    let (mut client, server) = tcp_pair().await;
    let (established_tls, mut client_write_records, mut client_read_records) =
        if consume_cover_shaped_fake_ticket {
            tls_states_after_cover_shaped_fake_ticket()
        } else {
            tls_states()
        };
    let expected_first_visible_server_sequence = if consume_cover_shaped_fake_ticket {
        1
    } else {
        0
    };
    assert_eq!(
        client_read_records.records_used(),
        expected_first_visible_server_sequence
    );
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
            // One burst: the request record and a post-request raw-mode
            // record travel together, so LINE's reader may hold the second
            // record as read-ahead ciphertext at the boundary; the
            // continuation must carry it and LANDING must open it in order.
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
                            assert_eq!(
                                client_read_records.records_used(),
                                expected_first_visible_server_sequence + 1,
                                "the first visible response must decrypt at the exported server sequence",
                            );
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
            // A real client closes the socket after close_notify; the raw
            // splice on LINE terminates only on TCP-level EOF.
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
        .expect("handoff exchange must not time out");
    let line_stats = line.expect("LINE handler must succeed");
    let landing_stats = landing.expect("LANDING handler must succeed");

    assert_eq!(
        destination_result.expect("destination I/O must succeed"),
        b"ping-more",
        "prefetched and post-boundary records must arrive byte-exactly, in order"
    );
    assert_eq!(
        client_result.expect("client I/O must succeed"),
        b"pong",
        "the resumed downlink must decrypt byte-exactly at the client"
    );
    assert_eq!(landing_stats.inbound_to_outbound_bytes(), 9);
    assert_eq!(landing_stats.outbound_to_inbound_bytes(), 4);
    assert!(
        line_stats.downlink_bytes() > 0,
        "LINE must report the raw downlink ciphertext it spliced: up={} down={}",
        line_stats.uplink_bytes(),
        line_stats.downlink_bytes()
    );
    // The whole client burst fit LINE's reader buffer, so it traveled
    // inside the sealed continuation and the uplink splice legitimately
    // moved zero bytes.
}

fn egress_registry(name: &str, outbound: OutboundConfig) -> OutboundRegistry {
    OutboundRegistry::new(
        &std::collections::BTreeMap::from([(name.to_owned(), outbound)]),
        &DirectBarrierPolicy::default(),
        Duration::from_secs(1),
        FdBudget::new(4_096),
    )
}

/// Reads resumed downlink records until the decoded payload equals
/// `expected`, returning the collected payload. The Vision decoder and
/// the decoded prefix come from [`read_response_header_record`], keeping
/// the decoder state continuous across the opening frame.
async fn read_resumed_payload(
    client: &mut TcpStream,
    records: &mut Tls13RecordLayer,
    expected: &[u8],
    decoder: &mut VisionDecoder,
    response: &mut Vec<u8>,
) -> io::Result<Vec<u8>> {
    let mut decoded = Vec::new();
    while response != expected {
        let mut record = read_tls_record(client, TEST_TIMEOUT)
            .await
            .map_err(io::Error::other)?
            .into_wire();
        let opened = records
            .open_in_place(&mut record)
            .map_err(io::Error::other)?;
        if opened.content_type() != ContentType::ApplicationData {
            return Err(io::Error::other(
                "unexpected non-application downlink record",
            ));
        }
        let _ = decoder
            .decode(opened.plaintext(), &mut decoded)
            .map_err(io::Error::other)?;
        response.extend_from_slice(&decoded);
    }
    Ok(std::mem::take(response))
}

/// Reads and validates the first resumed downlink record — the VLESS
/// response header plus the opening Vision frame — and returns the
/// decoder primed with that frame and the payload decoded so far.
async fn read_response_header_record(
    client: &mut TcpStream,
    records: &mut Tls13RecordLayer,
) -> io::Result<(VisionDecoder, Vec<u8>)> {
    let mut first = read_tls_record(client, TEST_TIMEOUT)
        .await
        .map_err(io::Error::other)?
        .into_wire();
    let opened = records
        .open_in_place(&mut first)
        .map_err(io::Error::other)?;
    let plaintext = opened.plaintext();
    if opened.content_type() != ContentType::ApplicationData
        || plaintext.get(..2) != Some([VERSION, 0].as_slice())
    {
        return Err(io::Error::other("missing resumed response header"));
    }
    let mut decoder = VisionDecoder::new(USER);
    let mut decoded = Vec::new();
    let _ = decoder
        .decode(&plaintext[2..], &mut decoded)
        .map_err(io::Error::other)?;
    Ok((decoder, decoded))
}

/// Seals `payload` into as many application records as its size requires.
fn seal_application_records(records: &mut Tls13RecordLayer, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    for chunk in payload.chunks(16_000) {
        // `seal_into` replaces its output, so each record is staged apart.
        let mut record = Vec::new();
        records
            .seal_into(ContentType::ApplicationData, chunk, 0, &mut record)
            .map_err(io::Error::other)?;
        output.extend_from_slice(&record);
    }
    Ok(output)
}

/// Closes the client the way a real TLS client commonly does: the final
/// server close_notify is left unread, so the kernel resets the
/// connection. Waits briefly first so LINE has spliced every downlink
/// byte into the client's receive queue.
async fn reset_client_unread(client: TcpStream) {
    tokio::time::sleep(Duration::from_millis(200)).await;
    rr_linux::socket::abort_linger(&client).expect("abort linger must apply");
    drop(client);
}

struct HandoffRig {
    destination_listener: TcpListener,
    landing_listener: TcpListener,
    landing_handler: HandoffLandingHandler,
    line_handler: VisionHandler,
    client: TcpStream,
    established: RealityEstablished,
    client_write_records: Tls13RecordLayer,
    client_read_records: Tls13RecordLayer,
}

async fn handoff_rig() -> HandoffRig {
    let destination_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("destination must bind");
    let landing_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("landing must bind");
    let landing_address = landing_listener
        .local_addr()
        .expect("landing address must exist");
    let (client, server) = tcp_pair().await;
    let (established_tls, client_write_records, client_read_records) = tls_states();
    HandoffRig {
        destination_listener,
        landing_listener,
        landing_handler: test_landing_handler(),
        line_handler: handoff_vision_handler(landing_address),
        client,
        established: RealityEstablished::from_test_parts(
            TlsApplicationIo::new(server, established_tls),
            USER,
        ),
        client_write_records,
        client_read_records,
    }
}
