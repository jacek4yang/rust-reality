//! Loopback integration tests: a real LINE association against a real
//! LANDING channel task over UDP sockets.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use tokio::{net::UdpSocket, sync::watch, task::JoinHandle, time::timeout};

use super::{
    LandingUdpPolicy, LandingUdpStats, XudpHandoffUdpAssociation, bind_landing_udp, run_landing_udp,
};
use crate::{
    config::{SecretString, node::outbound::HandoffOutboundConfig},
    crypto::StaticX25519Key,
    protocol::{
        handoff::{
            HandoffLandingKeys, HandoffPsk,
            udp::{MAX_UDP_PAYLOAD_LEN, PacketType, UdpChannel, encode_data_plaintext, seal_open},
        },
        vless::{Destination, XudpOption, XudpPacket, XudpSessionStatus, decode_xudp_packet},
    },
    server::{
        handoff::HandoffLine,
        xudp::{XudpGlobalMap, XudpSessionError, destination_to_socket_addr},
    },
    transport::FdBudget,
};

const PSK: [u8; 32] = [0x31; 32];
const SECRET: [u8; 32] = [0x52; 32];
const USER: [u8; 16] = [0x0a; 16];

fn policy(fixed_mtu: Option<u16>, direct_egress: bool) -> LandingUdpPolicy {
    LandingUdpPolicy {
        keys: HandoffLandingKeys::single(HandoffPsk::new(PSK), StaticX25519Key::new(&SECRET)),
        maximum_time_difference: 30,
        fixed_mtu,
        direct_egress,
    }
}

struct Landing {
    address: SocketAddr,
    stats: Arc<LandingUdpStats>,
    _shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl Drop for Landing {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn start_landing_on(address: SocketAddr, policy: LandingUdpPolicy) -> Landing {
    let socket = bind_landing_udp(address).expect("bind landing channel");
    let address = socket.local_addr().expect("landing address");
    let stats = Arc::new(LandingUdpStats::default());
    let (shutdown, receiver) = watch::channel(false);
    let task = tokio::spawn(run_landing_udp(
        socket,
        move || Some(policy.clone()),
        FdBudget::new(1024),
        Arc::clone(&stats),
        receiver,
    ));
    Landing {
        address,
        stats,
        _shutdown: shutdown,
        task,
    }
}

fn start_landing(policy: LandingUdpPolicy) -> Landing {
    start_landing_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), policy)
}

fn line(landing: SocketAddr, udp_mtu: Option<u16>, connect_timeout_ms: u64) -> HandoffLine {
    let landing_public = StaticX25519Key::new(&SECRET).public_key();
    HandoffLine::from_settings(&HandoffOutboundConfig {
        udp_port: Some(landing.port()),
        udp_mtu,
        address: landing.ip().to_string(),
        // The TCP port is never dialed by the UDP channel.
        port: 9,
        psk: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(PSK)),
        landing_public_key: BASE64_URL_SAFE_NO_PAD.encode(landing_public),
        connect_timeout_ms: Some(connect_timeout_ms),
        first_byte_timeout_ms: Some(1_000),
        warm_tcp: Some(false),
    })
    .expect("handoff line settings")
}

/// UDP echo that counts every datagram it receives.
async fn echo(address: SocketAddr) -> (SocketAddr, Arc<AtomicU64>, JoinHandle<()>) {
    let socket = UdpSocket::bind(address).await.expect("bind echo");
    let local = socket.local_addr().expect("echo address");
    let received = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&received);
    let task = tokio::spawn(async move {
        let mut buffer = vec![0_u8; 65_536];
        while let Ok((length, source)) = socket.recv_from(&mut buffer).await {
            counter.fetch_add(1, Ordering::Relaxed);
            let _ = socket.send_to(&buffer[..length], source).await;
        }
    });
    (local, received, task)
}

fn keep(destination: SocketAddr, payload: Vec<u8>) -> XudpPacket {
    XudpPacket {
        session_id: 0,
        status: XudpSessionStatus::Keep,
        option: XudpOption::DATA,
        destination: Some(Destination::from(destination)),
        global_id: None,
        payload,
    }
}

async fn round_trip(
    association: &mut XudpHandoffUdpAssociation<'_>,
    destination: SocketAddr,
    payload: Vec<u8>,
) -> (SocketAddr, Vec<u8>) {
    let target = Destination::from(destination);
    association
        .handle_uplink_packet(&keep(destination, payload), Some(&target), Instant::now())
        .await
        .expect("uplink");
    let mut frame = Vec::new();
    timeout(
        Duration::from_secs(5),
        association.recv_downlink_frame(&mut [], &mut frame, Instant::now()),
    )
    .await
    .expect("downlink within deadline")
    .expect("downlink frame");
    let (packet, _) = decode_xudp_packet(&frame).expect("decode downlink XUDP frame");
    let source =
        destination_to_socket_addr(&packet.destination.expect("downlink names its source"))
            .expect("downlink source is an address");
    (source, packet.payload)
}

fn payload(tag: u8, length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| tag ^ u8::try_from(index % 251).expect("small"))
        .collect()
}

#[tokio::test]
async fn multi_destination_and_large_datagrams_round_trip_natively() {
    let landing = start_landing(policy(None, true));
    let handoff = line(landing.address, None, 2_000);
    let globals = XudpGlobalMap::new();
    let (echo_a, seen_a, _a) = echo(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await;
    let (echo_b, seen_b, _b) = echo(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await;
    let mut association = XudpHandoffUdpAssociation::open(
        &handoff,
        &Destination::from(echo_a),
        USER,
        None,
        &globals,
        Instant::now(),
    )
    .await
    .expect("open");
    // Alternating destinations in one association (the reported failure
    // shape), including sizes above the conservative base PLPMTU so the
    // fragmentation path runs before any probe has raised it.
    let sizes = [1_usize, 64, 1_200, 1_350, 1_472, 4_000, MAX_UDP_PAYLOAD_LEN];
    for (round, size) in sizes.iter().copied().enumerate() {
        for (destination, tag) in [(echo_a, 0xa0_u8), (echo_b, 0xb0_u8)] {
            let sent = payload(tag ^ u8::try_from(round).expect("small"), size);
            let (source, echoed) = round_trip(&mut association, destination, sent.clone()).await;
            assert_eq!(source, destination, "reply names the real source");
            assert_eq!(echoed, sent, "{size}-byte datagram survives intact");
        }
    }
    assert!(association.confirmed());
    assert!(association.channel_stats().fragmented_datagrams > 0);
    assert!(association.channel_stats().reassembled_datagrams > 0);
    let rounds = u64::try_from(sizes.len()).expect("small");
    assert_eq!(seen_a.load(Ordering::Relaxed), rounds);
    assert_eq!(seen_b.load(Ordering::Relaxed), rounds);
    assert_eq!(landing.stats.sessions_opened.load(Ordering::Relaxed), 1);
    assert_eq!(
        landing.stats.uplink_datagrams.load(Ordering::Relaxed),
        2 * rounds
    );
    association.close(Instant::now()).await;
    wait_for(|| landing.stats.sessions_closed.load(Ordering::Relaxed) == 1).await;
}

#[tokio::test]
async fn ipv6_channel_and_ipv6_destination_round_trip() {
    let loopback6 = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 0));
    if std::net::UdpSocket::bind(loopback6).is_err() {
        eprintln!("SKIP: no IPv6 loopback on this host");
        return;
    }
    let landing = start_landing_on(loopback6, policy(None, true));
    let handoff = line(landing.address, None, 2_000);
    let globals = XudpGlobalMap::new();
    let (echo6, _, _e6) = echo(loopback6).await;
    let mut association = XudpHandoffUdpAssociation::open(
        &handoff,
        &Destination::from(echo6),
        USER,
        None,
        &globals,
        Instant::now(),
    )
    .await
    .expect("open over IPv6");
    for size in [32_usize, 1_300, 3_000] {
        let sent = payload(0x66, size);
        let (source, echoed) = round_trip(&mut association, echo6, sent.clone()).await;
        assert_eq!(source, echo6);
        assert_eq!(echoed, sent);
    }
}

#[tokio::test]
async fn fixed_minimum_mtu_fragments_every_large_datagram_within_limits() {
    let landing = start_landing(policy(Some(576), true));
    let handoff = line(landing.address, Some(576), 2_000);
    let globals = XudpGlobalMap::new();
    let (echo_a, _, _a) = echo(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await;
    let mut association = XudpHandoffUdpAssociation::open(
        &handoff,
        &Destination::from(echo_a),
        USER,
        None,
        &globals,
        Instant::now(),
    )
    .await
    .expect("open");
    let limit = association.plpmtu();
    assert!(limit < 576, "fixed MTU bounds every packet, got {limit}");
    for size in [1_200_usize, 2_500, MAX_UDP_PAYLOAD_LEN] {
        let sent = payload(0x5a, size);
        let (_, echoed) = round_trip(&mut association, echo_a, sent.clone()).await;
        assert_eq!(echoed, sent, "{size}-byte datagram through a 576-byte path");
    }
    assert_eq!(association.plpmtu(), limit, "fixed mode never probes");
    assert!(association.channel_stats().fragments_sent >= 15);
}

#[tokio::test]
async fn lost_open_is_retransmitted_until_landing_answers() {
    // Reserve a port, drop everything sent to it for a while, then start
    // LANDING on the same port: the first OPEN (and its datagram) is lost.
    let placeholder = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let address = placeholder.local_addr().expect("address");
    let handoff = line(address, None, 5_000);
    let globals = XudpGlobalMap::new();
    let (echo_a, _, _a) = echo(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await;
    let mut association = XudpHandoffUdpAssociation::open(
        &handoff,
        &Destination::from(echo_a),
        USER,
        None,
        &globals,
        Instant::now(),
    )
    .await
    .expect("open");
    let target = Destination::from(echo_a);
    association
        .handle_uplink_packet(
            &keep(echo_a, b"lost".to_vec()),
            Some(&target),
            Instant::now(),
        )
        .await
        .expect("uplink before landing exists");
    drop(placeholder);
    let landing = start_landing_on(address, policy(None, true));
    // Drive retransmission: nothing comes back for the lost datagram, but the
    // retransmitted OPEN must be acknowledged.
    let mut frame = Vec::new();
    let _ = timeout(
        Duration::from_secs(3),
        association.recv_downlink_frame(&mut [], &mut frame, Instant::now()),
    )
    .await;
    assert!(association.confirmed(), "retransmitted OPEN acknowledged");
    assert_eq!(landing.stats.sessions_opened.load(Ordering::Relaxed), 1);
    let (_, echoed) = round_trip(&mut association, echo_a, b"after".to_vec()).await;
    assert_eq!(echoed, b"after");
}

#[tokio::test]
async fn silent_or_refusing_landing_fails_closed_with_open_timeout() {
    for direct_egress in [false, true] {
        let landing = if direct_egress {
            None
        } else {
            Some(start_landing(policy(None, false)))
        };
        let address = landing.as_ref().map_or_else(
            || {
                // Bound but never read: OPENs vanish.
                let silent = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
                let address = silent.local_addr().expect("address");
                std::mem::forget(silent);
                address
            },
            |landing| landing.address,
        );
        let handoff = line(address, None, 800);
        let globals = XudpGlobalMap::new();
        let destination = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
        let started = Instant::now();
        let mut association = XudpHandoffUdpAssociation::open(
            &handoff,
            &Destination::from(destination),
            USER,
            None,
            &globals,
            started,
        )
        .await
        .expect("open is local");
        let mut frame = Vec::new();
        let error = timeout(
            Duration::from_secs(5),
            association.recv_downlink_frame(&mut [], &mut frame, Instant::now()),
        )
        .await
        .expect("bounded")
        .expect_err("no acknowledgement must fail the association");
        assert!(
            matches!(error, XudpSessionError::HandoffUdpOpenTimeout),
            "{error:?}"
        );
        assert!(started.elapsed() >= Duration::from_millis(700));
        if let Some(landing) = landing {
            assert!(landing.stats.refused_opens.load(Ordering::Relaxed) >= 1);
            assert_eq!(landing.stats.sessions_opened.load(Ordering::Relaxed), 0);
        }
    }
}

#[tokio::test]
async fn landing_forwards_nothing_unauthenticated_and_follows_nat_rebinding() {
    let landing = start_landing(policy(None, true));
    let (echo_a, seen, _a) = echo(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await;
    let attacker = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let public = StaticX25519Key::new(&SECRET).public_key();

    // Garbage, truncated headers, and an OPEN sealed with the wrong PSK.
    let mut forged_open = Vec::new();
    let mut forged = seal_open(
        &HandoffPsk::new([0x99; 32]),
        &public,
        USER,
        unix(),
        &mut forged_open,
    )
    .expect("seal");
    attacker
        .send_to(&[0xff; 3], landing.address)
        .await
        .expect("send");
    attacker
        .send_to(&[1; 200], landing.address)
        .await
        .expect("send");
    attacker
        .send_to(&forged_open, landing.address)
        .await
        .expect("send");
    let mut plain = Vec::new();
    encode_data_plaintext(echo_a, b"forged", &mut plain).expect("plaintext");
    let mut wire = Vec::new();
    forged
        .seal(PacketType::Data, &plain, &mut wire)
        .expect("seal");
    attacker
        .send_to(&wire, landing.address)
        .await
        .expect("send");

    // A genuine session driven by hand.
    let line_a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let mut open = Vec::new();
    let mut channel =
        seal_open(&HandoffPsk::new(PSK), &public, USER, unix(), &mut open).expect("seal");
    line_a.send_to(&open, landing.address).await.expect("send");
    let mut buffer = vec![0_u8; 65_536];
    recv_kind(&line_a, &mut channel, PacketType::OpenAck, "ack").await;
    // A replayed OPEN from another address is never acknowledged there.
    attacker
        .send_to(&open, landing.address)
        .await
        .expect("send");
    assert!(
        timeout(Duration::from_millis(300), attacker.recv_from(&mut buffer))
            .await
            .is_err(),
        "LANDING never answers an unauthenticated or replayed sender"
    );
    recv_kind(
        &line_a,
        &mut channel,
        PacketType::OpenAck,
        "re-ack to the bound peer",
    )
    .await;

    encode_data_plaintext(echo_a, b"genuine", &mut plain).expect("plaintext");
    channel
        .seal(PacketType::Data, &plain, &mut wire)
        .expect("seal");
    line_a.send_to(&wire, landing.address).await.expect("send");
    recv_kind(&line_a, &mut channel, PacketType::Data, "reply").await;
    // The captured DATA replayed (from anywhere) is never forwarded again.
    line_a.send_to(&wire, landing.address).await.expect("send");
    attacker
        .send_to(&wire, landing.address)
        .await
        .expect("send");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        seen.load(Ordering::Relaxed),
        1,
        "only the genuine datagram reached the destination"
    );

    // LINE's NAT rebinds: a fresh authenticated packet from a new address
    // moves the session there.
    let line_b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    encode_data_plaintext(echo_a, b"rebound", &mut plain).expect("plaintext");
    channel
        .seal(PacketType::Data, &plain, &mut wire)
        .expect("seal");
    line_b.send_to(&wire, landing.address).await.expect("send");
    recv_kind(
        &line_b,
        &mut channel,
        PacketType::Data,
        "reply follows the rebinding",
    )
    .await;
    assert_eq!(seen.load(Ordering::Relaxed), 2);
    assert_eq!(landing.stats.sessions_opened.load(Ordering::Relaxed), 1);
    assert!(landing.stats.rejected_packets.load(Ordering::Relaxed) >= 6);
}

/// Receives until one packet of kind `want`, skipping LANDING's PMTU probes.
async fn recv_kind(
    socket: &UdpSocket,
    channel: &mut UdpChannel,
    want: PacketType,
    context: &str,
) -> Vec<u8> {
    let mut buffer = vec![0_u8; 65_536];
    let mut plain = Vec::new();
    loop {
        let (length, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
            .await
            .expect(context)
            .expect("recv");
        match channel.open(&buffer[..length], &mut plain) {
            Ok(kind) if kind == want => return plain,
            Ok(PacketType::Probe | PacketType::ProbeAck) => {}
            other => panic!("{context}: unexpected {other:?}"),
        }
    }
}

fn unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

async fn wait_for(condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !condition() {
        assert!(Instant::now() < deadline, "condition not reached in time");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
