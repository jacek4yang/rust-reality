use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use super::super::{HandoffLandingKeys, HandoffPsk, HandoffReplayCache};
use super::*;
use crate::crypto::StaticX25519Key;

const PSK: [u8; 32] = [0x21; 32];
const SECRET: [u8; 32] = [0x42; 32];
const USER: [u8; 16] = [0x07; 16];
const NOW: u64 = 1_800_000_000;

fn keys() -> HandoffLandingKeys {
    HandoffLandingKeys::single(HandoffPsk::new(PSK), StaticX25519Key::new(&SECRET))
}

fn replay() -> HandoffReplayCache {
    HandoffReplayCache::new(64, Duration::from_secs(61)).expect("cache")
}

fn pair() -> (UdpChannel, UdpChannel, Vec<u8>) {
    let public = StaticX25519Key::new(&SECRET).public_key();
    let mut open = Vec::new();
    let line = seal_open(&HandoffPsk::new(PSK), &public, USER, NOW, &mut open).expect("seal");
    let (opened, landing) = accept_open(&open, &keys(), &replay(), NOW, 30).expect("accept");
    assert_eq!(opened.user_id, USER);
    assert_eq!(opened.session_id, line.session_id());
    (line, landing, open)
}

#[test]
fn open_round_trip_derives_matching_direction_keys() {
    let (mut line, mut landing, open) = pair();
    assert_eq!(open.len(), OPEN_LEN);
    let mut wire = Vec::new();
    let mut plain = Vec::new();
    line.seal(PacketType::Data, b"uplink", &mut wire)
        .expect("seal");
    assert_eq!(landing.open(&wire, &mut plain), Ok(PacketType::Data));
    assert_eq!(plain, b"uplink");
    landing
        .seal(PacketType::Data, b"downlink", &mut wire)
        .expect("seal");
    assert_eq!(line.open(&wire, &mut plain), Ok(PacketType::Data));
    assert_eq!(plain, b"downlink");
    // A direction key never opens its own direction (reflection fails).
    line.seal(PacketType::Data, b"x", &mut wire).expect("seal");
    assert_eq!(
        line.open(&wire, &mut plain),
        Err(UdpPacketError::Authentication)
    );
}

#[test]
fn open_rejects_wrong_psk_wrong_key_replay_time_and_tamper() {
    let public = StaticX25519Key::new(&SECRET).public_key();
    let mut open = Vec::new();
    seal_open(&HandoffPsk::new([0x99; 32]), &public, USER, NOW, &mut open).expect("seal");
    assert_eq!(
        accept_open(&open, &keys(), &replay(), NOW, 30).unwrap_err(),
        UdpPacketError::Authentication
    );
    let other = StaticX25519Key::new(&[0x55; 32]).public_key();
    seal_open(&HandoffPsk::new(PSK), &other, USER, NOW, &mut open).expect("seal");
    assert_eq!(
        accept_open(&open, &keys(), &replay(), NOW, 30).unwrap_err(),
        UdpPacketError::Authentication
    );
    seal_open(&HandoffPsk::new(PSK), &public, USER, NOW, &mut open).expect("seal");
    let cache = replay();
    accept_open(&open, &keys(), &cache, NOW, 30).expect("first");
    assert_eq!(
        accept_open(&open, &keys(), &cache, NOW, 30).unwrap_err(),
        UdpPacketError::Replay
    );
    assert_eq!(
        accept_open(&open, &keys(), &replay(), NOW + 31, 30).unwrap_err(),
        UdpPacketError::TimeWindow
    );
    for index in 0..open.len() {
        let mut tampered = open.clone();
        tampered[index] ^= 0x01;
        assert!(
            accept_open(&tampered, &keys(), &replay(), NOW, 30).is_err(),
            "tampering byte {index} must fail"
        );
    }
    assert_eq!(
        accept_open(&open[..OPEN_LEN - 1], &keys(), &replay(), NOW, 30).unwrap_err(),
        UdpPacketError::Length
    );
}

#[test]
fn forged_open_without_psk_never_burns_replay_capacity() {
    // A one-slot cache: if a forged OPEN reserved its nonce, the genuine
    // OPEN below would be refused as capacity-exhausted.
    let cache = HandoffReplayCache::new(1, Duration::from_secs(61)).expect("cache");
    let public = StaticX25519Key::new(&SECRET).public_key();
    let mut forged = Vec::new();
    for attempt in 0..32_u8 {
        seal_open(
            &HandoffPsk::new([attempt; 32]),
            &public,
            USER,
            NOW,
            &mut forged,
        )
        .expect("seal");
        assert_eq!(
            accept_open(&forged, &keys(), &cache, NOW, 30).unwrap_err(),
            UdpPacketError::Authentication
        );
    }
    // Random bytes with a valid header shape are rejected the same way.
    let mut noise = forged.clone();
    for (index, byte) in noise.iter_mut().enumerate().skip(HEADER_LEN + 8) {
        *byte = u8::try_from(index % 251).expect("small");
    }
    assert_eq!(
        accept_open(&noise, &keys(), &cache, NOW, 30).unwrap_err(),
        UdpPacketError::Authentication
    );
    let mut genuine = Vec::new();
    seal_open(&HandoffPsk::new(PSK), &public, USER, NOW, &mut genuine).expect("seal");
    accept_open(&genuine, &keys(), &cache, NOW, 30).expect("genuine OPEN keeps its slot");
}

#[test]
fn open_accepts_rotation_candidates() {
    let rotated = HandoffLandingKeys::with_previous(
        HandoffPsk::new([0x77; 32]),
        vec![HandoffPsk::new(PSK)],
        StaticX25519Key::new(&[0x78; 32]),
        vec![StaticX25519Key::new(&SECRET)],
    )
    .expect("bounded");
    let public = StaticX25519Key::new(&SECRET).public_key();
    let mut open = Vec::new();
    seal_open(&HandoffPsk::new(PSK), &public, USER, NOW, &mut open).expect("seal");
    accept_open(&open, &rotated, &replay(), NOW, 30).expect("retired pair accepted");
}

#[test]
fn data_replay_reorder_tamper_and_foreign_session() {
    let (mut line, mut landing, _) = pair();
    let mut wires = Vec::new();
    for index in 0..8_u8 {
        let mut wire = Vec::new();
        line.seal(PacketType::Data, &[index], &mut wire)
            .expect("seal");
        wires.push(wire);
    }
    let mut plain = Vec::new();
    // Reordered delivery inside the window is accepted exactly once.
    for index in [3, 1, 7, 0, 2, 6, 5, 4] {
        assert_eq!(
            landing.open(&wires[index], &mut plain),
            Ok(PacketType::Data)
        );
        assert_eq!(plain, [u8::try_from(index).expect("small")]);
        assert_eq!(
            landing.open(&wires[index], &mut plain),
            Err(UdpPacketError::Replay)
        );
    }
    let mut tampered = wires[0].clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(landing.open(&tampered, &mut plain).is_err());
    // A forgery with a fresh counter must not advance the window.
    let mut forged = wires[7].clone();
    forged[HEADER_LEN - 1] = 0xff;
    assert_eq!(
        landing.open(&forged, &mut plain),
        Err(UdpPacketError::Authentication)
    );
    let mut next = Vec::new();
    line.seal(PacketType::Data, b"n", &mut next).expect("seal");
    assert_eq!(landing.open(&next, &mut plain), Ok(PacketType::Data));
    let (mut other_line, _, _) = pair();
    other_line
        .seal(PacketType::Data, b"z", &mut next)
        .expect("seal");
    assert_eq!(
        landing.open(&next, &mut plain),
        Err(UdpPacketError::Session)
    );
}

#[test]
fn replay_window_rejects_too_old_and_zero() {
    let mut window = ReplayWindow::new();
    assert!(!window.check(0));
    assert!(window.commit(1));
    assert!(window.commit(REPLAY_WINDOW_BITS + 10));
    assert!(!window.check(1), "older than the window");
    assert!(window.check(11));
    assert!(window.commit(11));
    assert!(!window.commit(11));
    assert!(window.commit(u64::MAX - 1));
    assert!(!window.check(REPLAY_WINDOW_BITS + 10));
}

#[test]
fn probe_padding_produces_exact_sizes() {
    let (mut line, mut landing, _) = pair();
    let mut wire = Vec::new();
    let mut plain = Vec::new();
    for size in [64, BASE_PLPMTU, 1472, 8000] {
        line.seal_padded(PacketType::Probe, &7_u32.to_be_bytes(), size, &mut wire)
            .expect("seal");
        assert_eq!(wire.len(), size);
        assert_eq!(landing.open(&wire, &mut plain), Ok(PacketType::Probe));
        assert_eq!(&plain[..4], &7_u32.to_be_bytes());
    }
}

#[test]
fn data_plaintext_round_trips_ipv4_ipv6_and_rejects_bad_addresses() {
    let mut out = Vec::new();
    for address in [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 53),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
    ] {
        encode_data_plaintext(address, b"payload", &mut out).expect("encode");
        let (decoded, payload) = decode_data(&out).expect("decode");
        assert_eq!(decoded, address);
        assert_eq!(payload, b"payload");
    }
    assert_eq!(
        encode_data_plaintext("1.2.3.4:0".parse().expect("addr"), b"", &mut out),
        Err(UdpPacketError::Address)
    );
    assert_eq!(
        encode_data_plaintext("0.0.0.0:53".parse().expect("addr"), b"", &mut out),
        Err(UdpPacketError::Address)
    );
    let big = vec![0_u8; MAX_UDP_PAYLOAD_LEN + 1];
    assert_eq!(
        encode_data_plaintext("1.2.3.4:53".parse().expect("addr"), &big, &mut out),
        Err(UdpPacketError::Length)
    );
    assert_eq!(decode_data(&[9, 1, 2]), Err(UdpPacketError::Address));
    assert_eq!(decode_data(&[4, 1, 2]), Err(UdpPacketError::Length));
}

#[test]
fn fragments_reassemble_out_of_order_and_respect_bounds() {
    let plaintext: Vec<u8> = (0..MAX_DATA_PLAINTEXT_LEN)
        .map(|index| u8::try_from(index % 251).expect("byte"))
        .collect();
    let fragments = split_fragments(9, &plaintext, 1000).expect("split");
    assert_eq!(fragments.len(), MAX_DATA_PLAINTEXT_LEN.div_ceil(1000));
    let now = Instant::now();
    let mut reassembler = Reassembler::new(ReassemblyLimits::default());
    let mut order: Vec<usize> = (0..fragments.len()).rev().collect();
    order.swap(0, 3);
    let mut result = None;
    for index in order {
        if let Some(whole) = reassembler.insert(&fragments[index], now).expect("insert") {
            result = Some(whole);
        }
    }
    assert_eq!(result.expect("complete"), plaintext);
    assert_eq!(reassembler.buffered_bytes(), 0);
    assert!(
        split_fragments(1, &plaintext, 100).is_err(),
        "too many fragments"
    );
    assert!(split_fragments(1, &[], 100).is_err());
}

#[test]
fn reassembly_times_out_evicts_and_caps_memory() {
    let limits = ReassemblyLimits {
        max_groups: 2,
        max_bytes: 3000,
        timeout: Duration::from_millis(100),
    };
    let now = Instant::now();
    let mut reassembler = Reassembler::new(limits);
    let a = split_fragments(1, &[1; 2000], 1000).expect("split");
    let b = split_fragments(2, &[2; 2000], 1000).expect("split");
    let c = split_fragments(3, &[3; 2000], 1000).expect("split");
    assert_eq!(reassembler.insert(&a[0], now).expect("a0"), None);
    assert_eq!(reassembler.insert(&b[0], now).expect("b0"), None);
    // A third group evicts the oldest; byte cap evicts too.
    assert_eq!(reassembler.insert(&c[0], now).expect("c0"), None);
    assert!(reassembler.pending_groups() <= 2);
    assert!(reassembler.buffered_bytes() <= 3000);
    assert!(reassembler.dropped_groups() >= 1);
    // Timeout: the late fragment of an expired group never completes it.
    let later = now + Duration::from_millis(150);
    assert_eq!(reassembler.insert(&c[1], later).expect("c1"), None);
    assert_eq!(reassembler.pending_groups(), 1);
    // Inconsistent count discards the group.
    let mut lying = c[0].clone();
    lying[5] = 3;
    assert_eq!(reassembler.insert(&lying, later).expect("lie"), None);
    assert!(reassembler.insert(&[0, 0, 0, 1, 5, 2, 0], later).is_err());
    assert!(reassembler.insert(&[0, 0, 0, 1, 0, 1, 0], later).is_err());
}

/// Simulated path: probes at or below `path` are acknowledged.
fn run_search(prober: &mut PmtuProber, path: usize, start: Instant, steps: u32) -> Instant {
    let mut now = start;
    for _ in 0..steps {
        if let Some(probe) = prober.poll(now)
            && probe.size <= path
        {
            prober.on_probe_ack(probe.id, probe.size, now);
        }
        now += Duration::from_millis(250);
    }
    now
}

#[test]
fn pmtu_search_converges_to_path_limit() {
    let start = Instant::now();
    let mut prober = PmtuProber::discover(1472, PmtuTimers::default(), start);
    assert_eq!(prober.plpmtu(), BASE_PLPMTU);
    run_search(&mut prober, 1400, start, 200);
    assert!(prober.search_complete());
    assert!(prober.plpmtu() <= 1400);
    assert!(prober.plpmtu() > 1400 - 16, "plpmtu {}", prober.plpmtu());
}

#[test]
fn pmtu_detects_black_hole_and_researches() {
    let start = Instant::now();
    let timers = PmtuTimers {
        confirm_interval: Duration::from_secs(2),
        ..PmtuTimers::default()
    };
    let mut prober = PmtuProber::discover(1472, timers, start);
    let now = run_search(&mut prober, 1472, start, 200);
    assert!(prober.plpmtu() > 1450);
    // The path shrinks silently (no ICMP): confirmation probes are lost.
    let now = run_search(&mut prober, 1300, now, 400);
    assert_eq!(prober.black_holes(), 1);
    assert!(prober.plpmtu() <= 1300 && prober.plpmtu() >= BASE_PLPMTU);
    // A base black hole drops to the floor, then searches up to the path.
    run_search(&mut prober, 600, now, 400);
    assert!(prober.black_holes() >= 2);
    assert!((MIN_PLPMTU..=600).contains(&prober.plpmtu()));
}

#[test]
fn pmtu_validates_base_first_and_finds_a_path_below_it_quickly() {
    let start = Instant::now();
    let mut prober = PmtuProber::discover(1472, PmtuTimers::default(), start);
    // The very first probe confirms the starting size.
    assert_eq!(
        prober.poll(start).map(|probe| probe.size),
        Some(BASE_PLPMTU)
    );
    // Path silently drops everything above 1000 bytes from the start:
    // three lost base probes (3 s) fall back to the floor.
    let now = run_search(&mut prober, 1000, start, 14);
    assert_eq!(prober.black_holes(), 1);
    assert!(prober.plpmtu() < 1000);
    // The search then climbs to just under the silent limit.
    run_search(&mut prober, 1000, now, 120);
    assert!(prober.search_complete());
    assert!(
        (1000 - 16..=1000).contains(&prober.plpmtu()),
        "plpmtu {}",
        prober.plpmtu()
    );
}

#[test]
fn pmtu_kernel_feedback_lowers_and_raise_recovers() {
    let start = Instant::now();
    let timers = PmtuTimers {
        raise_interval: Duration::from_secs(5),
        ..PmtuTimers::default()
    };
    let mut prober = PmtuProber::discover(1472, timers, start);
    let now = run_search(&mut prober, 1472, start, 200);
    prober.on_send_too_big(prober.plpmtu(), Some(1252));
    assert_eq!(prober.plpmtu(), 1252);
    assert_eq!(prober.ceiling(), 1252);
    // The path grows back mid-session: the raise timer finds it.
    run_search(&mut prober, 1472, now, 400);
    assert!(prober.plpmtu() > 1450, "plpmtu {}", prober.plpmtu());
    // Interface below the base.
    let mut small = PmtuProber::discover(plpmtu_from_ip_mtu(1000, false), timers, start);
    assert_eq!(small.plpmtu(), 972);
    run_search(&mut small, 972, start, 50);
    assert_eq!(small.plpmtu(), 972);
}

#[test]
fn pmtu_fixed_never_probes() {
    let now = Instant::now();
    let mut prober = PmtuProber::fixed(1400, now);
    assert_eq!(prober.poll(now + Duration::from_secs(3600)), None);
    assert_eq!(prober.plpmtu(), 1400);
    assert_eq!(plpmtu_from_ip_mtu(1280, true), 1232);
    assert_eq!(plpmtu_from_ip_mtu(100, true), MIN_PLPMTU);
}
