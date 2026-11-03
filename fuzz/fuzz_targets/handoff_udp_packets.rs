#![no_main]

//! Native Handoff UDP channel (ADR 0069): raw header/OPEN/DATA/FRAG parsing
//! on attacker bytes, plus a structured seal → open round trip with
//! bitflip rejection and a fragment split → shuffled reassembly round trip.

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use libfuzzer_sys::fuzz_target;
use rust_reality::{
    crypto::StaticX25519Key,
    protocol::handoff::{
        HandoffLandingKeys, HandoffPsk, HandoffReplayCache,
        udp::{
            MAX_FRAGMENTS, MAX_UDP_PAYLOAD_LEN, PacketType, Reassembler, ReassemblyLimits,
            accept_open, decode_data, encode_data_plaintext, parse_header, seal_open,
            split_fragments,
        },
    },
};

const NOW: u64 = 1_800_000_000;

fuzz_target!(|data: &[u8]| {
    let keys = HandoffLandingKeys::single(
        HandoffPsk::new([0x55; 32]),
        StaticX25519Key::new(&[0x77; 32]),
    );
    let replay = HandoffReplayCache::new(64, Duration::from_secs(61)).expect("bounded cache");
    // Raw attacker input on every LANDING-facing parser.
    let _ = parse_header(data);
    let _ = accept_open(data, &keys, &replay, NOW, 30);
    let _ = decode_data(data);
    let started = Instant::now();
    let mut reassembler = Reassembler::new(ReassemblyLimits::default());
    for (step, chunk) in data.chunks(97).enumerate() {
        let at = started + Duration::from_millis(u64::try_from(step).unwrap_or(0) * 400);
        if let Ok(Some(whole)) = reassembler.insert(chunk, at) {
            let _ = decode_data(&whole);
        }
        assert!(reassembler.buffered_bytes() <= ReassemblyLimits::default().max_bytes);
    }

    // Structured round trip through a genuine session.
    let mode = data.first().copied().unwrap_or(0);
    let public = StaticX25519Key::new(&[0x77; 32]).public_key();
    let mut open = Vec::new();
    let mut line = seal_open(&HandoffPsk::new([0x55; 32]), &public, [mode; 16], NOW, &mut open)
        .expect("seal OPEN");
    let (_, mut landing) = accept_open(&open, &keys, &replay, NOW, 30).expect("genuine OPEN");
    let mut plain = Vec::new();
    let _ = landing.open(data, &mut plain);
    let address = if mode & 1 == 0 {
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, mode), u16::from(mode) | 1))
    } else {
        SocketAddr::from((Ipv6Addr::from([mode; 16]), u16::from(mode) | 1))
    };
    let payload = &data[..data.len().min(MAX_UDP_PAYLOAD_LEN)];
    let mut sealed_plain = Vec::new();
    encode_data_plaintext(address, payload, &mut sealed_plain).expect("bounded payload");
    let mut wire = Vec::new();
    line.seal(PacketType::Data, &sealed_plain, &mut wire).expect("seal DATA");
    let mut flipped = wire.clone();
    let index = usize::from(mode) % flipped.len();
    flipped[index] ^= 0x01;
    assert!(landing.open(&flipped, &mut plain).is_err(), "bitflip must fail");
    assert_eq!(landing.open(&wire, &mut plain), Ok(PacketType::Data));
    let (decoded, body) = decode_data(&plain).expect("own plaintext decodes");
    assert_eq!(decoded, address);
    assert_eq!(body, payload);
    assert!(landing.open(&wire, &mut plain).is_err(), "replay must fail");

    // Fragmentation round trip in a data-chosen order.
    let chunk = 64 + usize::from(mode) * 8;
    if let Ok(fragments) = split_fragments(u32::from(mode), &sealed_plain, chunk)
        && fragments.len() > 1
    {
        assert!(fragments.len() <= MAX_FRAGMENTS);
        let mut reassembler = Reassembler::new(ReassemblyLimits::default());
        let mut whole = None;
        let rotate = usize::from(mode) % fragments.len();
        for fragment in fragments.iter().cycle().skip(rotate).take(fragments.len()) {
            if let Some(done) = reassembler.insert(fragment, started).expect("own fragment") {
                whole = Some(done);
            }
        }
        assert_eq!(whole.as_deref(), Some(sealed_plain.as_slice()));
    }
});
