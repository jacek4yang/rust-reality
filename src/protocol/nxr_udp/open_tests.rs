//! Authentication and freshness tests for the NXR UDP-mode open.
//!
//! LANDING admits a UDP association only through [`super::decode_udp_open`]
//! (see `server::nxr::auth`), so the open's HMAC, time window, and port check
//! are the hop's admission boundary. These tests pin each of them directly.

use std::net::Ipv4Addr;

use super::keys::open_tag;
use super::layout::{OPEN_TAG_LEN, PORT_OFFSET, TIMESTAMP_OFFSET};
use super::{NxrUdpError, decode_udp_open, encode_udp_open};
use crate::protocol::nxr::NxrKey;
use crate::protocol::vless::{Address, Destination};

const NOW: u64 = 1_700_000_000;
const WINDOW: u64 = 10;

fn key() -> NxrKey {
    NxrKey::new([0x0b; 32])
}

fn open_at(timestamp: u64) -> Vec<u8> {
    let destination = Destination::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, 7)), 53);
    let mut open = Vec::new();
    encode_udp_open(
        &destination,
        [0xAB; 16],
        timestamp,
        [0x44; 16],
        &key(),
        &mut open,
    )
    .expect("encode");
    open
}

/// Re-seals a modified open with the genuine key, so only the field under
/// test (not the tag) decides the outcome.
fn reseal(open: &mut [u8]) {
    let authenticated_len = open.len() - OPEN_TAG_LEN;
    let tag = open_tag(&key(), &open[..authenticated_len]);
    open[authenticated_len..].copy_from_slice(&tag);
}

#[test]
fn every_authenticated_byte_and_the_tag_are_bound_by_the_hmac() {
    let open = open_at(NOW);
    decode_udp_open(&open, &key(), NOW, WINDOW).expect("genuine open");
    // Header bytes before the port are structural (magic, mode, address shape,
    // declared length) and fail their own checks; everything from the port on
    // carries no structural meaning the parser could reject first.
    for index in PORT_OFFSET..open.len() {
        let mut tampered = open.clone();
        tampered[index] ^= 0x01;
        assert_eq!(
            decode_udp_open(&tampered, &key(), NOW, WINDOW),
            Err(NxrUdpError::Authentication),
            "flipping byte {index} must fail authentication"
        );
    }
    assert_eq!(
        decode_udp_open(&open, &NxrKey::new([0x0c; 32]), NOW, WINDOW),
        Err(NxrUdpError::Authentication),
        "a different PSK must not authenticate"
    );
}

#[test]
fn time_window_is_symmetric_and_inclusive_at_its_bound() {
    for timestamp in [NOW - WINDOW, NOW, NOW + WINDOW] {
        decode_udp_open(&open_at(timestamp), &key(), NOW, WINDOW)
            .unwrap_or_else(|error| panic!("timestamp {timestamp} in window: {error:?}"));
    }
    for timestamp in [NOW - WINDOW - 1, NOW + WINDOW + 1, 0, u64::MAX] {
        assert_eq!(
            decode_udp_open(&open_at(timestamp), &key(), NOW, WINDOW),
            Err(NxrUdpError::TimeWindow),
            "timestamp {timestamp} outside the window must be rejected"
        );
    }
}

#[test]
fn authenticated_port_zero_is_rejected() {
    let mut open = open_at(NOW);
    open[PORT_OFFSET..PORT_OFFSET + 2].copy_from_slice(&0_u16.to_be_bytes());
    reseal(&mut open);
    assert_eq!(
        decode_udp_open(&open, &key(), NOW, WINDOW),
        Err(NxrUdpError::Port)
    );
    // Sanity: the resealed open is otherwise genuine.
    let mut port_one = open.clone();
    port_one[PORT_OFFSET..PORT_OFFSET + 2].copy_from_slice(&1_u16.to_be_bytes());
    reseal(&mut port_one);
    decode_udp_open(&port_one, &key(), NOW, WINDOW).expect("resealed open decodes");
    assert_eq!(
        u64::from_be_bytes(
            open[TIMESTAMP_OFFSET..TIMESTAMP_OFFSET + 8]
                .try_into()
                .unwrap()
        ),
        NOW
    );
}

#[test]
fn open_header_sizing_rejects_bad_magic_and_address_lengths() {
    use super::layout::{ADDRESS_DOMAIN, ADDRESS_IPV4, ADDRESS_LENGTH_OFFSET, MAX_DOMAIN_LEN};
    use super::udp_open_len_from_header;
    use crate::protocol::nxr::REQUEST_HEADER_LEN;

    let open = open_at(NOW);
    let header = &open[..REQUEST_HEADER_LEN];
    assert_eq!(udp_open_len_from_header(header), Ok(open.len()));

    let mut bad_magic = header.to_vec();
    bad_magic[0] ^= 0xff;
    assert_eq!(
        udp_open_len_from_header(&bad_magic),
        Err(NxrUdpError::Version)
    );

    let with_address = |kind: u8, length: u16| {
        let mut header = header.to_vec();
        header[5] = kind;
        header[ADDRESS_LENGTH_OFFSET..ADDRESS_LENGTH_OFFSET + 2]
            .copy_from_slice(&length.to_be_bytes());
        udp_open_len_from_header(&header)
    };
    let max = u16::try_from(MAX_DOMAIN_LEN).unwrap();
    assert!(with_address(ADDRESS_DOMAIN, max).is_ok());
    for (kind, length) in [
        (ADDRESS_DOMAIN, 0),
        (ADDRESS_DOMAIN, max + 1),
        (ADDRESS_IPV4, 5),
        (ADDRESS_IPV4, 16),
    ] {
        assert_eq!(
            with_address(kind, length),
            Err(NxrUdpError::Address),
            "kind {kind} length {length}"
        );
    }
}

#[test]
fn open_rejects_trailing_bytes_and_port_zero_on_encode() {
    let mut open = open_at(NOW);
    open.push(0);
    assert_eq!(
        decode_udp_open(&open, &key(), NOW, WINDOW),
        Err(NxrUdpError::Length)
    );

    let destination = Destination::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, 7)), 0);
    let mut out = Vec::new();
    assert_eq!(
        encode_udp_open(&destination, [0xAB; 16], NOW, [0x44; 16], &key(), &mut out),
        Err(NxrUdpError::Port)
    );
}
