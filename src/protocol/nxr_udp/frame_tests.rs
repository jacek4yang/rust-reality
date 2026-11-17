//! Authenticated-body strictness for NXR UDP frames.
//!
//! Every frame here carries a genuine session MAC, so each case pins the body
//! parser (and the length prefix) rather than the authenticator.

use super::layout::{ADDRESS_DOMAIN, MAX_DOMAIN_LEN};
use super::{
    DIR_LANDING_TO_LINE, DIR_LINE_TO_LANDING, FRAME_TYPE_CLOSE, FRAME_TYPE_DATAGRAM,
    MAX_FRAME_BODY_LEN, NXR_UDP_MAX_PAYLOAD, NxrUdpError, NxrUdpSessionKey, decode_frame,
    encode_frame, frame_wire_len_from_prefix,
};
use crate::protocol::nxr::NxrKey;
use crate::protocol::vless::{Address, Destination};

fn session() -> NxrUdpSessionKey {
    NxrUdpSessionKey::derive(&NxrKey::new([0x5c; 32]), b"frame-tests")
}

/// Length-prefixes `body` and appends a valid LINE→LANDING MAC.
fn sealed(body: &[u8]) -> Vec<u8> {
    let mut wire = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    wire.extend_from_slice(body);
    wire.extend_from_slice(&session().frame_tag(DIR_LINE_TO_LANDING, body));
    wire
}

fn body(frame_type: u8, flags: u8, destination: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut body = vec![frame_type, flags, 0, 0, 0, 7];
    body.extend_from_slice(destination);
    body.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    body.extend_from_slice(payload);
    body
}

fn domain_destination(length: usize) -> Vec<u8> {
    let mut destination = vec![ADDRESS_DOMAIN];
    destination.extend_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
    destination.extend_from_slice(&53_u16.to_be_bytes());
    destination.extend(std::iter::repeat_n(b'a', length));
    destination
}

fn decode(wire: &[u8]) -> Result<super::NxrUdpFrame, NxrUdpError> {
    decode_frame(wire, &session(), DIR_LINE_TO_LANDING).map(|(frame, _)| frame)
}

#[test]
fn length_prefix_rejects_zero_and_enforces_the_exact_body_cap() {
    let prefix = |length: usize| u32::try_from(length).unwrap().to_be_bytes();
    assert_eq!(
        frame_wire_len_from_prefix(&prefix(0)),
        Err(NxrUdpError::Length)
    );
    assert_eq!(
        frame_wire_len_from_prefix(&prefix(MAX_FRAME_BODY_LEN)),
        Ok(4 + MAX_FRAME_BODY_LEN + 32)
    );
    assert_eq!(
        frame_wire_len_from_prefix(&prefix(MAX_FRAME_BODY_LEN + 1)),
        Err(NxrUdpError::Length)
    );
}

#[test]
fn authenticated_bodies_reject_unknown_types_trailing_bytes_and_oversized_payloads() {
    assert!(decode(&sealed(&body(FRAME_TYPE_DATAGRAM, 0, &[], b"ok"))).is_ok());
    assert!(decode(&sealed(&body(FRAME_TYPE_CLOSE, 0, &[], b""))).is_ok());
    for frame_type in [0, 3, 0xff] {
        assert_eq!(
            decode(&sealed(&body(frame_type, 0, &[], b"x"))),
            Err(NxrUdpError::FrameType)
        );
    }

    let mut trailing = body(FRAME_TYPE_DATAGRAM, 0, &[], b"x");
    trailing.push(0);
    assert_eq!(decode(&sealed(&trailing)), Err(NxrUdpError::Length));

    let at_cap = vec![0_u8; NXR_UDP_MAX_PAYLOAD];
    let frame = decode(&sealed(&body(FRAME_TYPE_DATAGRAM, 0, &[], &at_cap))).unwrap();
    assert_eq!(frame.payload.len(), NXR_UDP_MAX_PAYLOAD);
    let over = vec![0_u8; NXR_UDP_MAX_PAYLOAD + 1];
    assert_eq!(
        decode(&sealed(&body(FRAME_TYPE_DATAGRAM, 0, &[], &over))),
        Err(NxrUdpError::Payload)
    );
}

#[test]
fn authenticated_destinations_reject_port_zero_and_out_of_range_domains() {
    let mut port_zero = domain_destination(4);
    port_zero[3..5].copy_from_slice(&[0, 0]);
    assert_eq!(
        decode(&sealed(&body(FRAME_TYPE_DATAGRAM, 1, &port_zero, b"x"))),
        Err(NxrUdpError::Port)
    );

    let frame = decode(&sealed(&body(
        FRAME_TYPE_DATAGRAM,
        1,
        &domain_destination(MAX_DOMAIN_LEN),
        b"x",
    )))
    .expect("maximum domain is accepted");
    assert_eq!(
        frame.destination,
        Some(Destination::new(
            Address::Domain("a".repeat(MAX_DOMAIN_LEN)),
            53
        ))
    );
    for length in [0, MAX_DOMAIN_LEN + 1, 1024] {
        assert_eq!(
            decode(&sealed(&body(
                FRAME_TYPE_DATAGRAM,
                1,
                &domain_destination(length),
                b"x"
            ))),
            Err(NxrUdpError::Address),
            "domain length {length}"
        );
    }
}

#[test]
fn encoder_rejects_unknown_directions_and_port_zero_destinations() {
    let mut out = vec![0xAA];
    for direction in [2, 0xff] {
        assert_eq!(
            encode_frame(
                &session(),
                direction,
                FRAME_TYPE_DATAGRAM,
                0,
                None,
                b"x",
                &mut out
            ),
            Err(NxrUdpError::Direction)
        );
    }
    let port_zero = Destination::new(Address::Domain("dns.test".to_owned()), 0);
    assert_eq!(
        encode_frame(
            &session(),
            DIR_LANDING_TO_LINE,
            FRAME_TYPE_DATAGRAM,
            0,
            Some(&port_zero),
            b"x",
            &mut out
        ),
        Err(NxrUdpError::Port)
    );
    assert_eq!(out, vec![0xAA], "failed encode must not modify the buffer");
}
