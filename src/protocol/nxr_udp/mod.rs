//! NXR UDP association over the LINE→LANDING TCP hop (ADR 0060 Option A).
//!
//! After an authenticated UDP-mode open ([`crate::protocol::nxr::FLAG_UDP`]), both
//! directions exchange length-prefixed datagram frames whose destination fields
//! are covered by a session MAC derived from the PSK and the open transcript.
//! Payload bytes are not encrypted (same hop threat model as TCP NXR).

mod error;
mod keys;
mod layout;
mod open;
mod wire;

pub use error::NxrUdpError;
pub use keys::NxrUdpSessionKey;
pub use layout::{
    DIR_LANDING_TO_LINE, DIR_LINE_TO_LANDING, FRAME_FLAG_DESTINATION, FRAME_LEN_SIZE,
    FRAME_TYPE_CLOSE, FRAME_TYPE_DATAGRAM, MAX_FRAME_BODY_LEN, MAX_FRAME_WIRE_LEN,
    MAX_UDP_OPEN_LEN, NXR_UDP_MAX_PAYLOAD, SESSION_TAG_LEN,
};
pub use open::{
    UdpAuthenticatedOpen, classify_open, decode_udp_open, encode_udp_open,
    open_authenticated_prefix, udp_open_len_from_header,
};
pub use wire::{
    NxrUdpFrame, NxrUdpSeq, decode_frame, drain_frames, encode_frame, frame_wire_len_from_prefix,
};

#[cfg(any(test, feature = "fuzzing"))]
pub use wire::fuzz_decode_frame;

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::protocol::nxr::{
        FLAG_TCP, FLAG_UDP, NxrKey, REQUEST_HEADER_LEN, decode_authenticated_request,
        encode_request,
    };
    use crate::protocol::vless::{Address, Destination};

    const NOW: u64 = 1_700_000_000;

    fn key() -> NxrKey {
        NxrKey::new([0x0b; 32])
    }

    #[test]
    fn udp_open_round_trip_and_rejects_tcp_decoder() {
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 53);
        let user = [0xAB; 16];
        let mut open = Vec::new();
        encode_udp_open(&destination, user, NOW, [0x44; 16], &key(), &mut open).unwrap();
        assert_eq!(
            udp_open_len_from_header(&open[..REQUEST_HEADER_LEN]).unwrap(),
            open.len()
        );
        let decoded = decode_udp_open(&open, &key(), NOW, 10).unwrap();
        assert_eq!(decoded.destination(), &destination);
        assert_eq!(decoded.user_id(), &user);
        assert_eq!(classify_open(&open[..REQUEST_HEADER_LEN]), Some(FLAG_UDP));

        // TCP decoder must reject UDP opens (wrong flags / length contract).
        assert!(decode_authenticated_request(&open, &key(), NOW, 10).is_err());
    }

    #[test]
    fn tcp_open_rejected_by_udp_decoder() {
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::new(9, 9, 9, 9)), 443);
        let mut open = Vec::new();
        encode_request(&destination, NOW, [0x55; 16], &key(), &mut open).unwrap();
        assert_eq!(classify_open(&open[..REQUEST_HEADER_LEN]), Some(FLAG_TCP));
        assert_eq!(
            decode_udp_open(&open, &key(), NOW, 10),
            Err(NxrUdpError::WrongMode)
        );
    }

    #[test]
    fn frame_round_trip_preserves_datagram_and_dest() {
        let mut open = Vec::new();
        let dest = Destination::new(Address::Domain("dns.example".to_owned()), 53);
        encode_udp_open(&dest, [1; 16], NOW, [2; 16], &key(), &mut open).unwrap();
        let prefix = open_authenticated_prefix(&open).unwrap();
        let session = NxrUdpSessionKey::derive(&key(), prefix);

        let mut wire = Vec::new();
        encode_frame(
            &session,
            DIR_LINE_TO_LANDING,
            FRAME_TYPE_DATAGRAM,
            0,
            Some(&dest),
            b"ping",
            &mut wire,
        )
        .unwrap();
        let (frame, consumed) = decode_frame(&wire, &session, DIR_LINE_TO_LANDING).unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(frame.payload, b"ping");
        assert_eq!(frame.destination.as_ref(), Some(&dest));
        assert_eq!(frame.seq, 0);

        // Wrong direction MAC fails closed.
        assert!(decode_frame(&wire, &session, DIR_LANDING_TO_LINE).is_err());
    }

    #[test]
    fn authenticated_frames_reject_every_unknown_flag_with_or_without_address() {
        let session = NxrUdpSessionKey::derive(&key(), b"flag-boundary");
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 53);
        for direction in [DIR_LINE_TO_LANDING, DIR_LANDING_TO_LINE] {
            for address in [None, Some(&destination)] {
                let mut wire = Vec::new();
                encode_frame(
                    &session,
                    direction,
                    FRAME_TYPE_DATAGRAM,
                    0,
                    address,
                    b"payload",
                    &mut wire,
                )
                .unwrap();
                let body_end = wire.len() - SESSION_TAG_LEN;
                for unknown in 0_u8..=127 {
                    wire[FRAME_LEN_SIZE + 1] =
                        (unknown << 1) | (u8::from(address.is_some()) * FRAME_FLAG_DESTINATION);
                    let tag = session.frame_tag(direction, &wire[FRAME_LEN_SIZE..body_end]);
                    wire[body_end..].copy_from_slice(&tag);
                    let decoded = decode_frame(&wire, &session, direction);
                    if unknown == 0 {
                        let (frame, consumed) = decoded.unwrap();
                        assert_eq!(consumed, wire.len());
                        assert_eq!(frame.destination.as_ref(), address);
                        assert_eq!(frame.payload, b"payload");
                    } else {
                        assert_eq!(decoded, Err(NxrUdpError::Flags));
                    }
                }
            }
        }
    }

    #[test]
    fn drain_handles_split_and_coalesced_frames() {
        let session = NxrUdpSessionKey::derive(&key(), b"prefix");
        let mut a = Vec::new();
        let mut b = Vec::new();
        encode_frame(
            &session,
            DIR_LANDING_TO_LINE,
            FRAME_TYPE_DATAGRAM,
            0,
            None,
            b"one",
            &mut a,
        )
        .unwrap();
        encode_frame(
            &session,
            DIR_LANDING_TO_LINE,
            FRAME_TYPE_DATAGRAM,
            1,
            None,
            b"two",
            &mut b,
        )
        .unwrap();

        let mut buffer = Vec::new();
        buffer.extend_from_slice(&a[..3]);
        assert!(
            drain_frames(&mut buffer, &session, DIR_LANDING_TO_LINE)
                .unwrap()
                .is_empty()
        );
        buffer.extend_from_slice(&a[3..]);
        buffer.extend_from_slice(&b);
        let frames = drain_frames(&mut buffer, &session, DIR_LANDING_TO_LINE).unwrap();
        assert!(buffer.is_empty());
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].payload, b"one");
        assert_eq!(frames[1].payload, b"two");
    }

    #[test]
    fn rejects_bad_mac_oversized_and_replay_seq() {
        let session = NxrUdpSessionKey::derive(&key(), b"prefix");
        let mut wire = Vec::new();
        encode_frame(
            &session,
            DIR_LINE_TO_LANDING,
            FRAME_TYPE_DATAGRAM,
            0,
            None,
            b"x",
            &mut wire,
        )
        .unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        assert_eq!(
            decode_frame(&wire, &session, DIR_LINE_TO_LANDING),
            Err(NxrUdpError::Authentication)
        );

        let big = vec![0_u8; NXR_UDP_MAX_PAYLOAD + 1];
        assert_eq!(
            encode_frame(
                &session,
                DIR_LINE_TO_LANDING,
                FRAME_TYPE_DATAGRAM,
                0,
                None,
                &big,
                &mut wire
            ),
            Err(NxrUdpError::Payload)
        );

        let mut inbound = NxrUdpSeq::new();
        inbound.accept_in(0).unwrap();
        assert_eq!(inbound.accept_in(0), Err(NxrUdpError::Sequence));
        assert_eq!(inbound.accept_in(2), Err(NxrUdpError::Sequence));
        inbound.accept_in(1).unwrap();
        let mut outbound = NxrUdpSeq::new();
        assert_eq!(outbound.next_out(), Ok(0));
        assert_eq!(outbound.next_out(), Ok(1));
    }

    #[test]
    fn session_keys_differ_across_opens_and_modes() {
        let mut open_a = Vec::new();
        let mut open_b = Vec::new();
        let dest = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 9);
        encode_udp_open(&dest, [1; 16], NOW, [0x01; 16], &key(), &mut open_a).unwrap();
        encode_udp_open(&dest, [1; 16], NOW, [0x02; 16], &key(), &mut open_b).unwrap();
        let ka = NxrUdpSessionKey::derive(&key(), open_authenticated_prefix(&open_a).unwrap());
        let kb = NxrUdpSessionKey::derive(&key(), open_authenticated_prefix(&open_b).unwrap());
        assert_ne!(ka, kb);
    }
}
