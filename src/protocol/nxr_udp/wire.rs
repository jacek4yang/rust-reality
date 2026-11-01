//! NXR UDP frame encode/decode (ADR 0060 Option A).
//!
//! Layout constants live in [`super::layout`]; session MAC helpers in
//! [`super::keys`]; authenticated open codecs in [`super::open`]. This module
//! owns frame structs and the encode / length / decode / drain surface.

use std::net::{Ipv4Addr, Ipv6Addr};

#[cfg(any(test, feature = "fuzzing"))]
use super::super::nxr::NxrKey;
use super::super::vless::{Address, Destination};
use super::error::NxrUdpError;
use super::keys::NxrUdpSessionKey;
use super::layout::{
    ADDRESS_DOMAIN, ADDRESS_IPV4, ADDRESS_IPV6, DIR_LANDING_TO_LINE, DIR_LINE_TO_LANDING,
    FRAME_FLAG_DESTINATION, FRAME_LEN_SIZE, FRAME_TYPE_CLOSE, FRAME_TYPE_DATAGRAM, MAX_DOMAIN_LEN,
    MAX_FRAME_BODY_LEN, NXR_UDP_MAX_PAYLOAD, SESSION_TAG_LEN,
};

/// One decoded datagram/close frame (MAC already verified).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NxrUdpFrame {
    pub frame_type: u8,
    pub seq: u32,
    pub destination: Option<Destination>,
    pub payload: Vec<u8>,
}

/// Exact next-sequence tracker (rejects replay and reordering).
#[derive(Clone, Debug, Default)]
pub struct NxrUdpSeq {
    // One extra state represents exhaustion without reusing a wire sequence.
    next: u64,
}

impl NxrUdpSeq {
    #[must_use]
    pub const fn new() -> Self {
        Self { next: 0 }
    }

    /// Allocates a wire sequence once; exhaustion requires a new association.
    ///
    /// # Errors
    ///
    /// [`NxrUdpError::Sequence`] after every 32-bit sequence has been used.
    pub fn next_out(&mut self) -> Result<u32, NxrUdpError> {
        let seq = u32::try_from(self.next).map_err(|_| NxrUdpError::Sequence)?;
        self.next += 1;
        Ok(seq)
    }

    /// # Errors
    ///
    /// [`NxrUdpError::Sequence`] when `seq` is not expected or the
    /// association has exhausted its wire sequence space.
    pub fn accept_in(&mut self, seq: u32) -> Result<(), NxrUdpError> {
        if u64::from(seq) != self.next {
            return Err(NxrUdpError::Sequence);
        }
        self.next += 1;
        Ok(())
    }
}

/// Encodes one length-prefixed, MAC'd frame.
///
/// # Errors
///
/// Oversized payload/destination, bad type/direction, or allocation failure.
pub fn encode_frame(
    session: &NxrUdpSessionKey,
    direction: u8,
    frame_type: u8,
    seq: u32,
    destination: Option<&Destination>,
    payload: &[u8],
    output: &mut Vec<u8>,
) -> Result<(), NxrUdpError> {
    if payload.len() > NXR_UDP_MAX_PAYLOAD {
        return Err(NxrUdpError::Payload);
    }
    if !matches!(frame_type, FRAME_TYPE_DATAGRAM | FRAME_TYPE_CLOSE) {
        return Err(NxrUdpError::FrameType);
    }
    if direction != DIR_LINE_TO_LANDING && direction != DIR_LANDING_TO_LINE {
        return Err(NxrUdpError::Direction);
    }

    // Validate every fallible field before modifying the caller's buffer.
    let destination_shape = destination
        .map(|dest| {
            let (kind, len) = address_shape(dest.address())?;
            if dest.port() == 0 {
                return Err(NxrUdpError::Port);
            }
            let len = u16::try_from(len).map_err(|_| NxrUdpError::Address)?;
            Ok((kind, len))
        })
        .transpose()?;
    let flags = u8::from(destination.is_some()) * FRAME_FLAG_DESTINATION;
    let dest_len = destination_shape.map_or(0, |(_, len)| 5 + usize::from(len));
    let body_len = 1_usize
        .checked_add(1)
        .and_then(|n| n.checked_add(4))
        .and_then(|n| n.checked_add(dest_len))
        .and_then(|n| n.checked_add(2))
        .and_then(|n| n.checked_add(payload.len()))
        .ok_or(NxrUdpError::Length)?;
    if body_len > MAX_FRAME_BODY_LEN {
        return Err(NxrUdpError::Length);
    }

    let payload_len = u16::try_from(payload.len()).map_err(|_| NxrUdpError::Payload)?;
    let wire_len = FRAME_LEN_SIZE
        .checked_add(body_len)
        .and_then(|n| n.checked_add(SESSION_TAG_LEN))
        .ok_or(NxrUdpError::Length)?;
    let body_len = u32::try_from(body_len).map_err(|_| NxrUdpError::Length)?;
    output.clear();
    output
        .try_reserve_exact(wire_len)
        .map_err(|_| NxrUdpError::Allocation)?;
    output.extend_from_slice(&body_len.to_be_bytes());
    output.push(frame_type);
    output.push(flags);
    output.extend_from_slice(&seq.to_be_bytes());
    if let (Some(dest), Some((kind, len))) = (destination, destination_shape) {
        output.push(kind);
        output.extend_from_slice(&len.to_be_bytes());
        output.extend_from_slice(&dest.port().to_be_bytes());
        match dest.address() {
            Address::Ipv4(address) => output.extend_from_slice(&address.octets()),
            Address::Domain(domain) => output.extend_from_slice(domain.as_bytes()),
            Address::Ipv6(address) => output.extend_from_slice(&address.octets()),
        }
    }
    output.extend_from_slice(&payload_len.to_be_bytes());
    output.extend_from_slice(payload);
    let tag = session.frame_tag(direction, &output[FRAME_LEN_SIZE..]);
    output.extend_from_slice(&tag);
    Ok(())
}

/// Total on-wire length from the 4-byte length prefix.
///
/// # Errors
///
/// Truncated prefix or oversized/zero body length.
pub fn frame_wire_len_from_prefix(prefix: &[u8]) -> Result<usize, NxrUdpError> {
    if prefix.len() < FRAME_LEN_SIZE {
        return Err(NxrUdpError::Truncated);
    }
    let body_len = usize::try_from(u32::from_be_bytes(
        prefix[..FRAME_LEN_SIZE]
            .try_into()
            .map_err(|_| NxrUdpError::Length)?,
    ))
    .map_err(|_| NxrUdpError::Length)?;
    if body_len == 0 || body_len > MAX_FRAME_BODY_LEN {
        return Err(NxrUdpError::Length);
    }
    FRAME_LEN_SIZE
        .checked_add(body_len)
        .and_then(|n| n.checked_add(SESSION_TAG_LEN))
        .ok_or(NxrUdpError::Length)
}

/// Verifies and decodes one complete frame; returns frame and bytes consumed.
///
/// # Errors
///
/// Truncation, bad MAC, or malformed body.
pub fn decode_frame(
    input: &[u8],
    session: &NxrUdpSessionKey,
    direction: u8,
) -> Result<(NxrUdpFrame, usize), NxrUdpError> {
    let wire_len = frame_wire_len_from_prefix(input)?;
    if input.len() < wire_len {
        return Err(NxrUdpError::Truncated);
    }
    let body_len = wire_len
        .checked_sub(FRAME_LEN_SIZE + SESSION_TAG_LEN)
        .ok_or(NxrUdpError::Length)?;
    let body = &input[FRAME_LEN_SIZE..FRAME_LEN_SIZE + body_len];
    let tag = &input[FRAME_LEN_SIZE + body_len..wire_len];
    session.verify_frame(direction, body, tag)?;
    Ok((parse_frame_body(body)?, wire_len))
}

/// Drains complete frames from a stream buffer (split/coalesce safe).
///
/// Incomplete trailing bytes remain. On a hard decode error after a complete
/// length prefix, returns the error (caller must tear down).
///
/// # Errors
///
/// Propagates decode failures for a fully buffered frame.
pub fn drain_frames(
    buffer: &mut Vec<u8>,
    session: &NxrUdpSessionKey,
    direction: u8,
) -> Result<Vec<NxrUdpFrame>, NxrUdpError> {
    let mut frames = Vec::new();
    loop {
        if buffer.len() < FRAME_LEN_SIZE {
            break;
        }
        let wire_len = match frame_wire_len_from_prefix(buffer) {
            Ok(len) => len,
            Err(NxrUdpError::Truncated) => break,
            Err(error) => return Err(error),
        };
        if buffer.len() < wire_len {
            break;
        }
        let (frame, consumed) = decode_frame(&buffer[..wire_len], session, direction)?;
        buffer.drain(..consumed);
        frames.push(frame);
    }
    Ok(frames)
}

fn parse_frame_body(body: &[u8]) -> Result<NxrUdpFrame, NxrUdpError> {
    if body.len() < 8 {
        return Err(NxrUdpError::Length);
    }
    let frame_type = body[0];
    if !matches!(frame_type, FRAME_TYPE_DATAGRAM | FRAME_TYPE_CLOSE) {
        return Err(NxrUdpError::FrameType);
    }
    let flags = body[1];
    if flags & !FRAME_FLAG_DESTINATION != 0 {
        return Err(NxrUdpError::Flags);
    }
    let seq = u32::from_be_bytes(body[2..6].try_into().map_err(|_| NxrUdpError::Length)?);
    let mut offset = 6;
    let destination = if flags & FRAME_FLAG_DESTINATION != 0 {
        let (dest, consumed) = decode_destination(&body[offset..])?;
        offset = offset.checked_add(consumed).ok_or(NxrUdpError::Length)?;
        Some(dest)
    } else {
        None
    };
    let payload_len = usize::from(read_u16_at(body, offset)?);
    offset = offset.checked_add(2).ok_or(NxrUdpError::Length)?;
    if payload_len > NXR_UDP_MAX_PAYLOAD {
        return Err(NxrUdpError::Payload);
    }
    let end = offset.checked_add(payload_len).ok_or(NxrUdpError::Length)?;
    if end != body.len() {
        return Err(NxrUdpError::Length);
    }
    Ok(NxrUdpFrame {
        frame_type,
        seq,
        destination,
        payload: body[offset..end].to_vec(),
    })
}

fn decode_destination(input: &[u8]) -> Result<(Destination, usize), NxrUdpError> {
    if input.len() < 5 {
        return Err(NxrUdpError::Truncated);
    }
    let address_type = input[0];
    let address_len = usize::from(u16::from_be_bytes([input[1], input[2]]));
    let port = u16::from_be_bytes([input[3], input[4]]);
    if port == 0 {
        return Err(NxrUdpError::Port);
    }
    let total = 5usize.checked_add(address_len).ok_or(NxrUdpError::Length)?;
    if input.len() < total {
        return Err(NxrUdpError::Truncated);
    }
    let address = parse_address(address_type, &input[5..total])?;
    Ok((Destination::new(address, port), total))
}

pub(super) fn address_shape(address: &Address) -> Result<(u8, usize), NxrUdpError> {
    match address {
        Address::Ipv4(_) => Ok((ADDRESS_IPV4, 4)),
        Address::Domain(domain) => {
            if domain.is_empty() || domain.len() > MAX_DOMAIN_LEN {
                return Err(NxrUdpError::Address);
            }
            Ok((ADDRESS_DOMAIN, domain.len()))
        }
        Address::Ipv6(_) => Ok((ADDRESS_IPV6, 16)),
    }
}

pub(super) fn parse_address(address_type: u8, address: &[u8]) -> Result<Address, NxrUdpError> {
    match address_type {
        ADDRESS_IPV4 => {
            let bytes: [u8; 4] = address.try_into().map_err(|_| NxrUdpError::Address)?;
            Ok(Address::Ipv4(Ipv4Addr::from(bytes)))
        }
        ADDRESS_DOMAIN => std::str::from_utf8(address)
            .map(str::to_owned)
            .map(Address::Domain)
            .map_err(|_| NxrUdpError::Address),
        ADDRESS_IPV6 => {
            let bytes: [u8; 16] = address.try_into().map_err(|_| NxrUdpError::Address)?;
            Ok(Address::Ipv6(Ipv6Addr::from(bytes)))
        }
        _ => Err(NxrUdpError::Address),
    }
}

pub(super) fn read_u16(input: &[u8], offset: usize) -> Result<u16, NxrUdpError> {
    read_u16_at(input, offset)
}

pub(super) fn read_u16_at(input: &[u8], offset: usize) -> Result<u16, NxrUdpError> {
    let bytes = input
        .get(offset..offset + 2)
        .ok_or(NxrUdpError::Length)?
        .try_into()
        .map_err(|_| NxrUdpError::Length)?;
    Ok(u16::from_be_bytes(bytes))
}

pub(super) fn read_u64(input: &[u8], offset: usize) -> Result<u64, NxrUdpError> {
    let bytes = input
        .get(offset..offset + 8)
        .ok_or(NxrUdpError::Length)?
        .try_into()
        .map_err(|_| NxrUdpError::Length)?;
    Ok(u64::from_be_bytes(bytes))
}

/// Fuzz both arbitrary authenticated bodies and raw frames under a fixed session.
#[cfg(any(test, feature = "fuzzing"))]
pub fn fuzz_decode_frame(input: &[u8]) -> Result<(), NxrUdpError> {
    // Arbitrary raw frames almost always fail their MAC. Exercise the same body
    // parser independently in this test-only entry, without changing production
    // decode ordering or accepting unauthenticated network input.
    let _ = parse_frame_body(input);
    let key = NxrKey::new([0x11; 32]);
    let session = NxrUdpSessionKey::derive(&key, b"fuzz-open-prefix");
    let _ = drain_frames(&mut input.to_vec(), &session, DIR_LINE_TO_LANDING)?;
    Ok(())
}

#[cfg(test)]
mod sequence_exhaustion_tests {
    use super::{
        DIR_LINE_TO_LANDING, FRAME_TYPE_DATAGRAM, NxrKey, NxrUdpError, NxrUdpSeq, NxrUdpSessionKey,
        decode_frame, encode_frame,
    };

    #[test]
    fn exhausted_inbound_sequence_rejects_replay() {
        let mut sequence = NxrUdpSeq {
            next: u64::from(u32::MAX),
        };
        // An old frame remains MAC-valid under this association's key. The
        // sequence guard must still reject it after the final wire value.
        let key = NxrKey::new([0x37; 32]);
        let session = NxrUdpSessionKey::derive(&key, b"sequence-exhaustion-test");
        let mut replay = Vec::new();
        encode_frame(
            &session,
            DIR_LINE_TO_LANDING,
            FRAME_TYPE_DATAGRAM,
            0,
            None,
            b"old-datagram",
            &mut replay,
        )
        .unwrap();
        sequence.accept_in(u32::MAX).unwrap();
        let (frame, consumed) = decode_frame(&replay, &session, DIR_LINE_TO_LANDING).unwrap();
        assert_eq!(consumed, replay.len());
        assert_eq!(sequence.accept_in(frame.seq), Err(NxrUdpError::Sequence));
        assert_eq!(sequence.accept_in(u32::MAX), Err(NxrUdpError::Sequence));
    }

    #[test]
    fn exhausted_outbound_sequence_never_reuses_a_wire_value() {
        let mut sequence = NxrUdpSeq {
            next: u64::from(u32::MAX) - 1,
        };
        assert_eq!(sequence.next_out(), Ok(u32::MAX - 1));
        assert_eq!(sequence.next_out(), Ok(u32::MAX));
        for _ in 0..3 {
            assert_eq!(sequence.next_out(), Err(NxrUdpError::Sequence));
        }
    }
}

#[cfg(test)]
mod encoder_storage_tests {
    use super::*;
    use crate::protocol::nxr_udp::MAX_FRAME_WIRE_LEN;

    #[test]
    fn frame_writer_preserves_frozen_wire_and_reuses_storage() {
        // Captured from the qualified pre-optimization writer at 54c204af.
        let expected = [
            0x00, 0x00, 0x00, 0x15, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x01,
            0xbb, 0xc0, 0x00, 0x02, 0x01, 0x00, 0x04, 0x5a, 0x5a, 0x5a, 0x5a, 0xa4, 0x8c, 0xf2,
            0x9c, 0x1f, 0x30, 0xc5, 0xbf, 0xdf, 0x03, 0x05, 0xe2, 0x7c, 0xee, 0xe5, 0xa0, 0xb4,
            0x9d, 0x31, 0x7c, 0x12, 0x72, 0x12, 0xa1, 0xc6, 0x93, 0xd5, 0x69, 0x0d, 0xfd, 0x0f,
            0xcf,
        ];
        let session = NxrUdpSessionKey::derive(
            &NxrKey::new([0x33; 32]),
            b"local-synthetic-allocation-probe",
        );
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)), 443);
        let mut output = Vec::with_capacity(MAX_FRAME_WIRE_LEN);
        let pointer = output.as_ptr();
        for length in [NXR_UDP_MAX_PAYLOAD, 4, 0, 4] {
            let payload = vec![0x5a; length];
            encode_frame(
                &session,
                DIR_LINE_TO_LANDING,
                FRAME_TYPE_DATAGRAM,
                0,
                Some(&destination),
                &payload,
                &mut output,
            )
            .unwrap();
            assert_eq!(output.as_ptr(), pointer);
            let (decoded, consumed) = decode_frame(&output, &session, DIR_LINE_TO_LANDING).unwrap();
            assert_eq!(consumed, output.len());
            assert_eq!(decoded.payload, payload);
            if length == 4 {
                assert_eq!(output, expected);
            }
        }
    }

    #[test]
    fn invalid_destination_preserves_previous_output() {
        let session = NxrUdpSessionKey::derive(&NxrKey::new([0x33; 32]), b"invalid-input");
        for destination in [
            Destination::new(Address::Domain(String::new()), 443),
            Destination::new(Address::Domain("a".repeat(MAX_DOMAIN_LEN + 1)), 443),
            Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 0),
        ] {
            let mut output = vec![0xa5; 100];
            assert!(
                encode_frame(
                    &session,
                    DIR_LINE_TO_LANDING,
                    FRAME_TYPE_DATAGRAM,
                    0,
                    Some(&destination),
                    b"payload",
                    &mut output
                )
                .is_err()
            );
            assert_eq!(output, [0xa5; 100]);
        }
    }
}
