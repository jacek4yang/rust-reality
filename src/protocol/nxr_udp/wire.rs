//! NXR UDP frame encode/decode (ADR 0060 Option A).
//!
//! Layout constants live in [`super::layout`]; session MAC helpers in
//! [`super::keys`]; authenticated open codecs in [`super::open`]. This module
//! owns frame structs and the encode / length / decode / drain surface;
//! address and integer field codecs live in [`super::fields`] and sequence
//! state in [`super::seq`].

#[cfg(any(test, feature = "fuzzing"))]
use super::super::nxr::NxrKey;
use super::super::vless::{Address, Destination};
use super::error::NxrUdpError;
use super::fields::{address_shape, decode_destination, read_u16_at};
use super::keys::NxrUdpSessionKey;
use super::layout::{
    DIR_LANDING_TO_LINE, DIR_LINE_TO_LANDING, FRAME_FLAG_DESTINATION, FRAME_LEN_SIZE,
    FRAME_TYPE_CLOSE, FRAME_TYPE_DATAGRAM, MAX_FRAME_BODY_LEN, NXR_UDP_MAX_PAYLOAD,
    SESSION_TAG_LEN,
};

/// One decoded datagram/close frame (MAC already verified).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NxrUdpFrame {
    pub frame_type: u8,
    pub seq: u32,
    pub destination: Option<Destination>,
    pub payload: Vec<u8>,
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
mod encoder_storage_tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::protocol::nxr_udp::{MAX_FRAME_WIRE_LEN, layout::MAX_DOMAIN_LEN};

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
