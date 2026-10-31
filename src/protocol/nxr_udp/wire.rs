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
    next: u32,
}

impl NxrUdpSeq {
    #[must_use]
    pub const fn new() -> Self {
        Self { next: 0 }
    }

    #[must_use]
    pub fn next_out(&mut self) -> u32 {
        let seq = self.next;
        self.next = self.next.wrapping_add(1);
        seq
    }

    /// # Errors
    ///
    /// [`NxrUdpError::Sequence`] when `seq` is not expected.
    pub fn accept_in(&mut self, seq: u32) -> Result<(), NxrUdpError> {
        if seq != self.next {
            return Err(NxrUdpError::Sequence);
        }
        self.next = self.next.wrapping_add(1);
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

    let dest_bytes = match destination {
        Some(dest) => Some(encode_destination(dest)?),
        None => None,
    };
    let flags = u8::from(dest_bytes.is_some()) * FRAME_FLAG_DESTINATION;
    let dest_len = dest_bytes.as_ref().map_or(0, Vec::len);
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

    let mut body = Vec::new();
    body.try_reserve_exact(body_len)
        .map_err(|_| NxrUdpError::Allocation)?;
    body.push(frame_type);
    body.push(flags);
    body.extend_from_slice(&seq.to_be_bytes());
    if let Some(bytes) = &dest_bytes {
        body.extend_from_slice(bytes);
    }
    let payload_len = u16::try_from(payload.len()).map_err(|_| NxrUdpError::Payload)?;
    body.extend_from_slice(&payload_len.to_be_bytes());
    body.extend_from_slice(payload);

    let tag = session.frame_tag(direction, &body);
    let wire_len = FRAME_LEN_SIZE
        .checked_add(body.len())
        .and_then(|n| n.checked_add(SESSION_TAG_LEN))
        .ok_or(NxrUdpError::Length)?;
    output.clear();
    output
        .try_reserve_exact(wire_len)
        .map_err(|_| NxrUdpError::Allocation)?;
    output.extend_from_slice(
        &u32::try_from(body.len())
            .map_err(|_| NxrUdpError::Length)?
            .to_be_bytes(),
    );
    output.extend_from_slice(&body);
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

fn encode_destination(destination: &Destination) -> Result<Vec<u8>, NxrUdpError> {
    let (address_type, address_length) = address_shape(destination.address())?;
    if destination.port() == 0 {
        return Err(NxrUdpError::Port);
    }
    let mut out = Vec::with_capacity(5 + address_length);
    out.push(address_type);
    out.extend_from_slice(
        &u16::try_from(address_length)
            .map_err(|_| NxrUdpError::Address)?
            .to_be_bytes(),
    );
    out.extend_from_slice(&destination.port().to_be_bytes());
    match destination.address() {
        Address::Ipv4(address) => out.extend_from_slice(&address.octets()),
        Address::Domain(domain) => out.extend_from_slice(domain.as_bytes()),
        Address::Ipv6(address) => out.extend_from_slice(&address.octets()),
    }
    Ok(out)
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
