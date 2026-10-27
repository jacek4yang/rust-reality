//! NXR UDP association over the LINE→LANDING TCP hop (ADR 0060 Option A).
//!
//! After an authenticated UDP-mode open ([`FLAG_UDP`]), both
//! directions exchange length-prefixed datagram frames whose destination fields
//! are covered by a session MAC derived from the PSK and the open transcript.
//! Payload bytes are not encrypted (same hop threat model as TCP NXR).

mod error;
mod layout;

pub use error::NxrUdpError;
pub use layout::{
    DIR_LANDING_TO_LINE, DIR_LINE_TO_LANDING, FRAME_FLAG_DESTINATION, FRAME_LEN_SIZE,
    FRAME_TYPE_CLOSE, FRAME_TYPE_DATAGRAM, MAX_FRAME_BODY_LEN, MAX_FRAME_WIRE_LEN,
    MAX_UDP_OPEN_LEN, NXR_UDP_MAX_PAYLOAD, SESSION_TAG_LEN,
};

use std::{fmt, net::Ipv4Addr, net::Ipv6Addr};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::nxr::{FLAG_TCP, FLAG_UDP, FLAGS_OFFSET, NxrKey, REQUEST_HEADER_LEN, peek_open_flags};
use super::vless::{Address, Destination};

use layout::{
    ADDRESS_DOMAIN, ADDRESS_IPV4, ADDRESS_IPV6, ADDRESS_LENGTH_OFFSET, ADDRESS_OFFSET, MAGIC,
    MAX_DOMAIN_LEN, NONCE_OFFSET, OPEN_TAG_LEN, PORT_OFFSET, TIMESTAMP_OFFSET, UDP_OPEN_TRAILER,
    USER_ID_LEN,
};

type SessionHmac = Hmac<Sha256>;

/// Domain separation for UDP session-MAC key derivation.
const SESSION_MAC_LABEL: &[u8] = b"rust-reality/nxr-udp/v1/session-mac\0";

/// Domain separation for per-frame MACs (direction byte follows the label).
const FRAME_MAC_LABEL: &[u8] = b"rust-reality/nxr-udp/v1/frame-mac\0";

/// One authenticated NXR UDP association open.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpAuthenticatedOpen {
    timestamp: u64,
    nonce: [u8; 16],
    destination: Destination,
    user_id: [u8; 16],
}

impl UdpAuthenticatedOpen {
    #[must_use]
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; 16] {
        &self.nonce
    }

    #[must_use]
    pub const fn destination(&self) -> &Destination {
        &self.destination
    }

    #[must_use]
    pub const fn user_id(&self) -> &[u8; 16] {
        &self.user_id
    }

    #[must_use]
    pub fn into_parts(self) -> ([u8; 16], Destination, [u8; 16]) {
        (self.nonce, self.destination, self.user_id)
    }
}

/// Encodes one UDP-mode NXR open (`FLAG_UDP` + user id trailer + HMAC).
///
/// # Errors
///
/// Rejects port zero, empty/oversized domains, and allocator failure.
pub fn encode_udp_open(
    destination: &Destination,
    user_id: [u8; 16],
    timestamp: u64,
    nonce: [u8; 16],
    key: &NxrKey,
    output: &mut Vec<u8>,
) -> Result<(), NxrUdpError> {
    let (address_type, address_length) = address_shape(destination.address())?;
    let address_len = u16::try_from(address_length).map_err(|_| NxrUdpError::Address)?;
    if destination.port() == 0 {
        return Err(NxrUdpError::Port);
    }
    let total = REQUEST_HEADER_LEN
        .checked_add(address_length)
        .and_then(|n| n.checked_add(UDP_OPEN_TRAILER))
        .and_then(|n| n.checked_add(OPEN_TAG_LEN))
        .ok_or(NxrUdpError::Length)?;
    if total > MAX_UDP_OPEN_LEN {
        return Err(NxrUdpError::Length);
    }
    output.clear();
    output
        .try_reserve_exact(total)
        .map_err(|_| NxrUdpError::Allocation)?;
    output.extend_from_slice(&MAGIC);
    output.push(FLAG_UDP);
    output.push(address_type);
    output.extend_from_slice(&address_len.to_be_bytes());
    output.extend_from_slice(&destination.port().to_be_bytes());
    output.extend_from_slice(&timestamp.to_be_bytes());
    output.extend_from_slice(&nonce);
    match destination.address() {
        Address::Ipv4(address) => output.extend_from_slice(&address.octets()),
        Address::Domain(domain) => output.extend_from_slice(domain.as_bytes()),
        Address::Ipv6(address) => output.extend_from_slice(&address.octets()),
    }
    output.extend_from_slice(&user_id);
    let tag = open_tag(key, output);
    output.extend_from_slice(&tag);
    Ok(())
}

/// Exact UDP open size from a fixed header.
///
/// # Errors
///
/// Rejects non-UDP flags, bad address shapes, and oversized declarations.
pub fn udp_open_len_from_header(header: &[u8]) -> Result<usize, NxrUdpError> {
    if header.len() != REQUEST_HEADER_LEN {
        return Err(NxrUdpError::Length);
    }
    if header[..MAGIC.len()] != MAGIC {
        return Err(NxrUdpError::Version);
    }
    if header[FLAGS_OFFSET] != FLAG_UDP {
        return Err(NxrUdpError::WrongMode);
    }
    let address_len = usize::from(u16::from_be_bytes([
        header[ADDRESS_LENGTH_OFFSET],
        header[ADDRESS_LENGTH_OFFSET + 1],
    ]));
    let valid = match header[5] {
        ADDRESS_IPV4 => address_len == 4,
        ADDRESS_DOMAIN => (1..=MAX_DOMAIN_LEN).contains(&address_len),
        ADDRESS_IPV6 => address_len == 16,
        _ => false,
    };
    if !valid {
        return Err(NxrUdpError::Address);
    }
    REQUEST_HEADER_LEN
        .checked_add(address_len)
        .and_then(|n| n.checked_add(UDP_OPEN_TRAILER))
        .and_then(|n| n.checked_add(OPEN_TAG_LEN))
        .ok_or(NxrUdpError::Length)
}

/// Verifies and decodes one complete UDP-mode open.
///
/// # Errors
///
/// Rejects TCP-mode bytes, HMAC failure, clock skew, and malformed fields.
pub fn decode_udp_open(
    input: &[u8],
    key: &NxrKey,
    now: u64,
    maximum_time_difference: u64,
) -> Result<UdpAuthenticatedOpen, NxrUdpError> {
    let header = input.get(..REQUEST_HEADER_LEN).ok_or(NxrUdpError::Length)?;
    let expected = udp_open_len_from_header(header)?;
    if input.len() != expected {
        return Err(NxrUdpError::Length);
    }
    let authenticated_len = expected
        .checked_sub(OPEN_TAG_LEN)
        .ok_or(NxrUdpError::Length)?;
    let (authenticated, tag) = input.split_at(authenticated_len);
    verify_open_tag(key, authenticated, tag)?;

    let timestamp = read_u64(header, TIMESTAMP_OFFSET)?;
    if timestamp.abs_diff(now) > maximum_time_difference {
        return Err(NxrUdpError::TimeWindow);
    }
    let port = read_u16(header, PORT_OFFSET)?;
    if port == 0 {
        return Err(NxrUdpError::Port);
    }
    let nonce: [u8; 16] = header[NONCE_OFFSET..ADDRESS_OFFSET]
        .try_into()
        .map_err(|_| NxrUdpError::Length)?;
    let address_end = authenticated_len
        .checked_sub(USER_ID_LEN)
        .ok_or(NxrUdpError::Length)?;
    let address = parse_address(header[5], &input[ADDRESS_OFFSET..address_end])?;
    let user_id: [u8; 16] = input[address_end..authenticated_len]
        .try_into()
        .map_err(|_| NxrUdpError::Length)?;
    Ok(UdpAuthenticatedOpen {
        timestamp,
        nonce,
        destination: Destination::new(address, port),
        user_id,
    })
}

/// Authenticated open prefix (without tag) for [`NxrUdpSessionKey::derive`].
#[must_use]
pub fn open_authenticated_prefix(open_wire: &[u8]) -> Option<&[u8]> {
    (open_wire.len() > OPEN_TAG_LEN).then(|| &open_wire[..open_wire.len() - OPEN_TAG_LEN])
}

/// Classifies a header as TCP or UDP open without authenticating.
#[must_use]
pub fn classify_open(header: &[u8]) -> Option<u8> {
    peek_open_flags(header).filter(|&flags| flags == FLAG_TCP || flags == FLAG_UDP)
}

/// Session MAC key for one NXR UDP association.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct NxrUdpSessionKey(Zeroizing<[u8; SESSION_TAG_LEN]>);

impl fmt::Debug for NxrUdpSessionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NxrUdpSessionKey([REDACTED])")
    }
}

impl PartialEq for NxrUdpSessionKey {
    fn eq(&self, other: &Self) -> bool {
        // Equality only for tests; not used on hot paths.
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for NxrUdpSessionKey {}

impl NxrUdpSessionKey {
    /// Derives the session MAC key from the PSK and authenticated open prefix.
    #[must_use]
    pub fn derive(key: &NxrKey, open_authenticated_prefix: &[u8]) -> Self {
        Self(Zeroizing::new(
            key.derive(SESSION_MAC_LABEL, open_authenticated_prefix),
        ))
    }

    fn mac(&self) -> SessionHmac {
        SessionHmac::new_from_slice(self.0.as_slice()).expect("HMAC-SHA256 accepts 32-byte key")
    }

    /// Computes the frame MAC for `direction` over `body`.
    #[must_use]
    pub fn frame_tag(&self, direction: u8, body: &[u8]) -> [u8; SESSION_TAG_LEN] {
        let mut mac = self.mac();
        mac.update(FRAME_MAC_LABEL);
        mac.update(&[direction]);
        mac.update(body);
        mac.finalize().into_bytes().into()
    }

    /// Verifies a frame MAC in constant time.
    ///
    /// # Errors
    ///
    /// [`NxrUdpError::Authentication`] on mismatch.
    pub fn verify_frame(&self, direction: u8, body: &[u8], tag: &[u8]) -> Result<(), NxrUdpError> {
        let mut mac = self.mac();
        mac.update(FRAME_MAC_LABEL);
        mac.update(&[direction]);
        mac.update(body);
        mac.verify_slice(tag)
            .map_err(|_| NxrUdpError::Authentication)
    }
}

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
    let seq = u32::from_be_bytes(body[2..6].try_into().map_err(|_| NxrUdpError::Length)?);
    let mut offset = 6;
    let destination = if flags & FRAME_FLAG_DESTINATION != 0 {
        let (dest, consumed) = decode_destination(&body[offset..])?;
        offset = offset.checked_add(consumed).ok_or(NxrUdpError::Length)?;
        Some(dest)
    } else if flags != 0 {
        return Err(NxrUdpError::Flags);
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

fn address_shape(address: &Address) -> Result<(u8, usize), NxrUdpError> {
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

fn parse_address(address_type: u8, address: &[u8]) -> Result<Address, NxrUdpError> {
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

fn open_tag(key: &NxrKey, authenticated: &[u8]) -> [u8; OPEN_TAG_LEN] {
    // Same construction as TCP NXR open tags: HMAC(psk, authenticated_bytes).
    // Mode separation is the FLAG_UDP byte inside `authenticated`.
    key.tag(authenticated)
}

fn verify_open_tag(key: &NxrKey, authenticated: &[u8], tag: &[u8]) -> Result<(), NxrUdpError> {
    let expected = open_tag(key, authenticated);
    use subtle::ConstantTimeEq;
    if bool::from(expected.as_slice().ct_eq(tag)) {
        Ok(())
    } else {
        Err(NxrUdpError::Authentication)
    }
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, NxrUdpError> {
    read_u16_at(input, offset)
}

fn read_u16_at(input: &[u8], offset: usize) -> Result<u16, NxrUdpError> {
    let bytes = input
        .get(offset..offset + 2)
        .ok_or(NxrUdpError::Length)?
        .try_into()
        .map_err(|_| NxrUdpError::Length)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, NxrUdpError> {
    let bytes = input
        .get(offset..offset + 8)
        .ok_or(NxrUdpError::Length)?
        .try_into()
        .map_err(|_| NxrUdpError::Length)?;
    Ok(u64::from_be_bytes(bytes))
}

/// Fuzz entry: decode arbitrary bytes as a UDP frame under a fixed session.
#[cfg(any(test, feature = "fuzzing"))]
pub fn fuzz_decode_frame(input: &[u8]) -> Result<(), NxrUdpError> {
    let key = NxrKey::new([0x11; 32]);
    let session = NxrUdpSessionKey::derive(&key, b"fuzz-open-prefix");
    let _ = drain_frames(&mut input.to_vec(), &session, DIR_LINE_TO_LANDING)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::nxr::{FLAG_TCP, decode_authenticated_request, encode_request};

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
        assert_eq!(outbound.next_out(), 0);
        assert_eq!(outbound.next_out(), 1);
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
