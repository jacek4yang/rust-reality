//! NXR UDP association open encode/decode.
//!
//! Owns [`UdpAuthenticatedOpen`] and the UDP-mode open wire helpers. Frame
//! codecs stay in [`super::wire`]; layout/HMAC helpers remain shared.

use super::error::NxrUdpError;
use super::keys::{open_tag, verify_open_tag};
use super::layout::{
    ADDRESS_DOMAIN, ADDRESS_IPV4, ADDRESS_IPV6, ADDRESS_LENGTH_OFFSET, ADDRESS_OFFSET, MAGIC,
    MAX_DOMAIN_LEN, MAX_UDP_OPEN_LEN, NONCE_OFFSET, OPEN_TAG_LEN, PORT_OFFSET, TIMESTAMP_OFFSET,
    UDP_OPEN_TRAILER, USER_ID_LEN,
};
use super::wire::{address_shape, parse_address, read_u16, read_u64};
use crate::protocol::nxr::{
    FLAG_TCP, FLAG_UDP, FLAGS_OFFSET, NxrKey, REQUEST_HEADER_LEN, peek_open_flags,
};
use crate::protocol::vless::{Address, Destination};

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

/// Authenticated open prefix (without tag) for [`super::NxrUdpSessionKey::derive`].
#[must_use]
pub fn open_authenticated_prefix(open_wire: &[u8]) -> Option<&[u8]> {
    (open_wire.len() > OPEN_TAG_LEN).then(|| &open_wire[..open_wire.len() - OPEN_TAG_LEN])
}

/// Classifies a header as TCP or UDP open without authenticating.
#[must_use]
pub fn classify_open(header: &[u8]) -> Option<u8> {
    peek_open_flags(header).filter(|&flags| flags == FLAG_TCP || flags == FLAG_UDP)
}
