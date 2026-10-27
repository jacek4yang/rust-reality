//! Authenticated NXR open-request encode/decode (TCP FLAG_TCP path).
//!
//! Layout constants live in [`super::layout`]; HMAC helpers in [`super::keys`].
//! This module owns the request struct and the encode / length / decode surface
//! so `mod.rs` stays a thin re-export facade matching `protocol::handoff`.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::super::vless::{Address, Destination};
use super::error::NxrProtocolError;
use super::keys::{NxrKey, authenticate, verify};
use super::layout::{
    ADDRESS_DOMAIN, ADDRESS_IPV4, ADDRESS_IPV6, ADDRESS_LENGTH_OFFSET, ADDRESS_OFFSET, FLAG_TCP,
    MAGIC, MAX_DOMAIN_LEN, MAX_REQUEST_LEN, NONCE_OFFSET, PORT_OFFSET, REQUEST_HEADER_LEN, TAG_LEN,
    TIMESTAMP_OFFSET,
};

/// One authenticated NXR destination request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedRequest {
    timestamp: u64,
    nonce: [u8; 16],
    destination: Destination,
}

impl AuthenticatedRequest {
    /// Returns the sender's Unix timestamp in seconds.
    #[must_use]
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Returns the one-time random replay token.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 16] {
        &self.nonce
    }

    /// Returns the destination authenticated by the HMAC.
    #[must_use]
    pub const fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Separates the replay token and destination without retaining request bytes.
    #[must_use]
    pub fn into_parts(self) -> ([u8; 16], Destination) {
        (self.nonce, self.destination)
    }
}

/// Encodes one complete NXR authentication request.
///
/// The HMAC covers the version, TCP flags (`0`), address type and length, port,
/// timestamp, nonce, and destination address. No framing follows this request:
/// the next byte on the connection is raw user TCP payload.
///
/// UDP association opens use [`crate::protocol::nxr_udp`] instead (`FLAG_UDP`).
///
/// # Errors
///
/// Rejects port zero, empty or oversized domains, and allocator failure.
pub fn encode_request(
    destination: &Destination,
    timestamp: u64,
    nonce: [u8; 16],
    key: &NxrKey,
    output: &mut Vec<u8>,
) -> Result<(), NxrProtocolError> {
    let (address_type, address_length) = address_shape(destination.address())?;
    let address_len = u16::try_from(address_length).map_err(|_| NxrProtocolError::Address)?;
    if destination.port() == 0 {
        return Err(NxrProtocolError::Port);
    }
    let total = REQUEST_HEADER_LEN
        .checked_add(address_length)
        .and_then(|length| length.checked_add(TAG_LEN))
        .ok_or(NxrProtocolError::Length)?;
    if total > MAX_REQUEST_LEN {
        return Err(NxrProtocolError::Length);
    }
    output.clear();
    output
        .try_reserve_exact(total)
        .map_err(|_| NxrProtocolError::Allocation)?;
    output.extend_from_slice(&MAGIC);
    output.push(FLAG_TCP);
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
    let tag = authenticate(key, output);
    output.extend_from_slice(&tag);
    Ok(())
}

/// Returns the exact total request size declared by one fixed header.
///
/// This performs only bounded structural checks needed to read exactly one
/// request. It does not parse a domain or authenticate any field.
///
/// # Errors
///
/// Rejects truncated, unknown-version, unsupported-flag, invalid address-shape,
/// and oversized headers.
pub fn request_len_from_header(header: &[u8]) -> Result<usize, NxrProtocolError> {
    if header.len() != REQUEST_HEADER_LEN {
        return Err(NxrProtocolError::Length);
    }
    if header[..MAGIC.len()] != MAGIC {
        return Err(NxrProtocolError::Version);
    }
    if header[4] != FLAG_TCP {
        return Err(NxrProtocolError::Flags);
    }
    let address_len = usize::from(u16::from_be_bytes([
        header[ADDRESS_LENGTH_OFFSET],
        header[ADDRESS_LENGTH_OFFSET + 1],
    ]));
    let valid_address = match header[5] {
        ADDRESS_IPV4 => address_len == 4,
        ADDRESS_DOMAIN => (1..=MAX_DOMAIN_LEN).contains(&address_len),
        ADDRESS_IPV6 => address_len == 16,
        _ => false,
    };
    if !valid_address {
        return Err(NxrProtocolError::Address);
    }
    REQUEST_HEADER_LEN
        .checked_add(address_len)
        .and_then(|length| length.checked_add(TAG_LEN))
        .filter(|length| *length <= MAX_REQUEST_LEN)
        .ok_or(NxrProtocolError::Length)
}

/// Verifies and decodes exactly one complete authentication request.
///
/// Destination bytes are converted into an address only after constant-time HMAC
/// verification and timestamp validation. Callers must reserve the returned nonce
/// in a bounded replay cache before DNS resolution or destination connection.
///
/// # Errors
///
/// Rejects malformed length or address data, HMAC failure, clock-window failure,
/// port zero, and invalid UTF-8 domains.
pub fn decode_authenticated_request(
    input: &[u8],
    key: &NxrKey,
    now: u64,
    maximum_time_difference: u64,
) -> Result<AuthenticatedRequest, NxrProtocolError> {
    let header = input
        .get(..REQUEST_HEADER_LEN)
        .ok_or(NxrProtocolError::Length)?;
    let expected = request_len_from_header(header)?;
    if input.len() != expected {
        return Err(NxrProtocolError::Length);
    }
    let authenticated_len = expected
        .checked_sub(TAG_LEN)
        .ok_or(NxrProtocolError::Length)?;
    let (authenticated, tag) = input.split_at(authenticated_len);
    verify(key, authenticated, tag)?;

    let timestamp = read_u64(header, TIMESTAMP_OFFSET)?;
    if timestamp.abs_diff(now) > maximum_time_difference {
        return Err(NxrProtocolError::TimeWindow);
    }
    let port = read_u16(header, PORT_OFFSET)?;
    if port == 0 {
        return Err(NxrProtocolError::Port);
    }
    let nonce: [u8; 16] = header[NONCE_OFFSET..ADDRESS_OFFSET]
        .try_into()
        .map_err(|_| NxrProtocolError::Length)?;
    let address = parse_address(header[5], &input[ADDRESS_OFFSET..authenticated_len])?;
    Ok(AuthenticatedRequest {
        timestamp,
        nonce,
        destination: Destination::new(address, port),
    })
}

fn address_shape(address: &Address) -> Result<(u8, usize), NxrProtocolError> {
    match address {
        Address::Ipv4(_) => Ok((ADDRESS_IPV4, 4)),
        Address::Domain(domain) => {
            if domain.is_empty() || domain.len() > MAX_DOMAIN_LEN {
                return Err(NxrProtocolError::Address);
            }
            Ok((ADDRESS_DOMAIN, domain.len()))
        }
        Address::Ipv6(_) => Ok((ADDRESS_IPV6, 16)),
    }
}

fn parse_address(address_type: u8, address: &[u8]) -> Result<Address, NxrProtocolError> {
    match address_type {
        ADDRESS_IPV4 => {
            let bytes: [u8; 4] = address.try_into().map_err(|_| NxrProtocolError::Address)?;
            Ok(Address::Ipv4(Ipv4Addr::from(bytes)))
        }
        ADDRESS_DOMAIN => std::str::from_utf8(address)
            .map(str::to_owned)
            .map(Address::Domain)
            .map_err(|_| NxrProtocolError::Address),
        ADDRESS_IPV6 => {
            let bytes: [u8; 16] = address.try_into().map_err(|_| NxrProtocolError::Address)?;
            Ok(Address::Ipv6(Ipv6Addr::from(bytes)))
        }
        _ => Err(NxrProtocolError::Address),
    }
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, NxrProtocolError> {
    let bytes = input
        .get(offset..offset + 2)
        .ok_or(NxrProtocolError::Length)?
        .try_into()
        .map_err(|_| NxrProtocolError::Length)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, NxrProtocolError> {
    let bytes = input
        .get(offset..offset + 8)
        .ok_or(NxrProtocolError::Length)?
        .try_into()
        .map_err(|_| NxrProtocolError::Length)?;
    Ok(u64::from_be_bytes(bytes))
}
