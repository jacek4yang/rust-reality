use std::{error::Error, fmt, net::Ipv4Addr, net::Ipv6Addr};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::vless::{Address, Destination};

type NxrHmac = Hmac<Sha256>;

const MAGIC: [u8; 4] = [b'N', b'X', b'R', 1];
const FLAGS: u8 = 0;
const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 2;
const ADDRESS_IPV6: u8 = 3;
const ADDRESS_LENGTH_OFFSET: usize = 6;
const PORT_OFFSET: usize = 8;
const TIMESTAMP_OFFSET: usize = 10;
const NONCE_OFFSET: usize = 18;
const ADDRESS_OFFSET: usize = 34;
const TAG_LEN: usize = 32;
const MAX_DOMAIN_LEN: usize = 253;

/// Bytes required before the receiver can determine the exact request length.
pub const REQUEST_HEADER_LEN: usize = ADDRESS_OFFSET;

/// Strict maximum for one NXR authentication request.
pub const MAX_REQUEST_LEN: usize = REQUEST_HEADER_LEN + MAX_DOMAIN_LEN + TAG_LEN;

/// Independent NXR HMAC key. Debug output never reveals its bytes. The cached
/// keyed SHA-256 cores and buffer zeroize through their composed drop paths.
#[derive(Clone)]
pub struct NxrKey(NxrHmac);

impl NxrKey {
    /// Creates a key from exactly 256 bits of independently generated entropy.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        let bytes = Zeroizing::new(bytes);
        let template =
            NxrHmac::new_from_slice(bytes.as_slice()).expect("HMAC-SHA256 accepts a 32-byte key");
        Self(template)
    }

    fn mac(&self) -> NxrHmac {
        self.0.clone()
    }
}

impl fmt::Debug for NxrKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NxrKey([REDACTED])")
    }
}

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
/// The HMAC covers the version, flags, address type and length, port, timestamp,
/// nonce, and destination address. No framing follows this request: the next byte
/// on the connection is raw user payload.
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
    output.push(FLAGS);
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
    if header[4] != FLAGS {
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

fn authenticate(key: &NxrKey, input: &[u8]) -> [u8; TAG_LEN] {
    let mut mac = key.mac();
    mac.update(input);
    mac.finalize().into_bytes().into()
}

fn verify(key: &NxrKey, input: &[u8], tag: &[u8]) -> Result<(), NxrProtocolError> {
    let mut mac = key.mac();
    mac.update(input);
    mac.verify_slice(tag)
        .map_err(|_| NxrProtocolError::Authentication)
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

/// NXR request construction or authentication failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NxrProtocolError {
    Length,
    Version,
    Flags,
    Address,
    Port,
    TimeWindow,
    Authentication,
    Allocation,
}

impl fmt::Display for NxrProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length => formatter.write_str("NXR authentication request length is invalid"),
            Self::Version => formatter.write_str("NXR authentication version is invalid"),
            Self::Flags => formatter.write_str("NXR authentication flags are unsupported"),
            Self::Address => formatter.write_str("NXR destination address is invalid"),
            Self::Port => formatter.write_str("NXR destination port is invalid"),
            Self::TimeWindow => {
                formatter.write_str("NXR authentication timestamp is outside policy")
            }
            Self::Authentication => formatter.write_str("NXR authentication failed"),
            Self::Allocation => formatter.write_str("NXR request allocation failed"),
        }
    }
}

impl Error for NxrProtocolError {}

#[cfg(test)]
mod tests {
    use std::{hint::black_box, net::Ipv4Addr, net::Ipv6Addr};

    use super::{
        MAX_REQUEST_LEN, NxrKey, NxrProtocolError, REQUEST_HEADER_LEN,
        decode_authenticated_request, encode_request, request_len_from_header,
    };
    use crate::protocol::vless::{Address, Destination};

    const NOW: u64 = 1_700_000_000;

    #[test]
    fn repeated_encode_reuses_reserved_output_without_allocating() {
        let key = NxrKey::new([0x0b; 32]);
        let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);
        let mut encoded = Vec::with_capacity(MAX_REQUEST_LEN);

        let measured = allocation_counter::measure(|| {
            for _ in 0..1_024 {
                encode_request(
                    black_box(&destination),
                    black_box(NOW),
                    black_box([0x44; 16]),
                    black_box(&key),
                    black_box(&mut encoded),
                )
                .expect("request must encode");
            }
        });

        assert_eq!(
            measured.count_total, 0,
            "reserved NXR encoding must not allocate: {measured:?}"
        );
    }

    #[test]
    fn fixed_ipv4_hmac_vector_round_trips() {
        let key = NxrKey::new([0x0b; 32]);
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 443);
        let mut encoded = Vec::new();
        encode_request(
            &destination,
            NOW,
            core::array::from_fn(|index| u8::try_from(index).expect("index must fit")),
            &key,
            &mut encoded,
        )
        .expect("request must encode");

        assert_eq!(
            hex(&encoded),
            "4e5852010001000401bb000000006553f100000102030405060708090a0b0c0d0e0f01020304a5cf813fbe96f09cfedd30ce904f3664887f57a5f1fd026ae7a855ff15767d74"
        );
        let decoded = decode_authenticated_request(&encoded, &key, NOW + 5, 10)
            .expect("authenticated vector must decode");
        assert_eq!(decoded.destination(), &destination);
        assert_eq!(decoded.timestamp(), NOW);
    }

    #[test]
    fn domain_and_ipv6_requests_round_trip_at_exact_boundaries() {
        let key = NxrKey::new([0x42; 32]);
        let destinations = [
            Destination::new(Address::Domain("a".repeat(253)), 53),
            Destination::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 8443),
        ];
        for destination in destinations {
            let mut encoded = Vec::new();
            encode_request(&destination, NOW, [0x55; 16], &key, &mut encoded)
                .expect("bounded destination must encode");
            assert_eq!(
                request_len_from_header(&encoded[..REQUEST_HEADER_LEN])
                    .expect("header must declare exact size"),
                encoded.len()
            );
            assert!(encoded.len() <= MAX_REQUEST_LEN);
            assert_eq!(
                decode_authenticated_request(&encoded, &key, NOW, 0)
                    .expect("request must authenticate")
                    .destination(),
                &destination
            );
        }
    }

    #[test]
    fn rejects_tamper_wrong_key_time_and_trailing_data() {
        let key = NxrKey::new([0x31; 32]);
        let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);
        let mut encoded = Vec::new();
        encode_request(&destination, NOW, [0x77; 16], &key, &mut encoded)
            .expect("request must encode");

        let mut tampered = encoded.clone();
        tampered[REQUEST_HEADER_LEN] ^= 1;
        assert_eq!(
            decode_authenticated_request(&tampered, &key, NOW, 1),
            Err(NxrProtocolError::Authentication)
        );
        assert_eq!(
            decode_authenticated_request(&encoded, &NxrKey::new([0x32; 32]), NOW, 1),
            Err(NxrProtocolError::Authentication)
        );
        assert_eq!(
            decode_authenticated_request(&encoded, &key, NOW + 2, 1),
            Err(NxrProtocolError::TimeWindow)
        );
        encoded.push(0);
        assert_eq!(
            decode_authenticated_request(&encoded, &key, NOW, 1),
            Err(NxrProtocolError::Length)
        );
    }

    #[test]
    fn arbitrary_bytes_never_panic_or_exceed_declared_bound() {
        let key = NxrKey::new([0x99; 32]);
        let mut state = 0x6a09_e667_f3bc_c909_u64;
        for length in 0..=MAX_REQUEST_LEN + 8 {
            let mut input = vec![0_u8; length];
            for byte in &mut input {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state.to_le_bytes()[0];
            }
            let _ignored = decode_authenticated_request(&input, &key, NOW, 30);
            if length >= REQUEST_HEADER_LEN
                && let Ok(declared) = request_len_from_header(&input[..REQUEST_HEADER_LEN])
            {
                assert!(declared <= MAX_REQUEST_LEN);
            }
        }
    }

    fn hex(input: &[u8]) -> String {
        input.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
