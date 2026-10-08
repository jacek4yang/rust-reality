//! Client-side wire operations over the same VLESS model as the server.
//!
//! These functions do not establish a connection or imply remote destination
//! readiness. In particular, the response's second byte is an Addons length,
//! never an authentication or destination-error status code.

use std::{error::Error, fmt};

use super::{Addons, AddonsDecodeError, Address, Destination, UserId, VERSION, VISION_FLOW};

/// Validation failure before any request bytes are written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestEncodeError {
    /// A TCP destination must have a nonzero port.
    ZeroPort,
    /// The domain must fit the existing server's wire grammar.
    InvalidDomain,
    /// The caller's buffer is too small; it remains unchanged.
    BufferTooSmall { needed: usize },
}

impl fmt::Display for RequestEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroPort => f.write_str("VLESS TCP destination port must be nonzero"),
            Self::InvalidDomain => f.write_str("VLESS destination domain is invalid"),
            Self::BufferTooSmall { needed } => {
                write!(f, "VLESS request buffer needs {needed} bytes")
            }
        }
    }
}
impl Error for RequestEncodeError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DestinationValidationError {
    ZeroPort,
    InvalidDomain,
}

impl From<DestinationValidationError> for RequestEncodeError {
    fn from(error: DestinationValidationError) -> Self {
        match error {
            DestinationValidationError::ZeroPort => Self::ZeroPort,
            DestinationValidationError::InvalidDomain => Self::InvalidDomain,
        }
    }
}

/// Checks the bounded ASCII domain grammar shared by the VLESS and SOCKS5 codecs.
pub(crate) fn is_valid_domain_name(domain: &[u8]) -> bool {
    !domain.is_empty()
        && domain.len() <= usize::from(u8::MAX)
        && domain.iter().copied().all(super::decode::is_domain_byte)
}

/// Validates destination fields shared by VLESS and SOCKS5 TCP request encoders.
pub(crate) fn validate_destination(
    destination: &Destination,
) -> Result<(), DestinationValidationError> {
    if destination.port() == 0 {
        return Err(DestinationValidationError::ZeroPort);
    }
    if let Address::Domain(domain) = destination.address()
        && !is_valid_domain_name(domain.as_bytes())
    {
        return Err(DestinationValidationError::InvalidDomain);
    }
    Ok(())
}

/// Encodes a version-zero TCP request with the canonical Vision flow.
///
/// The caller owns storage and I/O. Invalid input or insufficient capacity leaves
/// the entire buffer unchanged. Only the returned prefix is initialized; bytes
/// after it are untouched. The result is an unframed VLESS header, not a Vision
/// frame. Application bytes must not be replayed across speculative candidates.
pub fn encode_vision_tcp_request(
    user: UserId,
    destination: &Destination,
    output: &mut [u8],
) -> Result<usize, RequestEncodeError> {
    validate_destination(destination).map_err(RequestEncodeError::from)?;
    let address_len = match destination.address() {
        Address::Ipv4(_) => 5,
        Address::Ipv6(_) => 17,
        Address::Domain(domain) => 2 + domain.len(),
    };
    // version, user, addons length, protobuf key/length/flow, command, port.
    let prefix_len = 1 + 16 + 1 + 2 + VISION_FLOW.len() + 1 + 2;
    let needed = prefix_len + address_len;
    if output.len() < needed {
        return Err(RequestEncodeError::BufferTooSmall { needed });
    }
    output[0] = VERSION;
    output[1..17].copy_from_slice(user.as_bytes());
    output[17] = (2 + VISION_FLOW.len()) as u8;
    output[18] = 0x0a;
    output[19] = VISION_FLOW.len() as u8;
    output[20..20 + VISION_FLOW.len()].copy_from_slice(VISION_FLOW.as_bytes());
    let command = 20 + VISION_FLOW.len();
    output[command] = super::Command::Tcp.as_byte();
    output[command + 1..prefix_len].copy_from_slice(&destination.port().to_be_bytes());
    match destination.address() {
        Address::Ipv4(address) => {
            output[prefix_len] = 1;
            output[prefix_len + 1..needed].copy_from_slice(&address.octets());
        }
        Address::Ipv6(address) => {
            output[prefix_len] = 3;
            output[prefix_len + 1..needed].copy_from_slice(&address.octets());
        }
        Address::Domain(domain) => {
            output[prefix_len] = 2;
            output[prefix_len + 1] = domain.len() as u8;
            output[prefix_len + 2..needed].copy_from_slice(domain.as_bytes());
        }
    }
    Ok(needed)
}

/// A response header borrowed from the caller's bounded input buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeResponse<'a> {
    addons: Addons<'a>,
    payload: &'a [u8],
}
impl<'a> DecodeResponse<'a> {
    /// Parsed Addons; supported unknown protobuf fields are skipped.
    pub const fn addons(self) -> Addons<'a> {
        self.addons
    }
    /// Every byte following the response header, without copying or consuming it.
    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }
}

/// A VLESS response framing or protobuf failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseDecodeError {
    /// More input is required; `needed` is the total required buffer length.
    Incomplete { needed: usize },
    /// The peer did not return the version-zero request's version.
    UnsupportedVersion(u8),
    /// Complete, length-delimited Addons were malformed. Do not retry parsing
    /// by consuming application bytes beyond the declared header.
    InvalidAddons(AddonsDecodeError),
}
impl fmt::Display for ResponseDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete { needed } => write!(f, "VLESS response needs {needed} bytes"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported VLESS response version {version}")
            }
            Self::InvalidAddons(error) => write!(f, "invalid VLESS response Addons: {error}"),
        }
    }
}
impl Error for ResponseDecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidAddons(error) => Some(error),
            _ => None,
        }
    }
}

/// Decodes one version-zero response header without allocating or doing I/O.
///
/// A caller may retain input and retry after `Incomplete`; at most 257 bytes
/// are needed for the header. EOF and deadlines are the runtime adapter's job.
/// A syntactically valid response does not attest destination availability,
/// authenticated identity, or authorization. No error-status byte exists here.
pub fn decode_response(input: &[u8]) -> Result<DecodeResponse<'_>, ResponseDecodeError> {
    let Some(&version) = input.first() else {
        return Err(ResponseDecodeError::Incomplete { needed: 1 });
    };
    if version != VERSION {
        return Err(ResponseDecodeError::UnsupportedVersion(version));
    }
    let Some(&length) = input.get(1) else {
        return Err(ResponseDecodeError::Incomplete { needed: 2 });
    };
    let needed = 2 + usize::from(length);
    if input.len() < needed {
        return Err(ResponseDecodeError::Incomplete { needed });
    }
    let addons = Addons::parse(&input[2..needed]).map_err(ResponseDecodeError::InvalidAddons)?;
    Ok(DecodeResponse {
        addons,
        payload: &input[needed..],
    })
}

#[cfg(test)]
mod tests {
    use super::super::{Command, decode_request};
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn all_destination_kinds_round_trip_through_server_decoder() {
        for address in [
            Address::Ipv4(Ipv4Addr::LOCALHOST),
            Address::Ipv6(Ipv6Addr::LOCALHOST),
            Address::Domain("example.test".into()),
            Address::Domain("a".repeat(255)),
        ] {
            let dest = Destination::new(address, 443);
            let mut bytes = [0xcc; 533];
            let length =
                encode_vision_tcp_request(UserId::new([0x11; 16]), &dest, &mut bytes).unwrap();
            assert!(bytes[length..].iter().all(|&b| b == 0xcc));
            let decoded = decode_request(&bytes[..length]).unwrap();
            assert_eq!(decoded.header().destination(), Some(&dest));
            assert_eq!(decoded.header().command(), Command::Tcp);
            assert_eq!(decoded.header().user_id(), UserId::new([0x11; 16]));
            assert_eq!(
                Addons::parse(decoded.header().addons()).unwrap().flow(),
                Some(VISION_FLOW)
            );
            assert!(decoded.payload().is_empty());
        }
    }

    #[test]
    fn ipv4_request_has_independently_specified_wire_bytes() {
        let mut bytes = [0; 128];
        let dest = Destination::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)), 443);
        let n = encode_vision_tcp_request(UserId::new([0x11; 16]), &dest, &mut bytes).unwrap();
        let mut expected = vec![0];
        expected.extend_from_slice(&[0x11; 16]);
        expected.extend_from_slice(&[18, 0x0a, 16]);
        expected.extend_from_slice(b"xtls-rprx-vision");
        expected.extend_from_slice(&[1, 1, 0xbb, 1, 192, 0, 2, 1]);
        assert_eq!(&bytes[..n], expected);
    }

    #[test]
    fn rejected_requests_leave_storage_unchanged() {
        for (domain, port, expected) in [
            ("", 443, RequestEncodeError::InvalidDomain),
            ("bad/name", 443, RequestEncodeError::InvalidDomain),
            ("测试", 443, RequestEncodeError::InvalidDomain),
            ("ok.test", 0, RequestEncodeError::ZeroPort),
        ] {
            let mut bytes = [0xcc; 533];
            assert_eq!(
                encode_vision_tcp_request(
                    UserId::new([0; 16]),
                    &Destination::new(Address::Domain(domain.into()), port),
                    &mut bytes
                ),
                Err(expected)
            );
            assert_eq!(bytes, [0xcc; 533]);
        }
        let mut bytes = [0xcc; 533];
        assert_eq!(
            encode_vision_tcp_request(
                UserId::new([0; 16]),
                &Destination::new(Address::Domain("a".repeat(256)), 443),
                &mut bytes
            ),
            Err(RequestEncodeError::InvalidDomain)
        );
        assert_eq!(bytes, [0xcc; 533]);
    }

    #[test]
    fn each_short_output_is_atomic_and_exact_size_succeeds() {
        let dest = Destination::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 65535);
        let mut bytes = [0xcc; 533];
        let n = encode_vision_tcp_request(UserId::new([0; 16]), &dest, &mut bytes).unwrap();
        for len in 0..n {
            bytes.fill(0xcc);
            assert_eq!(
                encode_vision_tcp_request(UserId::new([0; 16]), &dest, &mut bytes[..len]),
                Err(RequestEncodeError::BufferTooSmall { needed: n })
            );
            assert_eq!(bytes, [0xcc; 533]);
        }
        assert_eq!(
            encode_vision_tcp_request(UserId::new([0; 16]), &dest, &mut bytes[..n]),
            Ok(n)
        );
    }

    #[test]
    fn response_addons_length_is_not_a_status_code() {
        // Unknown valid varint field. Length 2 must not mean "forbidden".
        let bytes = [0, 2, 0x18, 1, 0xde, 0xad];
        let decoded = decode_response(&bytes).unwrap();
        assert_eq!(decoded.addons(), Addons::default());
        assert_eq!(decoded.payload(), &[0xde, 0xad]);
        assert_eq!(decode_response(&[0, 0, 1, 2]).unwrap().payload(), &[1, 2]);
    }

    #[test]
    fn every_fragment_boundary_and_maximum_header_are_bounded() {
        let mut bytes = vec![0, 255, 0x12, 0xfc, 0x01];
        bytes.extend_from_slice(&[0x55; 252]);
        for len in 0..257 {
            assert!(
                matches!(decode_response(&bytes[..len]),Err(ResponseDecodeError::Incomplete{needed}) if needed > len && needed <=257)
            );
        }
        bytes.extend_from_slice(b"application");
        let result = decode_response(&bytes).unwrap();
        assert_eq!(result.addons().seed(), Some([0x55; 252].as_slice()));
        assert_eq!(result.payload(), b"application");
    }

    #[test]
    fn malformed_complete_addons_do_not_borrow_payload_bytes() {
        assert!(matches!(
            decode_response(&[0, 1, 0x12, 0, 0]),
            Err(ResponseDecodeError::InvalidAddons(
                AddonsDecodeError::Truncated
            ))
        ));
        for version in 1..=255 {
            assert_eq!(
                decode_response(&[version]),
                Err(ResponseDecodeError::UnsupportedVersion(version))
            );
        }
    }

    #[test]
    fn codecs_allocate_nothing() {
        let dest = Destination::new(Address::Domain("example.test".into()), 443);
        let mut bytes = [0; 533];
        let allocation = allocation_counter::measure(|| {
            std::hint::black_box(
                encode_vision_tcp_request(UserId::new([0; 16]), &dest, &mut bytes).unwrap(),
            );
            std::hint::black_box(decode_response(&[0, 2, 0x18, 1, 9]).unwrap());
        });
        assert_eq!(allocation.count_total, 0);
    }
}
