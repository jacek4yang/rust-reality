//! A bounded RFC 1928 wire-codec subset for a future SOCKS5 inbound.
//!
//! This module handles only the no-authentication method negotiation and TCP
//! `CONNECT` requests. It parses IPv4, IPv6, and non-empty domain destinations,
//! returns the exact request-header length, and borrows any bytes after a
//! complete header as payload. A domain is copied into the canonical VLESS
//! [`Destination`] only after its length and the shared VLESS domain-byte
//! grammar have been checked; its wire length is at most 255 bytes.
//!
//! No listener, socket, DNS lookup, bind operation, authentication subprotocol,
//! UDP, `BIND`, `CONNECT` reply, or runtime policy is part of this codec.

use std::{
    error::Error,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    str,
};

use super::vless::{
    Address, Destination, DestinationValidationError, is_valid_domain_name, validate_destination,
};

/// SOCKS protocol version defined by RFC 1928.
pub const VERSION: u8 = 0x05;

/// Maximum wire length of a TCP CONNECT request with a 255-byte domain.
pub const MAX_CONNECT_REQUEST_LEN: usize = 4 + 1 + u8::MAX as usize + 2;

const METHOD_NO_AUTHENTICATION: u8 = 0x00;
const METHOD_NO_ACCEPTABLE_METHODS: u8 = 0xff;
const COMMAND_CONNECT: u8 = 0x01;
const ADDRESS_IPV4: u8 = 0x01;
const ADDRESS_DOMAIN: u8 = 0x03;
const ADDRESS_IPV6: u8 = 0x04;

/// The no-authentication result of parsing a client's method offer.
///
/// The offered methods and trailing bytes remain borrowed from the input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MethodRequest<'a> {
    methods: &'a [u8],
    consumed: usize,
    trailing: &'a [u8],
}

impl<'a> MethodRequest<'a> {
    /// Returns the methods offered by the client.
    pub const fn methods(&self) -> &'a [u8] {
        self.methods
    }

    /// Returns the number of bytes in the complete method request.
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Returns bytes after the complete method request unchanged.
    pub const fn trailing(&self) -> &'a [u8] {
        self.trailing
    }
}

/// The method value to encode in a SOCKS5 method-selection reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MethodResponse {
    /// The client offered and the server selected no authentication (`0x00`).
    NoAuthentication,
    /// The server supports none of the methods offered (`0xff`).
    NoAcceptableMethods,
}

/// A parsed TCP CONNECT request and its unconsumed payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectRequest<'a> {
    destination: Destination,
    consumed: usize,
    payload: &'a [u8],
}

impl<'a> ConnectRequest<'a> {
    /// Returns the canonical destination carried by the request.
    pub const fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Returns the number of bytes in the complete CONNECT header.
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Returns bytes following the CONNECT header unchanged as payload.
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Splits the parsed request into its destination and trailing payload.
    pub fn into_parts(self) -> (Destination, &'a [u8]) {
        (self.destination, self.payload)
    }
}

/// An error produced while parsing the supported SOCKS5 request subset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The input ended before the indicated field was complete.
    IncompleteInput {
        /// Name of the field being read.
        field: &'static str,
        /// Number of bytes needed for that field.
        needed: usize,
        /// Number of bytes available for that field.
        available: usize,
    },
    /// The request used a protocol version other than 5.
    InvalidVersion(u8),
    /// A method offer declared zero methods; RFC 1928 requires 1–255.
    InvalidMethodCount,
    /// The method offer did not include the supported no-auth method.
    UnsupportedMethod,
    /// The request used a command other than TCP CONNECT.
    UnsupportedCommand(u8),
    /// The reserved request field was not zero.
    InvalidReservedField(u8),
    /// The request used an address type outside IPv4, domain, and IPv6.
    UnsupportedAddressType(u8),
    /// A domain destination declared zero name bytes.
    EmptyDomain,
    /// A TCP CONNECT destination port must be nonzero.
    ZeroPort,
    /// A domain contains bytes outside the canonical VLESS domain grammar.
    InvalidDomainName,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteInput {
                field,
                needed,
                available,
            } => write!(
                formatter,
                "incomplete SOCKS5 {field}: need {needed} bytes, have {available}"
            ),
            Self::InvalidVersion(version) => {
                write!(formatter, "unsupported SOCKS protocol version {version}")
            }
            Self::InvalidMethodCount => {
                formatter.write_str("SOCKS5 method offer must contain 1–255 methods")
            }
            Self::UnsupportedMethod => {
                formatter.write_str("SOCKS5 method offer does not include no authentication")
            }
            Self::UnsupportedCommand(command) => {
                write!(formatter, "SOCKS5 command {command:#04x} is not supported")
            }
            Self::InvalidReservedField(value) => {
                write!(
                    formatter,
                    "SOCKS5 reserved field must be zero, got {value:#04x}"
                )
            }
            Self::UnsupportedAddressType(address_type) => {
                write!(
                    formatter,
                    "SOCKS5 address type {address_type:#04x} is not supported"
                )
            }
            Self::EmptyDomain => formatter.write_str("SOCKS5 domain destination must not be empty"),
            Self::ZeroPort => {
                formatter.write_str("SOCKS5 TCP CONNECT destination port must be nonzero")
            }
            Self::InvalidDomainName => formatter.write_str("SOCKS5 domain destination is invalid"),
        }
    }
}

impl Error for DecodeError {}

/// An error produced while encoding a supported SOCKS5 message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// The supplied output slice cannot hold the complete message.
    OutputTooSmall { required: usize, available: usize },
    /// A TCP CONNECT destination port must be nonzero.
    ZeroPort,
    /// The canonical destination contains an empty or invalid domain name.
    InvalidDomainName,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputTooSmall {
                required,
                available,
            } => write!(
                formatter,
                "SOCKS5 output needs {required} bytes, buffer has {available}"
            ),
            Self::ZeroPort => {
                formatter.write_str("SOCKS5 TCP CONNECT destination port must be nonzero")
            }
            Self::InvalidDomainName => formatter.write_str("SOCKS5 domain destination is invalid"),
        }
    }
}

impl Error for EncodeError {}

/// Parses one RFC 1928 method offer and selects no authentication.
///
/// The input may contain bytes after the method list. They are not consumed;
/// [`MethodRequest::trailing`] returns the exact remainder. A complete but
/// unsupported offer is distinct from truncated input.
pub fn decode_method_request(input: &[u8]) -> Result<MethodRequest<'_>, DecodeError> {
    let mut cursor = Cursor::new(input);
    let version = cursor.read_u8("version")?;
    if version != VERSION {
        return Err(DecodeError::InvalidVersion(version));
    }

    let method_count = usize::from(cursor.read_u8("method count")?);
    if method_count == 0 {
        return Err(DecodeError::InvalidMethodCount);
    }

    let methods = cursor.take(method_count, "method list")?;
    if !methods.contains(&METHOD_NO_AUTHENTICATION) {
        return Err(DecodeError::UnsupportedMethod);
    }

    let consumed = cursor.position;
    Ok(MethodRequest {
        methods,
        consumed,
        trailing: cursor.remaining_slice(),
    })
}

/// Encodes a two-byte RFC 1928 method-selection reply.
///
/// The output is left unchanged if it is too short.
pub fn encode_method_response(
    response: MethodResponse,
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    const LENGTH: usize = 2;
    ensure_capacity(output, LENGTH)?;

    output[..LENGTH].copy_from_slice(&[
        VERSION,
        match response {
            MethodResponse::NoAuthentication => METHOD_NO_AUTHENTICATION,
            MethodResponse::NoAcceptableMethods => METHOD_NO_ACCEPTABLE_METHODS,
        },
    ]);
    Ok(LENGTH)
}

/// Parses one RFC 1928 TCP CONNECT request.
///
/// The parser supports IPv4 (`ATYP=1`), domain (`ATYP=3`), and IPv6
/// (`ATYP=4`) destinations, validates `VER=5`, `CMD=CONNECT`, and `RSV=0`,
/// and returns any coalesced payload unchanged. Incomplete fields return
/// [`DecodeError::IncompleteInput`]; invalid or unsupported fields return a
/// different error.
pub fn decode_connect_request(input: &[u8]) -> Result<ConnectRequest<'_>, DecodeError> {
    let mut cursor = Cursor::new(input);
    let version = cursor.read_u8("version")?;
    if version != VERSION {
        return Err(DecodeError::InvalidVersion(version));
    }

    let command = cursor.read_u8("command")?;
    if command != COMMAND_CONNECT {
        return Err(DecodeError::UnsupportedCommand(command));
    }

    let reserved = cursor.read_u8("reserved field")?;
    if reserved != 0 {
        return Err(DecodeError::InvalidReservedField(reserved));
    }

    let address_type = cursor.read_u8("address type")?;
    let address = match address_type {
        ADDRESS_IPV4 => Address::Ipv4(Ipv4Addr::from(cursor.read_array::<4>("IPv4 address")?)),
        ADDRESS_DOMAIN => decode_domain(&mut cursor)?,
        ADDRESS_IPV6 => Address::Ipv6(Ipv6Addr::from(cursor.read_array::<16>("IPv6 address")?)),
        unsupported => return Err(DecodeError::UnsupportedAddressType(unsupported)),
    };
    let port = cursor.read_u16("destination port")?;
    let consumed = cursor.position;
    let destination = Destination::new(address, port);
    validate_destination(&destination).map_err(map_validation_to_decode)?;

    Ok(ConnectRequest {
        destination,
        consumed,
        payload: cursor.remaining_slice(),
    })
}

/// Encodes a TCP CONNECT request using the canonical VLESS destination type.
///
/// The function checks the complete required length and domain grammar before
/// writing. On error, the output slice remains unchanged. Payload bytes are
/// deliberately separate from this request-header encoder.
pub fn encode_connect_request(
    destination: &Destination,
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    validate_destination(destination).map_err(map_validation_to_encode)?;
    let required = connect_request_len(destination);
    ensure_capacity(output, required)?;

    output[0] = VERSION;
    output[1] = COMMAND_CONNECT;
    output[2] = 0;
    match destination.address() {
        Address::Ipv4(address) => {
            output[3] = ADDRESS_IPV4;
            output[4..8].copy_from_slice(&address.octets());
            output[8..10].copy_from_slice(&destination.port().to_be_bytes());
        }
        Address::Domain(domain) => {
            let domain_bytes = domain.as_bytes();
            output[3] = ADDRESS_DOMAIN;
            output[4] = domain_bytes.len() as u8;
            output[5..5 + domain_bytes.len()].copy_from_slice(domain_bytes);
            let port_start = 5 + domain_bytes.len();
            output[port_start..port_start + 2].copy_from_slice(&destination.port().to_be_bytes());
        }
        Address::Ipv6(address) => {
            output[3] = ADDRESS_IPV6;
            output[4..20].copy_from_slice(&address.octets());
            output[20..22].copy_from_slice(&destination.port().to_be_bytes());
        }
    }

    Ok(required)
}

fn connect_request_len(destination: &Destination) -> usize {
    match destination.address() {
        Address::Ipv4(_) => 4 + 4 + 2,
        Address::Ipv6(_) => 4 + 16 + 2,
        Address::Domain(domain) => 4 + 1 + domain.len() + 2,
    }
}

fn decode_domain(cursor: &mut Cursor<'_>) -> Result<Address, DecodeError> {
    let length = usize::from(cursor.read_u8("domain length")?);
    if length == 0 {
        return Err(DecodeError::EmptyDomain);
    }

    let bytes = cursor.take(length, "domain name")?;
    if !is_valid_domain_name(bytes) {
        return Err(DecodeError::InvalidDomainName);
    }
    let domain = str::from_utf8(bytes).map_err(|_| DecodeError::InvalidDomainName)?;
    Ok(Address::Domain(domain.to_owned()))
}

fn map_validation_to_decode(error: DestinationValidationError) -> DecodeError {
    match error {
        DestinationValidationError::ZeroPort => DecodeError::ZeroPort,
        DestinationValidationError::InvalidDomain => DecodeError::InvalidDomainName,
    }
}

fn map_validation_to_encode(error: DestinationValidationError) -> EncodeError {
    match error {
        DestinationValidationError::ZeroPort => EncodeError::ZeroPort,
        DestinationValidationError::InvalidDomain => EncodeError::InvalidDomainName,
    }
}

fn ensure_capacity(output: &[u8], required: usize) -> Result<(), EncodeError> {
    if output.len() < required {
        return Err(EncodeError::OutputTooSmall {
            required,
            available: output.len(),
        });
    }
    Ok(())
}

struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, DecodeError> {
        Ok(self.take(1, field)?[0])
    }

    fn read_u16(&mut self, field: &'static str) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.read_array::<2>(field)?))
    }

    fn read_array<const LENGTH: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; LENGTH], DecodeError> {
        let bytes = self.take(LENGTH, field)?;
        let mut result = [0_u8; LENGTH];
        result.copy_from_slice(bytes);
        Ok(result)
    }

    fn take(&mut self, length: usize, field: &'static str) -> Result<&'a [u8], DecodeError> {
        let remaining = self.input.len().saturating_sub(self.position);
        if remaining < length {
            return Err(DecodeError::IncompleteInput {
                field,
                needed: length,
                available: remaining,
            });
        }

        let start = self.position;
        self.position += length;
        Ok(&self.input[start..self.position])
    }

    fn remaining_slice(&self) -> &'a [u8] {
        &self.input[self.position..]
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::{
        ConnectRequest, DecodeError, EncodeError, MAX_CONNECT_REQUEST_LEN, MethodResponse, VERSION,
        decode_connect_request, decode_method_request, encode_connect_request,
        encode_method_response,
    };
    use crate::protocol::vless::{Address, Destination};

    #[test]
    fn decodes_no_auth_method_offer_with_coalesced_bytes() {
        let input = [VERSION, 3, 2, 0, 1, 0xaa, 0xbb];
        let decoded = decode_method_request(&input).expect("no-auth offer should parse");

        assert_eq!(decoded.methods(), &[2, 0, 1]);
        assert_eq!(decoded.consumed(), 5);
        assert_eq!(decoded.trailing(), &[0xaa, 0xbb]);
        assert_eq!(&input[..decoded.consumed()], &[VERSION, 3, 2, 0, 1]);
    }

    #[test]
    fn distinguishes_every_truncated_method_prefix_from_invalid_input() {
        let complete = [VERSION, 2, 2, 0];
        for end in 0..complete.len() {
            assert!(
                matches!(
                    decode_method_request(&complete[..end]),
                    Err(DecodeError::IncompleteInput { .. })
                ),
                "prefix length {end} must be incomplete"
            );
        }
        assert!(decode_method_request(&complete).is_ok());
        assert_eq!(
            decode_method_request(&[4, 1, 0]),
            Err(DecodeError::InvalidVersion(4))
        );
        assert_eq!(
            decode_method_request(&[VERSION, 0]),
            Err(DecodeError::InvalidMethodCount)
        );
        assert_eq!(
            decode_method_request(&[VERSION, 1, 2]),
            Err(DecodeError::UnsupportedMethod)
        );
    }

    #[test]
    fn accepts_the_rfc_maximum_method_count() {
        let mut input = vec![VERSION, u8::MAX];
        input.resize(2 + usize::from(u8::MAX), 0x02);
        input[2 + usize::from(u8::MAX) - 1] = 0;

        let decoded = decode_method_request(&input).expect("255 offered methods are valid");
        assert_eq!(decoded.methods().len(), usize::from(u8::MAX));
        assert_eq!(decoded.consumed(), input.len());
        assert!(decoded.trailing().is_empty());
    }

    #[test]
    fn encodes_both_method_selection_values() {
        let mut output = [0xa5; 4];
        assert_eq!(
            encode_method_response(MethodResponse::NoAuthentication, &mut output),
            Ok(2)
        );
        assert_eq!(&output[..2], &[VERSION, 0]);
        assert_eq!(&output[2..], &[0xa5; 2]);
        assert_eq!(
            encode_method_response(MethodResponse::NoAcceptableMethods, &mut output),
            Ok(2)
        );
        assert_eq!(&output[..2], &[VERSION, 0xff]);
        assert_eq!(&output[2..], &[0xa5; 2]);
    }

    #[test]
    fn method_response_bounds_fail_at_every_short_length_without_mutation() {
        for available in 0..2 {
            let mut output = [0xa5; 2];
            assert_eq!(
                encode_method_response(MethodResponse::NoAuthentication, &mut output[..available]),
                Err(EncodeError::OutputTooSmall {
                    required: 2,
                    available,
                })
            );
            assert_eq!(output, [0xa5; 2]);
        }
    }

    #[test]
    fn round_trips_ipv4_ipv6_and_domain_connect_requests() {
        let destinations = [
            Destination::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, 19)), 443),
            Destination::new(
                Address::Ipv6("2001:db8::19".parse().expect("IPv6 literal")),
                65535,
            ),
            Destination::new(Address::Domain("example.com".to_owned()), 1),
        ];

        for destination in destinations {
            let mut output = [0xa5; MAX_CONNECT_REQUEST_LEN];
            let written = encode_connect_request(&destination, &mut output)
                .expect("canonical destination should encode");
            assert!(output[written..].iter().all(|&byte| byte == 0xa5));
            let decoded = decode_connect_request(&output[..written])
                .expect("encoded CONNECT request should decode");
            assert_eq!(decoded.destination(), &destination);
            assert_eq!(decoded.consumed(), written);
            assert!(decoded.payload().is_empty());
        }
    }

    #[test]
    fn connect_parser_preserves_coalesced_payload_and_consumed_length() {
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 8443);
        let mut input = [0_u8; MAX_CONNECT_REQUEST_LEN];
        let written = encode_connect_request(&destination, &mut input).expect("encode request");
        let mut coalesced = input[..written].to_vec();
        coalesced.extend_from_slice(b"first application payload");

        let decoded = decode_connect_request(&coalesced).expect("coalesced request should parse");
        assert_eq!(decoded.destination(), &destination);
        assert_eq!(decoded.consumed(), written);
        assert_eq!(decoded.payload(), b"first application payload");
        assert_eq!(&coalesced[..decoded.consumed()], &input[..written]);
    }

    #[test]
    fn every_truncated_prefix_of_each_address_form_is_incomplete() {
        let requests = [
            encode(&Destination::new(
                Address::Ipv4(Ipv4Addr::new(203, 0, 113, 5)),
                1080,
            )),
            encode(&Destination::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 1080)),
            encode(&Destination::new(
                Address::Domain("edge.example".to_owned()),
                1080,
            )),
        ];

        for request in requests {
            for end in 0..request.len() {
                assert!(
                    matches!(
                        decode_connect_request(&request[..end]),
                        Err(DecodeError::IncompleteInput { .. })
                    ),
                    "prefix length {end} of {} must be incomplete",
                    request.len()
                );
            }
            assert!(decode_connect_request(&request).is_ok());
        }
    }

    #[test]
    fn fragmented_connect_bytes_become_complete_only_after_the_last_fragment() {
        let complete = encode(&Destination::new(
            Address::Domain("fragments.example".to_owned()),
            8443,
        ));
        let mut accumulated = Vec::new();

        for (index, byte) in complete.iter().copied().enumerate() {
            accumulated.push(byte);
            if index + 1 < complete.len() {
                assert!(matches!(
                    decode_connect_request(&accumulated),
                    Err(DecodeError::IncompleteInput { .. })
                ));
            }
        }
        assert!(decode_connect_request(&accumulated).is_ok());
    }

    #[test]
    fn rejects_invalid_version_reserved_command_and_address_type() {
        assert_eq!(
            decode_connect_request(&[4, 1, 0, 1]),
            Err(DecodeError::InvalidVersion(4))
        );
        assert_eq!(
            decode_connect_request(&[VERSION, 1, 1, 1]),
            Err(DecodeError::InvalidReservedField(1))
        );
        assert_eq!(
            decode_connect_request(&[VERSION, 2, 0, 1]),
            Err(DecodeError::UnsupportedCommand(2))
        );
        assert_eq!(
            decode_connect_request(&[VERSION, 3, 0, 1]),
            Err(DecodeError::UnsupportedCommand(3))
        );
        assert_eq!(
            decode_connect_request(&[VERSION, 1, 0, 1, 127, 0, 0, 1, 0, 0]),
            Err(DecodeError::ZeroPort)
        );
        assert_eq!(
            decode_connect_request(&[VERSION, 1, 0, 2]),
            Err(DecodeError::UnsupportedAddressType(2))
        );
    }

    #[test]
    fn validates_domain_length_and_canonical_domain_grammar() {
        assert_eq!(
            decode_connect_request(&[VERSION, 1, 0, 3, 0]),
            Err(DecodeError::EmptyDomain)
        );
        assert_eq!(
            decode_connect_request(&[VERSION, 1, 0, 3, 1, b'/', 0, 80]),
            Err(DecodeError::InvalidDomainName)
        );

        let max_domain = "x".repeat(usize::from(u8::MAX));
        let destination = Destination::new(Address::Domain(max_domain), u16::MAX);
        let bytes = encode(&destination);
        assert_eq!(bytes.len(), MAX_CONNECT_REQUEST_LEN);
        assert_eq!(bytes[4], u8::MAX);
        assert_eq!(
            decode_connect_request(&bytes)
                .expect("255-byte domain is valid")
                .destination(),
            &destination
        );
    }

    #[test]
    fn connect_request_output_bounds_and_invalid_domain_do_not_mutate_output() {
        let destination = Destination::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 443);
        let mut too_short = [0xa5; 21];
        assert_eq!(
            encode_connect_request(&destination, &mut too_short),
            Err(EncodeError::OutputTooSmall {
                required: 22,
                available: 21,
            })
        );
        assert_eq!(too_short, [0xa5; 21]);

        let invalid_domain = Destination::new(Address::Domain(String::new()), 80);
        let mut output = [0xa5; MAX_CONNECT_REQUEST_LEN];
        assert_eq!(
            encode_connect_request(&invalid_domain, &mut output),
            Err(EncodeError::InvalidDomainName)
        );
        assert_eq!(output, [0xa5; MAX_CONNECT_REQUEST_LEN]);

        for invalid_domain in [
            Destination::new(Address::Domain("bad/name".to_owned()), 80),
            Destination::new(Address::Domain("x".repeat(usize::from(u8::MAX) + 1)), 80),
        ] {
            assert_eq!(
                encode_connect_request(&invalid_domain, &mut output),
                Err(EncodeError::InvalidDomainName)
            );
            assert_eq!(output, [0xa5; MAX_CONNECT_REQUEST_LEN]);
        }

        let zero_port = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 0);
        assert_eq!(
            encode_connect_request(&zero_port, &mut output),
            Err(EncodeError::ZeroPort)
        );
        assert_eq!(output, [0xa5; MAX_CONNECT_REQUEST_LEN]);
    }

    #[test]
    fn connect_output_bounds_cover_every_destination_encoding() {
        let destinations = [
            Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 80),
            Destination::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 80),
            Destination::new(Address::Domain("x".to_owned()), 80),
            Destination::new(Address::Domain("x".repeat(usize::from(u8::MAX))), 80),
        ];

        for destination in destinations {
            let required = encode(&destination).len();
            for available in 0..required {
                let mut output = [0xa5; MAX_CONNECT_REQUEST_LEN];
                assert_eq!(
                    encode_connect_request(&destination, &mut output[..available]),
                    Err(EncodeError::OutputTooSmall {
                        required,
                        available,
                    })
                );
                assert_eq!(output, [0xa5; MAX_CONNECT_REQUEST_LEN]);
            }
            let mut exact = [0xa5; MAX_CONNECT_REQUEST_LEN];
            assert_eq!(
                encode_connect_request(&destination, &mut exact[..required]),
                Ok(required)
            );
        }
    }

    #[test]
    fn decoder_result_retains_only_borrowed_payload_after_owned_destination() {
        let input = [VERSION, 1, 0, 1, 127, 0, 0, 1, 0, 80, 0xde, 0xad];
        let decoded: ConnectRequest<'_> = decode_connect_request(&input).expect("request");
        let (destination, payload) = decoded.into_parts();
        assert_eq!(
            destination,
            Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 80)
        );
        assert_eq!(payload, &[0xde, 0xad]);
    }

    fn encode(destination: &Destination) -> Vec<u8> {
        let mut output = [0_u8; MAX_CONNECT_REQUEST_LEN];
        let written = encode_connect_request(destination, &mut output).expect("encode destination");
        output[..written].to_vec()
    }
}
