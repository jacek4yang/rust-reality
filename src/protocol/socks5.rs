//! A bounded RFC 1928 wire-codec subset for the client SOCKS5 inbound.
//!
//! This module handles the no-authentication method negotiation, TCP `CONNECT`,
//! and UDP `ASSOCIATE` requests, plus the SOCKS5 UDP datagram header used after
//! a successful associate. It parses IPv4, IPv6, and non-empty domain
//! destinations, returns the exact request-header length, and borrows any bytes
//! after a complete header as payload. A domain is copied into the canonical
//! VLESS [`Destination`] only after its length and the shared VLESS domain-byte
//! grammar have been checked; its wire length is at most 255 bytes.
//!
//! No listener, socket, DNS lookup, authentication subprotocol, `BIND`, or
//! runtime routing policy is part of this codec. Fragmented UDP (`FRAG != 0`)
//! is rejected.

use std::{
    error::Error,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    str,
};

use super::vless::{Address, Destination};

const fn is_domain_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.' || byte == b'_'
}

fn is_valid_domain_name(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.len() <= usize::from(u8::MAX)
        && bytes.iter().copied().all(is_domain_byte)
        && str::from_utf8(bytes).is_ok()
}

fn validate_destination(destination: &Destination) -> Result<(), DecodeError> {
    if destination.port() == 0 {
        return Err(DecodeError::ZeroPort);
    }
    if let Address::Domain(domain) = destination.address()
        && !is_valid_domain_name(domain.as_bytes())
    {
        return Err(DecodeError::InvalidDomainName);
    }
    Ok(())
}

/// SOCKS protocol version defined by RFC 1928.
pub const VERSION: u8 = 0x05;

/// Maximum wire length of a TCP CONNECT request with a 255-byte domain.
pub const MAX_CONNECT_REQUEST_LEN: usize = 4 + 1 + u8::MAX as usize + 2;

const METHOD_NO_AUTHENTICATION: u8 = 0x00;
const METHOD_NO_ACCEPTABLE_METHODS: u8 = 0xff;
const COMMAND_CONNECT: u8 = 0x01;
const COMMAND_UDP_ASSOCIATE: u8 = 0x03;
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

/// A parsed UDP ASSOCIATE request (RFC 1928 CMD=0x03).
///
/// The destination is the address the client expects to send from; many clients
/// use `0.0.0.0:0` / `[::]:0`. Port zero is allowed here (unlike CONNECT).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpAssociateRequest {
    destination: Destination,
    consumed: usize,
}

impl UdpAssociateRequest {
    /// Client-reported expected source (often unspecified).
    pub const fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Bytes consumed by the complete ASSOCIATE header.
    pub const fn consumed(&self) -> usize {
        self.consumed
    }
}

/// One SOCKS5 UDP request/response datagram header plus payload (RFC 1928 §7).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpDatagram<'a> {
    destination: Destination,
    payload: &'a [u8],
    consumed: usize,
}

impl<'a> UdpDatagram<'a> {
    /// Destination carried in the UDP header.
    pub const fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Application payload after the SOCKS5 UDP header.
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Total header length (RSV+FRAG+ATYP+ADDR+PORT).
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Splits into owned destination and borrowed payload.
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
    /// The request used a command other than TCP CONNECT or UDP ASSOCIATE.
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
    /// SOCKS5 UDP datagram used a non-zero FRAG field (fragmentation unsupported).
    FragmentedUdp(u8),
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
            Self::FragmentedUdp(frag) => {
                write!(
                    formatter,
                    "SOCKS5 UDP fragmentation is unsupported (FRAG={frag})"
                )
            }
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

/// Parses one RFC 1928 UDP ASSOCIATE request (`CMD=0x03`).
///
/// Address and port may be unspecified (`0.0.0.0:0`). Port zero is accepted.
pub fn decode_udp_associate_request(input: &[u8]) -> Result<UdpAssociateRequest, DecodeError> {
    let mut cursor = Cursor::new(input);
    let version = cursor.read_u8("version")?;
    if version != VERSION {
        return Err(DecodeError::InvalidVersion(version));
    }

    let command = cursor.read_u8("command")?;
    if command != COMMAND_UDP_ASSOCIATE {
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
    let destination = Destination::new(address, port);
    if let Address::Domain(domain) = destination.address()
        && !is_valid_domain_name(domain.as_bytes())
    {
        return Err(DecodeError::InvalidDomainName);
    }

    Ok(UdpAssociateRequest {
        destination,
        consumed: cursor.position,
    })
}

/// Encodes a UDP ASSOCIATE request header.
pub fn encode_udp_associate_request(
    destination: &Destination,
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    if let Address::Domain(domain) = destination.address()
        && (domain.is_empty()
            || domain.len() > usize::from(u8::MAX)
            || !is_valid_domain_name(domain.as_bytes()))
    {
        return Err(EncodeError::InvalidDomainName);
    }
    let required = connect_request_len(destination);
    ensure_capacity(output, required)?;

    output[0] = VERSION;
    output[1] = COMMAND_UDP_ASSOCIATE;
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

/// Maximum SOCKS5 UDP header length (RSV+FRAG+ATYP+255-domain+PORT).
pub const MAX_UDP_HEADER_LEN: usize = 2 + 1 + 1 + 1 + u8::MAX as usize + 2;

/// Parses one SOCKS5 UDP datagram (RFC 1928 §7). Rejects `FRAG != 0`.
pub fn decode_udp_datagram(input: &[u8]) -> Result<UdpDatagram<'_>, DecodeError> {
    let mut cursor = Cursor::new(input);
    let _rsv = cursor.read_u16("UDP reserved")?;
    let frag = cursor.read_u8("UDP fragment")?;
    if frag != 0 {
        return Err(DecodeError::FragmentedUdp(frag));
    }
    let address_type = cursor.read_u8("address type")?;
    let address = match address_type {
        ADDRESS_IPV4 => Address::Ipv4(Ipv4Addr::from(cursor.read_array::<4>("IPv4 address")?)),
        ADDRESS_DOMAIN => decode_domain(&mut cursor)?,
        ADDRESS_IPV6 => Address::Ipv6(Ipv6Addr::from(cursor.read_array::<16>("IPv6 address")?)),
        unsupported => return Err(DecodeError::UnsupportedAddressType(unsupported)),
    };
    let port = cursor.read_u16("destination port")?;
    if port == 0 {
        return Err(DecodeError::ZeroPort);
    }
    let destination = Destination::new(address, port);
    if let Address::Domain(domain) = destination.address()
        && !is_valid_domain_name(domain.as_bytes())
    {
        return Err(DecodeError::InvalidDomainName);
    }
    let consumed = cursor.position;
    Ok(UdpDatagram {
        destination,
        payload: cursor.remaining_slice(),
        consumed,
    })
}

/// Encodes a SOCKS5 UDP datagram header followed by `payload` into `output`.
pub fn encode_udp_datagram(
    destination: &Destination,
    payload: &[u8],
    output: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    validate_destination(destination).map_err(map_validation_to_encode)?;
    let header_len = match destination.address() {
        Address::Ipv4(_) => 2 + 1 + 1 + 4 + 2,
        Address::Ipv6(_) => 2 + 1 + 1 + 16 + 2,
        Address::Domain(domain) => 2 + 1 + 1 + 1 + domain.len() + 2,
    };
    output.clear();
    output.reserve(header_len + payload.len());
    output.extend_from_slice(&[0, 0, 0]); // RSV RSV FRAG
    match destination.address() {
        Address::Ipv4(address) => {
            output.push(ADDRESS_IPV4);
            output.extend_from_slice(&address.octets());
        }
        Address::Domain(domain) => {
            output.push(ADDRESS_DOMAIN);
            output.push(domain.len() as u8);
            output.extend_from_slice(domain.as_bytes());
        }
        Address::Ipv6(address) => {
            output.push(ADDRESS_IPV6);
            output.extend_from_slice(&address.octets());
        }
    }
    output.extend_from_slice(&destination.port().to_be_bytes());
    output.extend_from_slice(payload);
    Ok(())
}

/// Encodes a SOCKS5 command reply (CONNECT or UDP ASSOCIATE) with an IPv4/IPv6 bind address.
pub fn encode_command_reply(
    rep: u8,
    bound: &std::net::SocketAddr,
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    match bound {
        std::net::SocketAddr::V4(v4) => {
            ensure_capacity(output, 10)?;
            output[0] = VERSION;
            output[1] = rep;
            output[2] = 0;
            output[3] = ADDRESS_IPV4;
            output[4..8].copy_from_slice(&v4.ip().octets());
            output[8..10].copy_from_slice(&v4.port().to_be_bytes());
            Ok(10)
        }
        std::net::SocketAddr::V6(v6) => {
            ensure_capacity(output, 22)?;
            output[0] = VERSION;
            output[1] = rep;
            output[2] = 0;
            output[3] = ADDRESS_IPV6;
            output[4..20].copy_from_slice(&v6.ip().octets());
            output[20..22].copy_from_slice(&v6.port().to_be_bytes());
            Ok(22)
        }
    }
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

fn map_validation_to_decode(error: DecodeError) -> DecodeError {
    error
}

fn map_validation_to_encode(error: DecodeError) -> EncodeError {
    match error {
        DecodeError::ZeroPort => EncodeError::ZeroPort,
        _ => EncodeError::InvalidDomainName,
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
mod tests;
