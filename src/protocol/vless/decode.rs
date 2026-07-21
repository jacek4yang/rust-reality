use std::{
    error::Error,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    str,
};

use super::{Address, Command, Destination, RequestHeader, UserId, VERSION};

const ADDRESS_TYPE_IPV4: u8 = 0x01;
const ADDRESS_TYPE_DOMAIN: u8 = 0x02;
const ADDRESS_TYPE_IPV6: u8 = 0x03;

/// A decoded request header and the request payload following it.
#[derive(Debug, Eq, PartialEq)]
pub struct DecodeRequest<'a> {
    header: RequestHeader,
    payload: &'a [u8],
}

impl<'a> DecodeRequest<'a> {
    /// Returns the decoded request header.
    pub const fn header(&self) -> &RequestHeader {
        &self.header
    }

    /// Returns bytes following the complete request header.
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Splits the decoded value into its header and remaining payload.
    pub fn into_parts(self) -> (RequestHeader, &'a [u8]) {
        (self.header, self.payload)
    }
}

/// An error produced while decoding a VLESS request header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The input ended before a complete field was available.
    UnexpectedEnd {
        field: &'static str,
        needed: usize,
        remaining: usize,
    },

    /// The request used a protocol version not implemented here.
    UnsupportedVersion(u8),

    /// The request contained an unknown command value.
    UnknownCommand(u8),

    /// The request contained an unknown command value.
    UnknownAddressType(u8),

    /// A domain address declared a zero-byte name.
    EmptyDomain,

    /// A domain contained bytes outside the accepted wire character set.
    InvalidDomainName,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEnd {
                field,
                needed,
                remaining,
            } => write!(
                formatter,
                "unexpected end while reading {field}: \
                need {needed} bytes, have {remaining}"
            ),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported VLESS version {version}")
            }
            Self::UnknownCommand(command) => write!(formatter, "unknown VLESS command {command}"),
            Self::UnknownAddressType(address_type) => {
                write!(formatter, "unknown VLESS address type {address_type}")
            }
            Self::EmptyDomain => formatter.write_str("VLESS domain must not be empty"),
            Self::InvalidDomainName => formatter.write_str("invalid VLESS domain name"),
        }
    }
}

impl Error for DecodeError {}

/// Decodes one VLESS request from a complete byte slice.
///
/// Bytes following the request header are returned unchanged as payload.
pub fn decode_request(input: &[u8]) -> Result<DecodeRequest<'_>, DecodeError> {
    let mut cursor = Cursor::new(input);

    let version = cursor.read_u8("protocol version")?;

    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }

    let user_id = UserId::new(cursor.read_array::<16>("user ID")?);

    let addons_length = usize::from(cursor.read_u8("addons length")?);

    let addons = cursor.take(addons_length, "addons")?.to_vec();

    let command = decode_command(cursor.read_u8("command")?)?;

    let destination = if command.requires_destination() {
        Some(decode_destination(&mut cursor)?)
    } else {
        None
    };

    let header = RequestHeader::new(version, user_id, addons, command, destination);

    Ok(DecodeRequest {
        header,
        payload: cursor.remaining_slice(),
    })
}

fn decode_command(value: u8) -> Result<Command, DecodeError> {
    match value {
        0x01 => Ok(Command::Tcp),
        0x02 => Ok(Command::Udp),
        0x03 => Ok(Command::Mux),
        0x04 => Ok(Command::Reverse),
        unknown => Err(DecodeError::UnknownCommand(unknown)),
    }
}

fn decode_destination(cursor: &mut Cursor<'_>) -> Result<Destination, DecodeError> {
    let port = cursor.read_u16("destination port")?;
    let address_type = cursor.read_u8("address type")?;

    let address = match address_type {
        ADDRESS_TYPE_IPV4 => {
            let octets = cursor.read_array("IPv4 address")?;

            Address::Ipv4(Ipv4Addr::from(octets))
        }

        ADDRESS_TYPE_DOMAIN => decode_domain(cursor)?,

        ADDRESS_TYPE_IPV6 => {
            let octets = cursor.read_array("IPv6 address")?;

            Address::Ipv6(Ipv6Addr::from(octets))
        }

        unknown => {
            return Err(DecodeError::UnknownAddressType(unknown));
        }
    };

    Ok(Destination::new(address, port))
}

fn decode_domain(cursor: &mut Cursor<'_>) -> Result<Address, DecodeError> {
    let length = usize::from(cursor.read_u8("domain length")?);

    if length == 0 {
        return Err(DecodeError::EmptyDomain);
    }

    let bytes = cursor.take(length, "domain")?;

    if !bytes.iter().copied().all(is_domain_byte) {
        return Err(DecodeError::InvalidDomainName);
    }

    let domain = str::from_utf8(bytes)
        .expect("validated ASCII bytes must be UTF-8")
        .to_owned();

    Ok(Address::Domain(domain))
}

const fn is_domain_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.' || byte == b'_'
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
        let mut array = [0_u8; LENGTH];

        array.copy_from_slice(bytes);

        Ok(array)
    }

    fn take(&mut self, length: usize, field: &'static str) -> Result<&'a [u8], DecodeError> {
        let remaining = self.input.len().saturating_sub(self.position);

        if remaining < length {
            return Err(DecodeError::UnexpectedEnd {
                field,
                needed: length,
                remaining,
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

    use super::{Address, Command, DecodeError, VERSION, decode_request};

    const USER_ID: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];

    #[test]
    fn decodes_domain_request_and_preserves_payload() {
        let mut input = Vec::new();

        input.push(VERSION);
        input.extend_from_slice(&USER_ID);
        input.push(2);
        input.extend_from_slice(&[0xAA, 0xBB]);
        input.push(Command::Tcp.as_bytes());
        input.extend_from_slice(&443_u16.to_be_bytes());
        input.push(0x02);
        input.push(11);
        input.extend_from_slice(b"example.com");
        input.extend_from_slice(b"payload");

        let decoded = decode_request(&input).expect("request should decode");

        assert_eq!(decoded.header().version(), VERSION);
        assert_eq!(decoded.header().user_id().as_bytes(), &USER_ID);
        assert_eq!(decoded.header().command(), Command::Tcp);

        let destination = decoded
            .header()
            .destination()
            .expect("TCP request should have a destination");

        assert_eq!(destination.port(), 443);
        assert_eq!(
            destination.address(),
            &Address::Domain("example.com".to_owned())
        );
        assert_eq!(decoded.payload(), b"payload");
    }

    #[test]
    fn decodes_ipv4_destination() {
        let mut input = request_prefix(Command::Tcp);

        input.extend_from_slice(&53_u16.to_be_bytes());
        input.push(0x01);
        input.extend_from_slice(&[1, 1, 1, 1]);

        let decoded = decode_request(&input).expect("request should decode");

        let destination = decoded
            .header()
            .destination()
            .expect("TCP request should have a destination");

        assert_eq!(destination.port(), 53);
        assert_eq!(
            destination.address(),
            &Address::Ipv4(Ipv4Addr::new(1, 1, 1, 1))
        );
    }

    #[test]
    fn decodes_ipv6_destination() {
        let address = "2001:db8::1"
            .parse::<Ipv6Addr>()
            .expect("test address should parse");

        let mut input = request_prefix(Command::Udp);

        input.extend_from_slice(&5353_u16.to_be_bytes());
        input.push(0x03);
        input.extend_from_slice(&address.octets());

        let decoded = decode_request(&input).expect("request should decode");

        let destination = decoded
            .header()
            .destination()
            .expect("UDP request should have a destination");

        assert_eq!(destination.port(), 5353);
        assert_eq!(destination.address(), &Address::Ipv6(address));
    }

    #[test]
    fn decodes_mux_without_destination() {
        let mut input = request_prefix(Command::Mux);
        input.extend_from_slice(b"mux payload");

        let decoded = decode_request(&input).expect("request should decode");

        assert_eq!(decoded.header().command(), Command::Mux);
        assert_eq!(decoded.header().destination(), None);
        assert_eq!(decoded.payload(), b"mux payload");
    }

    #[test]
    fn rejects_unknown_command() {
        let mut input = Vec::new();

        input.push(VERSION);
        input.extend_from_slice(&USER_ID);
        input.push(0);
        input.push(0xff);

        assert_eq!(
            decode_request(&input),
            Err(DecodeError::UnknownCommand(0xff))
        );
    }

    #[test]
    fn reports_truncated_user_id() {
        let input = [VERSION, 0x01, 0x02];

        assert_eq!(
            decode_request(&input),
            Err(DecodeError::UnexpectedEnd {
                field: "user ID",
                needed: 16,
                remaining: 2
            })
        );
    }

    fn request_prefix(command: Command) -> Vec<u8> {
        let mut input = Vec::new();

        input.push(VERSION);
        input.extend_from_slice(&USER_ID);
        input.push(0);
        input.push(command.as_bytes());

        input
    }
}
