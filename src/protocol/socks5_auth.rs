//! Bounded RFC 1928 method policy and RFC 1929 username/password codecs.
//!
//! Parsing borrows credential bytes and does not authenticate them. In
//! particular, selecting username/password when it is required never falls
//! back to no authentication. RFC 1929 carries credentials in cleartext; this
//! module provides no transport confidentiality.

use std::{error::Error, fmt};

use super::{
    socks5::{EncodeError, VERSION},
    vless::{Address, is_valid_domain_name},
};

const NO_AUTHENTICATION: u8 = 0x00;
const USERNAME_PASSWORD: u8 = 0x02;
const NO_ACCEPTABLE_METHODS: u8 = 0xff;
const AUTHENTICATION_VERSION: u8 = 0x01;
const IPV4: u8 = 0x01;
const DOMAIN: u8 = 0x03;
const IPV6: u8 = 0x04;

/// Maximum wire length of an RFC 1928 method offer.
pub const MAX_METHOD_OFFER_LEN: usize = 2 + u8::MAX as usize;
/// Maximum wire length of an RFC 1929 username/password request.
pub const MAX_USERNAME_PASSWORD_REQUEST_LEN: usize =
    1 + 1 + u8::MAX as usize + 1 + u8::MAX as usize;
/// Maximum wire length of a SOCKS5 CONNECT reply with a 255-byte domain address.
pub const MAX_CONNECT_REPLY_LEN: usize = 4 + 1 + u8::MAX as usize + 2;

/// A syntactically complete RFC 1928 method offer before local policy is applied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MethodOffer<'a> {
    methods: &'a [u8],
    consumed: usize,
    trailing: &'a [u8],
}

impl<'a> MethodOffer<'a> {
    /// Methods offered by the client.
    pub const fn methods(&self) -> &'a [u8] {
        self.methods
    }

    /// Number of bytes in the complete method offer.
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Bytes following the method offer, unchanged.
    pub const fn trailing(&self) -> &'a [u8] {
        self.trailing
    }
}

/// Authentication policy used to choose one method from an offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationPolicy {
    /// Select no authentication only when the client offered it.
    NoAuthentication,
    /// Select username/password only; never downgrade to no authentication.
    UsernamePasswordRequired,
}

/// Method selected for the RFC 1928 response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MethodSelection {
    /// No authentication (`0x00`).
    NoAuthentication,
    /// RFC 1929 username/password (`0x02`).
    UsernamePassword,
    /// No offered method satisfies policy (`0xff`).
    NoAcceptableMethods,
}

/// A malformed or incomplete method offer or RFC 1929 request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthDecodeError {
    /// The input ended before the named field was complete.
    IncompleteInput {
        /// Field currently being read.
        field: &'static str,
        /// Number of bytes needed for the field.
        needed: usize,
        /// Number of bytes available for the field.
        available: usize,
    },
    /// The RFC 1928 method offer did not use SOCKS version 5.
    InvalidSocksVersion(u8),
    /// The RFC 1928 method offer declared zero methods.
    InvalidMethodCount,
    /// RFC 1929 subnegotiation did not use version 1.
    InvalidAuthenticationVersion(u8),
    /// RFC 1929 requires a non-empty username.
    EmptyUsername,
    /// RFC 1929 requires a non-empty password.
    EmptyPassword,
}

impl fmt::Display for AuthDecodeError {
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
            Self::InvalidSocksVersion(version) => {
                write!(formatter, "unsupported SOCKS protocol version {version}")
            }
            Self::InvalidMethodCount => {
                formatter.write_str("SOCKS5 method offer must contain 1–255 methods")
            }
            Self::InvalidAuthenticationVersion(version) => {
                write!(
                    formatter,
                    "unsupported SOCKS5 authentication version {version}"
                )
            }
            Self::EmptyUsername => formatter.write_str("SOCKS5 username must not be empty"),
            Self::EmptyPassword => formatter.write_str("SOCKS5 password must not be empty"),
        }
    }
}

impl Error for AuthDecodeError {}

/// Parses one bounded RFC 1928 method offer.
///
/// A complete offer is returned even if it has no method acceptable to the
/// server; policy selection is performed separately by [`select_method`].
pub fn decode_method_offer(input: &[u8]) -> Result<MethodOffer<'_>, AuthDecodeError> {
    let mut cursor = Cursor::new(input);
    let version = cursor.read_u8("version")?;
    if version != VERSION {
        return Err(AuthDecodeError::InvalidSocksVersion(version));
    }
    let count = usize::from(cursor.read_u8("method count")?);
    if count == 0 {
        return Err(AuthDecodeError::InvalidMethodCount);
    }
    let methods = cursor.take(count, "method list")?;
    Ok(MethodOffer {
        methods,
        consumed: cursor.position,
        trailing: cursor.remaining(),
    })
}

/// Selects only the method permitted by the configured policy.
///
/// An offer containing both methods selects username/password in required-auth
/// mode, while a no-auth-only offer receives `NoAcceptableMethods`.
#[must_use]
pub fn select_method(offer: &MethodOffer<'_>, policy: AuthenticationPolicy) -> MethodSelection {
    match policy {
        AuthenticationPolicy::NoAuthentication if offer.methods.contains(&NO_AUTHENTICATION) => {
            MethodSelection::NoAuthentication
        }
        AuthenticationPolicy::UsernamePasswordRequired
            if offer.methods.contains(&USERNAME_PASSWORD) =>
        {
            MethodSelection::UsernamePassword
        }
        AuthenticationPolicy::NoAuthentication | AuthenticationPolicy::UsernamePasswordRequired => {
            MethodSelection::NoAcceptableMethods
        }
    }
}

/// Encodes the two-byte RFC 1928 method-selection response.
pub fn encode_method_selection(
    selection: MethodSelection,
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    const LENGTH: usize = 2;
    ensure_capacity(output, LENGTH)?;
    output[..LENGTH].copy_from_slice(&[
        VERSION,
        match selection {
            MethodSelection::NoAuthentication => NO_AUTHENTICATION,
            MethodSelection::UsernamePassword => USERNAME_PASSWORD,
            MethodSelection::NoAcceptableMethods => NO_ACCEPTABLE_METHODS,
        },
    ]);
    Ok(LENGTH)
}

/// Borrowed RFC 1929 username/password octets.
///
/// The request is only syntactically parsed, not authenticated. `Debug` always
/// redacts both credential values.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct UsernamePasswordRequest<'a> {
    username: &'a [u8],
    password: &'a [u8],
    consumed: usize,
    trailing: &'a [u8],
}

impl<'a> UsernamePasswordRequest<'a> {
    /// Borrowed username bytes.
    pub const fn username(&self) -> &'a [u8] {
        self.username
    }

    /// Borrowed password bytes.
    pub const fn password(&self) -> &'a [u8] {
        self.password
    }

    /// Number of bytes in the complete RFC 1929 request.
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Bytes following the request, unchanged.
    pub const fn trailing(&self) -> &'a [u8] {
        self.trailing
    }
}

impl fmt::Debug for UsernamePasswordRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UsernamePasswordRequest")
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .field("consumed", &self.consumed)
            .finish_non_exhaustive()
    }
}

/// Parses one bounded RFC 1929 username/password request.
///
/// Both fields must contain 1–255 octets. The fields are borrowed, and
/// coalesced bytes after the request are preserved. Credential verification is
/// deliberately outside this wire codec.
pub fn decode_username_password_request(
    input: &[u8],
) -> Result<UsernamePasswordRequest<'_>, AuthDecodeError> {
    let mut cursor = Cursor::new(input);
    let version = cursor.read_u8("authentication version")?;
    if version != AUTHENTICATION_VERSION {
        return Err(AuthDecodeError::InvalidAuthenticationVersion(version));
    }
    let username_length = usize::from(cursor.read_u8("username length")?);
    if username_length == 0 {
        return Err(AuthDecodeError::EmptyUsername);
    }
    let username = cursor.take(username_length, "username")?;
    let password_length = usize::from(cursor.read_u8("password length")?);
    if password_length == 0 {
        return Err(AuthDecodeError::EmptyPassword);
    }
    let password = cursor.take(password_length, "password")?;
    Ok(UsernamePasswordRequest {
        username,
        password,
        consumed: cursor.position,
        trailing: cursor.remaining(),
    })
}

/// RFC 1929 authentication outcome to encode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationResult {
    /// Credential verification succeeded (`STATUS=0`).
    Succeeded,
    /// Credential verification failed (`STATUS=1`).
    Failed,
}

/// Encodes the two-byte RFC 1929 authentication response.
pub fn encode_authentication_response(
    result: AuthenticationResult,
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    const LENGTH: usize = 2;
    ensure_capacity(output, LENGTH)?;
    output[..LENGTH].copy_from_slice(&[
        AUTHENTICATION_VERSION,
        match result {
            AuthenticationResult::Succeeded => 0,
            AuthenticationResult::Failed => 1,
        },
    ]);
    Ok(LENGTH)
}

/// RFC 1928 status for a TCP CONNECT response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ConnectReplyCode {
    /// Connection succeeded.
    Succeeded = 0x00,
    /// General server failure.
    GeneralFailure = 0x01,
    /// Connection not allowed by policy.
    ConnectionNotAllowed = 0x02,
    /// Network unreachable.
    NetworkUnreachable = 0x03,
    /// Destination host unreachable.
    HostUnreachable = 0x04,
    /// Destination refused the connection.
    ConnectionRefused = 0x05,
    /// TTL expired.
    TtlExpired = 0x06,
    /// Requested command is unsupported.
    CommandNotSupported = 0x07,
    /// Requested address type is unsupported.
    AddressTypeNotSupported = 0x08,
}

/// Encodes an RFC 1928 CONNECT response with a bound IPv4, domain, or IPv6 address.
///
/// This deliberately accepts a port of zero and does not use VLESS
/// [`super::vless::Destination`], whose destination validation requires a
/// non-zero port. RFC replies commonly use an unspecified endpoint on failure.
pub fn encode_connect_reply(
    code: ConnectReplyCode,
    bound_address: &Address,
    bound_port: u16,
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    let required = match bound_address {
        Address::Ipv4(_) => 10,
        Address::Ipv6(_) => 22,
        Address::Domain(domain) => {
            if !is_valid_domain_name(domain.as_bytes()) {
                return Err(EncodeError::InvalidDomainName);
            }
            4 + 1 + domain.len() + 2
        }
    };
    ensure_capacity(output, required)?;
    output[0] = VERSION;
    output[1] = code as u8;
    output[2] = 0;
    match bound_address {
        Address::Ipv4(address) => {
            output[3] = IPV4;
            output[4..8].copy_from_slice(&address.octets());
            output[8..10].copy_from_slice(&bound_port.to_be_bytes());
        }
        Address::Domain(domain) => {
            output[3] = DOMAIN;
            output[4] = domain.len() as u8;
            output[5..5 + domain.len()].copy_from_slice(domain.as_bytes());
            let port_start = 5 + domain.len();
            output[port_start..port_start + 2].copy_from_slice(&bound_port.to_be_bytes());
        }
        Address::Ipv6(address) => {
            output[3] = IPV6;
            output[4..20].copy_from_slice(&address.octets());
            output[20..22].copy_from_slice(&bound_port.to_be_bytes());
        }
    }
    Ok(required)
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

    fn read_u8(&mut self, field: &'static str) -> Result<u8, AuthDecodeError> {
        Ok(self.take(1, field)?[0])
    }

    fn take(&mut self, length: usize, field: &'static str) -> Result<&'a [u8], AuthDecodeError> {
        let available = self.input.len().saturating_sub(self.position);
        if available < length {
            return Err(AuthDecodeError::IncompleteInput {
                field,
                needed: length,
                available,
            });
        }
        let start = self.position;
        self.position += length;
        Ok(&self.input[start..self.position])
    }

    fn remaining(&self) -> &'a [u8] {
        &self.input[self.position..]
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::{
        AuthDecodeError, AuthenticationPolicy, AuthenticationResult, ConnectReplyCode,
        MAX_CONNECT_REPLY_LEN, MAX_METHOD_OFFER_LEN, MAX_USERNAME_PASSWORD_REQUEST_LEN,
        MethodSelection, decode_method_offer, decode_username_password_request,
        encode_authentication_response, encode_connect_reply, encode_method_selection,
        select_method,
    };
    use crate::protocol::{socks5::EncodeError, vless::Address};

    #[test]
    fn required_auth_does_not_downgrade_when_no_auth_is_offered() {
        let both = decode_method_offer(&[5, 2, 0, 2]).expect("method offer");
        assert_eq!(
            select_method(&both, AuthenticationPolicy::UsernamePasswordRequired),
            MethodSelection::UsernamePassword
        );
        assert_eq!(
            select_method(&both, AuthenticationPolicy::NoAuthentication),
            MethodSelection::NoAuthentication
        );
        let no_auth = decode_method_offer(&[5, 1, 0]).expect("method offer");
        assert_eq!(
            select_method(&no_auth, AuthenticationPolicy::UsernamePasswordRequired),
            MethodSelection::NoAcceptableMethods
        );
        let password_only = decode_method_offer(&[5, 1, 2]).expect("method offer");
        assert_eq!(
            select_method(&password_only, AuthenticationPolicy::NoAuthentication),
            MethodSelection::NoAcceptableMethods
        );
    }

    #[test]
    fn method_offer_preserves_coalesced_bytes_and_rejects_every_short_prefix() {
        let complete = [5, 2, 0, 2, 0xaa];
        let offer = decode_method_offer(&complete).expect("complete offer");
        assert_eq!(offer.methods(), &[0, 2]);
        assert_eq!(offer.consumed(), 4);
        assert_eq!(offer.trailing(), &[0xaa]);
        assert!(offer.consumed() <= MAX_METHOD_OFFER_LEN);
        for end in 0..4 {
            assert!(matches!(
                decode_method_offer(&complete[..end]),
                Err(AuthDecodeError::IncompleteInput { .. })
            ));
        }
        assert_eq!(
            decode_method_offer(&[4, 1, 0]),
            Err(AuthDecodeError::InvalidSocksVersion(4))
        );
        assert_eq!(
            decode_method_offer(&[5, 0]),
            Err(AuthDecodeError::InvalidMethodCount)
        );
    }

    #[test]
    fn method_selection_encoder_is_bounded_and_uses_exact_values() {
        let cases = [
            (MethodSelection::NoAuthentication, [5, 0]),
            (MethodSelection::UsernamePassword, [5, 2]),
            (MethodSelection::NoAcceptableMethods, [5, 0xff]),
        ];
        for (selection, expected) in cases {
            let mut output = [0xa5; 3];
            assert_eq!(encode_method_selection(selection, &mut output), Ok(2));
            assert_eq!(&output[..2], &expected);
            assert_eq!(output[2], 0xa5);
        }
        let mut output = [0xa5; 2];
        assert_eq!(
            encode_method_selection(MethodSelection::UsernamePassword, &mut output[..1]),
            Err(EncodeError::OutputTooSmall {
                required: 2,
                available: 1
            })
        );
        assert_eq!(output, [0xa5; 2]);
    }

    #[test]
    fn username_password_parsing_preserves_payload_and_redacts_debug() {
        let username = b"synthetic-user";
        let password = b"sentinel-secret";
        let mut input = vec![1, username.len() as u8];
        input.extend_from_slice(username);
        input.push(password.len() as u8);
        input.extend_from_slice(password);
        input.push(0xaa);
        let request = decode_username_password_request(&input).expect("credentials parse");
        assert_eq!(request.username(), username);
        assert_eq!(request.password(), password);
        assert_eq!(request.consumed(), input.len() - 1);
        assert_eq!(request.trailing(), &[0xaa]);
        let debug = format!("{request:?}");
        assert!(!debug.contains("synthetic-user"));
        assert!(!debug.contains("sentinel-secret"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn every_truncated_username_password_prefix_is_incomplete() {
        let complete = [1, 2, b'u', b'n', 2, b'p', b'w'];
        for end in 0..complete.len() {
            assert!(
                matches!(
                    decode_username_password_request(&complete[..end]),
                    Err(AuthDecodeError::IncompleteInput { .. })
                ),
                "credential prefix length {end} must be incomplete"
            );
        }
        assert!(decode_username_password_request(&complete).is_ok());
    }

    #[test]
    fn username_password_rejects_wrong_version_and_empty_fields() {
        assert_eq!(
            decode_username_password_request(&[2]),
            Err(AuthDecodeError::InvalidAuthenticationVersion(2))
        );
        assert_eq!(
            decode_username_password_request(&[1, 0]),
            Err(AuthDecodeError::EmptyUsername)
        );
        assert_eq!(
            decode_username_password_request(&[1, 1, b'u', 0]),
            Err(AuthDecodeError::EmptyPassword)
        );
    }

    #[test]
    fn username_password_accepts_the_rfc_maximum_field_lengths() {
        let mut input = vec![1, u8::MAX];
        input.extend(std::iter::repeat_n(b'u', usize::from(u8::MAX)));
        input.push(u8::MAX);
        input.extend(std::iter::repeat_n(b'p', usize::from(u8::MAX)));
        input.push(0xaa);
        let request = decode_username_password_request(&input).expect("maximum credentials");
        assert_eq!(request.username().len(), usize::from(u8::MAX));
        assert_eq!(request.password().len(), usize::from(u8::MAX));
        assert_eq!(request.consumed(), MAX_USERNAME_PASSWORD_REQUEST_LEN);
        assert_eq!(request.trailing(), &[0xaa]);
    }

    #[test]
    fn authentication_responses_have_exact_wire_values_and_output_bounds() {
        for (result, expected) in [
            (AuthenticationResult::Succeeded, [1, 0]),
            (AuthenticationResult::Failed, [1, 1]),
        ] {
            let mut output = [0xa5; 3];
            assert_eq!(encode_authentication_response(result, &mut output), Ok(2));
            assert_eq!(&output[..2], &expected);
            assert_eq!(output[2], 0xa5);
        }
        for available in 0..2 {
            let mut output = [0xa5; 2];
            assert_eq!(
                encode_authentication_response(
                    AuthenticationResult::Succeeded,
                    &mut output[..available]
                ),
                Err(EncodeError::OutputTooSmall {
                    required: 2,
                    available
                })
            );
            assert_eq!(output, [0xa5; 2]);
        }
    }

    #[test]
    fn connect_replies_encode_ipv4_domain_ipv6_and_zero_port() {
        let cases = [
            (
                ConnectReplyCode::Succeeded,
                Address::Ipv4(Ipv4Addr::LOCALHOST),
                1080,
                &[5, 0, 0, 1, 127, 0, 0, 1, 4, 56][..],
            ),
            (
                ConnectReplyCode::NetworkUnreachable,
                Address::Domain("proxy.example".to_owned()),
                0,
                &[
                    5, 3, 0, 3, 13, b'p', b'r', b'o', b'x', b'y', b'.', b'e', b'x', b'a', b'm',
                    b'p', b'l', b'e', 0, 0,
                ][..],
            ),
            (
                ConnectReplyCode::ConnectionRefused,
                Address::Ipv6(Ipv6Addr::LOCALHOST),
                443,
                &[
                    5, 5, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187,
                ][..],
            ),
        ];
        for (code, address, port, expected) in cases {
            let mut output = [0xa5; MAX_CONNECT_REPLY_LEN];
            let written = encode_connect_reply(code, &address, port, &mut output)
                .expect("reply should encode");
            assert_eq!(&output[..written], expected);
            assert!(output[written..].iter().all(|byte| *byte == 0xa5));
        }
    }

    #[test]
    fn connect_reply_output_bounds_and_invalid_domain_do_not_mutate_output() {
        let address = Address::Ipv6(Ipv6Addr::LOCALHOST);
        for available in 0..22 {
            let mut output = [0xa5; MAX_CONNECT_REPLY_LEN];
            assert_eq!(
                encode_connect_reply(
                    ConnectReplyCode::Succeeded,
                    &address,
                    0,
                    &mut output[..available]
                ),
                Err(EncodeError::OutputTooSmall {
                    required: 22,
                    available
                })
            );
            assert!(output.iter().all(|byte| *byte == 0xa5));
        }
        let invalid = Address::Domain("bad/name".to_owned());
        let mut output = [0xa5; MAX_CONNECT_REPLY_LEN];
        assert_eq!(
            encode_connect_reply(ConnectReplyCode::GeneralFailure, &invalid, 0, &mut output),
            Err(EncodeError::InvalidDomainName)
        );
        assert!(output.iter().all(|byte| *byte == 0xa5));
    }
}
