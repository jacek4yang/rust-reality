//! Bounded HTTP/1.1 forward-proxy request and Basic-auth codecs.
//!
//! This module parses headers only; it does not open sockets or forward traffic.
//! Requests are capped by byte and header-count limits, ambiguous framing is
//! rejected, and proxy credentials are excluded from the safe forwarding-header
//! iterator. Basic credentials are zeroized on drop and never included in debug
//! output. HTTP Basic and RFC 1929 credentials are not confidential without a
//! protected transport.

use std::{
    error::Error,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    config::SecretString,
    protocol::vless::{Address, Destination, is_valid_domain_name},
};

/// Maximum bytes consumed by one HTTP request header block.
pub const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
/// Maximum number of fields in one request header block.
pub const MAX_HTTP_HEADER_COUNT: usize = 64;
/// Maximum field-name length in bytes.
pub const MAX_HTTP_HEADER_NAME_BYTES: usize = 256;
/// Maximum field-value length in bytes.
pub const MAX_HTTP_HEADER_VALUE_BYTES: usize = 8 * 1024;
/// Maximum `Proxy-Authorization` field value passed to the Basic decoder.
pub const MAX_BASIC_AUTH_VALUE_BYTES: usize = 4 * 1024;

const PROXY_AUTH_REQUIRED_RESPONSE: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"local-proxy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const CONNECT_ESTABLISHED_RESPONSE: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

/// Request-body framing parsed from the HTTP message headers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyFraming {
    /// No request body is framed by the headers.
    None,
    /// Exactly this many octets follow the header block.
    ContentLength(u64),
    /// The request uses the single supported transfer coding, `chunked`.
    Chunked,
}

/// Whether a parsed request uses CONNECT tunneling or HTTP forwarding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestKind {
    /// CONNECT with an authority-form target.
    Connect,
    /// A non-CONNECT request with an absolute `http://` target.
    Forward,
}

/// A decoded HTTP header safe to consider for forwarding.
///
/// The request's `forward_headers()` method removes proxy credentials and
/// hop-by-hop fields before yielding these values.
pub struct ForwardHeader<'a> {
    name: &'a str,
    value: &'a [u8],
}

impl<'a> ForwardHeader<'a> {
    /// Original field name.
    pub const fn name(&self) -> &'a str {
        self.name
    }

    /// Original field value bytes.
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }
}

/// One syntactically complete, bounded HTTP/1.1 proxy request header block.
pub struct HttpProxyRequest<'a> {
    kind: RequestKind,
    method: &'a str,
    target: &'a str,
    destination: Destination,
    headers: Vec<ForwardHeader<'a>>,
    proxy_authorization: Option<&'a [u8]>,
    consumed: usize,
    body_framing: BodyFraming,
}

impl<'a> HttpProxyRequest<'a> {
    /// Request kind: CONNECT or absolute-form forwarding.
    pub const fn kind(&self) -> RequestKind {
        self.kind
    }

    /// HTTP method token.
    pub const fn method(&self) -> &'a str {
        self.method
    }

    /// Original request target. Debug output intentionally omits this value.
    pub const fn target(&self) -> &'a str {
        self.target
    }

    /// Canonical VLESS destination derived from the request target.
    pub const fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Number of bytes consumed by the complete request headers.
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Request-body framing; body bytes begin at `consumed()`.
    pub const fn body_framing(&self) -> BodyFraming {
        self.body_framing
    }

    /// Proxy credentials from the single `Proxy-Authorization` header, if any.
    ///
    /// This value must be consumed only by the proxy authenticator and must not
    /// be copied to an origin request.
    pub const fn proxy_authorization(&self) -> Option<&'a [u8]> {
        self.proxy_authorization
    }

    /// Headers suitable to consider for forwarding after hop-by-hop filtering.
    ///
    /// The iterator never yields `Proxy-Authorization`, `Proxy-Authenticate`,
    /// or any field nominated by `Connection`. Transfer framing is exposed
    /// separately through [`Self::body_framing`] and must be reconstructed by a
    /// forwarding implementation.
    pub fn forward_headers(&self) -> impl Iterator<Item = &ForwardHeader<'a>> {
        self.headers.iter().filter(|header| {
            !is_hop_by_hop(header.name) && !is_connection_nominated(header.name, &self.headers)
        })
    }
}

impl fmt::Debug for HttpProxyRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpProxyRequest")
            .field("kind", &self.kind)
            .field("method", &self.method)
            .field("destination", &self.destination)
            .field("header_count", &self.headers.len())
            .field(
                "proxy_authorization_present",
                &self.proxy_authorization.is_some(),
            )
            .field("body_framing", &self.body_framing)
            .field("consumed", &self.consumed)
            .finish()
    }
}

/// Invalid, incomplete, or ambiguous HTTP proxy request headers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpDecodeError {
    /// More bytes are needed to finish the request header block.
    IncompleteHeaders,
    /// The byte limit or a per-field length limit was exceeded.
    HeaderTooLarge,
    /// More than [`MAX_HTTP_HEADER_COUNT`] fields were supplied.
    TooManyHeaders,
    /// The request or one of its fields has invalid syntax.
    InvalidSyntax,
    /// Only HTTP/1.1 is accepted by this codec.
    UnsupportedVersion(u8),
    /// The request target is neither CONNECT authority-form nor absolute-form.
    UnsupportedTargetForm,
    /// Only the `http` absolute-form scheme is supported for forwarding.
    UnsupportedScheme,
    /// The authority is invalid or cannot be represented as a canonical destination.
    InvalidAuthority,
    /// An HTTP/1.1 Host field is missing.
    MissingHost,
    /// More than one Host field was supplied.
    DuplicateHost,
    /// The Host field and request-target authority disagree.
    HostMismatch,
    /// More than one Content-Length field was supplied.
    DuplicateContentLength,
    /// Content-Length is not a single unsigned decimal integer.
    InvalidContentLength,
    /// Content-Length and Transfer-Encoding appeared together.
    ConflictingBodyFraming,
    /// CONNECT requests cannot carry HTTP message-body framing.
    ConnectBodyFraming,
    /// More than one Transfer-Encoding field was supplied.
    DuplicateTransferEncoding,
    /// Transfer-Encoding is not exactly `chunked`.
    UnsupportedTransferEncoding,
    /// A Connection field contains an empty or invalid token.
    InvalidConnectionHeader,
    /// More than one Proxy-Authorization field was supplied.
    DuplicateProxyAuthorization,
    /// A Trailer field appeared without chunked transfer coding.
    TrailerWithoutChunked,
    /// A field value contains a forbidden control byte.
    InvalidHeaderValue,
}

impl fmt::Display for HttpDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::IncompleteHeaders => "incomplete HTTP request headers",
            Self::HeaderTooLarge => "HTTP request headers exceed the configured bound",
            Self::TooManyHeaders => "HTTP request has too many headers",
            Self::InvalidSyntax => "invalid HTTP request syntax",
            Self::UnsupportedVersion(_) => "unsupported HTTP version",
            Self::UnsupportedTargetForm => "unsupported HTTP proxy request-target form",
            Self::UnsupportedScheme => "unsupported HTTP proxy request-target scheme",
            Self::InvalidAuthority => "invalid HTTP proxy authority",
            Self::MissingHost => "HTTP/1.1 request is missing its Host field",
            Self::DuplicateHost => "HTTP request contains multiple Host fields",
            Self::HostMismatch => "HTTP Host field does not match its request target",
            Self::DuplicateContentLength => "HTTP request contains multiple Content-Length fields",
            Self::InvalidContentLength => "invalid HTTP Content-Length field",
            Self::ConflictingBodyFraming => {
                "HTTP request contains both Content-Length and Transfer-Encoding"
            }
            Self::ConnectBodyFraming => "HTTP CONNECT requests cannot carry message-body framing",
            Self::DuplicateTransferEncoding => {
                "HTTP request contains multiple Transfer-Encoding fields"
            }
            Self::UnsupportedTransferEncoding => "unsupported HTTP Transfer-Encoding",
            Self::InvalidConnectionHeader => "invalid HTTP Connection field",
            Self::DuplicateProxyAuthorization => {
                "HTTP request contains multiple Proxy-Authorization fields"
            }
            Self::TrailerWithoutChunked => "HTTP Trailer field requires chunked transfer coding",
            Self::InvalidHeaderValue => "HTTP header value contains a forbidden control byte",
        };
        formatter.write_str(message)
    }
}

impl Error for HttpDecodeError {}

/// Parses one bounded HTTP/1.1 proxy request header block.
///
/// The parser accepts CONNECT authority-form and non-CONNECT absolute-form
/// `http://` targets. The returned `consumed()` length ends immediately after
/// `CRLF CRLF`; any body or next request bytes stay in the caller's input. It
/// rejects duplicate Host, Content-Length, Transfer-Encoding, or
/// Proxy-Authorization fields and rejects Content-Length/Transfer-Encoding
/// ambiguity. Only a single `chunked` transfer coding is accepted. CONNECT
/// requests with Content-Length or Transfer-Encoding are rejected so the tunnel
/// boundary cannot be confused with an HTTP message body.
pub fn decode_http_proxy_request(input: &[u8]) -> Result<HttpProxyRequest<'_>, HttpDecodeError> {
    let bounded_input = &input[..input.len().min(MAX_HTTP_HEADER_BYTES)];
    let mut header_storage = [httparse::EMPTY_HEADER; MAX_HTTP_HEADER_COUNT];
    let (method, target, version, consumed, headers) = {
        let mut request = httparse::Request::new(&mut header_storage);
        let consumed = match request.parse(bounded_input) {
            Ok(httparse::Status::Complete(consumed)) => consumed,
            Ok(httparse::Status::Partial) => {
                return if input.len() >= MAX_HTTP_HEADER_BYTES {
                    Err(HttpDecodeError::HeaderTooLarge)
                } else {
                    Err(HttpDecodeError::IncompleteHeaders)
                };
            }
            Err(httparse::Error::TooManyHeaders) => return Err(HttpDecodeError::TooManyHeaders),
            Err(_) => return Err(HttpDecodeError::InvalidSyntax),
        };
        let method = request.method.ok_or(HttpDecodeError::InvalidSyntax)?;
        let target = request.path.ok_or(HttpDecodeError::InvalidSyntax)?;
        let version = request.version.ok_or(HttpDecodeError::InvalidSyntax)?;
        let headers = request
            .headers
            .iter()
            .map(|header| ForwardHeader {
                name: header.name,
                value: header.value,
            })
            .collect::<Vec<_>>();
        (method, target, version, consumed, headers)
    };

    if consumed > MAX_HTTP_HEADER_BYTES {
        return Err(HttpDecodeError::HeaderTooLarge);
    }
    if version != 1 {
        return Err(HttpDecodeError::UnsupportedVersion(version));
    }
    if method.is_empty() || target.is_empty() || !target.is_ascii() {
        return Err(HttpDecodeError::InvalidSyntax);
    }

    let mut host_value = None;
    let mut content_length = None;
    let mut saw_content_length = false;
    let mut transfer_encoding = false;
    let mut saw_transfer_encoding = false;
    let mut saw_trailer = false;
    let mut proxy_authorization = None;

    for header in &headers {
        if header.name.len() > MAX_HTTP_HEADER_NAME_BYTES
            || header.value.len() > MAX_HTTP_HEADER_VALUE_BYTES
        {
            return Err(HttpDecodeError::HeaderTooLarge);
        }
        if header
            .value
            .iter()
            .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
        {
            return Err(HttpDecodeError::InvalidHeaderValue);
        }

        if header.name.eq_ignore_ascii_case("host") {
            if host_value.replace(header.value).is_some() {
                return Err(HttpDecodeError::DuplicateHost);
            }
        } else if header.name.eq_ignore_ascii_case("content-length") {
            if saw_content_length {
                return Err(HttpDecodeError::DuplicateContentLength);
            }
            saw_content_length = true;
            content_length = Some(parse_content_length(header.value)?);
        } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if saw_transfer_encoding {
                return Err(HttpDecodeError::DuplicateTransferEncoding);
            }
            saw_transfer_encoding = true;
            if !trim_ows(header.value).eq_ignore_ascii_case(b"chunked") {
                return Err(HttpDecodeError::UnsupportedTransferEncoding);
            }
            transfer_encoding = true;
        } else if header.name.eq_ignore_ascii_case("proxy-authorization") {
            if header.value.len() > MAX_BASIC_AUTH_VALUE_BYTES {
                return Err(HttpDecodeError::HeaderTooLarge);
            }
            if proxy_authorization.replace(header.value).is_some() {
                return Err(HttpDecodeError::DuplicateProxyAuthorization);
            }
        } else if header.name.eq_ignore_ascii_case("connection") {
            validate_connection_tokens(header.value)?;
        } else if header.name.eq_ignore_ascii_case("trailer") {
            saw_trailer = true;
        }
    }

    let host_value = host_value.ok_or(HttpDecodeError::MissingHost)?;
    if saw_content_length && saw_transfer_encoding {
        return Err(HttpDecodeError::ConflictingBodyFraming);
    }
    if saw_trailer && !saw_transfer_encoding {
        return Err(HttpDecodeError::TrailerWithoutChunked);
    }

    let (kind, destination, host_default_port) = if method == "CONNECT" {
        if saw_content_length || saw_transfer_encoding {
            return Err(HttpDecodeError::ConnectBodyFraming);
        }
        (RequestKind::Connect, parse_authority(target, None)?, None)
    } else {
        (
            RequestKind::Forward,
            parse_absolute_http_target(target)?,
            Some(80),
        )
    };
    let host_text =
        std::str::from_utf8(host_value).map_err(|_| HttpDecodeError::InvalidAuthority)?;
    let host_destination = parse_authority(host_text, host_default_port)?;
    if !same_authority(&destination, &host_destination) {
        return Err(HttpDecodeError::HostMismatch);
    }

    let body_framing = if transfer_encoding {
        BodyFraming::Chunked
    } else if let Some(length) = content_length {
        BodyFraming::ContentLength(length)
    } else {
        BodyFraming::None
    };

    Ok(HttpProxyRequest {
        kind,
        method,
        target,
        destination,
        headers,
        proxy_authorization,
        consumed,
        body_framing,
    })
}

fn parse_absolute_http_target(target: &str) -> Result<Destination, HttpDecodeError> {
    let (scheme, remainder) = target
        .split_once("://")
        .ok_or(HttpDecodeError::UnsupportedTargetForm)?;
    if !scheme.eq_ignore_ascii_case("http") {
        return Err(HttpDecodeError::UnsupportedScheme);
    }
    if remainder.contains('#') {
        return Err(HttpDecodeError::UnsupportedTargetForm);
    }
    let authority_end = remainder.find(['/', '?']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    parse_authority(authority, Some(80))
}

fn parse_authority(
    authority: &str,
    default_port: Option<u16>,
) -> Result<Destination, HttpDecodeError> {
    if authority.is_empty() || !authority.is_ascii() || authority.contains('@') {
        return Err(HttpDecodeError::InvalidAuthority);
    }

    let (address, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let close = bracketed
            .find(']')
            .ok_or(HttpDecodeError::InvalidAuthority)?;
        let host = &bracketed[..close];
        let suffix = &bracketed[close + 1..];
        let address = Address::Ipv6(
            host.parse::<Ipv6Addr>()
                .map_err(|_| HttpDecodeError::InvalidAuthority)?,
        );
        let port = match suffix.strip_prefix(':') {
            Some(port) => parse_port(port)?,
            None if suffix.is_empty() => default_port.ok_or(HttpDecodeError::InvalidAuthority)?,
            None => return Err(HttpDecodeError::InvalidAuthority),
        };
        (address, port)
    } else {
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, parse_port(port)?),
            Some(_) => return Err(HttpDecodeError::InvalidAuthority),
            None => (
                authority,
                default_port.ok_or(HttpDecodeError::InvalidAuthority)?,
            ),
        };
        if host.is_empty() {
            return Err(HttpDecodeError::InvalidAuthority);
        }
        let address = if let Ok(address) = host.parse::<Ipv4Addr>() {
            Address::Ipv4(address)
        } else if is_valid_domain_name(host.as_bytes()) {
            Address::Domain(host.to_owned())
        } else {
            return Err(HttpDecodeError::InvalidAuthority);
        };
        (address, port)
    };

    if port == 0 {
        return Err(HttpDecodeError::InvalidAuthority);
    }
    Ok(Destination::new(address, port))
}

fn parse_port(port: &str) -> Result<u16, HttpDecodeError> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HttpDecodeError::InvalidAuthority);
    }
    port.parse::<u16>()
        .map_err(|_| HttpDecodeError::InvalidAuthority)
}

fn same_authority(left: &Destination, right: &Destination) -> bool {
    if left.port() != right.port() {
        return false;
    }
    match (left.address(), right.address()) {
        (Address::Ipv4(left), Address::Ipv4(right)) => left == right,
        (Address::Ipv6(left), Address::Ipv6(right)) => left == right,
        (Address::Domain(left), Address::Domain(right)) => left.eq_ignore_ascii_case(right),
        _ => false,
    }
}

fn parse_content_length(value: &[u8]) -> Result<u64, HttpDecodeError> {
    let value = trim_ows(value);
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(HttpDecodeError::InvalidContentLength);
    }
    let text = std::str::from_utf8(value).map_err(|_| HttpDecodeError::InvalidContentLength)?;
    text.parse::<u64>()
        .map_err(|_| HttpDecodeError::InvalidContentLength)
}

fn validate_connection_tokens(value: &[u8]) -> Result<(), HttpDecodeError> {
    let mut count = 0;
    for token in value.split(|byte| *byte == b',') {
        let token = trim_ows(token);
        if token.is_empty() || !token.iter().copied().all(is_token_byte) {
            return Err(HttpDecodeError::InvalidConnectionHeader);
        }
        count += 1;
    }
    if count == 0 {
        return Err(HttpDecodeError::InvalidConnectionHeader);
    }
    Ok(())
}

fn is_connection_nominated(name: &str, headers: &[ForwardHeader<'_>]) -> bool {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("connection"))
        .flat_map(|header| header.value.split(|byte| *byte == b','))
        .map(trim_ows)
        .any(|token| token.eq_ignore_ascii_case(name.as_bytes()))
}

fn is_hop_by_hop(name: &str) -> bool {
    [
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "transfer-encoding",
        "upgrade",
    ]
    .iter()
    .any(|hop| name.eq_ignore_ascii_case(hop))
}

fn trim_ows(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| *byte != b' ' && *byte != b'\t')
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| *byte != b' ' && *byte != b'\t')
        .map_or(start, |position| position + 1);
    &value[start..end]
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Bounded Basic credentials held in zeroizing, debug-redacted strings.
pub struct BasicCredentials {
    username: SecretString,
    password: SecretString,
}

impl BasicCredentials {
    /// Explicitly exposes the username for credential lookup.
    pub fn username(&self) -> &str {
        self.username.expose()
    }

    /// Explicitly exposes the password for credential verification.
    pub fn password(&self) -> &str {
        self.password.expose()
    }
}

impl fmt::Debug for BasicCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BasicCredentials")
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Why a Basic `Proxy-Authorization` field could not be decoded safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpAuthError {
    /// The encoded field exceeded the configured limit.
    TooLong,
    /// The field does not have the expected scheme-and-token form.
    InvalidHeader,
    /// The scheme is not Basic.
    UnsupportedScheme,
    /// The token is not valid standard Base64.
    InvalidBase64,
    /// The decoded bytes do not contain a username/password separator.
    MissingSeparator,
    /// The Basic username is empty.
    EmptyUsername,
    /// The Basic password is empty.
    EmptyPassword,
    /// A decoded credential is not valid UTF-8.
    InvalidUtf8,
}

impl fmt::Display for HttpAuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::TooLong => "Basic proxy credentials exceed the configured bound",
            Self::InvalidHeader => "invalid Basic Proxy-Authorization field",
            Self::UnsupportedScheme => "unsupported Proxy-Authorization scheme",
            Self::InvalidBase64 => "invalid Basic proxy credential encoding",
            Self::MissingSeparator => "Basic credentials lack a username/password separator",
            Self::EmptyUsername => "Basic proxy username must not be empty",
            Self::EmptyPassword => "Basic proxy password must not be empty",
            Self::InvalidUtf8 => "Basic proxy credentials must be UTF-8",
        };
        formatter.write_str(message)
    }
}

impl Error for HttpAuthError {}

/// Parses a bounded HTTP Basic `Proxy-Authorization` field value.
///
/// The decoded pair is split at the first colon, so colons remain allowed in
/// passwords. The username and password must be non-empty UTF-8. Intermediate
/// decoded buffers are zeroized even if parsing fails.
pub fn decode_basic_credentials(value: &[u8]) -> Result<BasicCredentials, HttpAuthError> {
    if value.len() > MAX_BASIC_AUTH_VALUE_BYTES {
        return Err(HttpAuthError::TooLong);
    }
    let separator = value
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or(HttpAuthError::InvalidHeader)?;
    let scheme = &value[..separator];
    if !scheme.eq_ignore_ascii_case(b"basic") {
        return Err(HttpAuthError::UnsupportedScheme);
    }
    let token = &value[separator + 1..];
    if token.is_empty() || token.iter().any(u8::is_ascii_whitespace) {
        return Err(HttpAuthError::InvalidHeader);
    }
    let mut decoded = Zeroizing::new(Vec::new());
    STANDARD
        .decode_vec(token, &mut decoded)
        .map_err(|_| HttpAuthError::InvalidBase64)?;
    let colon = decoded
        .iter()
        .position(|byte| *byte == b':')
        .ok_or(HttpAuthError::MissingSeparator)?;
    if colon == 0 {
        return Err(HttpAuthError::EmptyUsername);
    }
    if colon + 1 == decoded.len() {
        return Err(HttpAuthError::EmptyPassword);
    }
    let password = Zeroizing::new(decoded.split_off(colon + 1));
    decoded.truncate(colon);
    let username = secret_from_zeroizing(decoded)?;
    let password = secret_from_zeroizing(password)?;
    Ok(BasicCredentials { username, password })
}

fn secret_from_zeroizing(mut bytes: Zeroizing<Vec<u8>>) -> Result<SecretString, HttpAuthError> {
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(value) => Ok(SecretString::new(value)),
        Err(error) => {
            let mut invalid_bytes = error.into_bytes();
            invalid_bytes.zeroize();
            Err(HttpAuthError::InvalidUtf8)
        }
    }
}

/// HTTP response encoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpEncodeError {
    /// The caller-provided output buffer is too small and remains unchanged.
    OutputTooSmall {
        /// Required output size.
        required: usize,
        /// Available output size.
        available: usize,
    },
}

impl fmt::Display for HttpEncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputTooSmall {
                required,
                available,
            } => write!(
                formatter,
                "HTTP response buffer needs {required} bytes, has {available}"
            ),
        }
    }
}

impl Error for HttpEncodeError {}

/// Encodes a fixed Basic challenge that closes an unauthenticated connection.
pub fn encode_proxy_auth_required_response(output: &mut [u8]) -> Result<usize, HttpEncodeError> {
    copy_fixed_response(PROXY_AUTH_REQUIRED_RESPONSE, output)
}

/// Encodes the fixed response to send only after a CONNECT outbound is ready.
pub fn encode_connect_established_response(output: &mut [u8]) -> Result<usize, HttpEncodeError> {
    copy_fixed_response(CONNECT_ESTABLISHED_RESPONSE, output)
}

fn copy_fixed_response(response: &[u8], output: &mut [u8]) -> Result<usize, HttpEncodeError> {
    if output.len() < response.len() {
        return Err(HttpEncodeError::OutputTooSmall {
            required: response.len(),
            available: output.len(),
        });
    }
    output[..response.len()].copy_from_slice(response);
    Ok(response.len())
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    use super::{
        BodyFraming, HttpAuthError, HttpDecodeError, HttpEncodeError, MAX_BASIC_AUTH_VALUE_BYTES,
        MAX_HTTP_HEADER_BYTES, MAX_HTTP_HEADER_COUNT, RequestKind, decode_basic_credentials,
        decode_http_proxy_request, encode_connect_established_response,
        encode_proxy_auth_required_response,
    };
    use crate::protocol::vless::{Address, Destination};

    fn parse(input: &[u8]) -> Result<super::HttpProxyRequest<'_>, HttpDecodeError> {
        decode_http_proxy_request(input)
    }

    fn auth_header(username: &[u8], password: &[u8]) -> Vec<u8> {
        let mut pair = Vec::with_capacity(username.len() + password.len() + 1);
        pair.extend_from_slice(username);
        pair.push(b':');
        pair.extend_from_slice(password);
        format!("Basic {}", STANDARD.encode(pair)).into_bytes()
    }

    fn assert_auth_error(value: &[u8], expected: HttpAuthError) {
        match decode_basic_credentials(value) {
            Err(actual) => assert_eq!(actual, expected),
            Ok(_) => panic!("invalid Basic credentials unexpectedly decoded"),
        }
    }

    #[test]
    fn connect_authority_targets_accept_domain_ipv4_and_bracketed_ipv6() {
        let requests = [
            (
                b"CONNECT Example.COM:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".as_slice(),
                Destination::new(Address::Domain("Example.COM".to_owned()), 443),
            ),
            (
                b"CONNECT 192.0.2.7:443 HTTP/1.1\r\nHost: 192.0.2.7:443\r\n\r\n".as_slice(),
                Destination::new(Address::Ipv4("192.0.2.7".parse().expect("IPv4")), 443),
            ),
            (
                b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\n\r\n"
                    .as_slice(),
                Destination::new(Address::Ipv6("2001:db8::1".parse().expect("IPv6")), 8443),
            ),
        ];
        for (input, destination) in requests {
            let request = parse(input).expect("CONNECT request");
            assert_eq!(request.kind(), RequestKind::Connect);
            assert_eq!(request.method(), "CONNECT");
            assert_eq!(request.destination(), &destination);
            assert_eq!(request.body_framing(), BodyFraming::None);
            assert_eq!(request.consumed(), input.len());
        }
    }

    #[test]
    fn absolute_form_forwarding_preserves_body_boundary_and_filters_secrets_and_hops() {
        let input = b"POST http://example.com:8080/path?q=1 HTTP/1.1\r\nHost: example.com:8080\r\nContent-Length: 3\r\nConnection: x-hop, keep-alive\r\nX-Hop: drop-me\r\nKeep-Alive: timeout=5\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\nabc";
        let request = parse(input).expect("forward proxy request");
        assert_eq!(request.kind(), RequestKind::Forward);
        assert_eq!(
            request.destination(),
            &Destination::new(Address::Domain("example.com".to_owned()), 8080)
        );
        assert_eq!(request.target(), "http://example.com:8080/path?q=1");
        assert_eq!(request.body_framing(), BodyFraming::ContentLength(3));
        assert_eq!(&input[request.consumed()..], b"abc");
        assert_eq!(
            request.proxy_authorization(),
            Some(b"Basic dXNlcjpwYXNz".as_slice())
        );
        let forwarded: Vec<_> = request
            .forward_headers()
            .map(|header| header.name())
            .collect();
        assert_eq!(forwarded, ["Host", "Content-Length"]);
        let debug = format!("{request:?}");
        assert!(!debug.contains("dXNlcjpwYXNz"));
        assert!(!debug.contains("Basic"));
    }

    #[test]
    fn chunked_framing_is_supported_and_retains_the_trailer_declaration() {
        let input = b"POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nTrailer: x-checksum\r\n\r\n4\r\ndata\r\n0\r\n\r\n";
        let request = parse(input).expect("chunked request");
        assert_eq!(request.body_framing(), BodyFraming::Chunked);
        assert!(
            request
                .forward_headers()
                .any(|header| header.name().eq_ignore_ascii_case("trailer"))
        );
        assert!(
            request
                .forward_headers()
                .all(|header| !header.name().eq_ignore_ascii_case("transfer-encoding"))
        );
        assert!(input[request.consumed()..].starts_with(b"4\r\ndata"));
    }

    #[test]
    fn framing_ambiguity_and_duplicate_sensitive_headers_are_rejected() {
        let cases: [(&[u8], HttpDecodeError); 11] = [
            (
                b"POST http://e.test/ HTTP/1.1\r\nHost: e.test\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
                HttpDecodeError::DuplicateContentLength,
            ),
            (
                b"POST http://e.test/ HTTP/1.1\r\nHost: e.test\r\nContent-Length: 0, 0\r\n\r\n",
                HttpDecodeError::InvalidContentLength,
            ),
            (
                b"POST http://e.test/ HTTP/1.1\r\nHost: e.test\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
                HttpDecodeError::ConflictingBodyFraming,
            ),
            (
                b"POST http://e.test/ HTTP/1.1\r\nHost: e.test\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
                HttpDecodeError::DuplicateTransferEncoding,
            ),
            (
                b"POST http://e.test/ HTTP/1.1\r\nHost: e.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
                HttpDecodeError::UnsupportedTransferEncoding,
            ),
            (
                b"POST http://e.test/ HTTP/1.1\r\nHost: e.test\r\nTrailer: x-test\r\n\r\n",
                HttpDecodeError::TrailerWithoutChunked,
            ),
            (
                b"GET http://e.test/ HTTP/1.1\r\nHost: e.test\r\nHost: e.test\r\n\r\n",
                HttpDecodeError::DuplicateHost,
            ),
            (
                b"GET http://e.test/ HTTP/1.1\r\nHost: e.test\r\nProxy-Authorization: Basic a\r\nProxy-Authorization: Basic b\r\n\r\n",
                HttpDecodeError::DuplicateProxyAuthorization,
            ),
            (
                b"CONNECT e.test:443 HTTP/1.1\r\nHost: e.test:443\r\nContent-Length: 0\r\n\r\n",
                HttpDecodeError::ConnectBodyFraming,
            ),
            (
                b"CONNECT e.test:443 HTTP/1.1\r\nHost: e.test:443\r\nContent-Length: 1\r\n\r\nX",
                HttpDecodeError::ConnectBodyFraming,
            ),
            (
                b"CONNECT e.test:443 HTTP/1.1\r\nHost: e.test:443\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                HttpDecodeError::ConnectBodyFraming,
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(
                parse(input).expect_err("ambiguous request rejected"),
                expected
            );
        }
    }

    #[test]
    fn host_authority_and_http_version_are_strictly_checked() {
        assert_eq!(
            parse(b"GET http://example.com/ HTTP/1.1\r\n\r\n").expect_err("missing host"),
            HttpDecodeError::MissingHost
        );
        assert_eq!(
            parse(b"GET http://example.com/ HTTP/1.1\r\nHost: other.example\r\n\r\n")
                .expect_err("mismatched host"),
            HttpDecodeError::HostMismatch
        );
        assert_eq!(
            parse(b"GET http://example.com/ HTTP/1.0\r\nHost: example.com\r\n\r\n")
                .expect_err("only HTTP/1.1"),
            HttpDecodeError::UnsupportedVersion(0)
        );
        assert_eq!(
            parse(b"CONNECT 2001:db8::1:443 HTTP/1.1\r\nHost: 2001:db8::1:443\r\n\r\n")
                .expect_err("IPv6 must be bracketed"),
            HttpDecodeError::InvalidAuthority
        );
        assert_eq!(
            parse(b"CONNECT example.com:0 HTTP/1.1\r\nHost: example.com:0\r\n\r\n")
                .expect_err("zero port"),
            HttpDecodeError::InvalidAuthority
        );
        assert_eq!(
            parse(b"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .expect_err("TLS must use CONNECT"),
            HttpDecodeError::UnsupportedScheme
        );
    }

    #[test]
    fn connection_tokens_are_validated_and_nominated_headers_are_removed() {
        let valid = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: x-private\r\nX-Private: do-not-forward\r\nX-Public: keep\r\n\r\n";
        let request = parse(valid).expect("valid Connection list");
        let forwarded: Vec<_> = request
            .forward_headers()
            .map(|header| header.name())
            .collect();
        assert_eq!(forwarded, ["Host", "X-Public"]);

        let invalid =
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: x, , y\r\n\r\n";
        assert_eq!(
            parse(invalid).expect_err("empty Connection token"),
            HttpDecodeError::InvalidConnectionHeader
        );
    }

    #[test]
    fn bounded_header_parser_distinguishes_incomplete_oversized_and_body_bytes() {
        let incomplete = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n";
        assert_eq!(
            parse(incomplete).expect_err("missing terminator"),
            HttpDecodeError::IncompleteHeaders
        );

        let mut oversized = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n".to_vec();
        for _ in 0..4 {
            oversized.extend_from_slice(b"X-Pad: ");
            oversized.extend(std::iter::repeat_n(b'x', 5000));
            oversized.extend_from_slice(b"\r\n");
        }
        oversized.extend_from_slice(b"\r\n");
        assert!(oversized.len() > MAX_HTTP_HEADER_BYTES);
        assert_eq!(
            parse(&oversized).expect_err("header byte bound"),
            HttpDecodeError::HeaderTooLarge
        );

        let mut oversized_incomplete =
            b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-Pad: ".to_vec();
        oversized_incomplete.extend(std::iter::repeat_n(b'x', MAX_HTTP_HEADER_BYTES));
        oversized_incomplete.push(0x01);
        assert!(oversized_incomplete.len() > MAX_HTTP_HEADER_BYTES);
        assert_eq!(
            parse(&oversized_incomplete).expect_err("parser must stop at header byte bound"),
            HttpDecodeError::HeaderTooLarge
        );

        let mut body = b"POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 20000\r\n\r\n".to_vec();
        let header_length = body.len();
        body.extend(std::iter::repeat_n(b'b', 20000));
        let request = parse(&body).expect("large body is not copied into header parser");
        assert_eq!(request.consumed(), header_length);
        assert_eq!(request.body_framing(), BodyFraming::ContentLength(20000));
    }

    #[test]
    fn too_many_headers_and_control_bytes_are_rejected() {
        let mut many = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n".to_vec();
        for index in 0..=MAX_HTTP_HEADER_COUNT {
            many.extend_from_slice(format!("X-{index}: value\r\n").as_bytes());
        }
        many.extend_from_slice(b"\r\n");
        assert_eq!(
            parse(&many).expect_err("header count bound"),
            HttpDecodeError::TooManyHeaders
        );

        let control = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-Test: bad\x01value\r\n\r\n";
        assert_eq!(
            parse(control).expect_err("control byte"),
            HttpDecodeError::InvalidSyntax
        );
    }

    #[test]
    fn obsolete_line_folding_is_rejected() {
        let folded = b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-Test: first\r\n second\r\n\r\n";
        assert_eq!(
            parse(folded).expect_err("obs-fold is prohibited"),
            HttpDecodeError::InvalidSyntax
        );
    }

    #[test]
    fn basic_credentials_are_bounded_split_at_first_colon_and_redacted() {
        let value = auth_header(b"synthetic-user", b"secret:with:colons");
        let credentials = decode_basic_credentials(&value).expect("valid Basic credentials");
        assert_eq!(credentials.username(), "synthetic-user");
        assert_eq!(credentials.password(), "secret:with:colons");
        let debug = format!("{credentials:?}");
        assert!(!debug.contains("synthetic-user"));
        assert!(!debug.contains("secret:with:colons"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn basic_auth_rejects_unsupported_malformed_empty_and_invalid_utf8_credentials() {
        assert_auth_error(b"Bearer token", HttpAuthError::UnsupportedScheme);
        assert_auth_error(b"Basic", HttpAuthError::InvalidHeader);
        assert_auth_error(b"Basic !!!", HttpAuthError::InvalidBase64);
        assert_auth_error(b"Basic dXNlcg==", HttpAuthError::MissingSeparator);
        assert_auth_error(b"Basic OnB3", HttpAuthError::EmptyUsername);
        assert_auth_error(b"Basic dXNlcjo=", HttpAuthError::EmptyPassword);
        assert_auth_error(b"Basic /zp4", HttpAuthError::InvalidUtf8);
        assert_auth_error(b"Basic ", HttpAuthError::InvalidHeader);
        assert_auth_error(
            &vec![b'a'; MAX_BASIC_AUTH_VALUE_BYTES + 1],
            HttpAuthError::TooLong,
        );
    }

    #[test]
    fn fixed_auth_and_connect_responses_are_exact_and_bounded() {
        let challenge = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"local-proxy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let mut output = vec![0xa5; challenge.len()];
        assert_eq!(
            encode_proxy_auth_required_response(&mut output),
            Ok(challenge.len())
        );
        assert_eq!(output, challenge);
        let mut short = vec![0xa5; challenge.len() - 1];
        assert_eq!(
            encode_proxy_auth_required_response(&mut short),
            Err(HttpEncodeError::OutputTooSmall {
                required: challenge.len(),
                available: challenge.len() - 1,
            })
        );
        assert!(short.iter().all(|byte| *byte == 0xa5));

        let established = b"HTTP/1.1 200 Connection Established\r\n\r\n";
        let mut output = vec![0; established.len()];
        assert_eq!(
            encode_connect_established_response(&mut output),
            Ok(established.len())
        );
        assert_eq!(output, established);
    }
}
