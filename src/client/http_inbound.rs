//! Loopback HTTP/1.x `CONNECT` acceptor (`HTTPS_PROXY=http://127.0.0.1:…`).
//!
//! CONNECT-only: non-CONNECT methods get 405 Allow: CONNECT. No absolute-form
//! GET forwarding, no Proxy-Agent, no body rewriting.

use std::{net::IpAddr, str};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::protocol::vless::{Address, Destination};

use super::{line::LineError, selection::LineGroup};

const MAX_HEAD_LEN: usize = 8 * 1024;

const OK: u16 = 200;
const BAD_REQUEST: u16 = 400;
const METHOD_NOT_ALLOWED: u16 = 405;
const REQUEST_HEADER_FIELDS_TOO_LARGE: u16 = 431;
const BAD_GATEWAY: u16 = 502;
const HTTP_VERSION_NOT_SUPPORTED: u16 = 505;

/// HTTP CONNECT refusal / protocol failure.
#[derive(Debug)]
pub(super) enum HttpError {
    /// Client sent an unusable head.
    Protocol { status: u16, reason: &'static str },
    /// LINE establishment failed.
    Line(LineError),
    /// Socket I/O failed.
    Io(std::io::Error),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol { reason, .. } => write!(f, "HTTP CONNECT inbound failed: {reason}"),
            Self::Line(_) => f.write_str("HTTP CONNECT inbound failed: LINE"),
            Self::Io(_) => f.write_str("HTTP CONNECT inbound failed: I/O"),
        }
    }
}

impl std::error::Error for HttpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Line(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Protocol { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Version {
    One0,
    One1,
}

impl Version {
    const fn label(self) -> &'static str {
        match self {
            Self::One0 => "HTTP/1.0",
            Self::One1 => "HTTP/1.1",
        }
    }
}

#[derive(Debug)]
struct Request {
    destination: Destination,
    version: Version,
}

/// Handles one HTTP CONNECT client connection through `line`.
pub(super) async fn handle_connection(
    mut local: TcpStream,
    group: &LineGroup,
) -> Result<(), HttpError> {
    let request = match timeout(super::REQUEST_BUDGET, read_request(&mut local)).await {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => {
            if let HttpError::Protocol { status, .. } = error {
                let _ = write_status(&mut local, Version::One1, status).await;
            }
            return Err(error);
        }
        Err(_) => {
            let _ = write_status(&mut local, Version::One1, BAD_REQUEST).await;
            return Err(HttpError::Protocol {
                status: BAD_REQUEST,
                reason: "CONNECT head timed out",
            });
        }
    };

    match group.establish(&request.destination).await {
        Ok(mut tunnel) => {
            write_status(&mut local, request.version, OK)
                .await
                .map_err(HttpError::Io)?;
            let _ = tunnel.relay(&mut local).await;
            Ok(())
        }
        Err(error) => {
            let _ = write_status(&mut local, request.version, map_line_status(&error)).await;
            Err(HttpError::Line(error))
        }
    }
}

async fn read_request(stream: &mut TcpStream) -> Result<Request, HttpError> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0_u8; 1024];
    loop {
        if buf.len() > MAX_HEAD_LEN {
            return Err(HttpError::Protocol {
                status: REQUEST_HEADER_FIELDS_TOO_LARGE,
                reason: "CONNECT head too large",
            });
        }
        let n = stream.read(&mut chunk).await.map_err(HttpError::Io)?;
        if n == 0 {
            return Err(HttpError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "HTTP peer closed before CONNECT head",
            )));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_head_end(&buf) {
            let head = &buf[..end];
            // Trailing bytes after the head belong to the tunnel; put them back
            // by establishing only after OK — callers must not have drained them.
            // We keep over-read in `buf[end..]` and prepend via a side channel:
            // simplest correct approach: if trailing non-empty, error for PR4
            // (curl waits for 200 before writing). Reject speculative write.
            if end < buf.len() {
                // Rare; most clients wait for 200. Stash by writing nothing —
                // VisionTunnel::relay reads from local after OK, so over-read is
                // lost unless we push it. Use tcp peek-less: require no trailing.
                // For correctness with pipelined clients, prepend into a buffer
                // wrapper — out of PR4 scope; curl HTTPS_PROXY does not pipeline.
                return Err(HttpError::Protocol {
                    status: BAD_REQUEST,
                    reason: "bytes after CONNECT head before 200 are not supported",
                });
            }
            return parse_head(head);
        }
        if buf.len() >= MAX_HEAD_LEN {
            return Err(HttpError::Protocol {
                status: REQUEST_HEADER_FIELDS_TOO_LARGE,
                reason: "CONNECT head too large",
            });
        }
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| buf.windows(2).position(|w| w == b"\n\n").map(|i| i + 2))
}

fn parse_head(head: &[u8]) -> Result<Request, HttpError> {
    let mut lines = head.split_inclusive(|&b| b == b'\n');
    let Some(line) = lines.next() else {
        return Err(proto(BAD_REQUEST, "missing request line"));
    };
    let request = parse_request_line(trim_line(line))?;
    for line in lines {
        if trim_line(line).is_empty() {
            return Ok(request);
        }
    }
    Err(proto(BAD_REQUEST, "header block not terminated"))
}

fn parse_request_line(line: &[u8]) -> Result<Request, HttpError> {
    let mut parts = line.splitn(3, |&b| b == b' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(proto(
            BAD_REQUEST,
            "request line is not method target version",
        ));
    };
    if method != b"CONNECT" {
        return Err(proto(METHOD_NOT_ALLOWED, "only CONNECT is supported"));
    }
    let version = match version {
        b"HTTP/1.1" => Version::One1,
        b"HTTP/1.0" => Version::One0,
        _ => {
            return Err(proto(
                HTTP_VERSION_NOT_SUPPORTED,
                "HTTP version not supported",
            ));
        }
    };
    let destination = parse_authority(target)?;
    Ok(Request {
        destination,
        version,
    })
}

fn parse_authority(target: &[u8]) -> Result<Destination, HttpError> {
    let target = str::from_utf8(target).map_err(|_| proto(BAD_REQUEST, "target is not UTF-8"))?;
    let Some((host, port)) = target.rsplit_once(':') else {
        return Err(proto(BAD_REQUEST, "CONNECT target must name a port"));
    };
    let port: u16 = port
        .parse()
        .map_err(|_| proto(BAD_REQUEST, "CONNECT port is not a number"))?;
    if port == 0 {
        return Err(proto(BAD_REQUEST, "CONNECT port must be nonzero"));
    }
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let address = if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => Address::Ipv4(v4),
            IpAddr::V6(v6) => Address::Ipv6(v6),
        }
    } else {
        if host.is_empty() || host.len() > usize::from(u8::MAX) {
            return Err(proto(BAD_REQUEST, "CONNECT host is not addressable"));
        }
        Address::Domain(host.to_owned())
    };
    Ok(Destination::new(address, port))
}

fn trim_line(line: &[u8]) -> &[u8] {
    let line = match line.last() {
        Some(b'\n') => &line[..line.len() - 1],
        _ => line,
    };
    match line.last() {
        Some(b'\r') => &line[..line.len() - 1],
        _ => line,
    }
}

async fn write_status(
    stream: &mut TcpStream,
    version: Version,
    status: u16,
) -> std::io::Result<()> {
    let phrase = match status {
        OK => "Connection Established",
        BAD_REQUEST => "Bad Request",
        METHOD_NOT_ALLOWED => "Method Not Allowed",
        REQUEST_HEADER_FIELDS_TOO_LARGE => "Request Header Fields Too Large",
        BAD_GATEWAY => "Bad Gateway",
        HTTP_VERSION_NOT_SUPPORTED => "HTTP Version Not Supported",
        _ => "Failure",
    };
    let mut reply = format!("{} {status} {phrase}\r\n", version.label());
    if status != OK {
        reply.push_str("Connection: close\r\n");
    }
    if status == METHOD_NOT_ALLOWED {
        reply.push_str("Allow: CONNECT\r\n");
    }
    reply.push_str("\r\n");
    stream.write_all(reply.as_bytes()).await?;
    stream.flush().await
}

fn map_line_status(error: &LineError) -> u16 {
    match error {
        LineError::Dial(_)
        | LineError::Handshake(_)
        | LineError::Session(_)
        | LineError::Selection(_) => BAD_GATEWAY,
        LineError::Config(_) => BAD_REQUEST,
    }
}

const fn proto(status: u16, reason: &'static str) -> HttpError {
    HttpError::Protocol { status, reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_authority_forms() {
        let req = parse_head(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .expect("parse");
        assert_eq!(req.version, Version::One1);
        assert_eq!(req.destination.port(), 443);

        let req = parse_head(b"CONNECT 127.0.0.1:8080 HTTP/1.0\r\n\r\n").expect("parse");
        assert_eq!(req.version, Version::One0);
        assert_eq!(req.destination.port(), 8080);
    }

    #[test]
    fn rejects_non_connect_with_allow_semantics() {
        let err = parse_head(b"GET http://example.com/ HTTP/1.1\r\n\r\n").expect_err("get");
        match err {
            HttpError::Protocol { status, .. } => assert_eq!(status, METHOD_NOT_ALLOWED),
            other => panic!("unexpected {other:?}"),
        }
    }
}
