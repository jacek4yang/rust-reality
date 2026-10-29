//! Independent TLS evidence decoding. No production protocol code is imported.
//!
//! Decoding preserves wire order, duplicates in capability vectors, GREASE,
//! record boundaries, and complete extension bodies. Normalization is a
//! separate policy: this decoder never turns a wire difference into equality.

use serde::Serialize;
use std::fmt;

/// Maximum captured ClientHello wire bytes accepted by the offline decoder.
pub const MAX_CAPTURE_BYTES: usize = 128 * 1024;
const MAX_MESSAGE_BYTES: usize = 65_535;

/// Malformed, truncated, or oversized evidence. Offsets refer to the current
/// framing layer, not a synthesized production diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub &'static str);
impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for DecodeError {}
type Result<T> = std::result::Result<T, DecodeError>;

/// One original TLS record boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Record {
    /// Original record-layer version, without normalization.
    pub version: u16,
    /// Original payload length.
    pub length: usize,
}
/// One original extension, including unknown extensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Extension {
    /// Wire extension type.
    pub kind: u16,
    /// Unmodified extension contents.
    pub body: Vec<u8>,
}
/// One offered key share, including GREASE entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyShare {
    /// Original group identifier.
    pub group: u16,
    /// Original public exchange bytes, retained to test inter-share relations.
    pub exchange: Vec<u8>,
}
/// Lossless structural view of a captured ClientHello.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClientHello {
    /// Record framing in capture order.
    pub records: Vec<Record>,
    /// Handshake legacy version.
    pub legacy_version: u16,
    /// Original random bytes.
    pub random: Vec<u8>,
    /// Original session identifier.
    pub session_id: Vec<u8>,
    /// Cipher suites in preference order, including GREASE.
    pub cipher_suites: Vec<u16>,
    /// Compression methods in original order.
    pub compression: Vec<u8>,
    /// Extensions in original order, retaining every byte.
    pub extensions: Vec<Extension>,
    /// Supported groups, if present.
    pub groups: Option<Vec<u16>>,
    /// Signature schemes, if present; duplicate entries are preserved.
    pub signature_algorithms: Option<Vec<u16>>,
    /// Supported versions, if present.
    pub supported_versions: Option<Vec<u16>>,
    /// Public key shares, if present.
    pub key_shares: Option<Vec<KeyShare>>,
    /// ALPN offers as opaque protocol bytes.
    pub alpn: Option<Vec<Vec<u8>>>,
}

struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let (a, b) = self
            .0
            .split_at_checked(n)
            .ok_or(DecodeError("truncated vector"))?;
        self.0 = b;
        Ok(a)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn word(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn short(&mut self) -> Result<&'a [u8]> {
        let n = usize::from(self.byte()?);
        self.take(n)
    }
    fn vector(&mut self) -> Result<&'a [u8]> {
        let n = usize::from(self.word()?);
        self.take(n)
    }
    fn end(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(DecodeError("trailing bytes"))
        }
    }
}
fn words(bytes: &[u8]) -> Result<Vec<u16>> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return Err(DecodeError("invalid u16 vector"));
    }
    Ok(bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_be_bytes([p[0], p[1]]))
        .collect())
}
fn word_extension(body: &[u8], short: bool) -> Result<Vec<u16>> {
    let mut r = Cursor(body);
    let values = words(if short { r.short()? } else { r.vector()? })?;
    r.end()?;
    Ok(values)
}

/// Decode exactly one complete ClientHello from its original TLS records.
///
/// Rejects trailing records/messages, duplicate extension types, invalid vector
/// lengths, and oversized input. It does not accept a summary in place of raw
/// bytes and does not use rust-reality's parser as its own oracle.
pub fn decode(wire: &[u8]) -> Result<ClientHello> {
    if wire.len() > MAX_CAPTURE_BYTES {
        return Err(DecodeError("capture too large"));
    }
    let mut r = Cursor(wire);
    let mut records = Vec::new();
    let mut message = Vec::new();
    while !r.0.is_empty() {
        if records.len() >= 256 {
            return Err(DecodeError("too many records"));
        }
        if r.byte()? != 22 {
            return Err(DecodeError("expected handshake record"));
        }
        let version = r.word()?;
        if !(0x0301..=0x0303).contains(&version) {
            return Err(DecodeError("invalid record version"));
        }
        let payload = r.vector()?;
        if payload.is_empty() || payload.len() > 16_384 {
            return Err(DecodeError("invalid plaintext record length"));
        }
        if message.len() + payload.len() > MAX_MESSAGE_BYTES {
            return Err(DecodeError("handshake too large"));
        }
        records.push(Record {
            version,
            length: payload.len(),
        });
        message.extend_from_slice(payload);
    }
    let mut r = Cursor(&message);
    if r.byte()? != 1 {
        return Err(DecodeError("expected ClientHello"));
    }
    let n = r.take(3)?;
    let declared = (usize::from(n[0]) << 16) | (usize::from(n[1]) << 8) | usize::from(n[2]);
    if declared != r.0.len() {
        return Err(DecodeError("handshake length mismatch"));
    }
    let legacy_version = r.word()?;
    let random = r.take(32)?.to_vec();
    let session_id = r.short()?.to_vec();
    if session_id.len() > 32 {
        return Err(DecodeError("session ID too long"));
    }
    let cipher_suites = words(r.vector()?)?;
    let compression = r.short()?.to_vec();
    if compression.is_empty() {
        return Err(DecodeError("empty compression methods"));
    }
    let mut e = Cursor(r.vector()?);
    r.end()?;
    let mut hello = ClientHello {
        records,
        legacy_version,
        random,
        session_id,
        cipher_suites,
        compression,
        extensions: Vec::new(),
        groups: None,
        signature_algorithms: None,
        supported_versions: None,
        key_shares: None,
        alpn: None,
    };
    while !e.0.is_empty() {
        if hello.extensions.len() >= 256 {
            return Err(DecodeError("too many extensions"));
        }
        let kind = e.word()?;
        if hello.extensions.iter().any(|e| e.kind == kind) {
            return Err(DecodeError("duplicate extension"));
        }
        let body = e.vector()?;
        match kind {
            10 => hello.groups = Some(word_extension(body, false)?),
            13 => hello.signature_algorithms = Some(word_extension(body, false)?),
            43 => hello.supported_versions = Some(word_extension(body, true)?),
            51 => {
                let mut b = Cursor(body);
                let mut s = Cursor(b.vector()?);
                b.end()?;
                let mut shares: Vec<KeyShare> = Vec::new();
                while !s.0.is_empty() {
                    let group = s.word()?;
                    if shares.iter().any(|k| k.group == group) {
                        return Err(DecodeError("duplicate key share"));
                    }
                    let exchange = s.vector()?.to_vec();
                    if exchange.is_empty() {
                        return Err(DecodeError("empty key share"));
                    }
                    shares.push(KeyShare { group, exchange });
                }
                hello.key_shares = Some(shares);
            }
            16 => {
                let mut b = Cursor(body);
                let mut s = Cursor(b.vector()?);
                b.end()?;
                let mut protocols = Vec::new();
                while !s.0.is_empty() {
                    let p = s.short()?;
                    if p.is_empty() {
                        return Err(DecodeError("empty ALPN protocol"));
                    }
                    protocols.push(p.to_vec());
                }
                if protocols.is_empty() {
                    return Err(DecodeError("empty ALPN list"));
                }
                hello.alpn = Some(protocols);
            }
            _ => {}
        }
        hello.extensions.push(Extension {
            kind,
            body: body.to_vec(),
        });
    }
    Ok(hello)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(message: &[u8]) -> Vec<u8> {
        let mut r = vec![22, 3, 1];
        r.extend_from_slice(&(message.len() as u16).to_be_bytes());
        r.extend_from_slice(message);
        r
    }
    fn message(ext: &[u8]) -> Vec<u8> {
        let mut b = vec![3, 3];
        b.extend([7; 32]);
        b.extend([0, 0, 4, 0x0a, 0x0a, 0x13, 1, 1, 0]);
        b.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        b.extend_from_slice(ext);
        let mut m = vec![1, 0];
        m.extend_from_slice(&(b.len() as u16).to_be_bytes());
        m.extend(b);
        m
    }
    #[test]
    fn fragmentation_preserves_record_boundaries_and_fields() {
        let m = message(&[0, 13, 0, 6, 0, 4, 8, 4, 8, 4, 0xfa, 0xfa, 0, 1, 0]);
        let baseline = decode(&record(&m)).unwrap();
        assert_eq!(baseline.signature_algorithms, Some(vec![0x0804, 0x0804]));
        assert_eq!(baseline.cipher_suites, vec![0x0a0a, 0x1301]);
        assert_eq!(baseline.extensions[1].body, vec![0]);
        for split in 1..m.len() {
            let mut wire = record(&m[..split]);
            wire.extend(record(&m[split..]));
            let mut observed = decode(&wire).unwrap();
            assert_eq!(
                observed.records.iter().map(|r| r.length).sum::<usize>(),
                m.len()
            );
            assert_eq!(observed.records.len(), 2);
            observed.records = baseline.records.clone();
            assert_eq!(observed, baseline);
        }
    }
    #[test]
    fn truncation_duplicates_and_trailing_messages_fail() {
        let wire = record(&message(&[]));
        for end in 0..wire.len() {
            assert!(decode(&wire[..end]).is_err());
        }
        assert!(decode(&record(&message(&[0, 5, 0, 0, 0, 5, 0, 0]))).is_err());
        let mut extra = wire.clone();
        extra.extend(&wire);
        assert!(decode(&extra).is_err());
        assert!(decode(&vec![0; MAX_CAPTURE_BYTES + 1]).is_err());
    }
    #[test]
    fn extension_order_body_and_record_version_are_observable() {
        let a = decode(&record(&message(&[0, 5, 0, 1, 1, 0, 18, 0, 0]))).unwrap();
        let b = decode(&record(&message(&[0, 18, 0, 0, 0, 5, 0, 1, 1]))).unwrap();
        assert_ne!(a, b);
        let mut wire = record(&message(&[0, 5, 0, 1, 1, 0, 18, 0, 0]));
        wire[2] = 3;
        assert_ne!(a, decode(&wire).unwrap());
    }
}
