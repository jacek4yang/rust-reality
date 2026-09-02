use std::{error::Error, fmt};

// The pure-Rust backend. It is the `--no-default-features` provider and the
// oracle the cross-provider equivalence tests compare ring against, so it is
// never merely dead weight in a default build.
#[cfg(not(feature = "ring-aead"))]
use aes_gcm::{
    Aes128Gcm, Aes256Gcm,
    aead::{AeadInOut, KeyInit, array::Array},
};
#[cfg(not(feature = "ring-aead"))]
use chacha20poly1305::ChaCha20Poly1305;

use super::{CipherSuite, TrafficKeys};

const HEADER_LEN: usize = 5;
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const OUTER_APPLICATION_DATA: u8 = 23;
const LEGACY_RECORD_VERSION: [u8; 2] = [3, 3];
const MAX_INNER_PLAINTEXT_LEN: usize = MAX_PLAINTEXT_LEN + 1;
const MAX_CIPHERTEXT_LEN: usize = MAX_INNER_PLAINTEXT_LEN + TAG_LEN;
const AES_GCM_RECORD_LIMIT: u64 = 1 << 24;

/// Header, authenticated inner content type, and AEAD tag around an unpadded record.
pub(crate) const UNPADDED_RECORD_WIRE_OVERHEAD: usize = HEADER_LEN + 1 + TAG_LEN;

/// Wire capacity of one record slot: header + maximum inner plaintext + tag.
pub(crate) const RECORD_SLOT_WIRE_CAPACITY: usize = HEADER_LEN + MAX_INNER_PLAINTEXT_LEN + TAG_LEN;

/// Number of consecutive record slots in the batched downlink write buffer.
///
/// Experiment D11 (downlink multi-record batching): one vectored destination
/// read fills up to this many plaintext regions, each filled slot is sealed in
/// place, and the contiguous sealed prefix is written with one write call, so
/// a full batch costs one read syscall plus one write syscall for
/// [`BATCHED_SLOT_COUNT`] records instead of one of each per record.
pub(crate) const BATCHED_SLOT_COUNT: usize = 4;

/// Total wire capacity of the batched downlink write buffer.
pub(crate) const BATCHED_WIRE_CAPACITY: usize = BATCHED_SLOT_COUNT * RECORD_SLOT_WIRE_CAPACITY;

/// Maximum unpadded TLS 1.3 record content accepted by this implementation.
pub const MAX_PLAINTEXT_LEN: usize = 1 << 14;

/// An authenticated TLS 1.3 inner content type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentType {
    /// `change_cipher_spec` compatibility content.
    ChangeCipherSpec,
    /// TLS alert messages.
    Alert,
    /// TLS handshake messages.
    Handshake,
    /// Application data carried after the handshake.
    ApplicationData,
}

impl ContentType {
    const fn wire_value(self) -> u8 {
        match self {
            Self::ChangeCipherSpec => 20,
            Self::Alert => 21,
            Self::Handshake => 22,
            Self::ApplicationData => 23,
        }
    }

    const fn from_wire(value: u8) -> Option<Self> {
        match value {
            20 => Some(Self::ChangeCipherSpec),
            21 => Some(Self::Alert),
            22 => Some(Self::Handshake),
            23 => Some(Self::ApplicationData),
            _ => None,
        }
    }
}

/// A decrypted TLS 1.3 record borrowing plaintext from its caller-owned buffer.
#[derive(Debug, Eq, PartialEq)]
pub struct OpenedRecord<'a> {
    content_type: ContentType,
    plaintext: &'a [u8],
}

impl<'a> OpenedRecord<'a> {
    /// Returns the authenticated inner content type.
    #[must_use]
    pub const fn content_type(&self) -> ContentType {
        self.content_type
    }

    /// Returns the authenticated plaintext without its type or zero padding.
    #[must_use]
    pub const fn plaintext(&self) -> &'a [u8] {
        self.plaintext
    }
}

/// A TLS 1.3 record could not be sealed or authenticated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tls13RecordError {
    /// Traffic key length does not match the selected cipher suite.
    InvalidKey,
    /// The record length, padding, or framing is outside the fixed TLS bounds.
    InvalidLength,
    /// The outer record type or legacy version is invalid for encrypted data.
    InvalidHeader,
    /// The AEAD tag did not authenticate under the expected sequence number.
    AuthenticationFailed,
    /// The decrypted inner content type is not valid in TLS 1.3.
    InvalidContentType,
    /// This key reached its conservative per-key record usage limit.
    KeyUsageExhausted,
    /// Reserving the bounded output buffer failed.
    BufferAllocation,
}

impl fmt::Display for Tls13RecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TLS 1.3 record processing failed")
    }
}

impl Error for Tls13RecordError {}

/// One TLS 1.3 record AEAD.
///
/// The default backend (feature `ring-aead`, on by default) is ring's
/// BoringSSL-derived implementation for **all three** suites; a
/// `--no-default-features` build selects the pure-Rust RustCrypto backends with
/// identical wire behavior. Measured on this repository's exact record shapes,
/// ring is faster than RustCrypto everywhere — AES-128-GCM ≈2.5x, AES-256-GCM
/// 1.55x–2.00x, ChaCha20-Poly1305 1.86x–8.58x, the largest margins at the small
/// records that handshake and control traffic actually use. ring also beat
/// `aws-lc-rs` in all eight measured AEAD cells, and unlike `aws-lc-rs` it
/// resolves without `std`, which this module requires: it is inside the
/// `no_std + alloc` protocol core enforced by
/// `tests/protocol_core_boundary.rs` (ADR 0016). See docs/en/performance.md.
///
/// Only the AEAD primitive differs between backends. Nonce derivation, sequence
/// ownership, AAD construction, framing, limits, and error semantics stay in
/// [`Tls13RecordLayer`].
///
/// Nonce-safety invariant (unchanged by the provider choice):
/// `Tls13RecordLayer` is the single source of nonce derivation
/// (`iv XOR sequence`), it never implements `Clone`, the sequence advances
/// exactly once per sealed/opened record, and AES-GCM keys are retired at the
/// conservative 2^24 record limit. ring's `assume_unique_for_key` therefore
/// always receives a nonce that is unique under this key.
struct RecordCipher {
    #[cfg(feature = "ring-aead")]
    inner: Box<ring::aead::LessSafeKey>,
    #[cfg(not(feature = "ring-aead"))]
    inner: RustCryptoRecordCipher,
    /// Retained so `Debug` names the suite without asking the backend.
    suite: CipherSuite,
}

/// The pure-Rust backend's per-suite key material.
#[cfg(not(feature = "ring-aead"))]
enum RustCryptoRecordCipher {
    Aes128Gcm(Box<Aes128Gcm>),
    Aes256Gcm(Box<Aes256Gcm>),
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
}

impl RecordCipher {
    fn new(suite: CipherSuite, key: &[u8]) -> Result<Self, Tls13RecordError> {
        #[cfg(feature = "ring-aead")]
        {
            let algorithm = match suite {
                CipherSuite::Aes128GcmSha256 => &ring::aead::AES_128_GCM,
                CipherSuite::Aes256GcmSha384 => &ring::aead::AES_256_GCM,
                CipherSuite::ChaCha20Poly1305Sha256 => &ring::aead::CHACHA20_POLY1305,
            };
            ring::aead::UnboundKey::new(algorithm, key)
                .map(|key| Self {
                    inner: Box::new(ring::aead::LessSafeKey::new(key)),
                    suite,
                })
                .map_err(|_| Tls13RecordError::InvalidKey)
        }
        #[cfg(not(feature = "ring-aead"))]
        {
            let inner = match suite {
                CipherSuite::Aes128GcmSha256 => Aes128Gcm::new_from_slice(key)
                    .map(Box::new)
                    .map(RustCryptoRecordCipher::Aes128Gcm),
                CipherSuite::Aes256GcmSha384 => Aes256Gcm::new_from_slice(key)
                    .map(Box::new)
                    .map(RustCryptoRecordCipher::Aes256Gcm),
                CipherSuite::ChaCha20Poly1305Sha256 => ChaCha20Poly1305::new_from_slice(key)
                    .map(Box::new)
                    .map(RustCryptoRecordCipher::ChaCha20Poly1305),
            }
            .map_err(|_| Tls13RecordError::InvalidKey)?;
            Ok(Self { inner, suite })
        }
    }

    fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Tls13RecordError> {
        #[cfg(feature = "ring-aead")]
        {
            let tag = self
                .inner
                .seal_in_place_separate_tag(
                    ring::aead::Nonce::assume_unique_for_key(*nonce),
                    ring::aead::Aad::from(aad),
                    plaintext,
                )
                .map_err(|_| Tls13RecordError::AuthenticationFailed)?;
            let mut output = [0_u8; TAG_LEN];
            output.copy_from_slice(tag.as_ref());
            Ok(output)
        }
        #[cfg(not(feature = "ring-aead"))]
        {
            // Each arm copies its own tag type into the fixed output. Unifying
            // them through a `Vec` would be shorter and would allocate 16 bytes
            // per record; `allocation_gate` requires the steady-state framed
            // write path to allocate nothing.
            let mut output = [0_u8; TAG_LEN];
            match &self.inner {
                RustCryptoRecordCipher::Aes128Gcm(cipher) => {
                    let tag = cipher
                        .encrypt_inout_detached(&Array(*nonce), aad, plaintext.into())
                        .map_err(|_| Tls13RecordError::AuthenticationFailed)?;
                    output.copy_from_slice(&tag);
                }
                RustCryptoRecordCipher::Aes256Gcm(cipher) => {
                    let tag = cipher
                        .encrypt_inout_detached(&Array(*nonce), aad, plaintext.into())
                        .map_err(|_| Tls13RecordError::AuthenticationFailed)?;
                    output.copy_from_slice(&tag);
                }
                RustCryptoRecordCipher::ChaCha20Poly1305(cipher) => {
                    let tag = cipher
                        .encrypt_inout_detached(&Array(*nonce), aad, plaintext.into())
                        .map_err(|_| Tls13RecordError::AuthenticationFailed)?;
                    output.copy_from_slice(&tag);
                }
            }
            Ok(output)
        }
    }

    /// Opens `body` — ciphertext immediately followed by its tag — in place.
    ///
    /// On error the body contents are UNSPECIFIED (ring decrypts before
    /// verifying, RustCrypto does not); callers must not read the buffer
    /// after a failed open.
    fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        body: &mut [u8],
    ) -> Result<(), Tls13RecordError> {
        #[cfg(feature = "ring-aead")]
        {
            // Mirror split_tag's guard so both providers map an undersized
            // body to InvalidLength (currently unreachable: open_in_place
            // guarantees body.len() > TAG_LEN).
            if body.len() < TAG_LEN {
                return Err(Tls13RecordError::InvalidLength);
            }
            self.inner
                .open_in_place(
                    ring::aead::Nonce::assume_unique_for_key(*nonce),
                    ring::aead::Aad::from(aad),
                    body,
                )
                .map_err(|_| Tls13RecordError::AuthenticationFailed)?;
            Ok(())
        }
        #[cfg(not(feature = "ring-aead"))]
        {
            let (ciphertext, tag) = split_tag(body)?;
            match &self.inner {
                RustCryptoRecordCipher::Aes128Gcm(cipher) => cipher.decrypt_inout_detached(
                    &Array(*nonce),
                    aad,
                    ciphertext.into(),
                    &Array(*tag),
                ),
                RustCryptoRecordCipher::Aes256Gcm(cipher) => cipher.decrypt_inout_detached(
                    &Array(*nonce),
                    aad,
                    ciphertext.into(),
                    &Array(*tag),
                ),
                RustCryptoRecordCipher::ChaCha20Poly1305(cipher) => cipher.decrypt_inout_detached(
                    &Array(*nonce),
                    aad,
                    ciphertext.into(),
                    &Array(*tag),
                ),
            }
            .map_err(|_| Tls13RecordError::AuthenticationFailed)
        }
    }
}

impl fmt::Debug for RecordCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self.suite {
            CipherSuite::Aes128GcmSha256 => "AES-128-GCM",
            CipherSuite::Aes256GcmSha384 => "AES-256-GCM",
            CipherSuite::ChaCha20Poly1305Sha256 => "ChaCha20-Poly1305",
        };
        formatter.debug_tuple("RecordCipher").field(&name).finish()
    }
}

/// Splits a contiguous `ciphertext || tag` body into its parts.
///
/// ring opens in place against the contiguous body, so only the pure-Rust
/// backend, whose API takes a detached tag, needs this split.
#[cfg(not(feature = "ring-aead"))]
fn split_tag(body: &mut [u8]) -> Result<(&mut [u8], &[u8; TAG_LEN]), Tls13RecordError> {
    if body.len() < TAG_LEN {
        return Err(Tls13RecordError::InvalidLength);
    }
    let (ciphertext, tag) = body.split_at_mut(body.len() - TAG_LEN);
    let tag: &[u8; TAG_LEN] = (&tag[..])
        .try_into()
        .map_err(|_| Tls13RecordError::InvalidLength)?;
    Ok((ciphertext, tag))
}

/// Directional TLS 1.3 AEAD state with non-reusable sequence ownership.
///
/// The type deliberately does not implement `Clone`: copying it would reuse a
/// key/nonce pair and break AEAD security. The traffic keys are retained so
/// the layer can be exported exactly once via [`Tls13RecordLayer::into_exported_state`]
/// at a session-handoff boundary; export consumes the layer, so a live
/// session's key and sequence never have two owners.
pub struct Tls13RecordLayer {
    cipher: RecordCipher,
    suite: CipherSuite,
    keys: TrafficKeys,
    sequence: u64,
}

impl Tls13RecordLayer {
    /// Consumes one direction's derived traffic key and IV.
    ///
    /// # Errors
    ///
    /// Rejects key material whose length does not match the suite.
    pub fn new(suite: CipherSuite, keys: TrafficKeys) -> Result<Self, Tls13RecordError> {
        let cipher = RecordCipher::new(suite, keys.key())?;
        Ok(Self {
            cipher,
            suite,
            keys,
            sequence: 0,
        })
    }

    /// Returns how many records have successfully used this traffic key.
    #[must_use]
    pub const fn records_used(&self) -> u64 {
        self.sequence
    }

    /// Consumes the layer and exports its key material and current sequence.
    ///
    /// This is the session-handoff escape hatch: the exported state is the
    /// only remaining owner of this direction's key and sequence, and it can
    /// be turned back into a working layer with
    /// [`Tls13RecordLayer::from_exported_state`] on the same suite.
    #[must_use]
    pub fn into_exported_state(self) -> ExportedRecordState {
        ExportedRecordState {
            suite: self.suite,
            keys: self.keys,
            sequence: self.sequence,
        }
    }

    /// Rebuilds a working layer from previously exported state.
    ///
    /// # Errors
    ///
    /// Rejects key material whose length does not match the exported suite and
    /// sequences that already reached the suite's per-key record limit.
    pub fn from_exported_state(state: ExportedRecordState) -> Result<Self, Tls13RecordError> {
        let cipher = RecordCipher::new(state.suite, state.keys.key())?;
        let layer = Self {
            cipher,
            suite: state.suite,
            keys: state.keys,
            sequence: state.sequence,
        };
        layer.ensure_key_available()?;
        Ok(layer)
    }

    /// Seals one complete TLS 1.3 record into a reusable caller-owned buffer.
    ///
    /// # Errors
    ///
    /// Rejects oversized content/padding, exhausted traffic keys, allocation
    /// failure, and AEAD primitive failure.
    pub fn seal_into(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
        padding_len: usize,
        output: &mut Vec<u8>,
    ) -> Result<(), Tls13RecordError> {
        self.ensure_key_available()?;
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(Tls13RecordError::InvalidLength);
        }
        let inner_len = plaintext
            .len()
            .checked_add(1)
            .and_then(|length| length.checked_add(padding_len))
            .filter(|length| *length <= MAX_INNER_PLAINTEXT_LEN)
            .ok_or(Tls13RecordError::InvalidLength)?;
        let ciphertext_len = inner_len
            .checked_add(TAG_LEN)
            .ok_or(Tls13RecordError::InvalidLength)?;
        let ciphertext_len =
            u16::try_from(ciphertext_len).map_err(|_| Tls13RecordError::InvalidLength)?;
        let header = [
            OUTER_APPLICATION_DATA,
            LEGACY_RECORD_VERSION[0],
            LEGACY_RECORD_VERSION[1],
            ciphertext_len.to_be_bytes()[0],
            ciphertext_len.to_be_bytes()[1],
        ];

        output.clear();
        output
            .try_reserve_exact(HEADER_LEN + usize::from(ciphertext_len))
            .map_err(|_| Tls13RecordError::BufferAllocation)?;
        output.extend_from_slice(&header);
        output.extend_from_slice(plaintext);
        output.push(content_type.wire_value());
        output.resize(HEADER_LEN + inner_len, 0);

        let nonce = self.nonce();
        let encrypted = output
            .get_mut(HEADER_LEN..)
            .ok_or(Tls13RecordError::InvalidLength)?;
        let tag = self.cipher.seal(&nonce, &header, encrypted)?;
        output.extend_from_slice(&tag);
        self.advance()?;
        Ok(())
    }

    /// Seals one record whose plaintext is assembled directly in final storage.
    ///
    /// The caller declares the exact plaintext length; `assemble` then receives
    /// the plaintext region of the output record and writes it in place. This
    /// removes the intermediate frame buffer that a higher-level framing layer
    /// would otherwise build and copy, leaving only the unavoidable single write
    /// into AEAD plaintext storage.
    ///
    /// # Errors
    ///
    /// Rejects oversized content/padding, exhausted traffic keys, allocation
    /// failure, and AEAD primitive failure.
    pub fn seal_assembled<Assemble>(
        &mut self,
        content_type: ContentType,
        plaintext_len: usize,
        padding_len: usize,
        output: &mut Vec<u8>,
        assemble: Assemble,
    ) -> Result<(), Tls13RecordError>
    where
        Assemble: FnOnce(&mut [u8]),
    {
        self.ensure_key_available()?;
        if plaintext_len > MAX_PLAINTEXT_LEN {
            return Err(Tls13RecordError::InvalidLength);
        }
        let inner_len = plaintext_len
            .checked_add(1)
            .and_then(|length| length.checked_add(padding_len))
            .filter(|length| *length <= MAX_INNER_PLAINTEXT_LEN)
            .ok_or(Tls13RecordError::InvalidLength)?;
        let ciphertext_len = inner_len
            .checked_add(TAG_LEN)
            .ok_or(Tls13RecordError::InvalidLength)?;
        let ciphertext_len =
            u16::try_from(ciphertext_len).map_err(|_| Tls13RecordError::InvalidLength)?;
        let header = [
            OUTER_APPLICATION_DATA,
            LEGACY_RECORD_VERSION[0],
            LEGACY_RECORD_VERSION[1],
            ciphertext_len.to_be_bytes()[0],
            ciphertext_len.to_be_bytes()[1],
        ];

        output.clear();
        output
            .try_reserve(HEADER_LEN + usize::from(ciphertext_len))
            .map_err(|_| Tls13RecordError::BufferAllocation)?;
        output.extend_from_slice(&header);
        output.resize(HEADER_LEN + inner_len, 0);
        let plaintext_end = HEADER_LEN
            .checked_add(plaintext_len)
            .ok_or(Tls13RecordError::InvalidLength)?;
        assemble(
            output
                .get_mut(HEADER_LEN..plaintext_end)
                .ok_or(Tls13RecordError::InvalidLength)?,
        );
        *output
            .get_mut(plaintext_end)
            .ok_or(Tls13RecordError::InvalidLength)? = content_type.wire_value();

        let nonce = self.nonce();
        let encrypted = output
            .get_mut(HEADER_LEN..)
            .ok_or(Tls13RecordError::InvalidLength)?;
        let tag = self.cipher.seal(&nonce, &header, encrypted)?;
        output.extend_from_slice(&tag);
        self.advance()?;
        Ok(())
    }

    /// Seals one record whose plaintext a caller already wrote into `output`.
    ///
    /// This is the asynchronous sibling of [`Tls13RecordLayer::seal_assembled`]:
    /// the caller filled the plaintext region obtained from
    /// `application_plaintext_region` — typically by reading a socket
    /// directly into it — and only the byte count is decided afterwards. The
    /// destination read therefore lands in final AEAD storage and is sealed in
    /// place, with no scratch buffer and no intermediate copy.
    ///
    /// `output` must hold `plaintext_len` plaintext bytes starting at the
    /// record header length and must already have length covering the header,
    /// the plaintext, the inner content type, and the tag, which
    /// `application_plaintext_region` guarantees. The buffer length is left
    /// unchanged so the storage stays grow-only; the returned length is the
    /// exact sealed record prefix to write.
    ///
    /// # Errors
    ///
    /// Rejects oversized content, exhausted traffic keys, a too-short buffer,
    /// and AEAD primitive failure.
    pub fn seal_filled(
        &mut self,
        content_type: ContentType,
        plaintext_len: usize,
        output: &mut [u8],
    ) -> Result<usize, Tls13RecordError> {
        self.ensure_key_available()?;
        if plaintext_len > MAX_PLAINTEXT_LEN {
            return Err(Tls13RecordError::InvalidLength);
        }
        let inner_len = plaintext_len
            .checked_add(1)
            .filter(|length| *length <= MAX_INNER_PLAINTEXT_LEN)
            .ok_or(Tls13RecordError::InvalidLength)?;
        let ciphertext_len = inner_len
            .checked_add(TAG_LEN)
            .ok_or(Tls13RecordError::InvalidLength)?;
        let ciphertext_len =
            u16::try_from(ciphertext_len).map_err(|_| Tls13RecordError::InvalidLength)?;
        let header = [
            OUTER_APPLICATION_DATA,
            LEGACY_RECORD_VERSION[0],
            LEGACY_RECORD_VERSION[1],
            ciphertext_len.to_be_bytes()[0],
            ciphertext_len.to_be_bytes()[1],
        ];
        let plaintext_end = HEADER_LEN
            .checked_add(plaintext_len)
            .ok_or(Tls13RecordError::InvalidLength)?;
        let tag_end = plaintext_end
            .checked_add(1)
            .and_then(|end| end.checked_add(TAG_LEN))
            .ok_or(Tls13RecordError::InvalidLength)?;
        if output.len() < tag_end {
            return Err(Tls13RecordError::InvalidLength);
        }

        output
            .get_mut(..HEADER_LEN)
            .ok_or(Tls13RecordError::InvalidLength)?
            .copy_from_slice(&header);
        *output
            .get_mut(plaintext_end)
            .ok_or(Tls13RecordError::InvalidLength)? = content_type.wire_value();
        let nonce = self.nonce();
        let encrypted = output
            .get_mut(HEADER_LEN..plaintext_end + 1)
            .ok_or(Tls13RecordError::InvalidLength)?;
        let tag = self.cipher.seal(&nonce, &header, encrypted)?;
        output
            .get_mut(plaintext_end + 1..tag_end)
            .ok_or(Tls13RecordError::InvalidLength)?
            .copy_from_slice(&tag);
        self.advance()?;
        Ok(tag_end)
    }

    /// Authenticates and decrypts exactly one complete TLS 1.3 record in place.    ///
    /// # Errors
    ///
    /// Rejects malformed framing, exhausted traffic keys, an invalid AEAD tag,
    /// and an invalid authenticated inner content type.
    pub fn open_in_place<'a>(
        &mut self,
        record: &'a mut [u8],
    ) -> Result<OpenedRecord<'a>, Tls13RecordError> {
        self.ensure_key_available()?;
        let header: [u8; HEADER_LEN] = record
            .get(..HEADER_LEN)
            .ok_or(Tls13RecordError::InvalidLength)?
            .try_into()
            .map_err(|_| Tls13RecordError::InvalidLength)?;
        if header[0] != OUTER_APPLICATION_DATA || header[1..3] != LEGACY_RECORD_VERSION {
            return Err(Tls13RecordError::InvalidHeader);
        }
        let ciphertext_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let expected_len = HEADER_LEN
            .checked_add(ciphertext_len)
            .ok_or(Tls13RecordError::InvalidLength)?;
        if record.len() != expected_len
            || !(TAG_LEN + 1..=MAX_CIPHERTEXT_LEN).contains(&ciphertext_len)
        {
            return Err(Tls13RecordError::InvalidLength);
        }

        let encrypted_len = ciphertext_len - TAG_LEN;
        let body = record
            .get_mut(HEADER_LEN..expected_len)
            .ok_or(Tls13RecordError::InvalidLength)?;
        let nonce = self.nonce();
        self.cipher.open(&nonce, &header, body)?;
        self.advance()?;

        let plaintext_region = body
            .get(..encrypted_len)
            .ok_or(Tls13RecordError::InvalidLength)?;
        let content_type_offset = plaintext_region
            .iter()
            .rposition(|byte| *byte != 0)
            .ok_or(Tls13RecordError::InvalidContentType)?;
        let content_type = ContentType::from_wire(plaintext_region[content_type_offset])
            .ok_or(Tls13RecordError::InvalidContentType)?;
        let plaintext = plaintext_region
            .get(..content_type_offset)
            .ok_or(Tls13RecordError::InvalidLength)?;
        Ok(OpenedRecord {
            content_type,
            plaintext,
        })
    }

    fn ensure_key_available(&self) -> Result<(), Tls13RecordError> {
        let available = match self.suite {
            CipherSuite::Aes128GcmSha256 | CipherSuite::Aes256GcmSha384 => {
                self.sequence < AES_GCM_RECORD_LIMIT
            }
            CipherSuite::ChaCha20Poly1305Sha256 => self.sequence < u64::MAX,
        };
        if available {
            Ok(())
        } else {
            Err(Tls13RecordError::KeyUsageExhausted)
        }
    }

    fn advance(&mut self) -> Result<(), Tls13RecordError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(Tls13RecordError::KeyUsageExhausted)?;
        Ok(())
    }

    fn nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = *self.keys.iv();
        let encoded = self.sequence.to_be_bytes();
        for (nonce_byte, sequence_byte) in nonce[4..].iter_mut().zip(encoded) {
            *nonce_byte ^= sequence_byte;
        }
        nonce
    }
}

impl fmt::Debug for Tls13RecordLayer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Tls13RecordLayer")
            .field("suite", &self.suite)
            .field("sequence", &self.sequence)
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

/// One record direction's exported application-traffic state.
///
/// Created only by consuming a live [`Tls13RecordLayer`], so the key/sequence
/// pair of a session can never end up with two owners. The key material is
/// zeroized on drop and never appears in `Debug` output.
pub struct ExportedRecordState {
    suite: CipherSuite,
    keys: TrafficKeys,
    sequence: u64,
}

impl ExportedRecordState {
    /// Returns the cipher suite the exported keys belong to.
    #[must_use]
    pub const fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// Returns the exported AEAD key and static IV.
    #[must_use]
    pub const fn keys(&self) -> &TrafficKeys {
        &self.keys
    }

    /// Returns how many records had been sealed or opened at export time.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Separates the exported state into suite, key material, and sequence.
    ///
    /// Ownership of the key material moves to the caller exactly once; the
    /// exported state is consumed, so the key/sequence pair still never has
    /// two owners.
    #[must_use]
    pub fn into_parts(self) -> (CipherSuite, TrafficKeys, u64) {
        (self.suite, self.keys, self.sequence)
    }

    /// Reassembles one direction's exported state from received parts.
    ///
    /// This is the receiving side of a session handoff: the parts arrive from
    /// an authenticated transfer channel, and this constructor enforces the
    /// one structural invariant that can be checked without building the
    /// cipher — the key length must match the suite. The sequence ceiling is
    /// enforced when the state becomes a working layer again through
    /// [`Tls13RecordLayer::from_exported_state`].
    ///
    /// # Errors
    ///
    /// Rejects key material whose length does not match the suite.
    pub fn from_parts(
        suite: CipherSuite,
        keys: TrafficKeys,
        sequence: u64,
    ) -> Result<Self, Tls13RecordError> {
        if keys.key().len() != suite.key_len() {
            return Err(Tls13RecordError::InvalidKey);
        }
        Ok(Self {
            suite,
            keys,
            sequence,
        })
    }
}

impl fmt::Debug for ExportedRecordState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExportedRecordState")
            .field("suite", &self.suite)
            .field("sequence", &self.sequence)
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

/// Reserves one reusable record buffer and returns its maximum plaintext region.
///
/// The buffer grows — and zero-fills — at most once; afterwards the region is
/// already-initialized memory that a socket read can overwrite directly. This
/// is the write-side counterpart of the read path's grow-only record storage:
/// a destination read lands in final AEAD plaintext storage and is sealed in
/// place by [`Tls13RecordLayer::seal_filled`].
///
/// # Errors
///
/// Returns the allocator's reservation failure without panicking.
pub(crate) fn application_plaintext_region(
    output: &mut Vec<u8>,
) -> Result<&mut [u8], Tls13RecordError> {
    if output.len() < RECORD_SLOT_WIRE_CAPACITY {
        if RECORD_SLOT_WIRE_CAPACITY > output.capacity() {
            output
                .try_reserve_exact(RECORD_SLOT_WIRE_CAPACITY - output.len())
                .map_err(|_| Tls13RecordError::BufferAllocation)?;
        }
        output.resize(RECORD_SLOT_WIRE_CAPACITY, 0);
    }
    slot_plaintext_region(output)
}

/// Grows a record buffer to the batched downlink layout exactly once.
///
/// This is the growth step of the lazy batching policy (experiment D11): the
/// caller invokes it only after a completely-full record read, so connections
/// that never see a bulk flow keep the single-record buffer and never pay the
/// extra slots. The extension is reserved and zero-filled in this one step;
/// afterwards the buffer is grow-only and never shrinks back, and
/// [`Tls13RecordLayer::seal_filled`] overwrites slot headers, content types,
/// and tags without any zeroing.
///
/// # Errors
///
/// Returns the allocator's reservation failure without panicking.
pub(crate) fn grow_batched_record_storage(output: &mut Vec<u8>) -> Result<(), Tls13RecordError> {
    if output.len() < BATCHED_WIRE_CAPACITY {
        if BATCHED_WIRE_CAPACITY > output.capacity() {
            output
                .try_reserve_exact(BATCHED_WIRE_CAPACITY - output.len())
                .map_err(|_| Tls13RecordError::BufferAllocation)?;
        }
        output.resize(BATCHED_WIRE_CAPACITY, 0);
    }
    Ok(())
}

/// Returns the maximum plaintext region of every batched record slot.
///
/// The regions are disjoint windows into the one grow-only allocation: slot
/// `i` starts at `i * RECORD_SLOT_WIRE_CAPACITY`, so once each filled slot is
/// sealed in place the records form one contiguous wire prefix that a single
/// write covers. The buffer must already cover [`BATCHED_WIRE_CAPACITY`] via
/// [`grow_batched_record_storage`]; this function never grows.
///
/// # Errors
///
/// Rejects a buffer shorter than the batched wire capacity.
pub(crate) fn batched_plaintext_regions(
    output: &mut [u8],
) -> Result<[&mut [u8]; BATCHED_SLOT_COUNT], Tls13RecordError> {
    if output.len() < BATCHED_WIRE_CAPACITY {
        return Err(Tls13RecordError::InvalidLength);
    }
    let (slot0, rest) = output.split_at_mut(RECORD_SLOT_WIRE_CAPACITY);
    let (slot1, rest) = rest.split_at_mut(RECORD_SLOT_WIRE_CAPACITY);
    let (slot2, slot3) = rest.split_at_mut(RECORD_SLOT_WIRE_CAPACITY);
    Ok([
        slot_plaintext_region(slot0)?,
        slot_plaintext_region(slot1)?,
        slot_plaintext_region(slot2)?,
        slot_plaintext_region(slot3)?,
    ])
}

/// Returns the maximum plaintext region of one record slot.
fn slot_plaintext_region(slot: &mut [u8]) -> Result<&mut [u8], Tls13RecordError> {
    slot.get_mut(HEADER_LEN..HEADER_LEN + MAX_PLAINTEXT_LEN)
        .ok_or(Tls13RecordError::InvalidLength)
}

#[cfg(test)]
mod tests {
    use super::{ContentType, Tls13RecordError, Tls13RecordLayer};
    use crate::protocol::reality::tls13::{
        CipherSuite, HashAlgorithm, Tls13KeySchedule, Tls13KeyScheduleError, TrafficKeys,
        TranscriptHash,
    };

    #[test]
    fn rfc8448_client_finished_record_matches_byte_for_byte() {
        let schedule = rfc8448_schedule();
        let keys = schedule
            .traffic_keys(schedule.client_handshake_secret())
            .expect("RFC 8448 traffic keys must derive");
        let mut records = Tls13RecordLayer::new(CipherSuite::Aes128GcmSha256, keys)
            .expect("RFC 8448 record state must initialize");
        let plaintext =
            hex_vec("14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61");
        let mut record = Vec::new();
        records
            .seal_into(ContentType::Handshake, &plaintext, 0, &mut record)
            .expect("RFC 8448 Finished must seal");

        assert_eq!(
            record,
            hex_vec(
                "170303003575ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc44\
                 d87f38f80338ac98fc46deb384bd1caeacab6867d726c40546"
            )
        );
    }

    #[test]
    fn rfc8448_client_finished_record_opens_in_place() {
        let schedule = rfc8448_schedule();
        let keys = schedule
            .traffic_keys(schedule.client_handshake_secret())
            .expect("RFC 8448 traffic keys must derive");
        let mut records = Tls13RecordLayer::new(CipherSuite::Aes128GcmSha256, keys)
            .expect("RFC 8448 record state must initialize");
        let mut record = hex_vec(
            "170303003575ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc44\
             d87f38f80338ac98fc46deb384bd1caeacab6867d726c40546",
        );
        let opened = records
            .open_in_place(&mut record)
            .expect("RFC 8448 Finished must authenticate");

        assert_eq!(opened.content_type(), ContentType::Handshake);
        assert_eq!(
            opened.plaintext(),
            hex_vec("14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61")
        );
    }

    #[test]
    fn round_trips_all_supported_suites_with_padding_and_sequence() {
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let (mut writer, mut reader) = paired_layers(suite);
            for plaintext in [b"".as_slice(), b"interactive", &[0x42; 16_384]] {
                let padding = usize::from(plaintext.len() < 128) * 31;
                let mut record = Vec::new();
                writer
                    .seal_into(
                        ContentType::ApplicationData,
                        plaintext,
                        padding,
                        &mut record,
                    )
                    .expect("bounded test record must seal");
                let opened = reader
                    .open_in_place(&mut record)
                    .expect("matching direction must authenticate");
                assert_eq!(opened.content_type(), ContentType::ApplicationData);
                assert_eq!(opened.plaintext(), plaintext);
            }
            assert_eq!(writer.records_used(), 3);
            assert_eq!(reader.records_used(), 3);
        }
    }

    #[test]
    fn rejects_tamper_reordering_trailing_bytes_and_oversize() {
        let (mut writer, mut reader) = paired_layers(CipherSuite::Aes128GcmSha256);
        let mut first = Vec::new();
        writer
            .seal_into(ContentType::Handshake, b"first", 0, &mut first)
            .expect("first record must seal");
        let mut second = Vec::new();
        writer
            .seal_into(ContentType::Handshake, b"second", 0, &mut second)
            .expect("second record must seal");

        assert_eq!(
            reader.open_in_place(&mut second),
            Err(Tls13RecordError::AuthenticationFailed)
        );
        let mut tampered = first.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 1;
        }
        assert_eq!(
            reader.open_in_place(&mut tampered),
            Err(Tls13RecordError::AuthenticationFailed)
        );
        first.push(0);
        assert_eq!(
            reader.open_in_place(&mut first),
            Err(Tls13RecordError::InvalidLength)
        );

        let mut output = Vec::new();
        assert_eq!(
            writer.seal_into(
                ContentType::ApplicationData,
                &[0; super::MAX_PLAINTEXT_LEN + 1],
                0,
                &mut output,
            ),
            Err(Tls13RecordError::InvalidLength)
        );
    }

    #[test]
    fn debug_never_exposes_key_or_iv() {
        let (writer, _) = paired_layers(CipherSuite::Aes128GcmSha256);
        let rendered = format!("{writer:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("dbfa"));
        assert!(!rendered.contains("5bd3"));
    }

    #[test]
    fn exported_layer_continues_interoperation_both_ways() {
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            // Two directions, each a writer/reader pair over shared keys.
            let (mut up_writer, mut up_reader) = paired_layers(suite);
            let (mut down_writer, mut down_reader) = paired_layers(suite);
            for index in 0..3_u8 {
                let mut record = Vec::new();
                up_writer
                    .seal_into(ContentType::ApplicationData, &[index; 64], 0, &mut record)
                    .expect("pre-export record must seal");
                up_reader
                    .open_in_place(&mut record)
                    .expect("pre-export record must open");
                let mut downlink = Vec::new();
                down_writer
                    .seal_into(ContentType::ApplicationData, &[index; 16], 0, &mut downlink)
                    .expect("pre-export downlink must seal");
                down_reader
                    .open_in_place(&mut downlink)
                    .expect("pre-export downlink must open");
            }

            // Export after three records: the imported opener must authenticate
            // the original writer's fourth record.
            let exported_reader = up_reader.into_exported_state();
            assert_eq!(exported_reader.suite(), suite);
            assert_eq!(exported_reader.sequence(), 3);
            let mut imported_reader = Tls13RecordLayer::from_exported_state(exported_reader)
                .expect("exported reader state must rebuild");
            let mut fourth = Vec::new();
            up_writer
                .seal_into(
                    ContentType::ApplicationData,
                    b"after-export",
                    0,
                    &mut fourth,
                )
                .expect("continuation record must seal");
            let opened = imported_reader
                .open_in_place(&mut fourth)
                .expect("imported layer must open the original's continuation");
            assert_eq!(opened.plaintext(), b"after-export");
            assert_eq!(imported_reader.records_used(), 4);

            // And vice versa: a record sealed by the imported writer must
            // authenticate on the original reader.
            let mut imported_writer =
                Tls13RecordLayer::from_exported_state(down_writer.into_exported_state())
                    .expect("exported writer state must rebuild");
            let mut reply = Vec::new();
            imported_writer
                .seal_into(
                    ContentType::ApplicationData,
                    b"reply-after-export",
                    7,
                    &mut reply,
                )
                .expect("imported layer must seal the continuation");
            let opened = down_reader
                .open_in_place(&mut reply)
                .expect("original layer must open the imported continuation");
            assert_eq!(opened.plaintext(), b"reply-after-export");
            assert_eq!(down_reader.records_used(), 4);
        }
    }

    #[test]
    fn exported_state_preserves_key_material_and_redacts_debug() {
        let (writer, mut reader) = paired_layers(CipherSuite::ChaCha20Poly1305Sha256);
        let exported = writer.into_exported_state();
        let key = exported.keys().key().to_vec();
        let iv = *exported.keys().iv();
        assert_eq!(key.len(), 32);

        let rebuilt_keys = TrafficKeys::from_raw_parts(&key, iv).expect("raw parts must rebuild");
        let mut reference =
            Tls13RecordLayer::new(CipherSuite::ChaCha20Poly1305Sha256, rebuilt_keys)
                .expect("reference layer must initialize");
        let mut imported =
            Tls13RecordLayer::from_exported_state(exported).expect("exported state must rebuild");
        let mut record = Vec::new();
        imported
            .seal_into(ContentType::ApplicationData, b"same-key", 0, &mut record)
            .expect("imported layer must seal");
        let mut peer_copy = record.clone();
        let opened = reader
            .open_in_place(&mut peer_copy)
            .expect("original peer must open");
        assert_eq!(opened.plaintext(), b"same-key");
        let opened = reference
            .open_in_place(&mut record)
            .expect("raw-parts layer must agree on the first record");
        assert_eq!(opened.plaintext(), b"same-key");

        let rendered = format!("{imported:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("dbfa"));
    }

    #[test]
    fn raw_parts_reject_unsupported_key_lengths() {
        for length in [0_usize, 8, 15, 17, 31, 33, 48] {
            assert_eq!(
                TrafficKeys::from_raw_parts(&vec![0x55; length], [0; 12]).unwrap_err(),
                Tls13KeyScheduleError::InvalidLength
            );
        }
        assert!(TrafficKeys::from_raw_parts(&[0x55; 16], [0; 12]).is_ok());
        assert!(TrafficKeys::from_raw_parts(&[0x55; 32], [0; 12]).is_ok());
    }

    /// D9 cross-provider equivalence: the RustCrypto AES-128-GCM primitive and
    /// ring must produce byte-identical output for identical
    /// key/nonce/AAD/plaintext, using the record layer's exact nonce
    /// derivation (`iv XOR sequence`). Together with the RFC 8448 byte-exact
    /// tests above — which pass under both feature configurations — this
    /// proves the ring backend is wire-identical to the RustCrypto one.
    #[test]
    fn aes128_gcm_rustcrypto_and_ring_are_byte_identical() {
        use aes_gcm::{
            Aes128Gcm as RustCryptoAes128,
            aead::{AeadInOut, KeyInit as _, Nonce as RustCryptoNonce, array::Array},
        };

        let key = [0x42_u8; 16];
        let iv = [0x24_u8; 12];
        let aad = [23, 3, 3, 0x40, 0x11];
        let rustcrypto = RustCryptoAes128::new(&Array(key));
        let ring_key = ring::aead::LessSafeKey::new(
            ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, &key).expect("ring key"),
        );
        let derive_nonce = |sequence: u64| {
            let mut nonce = iv;
            for (nonce_byte, sequence_byte) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
                *nonce_byte ^= sequence_byte;
            }
            nonce
        };
        let rc_open = |body: &mut [u8], plaintext_len: usize, nonce: [u8; 12], aad: &[u8]| {
            let (ciphertext, tag) = body.split_at_mut(plaintext_len);
            let nonce: RustCryptoNonce<RustCryptoAes128> = Array(nonce);
            let tag: aes_gcm::aead::Tag<RustCryptoAes128> =
                Array(*tag.first_chunk::<16>().expect("tag length"));
            rustcrypto.decrypt_inout_detached(&nonce, aad, ciphertext.into(), &tag)
        };
        let ring_open = |body: &mut [u8], nonce: [u8; 12], aad: &[u8]| {
            ring_key
                .open_in_place(
                    ring::aead::Nonce::assume_unique_for_key(nonce),
                    ring::aead::Aad::from(aad),
                    body,
                )
                .map(|_| ())
        };

        for plaintext_len in [0_usize, 1, 64, 1024, 4096, 16_384] {
            let plaintext: Vec<u8> = (0..plaintext_len)
                .map(|index| (index * 31 + 7) as u8)
                .collect();
            for sequence in [0_u64, 1, 255, 65_536, (1 << 24) - 1] {
                let nonce = derive_nonce(sequence);

                let mut rc_body = plaintext.clone();
                let rc_nonce: RustCryptoNonce<RustCryptoAes128> = Array(nonce);
                let rc_tag = rustcrypto
                    .encrypt_inout_detached(&rc_nonce, &aad, rc_body.as_mut_slice().into())
                    .expect("RustCrypto seal");

                let mut ring_body = plaintext.clone();
                let ring_tag = ring_key
                    .seal_in_place_separate_tag(
                        ring::aead::Nonce::assume_unique_for_key(nonce),
                        ring::aead::Aad::from(&aad),
                        &mut ring_body,
                    )
                    .expect("ring seal");

                assert_eq!(
                    rc_body, ring_body,
                    "ciphertext mismatch at len {plaintext_len} seq {sequence}"
                );
                assert_eq!(
                    rc_tag.as_slice(),
                    ring_tag.as_ref(),
                    "tag mismatch at len {plaintext_len} seq {sequence}"
                );

                // Cross-open: each provider authenticates the other's record.
                let mut wire = ring_body.clone();
                wire.extend_from_slice(ring_tag.as_ref());
                ring_open(&mut wire.clone(), nonce, &aad).expect("ring opens its own record");
                let mut rc_wire = wire.clone();
                rc_open(&mut rc_wire, plaintext_len, nonce, &aad)
                    .expect("RustCrypto opens the ring record");
                assert_eq!(&rc_wire[..plaintext_len], plaintext.as_slice());

                // Corrupted tag, corrupted ciphertext, wrong AAD, and wrong
                // nonce must be rejected by both providers.
                let mut bad_tag = wire.clone();
                let tag_byte = bad_tag.len() - 1;
                bad_tag[tag_byte] ^= 1;
                assert!(ring_open(&mut bad_tag.clone(), nonce, &aad).is_err());
                assert!(rc_open(&mut bad_tag, plaintext_len, nonce, &aad).is_err());

                if plaintext_len > 0 {
                    let mut bad_ciphertext = wire.clone();
                    bad_ciphertext[0] ^= 1;
                    assert!(ring_open(&mut bad_ciphertext.clone(), nonce, &aad).is_err());
                    assert!(rc_open(&mut bad_ciphertext, plaintext_len, nonce, &aad).is_err());
                }

                let bad_aad = [23, 3, 3, 0x40, 0x12];
                assert!(ring_open(&mut wire.clone(), nonce, &bad_aad).is_err());
                assert!(rc_open(&mut wire.clone(), plaintext_len, nonce, &bad_aad).is_err());

                let wrong_nonce = derive_nonce(sequence.wrapping_add(1));
                assert!(ring_open(&mut wire.clone(), wrong_nonce, &aad).is_err());
                assert!(rc_open(&mut wire.clone(), plaintext_len, wrong_nonce, &aad).is_err());
            }
        }
    }

    /// The same cross-provider equivalence the AES-128-GCM test proves, for the
    /// two suites that moved from RustCrypto to ring.
    ///
    /// Both providers are compared as primitives rather than through
    /// `Tls13RecordLayer`, because the layer compiles against exactly one
    /// backend at a time; the layer's own nonce derivation (`iv XOR sequence`),
    /// record sizes and sequence numbers are reproduced here so the comparison
    /// is the production shape and not an abstract one.
    ///
    /// Equality of the sealed bytes is the protocol-compatibility claim.
    /// Rejection parity is the security claim: a record either provider refuses
    /// must be refused by the other, or swapping them would change which peer
    /// is accepted.
    #[test]
    fn the_alternate_suites_are_byte_identical_between_rustcrypto_and_ring() {
        use aes_gcm::{
            Aes256Gcm as RustCryptoAes256,
            aead::{AeadInOut, KeyInit as _, array::Array},
        };
        use chacha20poly1305::ChaCha20Poly1305 as RustCryptoChaCha;

        let key = [0x42_u8; 32];
        let iv = [0x24_u8; 12];
        let aad = [23, 3, 3, 0x40, 0x11];
        let derive_nonce = |sequence: u64| {
            let mut nonce = iv;
            for (nonce_byte, sequence_byte) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
                *nonce_byte ^= sequence_byte;
            }
            nonce
        };

        let aes = RustCryptoAes256::new(&Array(key));
        let chacha = RustCryptoChaCha::new(&Array(key));

        for (label, algorithm) in [
            ("AES-256-GCM", &ring::aead::AES_256_GCM),
            ("ChaCha20-Poly1305", &ring::aead::CHACHA20_POLY1305),
        ] {
            let ring_key = ring::aead::LessSafeKey::new(
                ring::aead::UnboundKey::new(algorithm, &key).expect("ring key"),
            );
            let is_aes = label == "AES-256-GCM";

            for plaintext_len in [0_usize, 1, 64, 1024, 4096, 16_384] {
                let plaintext: Vec<u8> = (0..plaintext_len)
                    .map(|index| (index * 31 + 7) as u8)
                    .collect();
                for sequence in [0_u64, 1, 255, 65_536, (1 << 24) - 1] {
                    let nonce = derive_nonce(sequence);

                    let mut rc_body = plaintext.clone();
                    let rc_tag = if is_aes {
                        aes.encrypt_inout_detached(
                            &Array(nonce),
                            &aad,
                            rc_body.as_mut_slice().into(),
                        )
                        .expect("RustCrypto seal")
                        .to_vec()
                    } else {
                        chacha
                            .encrypt_inout_detached(
                                &Array(nonce),
                                &aad,
                                rc_body.as_mut_slice().into(),
                            )
                            .expect("RustCrypto seal")
                            .to_vec()
                    };

                    let mut ring_body = plaintext.clone();
                    let ring_tag = ring_key
                        .seal_in_place_separate_tag(
                            ring::aead::Nonce::assume_unique_for_key(nonce),
                            ring::aead::Aad::from(&aad),
                            &mut ring_body,
                        )
                        .expect("ring seal");

                    assert_eq!(
                        rc_body, ring_body,
                        "{label} ciphertext differs at len {plaintext_len} sequence {sequence}"
                    );
                    assert_eq!(
                        rc_tag,
                        ring_tag.as_ref(),
                        "{label} tag differs at len {plaintext_len} sequence {sequence}"
                    );

                    // Rejection parity: ring opens the contiguous body, so build
                    // the wire form once and tamper with it.
                    let mut wire = ring_body.clone();
                    wire.extend_from_slice(ring_tag.as_ref());
                    let ring_open = |body: &mut Vec<u8>, nonce: [u8; 12], aad: &[u8]| {
                        ring_key
                            .open_in_place(
                                ring::aead::Nonce::assume_unique_for_key(nonce),
                                ring::aead::Aad::from(aad),
                                body.as_mut_slice(),
                            )
                            .map(|_| ())
                    };
                    let rc_open = |body: &mut Vec<u8>, nonce: [u8; 12], aad: &[u8]| {
                        let (ciphertext, tag) = body.split_at_mut(plaintext_len);
                        let tag = *tag.first_chunk::<16>().expect("tag length");
                        if is_aes {
                            aes.decrypt_inout_detached(
                                &Array(nonce),
                                aad,
                                ciphertext.into(),
                                &Array(tag),
                            )
                        } else {
                            chacha.decrypt_inout_detached(
                                &Array(nonce),
                                aad,
                                ciphertext.into(),
                                &Array(tag),
                            )
                        }
                    };

                    assert!(ring_open(&mut wire.clone(), nonce, &aad).is_ok(), "{label}");
                    assert!(rc_open(&mut wire.clone(), nonce, &aad).is_ok(), "{label}");

                    let mut bad_tag = wire.clone();
                    let last = bad_tag.len() - 1;
                    bad_tag[last] ^= 1;
                    assert!(
                        ring_open(&mut bad_tag.clone(), nonce, &aad).is_err(),
                        "{label}"
                    );
                    assert!(rc_open(&mut bad_tag, nonce, &aad).is_err(), "{label}");

                    if plaintext_len > 0 {
                        let mut bad_ciphertext = wire.clone();
                        bad_ciphertext[0] ^= 1;
                        assert!(
                            ring_open(&mut bad_ciphertext.clone(), nonce, &aad).is_err(),
                            "{label}"
                        );
                        assert!(
                            rc_open(&mut bad_ciphertext, nonce, &aad).is_err(),
                            "{label}"
                        );
                    }

                    let bad_aad = [23, 3, 3, 0x40, 0x12];
                    assert!(
                        ring_open(&mut wire.clone(), nonce, &bad_aad).is_err(),
                        "{label}"
                    );
                    assert!(
                        rc_open(&mut wire.clone(), nonce, &bad_aad).is_err(),
                        "{label}"
                    );

                    let wrong_nonce = derive_nonce(sequence.wrapping_add(1));
                    assert!(
                        ring_open(&mut wire.clone(), wrong_nonce, &aad).is_err(),
                        "{label}"
                    );
                    assert!(
                        rc_open(&mut wire.clone(), wrong_nonce, &aad).is_err(),
                        "{label}"
                    );
                }
            }
        }
    }

    fn paired_layers(suite: CipherSuite) -> (Tls13RecordLayer, Tls13RecordLayer) {
        let transcript = suite.hash().digest(b"ClientHelloServerHello");
        let writer_schedule = Tls13KeySchedule::new(suite, &[0x42; 32], &transcript)
            .expect("test schedule must derive");
        let reader_schedule = Tls13KeySchedule::new(suite, &[0x42; 32], &transcript)
            .expect("test schedule must derive");
        let writer_keys = writer_schedule
            .traffic_keys(writer_schedule.server_handshake_secret())
            .expect("test write keys must derive");
        let reader_keys = reader_schedule
            .traffic_keys(reader_schedule.server_handshake_secret())
            .expect("test read keys must derive");
        (
            Tls13RecordLayer::new(suite, writer_keys).expect("test writer must initialize"),
            Tls13RecordLayer::new(suite, reader_keys).expect("test reader must initialize"),
        )
    }

    fn rfc8448_schedule() -> Tls13KeySchedule {
        let shared_secret =
            hex_vec("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        let transcript = TranscriptHash::from_bytes(
            HashAlgorithm::Sha256,
            &hex_vec("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"),
        )
        .expect("RFC 8448 transcript must import");
        Tls13KeySchedule::new(CipherSuite::Aes128GcmSha256, &shared_secret, &transcript)
            .expect("RFC 8448 schedule must derive")
    }

    fn hex_vec(encoded: &str) -> Vec<u8> {
        encoded
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>()
            .chunks_exact(2)
            .map(|pair| {
                let decode = |byte| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("test hex must be lowercase"),
                };
                (decode(pair[0]) << 4) | decode(pair[1])
            })
            .collect()
    }
}
