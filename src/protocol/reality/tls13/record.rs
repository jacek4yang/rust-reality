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

use zeroize::Zeroizing;

use super::{CipherSuite, TrafficKeys, TrafficSecret, keys::derive_traffic_keys};

const HEADER_LEN: usize = 5;
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const OUTER_APPLICATION_DATA: u8 = 23;
const LEGACY_RECORD_VERSION: [u8; 2] = [3, 3];
const MAX_INNER_PLAINTEXT_LEN: usize = MAX_PLAINTEXT_LEN + 1;
const MAX_CIPHERTEXT_LEN: usize = MAX_INNER_PLAINTEXT_LEN + TAG_LEN;
const AES_GCM_RECORD_LIMIT: u64 = 1 << 24;
const CHACHA20_POLY1305_RECORD_LIMIT: u64 = 1 << 62;

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
    /// A traffic secret or derived key does not match the selected suite.
    InvalidKey,
    /// The record layer was not constructed from an evolvable traffic secret.
    KeyUpdateUnavailable,
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
    /// Ciphertext delivery was interrupted, so this direction cannot be resumed.
    WriteFailed,
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
/// exactly once per sealed/opened record, AES-GCM generations are retired at
/// the conservative 2^24 record limit, and ChaCha20-Poly1305 generations at
/// RFC 8446's 2^62 limit. ring's `assume_unique_for_key` therefore always
/// receives a nonce that is unique under this key.
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

    /// Replaces the key inside the existing cipher allocation.
    ///
    /// The backend key is fully constructed before assignment, so failure
    /// leaves the current cipher untouched and KeyUpdate adds no allocation.
    fn rekey(&mut self, suite: CipherSuite, key: &[u8]) -> Result<(), Tls13RecordError> {
        #[cfg(feature = "ring-aead")]
        {
            let algorithm = match suite {
                CipherSuite::Aes128GcmSha256 => &ring::aead::AES_128_GCM,
                CipherSuite::Aes256GcmSha384 => &ring::aead::AES_256_GCM,
                CipherSuite::ChaCha20Poly1305Sha256 => &ring::aead::CHACHA20_POLY1305,
            };
            let next = ring::aead::UnboundKey::new(algorithm, key)
                .map(ring::aead::LessSafeKey::new)
                .map_err(|_| Tls13RecordError::InvalidKey)?;
            *self.inner = next;
        }
        #[cfg(not(feature = "ring-aead"))]
        {
            match (&mut self.inner, suite) {
                (RustCryptoRecordCipher::Aes128Gcm(current), CipherSuite::Aes128GcmSha256) => {
                    let next =
                        Aes128Gcm::new_from_slice(key).map_err(|_| Tls13RecordError::InvalidKey)?;
                    **current = next;
                }
                (RustCryptoRecordCipher::Aes256Gcm(current), CipherSuite::Aes256GcmSha384) => {
                    let next =
                        Aes256Gcm::new_from_slice(key).map_err(|_| Tls13RecordError::InvalidKey)?;
                    **current = next;
                }
                (
                    RustCryptoRecordCipher::ChaCha20Poly1305(current),
                    CipherSuite::ChaCha20Poly1305Sha256,
                ) => {
                    let next = ChaCha20Poly1305::new_from_slice(key)
                        .map_err(|_| Tls13RecordError::InvalidKey)?;
                    **current = next;
                }
                _ => return Err(Tls13RecordError::InvalidKey),
            }
        }
        self.suite = suite;
        Ok(())
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
/// key/nonce pair and break AEAD security. Application layers retain the
/// current traffic secret so they can evolve it or export it exactly once at a
/// session-handoff boundary. Handshake layers retain no generation secret and
/// therefore cannot be exported or updated.
pub struct Tls13RecordLayer {
    cipher: RecordCipher,
    suite: CipherSuite,
    iv: Zeroizing<[u8; NONCE_LEN]>,
    traffic: TrafficState,
    sequence: u64,
    write_failed: bool,
    #[cfg(test)]
    test_key_usage_limit: Option<u64>,
}

enum TrafficState {
    Handshake,
    Application(TrafficSecret),
}

impl Tls13RecordLayer {
    /// Constructs a non-evolvable handshake record layer from derived keys.
    ///
    /// # Errors
    ///
    /// Rejects key material whose length does not match the suite.
    pub fn new(suite: CipherSuite, keys: TrafficKeys) -> Result<Self, Tls13RecordError> {
        let cipher = RecordCipher::new(suite, keys.key())?;
        Ok(Self {
            cipher,
            suite,
            iv: Zeroizing::new(*keys.iv()),
            traffic: TrafficState::Handshake,
            sequence: 0,
            write_failed: false,
            #[cfg(test)]
            test_key_usage_limit: None,
        })
    }

    /// Constructs an evolvable application record layer from its traffic secret.
    ///
    /// # Errors
    ///
    /// Rejects a traffic secret whose hash does not match the suite or whose
    /// derived key cannot initialize the suite's record cipher.
    pub fn from_traffic_secret(
        suite: CipherSuite,
        traffic_secret: TrafficSecret,
    ) -> Result<Self, Tls13RecordError> {
        let keys = derive_traffic_keys(suite, &traffic_secret)
            .map_err(|_| Tls13RecordError::InvalidKey)?;
        let cipher = RecordCipher::new(suite, keys.key())?;
        Ok(Self {
            cipher,
            suite,
            iv: Zeroizing::new(*keys.iv()),
            traffic: TrafficState::Application(traffic_secret),
            sequence: 0,
            write_failed: false,
            #[cfg(test)]
            test_key_usage_limit: None,
        })
    }

    /// Returns how many records have successfully used this traffic key.
    #[must_use]
    pub const fn records_used(&self) -> u64 {
        self.sequence
    }

    /// Returns whether exactly one safe old-generation record remains.
    ///
    /// A writer uses that final record for `KeyUpdate`, completes its write,
    /// and only then advances the traffic secret. No configurable threshold is
    /// involved, and this check performs no allocation or cryptographic work.
    #[must_use]
    pub const fn needs_key_update(&self) -> bool {
        self.sequence >= self.key_usage_limit() - 1
    }

    /// Permanently rejects a direction whose sealed ciphertext was not delivered.
    pub(crate) fn fail_write(&mut self) {
        self.write_failed = true;
    }

    pub(crate) const fn ensure_write_ready(&self) -> Result<(), Tls13RecordError> {
        if self.write_failed {
            Err(Tls13RecordError::WriteFailed)
        } else {
            Ok(())
        }
    }

    /// Lowers the record budget without skipping sequences or changing secrets.
    #[cfg(test)]
    pub(crate) fn set_test_key_usage_limit(&mut self, limit: u64) {
        assert!(limit >= 2 && limit <= self.key_usage_limit());
        self.test_key_usage_limit = Some(limit);
    }

    /// Atomically advances an application layer to its next traffic secret.
    ///
    /// The next secret, key, IV, and cipher are all constructed before any live
    /// state changes. If any derivation or cipher initialization fails, the
    /// current generation and sequence remain intact. The sequence resets only
    /// after the replacement cipher is ready.
    ///
    /// # Errors
    ///
    /// Rejects handshake-only layers and traffic-secret derivation or cipher
    /// initialization failures.
    pub fn update_traffic_secret(&mut self) -> Result<(), Tls13RecordError> {
        self.ensure_write_ready()?;
        let current = match &self.traffic {
            TrafficState::Application(secret) => secret,
            TrafficState::Handshake => return Err(Tls13RecordError::KeyUpdateUnavailable),
        };
        let next_secret = current
            .updated()
            .map_err(|_| Tls13RecordError::InvalidKey)?;
        let next_keys = derive_traffic_keys(self.suite, &next_secret)
            .map_err(|_| Tls13RecordError::InvalidKey)?;
        let next_iv = Zeroizing::new(*next_keys.iv());

        self.cipher.rekey(self.suite, next_keys.key())?;
        self.iv = next_iv;
        self.traffic = TrafficState::Application(next_secret);
        self.sequence = 0;
        Ok(())
    }

    /// Consumes an application layer and exports its current secret and sequence.
    ///
    /// This is the session-handoff escape hatch: the exported state is the only
    /// remaining owner of this direction's generation secret and sequence.
    ///
    /// # Errors
    ///
    /// Rejects handshake-only layers and directions with ambiguous ciphertext delivery.
    pub fn into_exported_state(self) -> Result<ExportedRecordState, Tls13RecordError> {
        self.ensure_write_ready()?;
        let traffic_secret = match self.traffic {
            TrafficState::Application(secret) => secret,
            TrafficState::Handshake => return Err(Tls13RecordError::KeyUpdateUnavailable),
        };
        Ok(ExportedRecordState {
            suite: self.suite,
            traffic_secret,
            sequence: self.sequence,
        })
    }

    /// Rebuilds a working layer from previously exported state.
    ///
    /// # Errors
    ///
    /// Rejects a secret whose hash does not match the suite and sequences that
    /// already reached the suite's per-key record limit.
    pub fn from_exported_state(state: ExportedRecordState) -> Result<Self, Tls13RecordError> {
        let mut layer = Self::from_traffic_secret(state.suite, state.traffic_secret)?;
        layer.sequence = state.sequence;
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

    const fn key_usage_limit(&self) -> u64 {
        #[cfg(test)]
        if let Some(limit) = self.test_key_usage_limit {
            return limit;
        }
        match self.suite {
            CipherSuite::Aes128GcmSha256 | CipherSuite::Aes256GcmSha384 => AES_GCM_RECORD_LIMIT,
            CipherSuite::ChaCha20Poly1305Sha256 => CHACHA20_POLY1305_RECORD_LIMIT,
        }
    }

    fn ensure_key_available(&self) -> Result<(), Tls13RecordError> {
        self.ensure_write_ready()?;
        let available = self.sequence < self.key_usage_limit();
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
        let mut nonce = *self.iv;
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
            .field("traffic_secret", &"[REDACTED]")
            .finish()
    }
}

/// One record direction's exported application-traffic state.
///
/// Created only by consuming a live application [`Tls13RecordLayer`], so the
/// generation secret and sequence can never have two owners. The secret is
/// zeroized on drop and never appears in `Debug` output.
pub struct ExportedRecordState {
    suite: CipherSuite,
    traffic_secret: TrafficSecret,
    sequence: u64,
}

impl ExportedRecordState {
    /// Returns the cipher suite the exported secret belongs to.
    #[must_use]
    pub const fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// Returns the exported generation secret.
    #[must_use]
    pub const fn traffic_secret(&self) -> &TrafficSecret {
        &self.traffic_secret
    }

    /// Returns how many records had been sealed or opened at export time.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Separates the exported state into suite, generation secret, and sequence.
    #[must_use]
    pub fn into_parts(self) -> (CipherSuite, TrafficSecret, u64) {
        (self.suite, self.traffic_secret, self.sequence)
    }

    /// Reassembles one direction's exported state from received parts.
    ///
    /// # Errors
    ///
    /// Rejects a traffic secret whose hash does not match the suite.
    pub fn from_parts(
        suite: CipherSuite,
        traffic_secret: TrafficSecret,
        sequence: u64,
    ) -> Result<Self, Tls13RecordError> {
        if traffic_secret.algorithm() != suite.hash() {
            return Err(Tls13RecordError::InvalidKey);
        }
        Ok(Self {
            suite,
            traffic_secret,
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
            .field("traffic_secret", &"[REDACTED]")
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
mod tests;
