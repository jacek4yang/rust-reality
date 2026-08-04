use std::{error::Error, fmt};

use aes_gcm::{
    Aes128Gcm, Aes256Gcm,
    aead::{AeadInOut, KeyInit, Nonce, Tag, array::Array},
};
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

enum RecordCipher {
    Aes128Gcm(Box<Aes128Gcm>),
    Aes256Gcm(Box<Aes256Gcm>),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl RecordCipher {
    fn new(suite: CipherSuite, key: &[u8]) -> Result<Self, Tls13RecordError> {
        match suite {
            CipherSuite::Aes128GcmSha256 => Aes128Gcm::new_from_slice(key)
                .map(Box::new)
                .map(Self::Aes128Gcm)
                .map_err(|_| Tls13RecordError::InvalidKey),
            CipherSuite::Aes256GcmSha384 => Aes256Gcm::new_from_slice(key)
                .map(Box::new)
                .map(Self::Aes256Gcm)
                .map_err(|_| Tls13RecordError::InvalidKey),
            CipherSuite::ChaCha20Poly1305Sha256 => ChaCha20Poly1305::new_from_slice(key)
                .map(Self::ChaCha20Poly1305)
                .map_err(|_| Tls13RecordError::InvalidKey),
        }
    }

    fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &mut [u8],
    ) -> Result<[u8; TAG_LEN], Tls13RecordError> {
        let mut output = [0_u8; TAG_LEN];
        match self {
            Self::Aes128Gcm(cipher) => {
                let nonce: Nonce<Aes128Gcm> = Array(*nonce);
                let tag = cipher
                    .encrypt_inout_detached(&nonce, aad, plaintext.into())
                    .map_err(|_| Tls13RecordError::AuthenticationFailed)?;
                output.copy_from_slice(&tag);
            }
            Self::Aes256Gcm(cipher) => {
                let nonce: Nonce<Aes256Gcm> = Array(*nonce);
                let tag = cipher
                    .encrypt_inout_detached(&nonce, aad, plaintext.into())
                    .map_err(|_| Tls13RecordError::AuthenticationFailed)?;
                output.copy_from_slice(&tag);
            }
            Self::ChaCha20Poly1305(cipher) => {
                let nonce: Nonce<ChaCha20Poly1305> = Array(*nonce);
                let tag = cipher
                    .encrypt_inout_detached(&nonce, aad, plaintext.into())
                    .map_err(|_| Tls13RecordError::AuthenticationFailed)?;
                output.copy_from_slice(&tag);
            }
        }
        Ok(output)
    }

    fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), Tls13RecordError> {
        match self {
            Self::Aes128Gcm(cipher) => {
                let nonce: Nonce<Aes128Gcm> = Array(*nonce);
                let tag: Tag<Aes128Gcm> = Array(*tag);
                cipher
                    .decrypt_inout_detached(&nonce, aad, ciphertext.into(), &tag)
                    .map_err(|_| Tls13RecordError::AuthenticationFailed)
            }
            Self::Aes256Gcm(cipher) => {
                let nonce: Nonce<Aes256Gcm> = Array(*nonce);
                let tag: Tag<Aes256Gcm> = Array(*tag);
                cipher
                    .decrypt_inout_detached(&nonce, aad, ciphertext.into(), &tag)
                    .map_err(|_| Tls13RecordError::AuthenticationFailed)
            }
            Self::ChaCha20Poly1305(cipher) => {
                let nonce: Nonce<ChaCha20Poly1305> = Array(*nonce);
                let tag: Tag<ChaCha20Poly1305> = Array(*tag);
                cipher
                    .decrypt_inout_detached(&nonce, aad, ciphertext.into(), &tag)
                    .map_err(|_| Tls13RecordError::AuthenticationFailed)
            }
        }
    }
}

impl fmt::Debug for RecordCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Aes128Gcm(_) => "AES-128-GCM",
            Self::Aes256Gcm(_) => "AES-256-GCM",
            Self::ChaCha20Poly1305(_) => "ChaCha20-Poly1305",
        };
        formatter.debug_tuple("RecordCipher").field(&name).finish()
    }
}

/// Directional TLS 1.3 AEAD state with non-reusable sequence ownership.
///
/// The type deliberately does not implement `Clone`: copying it would reuse a
/// key/nonce pair and break AEAD security.
pub struct Tls13RecordLayer {
    cipher: RecordCipher,
    suite: CipherSuite,
    iv: [u8; NONCE_LEN],
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
        let iv = *keys.iv();
        Ok(Self {
            cipher,
            suite,
            iv,
            sequence: 0,
        })
    }

    /// Returns how many records have successfully used this traffic key.
    #[must_use]
    pub const fn records_used(&self) -> u64 {
        self.sequence
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

    /// Authenticates and decrypts exactly one complete TLS 1.3 record in place.
    ///
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
        let (ciphertext, tag) = body.split_at_mut(encrypted_len);
        let tag: [u8; TAG_LEN] = tag
            .try_into()
            .map_err(|_| Tls13RecordError::InvalidLength)?;
        let nonce = self.nonce();
        self.cipher.open(&nonce, &header, ciphertext, &tag)?;
        self.advance()?;

        let content_type_offset = ciphertext
            .iter()
            .rposition(|byte| *byte != 0)
            .ok_or(Tls13RecordError::InvalidContentType)?;
        let content_type = ContentType::from_wire(ciphertext[content_type_offset])
            .ok_or(Tls13RecordError::InvalidContentType)?;
        let plaintext = ciphertext
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
        let mut nonce = self.iv;
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

#[cfg(test)]
mod tests {
    use super::{ContentType, Tls13RecordError, Tls13RecordLayer};
    use crate::protocol::reality::tls13::{
        CipherSuite, HashAlgorithm, Tls13KeySchedule, TranscriptHash,
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
