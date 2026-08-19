use std::{error::Error, fmt};

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256, Sha384};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAX_HASH_BYTES: usize = 48;
const TLS13_LABEL_PREFIX: &[u8] = b"tls13 ";

/// TLS 1.3 cipher suites accepted by the dedicated REALITY state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherSuite {
    /// TLS_AES_128_GCM_SHA256.
    Aes128GcmSha256,
    /// TLS_AES_256_GCM_SHA384.
    Aes256GcmSha384,
    /// TLS_CHACHA20_POLY1305_SHA256.
    ChaCha20Poly1305Sha256,
}

impl CipherSuite {
    /// Converts an IANA wire identifier into a supported suite.
    #[must_use]
    pub const fn from_wire(value: u16) -> Option<Self> {
        match value {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            0x1303 => Some(Self::ChaCha20Poly1305Sha256),
            _ => None,
        }
    }

    /// Returns the IANA wire identifier.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::Aes256GcmSha384 => 0x1302,
            Self::ChaCha20Poly1305Sha256 => 0x1303,
        }
    }

    /// Returns the transcript and HKDF hash selected by this suite.
    #[must_use]
    pub const fn hash(self) -> HashAlgorithm {
        match self {
            Self::Aes128GcmSha256 | Self::ChaCha20Poly1305Sha256 => HashAlgorithm::Sha256,
            Self::Aes256GcmSha384 => HashAlgorithm::Sha384,
        }
    }

    pub(crate) const fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha384 | Self::ChaCha20Poly1305Sha256 => 32,
        }
    }
}

/// Hash algorithms used by the supported TLS 1.3 cipher suites.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashAlgorithm {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
}

impl HashAlgorithm {
    /// Returns the digest length in bytes.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    /// Computes a transcript hash without retaining the input messages.
    #[must_use]
    pub fn digest(self, messages: &[u8]) -> TranscriptHash {
        let mut bytes = [0_u8; MAX_HASH_BYTES];
        match self {
            Self::Sha256 => bytes[..32].copy_from_slice(&Sha256::digest(messages)),
            Self::Sha384 => bytes.copy_from_slice(&Sha384::digest(messages)),
        }
        TranscriptHash {
            algorithm: self,
            bytes,
        }
    }

    fn extract(self, salt: &[u8], input: &[u8]) -> Secret {
        let mut bytes = [0_u8; MAX_HASH_BYTES];
        match self {
            Self::Sha256 => {
                let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), input);
                let prk = Zeroizing::new(prk);
                bytes[..32].copy_from_slice(prk.as_slice());
            }
            Self::Sha384 => {
                let (prk, _) = Hkdf::<Sha384>::extract(Some(salt), input);
                let prk = Zeroizing::new(prk);
                bytes.copy_from_slice(prk.as_slice());
            }
        }
        Secret {
            algorithm: self,
            bytes,
        }
    }

    fn expand_label(
        self,
        secret: &Secret,
        label: &[u8],
        context: &[u8],
        output: &mut [u8],
    ) -> Result<(), Tls13KeyScheduleError> {
        if secret.algorithm != self {
            return Err(Tls13KeyScheduleError::HashMismatch);
        }
        let info = encode_hkdf_label(label, context, output.len())?;
        match self {
            Self::Sha256 => Hkdf::<Sha256>::from_prk(secret.as_bytes())
                .map_err(|_| Tls13KeyScheduleError::Crypto)?
                .expand(&info, output)
                .map_err(|_| Tls13KeyScheduleError::InvalidLength),
            Self::Sha384 => Hkdf::<Sha384>::from_prk(secret.as_bytes())
                .map_err(|_| Tls13KeyScheduleError::Crypto)?
                .expand(&info, output)
                .map_err(|_| Tls13KeyScheduleError::InvalidLength),
        }
    }

    fn derive_secret(
        self,
        secret: &Secret,
        label: &[u8],
        transcript_hash: &TranscriptHash,
    ) -> Result<Secret, Tls13KeyScheduleError> {
        if transcript_hash.algorithm != self {
            return Err(Tls13KeyScheduleError::HashMismatch);
        }
        let mut output = Secret::zeroed(self);
        self.expand_label(
            secret,
            label,
            transcript_hash.as_bytes(),
            output.as_bytes_mut(),
        )?;
        Ok(output)
    }

    fn hmac(self, key: &[u8], input: &[u8]) -> Result<FinishedVerifyData, Tls13KeyScheduleError> {
        let mut output = FinishedVerifyData::zeroed(self);
        match self {
            Self::Sha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key)
                    .map_err(|_| Tls13KeyScheduleError::Crypto)?;
                mac.update(input);
                output.bytes[..32].copy_from_slice(&mac.finalize().into_bytes());
            }
            Self::Sha384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(key)
                    .map_err(|_| Tls13KeyScheduleError::Crypto)?;
                mac.update(input);
                output.bytes.copy_from_slice(&mac.finalize().into_bytes());
            }
        }
        Ok(output)
    }
}

/// One fixed-size transcript digest tagged with its algorithm.
#[derive(Clone, Eq, PartialEq)]
pub struct TranscriptHash {
    algorithm: HashAlgorithm,
    bytes: [u8; MAX_HASH_BYTES],
}

impl TranscriptHash {
    /// Imports a digest only when it has the exact algorithm length.
    ///
    /// # Errors
    ///
    /// Rejects truncated and oversized digests.
    pub fn from_bytes(
        algorithm: HashAlgorithm,
        input: &[u8],
    ) -> Result<Self, Tls13KeyScheduleError> {
        if input.len() != algorithm.output_len() {
            return Err(Tls13KeyScheduleError::InvalidLength);
        }
        let mut bytes = [0_u8; MAX_HASH_BYTES];
        let output = bytes
            .get_mut(..input.len())
            .ok_or(Tls13KeyScheduleError::InvalidLength)?;
        output.copy_from_slice(input);
        Ok(Self { algorithm, bytes })
    }

    /// Returns the digest algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Returns exactly the initialized digest bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
            .get(..self.algorithm.output_len())
            .unwrap_or_default()
    }
}

impl fmt::Debug for TranscriptHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TranscriptHash")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// Incremental hash state over the handshake transcript.
///
/// Each [`TranscriptHasher::snapshot`] finalizes a clone of the running
/// state, so repeated transcript digests cost one pass over the messages
/// instead of one from-scratch digest per snapshot. Snapshots are
/// byte-identical to [`HashAlgorithm::digest`] over the concatenated updates.
#[derive(Clone)]
pub(crate) struct TranscriptHasher {
    algorithm: HashAlgorithm,
    state: TranscriptHasherState,
}

#[derive(Clone)]
enum TranscriptHasherState {
    Sha256(Sha256),
    Sha384(Sha384),
}

impl TranscriptHasher {
    /// Starts an empty transcript hash for `algorithm`.
    #[must_use]
    pub(crate) fn new(algorithm: HashAlgorithm) -> Self {
        let state = match algorithm {
            HashAlgorithm::Sha256 => TranscriptHasherState::Sha256(Sha256::new()),
            HashAlgorithm::Sha384 => TranscriptHasherState::Sha384(Sha384::new()),
        };
        Self { algorithm, state }
    }

    /// Appends the next handshake message bytes to the transcript.
    pub(crate) fn update(&mut self, message: &[u8]) {
        match &mut self.state {
            TranscriptHasherState::Sha256(state) => state.update(message),
            TranscriptHasherState::Sha384(state) => state.update(message),
        }
    }

    /// Finalizes a clone of the running state into a transcript snapshot.
    #[must_use]
    pub(crate) fn snapshot(&self) -> TranscriptHash {
        let mut bytes = [0_u8; MAX_HASH_BYTES];
        match &self.state {
            TranscriptHasherState::Sha256(state) => {
                bytes[..32].copy_from_slice(&state.clone().finalize());
            }
            TranscriptHasherState::Sha384(state) => {
                bytes.copy_from_slice(&state.clone().finalize());
            }
        }
        TranscriptHash {
            algorithm: self.algorithm,
            bytes,
        }
    }
}

#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
struct Secret {
    #[zeroize(skip)]
    algorithm: HashAlgorithm,
    bytes: [u8; MAX_HASH_BYTES],
}

impl Secret {
    const fn zeroed(algorithm: HashAlgorithm) -> Self {
        Self {
            algorithm,
            bytes: [0_u8; MAX_HASH_BYTES],
        }
    }

    fn as_bytes(&self) -> &[u8] {
        self.bytes
            .get(..self.algorithm.output_len())
            .unwrap_or_default()
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        let length = self.algorithm.output_len();
        self.bytes.get_mut(..length).unwrap_or_default()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}

/// One directional TLS traffic secret, zeroized on drop.
#[derive(Eq, PartialEq)]
pub struct TrafficSecret(Secret);

impl fmt::Debug for TrafficSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrafficSecret([REDACTED])")
    }
}

/// AEAD key and IV for one TLS record direction, zeroized on drop.
#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct TrafficKeys {
    key: [u8; 32],
    key_len: usize,
    iv: [u8; 12],
}

impl TrafficKeys {
    /// Rebuilds one direction's exported AEAD key material.
    ///
    /// Only the two key lengths the supported cipher suites use (16 and 32
    /// bytes) are accepted; consistency between the key length and a cipher
    /// suite is enforced when a record layer is reconstructed from the
    /// returned value.
    ///
    /// # Errors
    ///
    /// Rejects key lengths no supported cipher suite can use.
    pub fn from_raw_parts(key: &[u8], iv: [u8; 12]) -> Result<Self, Tls13KeyScheduleError> {
        if !matches!(key.len(), 16 | 32) {
            return Err(Tls13KeyScheduleError::InvalidLength);
        }
        let mut bytes = [0_u8; 32];
        if let Some(region) = bytes.get_mut(..key.len()) {
            region.copy_from_slice(key);
        }
        Ok(Self {
            key: bytes,
            key_len: key.len(),
            iv,
        })
    }

    /// Returns the suite-sized AEAD key.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        self.key.get(..self.key_len).unwrap_or_default()
    }

    /// Returns the 96-bit static IV.
    #[must_use]
    pub const fn iv(&self) -> &[u8; 12] {
        &self.iv
    }
}

impl fmt::Debug for TrafficKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrafficKeys([REDACTED])")
    }
}

/// TLS Finished `verify_data`, zeroized when its handshake state is dropped.
#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct FinishedVerifyData {
    #[zeroize(skip)]
    algorithm: HashAlgorithm,
    bytes: [u8; MAX_HASH_BYTES],
}

impl FinishedVerifyData {
    const fn zeroed(algorithm: HashAlgorithm) -> Self {
        Self {
            algorithm,
            bytes: [0_u8; MAX_HASH_BYTES],
        }
    }

    /// Returns exactly the wire `verify_data` bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
            .get(..self.algorithm.output_len())
            .unwrap_or_default()
    }
}

impl fmt::Debug for FinishedVerifyData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FinishedVerifyData([REDACTED])")
    }
}

/// Client and server application traffic secrets derived after server Finished.
#[derive(Debug, Eq, PartialEq)]
pub struct ApplicationTrafficSecrets {
    client: TrafficSecret,
    server: TrafficSecret,
}

impl ApplicationTrafficSecrets {
    /// Returns the client application traffic secret.
    #[must_use]
    pub const fn client(&self) -> &TrafficSecret {
        &self.client
    }

    /// Returns the server application traffic secret.
    #[must_use]
    pub const fn server(&self) -> &TrafficSecret {
        &self.server
    }
}

/// A TLS 1.3 key schedule input or derivation is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tls13KeyScheduleError {
    /// Cipher-suite hash and supplied digest disagree.
    HashMismatch,
    /// An input or encoded HKDF label has an invalid length.
    InvalidLength,
    /// The ECDHE or hybrid shared secret is empty or exceeds the fixed bound.
    InvalidSharedSecret,
    /// A mature cryptographic primitive rejected an invariant.
    Crypto,
}

impl fmt::Display for Tls13KeyScheduleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TLS 1.3 key schedule failed")
    }
}

impl Error for Tls13KeyScheduleError {}

/// TLS 1.3 no-PSK handshake and master secret state.
pub struct Tls13KeySchedule {
    suite: CipherSuite,
    master: Secret,
    client_handshake: TrafficSecret,
    server_handshake: TrafficSecret,
}

impl Tls13KeySchedule {
    /// Derives a no-PSK TLS 1.3 schedule from ECDHE and `ClientHello..ServerHello`.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversized shared secrets, a mismatched transcript digest,
    /// and any HKDF invariant failure.
    pub fn new(
        suite: CipherSuite,
        shared_secret: &[u8],
        client_hello_server_hello: &TranscriptHash,
    ) -> Result<Self, Tls13KeyScheduleError> {
        if shared_secret.is_empty() || shared_secret.len() > 128 {
            return Err(Tls13KeyScheduleError::InvalidSharedSecret);
        }
        let hash = suite.hash();
        if client_hello_server_hello.algorithm != hash {
            return Err(Tls13KeyScheduleError::HashMismatch);
        }
        let zeros = [0_u8; MAX_HASH_BYTES];
        let zero = zeros
            .get(..hash.output_len())
            .ok_or(Tls13KeyScheduleError::InvalidLength)?;
        let early = hash.extract(zero, zero);
        let empty_hash = hash.digest(&[]);
        let derived_early = hash.derive_secret(&early, b"derived", &empty_hash)?;
        let handshake = hash.extract(derived_early.as_bytes(), shared_secret);
        let client_handshake = TrafficSecret(hash.derive_secret(
            &handshake,
            b"c hs traffic",
            client_hello_server_hello,
        )?);
        let server_handshake = TrafficSecret(hash.derive_secret(
            &handshake,
            b"s hs traffic",
            client_hello_server_hello,
        )?);
        let derived_handshake = hash.derive_secret(&handshake, b"derived", &empty_hash)?;
        let master = hash.extract(derived_handshake.as_bytes(), zero);
        Ok(Self {
            suite,
            master,
            client_handshake,
            server_handshake,
        })
    }

    /// Returns the negotiated cipher suite.
    #[must_use]
    pub const fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// Returns the client handshake traffic secret.
    #[must_use]
    pub const fn client_handshake_secret(&self) -> &TrafficSecret {
        &self.client_handshake
    }

    /// Returns the server handshake traffic secret.
    #[must_use]
    pub const fn server_handshake_secret(&self) -> &TrafficSecret {
        &self.server_handshake
    }

    /// Derives one direction's AEAD key and static IV.
    ///
    /// # Errors
    ///
    /// Rejects a traffic secret from a different suite hash or HKDF failure.
    pub fn traffic_keys(
        &self,
        traffic_secret: &TrafficSecret,
    ) -> Result<TrafficKeys, Tls13KeyScheduleError> {
        let hash = self.suite.hash();
        if traffic_secret.0.algorithm != hash {
            return Err(Tls13KeyScheduleError::HashMismatch);
        }
        let key_len = self.suite.key_len();
        let mut keys = TrafficKeys {
            key: [0_u8; 32],
            key_len,
            iv: [0_u8; 12],
        };
        let key = keys
            .key
            .get_mut(..key_len)
            .ok_or(Tls13KeyScheduleError::InvalidLength)?;
        hash.expand_label(&traffic_secret.0, b"key", &[], key)?;
        hash.expand_label(&traffic_secret.0, b"iv", &[], &mut keys.iv)?;
        Ok(keys)
    }

    /// Computes TLS Finished `verify_data` over an explicit transcript digest.
    ///
    /// # Errors
    ///
    /// Rejects mismatched traffic-secret/transcript hashes or primitive failure.
    pub fn finished_verify_data(
        &self,
        traffic_secret: &TrafficSecret,
        transcript_hash: &TranscriptHash,
    ) -> Result<FinishedVerifyData, Tls13KeyScheduleError> {
        let hash = self.suite.hash();
        if traffic_secret.0.algorithm != hash || transcript_hash.algorithm != hash {
            return Err(Tls13KeyScheduleError::HashMismatch);
        }
        let mut finished_key = Secret::zeroed(hash);
        hash.expand_label(
            &traffic_secret.0,
            b"finished",
            &[],
            finished_key.as_bytes_mut(),
        )?;
        hash.hmac(finished_key.as_bytes(), transcript_hash.as_bytes())
    }

    /// Derives application secrets from the transcript through server Finished.
    ///
    /// # Errors
    ///
    /// Rejects a digest using a different suite hash or HKDF failure.
    pub fn application_traffic_secrets(
        &self,
        transcript_through_server_finished: &TranscriptHash,
    ) -> Result<ApplicationTrafficSecrets, Tls13KeyScheduleError> {
        let hash = self.suite.hash();
        if transcript_through_server_finished.algorithm != hash {
            return Err(Tls13KeyScheduleError::HashMismatch);
        }
        Ok(ApplicationTrafficSecrets {
            client: TrafficSecret(hash.derive_secret(
                &self.master,
                b"c ap traffic",
                transcript_through_server_finished,
            )?),
            server: TrafficSecret(hash.derive_secret(
                &self.master,
                b"s ap traffic",
                transcript_through_server_finished,
            )?),
        })
    }
}

impl fmt::Debug for Tls13KeySchedule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Tls13KeySchedule")
            .field("suite", &self.suite)
            .field("secrets", &"[REDACTED]")
            .finish()
    }
}

fn encode_hkdf_label(
    label: &[u8],
    context: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, Tls13KeyScheduleError> {
    let full_label_len = TLS13_LABEL_PREFIX
        .len()
        .checked_add(label.len())
        .ok_or(Tls13KeyScheduleError::InvalidLength)?;
    let full_label_len =
        u8::try_from(full_label_len).map_err(|_| Tls13KeyScheduleError::InvalidLength)?;
    let context_len =
        u8::try_from(context.len()).map_err(|_| Tls13KeyScheduleError::InvalidLength)?;
    let output_len = u16::try_from(output_len).map_err(|_| Tls13KeyScheduleError::InvalidLength)?;
    let capacity = 2_usize
        .checked_add(1)
        .and_then(|value| value.checked_add(usize::from(full_label_len)))
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(context.len()))
        .ok_or(Tls13KeyScheduleError::InvalidLength)?;
    let mut info = Vec::with_capacity(capacity);
    info.extend_from_slice(&output_len.to_be_bytes());
    info.push(full_label_len);
    info.extend_from_slice(TLS13_LABEL_PREFIX);
    info.extend_from_slice(label);
    info.push(context_len);
    info.extend_from_slice(context);
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::{CipherSuite, HashAlgorithm, Tls13KeySchedule, TranscriptHash, TranscriptHasher};

    #[test]
    fn rfc8448_simple_handshake_schedule_matches() {
        let shared_secret =
            hex_vec("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        let ch_sh = transcript(
            HashAlgorithm::Sha256,
            "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8",
        );
        let schedule = Tls13KeySchedule::new(CipherSuite::Aes128GcmSha256, &shared_secret, &ch_sh)
            .expect("RFC 8448 schedule must derive");

        assert_eq!(
            schedule.client_handshake_secret().0.as_bytes(),
            hex_vec("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
        );
        assert_eq!(
            schedule.server_handshake_secret().0.as_bytes(),
            hex_vec("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
        );
        assert_eq!(
            schedule.master.as_bytes(),
            hex_vec("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")
        );
    }

    #[test]
    fn rfc8448_handshake_keys_and_finished_match() {
        let schedule = rfc8448_schedule();
        let server_keys = schedule
            .traffic_keys(schedule.server_handshake_secret())
            .expect("server handshake keys must derive");
        let client_keys = schedule
            .traffic_keys(schedule.client_handshake_secret())
            .expect("client handshake keys must derive");

        assert_eq!(
            server_keys.key(),
            hex_vec("3fce516009c21727d0f2e4e86ee403bc")
        );
        assert_eq!(server_keys.iv(), &hex_array("5d313eb2671276ee13000b30"));
        assert_eq!(
            client_keys.key(),
            hex_vec("dbfaa693d1762c5b666af5d950258d01")
        );
        assert_eq!(client_keys.iv(), &hex_array("5bd3c71b836e0b76bb73265f"));

        let through_server_finished = transcript(
            HashAlgorithm::Sha256,
            "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13",
        );
        let finished = schedule
            .finished_verify_data(schedule.client_handshake_secret(), &through_server_finished)
            .expect("client Finished must derive");
        assert_eq!(
            finished.as_bytes(),
            hex_vec("a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61")
        );
    }

    #[test]
    fn rfc8448_application_secrets_and_server_keys_match() {
        let schedule = rfc8448_schedule();
        let through_server_finished = transcript(
            HashAlgorithm::Sha256,
            "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13",
        );
        let application = schedule
            .application_traffic_secrets(&through_server_finished)
            .expect("application secrets must derive");
        assert_eq!(
            application.client().0.as_bytes(),
            hex_vec("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
        );
        assert_eq!(
            application.server().0.as_bytes(),
            hex_vec("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
        );
        let server_keys = schedule
            .traffic_keys(application.server())
            .expect("server application keys must derive");
        assert_eq!(
            server_keys.key(),
            hex_vec("9f02283b6c9c07efc26bb9f2ac92e356")
        );
        assert_eq!(server_keys.iv(), &hex_array("cf782b88dd83549aadf1e984"));
    }

    #[test]
    fn rejects_hash_mismatch_and_invalid_shared_secret() {
        let wrong_hash = HashAlgorithm::Sha384.digest(b"ClientHelloServerHello");
        assert!(
            Tls13KeySchedule::new(CipherSuite::Aes128GcmSha256, &[1; 32], &wrong_hash).is_err()
        );
        let right_hash = HashAlgorithm::Sha256.digest(b"ClientHelloServerHello");
        assert!(Tls13KeySchedule::new(CipherSuite::Aes128GcmSha256, &[], &right_hash).is_err());
    }

    #[test]
    fn transcript_hasher_snapshots_match_one_shot_digests() {
        let parts: [&[u8]; 4] = [
            b"ClientHello",
            b"ServerHello",
            b"EncryptedExtensionsCertificate",
            b"CertificateVerifyFinished",
        ];
        for algorithm in [HashAlgorithm::Sha256, HashAlgorithm::Sha384] {
            let mut hasher = TranscriptHasher::new(algorithm);
            let mut prefix = Vec::new();
            for part in parts {
                hasher.update(part);
                prefix.extend_from_slice(part);
                assert_eq!(hasher.snapshot(), algorithm.digest(&prefix));
            }
            // A snapshot must not disturb the running state.
            let through_parts = hasher.snapshot();
            hasher.update(b"extra");
            prefix.extend_from_slice(b"extra");
            assert_eq!(hasher.snapshot(), algorithm.digest(&prefix));
            assert_ne!(through_parts, hasher.snapshot());
        }
    }

    #[test]
    fn sha384_suite_uses_48_byte_transcripts_and_32_byte_keys() {
        let transcript = HashAlgorithm::Sha384.digest(b"ClientHelloServerHello");
        let schedule =
            Tls13KeySchedule::new(CipherSuite::Aes256GcmSha384, &[0x42; 32], &transcript)
                .expect("SHA-384 schedule must derive");
        let keys = schedule
            .traffic_keys(schedule.server_handshake_secret())
            .expect("AES-256 keys must derive");

        assert_eq!(transcript.as_bytes().len(), 48);
        assert_eq!(
            transcript.as_bytes(),
            hex_vec(
                "57b14b5acba7cce6c39e106a40d82b48828670a2a616fa6f821f5c5810365bc9\
                 b341c36f617d84ff10018adbbe18436c"
            )
        );
        assert_eq!(
            schedule.client_handshake_secret().0.as_bytes(),
            hex_vec(
                "3578cceba48f64ceeff5237af06823acd0fa837a21dd133a127828ff7e1961136\
                 8672140c2ac6e2ea718c7e157c4a3a1"
            )
        );
        assert_eq!(
            schedule.server_handshake_secret().0.as_bytes(),
            hex_vec(
                "bcebc2d1ac93c114d8f0e2c857b017b8c3e92a56c7398ebcca19b77fc1a582d\
                 a8fd4bbf677ea10c805f8507d03f55543"
            )
        );
        assert_eq!(
            schedule.master.as_bytes(),
            hex_vec(
                "8df0e42bc34170cf567790494d4fbb5b61538895bdaa2cf8a0ad2db0b588b46\
                 d52853504d8713db39e4c28f396cab7b0"
            )
        );
        assert_eq!(keys.key().len(), 32);
        assert_eq!(
            keys.key(),
            hex_vec("b3c695f9b39ad922d8e94ee0c4ce505d3716f46ffcbbbc39226846ef3ddfb472")
        );
        assert_eq!(keys.iv().len(), 12);
        assert_eq!(keys.iv(), &hex_array("dfe68d539b6cf7905f9773e8"));
    }

    fn rfc8448_schedule() -> Tls13KeySchedule {
        let shared_secret =
            hex_vec("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        let transcript = transcript(
            HashAlgorithm::Sha256,
            "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8",
        );
        Tls13KeySchedule::new(CipherSuite::Aes128GcmSha256, &shared_secret, &transcript)
            .expect("RFC 8448 schedule must derive")
    }

    fn transcript(algorithm: HashAlgorithm, encoded: &str) -> TranscriptHash {
        TranscriptHash::from_bytes(algorithm, &hex_vec(encoded))
            .expect("test transcript has exact hash length")
    }

    fn hex_array<const LENGTH: usize>(encoded: &str) -> [u8; LENGTH] {
        hex_vec(encoded)
            .try_into()
            .unwrap_or_else(|_| panic!("test hex must contain {LENGTH} bytes"))
    }

    fn hex_vec(encoded: &str) -> Vec<u8> {
        encoded
            .as_bytes()
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
