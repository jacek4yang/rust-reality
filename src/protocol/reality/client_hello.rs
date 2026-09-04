use std::{error::Error, fmt, ops::Range, sync::Arc};

use ml_kem::{
    DecapsulationKey768, Seed,
    array::Array as MlKemArray,
    kem::{Decapsulate, KeyExport},
    ml_kem_768::Ciphertext,
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Maximum accepted ClientHello handshake message, including its four-byte header.
pub const MAX_CLIENT_HELLO_BYTES: usize = 64 * 1024;
/// Offset of the session ID bytes when the session ID has the REALITY length.
pub const SESSION_ID_OFFSET: usize = 39;
/// REALITY authentication ciphertext length.
pub const SESSION_ID_LEN: usize = 32;
/// TLS NamedGroup identifier for X25519.
pub const X25519_GROUP: u16 = 0x001d;
/// Xray-compatible NamedGroup identifier for X25519MLKEM768.
pub const X25519_MLKEM768_GROUP: u16 = 0x11ec;
/// ML-KEM-768 encapsulation key bytes in the hybrid client share.
pub const MLKEM768_ENCAP_KEY_LEN: usize = 1_184;
/// Complete X25519MLKEM768 client share length.
pub const X25519_MLKEM768_SHARE_LEN: usize = MLKEM768_ENCAP_KEY_LEN + 32;

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS13_VERSION: u16 = 0x0304;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_PADDING: u16 = 0x0015;
const EXT_PRE_SHARED_KEY: u16 = 0x0029;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

const MAX_EXTENSIONS: usize = 256;
const MAX_KEY_SHARES: usize = 16;
const MAX_ALPN_PROTOCOLS: usize = 32;
const MAX_PSK_IDENTITIES: usize = 16;
const MAX_PSK_BINDERS: usize = 16;

/// A strict ClientHello parsing failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientHelloError {
    /// The declared bytes have not all arrived.
    Truncated,
    /// Input exceeds the server's hard ClientHello allocation limit.
    TooLarge,
    /// A TLS record does not carry a handshake.
    NotHandshakeRecord,
    /// The handshake is not a ClientHello.
    NotClientHello,
    /// An outer declared length does not exactly match the supplied input.
    LengthMismatch,
    /// A bounded TLS vector or extension violates its structural invariant.
    Malformed(&'static str),
}

impl fmt::Display for ClientHelloError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("truncated TLS ClientHello"),
            Self::TooLarge => formatter.write_str("TLS ClientHello exceeds the hard size limit"),
            Self::NotHandshakeRecord => formatter.write_str("TLS record is not a handshake record"),
            Self::NotClientHello => formatter.write_str("TLS handshake is not a ClientHello"),
            Self::LengthMismatch => {
                formatter.write_str("TLS ClientHello length does not match input")
            }
            Self::Malformed(field) => write!(formatter, "malformed TLS ClientHello {field}"),
        }
    }
}

impl Error for ClientHelloError {}

/// Conservative, opaque identity of one behaviorally equivalent ClientHello.
///
/// Random, legacy-session-ID, and supported ephemeral key-share bytes are
/// excluded. Extension ordering is canonicalized because the controlled
/// collector must prove order independence before publishing a profile. SNI,
/// ALPN, offer ordering, extension bodies, key-share groups and lengths, and
/// ECH-GREASE shape remain inputs. The digest is intentionally not exposed in
/// `Debug` or routine diagnostics.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct NormalizedClientHelloClass([u8; 32]);

impl fmt::Debug for NormalizedClientHelloClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NormalizedClientHelloClass([REDACTED])")
    }
}

/// A strictly parsed ClientHello cannot safely enter profile selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientHelloClassError {
    /// The already validated message was internally inconsistent when
    /// reclassified. This is fail-closed and produces a live-cover miss.
    Malformed,
    /// TLS 1.3 PSK/resumption is outside the prebuilt-profile contract.
    PreSharedKey,
    /// A key-share group outside the two REALITY groups and GREASE was offered.
    UnsupportedKeyShare,
    /// Bounded temporary classifier storage could not be reserved.
    BufferAllocation,
}

impl fmt::Display for ClientHelloClassError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TLS ClientHello is not eligible for a cover profile")
    }
}

impl Error for ClientHelloClassError {}

/// A bounded controlled-probe construction or key agreement failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoverProbeError {
    Random,
    Malformed,
    UnsupportedKeyShare,
    NonContributoryKey,
    MlKem,
    BufferAllocation,
}

/// Secret-free normalized ClientHello bytes retained for controlled probes.
///
/// Fresh random, session-ID, GREASE-ECH, and key-share bytes are generated for
/// every probe. This template is admitted only after a complete authenticated
/// client handshake and is bounded by the normal ClientHello limit.
#[derive(Clone)]
pub(crate) struct CoverProbeTemplate {
    message: Arc<[u8]>,
    class: NormalizedClientHelloClass,
}

/// One controlled ClientHello and the private state needed to inspect only
/// the cover's corresponding encrypted handshake response.
pub(crate) struct CoverProbe {
    hello: ClientHello,
    wire_record: Vec<u8>,
    x25519: Option<StaticSecret>,
    hybrid_x25519: Option<StaticSecret>,
    hybrid_mlkem: Option<DecapsulationKey768>,
}

/// Fixed-capacity cover handshake shared secret.
pub(crate) struct CoverProbeSharedSecret {
    bytes: Zeroizing<[u8; 64]>,
    len: usize,
}

impl CoverProbeSharedSecret {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KeyShareRange {
    group: u16,
    data: Range<usize>,
}

/// A borrowed key share whose bytes remain owned by [`ClientHello`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyShare<'hello> {
    group: u16,
    data: &'hello [u8],
}

impl<'hello> KeyShare<'hello> {
    /// Returns the TLS NamedGroup identifier.
    #[must_use]
    pub const fn group(self) -> u16 {
        self.group
    }

    /// Returns the exact key exchange bytes.
    #[must_use]
    pub const fn data(self) -> &'hello [u8] {
        self.data
    }
}

/// Strictly parsed fields needed by REALITY authentication and presentation.
///
/// The original handshake message is stored once. Variable-sized fields retain
/// checked byte ranges into that immutable allocation instead of owning copies.
#[derive(Clone, Debug)]
pub struct ClientHello {
    raw_message: Arc<[u8]>,
    random: [u8; 32],
    session_id: Range<usize>,
    server_name: Option<Range<usize>>,
    alpn: Vec<Range<usize>>,
    key_shares: Vec<KeyShareRange>,
    cipher_suites: Vec<u16>,
    offers_tls13: bool,
    offers_psk: bool,
}

impl ClientHello {
    /// Parses one complete TLS handshake message without a record header.
    ///
    /// # Errors
    ///
    /// Rejects truncated, oversized, non-ClientHello, duplicate-extension, and
    /// structurally malformed input. Every attacker-controlled vector is bounded.
    pub fn parse_message(message: &[u8]) -> Result<Self, ClientHelloError> {
        if message.len() > MAX_CLIENT_HELLO_BYTES {
            return Err(ClientHelloError::TooLarge);
        }
        let mut reader = Reader::new(message);
        if reader.read_u8()? != HANDSHAKE_TYPE_CLIENT_HELLO {
            return Err(ClientHelloError::NotClientHello);
        }
        let declared =
            usize::try_from(reader.read_u24()?).map_err(|_| ClientHelloError::TooLarge)?;
        if declared != reader.remaining() {
            return Err(ClientHelloError::LengthMismatch);
        }

        let _legacy_version = reader.read_u16()?;
        let random: [u8; 32] = reader
            .read_bytes(32)?
            .try_into()
            .map_err(|_| ClientHelloError::Truncated)?;
        let session_id_len = usize::from(reader.read_u8()?);
        if session_id_len > SESSION_ID_LEN {
            return Err(ClientHelloError::Malformed("session ID"));
        }
        let session_id = reader.read_range(session_id_len)?;

        let cipher_bytes_len = usize::from(reader.read_u16()?);
        if cipher_bytes_len < 2 || cipher_bytes_len % 2 != 0 {
            return Err(ClientHelloError::Malformed("cipher suites"));
        }
        let cipher_bytes = reader.read_bytes(cipher_bytes_len)?;
        let cipher_suites = cipher_bytes
            .chunks_exact(2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
            .collect();

        let compression_len = usize::from(reader.read_u8()?);
        if compression_len == 0 {
            return Err(ClientHelloError::Malformed("compression methods"));
        }
        reader.read_bytes(compression_len)?;

        let mut state = ExtensionState::default();
        if !reader.is_empty() {
            let extensions_len = usize::from(reader.read_u16()?);
            let mut extensions = reader.read_subreader(extensions_len)?;
            if !reader.is_empty() {
                return Err(ClientHelloError::LengthMismatch);
            }
            parse_extensions(&mut extensions, &mut state)?;
        }

        Ok(Self {
            raw_message: Arc::from(message),
            random,
            session_id,
            server_name: state.server_name,
            alpn: state.alpn,
            key_shares: state.key_shares,
            cipher_suites,
            offers_tls13: state.offers_tls13,
            offers_psk: state.offers_psk,
        })
    }

    /// Parses one complete TLS handshake record containing only a ClientHello.
    ///
    /// Fragmented records are handled by the incremental reader layer rather than
    /// this exact-record convenience function.
    ///
    /// # Errors
    ///
    /// Rejects non-handshake, truncated, trailing, or malformed records.
    pub fn parse_record(record: &[u8]) -> Result<Self, ClientHelloError> {
        if record.len() < TLS_RECORD_HEADER_LEN {
            return Err(ClientHelloError::Truncated);
        }
        if record[0] != TLS_CONTENT_TYPE_HANDSHAKE {
            return Err(ClientHelloError::NotHandshakeRecord);
        }
        let body_len = usize::from(u16::from_be_bytes([record[3], record[4]]));
        let record_len = TLS_RECORD_HEADER_LEN
            .checked_add(body_len)
            .ok_or(ClientHelloError::TooLarge)?;
        if record.len() < record_len {
            return Err(ClientHelloError::Truncated);
        }
        if record.len() != record_len {
            return Err(ClientHelloError::LengthMismatch);
        }
        let body = record
            .get(TLS_RECORD_HEADER_LEN..record_len)
            .ok_or(ClientHelloError::Truncated)?;
        Self::parse_message(body)
    }

    /// Returns the exact ClientHello handshake bytes for the TLS transcript.
    #[must_use]
    pub fn raw_message(&self) -> &[u8] {
        &self.raw_message
    }

    /// Returns the 32-byte ClientHello random.
    #[must_use]
    pub const fn random(&self) -> &[u8; 32] {
        &self.random
    }

    /// Returns the validated SNI host name when present.
    #[must_use]
    pub fn server_name(&self) -> Option<&str> {
        let bytes = self.raw_message.get(self.server_name.clone()?)?;
        std::str::from_utf8(bytes).ok()
    }

    /// Returns the exact session ID bytes.
    #[must_use]
    pub fn session_id(&self) -> Option<&[u8]> {
        self.raw_message.get(self.session_id.clone())
    }

    /// Returns the fixed-size REALITY ciphertext only for a 32-byte session ID.
    #[must_use]
    pub fn session_ciphertext(&self) -> Option<&[u8; SESSION_ID_LEN]> {
        self.session_id()?.try_into().ok()
    }

    /// Builds the REALITY AEAD additional data with the session ID bytes zeroed.
    #[must_use]
    pub fn reality_aad(&self) -> Option<Vec<u8>> {
        self.session_ciphertext()?;
        let mut aad = self.raw_message.to_vec();
        aad.get_mut(self.session_id.clone())?.fill(0);
        Some(aad)
    }

    /// Returns the 12-byte REALITY AEAD nonce derived from random bytes 20 through 31.
    #[must_use]
    pub const fn aead_nonce(&self) -> [u8; 12] {
        [
            self.random[20],
            self.random[21],
            self.random[22],
            self.random[23],
            self.random[24],
            self.random[25],
            self.random[26],
            self.random[27],
            self.random[28],
            self.random[29],
            self.random[30],
            self.random[31],
        ]
    }

    /// Returns whether the supported-versions extension offers TLS 1.3.
    #[must_use]
    pub const fn offers_tls13(&self) -> bool {
        self.offers_tls13
    }

    /// Returns whether a structurally valid, bounded PSK offer was present.
    ///
    /// The REALITY server still performs a full handshake and never selects this PSK.
    #[must_use]
    pub const fn offers_psk(&self) -> bool {
        self.offers_psk
    }

    /// Iterates ALPN protocol bytes in client preference order.
    pub fn alpn_protocols(&self) -> impl Iterator<Item = &[u8]> {
        self.alpn
            .iter()
            .filter_map(|range| self.raw_message.get(range.clone()))
    }

    /// Iterates borrowed key shares without copying their attacker-controlled bytes.
    pub fn key_shares(&self) -> impl Iterator<Item = KeyShare<'_>> {
        self.key_shares.iter().filter_map(|share| {
            self.raw_message
                .get(share.data.clone())
                .map(|data| KeyShare {
                    group: share.group,
                    data,
                })
        })
    }

    /// Returns the offered standalone X25519 key, or the hybrid share's X25519 tail.
    #[must_use]
    pub fn peer_x25519(&self) -> Option<[u8; 32]> {
        if let Some(share) = self
            .key_shares()
            .find(|share| share.group == X25519_GROUP && share.data.len() == 32)
        {
            return share.data.try_into().ok();
        }
        let hybrid = self.key_shares().find(|share| {
            share.group == X25519_MLKEM768_GROUP && share.data.len() == X25519_MLKEM768_SHARE_LEN
        })?;
        hybrid
            .data
            .get(MLKEM768_ENCAP_KEY_LEN..X25519_MLKEM768_SHARE_LEN)?
            .try_into()
            .ok()
    }

    /// Returns the ML-KEM-768 encapsulation key from a valid hybrid share.
    #[must_use]
    pub fn peer_mlkem768_encapsulation_key(&self) -> Option<&[u8]> {
        let share = self.key_shares().find(|share| {
            share.group == X25519_MLKEM768_GROUP && share.data.len() == X25519_MLKEM768_SHARE_LEN
        })?;
        share.data.get(..MLKEM768_ENCAP_KEY_LEN)
    }

    /// Returns whether the client offered a cipher suite.
    #[must_use]
    pub fn cipher_offered(&self, cipher_suite: u16) -> bool {
        self.cipher_suites.contains(&cipher_suite)
    }

    /// Returns whether a non-GREASE share exists for the selected group.
    #[must_use]
    pub fn key_share_group_offered(&self, group: u16) -> bool {
        !is_grease(group) && self.key_shares.iter().any(|share| share.group == group)
    }

    /// Derives the conservative profile class after REALITY authentication.
    ///
    /// This reuses the canonical validated message allocation and performs no
    /// permissive parse: any internal inconsistency, PSK offer, or unsupported
    /// share is a profile miss. Extension order is intentionally ignored only
    /// at this identity layer; a profile cannot become `Validated` until the
    /// controlled collector observes the same cover behavior across multiple
    /// independently permuted probes.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed classification error for unsupported or
    /// inconsistent input and bounded allocation failure.
    pub fn normalized_profile_class(
        &self,
    ) -> Result<NormalizedClientHelloClass, ClientHelloClassError> {
        classify_profile_message(&self.raw_message)
    }

    /// Produces a secret-free template only after the caller has completed the
    /// authenticated REALITY handshake. User bytes can nominate a bounded
    /// class, but never contribute cover observations or profile semantics.
    pub(crate) fn controlled_cover_probe_template(
        &self,
    ) -> Result<CoverProbeTemplate, CoverProbeError> {
        let class = self
            .normalized_profile_class()
            .map_err(|_| CoverProbeError::Malformed)?;
        let mut message = self.raw_message.to_vec();
        message
            .get_mut(6..38)
            .ok_or(CoverProbeError::Malformed)?
            .fill(0);
        message
            .get_mut(self.session_id.clone())
            .ok_or(CoverProbeError::Malformed)?
            .fill(0);
        for share in &self.key_shares {
            message
                .get_mut(share.data.clone())
                .ok_or(CoverProbeError::Malformed)?
                .fill(0);
        }
        for range in ech_random_ranges(&message)? {
            message
                .get_mut(range)
                .ok_or(CoverProbeError::Malformed)?
                .fill(0);
        }
        Ok(CoverProbeTemplate {
            message: Arc::from(message),
            class,
        })
    }
}

impl CoverProbeTemplate {
    /// Generates one independently permuted controlled probe with fresh key
    /// ownership. `variant` guarantees coverage across extension orders even
    /// if secure random shuffling happens to repeat a prior order.
    pub(crate) fn generate(&self, variant: u8) -> Result<CoverProbe, CoverProbeError> {
        let sanitized =
            ClientHello::parse_message(&self.message).map_err(|_| CoverProbeError::Malformed)?;
        let mut message = self.message.to_vec();
        fill_random(message.get_mut(6..38).ok_or(CoverProbeError::Malformed)?)?;
        fill_random(
            message
                .get_mut(sanitized.session_id.clone())
                .ok_or(CoverProbeError::Malformed)?,
        )?;
        for range in ech_random_ranges(&message)? {
            fill_random(message.get_mut(range).ok_or(CoverProbeError::Malformed)?)?;
        }

        let mut x25519 = None;
        let mut hybrid_x25519 = None;
        let mut hybrid_mlkem = None;
        for share in &sanitized.key_shares {
            let output = message
                .get_mut(share.data.clone())
                .ok_or(CoverProbeError::Malformed)?;
            match share.group {
                X25519_GROUP if output.len() == 32 && x25519.is_none() => {
                    let secret = fresh_x25519_secret()?;
                    output.copy_from_slice(&PublicKey::from(&secret).to_bytes());
                    x25519 = Some(secret);
                }
                X25519_MLKEM768_GROUP
                    if output.len() == X25519_MLKEM768_SHARE_LEN
                        && hybrid_x25519.is_none()
                        && hybrid_mlkem.is_none() =>
                {
                    let mut seed = Seed::default();
                    fill_random(seed.as_mut())?;
                    let decapsulation = DecapsulationKey768::from_seed(seed);
                    let encapsulation = decapsulation.encapsulation_key().to_bytes();
                    let secret = fresh_x25519_secret()?;
                    let public = PublicKey::from(&secret).to_bytes();
                    output
                        .get_mut(..MLKEM768_ENCAP_KEY_LEN)
                        .ok_or(CoverProbeError::Malformed)?
                        .copy_from_slice(encapsulation.as_slice());
                    output
                        .get_mut(MLKEM768_ENCAP_KEY_LEN..)
                        .ok_or(CoverProbeError::Malformed)?
                        .copy_from_slice(&public);
                    hybrid_x25519 = Some(secret);
                    hybrid_mlkem = Some(decapsulation);
                }
                group if is_grease(group) => fill_random(output)?,
                _ => return Err(CoverProbeError::UnsupportedKeyShare),
            }
        }
        rotate_grease_values(&mut message, variant)?;
        message = permute_extensions(&message, variant)?;
        let hello = ClientHello::parse_message(&message).map_err(|_| CoverProbeError::Malformed)?;
        if hello
            .normalized_profile_class()
            .map_err(|_| CoverProbeError::Malformed)?
            != self.class
        {
            return Err(CoverProbeError::Malformed);
        }
        let wire_len = u16::try_from(message.len()).map_err(|_| CoverProbeError::Malformed)?;
        let mut wire_record = Vec::new();
        wire_record
            .try_reserve_exact(5_usize.saturating_add(message.len()))
            .map_err(|_| CoverProbeError::BufferAllocation)?;
        wire_record.extend_from_slice(&[TLS_CONTENT_TYPE_HANDSHAKE, 3, 1]);
        wire_record.extend_from_slice(&wire_len.to_be_bytes());
        wire_record.extend_from_slice(&message);
        Ok(CoverProbe {
            hello,
            wire_record,
            x25519,
            hybrid_x25519,
            hybrid_mlkem,
        })
    }

    pub(crate) const fn class(&self) -> NormalizedClientHelloClass {
        self.class
    }
}

impl CoverProbe {
    pub(crate) const fn hello(&self) -> &ClientHello {
        &self.hello
    }

    pub(crate) fn wire_record(&self) -> &[u8] {
        &self.wire_record
    }

    pub(crate) fn shared_secret(
        &self,
        group: u16,
        server_exchange: &[u8],
    ) -> Result<CoverProbeSharedSecret, CoverProbeError> {
        let mut output = Zeroizing::new([0_u8; 64]);
        let len = match group {
            X25519_GROUP => {
                let secret = self.x25519.as_ref().ok_or(CoverProbeError::Malformed)?;
                let public: [u8; 32] = server_exchange
                    .try_into()
                    .map_err(|_| CoverProbeError::Malformed)?;
                let shared = secret.diffie_hellman(&PublicKey::from(public));
                if !shared.was_contributory() {
                    return Err(CoverProbeError::NonContributoryKey);
                }
                output[..32].copy_from_slice(shared.as_bytes());
                32
            }
            X25519_MLKEM768_GROUP => {
                let ciphertext: Ciphertext = MlKemArray::try_from(
                    server_exchange
                        .get(..1_088)
                        .ok_or(CoverProbeError::Malformed)?,
                )
                .map_err(|_| CoverProbeError::MlKem)?;
                let server_public: [u8; 32] = server_exchange
                    .get(1_088..)
                    .ok_or(CoverProbeError::Malformed)?
                    .try_into()
                    .map_err(|_| CoverProbeError::Malformed)?;
                let mlkem = self
                    .hybrid_mlkem
                    .as_ref()
                    .ok_or(CoverProbeError::Malformed)?
                    .decapsulate(&ciphertext);
                let x25519 = self
                    .hybrid_x25519
                    .as_ref()
                    .ok_or(CoverProbeError::Malformed)?
                    .diffie_hellman(&PublicKey::from(server_public));
                if !x25519.was_contributory() {
                    return Err(CoverProbeError::NonContributoryKey);
                }
                output[..32].copy_from_slice(mlkem.as_ref());
                output[32..].copy_from_slice(x25519.as_bytes());
                64
            }
            _ => return Err(CoverProbeError::UnsupportedKeyShare),
        };
        Ok(CoverProbeSharedSecret { bytes: output, len })
    }
}

fn fresh_x25519_secret() -> Result<StaticSecret, CoverProbeError> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    fill_random(bytes.as_mut())?;
    Ok(StaticSecret::from(*bytes))
}

fn fill_random(bytes: &mut [u8]) -> Result<(), CoverProbeError> {
    crate::crypto::entropy::fill(bytes).map_err(|_| CoverProbeError::Random)
}

#[derive(Clone)]
struct ExtensionSegment {
    extension_type: u16,
    wire: Range<usize>,
    body: Range<usize>,
}

fn extension_segments(message: &[u8]) -> Result<Vec<ExtensionSegment>, CoverProbeError> {
    let mut reader = Reader::new(message);
    reader
        .read_bytes(4)
        .map_err(|_| CoverProbeError::Malformed)?;
    reader
        .read_bytes(2)
        .map_err(|_| CoverProbeError::Malformed)?;
    reader
        .read_bytes(32)
        .map_err(|_| CoverProbeError::Malformed)?;
    let session_len = usize::from(reader.read_u8().map_err(|_| CoverProbeError::Malformed)?);
    reader
        .read_bytes(session_len)
        .map_err(|_| CoverProbeError::Malformed)?;
    let cipher_len = usize::from(reader.read_u16().map_err(|_| CoverProbeError::Malformed)?);
    reader
        .read_bytes(cipher_len)
        .map_err(|_| CoverProbeError::Malformed)?;
    let compression_len = usize::from(reader.read_u8().map_err(|_| CoverProbeError::Malformed)?);
    reader
        .read_bytes(compression_len)
        .map_err(|_| CoverProbeError::Malformed)?;
    if reader.is_empty() {
        return Ok(Vec::new());
    }
    let extensions_len = usize::from(reader.read_u16().map_err(|_| CoverProbeError::Malformed)?);
    let mut extensions = reader
        .read_subreader(extensions_len)
        .map_err(|_| CoverProbeError::Malformed)?;
    if !reader.is_empty() {
        return Err(CoverProbeError::Malformed);
    }
    let mut output = Vec::new();
    output
        .try_reserve(32)
        .map_err(|_| CoverProbeError::BufferAllocation)?;
    while !extensions.is_empty() {
        if output.len() >= MAX_EXTENSIONS {
            return Err(CoverProbeError::Malformed);
        }
        let start = extensions.position;
        let extension_type = extensions
            .read_u16()
            .map_err(|_| CoverProbeError::Malformed)?;
        let body_len = usize::from(
            extensions
                .read_u16()
                .map_err(|_| CoverProbeError::Malformed)?,
        );
        let body = extensions
            .read_range(body_len)
            .map_err(|_| CoverProbeError::Malformed)?;
        output.push(ExtensionSegment {
            extension_type,
            wire: start..extensions.position,
            body,
        });
    }
    Ok(output)
}

fn ech_random_ranges(message: &[u8]) -> Result<Vec<Range<usize>>, CoverProbeError> {
    let mut output = Vec::new();
    output
        .try_reserve(3)
        .map_err(|_| CoverProbeError::BufferAllocation)?;
    for extension in extension_segments(message)? {
        if extension.extension_type != EXT_ENCRYPTED_CLIENT_HELLO {
            continue;
        }
        let mut reader = Reader {
            input: message,
            position: extension.body.start,
            end: extension.body.end,
        };
        if reader.read_u8().map_err(|_| CoverProbeError::Malformed)? != 0 {
            return Err(CoverProbeError::Malformed);
        }
        reader.read_u16().map_err(|_| CoverProbeError::Malformed)?;
        reader.read_u16().map_err(|_| CoverProbeError::Malformed)?;
        output.push(
            reader
                .read_range(1)
                .map_err(|_| CoverProbeError::Malformed)?,
        );
        for _ in 0..2 {
            let length = usize::from(reader.read_u16().map_err(|_| CoverProbeError::Malformed)?);
            output.push(
                reader
                    .read_range(length)
                    .map_err(|_| CoverProbeError::Malformed)?,
            );
        }
        if !reader.is_empty() {
            return Err(CoverProbeError::Malformed);
        }
    }
    Ok(output)
}

fn permute_extensions(message: &[u8], variant: u8) -> Result<Vec<u8>, CoverProbeError> {
    let segments = extension_segments(message)?;
    if segments.len() < 2 {
        return Ok(message.to_vec());
    }
    let mut order: Vec<usize> = (0..segments.len()).collect();
    let mut entropy = [0_u8; 32];
    fill_random(&mut entropy)?;
    let mut state = u64::from_le_bytes(
        entropy[..8]
            .try_into()
            .map_err(|_| CoverProbeError::Malformed)?,
    ) ^ u64::from(variant);
    for index in (1..order.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let swap = usize::try_from(state).unwrap_or(usize::MAX) % (index + 1);
        order.swap(index, swap);
    }
    let order_len = order.len();
    order.rotate_left(usize::from(variant) % order_len);

    let first = segments.first().ok_or(CoverProbeError::Malformed)?;
    let last = segments.last().ok_or(CoverProbeError::Malformed)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(message.len())
        .map_err(|_| CoverProbeError::BufferAllocation)?;
    output.extend_from_slice(
        message
            .get(..first.wire.start)
            .ok_or(CoverProbeError::Malformed)?,
    );
    for index in order {
        output.extend_from_slice(
            message
                .get(segments[index].wire.clone())
                .ok_or(CoverProbeError::Malformed)?,
        );
    }
    output.extend_from_slice(
        message
            .get(last.wire.end..)
            .ok_or(CoverProbeError::Malformed)?,
    );
    if output.len() != message.len() {
        return Err(CoverProbeError::Malformed);
    }
    Ok(output)
}

fn rotate_grease_values(message: &mut [u8], variant: u8) -> Result<(), CoverProbeError> {
    let cipher_range = {
        let mut reader = Reader::new(message);
        reader
            .read_bytes(4)
            .map_err(|_| CoverProbeError::Malformed)?;
        reader
            .read_bytes(2)
            .map_err(|_| CoverProbeError::Malformed)?;
        reader
            .read_bytes(32)
            .map_err(|_| CoverProbeError::Malformed)?;
        let session_len = usize::from(reader.read_u8().map_err(|_| CoverProbeError::Malformed)?);
        reader
            .read_bytes(session_len)
            .map_err(|_| CoverProbeError::Malformed)?;
        let cipher_len = usize::from(reader.read_u16().map_err(|_| CoverProbeError::Malformed)?);
        let cipher_range = reader
            .read_range(cipher_len)
            .map_err(|_| CoverProbeError::Malformed)?;
        let compression_len =
            usize::from(reader.read_u8().map_err(|_| CoverProbeError::Malformed)?);
        reader
            .read_bytes(compression_len)
            .map_err(|_| CoverProbeError::Malformed)?;
        cipher_range
    };
    rotate_u16_vector(message, cipher_range, variant, 0)?;

    let segments = extension_segments(message)?;
    for (ordinal, extension) in segments.into_iter().enumerate() {
        rotate_u16_at(message, extension.wire.start, variant, ordinal)?;
        match extension.extension_type {
            EXT_SUPPORTED_GROUPS | EXT_SIGNATURE_ALGORITHMS => {
                let start = extension
                    .body
                    .start
                    .checked_add(2)
                    .ok_or(CoverProbeError::Malformed)?;
                rotate_u16_vector(message, start..extension.body.end, variant, ordinal)?;
            }
            EXT_SUPPORTED_VERSIONS => {
                let start = extension
                    .body
                    .start
                    .checked_add(1)
                    .ok_or(CoverProbeError::Malformed)?;
                rotate_u16_vector(message, start..extension.body.end, variant, ordinal)?;
            }
            EXT_KEY_SHARE => {
                let mut position = extension
                    .body
                    .start
                    .checked_add(2)
                    .ok_or(CoverProbeError::Malformed)?;
                while position < extension.body.end {
                    rotate_u16_at(message, position, variant, ordinal)?;
                    let length_offset =
                        position.checked_add(2).ok_or(CoverProbeError::Malformed)?;
                    let length_bytes: [u8; 2] = message
                        .get(length_offset..length_offset + 2)
                        .ok_or(CoverProbeError::Malformed)?
                        .try_into()
                        .map_err(|_| CoverProbeError::Malformed)?;
                    position = length_offset
                        .checked_add(2)
                        .and_then(|offset| {
                            offset.checked_add(usize::from(u16::from_be_bytes(length_bytes)))
                        })
                        .ok_or(CoverProbeError::Malformed)?;
                }
                if position != extension.body.end {
                    return Err(CoverProbeError::Malformed);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn rotate_u16_vector(
    message: &mut [u8],
    range: Range<usize>,
    variant: u8,
    ordinal: usize,
) -> Result<(), CoverProbeError> {
    if !range.len().is_multiple_of(2) {
        return Err(CoverProbeError::Malformed);
    }
    for offset in (range.start..range.end).step_by(2) {
        rotate_u16_at(message, offset, variant, ordinal)?;
    }
    Ok(())
}

fn rotate_u16_at(
    message: &mut [u8],
    offset: usize,
    variant: u8,
    _ordinal: usize,
) -> Result<(), CoverProbeError> {
    let bytes: [u8; 2] = message
        .get(offset..offset + 2)
        .ok_or(CoverProbeError::Malformed)?
        .try_into()
        .map_err(|_| CoverProbeError::Malformed)?;
    let value = u16::from_be_bytes(bytes);
    if !is_grease(value) {
        return Ok(());
    }
    let low = u16::from(bytes[0]);
    let index = low.saturating_sub(0x0a) / 0x10;
    let rotated_index = (index + u16::from(variant) + 1) % 16;
    let rotated_byte =
        u8::try_from(rotated_index * 0x10 + 0x0a).map_err(|_| CoverProbeError::Malformed)?;
    message
        .get_mut(offset..offset + 2)
        .ok_or(CoverProbeError::Malformed)?
        .copy_from_slice(&[rotated_byte, rotated_byte]);
    Ok(())
}

fn classify_profile_message(
    message: &[u8],
) -> Result<NormalizedClientHelloClass, ClientHelloClassError> {
    let mut reader = Reader::new(message);
    if reader
        .read_u8()
        .map_err(|_| ClientHelloClassError::Malformed)?
        != HANDSHAKE_TYPE_CLIENT_HELLO
    {
        return Err(ClientHelloClassError::Malformed);
    }
    let declared = usize::try_from(
        reader
            .read_u24()
            .map_err(|_| ClientHelloClassError::Malformed)?,
    )
    .map_err(|_| ClientHelloClassError::Malformed)?;
    if declared != reader.remaining() {
        return Err(ClientHelloClassError::Malformed);
    }

    let mut digest = Sha256::new();
    digest.update(b"rust-reality/client-hello-profile/v1\0");
    digest.update(
        reader
            .read_u16()
            .map_err(|_| ClientHelloClassError::Malformed)?
            .to_be_bytes(),
    );
    reader
        .read_bytes(32)
        .map_err(|_| ClientHelloClassError::Malformed)?;
    let session_len = usize::from(
        reader
            .read_u8()
            .map_err(|_| ClientHelloClassError::Malformed)?,
    );
    digest.update([u8::try_from(session_len).map_err(|_| ClientHelloClassError::Malformed)?]);
    reader
        .read_bytes(session_len)
        .map_err(|_| ClientHelloClassError::Malformed)?;

    let cipher_bytes_len = usize::from(
        reader
            .read_u16()
            .map_err(|_| ClientHelloClassError::Malformed)?,
    );
    if cipher_bytes_len < 2 || cipher_bytes_len % 2 != 0 {
        return Err(ClientHelloClassError::Malformed);
    }
    digest.update(
        u16::try_from(cipher_bytes_len)
            .map_err(|_| ClientHelloClassError::Malformed)?
            .to_be_bytes(),
    );
    for bytes in reader
        .read_bytes(cipher_bytes_len)
        .map_err(|_| ClientHelloClassError::Malformed)?
        .chunks_exact(2)
    {
        digest.update(canonical_grease(u16::from_be_bytes([bytes[0], bytes[1]])).to_be_bytes());
    }

    let compression_len = usize::from(
        reader
            .read_u8()
            .map_err(|_| ClientHelloClassError::Malformed)?,
    );
    if compression_len == 0 {
        return Err(ClientHelloClassError::Malformed);
    }
    digest.update([u8::try_from(compression_len).map_err(|_| ClientHelloClassError::Malformed)?]);
    digest.update(
        reader
            .read_bytes(compression_len)
            .map_err(|_| ClientHelloClassError::Malformed)?,
    );

    let mut normalized_extensions = Vec::new();
    normalized_extensions
        .try_reserve(32)
        .map_err(|_| ClientHelloClassError::BufferAllocation)?;
    if !reader.is_empty() {
        let extensions_len = usize::from(
            reader
                .read_u16()
                .map_err(|_| ClientHelloClassError::Malformed)?,
        );
        let mut extensions = reader
            .read_subreader(extensions_len)
            .map_err(|_| ClientHelloClassError::Malformed)?;
        if !reader.is_empty() {
            return Err(ClientHelloClassError::Malformed);
        }
        while !extensions.is_empty() {
            if normalized_extensions.len() >= MAX_EXTENSIONS {
                return Err(ClientHelloClassError::Malformed);
            }
            let extension_type = extensions
                .read_u16()
                .map_err(|_| ClientHelloClassError::Malformed)?;
            if extension_type == EXT_PRE_SHARED_KEY {
                return Err(ClientHelloClassError::PreSharedKey);
            }
            let extension_len = usize::from(
                extensions
                    .read_u16()
                    .map_err(|_| ClientHelloClassError::Malformed)?,
            );
            let body = extensions
                .read_bytes(extension_len)
                .map_err(|_| ClientHelloClassError::Malformed)?;
            let body_digest = normalized_extension_digest(extension_type, body)?;
            normalized_extensions.push((canonical_grease(extension_type), body_digest));
        }
    }
    normalized_extensions.sort_unstable();
    digest.update(
        u16::try_from(normalized_extensions.len())
            .map_err(|_| ClientHelloClassError::Malformed)?
            .to_be_bytes(),
    );
    for (extension_type, body_digest) in normalized_extensions {
        digest.update(extension_type.to_be_bytes());
        digest.update(body_digest);
    }
    let output: [u8; 32] = digest.finalize().into();
    Ok(NormalizedClientHelloClass(output))
}

fn normalized_extension_digest(
    extension_type: u16,
    body: &[u8],
) -> Result<[u8; 32], ClientHelloClassError> {
    let mut digest = Sha256::new();
    digest.update(canonical_grease(extension_type).to_be_bytes());
    match extension_type {
        EXT_SUPPORTED_GROUPS | EXT_SIGNATURE_ALGORITHMS => {
            let mut reader = Reader::new(body);
            let vector_len = usize::from(
                reader
                    .read_u16()
                    .map_err(|_| ClientHelloClassError::Malformed)?,
            );
            if vector_len == 0 || vector_len % 2 != 0 || vector_len != reader.remaining() {
                return Err(ClientHelloClassError::Malformed);
            }
            digest.update(
                u16::try_from(vector_len)
                    .map_err(|_| ClientHelloClassError::Malformed)?
                    .to_be_bytes(),
            );
            while !reader.is_empty() {
                digest.update(
                    canonical_grease(
                        reader
                            .read_u16()
                            .map_err(|_| ClientHelloClassError::Malformed)?,
                    )
                    .to_be_bytes(),
                );
            }
        }
        EXT_SUPPORTED_VERSIONS => {
            let mut reader = Reader::new(body);
            let vector_len = usize::from(
                reader
                    .read_u8()
                    .map_err(|_| ClientHelloClassError::Malformed)?,
            );
            if vector_len == 0 || vector_len % 2 != 0 || vector_len != reader.remaining() {
                return Err(ClientHelloClassError::Malformed);
            }
            digest
                .update([u8::try_from(vector_len).map_err(|_| ClientHelloClassError::Malformed)?]);
            while !reader.is_empty() {
                digest.update(
                    canonical_grease(
                        reader
                            .read_u16()
                            .map_err(|_| ClientHelloClassError::Malformed)?,
                    )
                    .to_be_bytes(),
                );
            }
        }
        EXT_KEY_SHARE => normalize_key_shares(body, &mut digest)?,
        EXT_PADDING => {
            if body.iter().any(|byte| *byte != 0) {
                return Err(ClientHelloClassError::Malformed);
            }
            digest.update(
                u16::try_from(body.len())
                    .map_err(|_| ClientHelloClassError::Malformed)?
                    .to_be_bytes(),
            );
        }
        EXT_ENCRYPTED_CLIENT_HELLO => normalize_grease_ech(body, &mut digest)?,
        _ => {
            digest.update(
                u16::try_from(body.len())
                    .map_err(|_| ClientHelloClassError::Malformed)?
                    .to_be_bytes(),
            );
            digest.update(body);
        }
    }
    Ok(digest.finalize().into())
}

fn normalize_key_shares(body: &[u8], digest: &mut Sha256) -> Result<(), ClientHelloClassError> {
    let mut reader = Reader::new(body);
    let vector_len = usize::from(
        reader
            .read_u16()
            .map_err(|_| ClientHelloClassError::Malformed)?,
    );
    if vector_len == 0 || vector_len != reader.remaining() {
        return Err(ClientHelloClassError::Malformed);
    }
    digest.update(
        u16::try_from(vector_len)
            .map_err(|_| ClientHelloClassError::Malformed)?
            .to_be_bytes(),
    );
    let mut seen_groups = Vec::new();
    while !reader.is_empty() {
        let group = reader
            .read_u16()
            .map_err(|_| ClientHelloClassError::Malformed)?;
        if seen_groups.contains(&group) {
            return Err(ClientHelloClassError::Malformed);
        }
        seen_groups.push(group);
        let exchange_len = usize::from(
            reader
                .read_u16()
                .map_err(|_| ClientHelloClassError::Malformed)?,
        );
        if exchange_len == 0 {
            return Err(ClientHelloClassError::Malformed);
        }
        match group {
            X25519_GROUP if exchange_len == 32 => {}
            X25519_MLKEM768_GROUP if exchange_len == X25519_MLKEM768_SHARE_LEN => {}
            _ if is_grease(group) => {}
            _ => return Err(ClientHelloClassError::UnsupportedKeyShare),
        }
        reader
            .read_bytes(exchange_len)
            .map_err(|_| ClientHelloClassError::Malformed)?;
        digest.update(canonical_grease(group).to_be_bytes());
        digest.update(
            u16::try_from(exchange_len)
                .map_err(|_| ClientHelloClassError::Malformed)?
                .to_be_bytes(),
        );
        digest.update(b"ephemeral-key-share");
    }
    Ok(())
}

fn normalize_grease_ech(body: &[u8], digest: &mut Sha256) -> Result<(), ClientHelloClassError> {
    let mut reader = Reader::new(body);
    if reader
        .read_u8()
        .map_err(|_| ClientHelloClassError::Malformed)?
        != 0
    {
        return Err(ClientHelloClassError::Malformed);
    }
    digest.update([0]);
    digest.update(
        reader
            .read_u16()
            .map_err(|_| ClientHelloClassError::Malformed)?
            .to_be_bytes(),
    );
    digest.update(
        reader
            .read_u16()
            .map_err(|_| ClientHelloClassError::Malformed)?
            .to_be_bytes(),
    );
    reader
        .read_u8()
        .map_err(|_| ClientHelloClassError::Malformed)?;
    digest.update(b"grease-config-id");
    for label in [b"grease-encapsulation".as_slice(), b"grease-payload"] {
        let length = usize::from(
            reader
                .read_u16()
                .map_err(|_| ClientHelloClassError::Malformed)?,
        );
        reader
            .read_bytes(length)
            .map_err(|_| ClientHelloClassError::Malformed)?;
        digest.update(
            u16::try_from(length)
                .map_err(|_| ClientHelloClassError::Malformed)?
                .to_be_bytes(),
        );
        digest.update(label);
    }
    if !reader.is_empty() {
        return Err(ClientHelloClassError::Malformed);
    }
    Ok(())
}

const fn canonical_grease(value: u16) -> u16 {
    if is_grease(value) { 0x0a0a } else { value }
}

#[derive(Default)]
struct ExtensionState {
    seen: Vec<u16>,
    server_name: Option<Range<usize>>,
    alpn: Vec<Range<usize>>,
    key_shares: Vec<KeyShareRange>,
    offers_tls13: bool,
    offers_psk: bool,
}

fn parse_extensions(
    reader: &mut Reader<'_>,
    state: &mut ExtensionState,
) -> Result<(), ClientHelloError> {
    while !reader.is_empty() {
        if state.seen.len() >= MAX_EXTENSIONS {
            return Err(ClientHelloError::Malformed("extension count"));
        }
        let extension_type = reader.read_u16()?;
        if state.seen.contains(&extension_type) {
            return Err(ClientHelloError::Malformed("duplicate extension"));
        }
        state.seen.push(extension_type);
        let extension_len = usize::from(reader.read_u16()?);
        let mut extension = reader.read_subreader(extension_len)?;
        match extension_type {
            EXT_SERVER_NAME => state.server_name = parse_server_name(&mut extension)?,
            EXT_SUPPORTED_VERSIONS => {
                state.offers_tls13 = parse_supported_versions(&mut extension)?;
            }
            EXT_KEY_SHARE => state.key_shares = parse_key_shares(&mut extension)?,
            EXT_ALPN => state.alpn = parse_alpn(&mut extension)?,
            EXT_PRE_SHARED_KEY => {
                if !reader.is_empty() {
                    return Err(ClientHelloError::Malformed("pre-shared key ordering"));
                }
                parse_pre_shared_key(&mut extension)?;
                state.offers_psk = true;
            }
            _ => extension.skip_remaining(),
        }
        if !extension.is_empty() {
            return Err(ClientHelloError::Malformed("extension length"));
        }
    }
    Ok(())
}

fn parse_server_name(reader: &mut Reader<'_>) -> Result<Option<Range<usize>>, ClientHelloError> {
    let list_len = usize::from(reader.read_u16()?);
    let mut names = reader.read_subreader(list_len)?;
    if !reader.is_empty() || names.is_empty() {
        return Err(ClientHelloError::Malformed("server name"));
    }
    let mut host_name = None;
    while !names.is_empty() {
        let name_type = names.read_u8()?;
        let name_len = usize::from(names.read_u16()?);
        let range = names.read_range(name_len)?;
        if name_type == 0 {
            if host_name.is_some() {
                return Err(ClientHelloError::Malformed("duplicate host name"));
            }
            let bytes = names.bytes(&range)?;
            if bytes.is_empty() || bytes.len() > 253 || !bytes.is_ascii() || bytes.contains(&0) {
                return Err(ClientHelloError::Malformed("server name"));
            }
            host_name = Some(range);
        }
    }
    Ok(host_name)
}

fn parse_supported_versions(reader: &mut Reader<'_>) -> Result<bool, ClientHelloError> {
    let list_len = usize::from(reader.read_u8()?);
    if list_len < 2 || list_len % 2 != 0 {
        return Err(ClientHelloError::Malformed("supported versions"));
    }
    let mut versions = reader.read_subreader(list_len)?;
    if !reader.is_empty() {
        return Err(ClientHelloError::Malformed("supported versions"));
    }
    let mut offers_tls13 = false;
    while !versions.is_empty() {
        offers_tls13 |= versions.read_u16()? == TLS13_VERSION;
    }
    Ok(offers_tls13)
}

fn parse_key_shares(reader: &mut Reader<'_>) -> Result<Vec<KeyShareRange>, ClientHelloError> {
    let list_len = usize::from(reader.read_u16()?);
    let mut shares = reader.read_subreader(list_len)?;
    if !reader.is_empty() || shares.is_empty() {
        return Err(ClientHelloError::Malformed("key shares"));
    }
    let mut output = Vec::new();
    while !shares.is_empty() {
        if output.len() >= MAX_KEY_SHARES {
            return Err(ClientHelloError::Malformed("key share count"));
        }
        let group = shares.read_u16()?;
        let data_len = usize::from(shares.read_u16()?);
        if data_len == 0 {
            return Err(ClientHelloError::Malformed("empty key share"));
        }
        output.push(KeyShareRange {
            group,
            data: shares.read_range(data_len)?,
        });
    }
    Ok(output)
}

fn parse_alpn(reader: &mut Reader<'_>) -> Result<Vec<Range<usize>>, ClientHelloError> {
    let list_len = usize::from(reader.read_u16()?);
    let mut protocols = reader.read_subreader(list_len)?;
    if !reader.is_empty() || protocols.is_empty() {
        return Err(ClientHelloError::Malformed("ALPN"));
    }
    let mut output = Vec::new();
    while !protocols.is_empty() {
        if output.len() >= MAX_ALPN_PROTOCOLS {
            return Err(ClientHelloError::Malformed("ALPN protocol count"));
        }
        let protocol_len = usize::from(protocols.read_u8()?);
        if protocol_len == 0 {
            return Err(ClientHelloError::Malformed("empty ALPN protocol"));
        }
        output.push(protocols.read_range(protocol_len)?);
    }
    Ok(output)
}

fn parse_pre_shared_key(reader: &mut Reader<'_>) -> Result<(), ClientHelloError> {
    let identities_len = usize::from(reader.read_u16()?);
    let mut identities = reader.read_subreader(identities_len)?;
    let mut identity_count = 0;
    while !identities.is_empty() {
        if identity_count >= MAX_PSK_IDENTITIES {
            return Err(ClientHelloError::Malformed("PSK identity count"));
        }
        let identity_len = usize::from(identities.read_u16()?);
        if identity_len == 0 {
            return Err(ClientHelloError::Malformed("empty PSK identity"));
        }
        identities.read_bytes(identity_len)?;
        identities.read_bytes(4)?;
        identity_count += 1;
    }

    let binders_len = usize::from(reader.read_u16()?);
    let mut binders = reader.read_subreader(binders_len)?;
    if !reader.is_empty() {
        return Err(ClientHelloError::Malformed("PSK"));
    }
    let mut binder_count = 0;
    while !binders.is_empty() {
        if binder_count >= MAX_PSK_BINDERS {
            return Err(ClientHelloError::Malformed("PSK binder count"));
        }
        let binder_len = usize::from(binders.read_u8()?);
        if binder_len < 32 {
            return Err(ClientHelloError::Malformed("PSK binder"));
        }
        binders.read_bytes(binder_len)?;
        binder_count += 1;
    }
    if identity_count == 0 || identity_count != binder_count {
        return Err(ClientHelloError::Malformed("PSK identity and binder count"));
    }
    Ok(())
}

/// RFC 8701 GREASE value test.
const fn is_grease(value: u16) -> bool {
    (value & 0x0f0f) == 0x0a0a && (value >> 8) == (value & 0x00ff)
}

struct Reader<'input> {
    input: &'input [u8],
    position: usize,
    end: usize,
}

impl<'input> Reader<'input> {
    const fn new(input: &'input [u8]) -> Self {
        Self {
            input,
            position: 0,
            end: input.len(),
        }
    }

    const fn is_empty(&self) -> bool {
        self.position == self.end
    }

    const fn remaining(&self) -> usize {
        self.end.saturating_sub(self.position)
    }

    fn read_range(&mut self, length: usize) -> Result<Range<usize>, ClientHelloError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ClientHelloError::TooLarge)?;
        if end > self.end {
            return Err(ClientHelloError::Truncated);
        }
        let range = self.position..end;
        self.position = end;
        Ok(range)
    }

    fn read_bytes(&mut self, length: usize) -> Result<&'input [u8], ClientHelloError> {
        let range = self.read_range(length)?;
        self.bytes(&range)
    }

    fn bytes(&self, range: &Range<usize>) -> Result<&'input [u8], ClientHelloError> {
        self.input
            .get(range.clone())
            .ok_or(ClientHelloError::Truncated)
    }

    fn read_subreader(&mut self, length: usize) -> Result<Self, ClientHelloError> {
        let range = self.read_range(length)?;
        Ok(Self {
            input: self.input,
            position: range.start,
            end: range.end,
        })
    }

    fn read_u8(&mut self) -> Result<u8, ClientHelloError> {
        self.read_bytes(1)?
            .first()
            .copied()
            .ok_or(ClientHelloError::Truncated)
    }

    fn read_u16(&mut self) -> Result<u16, ClientHelloError> {
        let bytes: [u8; 2] = self
            .read_bytes(2)?
            .try_into()
            .map_err(|_| ClientHelloError::Truncated)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u24(&mut self) -> Result<u32, ClientHelloError> {
        let bytes: [u8; 3] = self
            .read_bytes(3)?
            .try_into()
            .map_err(|_| ClientHelloError::Truncated)?;
        Ok(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
    }

    fn skip_remaining(&mut self) {
        self.position = self.end;
    }
}

#[cfg(any(test, feature = "fuzzing"))]
pub(crate) mod fixtures {
    #[cfg(test)]
    use super::X25519_GROUP;
    use super::{
        EXT_ALPN, EXT_KEY_SHARE, EXT_SERVER_NAME, EXT_SUPPORTED_VERSIONS,
        HANDSHAKE_TYPE_CLIENT_HELLO,
    };

    #[cfg(test)]
    pub(crate) fn client_hello(
        random: [u8; 32],
        session_id: &[u8],
        server_name: &str,
        alpn: &[&[u8]],
    ) -> Vec<u8> {
        client_hello_with_key_share(
            random,
            session_id,
            server_name,
            alpn,
            X25519_GROUP,
            &[0x42; 32],
        )
    }

    pub(crate) fn client_hello_with_key_share(
        random: [u8; 32],
        session_id: &[u8],
        server_name: &str,
        alpn: &[&[u8]],
        key_share_group: u16,
        key_share_data: &[u8],
    ) -> Vec<u8> {
        let mut extensions = Vec::new();
        let mut names = vec![0];
        push_u16_length(&mut names, server_name.as_bytes());
        let mut server_name_body = Vec::new();
        push_u16_length(&mut server_name_body, &names);
        push_extension(&mut extensions, EXT_SERVER_NAME, &server_name_body);
        push_extension(&mut extensions, EXT_SUPPORTED_VERSIONS, &[2, 0x03, 0x04]);

        let mut share_entries = Vec::new();
        share_entries.extend_from_slice(&key_share_group.to_be_bytes());
        push_u16_length(&mut share_entries, key_share_data);
        let mut shares = Vec::new();
        push_u16_length(&mut shares, &share_entries);
        push_extension(&mut extensions, EXT_KEY_SHARE, &shares);

        if !alpn.is_empty() {
            let mut protocols = Vec::new();
            for protocol in alpn {
                protocols.push(u8::try_from(protocol.len()).expect("test ALPN must fit u8"));
                protocols.extend_from_slice(protocol);
            }
            let mut alpn_body = Vec::new();
            push_u16_length(&mut alpn_body, &protocols);
            push_extension(&mut extensions, EXT_ALPN, &alpn_body);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303_u16.to_be_bytes());
        body.extend_from_slice(&random);
        body.push(u8::try_from(session_id.len()).expect("test session ID must fit u8"));
        body.extend_from_slice(session_id);
        push_u16_length(&mut body, &0x1301_u16.to_be_bytes());
        body.extend_from_slice(&[1, 0]);
        push_u16_length(&mut body, &extensions);

        let mut message = vec![HANDSHAKE_TYPE_CLIENT_HELLO];
        let length = u32::try_from(body.len()).expect("test ClientHello must fit u24");
        message.extend_from_slice(&length.to_be_bytes()[1..]);
        message.extend_from_slice(&body);
        message
    }

    #[cfg(test)]
    pub(crate) fn record(message: &[u8]) -> Vec<u8> {
        let mut output = vec![0x16, 0x03, 0x01];
        push_u16_length(&mut output, message);
        output
    }

    pub(crate) fn push_extension(output: &mut Vec<u8>, extension_type: u16, body: &[u8]) {
        output.extend_from_slice(&extension_type.to_be_bytes());
        push_u16_length(output, body);
    }

    fn push_u16_length(output: &mut Vec<u8>, bytes: &[u8]) {
        output.extend_from_slice(
            &u16::try_from(bytes.len())
                .expect("test vector length must fit u16")
                .to_be_bytes(),
        );
        output.extend_from_slice(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClientHello, ClientHelloClassError, ClientHelloError, EXT_ENCRYPTED_CLIENT_HELLO,
        EXT_PRE_SHARED_KEY, MAX_CLIENT_HELLO_BYTES, SESSION_ID_LEN, SESSION_ID_OFFSET,
        X25519_GROUP, X25519_MLKEM768_GROUP, X25519_MLKEM768_SHARE_LEN, extension_segments,
        fixtures::{client_hello, client_hello_with_key_share, record},
    };

    #[test]
    fn parses_fields_without_copying_variable_payloads() {
        let random = [7; 32];
        let session_id = [0xcd; SESSION_ID_LEN];
        let message = client_hello(
            random,
            &session_id,
            "www.example.com",
            &[b"h2", b"http/1.1"],
        );
        let hello = ClientHello::parse_message(&message).expect("ClientHello must parse");

        assert_eq!(hello.raw_message(), message);
        assert_eq!(hello.random(), &random);
        assert_eq!(hello.server_name(), Some("www.example.com"));
        assert_eq!(hello.session_ciphertext(), Some(&session_id));
        assert_eq!(
            hello.alpn_protocols().collect::<Vec<_>>(),
            vec![b"h2".as_slice(), b"http/1.1".as_slice()]
        );
        assert!(hello.offers_tls13());
        assert_eq!(hello.peer_x25519(), Some([0x42; 32]));
        assert!(hello.cipher_offered(0x1301));
        assert!(hello.key_share_group_offered(X25519_GROUP));
    }

    #[test]
    fn profile_class_excludes_only_fresh_session_fields() {
        let first = ClientHello::parse_message(&client_hello_with_key_share(
            [0x11; 32],
            &[0x21; 32],
            "www.example.com",
            &[b"h2", b"http/1.1"],
            X25519_GROUP,
            &[0x31; 32],
        ))
        .expect("first ClientHello must parse");
        let second = ClientHello::parse_message(&client_hello_with_key_share(
            [0x12; 32],
            &[0x22; 32],
            "www.example.com",
            &[b"h2", b"http/1.1"],
            X25519_GROUP,
            &[0x32; 32],
        ))
        .expect("second ClientHello must parse");

        assert_eq!(
            first
                .normalized_profile_class()
                .expect("first class must normalize"),
            second
                .normalized_profile_class()
                .expect("second class must normalize")
        );
        assert_eq!(
            format!(
                "{:?}",
                first
                    .normalized_profile_class()
                    .expect("class must normalize")
            ),
            "NormalizedClientHelloClass([REDACTED])"
        );
    }

    #[test]
    fn profile_class_separates_behavioral_offers() {
        let h2 = ClientHello::parse_message(&client_hello(
            [0; 32],
            &[1; 32],
            "www.example.com",
            &[b"h2", b"http/1.1"],
        ))
        .expect("h2 ClientHello must parse");
        let http1 = ClientHello::parse_message(&client_hello(
            [0; 32],
            &[1; 32],
            "www.example.com",
            &[b"http/1.1"],
        ))
        .expect("http/1.1 ClientHello must parse");
        let other_sni = ClientHello::parse_message(&client_hello(
            [0; 32],
            &[1; 32],
            "other.example.com",
            &[b"h2", b"http/1.1"],
        ))
        .expect("other-SNI ClientHello must parse");
        let hybrid = ClientHello::parse_message(&client_hello_with_key_share(
            [0; 32],
            &[1; 32],
            "www.example.com",
            &[b"h2", b"http/1.1"],
            X25519_MLKEM768_GROUP,
            &[0x44; X25519_MLKEM768_SHARE_LEN],
        ))
        .expect("hybrid ClientHello must parse");

        let base = h2
            .normalized_profile_class()
            .expect("base class must normalize");
        assert_ne!(
            base,
            http1
                .normalized_profile_class()
                .expect("ALPN class must normalize")
        );
        assert_ne!(
            base,
            other_sni
                .normalized_profile_class()
                .expect("SNI class must normalize")
        );
        assert_ne!(
            base,
            hybrid
                .normalized_profile_class()
                .expect("hybrid class must normalize")
        );
    }

    #[test]
    fn profile_class_rejects_unsupported_key_share() {
        let hello = ClientHello::parse_message(&client_hello_with_key_share(
            [0; 32],
            &[1; 32],
            "www.example.com",
            &[b"h2"],
            0x0017,
            &[0x04; 65],
        ))
        .expect("P-256 offer remains a structurally valid ClientHello");
        assert_eq!(
            hello.normalized_profile_class(),
            Err(ClientHelloClassError::UnsupportedKeyShare)
        );
    }

    #[test]
    fn controlled_probes_refresh_session_fields_and_preserve_the_class() {
        let hello = ClientHello::parse_message(&client_hello(
            [0x10; 32],
            &[0x20; 32],
            "www.example.com",
            &[b"h2", b"http/1.1"],
        ))
        .expect("source ClientHello must parse");
        let template = hello
            .controlled_cover_probe_template()
            .expect("eligible authenticated shape must sanitize");
        let first = template.generate(0).expect("first probe must generate");
        let second = template.generate(1).expect("second probe must generate");

        assert_eq!(
            first
                .hello()
                .normalized_profile_class()
                .expect("first probe class must normalize"),
            template.class()
        );
        assert_eq!(
            second
                .hello()
                .normalized_profile_class()
                .expect("second probe class must normalize"),
            template.class()
        );
        assert_ne!(first.hello().random(), second.hello().random());
        assert_ne!(first.hello().session_id(), second.hello().session_id());
        assert_ne!(first.hello().raw_message(), second.hello().raw_message());
    }

    #[test]
    fn grease_values_and_extension_order_normalize_only_when_shape_matches() {
        let base = client_hello(
            [0x10; 32],
            &[0x20; 32],
            "www.example.com",
            &[b"h2", b"http/1.1"],
        );
        let grease_a = append_extension(base.clone(), 0x0a0a, &[]);
        let grease_b = append_extension(base, 0x1a1a, &[]);
        let reversed = reverse_extensions(&grease_a);
        let classes = [&grease_a, &grease_b, &reversed].map(|message| {
            ClientHello::parse_message(message)
                .expect("GREASE ClientHello must parse")
                .normalized_profile_class()
                .expect("GREASE class must normalize")
        });
        assert_eq!(classes[0], classes[1]);
        assert_eq!(classes[0], classes[2]);

        let source = ClientHello::parse_message(&grease_a).expect("GREASE source must parse");
        let template = source
            .controlled_cover_probe_template()
            .expect("GREASE template must sanitize");
        let first = template.generate(0).expect("first GREASE probe must build");
        let second = template
            .generate(1)
            .expect("second GREASE probe must build");
        let first_types: Vec<u16> = extension_segments(first.hello().raw_message())
            .expect("first probe extensions must parse")
            .into_iter()
            .map(|segment| segment.extension_type)
            .filter(|extension_type| super::is_grease(*extension_type))
            .collect();
        let second_types: Vec<u16> = extension_segments(second.hello().raw_message())
            .expect("second probe extensions must parse")
            .into_iter()
            .map(|segment| segment.extension_type)
            .filter(|extension_type| super::is_grease(*extension_type))
            .collect();
        assert_ne!(first_types, second_types);
        assert_eq!(
            first.hello().normalized_profile_class(),
            second.hello().normalized_profile_class()
        );
    }

    #[test]
    fn grease_ech_content_normalizes_but_observable_length_does_not() {
        let base = client_hello([0x10; 32], &[0x20; 32], "www.example.com", &[b"h2"]);
        let ech = |fill: u8, payload_len: usize| {
            let mut body = vec![0, 0, 1, 0, 1, fill, 0, 32];
            body.extend(std::iter::repeat_n(fill, 32));
            body.extend_from_slice(
                &u16::try_from(payload_len)
                    .expect("test ECH payload must fit")
                    .to_be_bytes(),
            );
            body.extend(std::iter::repeat_n(fill, payload_len));
            append_extension(base.clone(), EXT_ENCRYPTED_CLIENT_HELLO, &body)
        };
        let first = ClientHello::parse_message(&ech(0x11, 144)).expect("ECH must parse");
        let second = ClientHello::parse_message(&ech(0x22, 144)).expect("ECH must parse");
        let longer = ClientHello::parse_message(&ech(0x33, 176)).expect("ECH must parse");
        assert_eq!(
            first.normalized_profile_class(),
            second.normalized_profile_class()
        );
        assert_ne!(
            first.normalized_profile_class(),
            longer.normalized_profile_class()
        );
    }

    #[test]
    fn profile_class_rejects_valid_tls13_psk_offers() {
        let mut psk = Vec::new();
        psk.extend_from_slice(&7_u16.to_be_bytes());
        psk.extend_from_slice(&1_u16.to_be_bytes());
        psk.push(0x42);
        psk.extend_from_slice(&0_u32.to_be_bytes());
        psk.extend_from_slice(&33_u16.to_be_bytes());
        psk.push(32);
        psk.extend_from_slice(&[0x55; 32]);
        let message = append_extension(
            client_hello([0; 32], &[1; 32], "www.example.com", &[b"h2"]),
            EXT_PRE_SHARED_KEY,
            &psk,
        );
        let hello = ClientHello::parse_message(&message).expect("PSK offer must parse strictly");
        assert_eq!(
            hello.normalized_profile_class(),
            Err(ClientHelloClassError::PreSharedKey)
        );
    }

    fn append_extension(mut message: Vec<u8>, extension_type: u16, body: &[u8]) -> Vec<u8> {
        let segments = extension_segments(&message).expect("base extensions must parse");
        let extensions_start = segments.first().expect("fixture has extensions").wire.start;
        let length_offset = extensions_start - 2;
        let old_extensions_len = usize::from(u16::from_be_bytes([
            message[length_offset],
            message[length_offset + 1],
        ]));
        message.extend_from_slice(&extension_type.to_be_bytes());
        message.extend_from_slice(
            &u16::try_from(body.len())
                .expect("test extension body must fit")
                .to_be_bytes(),
        );
        message.extend_from_slice(body);
        let new_extensions_len = old_extensions_len + 4 + body.len();
        message[length_offset..length_offset + 2].copy_from_slice(
            &u16::try_from(new_extensions_len)
                .expect("test extension vector must fit")
                .to_be_bytes(),
        );
        let body_len = message.len() - 4;
        message[1..4].copy_from_slice(
            &u32::try_from(body_len)
                .expect("test message must fit")
                .to_be_bytes()[1..],
        );
        message
    }

    fn reverse_extensions(message: &[u8]) -> Vec<u8> {
        let segments = extension_segments(message).expect("extensions must parse");
        let first = segments.first().expect("fixture has extensions");
        let last = segments.last().expect("fixture has extensions");
        let mut output = message[..first.wire.start].to_vec();
        for segment in segments.iter().rev() {
            output.extend_from_slice(&message[segment.wire.clone()]);
        }
        output.extend_from_slice(&message[last.wire.end..]);
        output
    }

    #[test]
    fn builds_exact_reality_aad_and_nonce() {
        let random = [9; 32];
        let session_id = [0xab; SESSION_ID_LEN];
        let message = client_hello(random, &session_id, "a.example", &[]);
        let hello = ClientHello::parse_message(&message).expect("ClientHello must parse");
        let aad = hello
            .reality_aad()
            .expect("32-byte session ID must make AAD");

        assert_eq!(
            aad.get(SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN),
            Some([0_u8; SESSION_ID_LEN].as_slice())
        );
        assert_eq!(hello.aead_nonce(), [9; 12]);
    }

    #[test]
    fn extracts_hybrid_x25519_and_mlkem_parts() {
        let mut hybrid = vec![0x7a; X25519_MLKEM768_SHARE_LEN];
        hybrid
            .get_mut(X25519_MLKEM768_SHARE_LEN - 32..)
            .expect("test hybrid tail must exist")
            .fill(0x99);
        let message = client_hello_with_key_share(
            [0; 32],
            &[1; 32],
            "a.example",
            &[],
            X25519_MLKEM768_GROUP,
            &hybrid,
        );
        let hello = ClientHello::parse_message(&message).expect("hybrid ClientHello must parse");

        assert_eq!(hello.peer_x25519(), Some([0x99; 32]));
        assert_eq!(
            hello.peer_mlkem768_encapsulation_key(),
            hybrid.get(..X25519_MLKEM768_SHARE_LEN - 32)
        );
    }

    #[test]
    fn parses_exact_record_and_rejects_trailing_bytes() {
        let message = client_hello([0; 32], &[1; 32], "a.example", &[]);
        let mut record = record(&message);
        assert!(ClientHello::parse_record(&record).is_ok());

        record.push(0);
        assert!(matches!(
            ClientHello::parse_record(&record),
            Err(ClientHelloError::LengthMismatch)
        ));
    }

    #[test]
    fn rejects_odd_cipher_suite_vector() {
        let mut message = client_hello([0; 32], &[1; 32], "a.example", &[]);
        let cipher_length_offset = SESSION_ID_OFFSET + SESSION_ID_LEN;
        message[cipher_length_offset] = 0;
        message[cipher_length_offset + 1] = 1;

        assert!(matches!(
            ClientHello::parse_message(&message),
            Err(ClientHelloError::Malformed("cipher suites"))
        ));
    }

    #[test]
    fn rejects_oversized_input_before_parsing() {
        let oversized = vec![0; MAX_CLIENT_HELLO_BYTES + 1];

        assert!(matches!(
            ClientHello::parse_message(&oversized),
            Err(ClientHelloError::TooLarge)
        ));
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut state = 0x1234_5678_u32;
        for length in 0..2_048 {
            let mut input = Vec::with_capacity(length);
            for _ in 0..length {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                input.push(state.to_be_bytes()[1]);
            }
            let _result = ClientHello::parse_message(&input);
        }
    }
}
