//! REALITY session authentication: short-IDs, AEAD seal, and user binding.
//!
//! Derives the session key material from the authenticated ClientHello, seals
//! and opens the 16-byte session plaintext, and maps short IDs to configured
//! users. Crypto provider ownership stays with this module and is enforced by
//! `crypto_boundary`.

use std::{collections::HashMap, error::Error, fmt};

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{AeadInOut, Nonce, Tag, array::Array},
};
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use sha2::Sha256;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::ClientHello;
use crate::{
    config::node::{entry::EntryConfig, reality::RealityConfig},
    crypto::StaticX25519Key,
};
use crate::{
    protocol::vless::UserId,
    server_name::{is_server_name_pattern, server_name_matches},
};

const AUTH_KEY_INFO: &[u8] = b"REALITY";
const SESSION_PLAINTEXT_LEN: usize = 16;
const GCM_TAG_LEN: usize = 16;
/// Measured crossover: sorted lookup wins through 256 short IDs; SipHash wins
/// both hit and miss at 512. Keep the lower observed boundary.
const SORTED_SHORT_ID_LIMIT: usize = 256;

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing {
    use aes_gcm::{
        Aes256Gcm, KeyInit,
        aead::{AeadInOut, Nonce, array::Array},
    };
    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};

    use super::{RealityAuthenticator, derive_auth_key};
    use crate::crypto::StaticX25519Key;
    use crate::{
        config::{SecretString, node::reality::RealityConfig},
        protocol::{
            reality::{
                ClientHello, X25519_GROUP, client_hello::fixtures::client_hello_with_key_share,
            },
            vless::UserId,
        },
    };

    /// An entirely synthetic valid REALITY authentication transcript.
    pub struct SyntheticTranscript {
        /// Compiled server-side authentication state.
        pub authenticator: RealityAuthenticator,
        /// Parsed synthetic ClientHello carrying a valid REALITY session ID.
        pub hello: ClientHello,
        /// UUID that owns the selected short ID.
        pub owner: UserId,
    }

    /// Synthetic inputs for one valid REALITY transcript.
    pub struct SyntheticTranscriptSpec {
        /// Client X25519 private bytes.
        pub client_secret: [u8; 32],
        /// ClientHello random.
        pub random: [u8; 32],
        /// Three-byte Xray client version.
        pub client_version: [u8; 3],
        /// Client Unix timestamp.
        pub client_time: u32,
        /// Selected REALITY short ID.
        pub short_id: [u8; 8],
        /// UUID owning the selected short ID.
        pub owner: [u8; 16],
        /// A second configured short ID.
        pub other_short_id: [u8; 8],
        /// UUID owning the second short ID.
        pub other_owner: [u8; 16],
    }

    /// Builds a valid synthetic X25519/HKDF/AES-GCM REALITY transcript.
    ///
    /// This entry point exists only with the non-default `fuzzing` feature.
    #[must_use]
    pub fn synthetic_transcript(spec: SyntheticTranscriptSpec) -> SyntheticTranscript {
        const SERVER_SECRET: [u8; 32] = [0x11; 32];
        const SERVER_NAME: &str = "www.example.com";

        let server_public = StaticX25519Key::new(&SERVER_SECRET).public_key();
        let client_public = StaticX25519Key::new(&spec.client_secret).public_key();
        let shared = StaticX25519Key::new(&spec.client_secret)
            .agree(&server_public)
            .expect("the fixture secrets agree");
        let auth_key = derive_auth_key(&shared, &spec.random)
            .expect("REALITY HKDF output has a fixed valid length");
        let zero_message = client_hello_with_key_share(
            spec.random,
            &[0; 32],
            SERVER_NAME,
            &[],
            X25519_GROUP,
            &client_public,
        );
        let mut plaintext = [0_u8; 16];
        plaintext[..3].copy_from_slice(&spec.client_version);
        plaintext[4..8].copy_from_slice(&spec.client_time.to_be_bytes());
        plaintext[8..].copy_from_slice(&spec.short_id);
        let cipher = Aes256Gcm::new(&Array(*auth_key.as_bytes()));
        let nonce: Nonce<Aes256Gcm> = Array([
            spec.random[20],
            spec.random[21],
            spec.random[22],
            spec.random[23],
            spec.random[24],
            spec.random[25],
            spec.random[26],
            spec.random[27],
            spec.random[28],
            spec.random[29],
            spec.random[30],
            spec.random[31],
        ]);
        let tag = cipher
            .encrypt_inout_detached(&nonce, &zero_message, plaintext.as_mut_slice().into())
            .expect("fixed-size synthetic REALITY encryption must succeed");
        let mut session_id = [0_u8; 32];
        session_id[..16].copy_from_slice(&plaintext);
        session_id[16..].copy_from_slice(&tag);
        let message = client_hello_with_key_share(
            spec.random,
            &session_id,
            SERVER_NAME,
            &[],
            X25519_GROUP,
            &client_public,
        );
        let hello = ClientHello::parse_message(&message)
            .expect("synthetic ClientHello is structurally valid");
        let owner = UserId::new(spec.owner);
        let mut bindings = vec![(spec.short_id, spec.owner)];
        if spec.other_short_id != spec.short_id {
            bindings.push((spec.other_short_id, spec.other_owner));
        }
        let authenticator = synthetic_authenticator(&bindings);
        SyntheticTranscript {
            authenticator,
            hello,
            owner,
        }
    }

    /// Compiles synthetic ownership state for reject-path fuzzing.
    #[must_use]
    pub fn synthetic_authenticator(bindings: &[([u8; 8], [u8; 16])]) -> RealityAuthenticator {
        const SERVER_SECRET: [u8; 32] = [0x11; 32];
        let config = RealityConfig {
            cover: "cover.invalid:443".to_owned(),
            private_key: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(SERVER_SECRET)),
            server_names: Some(vec!["www.example.com".to_owned()]),
            max_time_diff_ms: None,
            cover_optimization: None,
        };
        let encoded = bindings
            .iter()
            .map(|(short_id, owner)| (UserId::new(*owner), encode_short_id(*short_id)))
            .collect::<Vec<_>>();
        RealityAuthenticator::compile(
            &config,
            encoded
                .iter()
                .map(|(owner, short_id)| (*owner, short_id.as_str())),
        )
        .expect("synthetic REALITY authentication state is valid")
    }

    fn encode_short_id(short_id: [u8; 8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(16);
        for byte in short_id {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}

/// A decoded REALITY setting cannot be compiled into authentication state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealityAuthConfigError {
    /// The URL-safe private key is not exactly 32 bytes.
    InvalidPrivateKey,
    /// A configured short ID is not valid even-length hexadecimal up to eight bytes.
    InvalidShortId,
    /// No server name was configured.
    MissingServerName,
    /// A server name was neither concrete DNS nor a safe leftmost wildcard.
    InvalidServerName,
    /// No short ID was configured.
    MissingShortId,
    /// A short ID was assigned more than once when validation was bypassed.
    DuplicateShortId,
    /// A client UUID was malformed when validation was bypassed.
    InvalidUserId,
}

impl fmt::Display for RealityAuthConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrivateKey => formatter.write_str("invalid REALITY private key"),
            Self::InvalidShortId => formatter.write_str("invalid REALITY short ID"),
            Self::MissingServerName => formatter.write_str("REALITY server name set is empty"),
            Self::InvalidServerName => formatter.write_str("invalid REALITY server name pattern"),
            Self::MissingShortId => formatter.write_str("REALITY short ID set is empty"),
            Self::DuplicateShortId => formatter.write_str("REALITY short ID has multiple owners"),
            Self::InvalidUserId => formatter.write_str("invalid REALITY client UUID"),
        }
    }
}

impl Error for RealityAuthConfigError {}

/// Authentication failures are internally distinguishable but all select fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealityAuthError {
    /// ClientHello does not offer TLS 1.3.
    UnsupportedTls,
    /// SNI is absent or not configured on this listener.
    ServerName,
    /// No compatible X25519 or hybrid key share exists.
    MissingKeyShare,
    /// X25519 produced a non-contributory all-zero shared secret.
    NonContributoryKey,
    /// Session ID is not a 32-byte REALITY ciphertext.
    MissingCiphertext,
    /// Key derivation failed.
    KeyDerivation,
    /// AES-GCM authentication failed.
    OpenFailed,
    /// The reserved plaintext byte is non-zero.
    ReservedByte,
    /// No configured short ID has an owner on this listener.
    ShortId,
    /// Client clock difference exceeds the configured limit.
    TimeSkew,
}

impl fmt::Display for RealityAuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("REALITY authentication failed")
    }
}

impl Error for RealityAuthError {}

/// The Xray-compatible client version advertised inside the authenticator.
///
/// The server records these three bytes and does not gate on them today; the
/// value must remain a plausible Xray release identifier for interoperability.
pub const CLIENT_VERSION: [u8; 3] = [26, 7, 28];

/// The 16-byte REALITY session-id plaintext sealed into the ClientHello.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthPlaintext {
    /// Three-byte client version.
    pub version: [u8; 3],
    /// Client Unix time in seconds.
    pub time: u32,
    /// Short ID, right-zero-padded to eight bytes on the wire.
    pub short_id: [u8; 8],
}

impl AuthPlaintext {
    /// Encodes the authenticator plaintext. Byte 3 is reserved and always zero.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; SESSION_PLAINTEXT_LEN] {
        let time = self.time.to_be_bytes();
        [
            self.version[0],
            self.version[1],
            self.version[2],
            0,
            time[0],
            time[1],
            time[2],
            time[3],
            self.short_id[0],
            self.short_id[1],
            self.short_id[2],
            self.short_id[3],
            self.short_id[4],
            self.short_id[5],
            self.short_id[6],
            self.short_id[7],
        ]
    }
}

/// Derived REALITY authentication key, zeroized on drop and redacted in debug output.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct AuthKey([u8; 32]);

impl AuthKey {
    /// Exposes the key only to protocol code that explicitly needs certificate binding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derives the authentication key from the ECDHE shared secret and ClientHello random.
    ///
    /// # Errors
    ///
    /// Returns [`RealityAuthError::KeyDerivation`] when HKDF refuses the fixed-size inputs.
    pub fn derive(
        shared_secret: &[u8; 32],
        client_random: &[u8; 32],
    ) -> Result<Self, RealityAuthError> {
        derive_auth_key(shared_secret, client_random)
    }

    /// Seals the 32-byte session ID for a ClientHello whose session ID is zeroed in `aad`.
    ///
    /// `aad` must be the handshake message with the 32-byte session ID set to zero — the
    /// same buffer the server reconstructs the server reconstructs before opening.
    ///
    /// # Errors
    ///
    /// Returns [`RealityAuthError::OpenFailed`] when AES-GCM refuses the inputs (should not
    /// occur for well-formed fixed-size plaintext).
    pub fn seal_session_id(
        &self,
        client_random: &[u8; 32],
        aad: &[u8],
        plaintext: AuthPlaintext,
    ) -> Result<[u8; 32], RealityAuthError> {
        let nonce = aead_nonce_from_random(client_random);
        seal_session_id(self.as_bytes(), &nonce, &plaintext.to_bytes(), aad)
    }

    #[cfg(test)]
    pub(crate) const fn from_test_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for AuthKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthKey([REDACTED])")
    }
}

/// Recovered fixed REALITY client metadata and its derived authentication key.
pub struct RealityAuthResult {
    client_version: [u8; 3],
    client_time: u32,
    user_id: UserId,
    auth_key: AuthKey,
}

impl RealityAuthResult {
    /// Returns the three-byte Xray client version.
    #[must_use]
    pub const fn client_version(&self) -> [u8; 3] {
        self.client_version
    }

    /// Returns the client Unix timestamp in seconds.
    #[must_use]
    pub const fn client_time(&self) -> u32 {
        self.client_time
    }

    /// Returns the UUID that owns the authenticated short ID.
    #[must_use]
    pub const fn user_id(&self) -> UserId {
        self.user_id
    }

    /// Returns the derived authentication key.
    #[must_use]
    pub const fn auth_key(&self) -> &AuthKey {
        &self.auth_key
    }
}

impl fmt::Debug for RealityAuthResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityAuthResult")
            .field("client_version", &self.client_version)
            .field("client_time", &self.client_time)
            .field("user_id", &"[REDACTED]")
            .field("auth_key", &self.auth_key)
            .finish()
    }
}

/// Immutable, decoded authentication state for one REALITY listener snapshot.
///
/// Deliberately not `Clone`: one runtime generation owns one compiled key, and
/// the previous derive was unused. Cloning would copy private key material to
/// satisfy a derive rather than a requirement.
pub struct RealityAuthenticator {
    private_key: StaticX25519Key,
    server_names: Vec<String>,
    short_ids: ShortIdOwnerIndex,
    max_time_diff_ms: u64,
}

/// One sorted authentication selector and its unique UUID owner.
#[derive(Clone, Copy)]
struct ShortIdBinding {
    short_id: [u8; 8],
    user_id: UserId,
}

/// Cardinality-adaptive short-ID-to-UUID ownership index.
#[derive(Clone)]
enum ShortIdOwnerIndex {
    Sorted(Box<[ShortIdBinding]>),
    Hashed(HashMap<[u8; 8], UserId>),
}

impl ShortIdOwnerIndex {
    fn from_sorted(bindings: Vec<ShortIdBinding>) -> Self {
        if bindings.len() <= SORTED_SHORT_ID_LIMIT {
            Self::Sorted(bindings.into_boxed_slice())
        } else {
            Self::Hashed(
                bindings
                    .into_iter()
                    .map(|binding| (binding.short_id, binding.user_id))
                    .collect(),
            )
        }
    }

    fn owner(&self, candidate: &[u8; 8]) -> Option<UserId> {
        match self {
            Self::Sorted(bindings) => bindings
                .binary_search_by_key(candidate, |binding| binding.short_id)
                .ok()
                .map(|index| bindings[index].user_id),
            Self::Hashed(bindings) => bindings.get(candidate).copied(),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Sorted(bindings) => bindings.len(),
            Self::Hashed(bindings) => bindings.len(),
        }
    }
}

impl fmt::Debug for RealityAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityAuthenticator")
            .field("private_key", &"[REDACTED]")
            .field("server_name_count", &self.server_names.len())
            .field("short_id_count", &self.short_ids.len())
            .field("max_time_diff_ms", &self.max_time_diff_ms)
            .finish()
    }
}

impl RealityAuthenticator {
    /// Decodes and compiles one validated entry node into immutable
    /// authentication state.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed key material, server names, short IDs, or empty identity sets.
    pub fn from_entry(entry: &EntryConfig) -> Result<Self, RealityAuthConfigError> {
        let mut short_ids = Vec::new();
        for user in &entry.users {
            let uuid =
                Uuid::parse_str(&user.id).map_err(|_| RealityAuthConfigError::InvalidUserId)?;
            let user_id = UserId::new(*uuid.as_bytes());
            short_ids.extend(
                user.short_ids
                    .iter()
                    .map(|short_id| (user_id, short_id.as_str())),
            );
        }
        Self::compile(&entry.reality, short_ids)
    }

    fn compile<'a>(
        config: &RealityConfig,
        configured_short_ids: impl IntoIterator<Item = (UserId, &'a str)>,
    ) -> Result<Self, RealityAuthConfigError> {
        // An omitted `serverNames` accepts the cover host, which semantic
        // validation has already proved is a usable name.
        let server_names: Vec<String> = config
            .effective_server_names()
            .into_iter()
            .map(str::to_owned)
            .collect();
        if server_names.is_empty() {
            return Err(RealityAuthConfigError::MissingServerName);
        }
        if !server_names.iter().all(|name| is_server_name_pattern(name)) {
            return Err(RealityAuthConfigError::InvalidServerName);
        }
        let decoded_private = Zeroizing::new(
            BASE64_URL_SAFE_NO_PAD
                .decode(config.private_key.expose())
                .map_err(|_| RealityAuthConfigError::InvalidPrivateKey)?,
        );
        let private_bytes: [u8; 32] = decoded_private
            .as_slice()
            .try_into()
            .map_err(|_| RealityAuthConfigError::InvalidPrivateKey)?;
        let mut short_ids = configured_short_ids
            .into_iter()
            .map(|(user_id, short_id)| {
                decode_short_id(short_id).map(|short_id| ShortIdBinding { short_id, user_id })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if short_ids.is_empty() {
            return Err(RealityAuthConfigError::MissingShortId);
        }
        short_ids.sort_unstable_by_key(|binding| binding.short_id);
        if short_ids
            .windows(2)
            .any(|pair| pair[0].short_id == pair[1].short_id)
        {
            return Err(RealityAuthConfigError::DuplicateShortId);
        }
        Ok(Self {
            private_key: StaticX25519Key::new(&private_bytes),
            server_names,
            short_ids: ShortIdOwnerIndex::from_sorted(short_ids),
            max_time_diff_ms: config.max_time_diff_ms(),
        })
    }

    /// Authenticates one parsed ClientHello at an explicit Unix time.
    ///
    /// The caller must route every error to the same bounded byte-exact fallback.
    /// No replay state is changed here; replay reservation is a later explicit phase.
    ///
    /// # Errors
    ///
    /// Returns a non-observable internal category for any failed invariant.
    pub fn authenticate(
        &self,
        hello: &ClientHello,
        now_unix_seconds: u64,
    ) -> Result<RealityAuthResult, RealityAuthError> {
        if !hello.offers_tls13() {
            return Err(RealityAuthError::UnsupportedTls);
        }
        let server_name = hello.server_name().ok_or(RealityAuthError::ServerName)?;
        if !self
            .server_names
            .iter()
            .any(|configured| server_name_matches(configured, server_name))
        {
            return Err(RealityAuthError::ServerName);
        }

        let peer = hello
            .peer_x25519()
            .ok_or(RealityAuthError::MissingKeyShare)?;
        let shared = self
            .private_key
            .agree(&peer)
            .ok_or(RealityAuthError::NonContributoryKey)?;
        let auth_key = derive_auth_key(&shared, hello.random())?;
        let ciphertext = hello
            .session_ciphertext()
            .ok_or(RealityAuthError::MissingCiphertext)?;
        let aad = hello
            .reality_aad()
            .ok_or(RealityAuthError::MissingCiphertext)?;
        let mut plaintext =
            open_session_id(auth_key.as_bytes(), &hello.aead_nonce(), ciphertext, &aad)?;

        if plaintext[3] != 0 {
            return Err(RealityAuthError::ReservedByte);
        }
        let client_version = [plaintext[0], plaintext[1], plaintext[2]];
        let client_time =
            u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
        let mut short_id = [0_u8; 8];
        short_id.copy_from_slice(&plaintext[8..16]);
        plaintext.zeroize();

        let Some(user_id) = self.short_id_owner(&short_id) else {
            short_id.zeroize();
            return Err(RealityAuthError::ShortId);
        };
        short_id.zeroize();
        let difference_ms = u128::from(now_unix_seconds.abs_diff(u64::from(client_time))) * 1_000;
        if self.max_time_diff_ms != 0 && difference_ms > u128::from(self.max_time_diff_ms) {
            return Err(RealityAuthError::TimeSkew);
        }

        Ok(RealityAuthResult {
            client_version,
            client_time,
            user_id,
            auth_key,
        })
    }

    fn short_id_owner(&self, candidate: &[u8; 8]) -> Option<UserId> {
        self.short_ids.owner(candidate)
    }
}

fn derive_auth_key(
    shared_secret: &[u8; 32],
    client_random: &[u8; 32],
) -> Result<AuthKey, RealityAuthError> {
    let hkdf = Hkdf::<Sha256>::new(Some(&client_random[..20]), shared_secret);
    let mut output = [0_u8; 32];
    hkdf.expand(AUTH_KEY_INFO, &mut output)
        .map_err(|_| RealityAuthError::KeyDerivation)?;
    Ok(AuthKey(output))
}

fn open_session_id(
    auth_key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8; 32],
    aad: &[u8],
) -> Result<Zeroizing<[u8; SESSION_PLAINTEXT_LEN]>, RealityAuthError> {
    let mut plaintext = Zeroizing::new([0_u8; SESSION_PLAINTEXT_LEN]);
    plaintext.copy_from_slice(
        ciphertext
            .get(..SESSION_PLAINTEXT_LEN)
            .ok_or(RealityAuthError::OpenFailed)?,
    );
    let tag_bytes: [u8; GCM_TAG_LEN] = ciphertext
        .get(SESSION_PLAINTEXT_LEN..)
        .ok_or(RealityAuthError::OpenFailed)?
        .try_into()
        .map_err(|_| RealityAuthError::OpenFailed)?;
    let cipher = Aes256Gcm::new(&Array(*auth_key));
    let nonce: Nonce<Aes256Gcm> = Array(*nonce);
    let tag: Tag<Aes256Gcm> = Array(tag_bytes);
    cipher
        .decrypt_inout_detached(&nonce, aad, plaintext.as_mut_slice().into(), &tag)
        .map_err(|_| RealityAuthError::OpenFailed)?;
    Ok(plaintext)
}

fn aead_nonce_from_random(client_random: &[u8; 32]) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&client_random[20..]);
    nonce
}

fn seal_session_id(
    auth_key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8; SESSION_PLAINTEXT_LEN],
    aad: &[u8],
) -> Result<[u8; 32], RealityAuthError> {
    let cipher = Aes256Gcm::new(&Array(*auth_key));
    let nonce: Nonce<Aes256Gcm> = Array(*nonce);
    let mut body = *plaintext;
    let tag = cipher
        .encrypt_inout_detached(&nonce, aad, body.as_mut_slice().into())
        .map_err(|_| RealityAuthError::OpenFailed)?;
    let mut output = [0_u8; 32];
    output[..SESSION_PLAINTEXT_LEN].copy_from_slice(&body);
    output[SESSION_PLAINTEXT_LEN..].copy_from_slice(&tag);
    Ok(output)
}

pub(crate) fn decode_short_id(encoded: &str) -> Result<[u8; 8], RealityAuthConfigError> {
    if encoded.is_empty() || encoded.len() > 16 || !encoded.len().is_multiple_of(2) {
        return Err(RealityAuthConfigError::InvalidShortId);
    }
    let mut output = [0_u8; 8];
    for (index, pair) in encoded.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = decode_hex(pair[0]).ok_or(RealityAuthConfigError::InvalidShortId)?;
        let low = decode_hex(pair[1]).ok_or(RealityAuthConfigError::InvalidShortId)?;
        let Some(byte) = output.get_mut(index) else {
            return Err(RealityAuthConfigError::InvalidShortId);
        };
        *byte = (high << 4) | low;
    }
    Ok(output)
}

const fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
