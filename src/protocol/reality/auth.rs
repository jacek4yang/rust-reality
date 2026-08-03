use std::{error::Error, fmt};

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{AeadInOut, Nonce, Tag, array::Array},
};
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::ClientHello;
use crate::config::RealityConfig;

const AUTH_KEY_INFO: &[u8] = b"REALITY";
const SESSION_PLAINTEXT_LEN: usize = 16;
const GCM_TAG_LEN: usize = 16;

/// A decoded REALITY setting cannot be compiled into authentication state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealityAuthConfigError {
    /// The URL-safe private key is not exactly 32 bytes.
    InvalidPrivateKey,
    /// A configured short ID is not valid even-length hexadecimal up to eight bytes.
    InvalidShortId,
    /// No server name was configured.
    MissingServerName,
    /// No short ID was configured.
    MissingShortId,
}

impl fmt::Display for RealityAuthConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrivateKey => formatter.write_str("invalid REALITY private key"),
            Self::InvalidShortId => formatter.write_str("invalid REALITY short ID"),
            Self::MissingServerName => formatter.write_str("REALITY server name set is empty"),
            Self::MissingShortId => formatter.write_str("REALITY short ID set is empty"),
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
    /// No configured short ID matched in constant time.
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

/// Derived REALITY authentication key, zeroized on drop and redacted in debug output.
#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct AuthKey([u8; 32]);

impl AuthKey {
    /// Exposes the key only to protocol code that explicitly needs certificate binding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
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
    short_id: [u8; 8],
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

    /// Returns the padded eight-byte short ID for replay partitioning.
    #[must_use]
    pub const fn short_id(&self) -> [u8; 8] {
        self.short_id
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
            .field("short_id", &"[REDACTED]")
            .field("auth_key", &self.auth_key)
            .finish()
    }
}

/// Immutable, decoded authentication state for one REALITY listener snapshot.
#[derive(Clone)]
pub struct RealityAuthenticator {
    private_key: StaticSecret,
    server_names: Vec<String>,
    short_ids: Vec<[u8; 8]>,
    max_time_diff_ms: u64,
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
    /// Decodes and compiles validated configuration into immutable authentication state.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed key material, short IDs, or empty identity sets.
    pub fn from_config(config: &RealityConfig) -> Result<Self, RealityAuthConfigError> {
        if config.server_names.is_empty() {
            return Err(RealityAuthConfigError::MissingServerName);
        }
        if config.short_ids.is_empty() {
            return Err(RealityAuthConfigError::MissingShortId);
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
        let short_ids = config
            .short_ids
            .iter()
            .map(|short_id| decode_short_id(short_id))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            private_key: StaticSecret::from(private_bytes),
            server_names: config.server_names.clone(),
            short_ids,
            max_time_diff_ms: config.max_time_diff_ms,
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
            .any(|configured| configured.eq_ignore_ascii_case(server_name))
        {
            return Err(RealityAuthError::ServerName);
        }

        let peer = hello
            .peer_x25519()
            .ok_or(RealityAuthError::MissingKeyShare)?;
        let shared = self.private_key.diffie_hellman(&PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(RealityAuthError::NonContributoryKey);
        }
        let auth_key = derive_auth_key(shared.as_bytes(), hello.random())?;
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

        if !constant_time_short_id_match(&self.short_ids, &short_id) {
            short_id.zeroize();
            return Err(RealityAuthError::ShortId);
        }
        let difference_ms = u128::from(now_unix_seconds.abs_diff(u64::from(client_time))) * 1_000;
        if self.max_time_diff_ms != 0 && difference_ms > u128::from(self.max_time_diff_ms) {
            short_id.zeroize();
            return Err(RealityAuthError::TimeSkew);
        }

        Ok(RealityAuthResult {
            client_version,
            client_time,
            short_id,
            auth_key,
        })
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

fn decode_short_id(encoded: &str) -> Result<[u8; 8], RealityAuthConfigError> {
    if encoded.is_empty() || encoded.len() > 16 || !encoded.len().is_multiple_of(2) {
        return Err(RealityAuthConfigError::InvalidShortId);
    }
    let mut output = [0_u8; 8];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
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

fn constant_time_short_id_match(configured: &[[u8; 8]], candidate: &[u8; 8]) -> bool {
    let mut matched = Choice::from(0);
    for short_id in configured {
        matched |= short_id.ct_eq(candidate);
    }
    bool::from(matched)
}

#[cfg(test)]
mod tests {
    use aes_gcm::{
        Aes256Gcm, KeyInit,
        aead::{AeadInOut, Nonce, array::Array},
    };
    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::{RealityAuthError, RealityAuthenticator, derive_auth_key, open_session_id};
    use crate::{
        config::{RealityConfig, SecretString},
        protocol::reality::{
            ClientHello, X25519_GROUP, client_hello::fixtures::client_hello_with_key_share,
        },
    };

    const NOW: u32 = 1_700_000_000;
    const SHORT_ID: [u8; 8] = [0xaa, 0xbb, 0, 0, 0, 0, 0, 0];

    #[test]
    fn authenticates_xray_session_id_layout() {
        let (authenticator, hello) = valid_handshake(SHORT_ID, NOW, &["aabb"]);
        let result = authenticator
            .authenticate(&hello, u64::from(NOW))
            .expect("valid REALITY authentication must succeed");

        assert_eq!(result.client_version(), [1, 2, 3]);
        assert_eq!(result.client_time(), NOW);
        assert_eq!(result.short_id(), SHORT_ID);
        assert_eq!(
            result.auth_key().as_bytes(),
            &hex_array::<32>("913b3e7485c67fb677b4cc65906953c2f6a23eb7b6e24cf3d69091004ccd5a9d"),
            "must match Xray's Go X25519 and HKDF implementation"
        );
        assert!(!format!("{result:?}").contains("170, 187"));
    }

    #[test]
    fn rejects_wrong_server_identity_and_private_key() {
        let (_, hello) = valid_handshake(SHORT_ID, NOW, &["aabb"]);
        let mut wrong_name = auth_config([0x11; 32], &["aabb"]);
        wrong_name.server_names = vec!["other.example.com".to_owned()];
        let wrong_name =
            RealityAuthenticator::from_config(&wrong_name).expect("configuration must compile");
        assert!(matches!(
            wrong_name.authenticate(&hello, u64::from(NOW)),
            Err(RealityAuthError::ServerName)
        ));

        let wrong_key = RealityAuthenticator::from_config(&auth_config([0x55; 32], &["aabb"]))
            .expect("configuration must compile");
        assert!(matches!(
            wrong_key.authenticate(&hello, u64::from(NOW)),
            Err(RealityAuthError::OpenFailed)
        ));
    }

    #[test]
    fn rejects_ciphertext_and_aad_tampering() {
        let (authenticator, hello) = valid_handshake(SHORT_ID, NOW, &["aabb"]);
        let mut tampered_ciphertext = hello.raw_message().to_vec();
        tampered_ciphertext[crate::protocol::reality::SESSION_ID_OFFSET] ^= 1;
        let tampered_ciphertext = ClientHello::parse_message(&tampered_ciphertext)
            .expect("tampered ciphertext remains structurally valid");
        assert!(matches!(
            authenticator.authenticate(&tampered_ciphertext, u64::from(NOW)),
            Err(RealityAuthError::OpenFailed)
        ));

        let mut tampered_aad = hello.raw_message().to_vec();
        // The first cipher-suite byte is outside the zeroed session ID and does
        // not alter any pre-AEAD authentication decision.
        tampered_aad[73] ^= 1;
        let tampered_aad = ClientHello::parse_message(&tampered_aad)
            .expect("tampered AAD remains structurally valid");
        assert!(matches!(
            authenticator.authenticate(&tampered_aad, u64::from(NOW)),
            Err(RealityAuthError::OpenFailed)
        ));
    }

    #[test]
    fn rejects_unknown_short_id_and_time_skew() {
        let (wrong_short_id, hello) = valid_handshake(SHORT_ID, NOW, &["0102"]);
        assert!(matches!(
            wrong_short_id.authenticate(&hello, u64::from(NOW)),
            Err(RealityAuthError::ShortId)
        ));

        let (authenticator, hello) = valid_handshake(SHORT_ID, NOW, &["aabb"]);
        assert!(matches!(
            authenticator.authenticate(&hello, u64::from(NOW) + 61),
            Err(RealityAuthError::TimeSkew)
        ));
    }

    #[test]
    fn rejects_non_contributory_x25519_share() {
        let config = auth_config([0x11; 32], &["aabb"]);
        let authenticator =
            RealityAuthenticator::from_config(&config).expect("configuration must compile");
        let hello = ClientHello::parse_message(&client_hello_with_key_share(
            [0x33; 32],
            &[0; 32],
            "www.example.com",
            &[],
            X25519_GROUP,
            &[0; 32],
        ))
        .expect("ClientHello must parse");

        assert!(matches!(
            authenticator.authenticate(&hello, u64::from(NOW)),
            Err(RealityAuthError::NonContributoryKey)
        ));
    }

    #[test]
    fn nist_aes256_gcm_vector_decrypts() {
        let key = [0_u8; 32];
        let nonce = [0_u8; 12];
        let ciphertext =
            hex_array::<32>("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");

        assert_eq!(
            *open_session_id(&key, &nonce, &ciphertext, &[])
                .expect("NIST AES-256-GCM vector must authenticate"),
            [0_u8; 16]
        );
    }

    #[test]
    fn rfc5869_sha256_case_one_matches() {
        let ikm = [0x0b_u8; 22];
        let salt = hex_vec("000102030405060708090a0b0c");
        let info = hex_vec("f0f1f2f3f4f5f6f7f8f9");
        let expected = hex_vec(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut output = [0_u8; 42];

        hkdf.expand(&info, &mut output)
            .expect("RFC output length is valid");
        assert_eq!(output.as_slice(), expected);
    }

    #[test]
    fn rfc7748_alice_bob_shared_secret_matches() {
        let alice_private = StaticSecret::from(hex_array::<32>(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let bob_public = PublicKey::from(hex_array::<32>(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        ));
        let expected =
            hex_array::<32>("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        assert_eq!(
            alice_private.diffie_hellman(&bob_public).to_bytes(),
            expected
        );
    }

    fn valid_handshake(
        short_id: [u8; 8],
        client_time: u32,
        configured_short_ids: &[&str],
    ) -> (RealityAuthenticator, ClientHello) {
        let server_secret = StaticSecret::from([0x11; 32]);
        let client_secret = StaticSecret::from([0x22; 32]);
        let client_public = PublicKey::from(&client_secret).to_bytes();
        let shared = client_secret.diffie_hellman(&PublicKey::from(&server_secret));
        let random = [0x33; 32];
        let auth_key = derive_auth_key(shared.as_bytes(), &random)
            .expect("fixed valid HKDF length must succeed");
        let zero_message = client_hello_with_key_share(
            random,
            &[0; 32],
            "www.example.com",
            &[],
            X25519_GROUP,
            &client_public,
        );
        let mut plaintext = [0_u8; 16];
        plaintext[..3].copy_from_slice(&[1, 2, 3]);
        plaintext[4..8].copy_from_slice(&client_time.to_be_bytes());
        plaintext[8..].copy_from_slice(&short_id);
        let ciphertext =
            seal_session_id(auth_key.as_bytes(), &[0x33; 12], &plaintext, &zero_message);
        let message = client_hello_with_key_share(
            random,
            &ciphertext,
            "www.example.com",
            &[],
            X25519_GROUP,
            &client_public,
        );
        let hello = ClientHello::parse_message(&message).expect("ClientHello must parse");
        let config = auth_config([0x11; 32], configured_short_ids);
        let authenticator =
            RealityAuthenticator::from_config(&config).expect("configuration must compile");
        (authenticator, hello)
    }

    fn auth_config(private_key: [u8; 32], short_ids: &[&str]) -> RealityConfig {
        RealityConfig {
            target: "www.example.com:443".to_owned(),
            server_names: vec!["www.example.com".to_owned()],
            private_key: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(private_key)),
            short_ids: short_ids.iter().map(|value| (*value).to_owned()).collect(),
            max_time_diff_ms: 60_000,
        }
    }

    fn seal_session_id(
        auth_key: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8; 16],
        aad: &[u8],
    ) -> [u8; 32] {
        let cipher = Aes256Gcm::new(&Array(*auth_key));
        let nonce: Nonce<Aes256Gcm> = Array(*nonce);
        let mut ciphertext = *plaintext;
        let tag = cipher
            .encrypt_inout_detached(&nonce, aad, ciphertext.as_mut_slice().into())
            .expect("test encryption must succeed");
        let mut output = [0_u8; 32];
        output[..16].copy_from_slice(&ciphertext);
        output[16..].copy_from_slice(&tag);
        output
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
