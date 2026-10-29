//! ClientHello construction carrying a REALITY authenticator.
//!
//! Assembles the message twice: first with a zeroed session ID (the server's
//! AEAD AAD form), then patches the sealed 32-byte ciphertext into that slot.

use std::fmt;

use ml_kem::{
    DecapsulationKey768, Seed,
    kem::{Decapsulate, KeyExport},
    ml_kem_768::Ciphertext,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{
    AuthKey, AuthPlaintext, BrowserFingerprint, MAX_CLIENT_HELLO_BYTES, P256_GROUP,
    RealityAuthError, SESSION_ID_LEN, SESSION_ID_OFFSET, X25519_GROUP, X25519_MLKEM768_GROUP,
};
use crate::crypto::{EphemeralP256Key, SharedSecret, StaticX25519Key, entropy};

const X25519_PUBLIC_LEN: usize = 32;
const MLKEM768_CIPHERTEXT_LEN: usize = 1_088;
const MLKEM768_ENCAP_KEY_LEN: usize = 1_184;

const LEGACY_VERSION: [u8; 2] = [3, 3];
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const RECORD_HEADER_LEN: usize = 5;
/// A ClientHello could not be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelloError {
    /// Empty, over-long, NUL-containing, or non-ASCII presentation name.
    InvalidServerName,
    /// Empty or over-long ALPN protocol.
    InvalidAlpn,
    /// Message would exceed the server ClientHello or TLS record bound.
    TooLarge,
    /// Operating-system entropy was unavailable.
    Entropy,
    /// Key agreement produced a non-contributory result.
    NonContributory,
    /// Authenticator derivation or sealing failed.
    Auth(RealityAuthError),
}

impl fmt::Display for HelloError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidServerName => formatter.write_str("invalid REALITY server name"),
            Self::InvalidAlpn => formatter.write_str("invalid ALPN protocol"),
            Self::TooLarge => formatter.write_str("ClientHello exceeds the wire size limit"),
            Self::Entropy => formatter.write_str("entropy unavailable for ClientHello"),
            Self::NonContributory => formatter.write_str("non-contributory REALITY key agreement"),
            Self::Auth(error) => write!(formatter, "REALITY authenticator: {error}"),
        }
    }
}

impl std::error::Error for HelloError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Auth(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RealityAuthError> for HelloError {
    fn from(error: RealityAuthError) -> Self {
        Self::Auth(error)
    }
}

/// TLS shared secret after the peer selects a key-share group.
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum TlsSharedSecret {
    /// Plain X25519 (32 bytes).
    X25519([u8; 32]),
    /// P-256 ECDH (32 bytes).
    P256([u8; 32]),
    /// X25519MLKEM768 (ML-KEM shared || X25519 shared).
    Hybrid([u8; 64]),
}

impl TlsSharedSecret {
    /// Borrowed secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::X25519(bytes) | Self::P256(bytes) => bytes,
            Self::Hybrid(bytes) => bytes,
        }
    }
}

impl fmt::Debug for TlsSharedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TlsSharedSecret([REDACTED])")
    }
}

/// Ephemeral shares one ClientHello offers.
///
/// The standalone X25519 key is dual-use: REALITY authentication against the
/// configured server public key, and the TLS share when the peer selects plain
/// X25519. It is stored as [`StaticX25519Key`] so both agreements can use `&self`
/// without violating the single-consume ephemeral API.
pub struct ClientKeyAgreement {
    profile: BrowserFingerprint,
    p256: Option<EphemeralP256Key>,
    x25519: StaticX25519Key,
    x25519_public: [u8; X25519_PUBLIC_LEN],
    // Hybrid private state is read by `tls_shared_secret` during the TLS handshake.
    hybrid_x25519: StaticX25519Key,
    hybrid_x25519_public: [u8; X25519_PUBLIC_LEN],
    hybrid_mlkem: DecapsulationKey768,
    hybrid_encap: [u8; MLKEM768_ENCAP_KEY_LEN],
}

impl ClientKeyAgreement {
    /// Generates every share from operating-system entropy.
    ///
    /// # Errors
    ///
    /// Returns [`HelloError::Entropy`] when entropy is unavailable.
    pub fn generate() -> Result<Self, HelloError> {
        Self::for_profile(BrowserFingerprint::default())
    }

    /// Generate exactly the private agreements needed by the selected profile.
    pub fn for_profile(profile: BrowserFingerprint) -> Result<Self, HelloError> {
        let x25519_secret =
            Zeroizing::new(entropy::bytes::<32>().map_err(|_| HelloError::Entropy)?);
        let hybrid_secret = Zeroizing::new(match profile {
            BrowserFingerprint::Chrome => {
                entropy::bytes::<32>().map_err(|_| HelloError::Entropy)?
            }
            BrowserFingerprint::Firefox => *x25519_secret,
        });
        let p256 = match profile {
            BrowserFingerprint::Chrome => None,
            BrowserFingerprint::Firefox => {
                Some(EphemeralP256Key::generate().map_err(|_| HelloError::Entropy)?)
            }
        };
        let x25519 = StaticX25519Key::new(&x25519_secret);
        let hybrid_x25519 = StaticX25519Key::new(&hybrid_secret);
        let x25519_public = x25519.public_key();
        let hybrid_x25519_public = hybrid_x25519.public_key();
        let (hybrid_mlkem, hybrid_encap) = generate_mlkem()?;
        Ok(Self {
            profile,
            p256,
            x25519,
            x25519_public,
            hybrid_x25519,
            hybrid_x25519_public,
            hybrid_mlkem,
            hybrid_encap,
        })
    }

    /// Derives the REALITY authenticator key against the configured server.
    pub(crate) fn auth_key(
        &self,
        server_public_key: &[u8; X25519_PUBLIC_LEN],
        client_random: &[u8; 32],
    ) -> Result<AuthKey, HelloError> {
        let shared = self
            .x25519
            .agree(server_public_key)
            .ok_or(HelloError::NonContributory)?;
        Ok(AuthKey::derive(shared_as_array(&shared), client_random)?)
    }

    /// Agrees the TLS 1.3 ECDHE secret for the group the server selected.
    pub(crate) fn tls_shared_secret(
        self,
        group: u16,
        server_share: &[u8],
    ) -> Option<TlsSharedSecret> {
        match group {
            P256_GROUP => Some(TlsSharedSecret::P256(*self.p256?.agree(server_share)?)),
            X25519_GROUP => {
                let peer = <[u8; X25519_PUBLIC_LEN]>::try_from(server_share).ok()?;
                let secret = self.x25519.agree(&peer)?;
                Some(TlsSharedSecret::X25519(*shared_as_array(&secret)))
            }
            X25519_MLKEM768_GROUP => {
                let (ciphertext, peer_bytes) =
                    server_share.split_at_checked(MLKEM768_CIPHERTEXT_LEN)?;
                let peer = <[u8; X25519_PUBLIC_LEN]>::try_from(peer_bytes).ok()?;
                let mlkem = mlkem_decapsulate(&self.hybrid_mlkem, ciphertext)?;
                let x25519 = self.hybrid_x25519.agree(&peer)?;
                let mut bytes = [0_u8; 64];
                bytes[..32].copy_from_slice(mlkem.as_ref());
                bytes[32..].copy_from_slice(shared_as_array(&x25519));
                Some(TlsSharedSecret::Hybrid(bytes))
            }
            _ => None,
        }
    }

    /// The standalone X25519 public share used for REALITY authentication.
    #[must_use]
    pub const fn authentication_public_key(&self) -> &[u8; X25519_PUBLIC_LEN] {
        &self.x25519_public
    }

    fn key_shares(&self, grease: u16) -> Result<Vec<u8>, HelloError> {
        let mut output = Vec::with_capacity(1_332);
        if self.profile == BrowserFingerprint::Chrome {
            push_u16(&mut output, usize::from(grease))?;
            output.extend_from_slice(&[0, 1, 0]);
        }
        push_u16(&mut output, usize::from(X25519_MLKEM768_GROUP))?;
        push_u16(
            &mut output,
            self.hybrid_encap.len() + self.hybrid_x25519_public.len(),
        )?;
        output.extend_from_slice(&self.hybrid_encap);
        output.extend_from_slice(&self.hybrid_x25519_public);
        push_u16(&mut output, usize::from(X25519_GROUP))?;
        push_u16(&mut output, self.x25519_public.len())?;
        output.extend_from_slice(&self.x25519_public);
        if let Some(key) = &self.p256 {
            push_u16(&mut output, usize::from(P256_GROUP))?;
            push_u16(&mut output, 65)?;
            output.extend_from_slice(&key.public_key());
        }
        Ok(output)
    }
}

impl fmt::Debug for ClientKeyAgreement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientKeyAgreement([REDACTED])")
    }
}

/// One constructed ClientHello, ready to write.
pub struct HelloRecord {
    message: Vec<u8>,
    record_length: u16,
    random: [u8; 32],
    session_id: [u8; SESSION_ID_LEN],
    profile: BrowserFingerprint,
}

impl HelloRecord {
    /// Handshake message bytes (no record header).
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// TLS record that carries the handshake message.
    #[must_use]
    pub fn record(&self) -> Vec<u8> {
        let mut record = Vec::with_capacity(RECORD_HEADER_LEN + self.message.len());
        record.push(CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&[3, 1]);
        record.extend_from_slice(&self.record_length.to_be_bytes());
        record.extend_from_slice(&self.message);
        record
    }

    /// ClientHello random.
    #[must_use]
    pub const fn random(&self) -> &[u8; 32] {
        &self.random
    }

    /// Sealed session ID ciphertext.
    #[must_use]
    pub const fn session_id(&self) -> &[u8; SESSION_ID_LEN] {
        &self.session_id
    }

    /// Whether the peer echoed this session ID byte-for-byte.
    #[must_use]
    pub fn matches_session_id(&self, observed: &[u8]) -> bool {
        observed == self.session_id
    }

    /// Whether this hello offered the named cipher suite.
    #[must_use]
    pub fn cipher_offered(&self, suite: u16) -> bool {
        self.profile.ciphers().contains(&suite)
    }

    /// Whether this hello offered the named key-share group.
    #[must_use]
    pub fn key_share_group_offered(&self, group: u16) -> bool {
        matches!(group, X25519_GROUP | X25519_MLKEM768_GROUP)
            || (group == P256_GROUP && self.profile == BrowserFingerprint::Firefox)
    }
}

impl fmt::Debug for HelloRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HelloRecord")
            .field("message_len", &self.message.len())
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

/// Builds a ClientHello carrying a valid REALITY authenticator.
///
/// # Errors
///
/// Returns [`HelloError`] for invalid names, oversized messages, entropy
/// failure, or a non-contributory server key.
pub fn build_client_hello(
    server_name: &str,
    alpn: &[&[u8]],
    keys: &ClientKeyAgreement,
    server_public_key: &[u8; X25519_PUBLIC_LEN],
    auth: AuthPlaintext,
) -> Result<(HelloRecord, AuthKey), HelloError> {
    if server_name.is_empty()
        || server_name.len() > 253
        || !server_name.is_ascii()
        || server_name.as_bytes().contains(&0)
    {
        return Err(HelloError::InvalidServerName);
    }
    for protocol in alpn {
        if protocol.is_empty() || protocol.len() > 253 {
            return Err(HelloError::InvalidAlpn);
        }
    }

    let random = entropy::bytes::<32>().map_err(|_| HelloError::Entropy)?;
    let auth_key = keys.auth_key(server_public_key, &random)?;
    let mut message = assemble(server_name, alpn, keys, &random)?;
    let session_id = auth_key.seal_session_id(&random, &message, auth)?;
    message
        .get_mut(SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN)
        .ok_or(HelloError::TooLarge)?
        .copy_from_slice(&session_id);
    let record_length = u16::try_from(message.len()).map_err(|_| HelloError::TooLarge)?;
    Ok((
        HelloRecord {
            message,
            record_length,
            random,
            session_id,
            profile: keys.profile,
        },
        auth_key,
    ))
}

fn assemble(
    server_name: &str,
    alpn: &[&[u8]],
    keys: &ClientKeyAgreement,
    random: &[u8; 32],
) -> Result<Vec<u8>, HelloError> {
    let chrome = keys.profile == BrowserFingerprint::Chrome;
    let seeds = entropy::bytes::<6>().map_err(|_| HelloError::Entropy)?;
    let grease = seeds.map(|seed| u16::from(seed & 0xf0 | 0x0a) * 0x0101);
    let mut order = if chrome {
        vec![
            0, 23, 65281, 10, 11, 35, 16, 5, 18, 51, 43, 13, 45, 27, 65037, 17613, 51764,
        ]
    } else {
        vec![
            0, 23, 65281, 10, 11, 35, 16, 5, 34, 18, 51, 43, 13, 45, 28, 27, 65037,
        ]
    };
    if chrome {
        for i in (1..order.len()).rev() {
            let j = random_index(i + 1)?;
            order.swap(i, j);
        }
    }
    let mut extensions = Vec::with_capacity(1_900);
    if chrome {
        push_extension(&mut extensions, grease[4], |_| Ok(()))?;
    }
    for kind in order {
        push_extension(&mut extensions, kind, |body| {
            match kind {
                0 => {
                    push_u16(body, 3 + server_name.len())?;
                    body.push(0);
                    push_u16(body, server_name.len())?;
                    body.extend_from_slice(server_name.as_bytes());
                }
                23 | 35 | 18 => {}
                65281 => body.push(0),
                10 => {
                    let mut groups = vec![X25519_MLKEM768_GROUP, X25519_GROUP, P256_GROUP, 24];
                    if chrome {
                        groups.insert(0, grease[1]);
                    } else {
                        groups.push(25);
                    }
                    push_vector(body, &groups)?;
                }
                11 => body.extend_from_slice(&[1, 0]),
                16 => {
                    push_u16(body, alpn.iter().map(|p| 1 + p.len()).sum())?;
                    for p in alpn {
                        body.push(u8::try_from(p.len()).map_err(|_| HelloError::TooLarge)?);
                        body.extend_from_slice(p);
                    }
                }
                5 => body.extend_from_slice(&[1, 0, 0, 0, 0]),
                34 => body.extend_from_slice(&[0, 8, 4, 3, 5, 3, 6, 3, 2, 3]),
                51 => {
                    let entries = keys.key_shares(grease[1])?;
                    push_u16(body, entries.len())?;
                    body.extend_from_slice(&entries);
                }
                43 => {
                    body.push(if chrome { 6 } else { 4 });
                    if chrome {
                        push_u16(body, usize::from(grease[2]))?;
                    }
                    body.extend_from_slice(&[3, 4, 3, 3]);
                }
                13 => {
                    push_u16(
                        body,
                        (keys.profile.signatures().len() + usize::from(chrome)) * 2,
                    )?;
                    if chrome {
                        push_u16(body, usize::from(grease[3]))?;
                    }
                    for scheme in keys.profile.signatures() {
                        push_u16(body, usize::from(*scheme))?;
                    }
                }
                45 => body.extend_from_slice(&[1, 1]),
                28 => body.extend_from_slice(&[64, 1]),
                27 => body.extend_from_slice(if chrome {
                    &[2, 0, 2]
                } else {
                    &[6, 0, 1, 0, 2, 0, 3]
                }),
                17613 => body.extend_from_slice(&[0, 3, 2, b'h', b'2']),
                51764 => body.extend_from_slice(super::browser_profile::CHROME_TRUST_ANCHORS),
                65037 => write_ech(body, chrome, server_name.len())?,
                _ => unreachable!("immutable profile extension"),
            }
            Ok(())
        })?;
    }
    if chrome {
        // BoringSSL forces its two extension GREASE values to differ.
        let last = if grease[5] == grease[4] {
            grease[5] ^ 0x1010
        } else {
            grease[5]
        };
        push_extension(&mut extensions, last, |body| {
            body.push(0);
            Ok(())
        })?;
    }
    let suites = keys.profile.ciphers();
    let suites_len = (suites.len() + usize::from(chrome)) * 2;
    let body_len = 2 + 32 + 1 + SESSION_ID_LEN + 2 + suites_len + 1 + 1 + 2 + extensions.len();
    let message_len = body_len + 4;
    if message_len > MAX_CLIENT_HELLO_BYTES || message_len > usize::from(u16::MAX) {
        return Err(HelloError::TooLarge);
    }
    let mut message = Vec::with_capacity(message_len);
    message.push(HANDSHAKE_CLIENT_HELLO);
    let length = u32::try_from(body_len).map_err(|_| HelloError::TooLarge)?;
    message.extend_from_slice(&length.to_be_bytes()[1..]);
    message.extend_from_slice(&LEGACY_VERSION);
    message.extend_from_slice(random);
    message.push(u8::try_from(SESSION_ID_LEN).map_err(|_| HelloError::TooLarge)?);
    message.resize(message.len() + SESSION_ID_LEN, 0);
    push_u16(&mut message, suites_len)?;
    if chrome {
        push_u16(&mut message, usize::from(grease[0]))?;
    }
    for suite in suites {
        push_u16(&mut message, usize::from(*suite))?;
    }
    message.extend_from_slice(&[1, 0]);
    push_u16(&mut message, extensions.len())?;
    message.extend_from_slice(&extensions);
    Ok(message)
}

fn push_vector(body: &mut Vec<u8>, values: &[u16]) -> Result<(), HelloError> {
    push_u16(body, values.len() * 2)?;
    for value in values {
        push_u16(body, usize::from(*value))?;
    }
    Ok(())
}

fn random_index(bound: usize) -> Result<usize, HelloError> {
    // Rejection sampling avoids modulo bias; all callers have bounds <= 17.
    let cutoff = 256 - 256 % bound;
    for _ in 0..128 {
        let value = usize::from(entropy::bytes::<1>().map_err(|_| HelloError::Entropy)?[0]);
        if value < cutoff {
            return Ok(value % bound);
        }
    }
    Err(HelloError::Entropy)
}

fn write_ech(body: &mut Vec<u8>, chrome: bool, name_len: usize) -> Result<(), HelloError> {
    let seed = entropy::bytes::<2>().map_err(|_| HelloError::Entropy)?;
    // The captured Chrome platform has AES acceleration; Firefox chooses both
    // AEAD identifiers independently of hardware in NSS tls13_MaybeGreaseEch.
    let aead = if chrome || seed[0] & 1 != 0 { 1 } else { 3 };
    body.extend_from_slice(&[0, 0, 1, 0, aead, seed[1], 0, 32]);
    if chrome {
        let secret = Zeroizing::new(entropy::bytes::<32>().map_err(|_| HelloError::Entropy)?);
        body.extend_from_slice(&StaticX25519Key::new(&secret).public_key());
    } else {
        body.extend_from_slice(&entropy::bytes::<32>().map_err(|_| HelloError::Entropy)?);
    }
    // BoringSSL estimates 128..224 bytes in 32-byte steps. NSS compresses ten
    // outer extensions, keeps the SNI, and pads to its configured 100-byte name.
    let payload = if chrome {
        128 + 32 * random_index(4)? + 16
    } else {
        (117 + name_len.max(100)).div_ceil(32) * 32 + 16
    };
    push_u16(body, payload)?;
    let start = body.len();
    body.resize(start + payload, 0);
    entropy::fill(&mut body[start..]).map_err(|_| HelloError::Entropy)
}

fn push_extension(
    output: &mut Vec<u8>,
    extension_type: u16,
    write: impl FnOnce(&mut Vec<u8>) -> Result<(), HelloError>,
) -> Result<(), HelloError> {
    let mut body = Vec::new();
    write(&mut body)?;
    output.extend_from_slice(&extension_type.to_be_bytes());
    push_u16(output, body.len())?;
    output.extend_from_slice(&body);
    Ok(())
}

fn push_u16(output: &mut Vec<u8>, length: usize) -> Result<(), HelloError> {
    output.extend_from_slice(
        &u16::try_from(length)
            .map_err(|_| HelloError::TooLarge)?
            .to_be_bytes(),
    );
    Ok(())
}

fn shared_as_array(secret: &SharedSecret) -> &[u8; 32] {
    secret
}

fn generate_mlkem() -> Result<(DecapsulationKey768, [u8; MLKEM768_ENCAP_KEY_LEN]), HelloError> {
    let mut seed = Seed::default();
    entropy::fill(seed.as_mut()).map_err(|_| HelloError::Entropy)?;
    let decapsulation = DecapsulationKey768::from_seed(seed);
    let encapsulation = decapsulation.encapsulation_key().to_bytes();
    let mut hybrid_encap = [0_u8; MLKEM768_ENCAP_KEY_LEN];
    hybrid_encap.copy_from_slice(encapsulation.as_slice());
    Ok((decapsulation, hybrid_encap))
}

fn mlkem_decapsulate(
    decapsulation: &DecapsulationKey768,
    ciphertext: &[u8],
) -> Option<Zeroizing<[u8; 32]>> {
    use ml_kem::array::Array as MlKemArray;
    let ct: Ciphertext = MlKemArray::try_from(ciphertext).ok()?;
    let shared = decapsulation.decapsulate(&ct);
    let mut out = Zeroizing::new([0_u8; 32]);
    out.copy_from_slice(shared.as_ref());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::load_bytes,
        protocol::reality::{CLIENT_VERSION, ClientHello, RealityAuthenticator},
        protocol::vless::UserId,
    };
    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
    use std::path::Path;
    use x25519_dalek::{PublicKey, StaticSecret};

    const NAME: &str = "www.example.com";
    const ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
    const SHORT_ID_HEX: &str = "0102030405060708";
    const SHORT_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    const USER: &str = "11111111-1111-4111-8111-111111111111";

    fn plaintext(now: u32) -> AuthPlaintext {
        AuthPlaintext {
            version: CLIENT_VERSION,
            time: now,
            short_id: SHORT_ID,
        }
    }

    fn authenticator(private: [u8; 32]) -> (RealityAuthenticator, [u8; 32]) {
        let public = PublicKey::from(&StaticSecret::from(private)).to_bytes();
        let json = format!(
            r#"{{
  "role": "entry",
  "listeners": [{{ "port": 443 }}],
  "reality": {{
    "cover": "{name}:443",
    "privateKey": "{private_key}",
    "serverNames": ["{name}"],
    "maxTimeDiffMs": 60000
  }},
  "users": [{{
    "id": "{user}",
    "shortIds": ["{short_id}"],
    "label": "alice"
  }}],
  "routing": {{ "default": "direct" }}
}}"#,
            name = NAME,
            private_key = BASE64_URL_SAFE_NO_PAD.encode(private),
            user = USER,
            short_id = SHORT_ID_HEX,
        );
        let validated = load_bytes(Path::new("client-offer-entry.json"), json.as_bytes())
            .expect("entry config must load");
        let node = validated.into_node();
        let entry = node.as_entry().expect("role is entry");
        (
            RealityAuthenticator::from_entry(entry).expect("authenticator"),
            public,
        )
    }

    #[test]
    fn invalid_sni_fails_before_serializing_an_unparseable_offer() {
        for profile in [BrowserFingerprint::Chrome, BrowserFingerprint::Firefox] {
            let keys = ClientKeyAgreement::for_profile(profile).unwrap();
            for name in ["", "\0", "www.\0example.com", &"x".repeat(254)] {
                assert!(matches!(
                    build_client_hello(name, ALPN, &keys, &[0x22; 32], plaintext(1)),
                    Err(HelloError::InvalidServerName)
                ));
            }
        }
    }

    #[test]
    fn browser_offers_preserve_key_relationships() {
        for profile in [BrowserFingerprint::Chrome, BrowserFingerprint::Firefox] {
            for _ in 0..8 {
                let keys = ClientKeyAgreement::for_profile(profile).unwrap();
                let (record, _) = build_client_hello(
                    "browser-capture.test",
                    ALPN,
                    &keys,
                    &[0x22; 32],
                    plaintext(1),
                )
                .unwrap();
                let wire = record.record();
                let hello = ClientHello::parse_record(&wire).unwrap();
                assert_eq!(hello.peer_x25519(), Some(*keys.authentication_public_key()));
                assert_eq!(
                    keys.x25519_public == keys.hybrid_x25519_public,
                    profile == BrowserFingerprint::Firefox
                );
            }
        }
    }

    #[test]
    fn built_hello_authenticates_against_the_shared_server_authenticator() {
        let (authenticator, server_public) = authenticator([0x42; 32]);
        let keys = ClientKeyAgreement::generate().expect("keys");
        let now = 1_700_000_000_u32;
        let (record, client_auth_key) =
            build_client_hello(NAME, ALPN, &keys, &server_public, plaintext(now))
                .expect("client hello");

        let hello = ClientHello::parse_message(record.message()).expect("parse");
        assert_eq!(hello.session_ciphertext(), Some(record.session_id()));
        assert_eq!(*hello.random(), *record.random());

        let result = authenticator
            .authenticate(&hello, u64::from(now))
            .expect("server must accept the client authenticator");
        assert_eq!(result.client_version(), CLIENT_VERSION);
        assert_eq!(result.client_time(), now);
        assert_eq!(result.auth_key().as_bytes(), client_auth_key.as_bytes());
        assert_eq!(
            result.user_id(),
            UserId::new(*uuid::Uuid::parse_str(USER).unwrap().as_bytes())
        );
    }

    #[test]
    fn session_id_slot_starts_zeroed_in_aad_form() {
        let keys = ClientKeyAgreement::generate().expect("keys");
        let server_public = [0x11; 32];
        let (record, _) =
            build_client_hello(NAME, ALPN, &keys, &server_public, plaintext(1)).expect("hello");
        let hello = ClientHello::parse_message(record.message()).expect("parse");
        let aad = hello.reality_aad().expect("aad");
        assert!(
            aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN]
                .iter()
                .all(|&b| b == 0)
        );
        assert_ne!(record.session_id(), &[0; SESSION_ID_LEN]);
    }

    #[test]
    fn tls_shared_secret_agrees_for_plain_x25519() {
        let keys = ClientKeyAgreement::generate().expect("keys");
        let peer = ClientKeyAgreement::generate().expect("peer");
        let public = *keys.authentication_public_key();
        let secret = keys
            .tls_shared_secret(X25519_GROUP, peer.authentication_public_key())
            .expect("x25519 agreement");
        let mirrored = peer
            .tls_shared_secret(X25519_GROUP, &public)
            .expect("mirrored");
        assert_eq!(secret.as_bytes(), mirrored.as_bytes());
        assert_eq!(secret.as_bytes().len(), 32);
    }

    #[test]
    fn offers_hybrid_and_x25519_key_shares() {
        let keys = ClientKeyAgreement::generate().expect("keys");
        let (record, _) =
            build_client_hello(NAME, ALPN, &keys, &[0x22; 32], plaintext(1)).expect("hello");
        assert!(record.key_share_group_offered(X25519_MLKEM768_GROUP));
        assert!(record.key_share_group_offered(X25519_GROUP));
        assert!(record.cipher_offered(0x1301));
    }

    #[test]
    fn client_hello_extensions_match_stock_xray_go_parser() {
        let keys = ClientKeyAgreement::generate().expect("keys");
        let (record, _) =
            build_client_hello(NAME, ALPN, &keys, &[0x22; 32], plaintext(1)).expect("hello");
        let message = record.message();
        // Skip handshake header (4) + legacy_ver(2)+random(32)+session_id
        let sid_len = message[4 + 2 + 32] as usize;
        let mut off = 4 + 2 + 32 + 1 + sid_len;
        let cs_len = u16::from_be_bytes([message[off], message[off + 1]]) as usize;
        off += 2 + cs_len;
        let comp_len = message[off] as usize;
        off += 1 + comp_len;
        let ext_len = u16::from_be_bytes([message[off], message[off + 1]]) as usize;
        off += 2;
        let end = off + ext_len;
        let mut saw_status = false;
        let mut saw_psk_modes = false;
        while off + 4 <= end {
            let et = u16::from_be_bytes([message[off], message[off + 1]]);
            let el = u16::from_be_bytes([message[off + 2], message[off + 3]]) as usize;
            off += 4;
            let body = &message[off..off + el];
            off += el;
            match et {
                0x0005 => {
                    saw_status = true;
                    assert_eq!(
                        body,
                        &[1, 0, 0, 0, 0],
                        "status_request must be OCSP empty lists"
                    );
                }
                0x002d => {
                    saw_psk_modes = true;
                    assert_eq!(body, &[1, 1], "psk_key_exchange_modes");
                }
                0x2d00 => panic!("legacy typo extension 0x2d00 must not be present"),
                _ => {}
            }
        }
        assert!(saw_status, "status_request required for Go crypto/tls");
        assert!(saw_psk_modes, "psk_key_exchange_modes 0x002d required");
    }
}
