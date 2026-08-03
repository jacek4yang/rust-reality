use std::{error::Error, fmt};

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use libcrux_ml_dsa::ml_dsa_65;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::config::SecretString;

/// Operating-system random generation failed.
#[derive(Debug)]
pub struct KeyGenerationError(getrandom::Error);

impl fmt::Display for KeyGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("operating-system random generation failed")
    }
}

impl Error for KeyGenerationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

/// One URL-safe, unpadded X25519 key pair compatible with REALITY.
#[derive(Debug)]
pub struct X25519KeyPair {
    private_key: SecretString,
    public_key: String,
}

/// One Xray-compatible ML-DSA-65 seed and verification key.
///
/// The expanded signing key is never retained: it is erased immediately after
/// deriving the public verification key. Xray consumes the 32-byte seed.
#[derive(Debug)]
pub struct MlDsa65KeyPair {
    seed: SecretString,
    verification_key: String,
}

impl MlDsa65KeyPair {
    /// Returns the secret seed through the explicit secret wrapper.
    #[must_use]
    pub const fn seed(&self) -> &SecretString {
        &self.seed
    }

    /// Returns the public verification key.
    #[must_use]
    pub fn verification_key(&self) -> &str {
        &self.verification_key
    }
}

impl X25519KeyPair {
    /// Returns the private key through the explicit secret wrapper.
    #[must_use]
    pub const fn private_key(&self) -> &SecretString {
        &self.private_key
    }

    /// Returns the public key.
    #[must_use]
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// Separates the key pair into its private and public encodings.
    #[must_use]
    pub fn into_parts(self) -> (SecretString, String) {
        (self.private_key, self.public_key)
    }
}

/// Generates one RFC 4122 UUID version 4 from the operating-system CSPRNG.
///
/// # Errors
///
/// Returns an error if the operating system cannot provide random bytes.
pub fn generate_uuid() -> Result<Uuid, KeyGenerationError> {
    let mut bytes = random_bytes::<16>()?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(bytes))
}

/// Generates an eight-byte REALITY short ID as lowercase hexadecimal.
///
/// # Errors
///
/// Returns an error if the operating system cannot provide random bytes.
pub fn generate_short_id() -> Result<String, KeyGenerationError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = random_bytes::<8>()?;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(encoded)
}

/// Generates one X25519 key pair using `x25519-dalek` and OS entropy.
///
/// # Errors
///
/// Returns an error if the operating system cannot provide random bytes.
pub fn generate_x25519_key_pair() -> Result<X25519KeyPair, KeyGenerationError> {
    let secret = StaticSecret::from(random_bytes::<32>()?);
    let public = PublicKey::from(&secret);
    Ok(X25519KeyPair {
        private_key: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(secret.to_bytes())),
        public_key: BASE64_URL_SAFE_NO_PAD.encode(public.as_bytes()),
    })
}

/// Generates one independent 32-byte NXR pre-shared key.
///
/// # Errors
///
/// Returns an error if the operating system cannot provide random bytes.
pub fn generate_node_key() -> Result<SecretString, KeyGenerationError> {
    let mut bytes = random_bytes::<32>()?;
    let encoded = BASE64_URL_SAFE_NO_PAD.encode(bytes);
    bytes.zeroize();
    Ok(SecretString::new(encoded))
}

/// Generates one Xray-compatible ML-DSA-65 seed and verification key.
///
/// # Errors
///
/// Returns an error if the operating system cannot provide random bytes.
pub fn generate_mldsa65_key_pair() -> Result<MlDsa65KeyPair, KeyGenerationError> {
    Ok(generate_mldsa65_key_pair_from_seed(random_bytes::<32>()?))
}

/// Deterministically derives an ML-DSA-65 verification key from a 32-byte seed.
///
/// This entry point exists for RFC/FIPS vectors and differential testing with
/// Xray. The expanded signing key is zeroized before this function returns.
#[must_use]
pub fn generate_mldsa65_key_pair_from_seed(mut seed: [u8; 32]) -> MlDsa65KeyPair {
    let encoded_seed = BASE64_URL_SAFE_NO_PAD.encode(seed);
    let mut expanded = ml_dsa_65::generate_key_pair(seed);
    seed.zeroize();
    let verification_key = BASE64_URL_SAFE_NO_PAD.encode(expanded.verification_key.as_slice());
    expanded.signing_key.as_mut_slice().zeroize();

    MlDsa65KeyPair {
        seed: SecretString::new(encoded_seed),
        verification_key,
    }
}

fn random_bytes<const LENGTH: usize>() -> Result<[u8; LENGTH], KeyGenerationError> {
    let mut bytes = [0_u8; LENGTH];
    getrandom::fill(&mut bytes).map_err(KeyGenerationError)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
    use uuid::{Variant, Version};
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::{
        generate_mldsa65_key_pair_from_seed, generate_node_key, generate_short_id, generate_uuid,
        generate_x25519_key_pair,
    };

    #[test]
    fn generates_rfc4122_version_four_uuid() {
        let uuid = generate_uuid().expect("OS randomness must be available in tests");

        assert_eq!(uuid.get_version(), Some(Version::Random));
        assert_eq!(uuid.get_variant(), Variant::RFC4122);
    }

    #[test]
    fn generates_eight_byte_short_id() {
        let short_id = generate_short_id().expect("OS randomness must be available in tests");

        assert_eq!(short_id.len(), 16);
        assert!(short_id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn x25519_public_key_matches_private_key() {
        let pair = generate_x25519_key_pair().expect("OS randomness must be available in tests");
        let private_bytes: [u8; 32] = BASE64_URL_SAFE_NO_PAD
            .decode(pair.private_key().expose())
            .expect("private key must be base64")
            .try_into()
            .expect("private key must contain 32 bytes");
        let public = PublicKey::from(&StaticSecret::from(private_bytes));

        assert_eq!(
            BASE64_URL_SAFE_NO_PAD.encode(public.as_bytes()),
            pair.public_key()
        );
        assert!(!format!("{pair:?}").contains(pair.private_key().expose()));
    }

    #[test]
    fn node_key_contains_32_random_bytes() {
        let key = generate_node_key().expect("OS randomness must be available in tests");
        let decoded = BASE64_URL_SAFE_NO_PAD
            .decode(key.expose())
            .expect("node key must be base64");

        assert_eq!(decoded.len(), 32);
        assert!(!format!("{key:?}").contains(key.expose()));
    }

    #[test]
    fn mldsa65_derivation_is_deterministic_and_redacted() {
        let first = generate_mldsa65_key_pair_from_seed([0x42; 32]);
        let second = generate_mldsa65_key_pair_from_seed([0x42; 32]);

        assert_eq!(first.seed().expose().len(), 43);
        assert_eq!(first.verification_key().len(), 2_603);
        assert_eq!(first.verification_key(), second.verification_key());
        assert!(!format!("{first:?}").contains(first.seed().expose()));
    }
}
