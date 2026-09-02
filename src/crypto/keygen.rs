use std::{error::Error, fmt};

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
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

/// Generates a REALITY short ID of `bytes` bytes, as lowercase hexadecimal.
///
/// The wire format carries at most eight bytes, so a larger request is
/// clamped there rather than producing a value no client could send.
///
/// # Errors
///
/// Returns an error if the operating system cannot provide random bytes.
pub fn generate_short_id(bytes: u8) -> Result<String, KeyGenerationError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let width = usize::from(bytes.clamp(1, 8));
    let random = random_bytes::<8>()?;
    let mut encoded = String::with_capacity(width * 2);
    for byte in random.into_iter().take(width) {
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

/// Draws `LENGTH` bytes from the operating system entropy source.
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

    use super::{generate_node_key, generate_short_id, generate_uuid, generate_x25519_key_pair};

    #[test]
    fn generates_rfc4122_version_four_uuid() {
        let uuid = generate_uuid().expect("OS randomness must be available in tests");

        assert_eq!(uuid.get_version(), Some(Version::Random));
        assert_eq!(uuid.get_variant(), Variant::RFC4122);
    }

    #[test]
    fn generates_short_ids_at_the_requested_width() {
        let short_id = generate_short_id(8).expect("OS randomness must be available in tests");

        assert_eq!(short_id.len(), 16);
        assert!(short_id.bytes().all(|byte| byte.is_ascii_hexdigit()));

        for bytes in 1..=8_u8 {
            let value = generate_short_id(bytes).expect("OS randomness must be available");
            assert_eq!(value.len(), usize::from(bytes) * 2);
        }
        assert_eq!(
            generate_short_id(9)
                .expect("OS randomness must be available")
                .len(),
            16,
            "the wire format carries at most eight bytes, so a wider request clamps"
        );
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
}
