//! Narrow P-256 ECDH boundary for TLS browser key shares (ADR 0062).
use p256::{PublicKey, SecretKey, ecdh::diffie_hellman, elliptic_curve::sec1::ToSec1Point};
use zeroize::Zeroizing;

/// P-256 key generation failed without exposing secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P256Error;
impl core::fmt::Display for P256Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("P-256 key generation failed")
    }
}
impl core::error::Error for P256Error {}

/// One owned, non-clonable TLS P-256 secret, consumed by agreement.
///
/// RustCrypto owns scalar validation and zeroization. This wrapper restricts
/// peer encodings to TLS 1.3's 65-byte uncompressed SEC1 representation.
pub struct EphemeralP256Key(SecretKey);
impl core::fmt::Debug for EphemeralP256Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EphemeralP256Key([REDACTED])")
    }
}
impl EphemeralP256Key {
    /// Generate a scalar by rejection sampling from operating-system entropy.
    ///
    /// Zero and scalars outside the group order are rejected. The bounded
    /// loop fails closed; an entropy failure is never retried or substituted.
    pub fn generate() -> Result<Self, P256Error> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        for _ in 0..128 {
            super::entropy::fill(&mut *bytes).map_err(|_| P256Error)?;
            if let Ok(secret) = SecretKey::from_slice(bytes.as_ref()) {
                return Ok(Self(secret));
            }
        }
        Err(P256Error)
    }

    /// Encode the public share as an uncompressed SEC1 point.
    #[must_use]
    pub fn public_key(&self) -> [u8; 65] {
        let encoded = self.0.public_key().to_sec1_point(false);
        let mut output = [0_u8; 65];
        output.copy_from_slice(encoded.as_bytes());
        output
    }

    /// Consume this secret and agree with one valid TLS P-256 public share.
    ///
    /// Rejects compressed points, infinity, off-curve coordinates and malformed
    /// lengths. P-256 has cofactor one; a validated nonidentity point is in the
    /// required prime-order group. Returned secret storage zeroizes on drop.
    #[must_use]
    pub fn agree(self, peer: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
        if peer.len() != 65 || peer[0] != 4 {
            return None;
        }
        let public = PublicKey::from_sec1_bytes(peer).ok()?;
        let secret = diffie_hellman(self.0.to_nonzero_scalar(), public.as_affine());
        let mut output = Zeroizing::new([0_u8; 32]);
        output.copy_from_slice(secret.raw_secret_bytes());
        Some(output)
    }
}

/// Exercise TLS point decoding and agreement with a fixed nonproduction key.
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub fn fuzz_p256_agreement(peer: &[u8]) {
    let mut bytes = [0_u8; 32];
    bytes[31] = 1;
    if let Ok(secret) = SecretKey::from_slice(&bytes) {
        let _ = EphemeralP256Key(secret).agree(peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn agreements_match_and_secrets_are_not_diagnostic_output() {
        let a = EphemeralP256Key::generate().unwrap();
        let b = EphemeralP256Key::generate().unwrap();
        let ap = a.public_key();
        let bp = b.public_key();
        assert_eq!(format!("{a:?}"), "EphemeralP256Key([REDACTED])");
        assert_eq!(a.agree(&bp).unwrap(), b.agree(&ap).unwrap());
    }
    #[test]
    fn invalid_tls_points_fail_closed() {
        for peer in [
            vec![],
            vec![0],
            vec![4; 64],
            vec![4; 66],
            vec![0; 65],
            vec![4; 65],
        ] {
            assert!(EphemeralP256Key::generate().unwrap().agree(&peer).is_none());
        }
        let key = EphemeralP256Key::generate().unwrap();
        let compressed = key.0.public_key().to_sec1_point(true);
        assert!(key.agree(compressed.as_bytes()).is_none());
    }
}
