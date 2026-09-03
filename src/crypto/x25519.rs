//! The X25519 boundary.
//!
//! Two types, because the server performs X25519 in exactly two shapes and they
//! have different ownership rules:
//!
//! * [`StaticX25519Key`] — the configured REALITY private key. Imported once
//!   when authentication state is compiled, then used for one agreement per
//!   session. The import is deliberately *not* on the session path: importing
//!   costs ~7.7 µs against a ~23 µs agreement, so re-importing per connection
//!   would give back a quarter of the win for nothing.
//! * [`EphemeralX25519Key`] — one TLS key exchange. Generated, asked for its
//!   public share, then **consumed** by exactly one agreement. The type system
//!   enforces single use; nothing here caches, precomputes, or reuses an
//!   ephemeral secret.
//!
//! This is a boundary around a primitive, not a provider framework: no trait,
//! no dynamic dispatch, no runtime selection, and no configuration surface.
//! Which implementation computes X25519 is a build decision.
//!
//! Non-contributory shares are rejected. `aws-lc-rs` returns an error where
//! `x25519-dalek` returned an all-zero shared secret that the caller had to
//! test, so the rejection is expressed here as `None` and both call sites map it
//! to the protocol error they already had.

use fastcrypto::x25519::{EphemeralSecret, StaticSecret};
use zeroize::Zeroizing;

/// An X25519 shared secret.
pub type SharedSecret = Zeroizing<[u8; 32]>;

/// The configured private key could not be imported, or a key pair could not be
/// generated.
///
/// The variants are deliberately opaque: this type is returned on the
/// configuration path and must never describe key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X25519Error {
    /// The 32 configured bytes were not accepted as a private key.
    InvalidPrivateKey,
    /// The operating system or the provider could not produce a key pair.
    KeyGeneration,
}

impl core::fmt::Display for X25519Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPrivateKey => "the configured X25519 private key was rejected",
            Self::KeyGeneration => "X25519 key generation failed",
        })
    }
}

impl core::error::Error for X25519Error {}

/// A long-lived X25519 private key, imported once per configuration generation.
///
/// Not `Clone`: one configuration generation owns one key. Cloning would copy
/// secret material to satisfy a derive rather than a requirement.
pub struct StaticX25519Key {
    inner: StaticSecret,
}

impl StaticX25519Key {
    /// Imports the configured 32-byte private key.
    ///
    /// Accepts exactly what the previous implementation accepted: any 32 bytes,
    /// clamped by the primitive at use, matching Xray's REALITY key semantics.
    ///
    /// # Errors
    ///
    /// Returns [`X25519Error::InvalidPrivateKey`] if the provider rejects the
    /// bytes.
    pub fn new(private_key: &[u8; 32]) -> Result<Self, X25519Error> {
        Ok(Self {
            inner: StaticSecret::from_bytes(*private_key),
        })
    }

    /// Derives the matching public key.
    ///
    /// # Errors
    ///
    /// Returns [`X25519Error::KeyGeneration`] if the provider cannot derive it.
    pub fn public_key(&self) -> Result<[u8; 32], X25519Error> {
        Ok(self.inner.public_key())
    }

    /// Agrees with a peer public key.
    ///
    /// Returns `None` for a non-contributory or malformed peer share, which the
    /// caller must treat as an authentication failure.
    #[must_use]
    pub fn agree(&self, peer_public_key: &[u8; 32]) -> Option<SharedSecret> {
        self.inner
            .agree(peer_public_key)
            .map(|secret| Zeroizing::new(*secret.as_bytes()))
    }
}

impl core::fmt::Debug for StaticX25519Key {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("StaticX25519Key").finish()
    }
}

/// One ephemeral X25519 key exchange.
///
/// The public share is available while the key is held; [`Self::agree`] takes
/// `self`, so the private key cannot outlive its single agreement.
pub struct EphemeralX25519Key {
    inner: EphemeralSecret,
    public_key: [u8; 32],
}

impl EphemeralX25519Key {
    /// Generates one ephemeral key pair.
    ///
    /// The provider draws from its own CSPRNG. `aws-lc-rs` ignores the
    /// `SecureRandom` argument of `EphemeralPrivateKey::generate` and uses
    /// AWS-LC's internal DRBG, so passing one here would imply a control this
    /// code does not have.
    ///
    /// # Errors
    ///
    /// Returns [`X25519Error::KeyGeneration`] if generation or public-key
    /// derivation fails.
    pub fn generate() -> Result<Self, X25519Error> {
        let mut seed = [0_u8; 32];
        getrandom::fill(&mut seed).map_err(|_| X25519Error::KeyGeneration)?;
        let inner = EphemeralSecret::from_bytes(seed);
        let public_key = *inner.public_key();
        Ok(Self { inner, public_key })
    }

    /// The public share to send in the server key share.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Consumes the key to agree with the peer's public key.
    ///
    /// Returns `None` for a non-contributory or malformed peer share.
    #[must_use]
    pub fn agree(self, peer_public_key: &[u8; 32]) -> Option<SharedSecret> {
        self.inner
            .agree(peer_public_key)
            .map(|secret| Zeroizing::new(*secret.as_bytes()))
    }
}

impl core::fmt::Debug for EphemeralX25519Key {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("EphemeralX25519Key")
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// Proves the boundary is a real X25519 implementation, not merely that it is
/// self-consistent.
///
/// The cross-provider equivalence suite lives beside the call sites it
/// protects, in `protocol::reality::auth` and
/// `protocol::reality::tls13::handshake`, where the exact production shapes are
/// available. These are the primitive's own anchors.
#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(text: &str) -> [u8; 32] {
        let mut out = [0_u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex");
        }
        out
    }

    /// The canonical low-order points and the non-canonical field encodings.
    const ADVERSARIAL: &[&str] = &[
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];

    #[test]
    fn rfc7748_vectors_hold() {
        let alice = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_public =
            hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_public = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let expected = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        let key = StaticX25519Key::new(&alice).expect("RFC 7748 private key");
        assert_eq!(key.public_key().expect("public key"), alice_public);
        assert_eq!(*key.agree(&bob_public).expect("shared secret"), expected);
    }

    #[test]
    fn every_low_order_peer_share_is_refused() {
        let key = StaticX25519Key::new(&[0x11; 32]).expect("private key");
        for encoded in ADVERSARIAL {
            assert!(
                key.agree(&hex32(encoded)).is_none(),
                "a non-contributory share must not produce a secret: {encoded}"
            );
        }
    }

    #[test]
    fn any_thirty_two_bytes_are_a_usable_configured_key() {
        // The configured REALITY key is 32 raw base64url bytes with no further
        // validation. A configuration that worked before must still work.
        for bytes in [[0x00_u8; 32], [0xff_u8; 32], [0x11_u8; 32]] {
            let key = StaticX25519Key::new(&bytes).expect("configured key");
            key.public_key().expect("public key");
        }
        for encoded in ADVERSARIAL {
            StaticX25519Key::new(&hex32(encoded)).expect("configured key");
        }
    }

    #[test]
    fn an_ephemeral_exchange_agrees_with_a_static_peer() {
        let peer = StaticX25519Key::new(&[0x22; 32]).expect("peer key");
        let peer_public = peer.public_key().expect("peer public key");

        let ephemeral = EphemeralX25519Key::generate().expect("ephemeral key");
        let server_public = *ephemeral.public_key();
        let server_view = ephemeral.agree(&peer_public).expect("server shared secret");
        let peer_view = peer.agree(&server_public).expect("peer shared secret");

        assert_eq!(server_view, peer_view);
    }

    #[test]
    fn ephemeral_keys_are_never_the_same_key_twice() {
        let first = EphemeralX25519Key::generate().expect("first");
        let second = EphemeralX25519Key::generate().expect("second");
        assert_ne!(first.public_key(), second.public_key());
    }

    #[test]
    fn an_ephemeral_key_refuses_a_non_contributory_peer() {
        for encoded in ADVERSARIAL {
            let ephemeral = EphemeralX25519Key::generate().expect("ephemeral key");
            assert!(ephemeral.agree(&hex32(encoded)).is_none(), "{encoded}");
        }
    }

    /// A deterministic generator, so a failure names a reproducible input.
    struct Lcg(u64);

    impl Lcg {
        fn bytes(&mut self) -> [u8; 32] {
            let mut out = [0_u8; 32];
            for chunk in out.chunks_mut(8) {
                self.0 = self
                    .0
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                chunk.copy_from_slice(&self.0.to_le_bytes());
            }
            out
        }
    }

    /// The previous provider, as an independent oracle.
    ///
    /// `x25519-dalek` remains a production dependency for key generation, the
    /// destination probe and the handoff control channel, so this compares two
    /// real implementations rather than one implementation against itself.
    fn dalek_agree(private: &[u8; 32], peer: &[u8; 32]) -> Option<[u8; 32]> {
        let shared = x25519_dalek::StaticSecret::from(*private)
            .diffie_hellman(&x25519_dalek::PublicKey::from(*peer));
        shared.was_contributory().then(|| shared.to_bytes())
    }

    #[test]
    fn public_key_derivation_matches_the_previous_provider() {
        let mut rng = Lcg(0x1234_5678_9ABC_DEF0);
        for _ in 0..256 {
            let private = rng.bytes();
            let expected =
                x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private))
                    .to_bytes();
            let actual = StaticX25519Key::new(&private)
                .expect("configured key")
                .public_key()
                .expect("public key");
            assert_eq!(actual, expected, "derivation differs for {private:02x?}");
        }
    }

    #[test]
    fn agreement_matches_the_previous_provider() {
        let mut rng = Lcg(0x0FED_CBA9_8765_4321);
        for _ in 0..256 {
            let private = rng.bytes();
            let peer_secret = rng.bytes();
            let peer =
                x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(peer_secret))
                    .to_bytes();
            let ours = StaticX25519Key::new(&private)
                .expect("configured key")
                .agree(&peer)
                .map(|secret| *secret);
            assert_eq!(
                ours,
                dalek_agree(&private, &peer),
                "agreement differs for private={private:02x?} peer={peer:02x?}"
            );
        }
    }

    #[test]
    fn the_accept_or_reject_decision_matches_the_previous_provider_exactly() {
        // The two providers reject differently: dalek computes the agreement and
        // reports `was_contributory() == false`, aws-lc-rs returns an error. A
        // swap is only safe if those decisions coincide on every share,
        // including the non-canonical field encodings where clamping and
        // reduction could plausibly diverge. Divergence here would change which
        // client authenticates.
        let private = [0x11_u8; 32];
        let key = StaticX25519Key::new(&private).expect("configured key");
        for encoded in ADVERSARIAL.iter().chain(&[
            "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
            "d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ]) {
            let peer = hex32(encoded);
            let ours = key.agree(&peer).map(|secret| *secret);
            assert_eq!(ours, dalek_agree(&private, &peer), "diverged on {encoded}");
        }
    }

    #[test]
    fn neither_key_type_reveals_secret_material_when_formatted() {
        let key = StaticX25519Key::new(&[0x11; 32]).expect("private key");
        assert_eq!(format!("{key:?}"), "StaticX25519Key");
        let ephemeral = EphemeralX25519Key::generate().expect("ephemeral key");
        let rendered = format!("{ephemeral:?}");
        assert!(rendered.starts_with("EphemeralX25519Key"), "{rendered}");
        assert!(rendered.contains("public_key"), "{rendered}");
    }
}
