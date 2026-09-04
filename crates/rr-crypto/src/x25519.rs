//! X25519 key agreement.
//!
//! Two secret types, because rust-reality performs X25519 in exactly two
//! shapes and they have different ownership rules:
//!
//! * [`StaticSecret`] — the configured REALITY private key. Imported once when
//!   authentication state is compiled, then used for one agreement per session.
//! * [`EphemeralSecret`] — one TLS key exchange. Its public share is read while
//!   it is held, and [`EphemeralSecret::agree`] takes `self`, so the type
//!   system enforces single use.
//!
//! This is a boundary around a primitive, not a provider framework: no trait,
//! no dynamic dispatch, no runtime selection, no configuration surface.
//!
//! # Entropy
//!
//! Nothing here draws from the operating system: the platform layer owns
//! entropy, so this module stays `no_std`, deterministic under test, and
//! directly fuzzable. There are two ways to hand it over, and the difference
//! is secret handling rather than convenience.
//!
//! [`EphemeralSecret::from_entropy`] passes the key's own storage to a filler
//! the caller supplies, so the scalar is written where it will live and the
//! caller never holds a second copy of it. That is the one to use in
//! production; `getrandom::fill` has the required signature already.
//!
//! [`EphemeralSecret::from_bytes`] takes the 32 bytes by value and is for
//! tests, fuzzing and known-answer vectors, where the input has to be chosen
//! rather than drawn. Its bytes are `Copy`, so a caller that passes a secret
//! through it keeps a copy that this module cannot clear.
//!
//! # Non-contributory shares
//!
//! A peer share of small order agrees to the all-zero secret. Both agreement
//! methods detect that in constant time and return `None`; a caller must treat
//! it as an authentication failure. Following RFC 7748 section 6.1, the check
//! is on the *output*, so it also covers the non-canonical encodings of those
//! points.
//!
//! # Availability
//!
//! x86_64 and AArch64 Linux, which is rust-reality's entire release matrix.
//! The architecture crates supply s2n-bignum's assembly; there is deliberately
//! **no portable fallback**, because a portable X25519 measured 1.85x the
//! incumbent and would be a regression pretending to be a fallback. On any
//! other target this module is absent, which is a compile error at the call
//! site rather than a silent slowdown.

use core::fmt;

use zeroize::Zeroize;

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
pub(crate) mod aarch64;
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub(crate) mod x86_64;

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
use self::aarch64 as backend;
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
use self::x86_64 as backend;

/// Length of a private key, a public key and a shared secret, in bytes.
pub const KEY_LEN: usize = 32;

/// An X25519 shared secret.
///
/// Zeroized on drop. Does not implement `Clone` or `Debug` of its contents:
/// the bytes leave only through [`SharedSecret::as_bytes`].
pub struct SharedSecret([u8; KEY_LEN]);

impl SharedSecret {
    /// The agreed bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedSecret")
            .finish_non_exhaustive()
    }
}

impl Zeroize for SharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A long-lived X25519 private key.
///
/// Not `Clone`: one configuration generation owns one key, and cloning would
/// copy secret material to satisfy a derive rather than a requirement.
pub struct StaticSecret([u8; KEY_LEN]);

impl StaticSecret {
    /// Adopts 32 configured bytes as a private key.
    ///
    /// Every 32-byte string is a valid X25519 private key; the implementation
    /// clamps at use, which is what RFC 7748 specifies and what Xray's REALITY
    /// key semantics expect. There is no error case.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Derives the matching public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; KEY_LEN] {
        let mut public = [0_u8; KEY_LEN];
        backend::x25519_base(&mut public, &self.0);
        public
    }

    /// Agrees with a peer public key.
    ///
    /// Returns `None` for a non-contributory share.
    #[must_use]
    pub fn agree(&self, peer_public_key: &[u8; KEY_LEN]) -> Option<SharedSecret> {
        agree(&self.0, peer_public_key)
    }
}

impl fmt::Debug for StaticSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticSecret")
            .finish_non_exhaustive()
    }
}

impl Zeroize for StaticSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for StaticSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// One ephemeral X25519 key exchange.
///
/// The public share is available while the key is held; [`Self::agree`] takes
/// `self`, so the private key cannot outlive its single agreement.
pub struct EphemeralSecret {
    secret: [u8; KEY_LEN],
    public_key: [u8; KEY_LEN],
}

impl EphemeralSecret {
    /// Builds one ephemeral key pair, filling the key's own storage.
    ///
    /// `fill` is handed the scalar's final location, so the secret is never
    /// written anywhere else and the caller is not left holding a copy to
    /// clear. In rust-reality that argument is `getrandom::fill`, whose
    /// signature this is shaped for.
    ///
    /// What this does *not* claim: Rust makes no promise that a returned value
    /// is not moved, so this removes the caller's copy rather than proving the
    /// bytes occupy exactly one address for their whole life. If `fill` fails,
    /// the partially written key is dropped, and dropping zeroizes it.
    ///
    /// # Errors
    ///
    /// Returns whatever `fill` returned, unchanged.
    pub fn from_entropy<E>(
        fill: impl FnOnce(&mut [u8; KEY_LEN]) -> Result<(), E>,
    ) -> Result<Self, E> {
        let mut secret = Self {
            secret: [0_u8; KEY_LEN],
            public_key: [0_u8; KEY_LEN],
        };
        fill(&mut secret.secret)?;
        backend::x25519_base(&mut secret.public_key, &secret.secret);
        Ok(secret)
    }

    /// Builds one ephemeral key pair from 32 bytes the caller already has.
    ///
    /// For tests, fuzzing and known-answer vectors. `[u8; 32]` is `Copy`, so a
    /// production caller reaching for this keeps a copy of the scalar that this
    /// type cannot clear; use [`Self::from_entropy`] there instead.
    ///
    /// The caller is responsible for those bytes coming from a cryptographic
    /// random source and for never reusing them.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        let mut public_key = [0_u8; KEY_LEN];
        backend::x25519_base(&mut public_key, &bytes);
        Self {
            secret: bytes,
            public_key,
        }
    }

    /// The public share to send in the server key share.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; KEY_LEN] {
        &self.public_key
    }

    /// Consumes the key to agree with the peer's public key.
    ///
    /// Returns `None` for a non-contributory share.
    #[must_use]
    pub fn agree(self, peer_public_key: &[u8; KEY_LEN]) -> Option<SharedSecret> {
        agree(&self.secret, peer_public_key)
    }
}

impl fmt::Debug for EphemeralSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EphemeralSecret")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl Zeroize for EphemeralSecret {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl Drop for EphemeralSecret {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// The one agreement path, shared by both secret types.
fn agree(secret: &[u8; KEY_LEN], peer_public_key: &[u8; KEY_LEN]) -> Option<SharedSecret> {
    let mut agreed = SharedSecret([0_u8; KEY_LEN]);
    backend::x25519(&mut agreed.0, secret, peer_public_key);
    if is_zero(&agreed.0) {
        None
    } else {
        Some(agreed)
    }
}

/// Constant-time all-zero test.
///
/// Accumulates every byte rather than returning at the first non-zero one, so
/// the number of executed instructions does not depend on the secret.
fn is_zero(bytes: &[u8; KEY_LEN]) -> bool {
    let mut accumulator = 0_u8;
    for byte in bytes {
        accumulator |= *byte;
    }
    accumulator == 0
}

/// Name of the assembly variant this machine dispatches to.
///
/// Reporting only — benchmark output, evidence records and bug reports. Both
/// variants on both architectures compute the same function, and a caller must
/// never branch on this for correctness. It exists because a portability claim
/// ("the baseline routines run on a pre-Haswell CPU") is worth stating as an
/// observation rather than an assumption.
#[must_use]
pub fn backend_name() -> &'static str {
    backend::variant().name()
}

#[cfg(test)]
mod tests {
    use super::{EphemeralSecret, KEY_LEN, SharedSecret, StaticSecret, is_zero};

    use alloc::format;

    fn hex32(text: &str) -> [u8; 32] {
        let mut out = [0_u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex digit");
        }
        out
    }

    #[test]
    fn rfc7748_key_exchange_holds_for_both_secret_types() {
        let alice = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_public =
            hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob = hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_public = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let expected = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        let static_key = StaticSecret::from_bytes(alice);
        assert_eq!(static_key.public_key(), alice_public);
        assert_eq!(
            static_key.agree(&bob_public).expect("secret").as_bytes(),
            &expected
        );

        let ephemeral = EphemeralSecret::from_bytes(bob);
        assert_eq!(ephemeral.public_key(), &bob_public);
        assert_eq!(
            ephemeral.agree(&alice_public).expect("secret").as_bytes(),
            &expected
        );
    }

    #[test]
    fn every_non_contributory_share_is_refused() {
        const SHARES: &[&str] = &[
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ];
        let key = StaticSecret::from_bytes([0x11; 32]);
        for share in SHARES {
            assert!(
                key.agree(&hex32(share)).is_none(),
                "a non-contributory share must not produce a secret: {share}"
            );
            let ephemeral = EphemeralSecret::from_bytes([0x11; 32]);
            assert!(ephemeral.agree(&hex32(share)).is_none());
        }
    }

    #[test]
    fn from_entropy_and_from_bytes_build_the_same_key() {
        let scalar = [0x5c_u8; KEY_LEN];
        let filled = EphemeralSecret::from_entropy(|buffer| {
            buffer.copy_from_slice(&scalar);
            Ok::<(), ()>(())
        })
        .expect("a filler that succeeds must produce a key");
        let literal = EphemeralSecret::from_bytes(scalar);
        assert_eq!(filled.public_key(), literal.public_key());

        let peer = EphemeralSecret::from_bytes([0x27_u8; KEY_LEN]);
        let peer_public = *peer.public_key();
        assert_eq!(
            filled.agree(&peer_public).map(|s| *s.as_bytes()),
            literal.agree(&peer_public).map(|s| *s.as_bytes()),
        );
    }

    #[test]
    fn from_entropy_returns_the_fillers_error_unchanged() {
        #[derive(Debug, PartialEq, Eq)]
        struct NoEntropy;
        let outcome = EphemeralSecret::from_entropy(|_| Err(NoEntropy));
        assert_eq!(outcome.err(), Some(NoEntropy));
    }

    /// The filler must be handed the key's own storage, not a scratch buffer
    /// that is copied afterwards — that is the whole reason this constructor
    /// exists.
    #[test]
    fn from_entropy_fills_the_storage_the_public_key_is_derived_from() {
        let mut observed = [0_u8; KEY_LEN];
        let key = EphemeralSecret::from_entropy(|buffer| {
            buffer.copy_from_slice(&[0x3a_u8; KEY_LEN]);
            observed.copy_from_slice(buffer);
            Ok::<(), ()>(())
        })
        .expect("a filler that succeeds must produce a key");
        let expected = EphemeralSecret::from_bytes(observed);
        assert_eq!(key.public_key(), expected.public_key());
    }

    #[test]
    fn is_zero_accepts_only_the_zero_secret() {
        assert!(is_zero(&[0_u8; 32]));
        for index in 0..32 {
            let mut bytes = [0_u8; 32];
            bytes[index] = 1;
            assert!(!is_zero(&bytes), "byte {index} must be observed");
        }
    }

    #[test]
    fn no_secret_type_reveals_material_when_formatted() {
        let secret = [0xab_u8; 32];
        let secret_rendering = format!("{secret:?}");
        let rendered = format!(
            "{:?} {:?} {:?}",
            StaticSecret::from_bytes(secret),
            EphemeralSecret::from_bytes(secret),
            SharedSecret(secret),
        );
        assert!(!rendered.contains(&secret_rendering), "{rendered}");
        // The ephemeral type deliberately shows its public share, so only the
        // other two are required to render no bytes at all.
        let opaque = format!(
            "{:?} {:?}",
            StaticSecret::from_bytes(secret),
            SharedSecret(secret)
        );
        assert!(!opaque.contains(|c: char| c.is_ascii_digit()), "{opaque}");
    }
}
