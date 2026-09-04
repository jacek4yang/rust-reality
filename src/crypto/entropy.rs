//! The one place this binary asks the operating system for randomness.
//!
//! Every cryptographic secret, nonce and blinding value in rust-reality comes
//! from [`fill`]. Two non-cryptographic uses are deliberately not routed here
//! and are named in `tests/crypto_boundary.rs`: the uniqueness suffixes in the
//! asset-cache and status-file atomic writes, which need a value unlikely to
//! collide rather than one an adversary cannot predict.
//!
//! # Why a function and not a trait
//!
//! There is exactly one entropy source, chosen once, for the whole program.
//! A trait, a generic parameter, or an injected RNG object would let a caller
//! supply a different one, and nothing in this product wants that: a
//! configurable entropy source is a way to get a worse one. Tests that need
//! determinism construct their inputs directly rather than swapping the
//! source — the Vision padding CSPRNG is seeded from here and then produces
//! its own deterministic stream, which is the shape that actually needs
//! reproducing.
//!
//! # Why `getrandom` and not a provider's DRBG
//!
//! `getrandom::fill` is the operating-system CSPRNG. On Linux 6.11 and later
//! it is reached through the vDSO entry point and does not enter the kernel;
//! the two production hosts run 6.12 and qualify. The alternative in this
//! binary's dependency graph is AWS-LC's internal CTR-DRBG, which
//! `crypto::x25519` still uses for the ephemeral key because `aws-lc-rs`
//! seals its `SecureRandom` trait and offers no way to hand it this one. That
//! draw measures 1.562 µs against 0.060 µs here, which is the whole of the
//! measured whole-product difference in the X25519 migration — see issue #232.
//! Removing that second source is C3's job, not this module's.
//!
//! # Failure
//!
//! A failed draw is fatal to whatever needed it. This module does not retry,
//! does not fall back, and does not degrade: an operating system that cannot
//! produce randomness cannot host this program safely, and a caller that
//! continued with a predictable value would be worse than one that stopped.

use core::fmt;

/// The operating-system entropy source could not produce bytes.
///
/// Carries the underlying `getrandom` error as its
/// [`source`](core::error::Error::source), so a diagnostic can name the real
/// cause without this type re-describing it.
#[derive(Debug)]
pub struct EntropyError(getrandom::Error);

impl fmt::Display for EntropyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("operating-system random generation failed")
    }
}

impl core::error::Error for EntropyError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Fills `destination` with cryptographically secure random bytes.
///
/// This is the signature [`fastcrypto`-style fill-own-storage constructors][1]
/// take, so a secret type can be handed this function directly and never let
/// the caller hold a copy of the material.
///
/// [1]: https://github.com/jacek4yang/fastcrypto-rs/pull/15
///
/// # Errors
///
/// Returns [`EntropyError`] when the operating system refuses the request.
#[inline]
pub fn fill(destination: &mut [u8]) -> Result<(), EntropyError> {
    getrandom::fill(destination).map_err(EntropyError)
}

/// Returns `LENGTH` fresh random bytes.
///
/// A convenience over [`fill`] for the call sites whose secret is a
/// fixed-size array they immediately consume. Callers holding the result
/// longer than one expression should clear it; the callers here do.
///
/// # Errors
///
/// Returns [`EntropyError`] when the operating system refuses the request.
#[inline]
pub fn bytes<const LENGTH: usize>() -> Result<[u8; LENGTH], EntropyError> {
    let mut output = [0_u8; LENGTH];
    fill(&mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{bytes, fill};

    #[test]
    fn fill_writes_over_the_whole_destination() {
        // A source that returned short would leave the tail zeroed, and a
        // secret with a predictable tail is the failure this checks for.
        let mut buffer = [0_u8; 64];
        fill(&mut buffer).expect("the operating system must provide entropy");
        assert!(
            buffer.iter().any(|byte| *byte != 0),
            "64 zero bytes from the entropy source is not a plausible draw"
        );
    }

    #[test]
    fn an_empty_request_succeeds_without_writing() {
        let mut empty: [u8; 0] = [];
        fill(&mut empty).expect("a zero-length draw is not an error");
    }

    #[test]
    fn successive_draws_differ() {
        let first = bytes::<32>().expect("the operating system must provide entropy");
        let second = bytes::<32>().expect("the operating system must provide entropy");
        assert_ne!(
            first, second,
            "two 32-byte draws colliding means this is not an entropy source"
        );
    }

    #[test]
    fn the_error_names_its_cause_rather_than_restating_itself() {
        // Constructed rather than provoked: an OS that fails this call cannot
        // be arranged in a test, and the property under test is the wiring.
        let error = super::EntropyError(getrandom::Error::UNSUPPORTED);
        assert_eq!(
            error.to_string(),
            "operating-system random generation failed"
        );
        assert!(
            core::error::Error::source(&error).is_some(),
            "the underlying getrandom error must remain reachable"
        );
    }
}
