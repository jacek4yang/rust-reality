//! `rr-crypto`'s X25519 against the two implementations already in this graph.
//!
//! `crates/rr-crypto` carries RFC 7748's published vectors, proves its two
//! compiled variants agree with each other, and proves the committed assembly
//! is upstream's mechanical expansion. None of that answers the question a
//! migration actually turns on: **does it compute what the code being replaced
//! computes, on inputs nobody chose in advance?**
//!
//! So this compares it against `aws-lc-rs`, the provider `src/crypto/x25519.rs`
//! uses today, and against `x25519-dalek`, the independent second opinion the
//! `no_std` core already depends on. Agreement with one could be a shared
//! mistake; agreement with two implementations that share no code is the
//! evidence worth having.
//!
//! The inputs are deterministic — a counter-seeded SHA-256 chain — so a failure
//! reproduces exactly rather than being a story about a random seed.

use aws_lc_rs::agreement::{PrivateKey, UnparsedPublicKey, X25519, agree};
use sha2::{Digest, Sha256};

/// Deterministic pseudo-random 32-byte values.
///
/// Not a CSPRNG and not trying to be: this needs a reproducible stream that
/// covers the input space, and a hash chain is the shortest honest way to get
/// one without adding a dependency.
struct Stream([u8; 32]);

impl Stream {
    fn new(label: &str) -> Self {
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&Sha256::digest(label.as_bytes()));
        Self(seed)
    }

    fn next(&mut self) -> [u8; 32] {
        let next = Sha256::digest(self.0);
        self.0.copy_from_slice(&next);
        self.0
    }
}

/// `aws-lc-rs`'s agreement, as `src/crypto/x25519.rs` performs it today.
///
/// Returns `None` exactly when the provider refuses, which for a
/// non-contributory share is what it does.
fn aws_lc_agree(private: &[u8; 32], peer: &[u8; 32]) -> Option<[u8; 32]> {
    let key = PrivateKey::from_private_key(&X25519, private).ok()?;
    agree(
        &key,
        UnparsedPublicKey::new(&X25519, &peer[..]),
        (),
        |shared| <[u8; 32]>::try_from(shared).map_err(drop),
    )
    .ok()
}

/// `aws-lc-rs`'s public-key derivation.
fn aws_lc_public(private: &[u8; 32]) -> [u8; 32] {
    let key = PrivateKey::from_private_key(&X25519, private).expect("any 32 bytes are a scalar");
    let public = key.compute_public_key().expect("public key derivation");
    <[u8; 32]>::try_from(public.as_ref()).expect("X25519 public keys are 32 bytes")
}

#[test]
fn public_keys_agree_with_both_incumbents() {
    let mut stream = Stream::new("rr-crypto/x25519/public");
    for round in 0..256 {
        let scalar = stream.next();

        let ours = rr_crypto::StaticSecret::from_bytes(scalar).public_key();
        let aws = aws_lc_public(&scalar);
        let dalek =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(scalar)).to_bytes();

        assert_eq!(ours, aws, "round {round}: disagreed with aws-lc-rs");
        assert_eq!(ours, dalek, "round {round}: disagreed with x25519-dalek");
    }
}

#[test]
fn agreements_agree_with_both_incumbents() {
    let mut scalars = Stream::new("rr-crypto/x25519/scalar");
    let mut peers = Stream::new("rr-crypto/x25519/peer");
    for round in 0..256 {
        let scalar = scalars.next();
        // A peer share both sides will accept: derive it, rather than hashing
        // bytes into a u-coordinate that may not be on the curve's main
        // subgroup and would exercise the rejection path instead.
        let peer = rr_crypto::StaticSecret::from_bytes(peers.next()).public_key();

        let ours = rr_crypto::StaticSecret::from_bytes(scalar)
            .agree(&peer)
            .map(|secret| *secret.as_bytes());
        let aws = aws_lc_agree(&scalar, &peer);
        let dalek = {
            let shared = x25519_dalek::StaticSecret::from(scalar)
                .diffie_hellman(&x25519_dalek::PublicKey::from(peer));
            shared.was_contributory().then(|| shared.to_bytes())
        };

        assert_eq!(ours, aws, "round {round}: disagreed with aws-lc-rs");
        assert_eq!(ours, dalek, "round {round}: disagreed with x25519-dalek");
        assert!(
            ours.is_some(),
            "round {round}: a derived peer share must agree"
        );
    }
}

#[test]
fn the_ephemeral_shape_agrees_with_the_incumbent() {
    // The shape `tls13/handshake.rs` performs: generate, publish the share,
    // agree once, consuming the key.
    let mut scalars = Stream::new("rr-crypto/x25519/ephemeral");
    let mut peers = Stream::new("rr-crypto/x25519/ephemeral-peer");
    for round in 0..128 {
        let scalar = scalars.next();
        let peer = aws_lc_public(&peers.next());

        let ephemeral = rr_crypto::EphemeralSecret::from_entropy(|buffer| {
            buffer.copy_from_slice(&scalar);
            Ok::<(), core::convert::Infallible>(())
        })
        .expect("an infallible filler");
        let public = *ephemeral.public_key();
        let ours = ephemeral.agree(&peer).map(|secret| *secret.as_bytes());

        assert_eq!(
            public,
            aws_lc_public(&scalar),
            "round {round}: public share"
        );
        assert_eq!(
            ours,
            aws_lc_agree(&scalar, &peer),
            "round {round}: agreement"
        );
    }
}

/// RFC 7748 §6.1 rejection has to mean the same thing on both sides, or a
/// migration silently changes which peers authenticate.
#[test]
fn non_contributory_shares_are_refused_by_everyone() {
    // Exactly the set `crates/rr-crypto` itself verifies, so the two tests
    // cannot drift apart: the five small-order u-coordinates and the two
    // non-canonical encodings that reduce onto them. Values are not invented
    // here — an encoding that merely looks unusual is a valid point, and
    // asserting it must be refused would test nothing but the author's memory.
    const REJECTED: &[&str] = &[
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];

    let mut scalars = Stream::new("rr-crypto/x25519/low-order");
    for share in REJECTED {
        let mut peer = [0_u8; 32];
        for (index, byte) in peer.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&share[index * 2..index * 2 + 2], 16).expect("hex");
        }
        let scalar = scalars.next();

        assert!(
            rr_crypto::StaticSecret::from_bytes(scalar)
                .agree(&peer)
                .is_none(),
            "rr-crypto accepted the non-contributory share {share}"
        );
        assert!(
            aws_lc_agree(&scalar, &peer).is_none(),
            "aws-lc-rs accepted the non-contributory share {share}"
        );
        let dalek = x25519_dalek::StaticSecret::from(scalar)
            .diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        assert!(
            !dalek.was_contributory(),
            "x25519-dalek accepted the non-contributory share {share}"
        );
    }
}
