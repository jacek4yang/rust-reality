//! The cryptographic boundary: entropy, key agreement, and key generation.
//!
//! # What lives here, and what does not
//!
//! This module owns the operations whose *provider* is a decision rather than
//! a detail — today entropy and X25519. Hashing, HMAC, HKDF, the record AEAD,
//! Ed25519 and ML-KEM are still called directly from the protocol modules that
//! need them, against RustCrypto, `ring`, `ed25519-dalek` and `ml-kem`. That is
//! recorded rather than hidden: `tests/crypto_boundary.rs` lists exactly which
//! module may name which provider crate, so the set can only shrink, and every
//! migration step is visible as a line removed from that list.
//!
//! Growing this module before there is a second implementation to choose
//! between would be a provider framework with one provider. The boundary
//! arrives where a decision arrives.
//!
//! # Layering
//!
//! ```text
//! protocol semantics  ->  this module  ->  provider crate / architecture backend
//!                                 ^
//!                          entropy from the platform
//! ```
//!
//! The protocol core (ADR 0016, `tests/protocol_core_boundary.rs`) compiles
//! against `core` + `alloc`. Nothing here may break that, which is why
//! `aws_lc_rs` — the one `std`-only provider in the graph — is named as
//! forbidden inside the core and confined to the X25519 module, reached only
//! from `reality/auth.rs` and `reality/tls13/handshake.rs`, both deliberately
//! outside the enforced list.
//!
//! That confinement is also why this binary links **two** X25519
//! implementations: `aws-lc-rs` for the two per-session agreements, and
//! `x25519-dalek` where the caller is inside the `no_std` core or does not
//! justify the `std` provider. It is a symptom of the provider being
//! `std`-only, not a design choice, and it resolves when a `no_std`-capable
//! X25519 replaces it.
//!
//! # Secret ownership
//!
//! Types here exist only where they enforce something the type system can
//! check:
//!
//! - [`StaticX25519Key`] is not `Clone`. One configuration generation owns one
//!   key; cloning would copy secret material to satisfy a derive rather than a
//!   requirement.
//! - [`EphemeralX25519Key::agree`] takes `self`. One ephemeral key serves one
//!   agreement, and the compiler is what says so.
//! - [`SharedSecret`] is `Zeroizing`, so an agreed secret clears itself
//!   wherever a caller drops it.
//! - Neither key type renders its material through `Debug`.
//!
//! No wrapper is added merely because the value is secret. `Zeroizing` around
//! a byte array already carries the erasure property, and a named type that
//! adds nothing to it would be a rename with a maintenance cost.
//!
//! # Entropy ownership
//!
//! [`entropy`] is the single source. See its documentation for why it is a
//! function rather than an injectable trait, and for the one draw that does
//! not go through it yet.

pub mod entropy;
mod keygen;
mod x25519;

pub use entropy::EntropyError;
pub use keygen::{
    X25519KeyPair, generate_node_key, generate_short_id, generate_uuid, generate_x25519_key_pair,
};
pub use x25519::{EphemeralX25519Key, SharedSecret, StaticX25519Key, X25519Error};
