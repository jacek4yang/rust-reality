//! Mature cryptographic primitives and key-generation helpers.

mod keygen;
mod x25519;

pub use keygen::{
    KeyGenerationError, X25519KeyPair, generate_node_key, generate_short_id, generate_uuid,
    generate_x25519_key_pair,
};
pub use x25519::{EphemeralX25519Key, SharedSecret, StaticX25519Key, X25519Error};
