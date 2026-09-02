//! Mature cryptographic primitives and key-generation helpers.

mod keygen;

pub use keygen::{
    KeyGenerationError, X25519KeyPair, generate_node_key, generate_short_id, generate_uuid,
    generate_x25519_key_pair,
};
