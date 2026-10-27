//! LINE→LANDING session-continuation transfer ("Handoff", wire protocol v1).
//!
//! A Noise_NK-shaped single-flight protocol (notes/v1.1/p9-security-design.md,
//! Option B): LINE seals the continuation state of one accepted session with a
//! per-transfer X25519 ephemeral DH'd against LANDING's static public key, the
//! DH output mixed with the pair PSK in one HKDF-SHA256 chain, and one
//! ChaCha20-Poly1305 seal over the state blob with the entire fixed header as
//! associated data. AEAD open success is the mutual key confirmation: LANDING
//! proves its static key, LINE proves the PSK.
//!
//! Wire layout:
//!
//! ```text
//! "HND1" | u8 proto_version | u8 state_version | u64 unix_ts
//!      | [16] transfer_nonce | [32] E_pub | [32] client_random
//!      | [16] user_id | u32 blob_len | AEAD(blob) || [16] tag
//! ```
//!
//! LANDING validates in exactly this order: header structure, timestamp
//! window, nonce reserve (bounded sharded replay cache), DH + HKDF, AEAD open,
//! then internal cross-checks. During a bounded key-rotation window LANDING
//! accepts retired keys alongside the active pair (see [`HandoffLandingKeys`]);
//! the timestamp check and the one nonce reserve stay hoisted ahead of all
//! candidate trials. The blob is decrypted fully before any plaintext field
//! is parsed, and every failure maps to the closed-vocabulary
//! [`HandoffError`]; a handler must answer any failure with zero bytes and a
//! silent close.

/// Monotonic clock alias used by the replay cache and its unit tests.
pub use std::time::Instant as MonotonicInstant;

mod blob;
mod error;
mod keys;
mod layout;
mod policy;
mod replay;
mod state;
mod transfer;
mod wire;

#[cfg(feature = "fuzzing")]
pub use blob::fuzz_decode_blob;
pub use error::HandoffError;
pub use keys::{HandoffLandingKeys, HandoffPsk, MAX_PREVIOUS_KEYS};
pub use policy::{
    HANDOFF_POLICY_SNAPSHOT_VERSION, HANDOFF_POLICY_SNAPSHOT_VERSION_V1, HandoffPolicySnapshot,
    MAX_POLICY_SNAPSHOT_LEN, MAX_SEALED_HANDOFF_RULES, SealedDomainMatcher, SealedHandoffRouteRule,
    SealedIpNetwork, SealedPortRange, SessionKind,
};
pub use replay::HandoffReplayCache;
pub use state::{ContinuationParts, ContinuationState, OpenedTransfer};
pub use transfer::{open_transfer, seal_transfer};
pub use wire::message_len_from_header;

pub(crate) use layout::{
    ADDRESS_DOMAIN, ADDRESS_IPV4, ADDRESS_IPV6, BLOB_LEN_OFFSET, CLIENT_RANDOM_OFFSET,
    EPHEMERAL_OFFSET, MAGIC, MAX_DOMAIN_LEN, MAX_PENDING_CIPHERTEXT_LEN,
    MAX_PREFETCHED_PLAINTEXT_LEN, NONCE_LEN, NONCE_OFFSET, STATE_VERSION_OFFSET, TAG_LEN,
    TIMESTAMP_OFFSET, USER_ID_LEN, USER_ID_OFFSET, VERSION_OFFSET, X25519_PUBLIC_LEN,
};
pub use layout::{
    CONTINUATION_STATE_VERSION, HANDOFF_PROTOCOL_VERSION, HEADER_LEN, MAX_BLOB_LEN,
    MAX_INBOUND_TAG_LEN, MAX_MESSAGE_LEN,
};

#[cfg(test)]
mod tests;
