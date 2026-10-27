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

/// Handoff wire protocol version carried in the fixed header.
pub const HANDOFF_PROTOCOL_VERSION: u8 = 1;

/// Current continuation-state blob version, carried in the header and repeated
/// inside the sealed blob.
///
/// - Version 1: rejected (cannot retain KeyUpdate state).
/// - Version 2: TCP-only continuation without session-kind / policy snapshot;
///   rejected by this build (no silent reinterpret as XUDP).
/// - Version 3: explicit [`SessionKind`] + inbound tag + [`HandoffPolicySnapshot`].
pub const CONTINUATION_STATE_VERSION: u8 = 3;

/// Maximum inbound tag bytes sealed into a continuation (operator tag length).
pub const MAX_INBOUND_TAG_LEN: usize = 64;

pub(crate) const MAGIC: [u8; 4] = *b"HND1";

/// Fixed header length in bytes.
pub const HEADER_LEN: usize = 114;

/// Hard cap on the sealed continuation blob length.
pub const MAX_BLOB_LEN: usize = 96 * 1024;

/// Largest valid transfer message: header, capped blob, and AEAD tag.
pub const MAX_MESSAGE_LEN: usize = HEADER_LEN + MAX_BLOB_LEN + TAG_LEN;

pub(crate) const VERSION_OFFSET: usize = 4;
pub(crate) const STATE_VERSION_OFFSET: usize = 5;
pub(crate) const TIMESTAMP_OFFSET: usize = 6;
pub(crate) const NONCE_OFFSET: usize = 14;
pub(crate) const EPHEMERAL_OFFSET: usize = 30;
pub(crate) const CLIENT_RANDOM_OFFSET: usize = 62;
pub(crate) const USER_ID_OFFSET: usize = 94;
pub(crate) const BLOB_LEN_OFFSET: usize = 110;

pub(crate) const NONCE_LEN: usize = 16;
pub(crate) const X25519_PUBLIC_LEN: usize = 32;
pub(crate) const USER_ID_LEN: usize = 16;
pub(crate) const TAG_LEN: usize = 16;
pub(crate) const MAX_DOMAIN_LEN: usize = 253;

/// Reader read-ahead cap: four TLS record slots, mirroring the
/// `TlsApplicationReader` socket buffer (`4 * MAX_TLS_RECORD_WIRE_LEN`).
pub(crate) const MAX_PENDING_CIPHERTEXT_LEN: usize = 4 * (5 + 16_384 + 1 + TAG_LEN);

/// Prefetched-payload cap, mirroring the Vision request buffer bound
/// (`MAX_REQUEST_HEADER_SIZE + MAX_PLAINTEXT_LEN` in `server::vision`).
pub(crate) const MAX_PREFETCHED_PLAINTEXT_LEN: usize = 533 + 16_384;

const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 2;
const ADDRESS_IPV6: u8 = 3;

#[cfg(test)]
mod tests;
