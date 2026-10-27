//! Wire layout constants for the Handoff single-flight transfer.
//!
//! Offsets and length caps shared by header encode/decode, blob codec,
//! transfer seal/open, and continuation-state construction. Behavior is
//! unchanged; this module only owns the numbers.

/// Handoff wire protocol version carried in the fixed header.
pub const HANDOFF_PROTOCOL_VERSION: u8 = 1;

/// Current continuation-state blob version, carried in the header and repeated
/// inside the sealed blob.
///
/// - Version 1: rejected (cannot retain KeyUpdate state).
/// - Version 2: TCP-only continuation without session-kind / policy snapshot;
///   rejected by this build (no silent reinterpret as XUDP).
/// - Version 3: explicit [`SessionKind`](crate::protocol::handoff::SessionKind) + inbound tag + [`HandoffPolicySnapshot`](crate::protocol::handoff::HandoffPolicySnapshot).
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

pub(crate) const ADDRESS_IPV4: u8 = 1;
pub(crate) const ADDRESS_DOMAIN: u8 = 2;
pub(crate) const ADDRESS_IPV6: u8 = 3;
