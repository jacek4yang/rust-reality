//! Wire layout constants for the NXR open request.
//!
//! Offsets, length caps, and open-mode flag helpers shared by encode/decode
//! and UDP open classification. Behavior is unchanged; this module only owns
//! the numbers and the unauthenticated flag peek.

/// NXR open magic and version prefix (`NXR\x01`).
pub(crate) const MAGIC: [u8; 4] = [b'N', b'X', b'R', 1];

pub(crate) const ADDRESS_IPV4: u8 = 1;
pub(crate) const ADDRESS_DOMAIN: u8 = 2;
pub(crate) const ADDRESS_IPV6: u8 = 3;
pub(crate) const ADDRESS_LENGTH_OFFSET: usize = 6;
pub(crate) const PORT_OFFSET: usize = 8;
pub(crate) const TIMESTAMP_OFFSET: usize = 10;
pub(crate) const NONCE_OFFSET: usize = 18;
pub(crate) const ADDRESS_OFFSET: usize = 34;
pub(crate) const TAG_LEN: usize = 32;
pub(crate) const MAX_DOMAIN_LEN: usize = 253;

/// Bytes required before the receiver can determine the exact request length.
pub const REQUEST_HEADER_LEN: usize = ADDRESS_OFFSET;

/// Strict maximum for one NXR authentication request.
pub const MAX_REQUEST_LEN: usize = REQUEST_HEADER_LEN + MAX_DOMAIN_LEN + TAG_LEN;

/// Fixed header flag byte offset (after 4-byte magic).
pub const FLAGS_OFFSET: usize = 4;

/// TCP connect mode (historical NXR open).
pub const FLAG_TCP: u8 = 0;

/// UDP/XUDP association mode (ADR 0060 Option A). Distinct from [`FLAG_TCP`] so
/// a UDP open cannot be interpreted as a TCP open byte-for-byte.
pub const FLAG_UDP: u8 = 1;

/// Returns the open-mode flag when the fixed header is present.
///
/// Does not authenticate. Callers still must run the matching decode path.
#[must_use]
pub fn peek_open_flags(header: &[u8]) -> Option<u8> {
    if header.len() < REQUEST_HEADER_LEN || header[..MAGIC.len()] != MAGIC {
        return None;
    }
    Some(header[FLAGS_OFFSET])
}
