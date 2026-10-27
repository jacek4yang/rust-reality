//! Wire layout constants for NXR UDP open and framed datagrams.
//!
//! Offsets, direction/type/flag tags, and length caps shared by open/frame
//! codecs. Behavior is unchanged; this module only owns the numbers.

use super::super::nxr::REQUEST_HEADER_LEN;
use super::super::vless::XUDP_MAX_PAYLOAD_LEN;

pub(crate) const MAGIC: [u8; 4] = [b'N', b'X', b'R', 1];
pub(crate) const ADDRESS_IPV4: u8 = 1;
pub(crate) const ADDRESS_DOMAIN: u8 = 2;
pub(crate) const ADDRESS_IPV6: u8 = 3;
pub(crate) const ADDRESS_LENGTH_OFFSET: usize = 6;
pub(crate) const PORT_OFFSET: usize = 8;
pub(crate) const TIMESTAMP_OFFSET: usize = 10;
pub(crate) const NONCE_OFFSET: usize = 18;
pub(crate) const ADDRESS_OFFSET: usize = 34;
pub(crate) const OPEN_TAG_LEN: usize = 32;
pub(crate) const USER_ID_LEN: usize = 16;
pub(crate) const MAX_DOMAIN_LEN: usize = 253;
pub(crate) const UDP_OPEN_TRAILER: usize = USER_ID_LEN;

/// LINE → LANDING (toward the UDP target).
pub const DIR_LINE_TO_LANDING: u8 = 0;

/// LANDING → LINE (replies toward the client path).
pub const DIR_LANDING_TO_LINE: u8 = 1;

/// Datagram frame.
pub const FRAME_TYPE_DATAGRAM: u8 = 1;

/// Association close (empty or ignored payload).
pub const FRAME_TYPE_CLOSE: u8 = 2;

/// Frame body flag: destination fields are present.
pub const FRAME_FLAG_DESTINATION: u8 = 1;

/// Session / frame MAC tag length.
pub const SESSION_TAG_LEN: usize = 32;

/// Maximum UDP payload in one frame (stock XUDP bound).
pub const NXR_UDP_MAX_PAYLOAD: usize = XUDP_MAX_PAYLOAD_LEN;

/// Outer length-prefix size.
pub const FRAME_LEN_SIZE: usize = 4;

/// Maximum encoded destination inside a frame.
pub(crate) const MAX_FRAME_DEST_LEN: usize = 1 + 2 + 2 + MAX_DOMAIN_LEN;

/// Strict maximum frame body length.
pub const MAX_FRAME_BODY_LEN: usize = 1 + 1 + 4 + MAX_FRAME_DEST_LEN + 2 + NXR_UDP_MAX_PAYLOAD;

/// Strict maximum on-wire frame size.
pub const MAX_FRAME_WIRE_LEN: usize = FRAME_LEN_SIZE + MAX_FRAME_BODY_LEN + SESSION_TAG_LEN;

/// Maximum UDP open request length (header + max domain + user id + tag).
pub const MAX_UDP_OPEN_LEN: usize =
    REQUEST_HEADER_LEN + MAX_DOMAIN_LEN + UDP_OPEN_TRAILER + OPEN_TAG_LEN;
