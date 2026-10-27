//! Fixed-header encode/decode for Handoff wire transfers.
//!
//! Kept in its own module so seal/open and AEAD key derivation stay readable
//! while the dense header layout (magic, versions, offsets, blob length) lives
//! beside the blob/keys/error surfaces.

use super::{
    BLOB_LEN_OFFSET, CLIENT_RANDOM_OFFSET, CONTINUATION_STATE_VERSION, EPHEMERAL_OFFSET,
    HANDOFF_PROTOCOL_VERSION, HEADER_LEN, HandoffError, MAGIC, MAX_BLOB_LEN, MAX_MESSAGE_LEN,
    NONCE_LEN, NONCE_OFFSET, STATE_VERSION_OFFSET, TAG_LEN, TIMESTAMP_OFFSET, USER_ID_LEN,
    USER_ID_OFFSET, VERSION_OFFSET, X25519_PUBLIC_LEN,
};

/// Returns the exact total message size declared by one fixed header.
///
/// Performs only the bounded structural checks needed to read exactly one
/// transfer off a stream: magic, both versions, and the blob-length cap. It
/// does not authenticate any field and never allocates.
///
/// # Errors
///
/// Rejects truncated, wrong-version, and oversized headers.
pub fn message_len_from_header(header: &[u8]) -> Result<usize, HandoffError> {
    let parsed = parse_header(header)?;
    HEADER_LEN
        .checked_add(parsed.blob_len)
        .and_then(|length| length.checked_add(TAG_LEN))
        .filter(|length| *length <= MAX_MESSAGE_LEN)
        .ok_or(HandoffError::Length)
}

pub(crate) struct TransferHeader {
    pub(crate) raw: [u8; HEADER_LEN],
    pub(crate) timestamp: u64,
    pub(crate) nonce: [u8; NONCE_LEN],
    pub(crate) ephemeral_public: [u8; X25519_PUBLIC_LEN],
    pub(crate) client_random: [u8; 32],
    pub(crate) user_id: [u8; USER_ID_LEN],
    pub(crate) blob_len: usize,
}

pub(crate) fn parse_header(header: &[u8]) -> Result<TransferHeader, HandoffError> {
    let raw: [u8; HEADER_LEN] = header.try_into().map_err(|_| HandoffError::Length)?;
    if raw[..MAGIC.len()] != MAGIC {
        return Err(HandoffError::Version);
    }
    if raw[VERSION_OFFSET] != HANDOFF_PROTOCOL_VERSION
        || raw[STATE_VERSION_OFFSET] != CONTINUATION_STATE_VERSION
    {
        return Err(HandoffError::Version);
    }
    let blob_len = u32::from_be_bytes(read_array(&raw, BLOB_LEN_OFFSET)?);
    let blob_len = usize::try_from(blob_len).map_err(|_| HandoffError::Length)?;
    if blob_len > MAX_BLOB_LEN {
        return Err(HandoffError::Length);
    }
    Ok(TransferHeader {
        raw,
        timestamp: u64::from_be_bytes(read_array(&raw, TIMESTAMP_OFFSET)?),
        nonce: read_array(&raw, NONCE_OFFSET)?,
        ephemeral_public: read_array(&raw, EPHEMERAL_OFFSET)?,
        client_random: read_array(&raw, CLIENT_RANDOM_OFFSET)?,
        user_id: read_array(&raw, USER_ID_OFFSET)?,
        blob_len,
    })
}

pub(crate) fn read_array<const N: usize>(
    raw: &[u8; HEADER_LEN],
    offset: usize,
) -> Result<[u8; N], HandoffError> {
    raw.get(offset..offset + N)
        .ok_or(HandoffError::Length)?
        .try_into()
        .map_err(|_| HandoffError::Length)
}

pub(crate) fn encode_header(
    timestamp: u64,
    nonce: [u8; NONCE_LEN],
    ephemeral_public: &[u8; X25519_PUBLIC_LEN],
    client_random: &[u8; 32],
    user_id: &[u8; USER_ID_LEN],
    blob_len: u32,
) -> [u8; HEADER_LEN] {
    let mut header = [0_u8; HEADER_LEN];
    header[..MAGIC.len()].copy_from_slice(&MAGIC);
    header[VERSION_OFFSET] = HANDOFF_PROTOCOL_VERSION;
    header[STATE_VERSION_OFFSET] = CONTINUATION_STATE_VERSION;
    header[TIMESTAMP_OFFSET..NONCE_OFFSET].copy_from_slice(&timestamp.to_be_bytes());
    header[NONCE_OFFSET..EPHEMERAL_OFFSET].copy_from_slice(&nonce);
    header[EPHEMERAL_OFFSET..CLIENT_RANDOM_OFFSET].copy_from_slice(ephemeral_public);
    header[CLIENT_RANDOM_OFFSET..USER_ID_OFFSET].copy_from_slice(client_random);
    header[USER_ID_OFFSET..BLOB_LEN_OFFSET].copy_from_slice(user_id);
    header[BLOB_LEN_OFFSET..].copy_from_slice(&blob_len.to_be_bytes());
    header
}
