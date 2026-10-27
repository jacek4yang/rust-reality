//! LINE→LANDING seal/open transfer and AEAD key derivation.
//!
//! Kept in its own module so the Noise_NK-shaped single-flight path
//! (`seal_transfer` / `open_transfer` / `derive_aead`) stays readable beside
//! the header, blob, keys, and continuation-state surfaces.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{AeadInOut, Nonce, Tag, array::Array},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::EphemeralX25519Key;

use super::blob::{decode_blob, encode_blob};
use super::wire::{encode_header, parse_header};
use super::{
    BLOB_LEN_OFFSET, CLIENT_RANDOM_OFFSET, ContinuationState, EPHEMERAL_OFFSET, HEADER_LEN,
    HandoffError, HandoffLandingKeys, HandoffPsk, HandoffReplayCache, NONCE_LEN, OpenedTransfer,
    TAG_LEN, USER_ID_LEN, X25519_PUBLIC_LEN, message_len_from_header,
};

const AEAD_NONCE_LEN: usize = 12;

/// At the handoff boundary the server direction is either untouched, or has
/// emitted exactly one empty application-data record while matching the cover
/// target's post-handshake shape. Larger values cannot arise before LINE
/// transfers ownership and therefore fail closed.
const MAX_SERVER_SEQUENCE_AT_HANDOFF: u64 = 1;

/// Domain separator for the control-channel HKDF chain. Deliberately distinct
/// from the TLS 1.3 `"tls13 "` label prefix.
const HKDF_SALT_LABEL: &[u8] = b"rust-reality/handoff/v1";

/// HKDF salt: label || E_pub || S_pub.
const SALT_LEN: usize = 23 + X25519_PUBLIC_LEN + X25519_PUBLIC_LEN;

/// HKDF info transcript: header through E_pub || S_pub || client_random ||
/// user_id (everything except `blob_len`, which the AEAD AD still covers).
const TRANSCRIPT_LEN: usize = CLIENT_RANDOM_OFFSET + X25519_PUBLIC_LEN + USER_ID_LEN + 32;

/// Seals one continuation state into a complete LINE→LANDING transfer message.
///
/// A fresh X25519 ephemeral and a fresh 128-bit transfer nonce are drawn for
/// every call; the ephemeral secret is consumed by the single DH and zeroized.
/// `output` is written only after a successful seal, so no error path ever
/// leaves plaintext in the caller's non-zeroizing buffer.
///
/// # Errors
///
/// Rejects out-of-bounds state, unavailable OS randomness, a non-contributory
/// LANDING public key, allocation failure, and AEAD failure.
pub fn seal_transfer(
    state: &ContinuationState,
    psk: &HandoffPsk,
    landing_public: &[u8; 32],
    client_random: [u8; 32],
    timestamp: u64,
    output: &mut Vec<u8>,
) -> Result<(), HandoffError> {
    let ephemeral = EphemeralX25519Key::generate().map_err(|_| HandoffError::Random)?;
    let ephemeral_public = *ephemeral.public_key();
    let mut nonce = [0_u8; NONCE_LEN];
    crate::crypto::entropy::fill(&mut nonce).map_err(|_| HandoffError::Random)?;

    let mut blob = Zeroizing::new(Vec::new());
    encode_blob(state, &mut blob)?;
    let blob_len = u32::try_from(blob.len()).map_err(|_| HandoffError::Length)?;
    let header = encode_header(
        timestamp,
        nonce,
        &ephemeral_public,
        &client_random,
        state.user_id(),
        blob_len,
    );

    // A non-contributory LANDING share agrees to all zeros, which would
    // authenticate nothing; the contributory check is folded into `None`.
    let shared = ephemeral
        .agree(landing_public)
        .ok_or(HandoffError::Authentication)?;
    let (key, aead_nonce) = derive_aead(&header, &shared, psk, landing_public)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| HandoffError::Crypto)?;
    let nonce_bytes: Nonce<ChaCha20Poly1305> = Array(*aead_nonce);

    // Seal inside the zeroizing blob buffer: on an AEAD failure the plaintext
    // is scrubbed when `blob` drops, and the caller's non-zeroizing `output`
    // only ever receives header, ciphertext, and tag.
    let tag = cipher
        .encrypt_inout_detached(&nonce_bytes, &header[..], blob.as_mut_slice().into())
        .map_err(|_| HandoffError::Crypto)?;
    output.clear();
    output
        .try_reserve_exact(HEADER_LEN + blob.len() + TAG_LEN)
        .map_err(|_| HandoffError::Allocation)?;
    output.extend_from_slice(&header);
    output.extend_from_slice(&blob);
    output.extend_from_slice(&tag);
    Ok(())
}

/// Verifies, decrypts, and validates exactly one complete transfer message.
///
/// Validation order is load-bearing: header structure, timestamp window,
/// nonce reserve, per-candidate ephemeral DH plus HKDF, AEAD open, and only
/// then the internal cross-checks (blob `state_version`, known suite,
/// server-direction sequence zero or one, header/blob user-id agreement). The
/// timestamp check and the single nonce reserve stay hoisted ahead of every
/// candidate trial: the nonce is reserved exactly once, so a forgery burns
/// one replay slot no matter how many candidates the landing accepts, and a
/// replayed message is rejected before any DH work. The blob is decrypted
/// fully before any plaintext field is parsed.
///
/// # Errors
///
/// Every failure maps to the closed [`HandoffError`] vocabulary; callers must
/// answer with zero bytes and a silent close. Which candidate matched — or
/// how many were tried — is never exposed in the error or log vocabulary.
/// (Trial count is still observable in fine-grained timing on a co-located
/// observer; the listener is firewall-restricted by design.)
pub fn open_transfer(
    message: &[u8],
    keys: &HandoffLandingKeys,
    replay: &HandoffReplayCache,
    now: u64,
    maximum_time_difference: u64,
) -> Result<OpenedTransfer, HandoffError> {
    let header_bytes = message.get(..HEADER_LEN).ok_or(HandoffError::Length)?;
    let expected = message_len_from_header(header_bytes)?;
    if message.len() != expected {
        return Err(HandoffError::Length);
    }
    let header = parse_header(header_bytes)?;
    if header.timestamp.abs_diff(now) > maximum_time_difference {
        return Err(HandoffError::TimeWindow);
    }
    replay.reserve(header.nonce)?;

    let ephemeral_public = header.ephemeral_public;
    let ciphertext_end = HEADER_LEN
        .checked_add(header.blob_len)
        .ok_or(HandoffError::Length)?;
    let body = message
        .get(HEADER_LEN..ciphertext_end)
        .ok_or(HandoffError::Length)?;
    let tag_bytes: &[u8; TAG_LEN] = message
        .get(ciphertext_end..expected)
        .ok_or(HandoffError::Length)?
        .try_into()
        .map_err(|_| HandoffError::Length)?;
    let tag: Tag<ChaCha20Poly1305> = Array(*tag_bytes);
    let mut blob = Zeroizing::new(Vec::new());
    blob.try_reserve_exact(header.blob_len)
        .map_err(|_| HandoffError::Allocation)?;

    // Candidate trials over the bounded cross product (see
    // `HandoffLandingKeys::candidates`). Every candidate performs its OWN
    // Diffie-Hellman, its own contributory check, and its own S_pub
    // derivation feeding `derive_aead` — none of these may be hoisted or
    // shared across candidates, or one candidate's DH output could be mixed
    // with another candidate's key material. A failed candidate is
    // indistinguishable from a wrong key: the trial moves on, and only the
    // closed Authentication error is ever reported when none matches.
    let mut decrypted = false;
    for (psk, landing_secret) in keys.candidates() {
        let Some(shared) = landing_secret.agree(&ephemeral_public) else {
            continue;
        };
        let landing_public = landing_secret.public_key();
        let (key, aead_nonce) = derive_aead(&header.raw, &shared, psk, &landing_public)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| HandoffError::Crypto)?;
        let nonce_bytes: Nonce<ChaCha20Poly1305> = Array(*aead_nonce);
        // A detached decrypt may scribble on its buffer before failing, so
        // every trial starts from a fresh copy of the wire ciphertext.
        blob.clear();
        blob.extend_from_slice(body);
        if cipher
            .decrypt_inout_detached(&nonce_bytes, header_bytes, blob.as_mut_slice().into(), &tag)
            .is_ok()
        {
            decrypted = true;
            break;
        }
    }
    if !decrypted {
        return Err(HandoffError::Authentication);
    }

    let state = decode_blob(&blob)?;
    if state.server_sequence() > MAX_SERVER_SEQUENCE_AT_HANDOFF
        || state.user_id() != &header.user_id
    {
        return Err(HandoffError::State);
    }
    Ok(OpenedTransfer::from_parts(
        header.timestamp,
        header.client_random,
        state,
    ))
}

/// The derived per-transfer AEAD key and nonce, both zeroized on drop.
type DerivedAead = (Zeroizing<[u8; 32]>, Zeroizing<[u8; AEAD_NONCE_LEN]>);

/// HKDF-Extract(salt = label || E_pub || S_pub, ikm = shared || PSK), then
/// HKDF-Expand over the transcript (fixed header through `user_id`, with
/// S_pub spliced in after E_pub; `blob_len` is covered by the AEAD AD).
pub(crate) fn derive_aead(
    header: &[u8; HEADER_LEN],
    shared: &[u8; 32],
    psk: &HandoffPsk,
    landing_public: &[u8; X25519_PUBLIC_LEN],
) -> Result<DerivedAead, HandoffError> {
    let mut salt = [0_u8; SALT_LEN];
    salt[..HKDF_SALT_LABEL.len()].copy_from_slice(HKDF_SALT_LABEL);
    salt[HKDF_SALT_LABEL.len()..HKDF_SALT_LABEL.len() + X25519_PUBLIC_LEN]
        .copy_from_slice(&header[EPHEMERAL_OFFSET..CLIENT_RANDOM_OFFSET]);
    salt[HKDF_SALT_LABEL.len() + X25519_PUBLIC_LEN..].copy_from_slice(landing_public);

    let mut ikm = Zeroizing::new([0_u8; 64]);
    ikm[..32].copy_from_slice(shared);
    ikm[32..].copy_from_slice(psk.as_bytes());

    let mut transcript = [0_u8; TRANSCRIPT_LEN];
    transcript[..CLIENT_RANDOM_OFFSET].copy_from_slice(&header[..CLIENT_RANDOM_OFFSET]);
    transcript[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + X25519_PUBLIC_LEN]
        .copy_from_slice(landing_public);
    transcript[CLIENT_RANDOM_OFFSET + X25519_PUBLIC_LEN..]
        .copy_from_slice(&header[CLIENT_RANDOM_OFFSET..BLOB_LEN_OFFSET]);

    let mut okm = Zeroizing::new([0_u8; 32 + AEAD_NONCE_LEN]);
    {
        let (prk, hkdf) = Hkdf::<Sha256>::extract(Some(&salt), ikm.as_slice());
        let _prk = Zeroizing::new(prk);
        hkdf.expand(&transcript, okm.as_mut_slice())
            .map_err(|_| HandoffError::Crypto)?;
    }
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&okm[..32]);
    let mut nonce = Zeroizing::new([0_u8; AEAD_NONCE_LEN]);
    nonce.copy_from_slice(&okm[32..]);
    Ok((key, nonce))
}

