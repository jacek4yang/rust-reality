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
//! then internal cross-checks. The blob is decrypted fully before any
//! plaintext field is parsed, and every failure maps to the closed-vocabulary
//! [`HandoffError`]; a handler must answer any failure with zero bytes and a
//! silent close.

use std::{
    collections::HashMap,
    error::Error,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant as MonotonicInstant},
};

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{AeadInOut, Nonce, Tag, array::Array},
};
use getrandom::SysRng;
use getrandom::rand_core::UnwrapErr;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::reality::tls13::{CipherSuite, TrafficKeys};
use super::vless::{Address, Destination};

/// Handoff wire protocol version carried in the fixed header.
pub const HANDOFF_PROTOCOL_VERSION: u8 = 1;

/// Continuation-state blob version carried in the header and repeated inside
/// the sealed blob.
pub const CONTINUATION_STATE_VERSION: u8 = 1;

const MAGIC: [u8; 4] = *b"HND1";

/// Fixed header length in bytes.
pub const HEADER_LEN: usize = 114;

/// Hard cap on the sealed continuation blob length.
pub const MAX_BLOB_LEN: usize = 96 * 1024;

/// Largest valid transfer message: header, capped blob, and AEAD tag.
pub const MAX_MESSAGE_LEN: usize = HEADER_LEN + MAX_BLOB_LEN + TAG_LEN;

const VERSION_OFFSET: usize = 4;
const STATE_VERSION_OFFSET: usize = 5;
const TIMESTAMP_OFFSET: usize = 6;
const NONCE_OFFSET: usize = 14;
const EPHEMERAL_OFFSET: usize = 30;
const CLIENT_RANDOM_OFFSET: usize = 62;
const USER_ID_OFFSET: usize = 94;
const BLOB_LEN_OFFSET: usize = 110;

const NONCE_LEN: usize = 16;
const X25519_PUBLIC_LEN: usize = 32;
const USER_ID_LEN: usize = 16;
const TAG_LEN: usize = 16;
const AEAD_NONCE_LEN: usize = 12;
const REPLAY_SHARDS: usize = 16;
const MAX_DOMAIN_LEN: usize = 253;

/// Reader read-ahead cap: four TLS record slots, mirroring the
/// `TlsApplicationReader` socket buffer (`4 * MAX_TLS_RECORD_WIRE_LEN`).
const MAX_PENDING_CIPHERTEXT_LEN: usize = 4 * (5 + 16_384 + 1 + TAG_LEN);

/// Prefetched-payload cap, mirroring the Vision request buffer bound
/// (`MAX_REQUEST_HEADER_SIZE + MAX_PLAINTEXT_LEN` in `server::vision`).
const MAX_PREFETCHED_PLAINTEXT_LEN: usize = 533 + 16_384;

/// Domain separator for the control-channel HKDF chain. Deliberately distinct
/// from the TLS 1.3 `"tls13 "` label prefix.
const HKDF_SALT_LABEL: &[u8] = b"rust-reality/handoff/v1";

/// HKDF salt: label || E_pub || S_pub.
const SALT_LEN: usize = 23 + X25519_PUBLIC_LEN + X25519_PUBLIC_LEN;

/// HKDF info transcript: header through E_pub || S_pub || client_random ||
/// user_id (everything except `blob_len`, which the AEAD AD still covers).
const TRANSCRIPT_LEN: usize = CLIENT_RANDOM_OFFSET + X25519_PUBLIC_LEN + USER_ID_LEN + 32;

const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 2;
const ADDRESS_IPV6: u8 = 3;

/// Independent Handoff pre-shared key. Debug output never reveals its bytes.
///
/// This MUST be generated independently of the NXR pre-shared key and of any
/// REALITY private key.
#[derive(Clone)]
pub struct HandoffPsk(Zeroizing<[u8; 32]>);

impl HandoffPsk {
    /// Creates a key from exactly 256 bits of independently generated entropy.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for HandoffPsk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HandoffPsk([REDACTED])")
    }
}

/// The full surviving session state carried inside the sealed blob.
///
/// Fields are encoded explicitly (no serde, no memory layout); the two
/// variable-length byte strings are bounded by
/// [`MAX_PENDING_CIPHERTEXT_LEN`] and [`MAX_PREFETCHED_PLAINTEXT_LEN`]. Key
/// material and buffered plaintext are zeroized on drop; `Debug` is redacted.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ContinuationState {
    #[zeroize(skip)]
    suite: CipherSuite,
    client_traffic: TrafficKeys,
    server_traffic: TrafficKeys,
    #[zeroize(skip)]
    client_sequence: u64,
    #[zeroize(skip)]
    server_sequence: u64,
    user_id: [u8; USER_ID_LEN],
    #[zeroize(skip)]
    destination: Destination,
    pending_ciphertext: Vec<u8>,
    prefetched_plaintext: Vec<u8>,
}

impl ContinuationState {
    /// Assembles one continuation state, enforcing every field bound.
    ///
    /// # Errors
    ///
    /// Rejects traffic keys whose length disagrees with the suite and pending
    /// buffers above their caps.
    #[allow(clippy::too_many_arguments, reason = "one parameter per blob field")]
    pub fn new(
        suite: CipherSuite,
        client_traffic: TrafficKeys,
        client_sequence: u64,
        server_traffic: TrafficKeys,
        server_sequence: u64,
        user_id: [u8; USER_ID_LEN],
        destination: Destination,
        pending_ciphertext: Vec<u8>,
        prefetched_plaintext: Vec<u8>,
    ) -> Result<Self, HandoffError> {
        if client_traffic.key().len() != suite.key_len()
            || server_traffic.key().len() != suite.key_len()
        {
            return Err(HandoffError::State);
        }
        if pending_ciphertext.len() > MAX_PENDING_CIPHERTEXT_LEN
            || prefetched_plaintext.len() > MAX_PREFETCHED_PLAINTEXT_LEN
        {
            return Err(HandoffError::State);
        }
        Ok(Self {
            suite,
            client_traffic,
            server_traffic,
            client_sequence,
            server_sequence,
            user_id,
            destination,
            pending_ciphertext,
            prefetched_plaintext,
        })
    }

    /// Returns the negotiated cipher suite.
    #[must_use]
    pub const fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// Returns the client-direction AEAD key and static IV.
    #[must_use]
    pub const fn client_traffic(&self) -> &TrafficKeys {
        &self.client_traffic
    }

    /// Returns the server-direction AEAD key and static IV.
    #[must_use]
    pub const fn server_traffic(&self) -> &TrafficKeys {
        &self.server_traffic
    }

    /// Returns the client-direction record sequence at the boundary.
    #[must_use]
    pub const fn client_sequence(&self) -> u64 {
        self.client_sequence
    }

    /// Returns the server-direction record sequence at the boundary.
    #[must_use]
    pub const fn server_sequence(&self) -> u64 {
        self.server_sequence
    }

    /// Returns the session's VLESS user identifier.
    #[must_use]
    pub const fn user_id(&self) -> &[u8; USER_ID_LEN] {
        &self.user_id
    }

    /// Returns the VLESS destination the session dialed toward.
    #[must_use]
    pub const fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Returns undecrypted client ciphertext read ahead of the boundary.
    #[must_use]
    pub fn pending_ciphertext(&self) -> &[u8] {
        &self.pending_ciphertext
    }

    /// Returns prefetched post-header plaintext not yet Vision-decoded.
    #[must_use]
    pub fn prefetched_plaintext(&self) -> &[u8] {
        &self.prefetched_plaintext
    }
}

impl fmt::Debug for ContinuationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContinuationState")
            .field("suite", &self.suite)
            .field("client_sequence", &self.client_sequence)
            .field("server_sequence", &self.server_sequence)
            .field("pending_ciphertext_len", &self.pending_ciphertext.len())
            .field("prefetched_plaintext_len", &self.prefetched_plaintext.len())
            .finish_non_exhaustive()
    }
}

/// One verified and decrypted transfer, ready to be installed on LANDING.
pub struct OpenedTransfer {
    timestamp: u64,
    nonce: [u8; NONCE_LEN],
    client_random: [u8; 32],
    state: ContinuationState,
}

impl OpenedTransfer {
    /// Returns the sender's Unix timestamp in seconds.
    #[must_use]
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Returns the one-time random replay token.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// Returns the client random of the transferred TLS session.
    #[must_use]
    pub const fn client_random(&self) -> &[u8; 32] {
        &self.client_random
    }

    /// Returns the verified continuation state.
    #[must_use]
    pub const fn state(&self) -> &ContinuationState {
        &self.state
    }

    /// Separates the continuation state without copying key material.
    #[must_use]
    pub fn into_state(self) -> ContinuationState {
        self.state
    }
}

impl fmt::Debug for OpenedTransfer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenedTransfer")
            .field("timestamp", &self.timestamp)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// Bounded nonce cache shared by all transfers of one LANDING listener.
///
/// Same construction as the NXR replay cache: sixteen mutex-sharded nonce
/// maps, one atomic capacity counter, monotonic retention deadlines, and
/// reserve-before-use so a nonce is burned even when the transfer it arrived
/// on later fails authentication. Reserve-before-use is deliberate — it keeps
/// the replay check ahead of all DH work — but it also means an
/// unauthenticated peer burns one slot per structurally valid, in-window
/// message, so cache capacity alone does not bound that burn. This is the
/// exact exposure the NXR listener already accepts on the same
/// firewall-restricted internal-port posture; per-source rate limiting
/// belongs to that outer layer, not to this process.
#[derive(Clone)]
pub struct HandoffReplayCache {
    inner: Arc<HandoffReplayCacheInner>,
}

type NonceEntries = HashMap<[u8; NONCE_LEN], MonotonicInstant>;
type NonceShards = Box<[Mutex<NonceEntries>]>;

struct HandoffReplayCacheInner {
    shards: NonceShards,
    capacity: usize,
    used: AtomicUsize,
    retention: Duration,
}

impl HandoffReplayCache {
    /// Creates an independently bounded nonce cache.
    ///
    /// # Errors
    ///
    /// Rejects zero capacity or retention before allocating shards.
    pub fn new(capacity: usize, retention: Duration) -> Result<Self, HandoffError> {
        if capacity == 0 || retention.is_zero() {
            return Err(HandoffError::Replay);
        }
        let shards = (0..REPLAY_SHARDS)
            .map(|_| Mutex::new(HashMap::new()))
            .collect();
        Ok(Self {
            inner: Arc::new(HandoffReplayCacheInner {
                shards,
                capacity,
                used: AtomicUsize::new(0),
                retention,
            }),
        })
    }

    /// Atomically records a structurally valid, fresh nonce until its
    /// monotonic retention deadline.
    ///
    /// # Errors
    ///
    /// Rejects duplicate nonces, exhausted bounded capacity, and allocation
    /// failure.
    pub fn reserve(&self, nonce: [u8; NONCE_LEN]) -> Result<(), HandoffError> {
        let expires_at = MonotonicInstant::now()
            .checked_add(self.inner.retention)
            .ok_or(HandoffError::Replay)?;
        self.purge_expired();
        let shard = usize::from(nonce[0]) % REPLAY_SHARDS;
        let mut entries = lock_recover(&self.inner.shards[shard]);
        if entries.contains_key(&nonce) {
            return Err(HandoffError::Replay);
        }
        entries
            .try_reserve(1)
            .map_err(|_| HandoffError::Allocation)?;
        self.reserve_slot()?;
        entries.insert(nonce, expires_at);
        Ok(())
    }

    /// Removes every expired nonce and returns the number of released entries.
    pub fn purge_expired(&self) -> usize {
        let now = MonotonicInstant::now();
        let removed: usize = self
            .inner
            .shards
            .iter()
            .map(|shard| {
                let mut entries = lock_recover(shard);
                let previous = entries.len();
                entries.retain(|_, expires_at| *expires_at > now);
                previous.saturating_sub(entries.len())
            })
            .sum();
        if removed != 0 {
            self.inner.used.fetch_sub(removed, Ordering::AcqRel);
        }
        removed
    }

    fn reserve_slot(&self) -> Result<(), HandoffError> {
        let mut observed = self.inner.used.load(Ordering::Acquire);
        loop {
            if observed >= self.inner.capacity {
                return Err(HandoffError::Replay);
            }
            match self.inner.used.compare_exchange_weak(
                observed,
                observed + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(current) => observed = current,
            }
        }
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.inner.used.load(Ordering::Acquire)
    }
}

impl fmt::Debug for HandoffReplayCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandoffReplayCache")
            .field("capacity", &self.inner.capacity)
            .finish_non_exhaustive()
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

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
    landing_public: &PublicKey,
    client_random: [u8; 32],
    timestamp: u64,
    output: &mut Vec<u8>,
) -> Result<(), HandoffError> {
    let ephemeral = EphemeralSecret::random_from_rng(&mut UnwrapErr(SysRng));
    let ephemeral_public = PublicKey::from(&ephemeral);
    let mut nonce = [0_u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| HandoffError::Random)?;

    let mut blob = Zeroizing::new(Vec::new());
    encode_blob(state, &mut blob)?;
    let blob_len = u32::try_from(blob.len()).map_err(|_| HandoffError::Length)?;
    let header = encode_header(
        timestamp,
        nonce,
        ephemeral_public.as_bytes(),
        &client_random,
        state.user_id(),
        blob_len,
    );

    let shared = ephemeral.diffie_hellman(landing_public);
    if !shared.was_contributory() {
        return Err(HandoffError::Authentication);
    }
    let (key, aead_nonce) =
        derive_aead(&header, shared.as_bytes(), psk, landing_public.as_bytes())?;
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
/// nonce reserve, ephemeral DH plus HKDF, AEAD open, and only then the
/// internal cross-checks (blob `state_version`, known suite, server-direction
/// sequence zero, header/blob user-id agreement). The nonce stays reserved
/// even when a later step fails, so a replayed message is rejected before any
/// DH work. The blob is decrypted fully before any plaintext field is parsed.
///
/// # Errors
///
/// Every failure maps to the closed [`HandoffError`] vocabulary; callers must
/// answer with zero bytes and a silent close.
pub fn open_transfer(
    message: &[u8],
    psk: &HandoffPsk,
    landing_secret: &StaticSecret,
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

    let ephemeral_public = PublicKey::from(header.ephemeral_public);
    let shared = landing_secret.diffie_hellman(&ephemeral_public);
    if !shared.was_contributory() {
        return Err(HandoffError::Authentication);
    }
    let landing_public = PublicKey::from(landing_secret);
    let (key, aead_nonce) = derive_aead(
        &header.raw,
        shared.as_bytes(),
        psk,
        landing_public.as_bytes(),
    )?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| HandoffError::Crypto)?;
    let nonce_bytes: Nonce<ChaCha20Poly1305> = Array(*aead_nonce);

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
    let mut blob = Zeroizing::new(Vec::new());
    blob.try_reserve_exact(header.blob_len)
        .map_err(|_| HandoffError::Allocation)?;
    blob.extend_from_slice(body);
    let tag: Tag<ChaCha20Poly1305> = Array(*tag_bytes);
    cipher
        .decrypt_inout_detached(&nonce_bytes, header_bytes, blob.as_mut_slice().into(), &tag)
        .map_err(|_| HandoffError::Authentication)?;

    let state = decode_blob(&blob)?;
    if state.server_sequence() != 0 || state.user_id() != &header.user_id {
        return Err(HandoffError::State);
    }
    Ok(OpenedTransfer {
        timestamp: header.timestamp,
        nonce: header.nonce,
        client_random: header.client_random,
        state,
    })
}

struct TransferHeader {
    raw: [u8; HEADER_LEN],
    timestamp: u64,
    nonce: [u8; NONCE_LEN],
    ephemeral_public: [u8; X25519_PUBLIC_LEN],
    client_random: [u8; 32],
    user_id: [u8; USER_ID_LEN],
    blob_len: usize,
}

fn parse_header(header: &[u8]) -> Result<TransferHeader, HandoffError> {
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

fn read_array<const N: usize>(
    raw: &[u8; HEADER_LEN],
    offset: usize,
) -> Result<[u8; N], HandoffError> {
    raw.get(offset..offset + N)
        .ok_or(HandoffError::Length)?
        .try_into()
        .map_err(|_| HandoffError::Length)
}

fn encode_header(
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

/// The derived per-transfer AEAD key and nonce, both zeroized on drop.
type DerivedAead = (Zeroizing<[u8; 32]>, Zeroizing<[u8; AEAD_NONCE_LEN]>);

/// HKDF-Extract(salt = label || E_pub || S_pub, ikm = shared || PSK), then
/// HKDF-Expand over the transcript (fixed header through `user_id`, with
/// S_pub spliced in after E_pub; `blob_len` is covered by the AEAD AD).
fn derive_aead(
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

fn encode_blob(state: &ContinuationState, output: &mut Vec<u8>) -> Result<(), HandoffError> {
    let address_length = bounded_address_length(state.destination())?;
    let total = 1_usize
        .checked_add(2)
        .and_then(|length| length.checked_add(2 * (1 + 32 + 12)))
        .and_then(|length| length.checked_add(2 * 8))
        .and_then(|length| length.checked_add(USER_ID_LEN))
        .and_then(|length| length.checked_add(1 + 2 + address_length + 2))
        .and_then(|length| length.checked_add(4 + state.pending_ciphertext().len()))
        .and_then(|length| length.checked_add(4 + state.prefetched_plaintext().len()))
        .filter(|length| *length <= MAX_BLOB_LEN)
        .ok_or(HandoffError::Length)?;
    output.clear();
    output
        .try_reserve_exact(total)
        .map_err(|_| HandoffError::Allocation)?;
    output.push(CONTINUATION_STATE_VERSION);
    output.extend_from_slice(&state.suite().wire_value().to_be_bytes());
    encode_traffic_keys(state.client_traffic(), output);
    encode_traffic_keys(state.server_traffic(), output);
    output.extend_from_slice(&state.client_sequence().to_be_bytes());
    output.extend_from_slice(&state.server_sequence().to_be_bytes());
    output.extend_from_slice(state.user_id());
    encode_address(state.destination(), output);
    output.extend_from_slice(&state.destination().port().to_be_bytes());
    encode_bounded_bytes(state.pending_ciphertext(), output);
    encode_bounded_bytes(state.prefetched_plaintext(), output);
    Ok(())
}

fn encode_address(destination: &Destination, output: &mut Vec<u8>) {
    match destination.address() {
        Address::Ipv4(address) => {
            output.push(ADDRESS_IPV4);
            output.extend_from_slice(&4_u16.to_be_bytes());
            output.extend_from_slice(&address.octets());
        }
        Address::Domain(domain) => {
            output.push(ADDRESS_DOMAIN);
            let length = u16::try_from(domain.len()).unwrap_or(0);
            output.extend_from_slice(&length.to_be_bytes());
            output.extend_from_slice(domain.as_bytes());
        }
        Address::Ipv6(address) => {
            output.push(ADDRESS_IPV6);
            output.extend_from_slice(&16_u16.to_be_bytes());
            output.extend_from_slice(&address.octets());
        }
    }
}

fn encode_traffic_keys(keys: &TrafficKeys, output: &mut Vec<u8>) {
    output.push(u8::try_from(keys.key().len()).unwrap_or(0));
    output.extend_from_slice(keys.key());
    output.extend_from_slice(keys.iv());
}

fn encode_bounded_bytes(bytes: &[u8], output: &mut Vec<u8>) {
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
}

fn decode_blob(blob: &[u8]) -> Result<ContinuationState, HandoffError> {
    let mut cursor = BlobCursor::new(blob);
    if cursor.u8()? != CONTINUATION_STATE_VERSION {
        return Err(HandoffError::State);
    }
    let suite = CipherSuite::from_wire(cursor.u16()?).ok_or(HandoffError::State)?;
    let client_traffic = decode_traffic_keys(&mut cursor)?;
    let server_traffic = decode_traffic_keys(&mut cursor)?;
    let client_sequence = cursor.u64()?;
    let server_sequence = cursor.u64()?;
    let user_id: [u8; USER_ID_LEN] = cursor
        .take(USER_ID_LEN)?
        .try_into()
        .map_err(|_| HandoffError::State)?;
    let destination = decode_destination(&mut cursor)?;
    let pending_ciphertext = decode_bounded_bytes(&mut cursor, MAX_PENDING_CIPHERTEXT_LEN)?;
    let prefetched_plaintext = decode_bounded_bytes(&mut cursor, MAX_PREFETCHED_PLAINTEXT_LEN)?;
    if cursor.remaining() != 0 {
        return Err(HandoffError::State);
    }
    ContinuationState::new(
        suite,
        client_traffic,
        client_sequence,
        server_traffic,
        server_sequence,
        user_id,
        destination,
        pending_ciphertext,
        prefetched_plaintext,
    )
}

fn decode_traffic_keys(cursor: &mut BlobCursor<'_>) -> Result<TrafficKeys, HandoffError> {
    let key_len = usize::from(cursor.u8()?);
    let key = cursor.take(key_len)?;
    let iv: [u8; 12] = cursor
        .take(12)?
        .try_into()
        .map_err(|_| HandoffError::State)?;
    TrafficKeys::from_raw_parts(key, iv).map_err(|_| HandoffError::State)
}

fn decode_destination(cursor: &mut BlobCursor<'_>) -> Result<Destination, HandoffError> {
    let address_type = cursor.u8()?;
    let address_len = usize::from(cursor.u16()?);
    let address = cursor.take(address_len)?;
    let parsed = match address_type {
        ADDRESS_IPV4 => {
            let bytes: [u8; 4] = address.try_into().map_err(|_| HandoffError::State)?;
            Address::Ipv4(Ipv4Addr::from(bytes))
        }
        ADDRESS_DOMAIN => {
            if address.is_empty() || address.len() > MAX_DOMAIN_LEN {
                return Err(HandoffError::State);
            }
            Address::Domain(
                std::str::from_utf8(address)
                    .map(str::to_owned)
                    .map_err(|_| HandoffError::State)?,
            )
        }
        ADDRESS_IPV6 => {
            let bytes: [u8; 16] = address.try_into().map_err(|_| HandoffError::State)?;
            Address::Ipv6(Ipv6Addr::from(bytes))
        }
        _ => return Err(HandoffError::State),
    };
    let port = cursor.u16()?;
    if port == 0 {
        return Err(HandoffError::State);
    }
    Ok(Destination::new(parsed, port))
}

fn decode_bounded_bytes(cursor: &mut BlobCursor<'_>, cap: usize) -> Result<Vec<u8>, HandoffError> {
    let length = usize::try_from(cursor.u32()?).map_err(|_| HandoffError::State)?;
    if length > cap {
        return Err(HandoffError::State);
    }
    let bytes = cursor.take(length)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| HandoffError::Allocation)?;
    output.extend_from_slice(bytes);
    Ok(output)
}

fn bounded_address_length(destination: &Destination) -> Result<usize, HandoffError> {
    match destination.address() {
        Address::Ipv4(_) => Ok(4),
        Address::Domain(domain) => {
            if domain.is_empty() || domain.len() > MAX_DOMAIN_LEN {
                return Err(HandoffError::State);
            }
            Ok(domain.len())
        }
        Address::Ipv6(_) => Ok(16),
    }
}

struct BlobCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BlobCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], HandoffError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(HandoffError::State)?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(HandoffError::State)?;
        self.position = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, HandoffError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, HandoffError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| HandoffError::State)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, HandoffError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| HandoffError::State)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, HandoffError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| HandoffError::State)?,
        ))
    }
}

/// Handoff transfer construction or verification failed.
///
/// This is the entire error vocabulary a LANDING handler may log; no variant
/// carries detail beyond the failure class, and nothing is ever written back
/// to the control connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffError {
    /// The message or blob length is outside the fixed bounds.
    Length,
    /// The magic, protocol version, or state version is unsupported.
    Version,
    /// The timestamp is outside the accepted clock window.
    TimeWindow,
    /// The transfer nonce was already seen or the replay cache is full.
    Replay,
    /// The ephemeral key agreement or AEAD authentication failed.
    Authentication,
    /// A decrypted continuation field failed a consistency check.
    State,
    /// A bounded buffer reservation failed.
    Allocation,
    /// Secure ephemeral randomness was unavailable.
    Random,
    /// A mature cryptographic primitive rejected an invariant.
    Crypto,
}

impl fmt::Display for HandoffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length => formatter.write_str("handoff transfer length is invalid"),
            Self::Version => formatter.write_str("handoff transfer version is unsupported"),
            Self::TimeWindow => formatter.write_str("handoff transfer timestamp is outside policy"),
            Self::Replay => formatter.write_str("handoff transfer nonce was rejected"),
            Self::Authentication => formatter.write_str("handoff transfer authentication failed"),
            Self::State => formatter.write_str("handoff continuation state is invalid"),
            Self::Allocation => formatter.write_str("handoff transfer allocation failed"),
            Self::Random => formatter.write_str("handoff randomness is unavailable"),
            Self::Crypto => formatter.write_str("handoff cryptographic primitive failed"),
        }
    }
}

impl Error for HandoffError {}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use x25519_dalek::{PublicKey, StaticSecret};

    use super::{
        CONTINUATION_STATE_VERSION, ContinuationState, HANDOFF_PROTOCOL_VERSION, HEADER_LEN,
        HandoffError, HandoffPsk, HandoffReplayCache, MAX_BLOB_LEN, MAX_MESSAGE_LEN,
        MAX_PENDING_CIPHERTEXT_LEN, MAX_PREFETCHED_PLAINTEXT_LEN, message_len_from_header,
        open_transfer, seal_transfer,
    };
    use crate::protocol::reality::tls13::{CipherSuite, TrafficKeys};
    use crate::protocol::vless::{Address, Destination};

    const NOW: u64 = 1_700_000_000;
    const WINDOW: u64 = 30;

    fn landing_key_pair(seed: u8) -> (StaticSecret, PublicKey) {
        let secret = StaticSecret::from([seed; 32]);
        let public = PublicKey::from(&secret);
        (secret, public)
    }

    fn test_state(pending: Vec<u8>, prefetched: Vec<u8>) -> ContinuationState {
        ContinuationState::new(
            CipherSuite::ChaCha20Poly1305Sha256,
            TrafficKeys::from_raw_parts(&[0x11; 32], [0x21; 12]).expect("client keys"),
            0x0102_0304_0506_0708,
            TrafficKeys::from_raw_parts(&[0x12; 32], [0x22; 12]).expect("server keys"),
            0,
            [0x33; 16],
            Destination::new(Address::Domain("example.com".to_owned()), 443),
            pending,
            prefetched,
        )
        .expect("test state must be valid")
    }

    fn test_cache() -> HandoffReplayCache {
        HandoffReplayCache::new(1_024, Duration::from_secs(120)).expect("test cache")
    }

    fn seal(state: &ContinuationState, psk: &HandoffPsk, public: &PublicKey) -> Vec<u8> {
        let mut message = Vec::new();
        seal_transfer(state, psk, public, [0x44; 32], NOW, &mut message)
            .expect("test state must seal");
        message
    }

    fn open_error(
        message: &[u8],
        psk: &HandoffPsk,
        secret: &StaticSecret,
        cache: &HandoffReplayCache,
        now: u64,
    ) -> HandoffError {
        open_transfer(message, psk, secret, cache, now, WINDOW)
            .map(|_| ())
            .expect_err("transfer must fail closed")
    }

    fn assert_states_equal(opened: &ContinuationState, expected: &ContinuationState) {
        assert_eq!(opened.suite(), expected.suite());
        assert_eq!(opened.client_traffic(), expected.client_traffic());
        assert_eq!(opened.server_traffic(), expected.server_traffic());
        assert_eq!(opened.client_sequence(), expected.client_sequence());
        assert_eq!(opened.server_sequence(), expected.server_sequence());
        assert_eq!(opened.user_id(), expected.user_id());
        assert_eq!(opened.destination(), expected.destination());
        assert_eq!(opened.pending_ciphertext(), expected.pending_ciphertext());
        assert_eq!(
            opened.prefetched_plaintext(),
            expected.prefetched_plaintext()
        );
    }

    #[test]
    fn sealed_transfer_round_trips_through_landing_open() {
        let (landing_secret, landing_public) = landing_key_pair(0x77);
        let psk = HandoffPsk::new([0x55; 32]);
        let state = test_state(b"read-ahead".to_vec(), b"prefetched".to_vec());
        let message = seal(&state, &psk, &landing_public);
        assert!(message.len() < 2 * 1_024);
        assert_eq!(
            message_len_from_header(&message[..HEADER_LEN]).expect("header must parse"),
            message.len()
        );

        let opened = open_transfer(&message, &psk, &landing_secret, &test_cache(), NOW, WINDOW)
            .expect("valid transfer must open");
        assert_eq!(opened.timestamp(), NOW);
        assert_eq!(opened.client_random(), &[0x44; 32]);
        assert_states_equal(opened.state(), &state);
    }

    #[test]
    fn empty_and_maximum_pending_buffers_round_trip() {
        let (landing_secret, landing_public) = landing_key_pair(0x78);
        let psk = HandoffPsk::new([0x56; 32]);
        for (pending, prefetched) in [
            (Vec::new(), Vec::new()),
            (
                vec![0xab; MAX_PENDING_CIPHERTEXT_LEN],
                vec![0xcd; MAX_PREFETCHED_PLAINTEXT_LEN],
            ),
        ] {
            let state = test_state(pending, prefetched);
            let message = seal(&state, &psk, &landing_public);
            assert!(message.len() <= MAX_MESSAGE_LEN);
            let opened = open_transfer(&message, &psk, &landing_secret, &test_cache(), NOW, WINDOW)
                .expect("bounded transfer must open");
            assert_states_equal(opened.state(), &state);
        }
    }

    #[test]
    fn wrong_psk_and_wrong_static_key_fail_authentication() {
        let (_, landing_public) = landing_key_pair(0x79);
        let (other_secret, _) = landing_key_pair(0x7a);
        let psk = HandoffPsk::new([0x55; 32]);
        let state = test_state(Vec::new(), Vec::new());
        let message = seal(&state, &psk, &landing_public);

        let (landing_secret, _) = landing_key_pair(0x79);
        assert_eq!(
            open_error(
                &message,
                &HandoffPsk::new([0x56; 32]),
                &landing_secret,
                &test_cache(),
                NOW,
            ),
            HandoffError::Authentication
        );
        assert_eq!(
            open_error(&message, &psk, &other_secret, &test_cache(), NOW),
            HandoffError::Authentication
        );
    }

    #[test]
    fn mutated_header_byte_fails_aead() {
        let (landing_secret, landing_public) = landing_key_pair(0x7b);
        let psk = HandoffPsk::new([0x55; 32]);
        let state = test_state(Vec::new(), Vec::new());
        let message = seal(&state, &psk, &landing_public);

        // A client_random byte: structure, timestamp, and nonce are untouched,
        // so the failure must come from the AEAD AD check.
        let mut tampered = message;
        tampered[62] ^= 1;
        assert_eq!(
            open_error(&tampered, &psk, &landing_secret, &test_cache(), NOW),
            HandoffError::Authentication
        );
    }

    #[test]
    fn replayed_nonce_is_rejected_before_any_dh_work() {
        let (landing_secret, landing_public) = landing_key_pair(0x7c);
        let (other_secret, _) = landing_key_pair(0x7d);
        let psk = HandoffPsk::new([0x55; 32]);
        let state = test_state(Vec::new(), Vec::new());
        let message = seal(&state, &psk, &landing_public);
        let cache = test_cache();

        open_transfer(&message, &psk, &landing_secret, &cache, NOW, WINDOW)
            .expect("first delivery must open");
        assert_eq!(cache.entry_count(), 1);
        // Even with the WRONG static key the replay check fires first,
        // proving the rejection happens before the DH.
        assert_eq!(
            open_error(&message, &psk, &other_secret, &cache, NOW),
            HandoffError::Replay
        );
        assert_eq!(
            open_error(&message, &psk, &landing_secret, &cache, NOW),
            HandoffError::Replay
        );
    }

    #[test]
    fn expired_and_future_timestamps_are_rejected() {
        let (landing_secret, landing_public) = landing_key_pair(0x7e);
        let psk = HandoffPsk::new([0x55; 32]);
        let state = test_state(Vec::new(), Vec::new());
        let message = seal(&state, &psk, &landing_public);

        for skewed_now in [NOW + WINDOW + 1, NOW - WINDOW - 1] {
            assert_eq!(
                open_error(&message, &psk, &landing_secret, &test_cache(), skewed_now),
                HandoffError::TimeWindow
            );
        }
        // Boundary values inside the window still authenticate.
        open_transfer(
            &message,
            &psk,
            &landing_secret,
            &test_cache(),
            NOW + WINDOW,
            WINDOW,
        )
        .expect("window boundary must open");
    }

    #[test]
    fn version_mismatches_fail_closed() {
        let (landing_secret, landing_public) = landing_key_pair(0x7f);
        let psk = HandoffPsk::new([0x55; 32]);
        let state = test_state(Vec::new(), Vec::new());
        let message = seal(&state, &psk, &landing_public);

        for offset in [4_usize, 5] {
            let mut tampered = message.clone();
            tampered[offset] = tampered[offset].wrapping_add(1);
            assert_eq!(
                open_error(&tampered, &psk, &landing_secret, &test_cache(), NOW),
                HandoffError::Version
            );
            assert_eq!(
                message_len_from_header(&tampered[..HEADER_LEN]),
                Err(HandoffError::Version)
            );
        }
        assert_eq!(HANDOFF_PROTOCOL_VERSION, 1);
        assert_eq!(CONTINUATION_STATE_VERSION, 1);
    }

    #[test]
    fn low_order_ephemeral_public_keys_are_rejected() {
        let (landing_secret, landing_public) = landing_key_pair(0x80);
        let psk = HandoffPsk::new([0x55; 32]);
        let state = test_state(Vec::new(), Vec::new());
        let message = seal(&state, &psk, &landing_public);

        for low_order in [[0_u8; 32], [1_u8; 32]] {
            let mut crafted = message.clone();
            crafted[30..62].copy_from_slice(&low_order);
            assert_eq!(
                open_error(&crafted, &psk, &landing_secret, &test_cache(), NOW),
                HandoffError::Authentication
            );
        }
    }

    #[test]
    fn blob_len_above_cap_is_rejected_before_allocation() {
        let (landing_secret, landing_public) = landing_key_pair(0x81);
        let psk = HandoffPsk::new([0x55; 32]);
        let state = test_state(Vec::new(), Vec::new());
        let message = seal(&state, &psk, &landing_public);

        let mut tampered = message;
        let over_cap = u32::try_from(MAX_BLOB_LEN + 1).expect("cap fits u32");
        tampered[110..114].copy_from_slice(&over_cap.to_be_bytes());
        assert_eq!(
            message_len_from_header(&tampered[..HEADER_LEN]),
            Err(HandoffError::Length)
        );
        assert_eq!(
            open_error(&tampered, &psk, &landing_secret, &test_cache(), NOW),
            HandoffError::Length
        );
    }

    #[test]
    fn nonzero_server_sequence_fails_the_cross_check() {
        let (landing_secret, landing_public) = landing_key_pair(0x82);
        let psk = HandoffPsk::new([0x55; 32]);
        let mut state = test_state(Vec::new(), Vec::new());
        state = ContinuationState::new(
            state.suite(),
            TrafficKeys::from_raw_parts(&[0x11; 32], [0x21; 12]).expect("client keys"),
            state.client_sequence(),
            TrafficKeys::from_raw_parts(&[0x12; 32], [0x22; 12]).expect("server keys"),
            1,
            *state.user_id(),
            state.destination().clone(),
            Vec::new(),
            Vec::new(),
        )
        .expect("state with a used server direction must build");
        let message = seal(&state, &psk, &landing_public);
        assert_eq!(
            open_error(&message, &psk, &landing_secret, &test_cache(), NOW),
            HandoffError::State
        );
    }

    #[test]
    fn oversized_pending_buffers_are_rejected_at_construction() {
        let pending = vec![0; MAX_PENDING_CIPHERTEXT_LEN + 1];
        let oversized = ContinuationState::new(
            CipherSuite::Aes128GcmSha256,
            TrafficKeys::from_raw_parts(&[0x11; 16], [0x21; 12]).expect("client keys"),
            0,
            TrafficKeys::from_raw_parts(&[0x12; 16], [0x22; 12]).expect("server keys"),
            0,
            [0x33; 16],
            Destination::new(Address::Ipv4(std::net::Ipv4Addr::LOCALHOST), 443),
            pending,
            Vec::new(),
        );
        assert_eq!(
            oversized.unwrap_err(),
            HandoffError::State,
            "oversized pending buffer must be rejected"
        );
        // Suite/key-length disagreement is rejected too.
        let mismatched = ContinuationState::new(
            CipherSuite::Aes128GcmSha256,
            TrafficKeys::from_raw_parts(&[0x11; 32], [0x21; 12]).expect("client keys"),
            0,
            TrafficKeys::from_raw_parts(&[0x12; 16], [0x22; 12]).expect("server keys"),
            0,
            [0x33; 16],
            Destination::new(Address::Ipv4(std::net::Ipv4Addr::LOCALHOST), 443),
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(
            mismatched.unwrap_err(),
            HandoffError::State,
            "suite/key-length disagreement must be rejected"
        );
    }

    #[test]
    fn truncated_and_trailing_messages_are_rejected() {
        let (landing_secret, landing_public) = landing_key_pair(0x83);
        let psk = HandoffPsk::new([0x55; 32]);
        let state = test_state(b"pending".to_vec(), Vec::new());
        let message = seal(&state, &psk, &landing_public);

        let truncated = &message[..message.len() - 1];
        assert_eq!(
            open_error(truncated, &psk, &landing_secret, &test_cache(), NOW),
            HandoffError::Length
        );
        let mut extended = message.clone();
        extended.push(0);
        assert_eq!(
            open_error(&extended, &psk, &landing_secret, &test_cache(), NOW),
            HandoffError::Length
        );
    }

    #[test]
    fn debug_output_is_redacted() {
        let psk = HandoffPsk::new([0x55; 32]);
        assert_eq!(format!("{psk:?}"), "HandoffPsk([REDACTED])");
        let state = test_state(b"pending".to_vec(), Vec::new());
        let rendered = format!("{state:?}");
        assert!(!rendered.contains("0x11"));
        assert!(!rendered.contains("user_id"));
        assert!(rendered.contains("ContinuationState"));
    }
}
