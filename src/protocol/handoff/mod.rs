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

use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap},
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
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::reality::tls13::{CipherSuite, ExportedRecordState, ExportedTlsState, TrafficSecret};
use super::vless::{Address, Destination};
use crate::crypto::{EphemeralX25519Key, StaticX25519Key};

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

/// Maximum sealed policy-snapshot payload (ADR 0060 Option B foundation).
pub const MAX_POLICY_SNAPSHOT_LEN: usize = 1024;

/// Maximum first-match sealed route rules inside one policy snapshot.
pub const MAX_SEALED_HANDOFF_RULES: usize = 32;

/// Policy snapshot format version inside the continuation blob.
///
/// - Version 1: initial destination + `allow_destination_rewrites` flag only
///   (PR4). Decoded as rewrite-disabled / empty rule list.
/// - Version 2: ordered sealable route rules + default-outbound allow bit (PR5).
pub const HANDOFF_POLICY_SNAPSHOT_VERSION: u8 = 2;

/// Legacy PR4 policy snapshot version (still accepted on decode).
pub const HANDOFF_POLICY_SNAPSHOT_VERSION_V1: u8 = 1;

/// Vision session kind transferred with the TLS continuation (ADR 0060).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SessionKind {
    /// Ordinary Vision TCP relay after LANDING resume.
    Tcp = 0,
    /// Vision XUDP (Mux); LANDING owns TLS decrypt and UDP sockets.
    Xudp = 1,
}

impl SessionKind {
    #[must_use]
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Tcp),
            1 => Some(Self::Xudp),
            _ => None,
        }
    }

    #[must_use]
    pub const fn wire(self) -> u8 {
        self as u8
    }
}

/// Sealable domain matcher (no geosite / regex / external assets).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SealedDomainMatcher {
    /// `full:example.com`
    Full(String),
    /// `domain:example.com` / bare suffix
    Suffix(String),
    /// `keyword:foo`
    Keyword(String),
}

impl SealedDomainMatcher {
    fn matches(&self, domain: &str) -> bool {
        let domain = domain.to_ascii_lowercase();
        match self {
            Self::Full(value) => domain == value.as_str(),
            Self::Suffix(value) => {
                domain == value.as_str()
                    || (domain.len() > value.len()
                        && domain.ends_with(value.as_str())
                        && domain.as_bytes()[domain.len() - value.len() - 1] == b'.')
            }
            Self::Keyword(value) => {
                value.is_empty()
                    || domain
                        .as_bytes()
                        .windows(value.len())
                        .any(|window| window == value.as_bytes())
            }
        }
    }
}

/// Sealable IPv4/IPv6 network (no geoip / external assets).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealedIpNetwork {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl SealedIpNetwork {
    #[must_use]
    pub fn contains(self, address: std::net::IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { network, prefix }, std::net::IpAddr::V4(addr)) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                (u32::from(addr) & mask) == (network & mask)
            }
            (Self::V6 { network, prefix }, std::net::IpAddr::V6(addr)) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                (u128::from(addr) & mask) == (network & mask)
            }
            _ => false,
        }
    }
}

/// Inclusive destination port range sealed into a Handoff policy rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedPortRange {
    pub start: u16,
    pub end: u16,
}

impl SealedPortRange {
    #[must_use]
    pub const fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

/// One first-match sealed rule mirroring LINE routing for this Handoff outbound.
///
/// Empty domain / IP / port groups mean "match any" for that group (AND across
/// groups), matching [`crate::server::routing`] semantics for sealable rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedHandoffRouteRule {
    /// `true` when the matched outbound is the Handoff egress used for transfer.
    pub allow: bool,
    pub domains: Vec<SealedDomainMatcher>,
    pub ips: Vec<SealedIpNetwork>,
    pub ports: Vec<SealedPortRange>,
}

impl SealedHandoffRouteRule {
    fn matches(&self, destination: &Destination) -> bool {
        let port_ok = self.ports.is_empty()
            || self
                .ports
                .iter()
                .any(|range| range.contains(destination.port()));
        if !port_ok {
            return false;
        }
        let domain_ok = if self.domains.is_empty() {
            true
        } else {
            match destination.address() {
                Address::Domain(domain) => self.domains.iter().any(|m| m.matches(domain)),
                Address::Ipv4(_) | Address::Ipv6(_) => false,
            }
        };
        if !domain_ok {
            return false;
        }
        if self.ips.is_empty() {
            true
        } else {
            match destination.address() {
                Address::Ipv4(addr) => self
                    .ips
                    .iter()
                    .any(|net| net.contains(std::net::IpAddr::V4(*addr))),
                Address::Ipv6(addr) => self
                    .ips
                    .iter()
                    .any(|net| net.contains(std::net::IpAddr::V6(*addr))),
                Address::Domain(_) => false,
            }
        }
    }
}

/// Session-bound UDP authorization sealed at Handoff transfer (ADR 0060 Option B).
///
/// PR5: LANDING evaluates Keep destination rewrites against ordered sealable
/// route rules compiled on LINE at transfer time. Non-sealable matchers
/// (geosite/geoip/regexp/ext) force rewrite-disabled fail-closed snapshots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffPolicySnapshot {
    initial_destination: Destination,
    allow_destination_rewrites: bool,
    /// First-match sealed rules (global then user), then [`Self::default_allow`].
    rules: Vec<SealedHandoffRouteRule>,
    /// Whether the user's default outbound is this Handoff egress.
    default_allow: bool,
}

impl HandoffPolicySnapshot {
    #[must_use]
    pub fn tcp_placeholder(destination: Destination) -> Self {
        Self {
            initial_destination: destination,
            allow_destination_rewrites: false,
            rules: Vec::new(),
            default_allow: false,
        }
    }

    /// Initial-destination-only XUDP policy (rewrites fail closed).
    #[must_use]
    pub fn xudp_initial(destination: Destination) -> Self {
        Self {
            initial_destination: destination,
            allow_destination_rewrites: false,
            rules: Vec::new(),
            default_allow: false,
        }
    }

    /// Multi-destination XUDP policy with ordered sealed rules (PR5).
    #[must_use]
    pub fn xudp_with_sealed_rules(
        destination: Destination,
        rules: Vec<SealedHandoffRouteRule>,
        default_allow: bool,
    ) -> Self {
        let allow_destination_rewrites = default_allow || rules.iter().any(|rule| rule.allow);
        Self {
            initial_destination: destination,
            allow_destination_rewrites,
            rules,
            default_allow,
        }
    }

    #[must_use]
    pub const fn initial_destination(&self) -> &Destination {
        &self.initial_destination
    }

    #[must_use]
    pub const fn allow_destination_rewrites(&self) -> bool {
        self.allow_destination_rewrites
    }

    #[must_use]
    pub fn sealed_rules(&self) -> &[SealedHandoffRouteRule] {
        &self.rules
    }

    #[must_use]
    pub const fn default_allow(&self) -> bool {
        self.default_allow
    }

    /// Authorize one XUDP New/Keep destination against this snapshot.
    ///
    /// # Errors
    ///
    /// Deny when the destination differs from the sealed initial target and
    /// either rewrites are disabled or no sealed rule / default allows it.
    pub fn authorize_udp_destination(&self, destination: &Destination) -> Result<(), HandoffError> {
        if destination == &self.initial_destination {
            return Ok(());
        }
        if !self.allow_destination_rewrites {
            return Err(HandoffError::State);
        }
        for rule in &self.rules {
            if rule.matches(destination) {
                return if rule.allow {
                    Ok(())
                } else {
                    Err(HandoffError::State)
                };
            }
        }
        if self.default_allow {
            Ok(())
        } else {
            Err(HandoffError::State)
        }
    }
}

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

/// At the handoff boundary the server direction is either untouched, or has
/// emitted exactly one empty application-data record while matching the cover
/// target's post-handshake shape. Larger values cannot arise before LINE
/// transfers ownership and therefore fail closed.
const MAX_SERVER_SEQUENCE_AT_HANDOFF: u64 = 1;

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

/// Maximum retired keys of each kind a landing accepts during a rotation
/// window. The candidate space is bounded at (1 + 2) PSKs times (1 + 2)
/// static secrets — nine trials worst case, all after the one nonce reserve.
pub const MAX_PREVIOUS_KEYS: usize = 2;

/// The key material one Handoff landing listener accepts, in trial order.
///
/// The active pair always comes first; retired keys configured for a bounded
/// zero-downtime rotation window follow. Senders always seal with the active
/// pair only, so previous keys never change the wire format — they only widen
/// what the landing will open while line nodes move to the new key material.
/// `Debug` never reveals key bytes. Secrets are shared behind `Arc` rather
/// than cloned: `Clone` exists so one compiled handler can fan out across
/// connections, and copying key material to satisfy that derive would widen
/// the zeroization high-water mark for no requirement.
#[derive(Clone)]
pub struct HandoffLandingKeys {
    active_psk: HandoffPsk,
    previous_psks: Vec<HandoffPsk>,
    active_secret: Arc<StaticX25519Key>,
    previous_secrets: Vec<Arc<StaticX25519Key>>,
}

impl HandoffLandingKeys {
    /// A landing that accepts exactly one active key pair — the steady state
    /// outside any rotation window.
    #[must_use]
    pub fn single(active_psk: HandoffPsk, active_secret: StaticX25519Key) -> Self {
        Self {
            active_psk,
            previous_psks: Vec::new(),
            active_secret: Arc::new(active_secret),
            previous_secrets: Vec::new(),
        }
    }

    /// A landing inside a rotation window, still accepting retired keys.
    ///
    /// Each retired list is bounded at [`MAX_PREVIOUS_KEYS`]; configuration
    /// validation enforces the same bound before this constructor runs.
    /// Returns `None` when either retired list exceeds the bound — an
    /// unbounded candidate space would multiply the per-message trial work.
    pub fn with_previous(
        active_psk: HandoffPsk,
        previous_psks: Vec<HandoffPsk>,
        active_secret: StaticX25519Key,
        previous_secrets: Vec<StaticX25519Key>,
    ) -> Option<Self> {
        if previous_psks.len() > MAX_PREVIOUS_KEYS || previous_secrets.len() > MAX_PREVIOUS_KEYS {
            return None;
        }
        Some(Self {
            active_psk,
            previous_psks,
            active_secret: Arc::new(active_secret),
            previous_secrets: previous_secrets.into_iter().map(Arc::new).collect(),
        })
    }

    /// Every candidate pair this landing opens with, active pair first.
    ///
    /// The candidate space is deliberately the full cross product of
    /// {active, previous...} PSKs x {active, previous...} static secrets:
    /// the pair PSK and the static key rotate on independent schedules, and
    /// restricting trials to pairwise-aligned slots would break a rotation
    /// where one list moved and the other has not. The bound is 3 x 3 by
    /// [`MAX_PREVIOUS_KEYS`], and every entry is tried only after the single
    /// hoisted nonce reserve.
    fn candidates(&self) -> impl Iterator<Item = (&HandoffPsk, &StaticX25519Key)> {
        std::iter::once(&self.active_psk)
            .chain(&self.previous_psks)
            .flat_map(|psk| {
                std::iter::once(&self.active_secret)
                    .chain(&self.previous_secrets)
                    .map(move |secret| (psk, Arc::as_ref(secret)))
            })
    }

    /// Whether any retired key material is still accepted (window open).
    #[must_use]
    pub fn rotation_window_open(&self) -> bool {
        !self.previous_psks.is_empty() || !self.previous_secrets.is_empty()
    }
}

impl fmt::Debug for HandoffLandingKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandoffLandingKeys")
            .field("key_material", &"[REDACTED]")
            .field("previous_psks", &self.previous_psks.len())
            .field("previous_secrets", &self.previous_secrets.len())
            .finish()
    }
}

/// The full surviving session state carried inside the sealed blob.
///
/// Fields are encoded explicitly (no serde, no memory layout); the two
/// variable-length byte strings are bounded by
/// `MAX_PENDING_CIPHERTEXT_LEN` and `MAX_PREFETCHED_PLAINTEXT_LEN`. Current
/// traffic secrets and buffered plaintext are zeroized on drop; `Debug` is
/// redacted.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ContinuationState {
    #[zeroize(skip)]
    suite: CipherSuite,
    client_traffic_secret: TrafficSecret,
    server_traffic_secret: TrafficSecret,
    #[zeroize(skip)]
    client_sequence: u64,
    #[zeroize(skip)]
    server_sequence: u64,
    #[zeroize(skip)]
    key_update_response_pending: bool,
    #[zeroize(skip)]
    session_kind: SessionKind,
    user_id: [u8; USER_ID_LEN],
    #[zeroize(skip)]
    inbound_tag: String,
    #[zeroize(skip)]
    destination: Destination,
    pending_ciphertext: Vec<u8>,
    prefetched_plaintext: Vec<u8>,
    #[zeroize(skip)]
    policy: HandoffPolicySnapshot,
}

/// The move-only parts needed to install one verified continuation.
pub type ContinuationParts = (
    ExportedTlsState,
    [u8; USER_ID_LEN],
    Destination,
    Vec<u8>,
    Vec<u8>,
    bool,
    SessionKind,
    String,
    HandoffPolicySnapshot,
);

impl ContinuationState {
    /// Assembles one continuation state, enforcing every field bound.
    ///
    /// # Errors
    ///
    /// Rejects traffic secrets whose hash disagrees with the suite and pending
    /// buffers above their caps.
    #[allow(clippy::too_many_arguments, reason = "one parameter per blob field")]
    pub fn new(
        suite: CipherSuite,
        client_traffic_secret: TrafficSecret,
        client_sequence: u64,
        server_traffic_secret: TrafficSecret,
        server_sequence: u64,
        key_update_response_pending: bool,
        session_kind: SessionKind,
        user_id: [u8; USER_ID_LEN],
        inbound_tag: impl Into<String>,
        destination: Destination,
        pending_ciphertext: Vec<u8>,
        prefetched_plaintext: Vec<u8>,
        policy: HandoffPolicySnapshot,
    ) -> Result<Self, HandoffError> {
        if client_traffic_secret.algorithm() != suite.hash()
            || server_traffic_secret.algorithm() != suite.hash()
        {
            return Err(HandoffError::State);
        }
        let inbound_tag = inbound_tag.into();
        if inbound_tag.len() > MAX_INBOUND_TAG_LEN
            || pending_ciphertext.len() > MAX_PENDING_CIPHERTEXT_LEN
            || prefetched_plaintext.len() > MAX_PREFETCHED_PLAINTEXT_LEN
        {
            return Err(HandoffError::State);
        }
        if !inbound_tag.is_ascii() {
            return Err(HandoffError::State);
        }
        Ok(Self {
            suite,
            client_traffic_secret,
            server_traffic_secret,
            client_sequence,
            server_sequence,
            key_update_response_pending,
            session_kind,
            user_id,
            inbound_tag,
            destination,
            pending_ciphertext,
            prefetched_plaintext,
            policy,
        })
    }

    /// Returns the negotiated cipher suite.
    #[must_use]
    pub const fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// Returns the client-direction current traffic secret.
    #[must_use]
    pub const fn client_traffic_secret(&self) -> &TrafficSecret {
        &self.client_traffic_secret
    }

    /// Returns the server-direction current traffic secret.
    #[must_use]
    pub const fn server_traffic_secret(&self) -> &TrafficSecret {
        &self.server_traffic_secret
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

    /// Returns whether the writer owes its peer a KeyUpdate response.
    #[must_use]
    pub const fn key_update_response_pending(&self) -> bool {
        self.key_update_response_pending
    }

    /// Returns whether this continuation resumes TCP Vision or XUDP.
    #[must_use]
    pub const fn session_kind(&self) -> SessionKind {
        self.session_kind
    }

    /// Returns the LINE inbound tag sealed for LANDING authorization context.
    #[must_use]
    pub fn inbound_tag(&self) -> &str {
        &self.inbound_tag
    }

    /// Returns the sealed UDP policy snapshot (Option B foundation).
    #[must_use]
    pub const fn policy(&self) -> &HandoffPolicySnapshot {
        &self.policy
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

    /// Consumes the continuation and moves its generation secrets into TLS state.
    ///
    /// Zero-valued replacement secrets are left behind solely so this
    /// zeroizing type can complete its drop; the live generation secrets and
    /// sequences each leave exactly once.
    ///
    /// # Errors
    ///
    /// Rejects an internal suite/secret disagreement.
    pub fn into_parts(mut self) -> Result<ContinuationParts, HandoffError> {
        let algorithm = self.suite.hash();
        let client_secret = std::mem::replace(
            &mut self.client_traffic_secret,
            TrafficSecret::zeroed(algorithm),
        );
        let server_secret = std::mem::replace(
            &mut self.server_traffic_secret,
            TrafficSecret::zeroed(algorithm),
        );
        let client =
            ExportedRecordState::from_parts(self.suite, client_secret, self.client_sequence)
                .map_err(|_| HandoffError::State)?;
        let server =
            ExportedRecordState::from_parts(self.suite, server_secret, self.server_sequence)
                .map_err(|_| HandoffError::State)?;
        let tls = ExportedTlsState::from_directions(client, server);
        let destination = std::mem::replace(
            &mut self.destination,
            Destination::new(Address::Ipv4(Ipv4Addr::UNSPECIFIED), 0),
        );
        let inbound_tag = std::mem::take(&mut self.inbound_tag);
        let policy = std::mem::replace(
            &mut self.policy,
            HandoffPolicySnapshot::tcp_placeholder(Destination::new(
                Address::Ipv4(Ipv4Addr::UNSPECIFIED),
                0,
            )),
        );
        Ok((
            tls,
            self.user_id,
            destination,
            std::mem::take(&mut self.pending_ciphertext),
            std::mem::take(&mut self.prefetched_plaintext),
            self.key_update_response_pending,
            self.session_kind,
            inbound_tag,
            policy,
        ))
    }
}

impl fmt::Debug for ContinuationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContinuationState")
            .field("suite", &self.suite)
            .field("client_sequence", &self.client_sequence)
            .field("server_sequence", &self.server_sequence)
            .field(
                "key_update_response_pending",
                &self.key_update_response_pending,
            )
            .field("session_kind", &self.session_kind)
            .field("inbound_tag", &self.inbound_tag)
            .field("pending_ciphertext_len", &self.pending_ciphertext.len())
            .field("prefetched_plaintext_len", &self.prefetched_plaintext.len())
            .finish_non_exhaustive()
    }
}

/// One verified and decrypted transfer, ready to be installed on LANDING.
pub struct OpenedTransfer {
    timestamp: u64,
    client_random: [u8; 32],
    state: ContinuationState,
}

impl OpenedTransfer {
    /// Returns the sender's Unix timestamp in seconds.
    #[must_use]
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
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

    /// Consumes the verified transfer and returns its continuation state.
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

#[derive(Default)]
struct NonceShard {
    entries: HashMap<[u8; NONCE_LEN], MonotonicInstant>,
    expirations: BinaryHeap<Reverse<(MonotonicInstant, [u8; NONCE_LEN])>>,
}

type NonceShards = Box<[Mutex<NonceShard>]>;

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
            .map(|_| Mutex::new(NonceShard::default()))
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
        self.reserve_at(nonce, MonotonicInstant::now())
    }

    fn reserve_at(
        &self,
        nonce: [u8; NONCE_LEN],
        now: MonotonicInstant,
    ) -> Result<(), HandoffError> {
        let expires_at = now
            .checked_add(self.inner.retention)
            .ok_or(HandoffError::Replay)?;
        let shard_index = usize::from(nonce[0]) % REPLAY_SHARDS;
        let mut swept_all = false;
        loop {
            let mut shard = lock_recover(&self.inner.shards[shard_index]);
            let removed = purge_nonce_shard(&mut shard, now);
            if removed != 0 {
                self.inner.used.fetch_sub(removed, Ordering::AcqRel);
            }
            if shard.entries.contains_key(&nonce) {
                return Err(HandoffError::Replay);
            }

            if self.inner.used.load(Ordering::Acquire) >= self.inner.capacity {
                drop(shard);
                if swept_all {
                    return Err(HandoffError::Replay);
                }
                self.purge_expired_at(now);
                swept_all = true;
                continue;
            }

            shard
                .entries
                .try_reserve(1)
                .map_err(|_| HandoffError::Allocation)?;
            shard
                .expirations
                .try_reserve(1)
                .map_err(|_| HandoffError::Allocation)?;
            match self.reserve_slot() {
                Ok(()) => {
                    shard.entries.insert(nonce, expires_at);
                    shard.expirations.push(Reverse((expires_at, nonce)));
                    return Ok(());
                }
                Err(_) if !swept_all => {
                    drop(shard);
                    self.purge_expired_at(now);
                    swept_all = true;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Removes every expired nonce and returns the number of released entries.
    pub fn purge_expired(&self) -> usize {
        self.purge_expired_at(MonotonicInstant::now())
    }

    fn purge_expired_at(&self, now: MonotonicInstant) -> usize {
        let removed: usize = self
            .inner
            .shards
            .iter()
            .map(|shard| {
                let mut shard = lock_recover(shard);
                purge_nonce_shard(&mut shard, now)
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

    pub(crate) fn retention_policy(&self) -> (usize, Duration) {
        (self.inner.capacity, self.inner.retention)
    }

    pub(crate) fn entry_count(&self) -> usize {
        self.inner.used.load(Ordering::Acquire)
    }
}

fn purge_nonce_shard(shard: &mut NonceShard, now: MonotonicInstant) -> usize {
    let mut removed = 0;
    while shard
        .expirations
        .peek()
        .is_some_and(|Reverse((expires_at, _))| *expires_at <= now)
    {
        let Some(Reverse((expires_at, nonce))) = shard.expirations.pop() else {
            break;
        };
        if shard
            .entries
            .get(&nonce)
            .is_some_and(|current| *current == expires_at)
        {
            shard.entries.remove(&nonce);
            removed += 1;
        }
    }
    removed
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
    Ok(OpenedTransfer {
        timestamp: header.timestamp,
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
    let policy_len = encoded_policy_len(state.policy())?;
    let inbound_len = state.inbound_tag().len();
    let total = 1_usize
        .checked_add(2)
        .and_then(|length| length.checked_add(2 * state.suite().hash().output_len()))
        .and_then(|length| length.checked_add(2 * 8))
        .and_then(|length| length.checked_add(1)) // key_update
        .and_then(|length| length.checked_add(1)) // session_kind
        .and_then(|length| length.checked_add(USER_ID_LEN))
        .and_then(|length| length.checked_add(1 + inbound_len)) // inbound tag
        .and_then(|length| length.checked_add(1 + 2 + address_length + 2))
        .and_then(|length| length.checked_add(4 + state.pending_ciphertext().len()))
        .and_then(|length| length.checked_add(4 + state.prefetched_plaintext().len()))
        .and_then(|length| length.checked_add(4 + policy_len))
        .filter(|length| *length <= MAX_BLOB_LEN)
        .ok_or(HandoffError::Length)?;
    output.clear();
    output
        .try_reserve_exact(total)
        .map_err(|_| HandoffError::Allocation)?;
    output.push(CONTINUATION_STATE_VERSION);
    output.extend_from_slice(&state.suite().wire_value().to_be_bytes());
    encode_traffic_secret(state.client_traffic_secret(), output);
    encode_traffic_secret(state.server_traffic_secret(), output);
    output.extend_from_slice(&state.client_sequence().to_be_bytes());
    output.extend_from_slice(&state.server_sequence().to_be_bytes());
    output.push(u8::from(state.key_update_response_pending()));
    output.push(state.session_kind().wire());
    output.extend_from_slice(state.user_id());
    encode_short_bytes(state.inbound_tag().as_bytes(), output)?;
    encode_address(state.destination(), output);
    output.extend_from_slice(&state.destination().port().to_be_bytes());
    encode_bounded_bytes(state.pending_ciphertext(), output);
    encode_bounded_bytes(state.prefetched_plaintext(), output);
    encode_policy_snapshot(state.policy(), output)?;
    Ok(())
}

fn encoded_policy_len(policy: &HandoffPolicySnapshot) -> Result<usize, HandoffError> {
    let mut body = Vec::new();
    encode_policy_snapshot_body(policy, &mut body)?;
    body.len()
        .checked_add(4) // outer length prefix
        .filter(|_length| body.len() <= MAX_POLICY_SNAPSHOT_LEN)
        .ok_or(HandoffError::Length)
}

fn encode_short_bytes(bytes: &[u8], output: &mut Vec<u8>) -> Result<(), HandoffError> {
    if bytes.len() > MAX_INBOUND_TAG_LEN {
        return Err(HandoffError::State);
    }
    let length = u8::try_from(bytes.len()).map_err(|_| HandoffError::State)?;
    output.push(length);
    output.extend_from_slice(bytes);
    Ok(())
}

fn encode_policy_snapshot(
    policy: &HandoffPolicySnapshot,
    output: &mut Vec<u8>,
) -> Result<(), HandoffError> {
    let mut body = Vec::new();
    encode_policy_snapshot_body(policy, &mut body)?;
    if body.len() > MAX_POLICY_SNAPSHOT_LEN {
        return Err(HandoffError::Length);
    }
    encode_bounded_bytes(&body, output);
    Ok(())
}

fn encode_policy_snapshot_body(
    policy: &HandoffPolicySnapshot,
    body: &mut Vec<u8>,
) -> Result<(), HandoffError> {
    body.push(HANDOFF_POLICY_SNAPSHOT_VERSION);
    body.push(u8::from(policy.allow_destination_rewrites()));
    body.push(u8::from(policy.default_allow()));
    encode_address(policy.initial_destination(), body);
    body.extend_from_slice(&policy.initial_destination().port().to_be_bytes());
    let rule_count = u8::try_from(policy.sealed_rules().len()).map_err(|_| HandoffError::Length)?;
    if usize::from(rule_count) > MAX_SEALED_HANDOFF_RULES {
        return Err(HandoffError::Length);
    }
    body.push(rule_count);
    for rule in policy.sealed_rules() {
        encode_sealed_rule(rule, body)?;
    }
    Ok(())
}

fn encode_sealed_rule(
    rule: &SealedHandoffRouteRule,
    body: &mut Vec<u8>,
) -> Result<(), HandoffError> {
    body.push(u8::from(rule.allow));
    let domain_count = u8::try_from(rule.domains.len()).map_err(|_| HandoffError::Length)?;
    body.push(domain_count);
    for domain in &rule.domains {
        encode_sealed_domain(domain, body)?;
    }
    let ip_count = u8::try_from(rule.ips.len()).map_err(|_| HandoffError::Length)?;
    body.push(ip_count);
    for ip in &rule.ips {
        encode_sealed_ip(*ip, body);
    }
    let port_count = u8::try_from(rule.ports.len()).map_err(|_| HandoffError::Length)?;
    body.push(port_count);
    for port in &rule.ports {
        body.extend_from_slice(&port.start.to_be_bytes());
        body.extend_from_slice(&port.end.to_be_bytes());
    }
    Ok(())
}

fn encode_sealed_domain(
    domain: &SealedDomainMatcher,
    body: &mut Vec<u8>,
) -> Result<(), HandoffError> {
    let (kind, value) = match domain {
        SealedDomainMatcher::Full(value) => (1_u8, value.as_str()),
        SealedDomainMatcher::Suffix(value) => (2_u8, value.as_str()),
        SealedDomainMatcher::Keyword(value) => (3_u8, value.as_str()),
    };
    if value.len() > 255 {
        return Err(HandoffError::Length);
    }
    body.push(kind);
    body.push(u8::try_from(value.len()).map_err(|_| HandoffError::Length)?);
    body.extend_from_slice(value.as_bytes());
    Ok(())
}

fn encode_sealed_ip(network: SealedIpNetwork, body: &mut Vec<u8>) {
    match network {
        SealedIpNetwork::V4 { network, prefix } => {
            body.push(4);
            body.push(prefix);
            body.extend_from_slice(&network.to_be_bytes());
        }
        SealedIpNetwork::V6 { network, prefix } => {
            body.push(6);
            body.push(prefix);
            body.extend_from_slice(&network.to_be_bytes());
        }
    }
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

fn encode_traffic_secret(secret: &TrafficSecret, output: &mut Vec<u8>) {
    output.extend_from_slice(secret.as_bytes());
}

fn encode_bounded_bytes(bytes: &[u8], output: &mut Vec<u8>) {
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
}

fn decode_blob(blob: &[u8]) -> Result<ContinuationState, HandoffError> {
    let mut cursor = BlobCursor::new(blob);
    let version = cursor.u8()?;
    // Reject legacy blobs explicitly: never reinterpret v1/v2 as v3 fields.
    if version != CONTINUATION_STATE_VERSION {
        return Err(HandoffError::State);
    }
    let suite = CipherSuite::from_wire(cursor.u16()?).ok_or(HandoffError::State)?;
    let client_traffic_secret = decode_traffic_secret(&mut cursor, suite)?;
    let server_traffic_secret = decode_traffic_secret(&mut cursor, suite)?;
    let client_sequence = cursor.u64()?;
    let server_sequence = cursor.u64()?;
    let key_update_response_pending = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => return Err(HandoffError::State),
    };
    let session_kind = SessionKind::from_wire(cursor.u8()?).ok_or(HandoffError::State)?;
    let user_id: [u8; USER_ID_LEN] = cursor
        .take(USER_ID_LEN)?
        .try_into()
        .map_err(|_| HandoffError::State)?;
    let inbound_tag = decode_short_string(&mut cursor)?;
    let destination = decode_destination(&mut cursor)?;
    let pending_ciphertext = decode_bounded_bytes(&mut cursor, MAX_PENDING_CIPHERTEXT_LEN)?;
    let prefetched_plaintext = decode_bounded_bytes(&mut cursor, MAX_PREFETCHED_PLAINTEXT_LEN)?;
    let policy = decode_policy_snapshot(&mut cursor)?;
    if cursor.remaining() != 0 {
        return Err(HandoffError::State);
    }
    ContinuationState::new(
        suite,
        client_traffic_secret,
        client_sequence,
        server_traffic_secret,
        server_sequence,
        key_update_response_pending,
        session_kind,
        user_id,
        inbound_tag,
        destination,
        pending_ciphertext,
        prefetched_plaintext,
        policy,
    )
}

fn decode_short_string(cursor: &mut BlobCursor<'_>) -> Result<String, HandoffError> {
    let length = usize::from(cursor.u8()?);
    if length > MAX_INBOUND_TAG_LEN {
        return Err(HandoffError::State);
    }
    let bytes = cursor.take(length)?;
    if !bytes.is_ascii() {
        return Err(HandoffError::State);
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| HandoffError::State)
}

fn decode_policy_snapshot(
    cursor: &mut BlobCursor<'_>,
) -> Result<HandoffPolicySnapshot, HandoffError> {
    let body = decode_bounded_bytes(cursor, MAX_POLICY_SNAPSHOT_LEN)?;
    let mut inner = BlobCursor::new(&body);
    let version = inner.u8()?;
    match version {
        HANDOFF_POLICY_SNAPSHOT_VERSION_V1 => {
            let allow_destination_rewrites = match inner.u8()? {
                0 => false,
                1 => true,
                _ => return Err(HandoffError::State),
            };
            let initial_destination = decode_destination(&mut inner)?;
            if inner.remaining() != 0 {
                return Err(HandoffError::State);
            }
            // Legacy v1 never carried compiled rules; ignore the rewrite flag and
            // keep initial-only semantics (no silent widen of authority).
            let _ = allow_destination_rewrites;
            Ok(HandoffPolicySnapshot::xudp_initial(initial_destination))
        }
        HANDOFF_POLICY_SNAPSHOT_VERSION => {
            let allow_destination_rewrites = match inner.u8()? {
                0 => false,
                1 => true,
                _ => return Err(HandoffError::State),
            };
            let default_allow = match inner.u8()? {
                0 => false,
                1 => true,
                _ => return Err(HandoffError::State),
            };
            let initial_destination = decode_destination(&mut inner)?;
            let rule_count = usize::from(inner.u8()?);
            if rule_count > MAX_SEALED_HANDOFF_RULES {
                return Err(HandoffError::State);
            }
            let mut rules = Vec::with_capacity(rule_count);
            for _ in 0..rule_count {
                rules.push(decode_sealed_rule(&mut inner)?);
            }
            if inner.remaining() != 0 {
                return Err(HandoffError::State);
            }
            let mut policy = HandoffPolicySnapshot::xudp_with_sealed_rules(
                initial_destination,
                rules,
                default_allow,
            );
            // Wire flag must agree with derived authority (no silent widen).
            if policy.allow_destination_rewrites() != allow_destination_rewrites {
                // Prefer fail-closed: force the more restrictive view.
                if !allow_destination_rewrites {
                    policy =
                        HandoffPolicySnapshot::xudp_initial(policy.initial_destination().clone());
                }
            }
            Ok(policy)
        }
        _ => Err(HandoffError::State),
    }
}

fn decode_sealed_rule(cursor: &mut BlobCursor<'_>) -> Result<SealedHandoffRouteRule, HandoffError> {
    let allow = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => return Err(HandoffError::State),
    };
    let domain_count = usize::from(cursor.u8()?);
    let mut domains = Vec::with_capacity(domain_count);
    for _ in 0..domain_count {
        domains.push(decode_sealed_domain(cursor)?);
    }
    let ip_count = usize::from(cursor.u8()?);
    let mut ips = Vec::with_capacity(ip_count);
    for _ in 0..ip_count {
        ips.push(decode_sealed_ip(cursor)?);
    }
    let port_count = usize::from(cursor.u8()?);
    let mut ports = Vec::with_capacity(port_count);
    for _ in 0..port_count {
        let start = cursor.u16()?;
        let end = cursor.u16()?;
        if start == 0 || start > end {
            return Err(HandoffError::State);
        }
        ports.push(SealedPortRange { start, end });
    }
    Ok(SealedHandoffRouteRule {
        allow,
        domains,
        ips,
        ports,
    })
}

fn decode_sealed_domain(cursor: &mut BlobCursor<'_>) -> Result<SealedDomainMatcher, HandoffError> {
    let kind = cursor.u8()?;
    let len = usize::from(cursor.u8()?);
    let bytes = cursor.take(len)?;
    if !bytes.is_ascii() {
        return Err(HandoffError::State);
    }
    let value = String::from_utf8(bytes.to_vec()).map_err(|_| HandoffError::State)?;
    match kind {
        1 => Ok(SealedDomainMatcher::Full(value)),
        2 => Ok(SealedDomainMatcher::Suffix(value)),
        3 => Ok(SealedDomainMatcher::Keyword(value)),
        _ => Err(HandoffError::State),
    }
}

fn decode_sealed_ip(cursor: &mut BlobCursor<'_>) -> Result<SealedIpNetwork, HandoffError> {
    match cursor.u8()? {
        4 => {
            let prefix = cursor.u8()?;
            if prefix > 32 {
                return Err(HandoffError::State);
            }
            let mut raw = [0_u8; 4];
            raw.copy_from_slice(cursor.take(4)?);
            Ok(SealedIpNetwork::V4 {
                network: u32::from_be_bytes(raw),
                prefix,
            })
        }
        6 => {
            let prefix = cursor.u8()?;
            if prefix > 128 {
                return Err(HandoffError::State);
            }
            let mut raw = [0_u8; 16];
            raw.copy_from_slice(cursor.take(16)?);
            Ok(SealedIpNetwork::V6 {
                network: u128::from_be_bytes(raw),
                prefix,
            })
        }
        _ => Err(HandoffError::State),
    }
}

fn decode_traffic_secret(
    cursor: &mut BlobCursor<'_>,
    suite: CipherSuite,
) -> Result<TrafficSecret, HandoffError> {
    TrafficSecret::from_bytes(suite.hash(), cursor.take(suite.hash().output_len())?)
        .map_err(|_| HandoffError::State)
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

/// Fuzz-target entry point for the continuation blob decoder: `blob` is
/// treated as already-decrypted plaintext, so the decoder's bounds checks
/// can be exercised without defeating the AEAD. Built only with the
/// `fuzzing` feature, which the `fuzz/` workspace enables on this crate.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_decode_blob(blob: &[u8]) -> Result<ContinuationState, HandoffError> {
    decode_blob(blob)
}

#[cfg(test)]
mod tests;
