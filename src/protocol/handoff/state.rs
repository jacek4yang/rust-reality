//! Continuation-state and opened-transfer types for Handoff.
//!
//! Kept beside the seal/open path so `mod` stays focused on AEAD transfer
//! construction while callers keep importing these types from
//! `protocol::handoff`.

use std::{fmt, net::Ipv4Addr};

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::policy::{HandoffPolicySnapshot, SessionKind};
use super::{
    HandoffError, MAX_INBOUND_TAG_LEN, MAX_PENDING_CIPHERTEXT_LEN, MAX_PREFETCHED_PLAINTEXT_LEN,
    USER_ID_LEN,
};
use crate::protocol::reality::tls13::{
    CipherSuite, ExportedRecordState, ExportedTlsState, TrafficSecret,
};
use crate::protocol::vless::{Address, Destination};

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

    /// Assembles one verified transfer from an authenticated open path.
    #[must_use]
    pub(crate) fn from_parts(
        timestamp: u64,
        client_random: [u8; 32],
        state: ContinuationState,
    ) -> Self {
        Self {
            timestamp,
            client_random,
            state,
        }
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
