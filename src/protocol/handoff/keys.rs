//! Handoff PSK and landing key-rotation material.
//!
//! Wire seal/open stays in the parent module; this submodule owns only the
//! independently generated pair PSK and the bounded landing candidate set.

use std::{fmt, sync::Arc};

use zeroize::Zeroizing;

use crate::crypto::StaticX25519Key;

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

    pub(super) fn as_bytes(&self) -> &[u8; 32] {
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
    pub(super) fn candidates(&self) -> impl Iterator<Item = (&HandoffPsk, &StaticX25519Key)> {
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

    /// Test-only handle to the shared active static secret (Arc identity).
    #[cfg(test)]
    pub(crate) fn active_secret_arc(&self) -> &Arc<StaticX25519Key> {
        &self.active_secret
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
