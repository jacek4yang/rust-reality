//! Vision relay statistics types and aggregation helpers.
//!
//! Internal to [`crate::server::vision`]: public [`VisionRelayStats`] plus the
//! per-direction counters and boundary byte views used by the relay paths.

use crate::transport::{RelayBackend, RelayOutcome};

/// Counts and direct-transition results from one Vision relay.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VisionRelayStats {
    pub(super) uplink_bytes: u64,
    pub(super) downlink_bytes: u64,
    pub(super) uplink_direct: bool,
    pub(super) downlink_direct: bool,
    pub(super) relay_backend: Option<RelayBackend>,
    pub(super) uplink_direct_at_bytes: u64,
    pub(super) downlink_direct_at_bytes: u64,
    pub(super) uplink_backend: Option<RelayBackend>,
    pub(super) downlink_backend: Option<RelayBackend>,
    pub(super) uplink_handoff_delay_us: u64,
    pub(super) downlink_handoff_delay_us: u64,
    pub(super) handoff_server_sequence: Option<u64>,
    pub(super) pipe_capacity_downgraded: bool,
}

impl VisionRelayStats {
    /// Returns unpadded client bytes delivered to the destination.
    #[must_use]
    pub const fn uplink_bytes(self) -> u64 {
        self.uplink_bytes
    }

    /// Returns destination bytes delivered to the client.
    #[must_use]
    pub const fn downlink_bytes(self) -> u64 {
        self.downlink_bytes
    }

    /// Returns whether the client authenticated a Vision Direct command.
    #[must_use]
    pub const fn uplink_direct(self) -> bool {
        self.uplink_direct
    }

    /// Returns whether the server completed a Vision Direct write boundary.
    #[must_use]
    pub const fn downlink_direct(self) -> bool {
        self.downlink_direct
    }

    /// Returns the backend that ran the raw relay after a bilateral handoff.
    #[must_use]
    pub const fn relay_backend(self) -> Option<RelayBackend> {
        self.relay_backend
    }

    /// Returns uplink bytes delivered before the uplink Direct boundary.
    #[must_use]
    pub const fn uplink_direct_at_bytes(self) -> u64 {
        self.uplink_direct_at_bytes
    }

    /// Returns downlink bytes delivered before the downlink Direct boundary.
    #[must_use]
    pub const fn downlink_direct_at_bytes(self) -> u64 {
        self.downlink_direct_at_bytes
    }

    /// Returns the backend that moved the uplink's raw bytes, when direct.
    #[must_use]
    pub const fn uplink_backend(self) -> Option<RelayBackend> {
        self.uplink_backend
    }

    /// Returns the backend that moved the downlink's raw bytes, when direct.
    #[must_use]
    pub const fn downlink_backend(self) -> Option<RelayBackend> {
        self.downlink_backend
    }

    /// Returns microseconds from the uplink boundary to its raw relay start.
    #[must_use]
    pub const fn uplink_handoff_delay_us(self) -> u64 {
        self.uplink_handoff_delay_us
    }

    /// Returns microseconds from the downlink boundary to its raw relay start.
    #[must_use]
    pub const fn downlink_handoff_delay_us(self) -> u64 {
        self.downlink_handoff_delay_us
    }

    /// Returns the server record sequence exported to LANDING, when this
    /// session used the distributed Handoff path.
    #[must_use]
    pub const fn handoff_server_sequence(self) -> Option<u64> {
        self.handoff_server_sequence
    }

    /// Returns whether a raw-relay backend was granted less pipe capacity
    /// than requested because kernel pipe-page limits downgraded it.
    #[must_use]
    pub const fn pipe_capacity_downgraded(self) -> bool {
        self.pipe_capacity_downgraded
    }
}

pub(super) struct DirectionStats {
    pub(super) bytes: u64,
    pub(super) direct: bool,
    /// Byte counts produced by the unified raw relay, present only on the
    /// direction that deposited its sockets last and therefore ran the relay.
    handoff: Option<RelayOutcome>,
    /// The backend that moved this direction's raw bytes: the directional
    /// backend for an independent relay, or the pair backend for the direction
    /// that ran the bilateral relay.
    backend: Option<RelayBackend>,
    /// Bytes this direction had delivered when it reached its Direct boundary.
    direct_at_bytes: u64,
    /// Microseconds from the boundary to the deposit or directional relay start.
    handoff_delay_us: u64,
    /// The backend's pipe capacity was downgraded by kernel pipe-page limits.
    pipe_downgrade: bool,
}

impl DirectionStats {
    pub(super) const fn framed(bytes: u64) -> Self {
        Self {
            bytes,
            direct: false,
            handoff: None,
            backend: None,
            direct_at_bytes: 0,
            handoff_delay_us: 0,
            pipe_downgrade: false,
        }
    }

    pub(super) const fn direct(
        bytes: u64,
        handoff: Option<RelayOutcome>,
        backend: Option<RelayBackend>,
        direct_at_bytes: u64,
        handoff_delay_us: u64,
        pipe_downgrade: bool,
    ) -> Self {
        Self {
            bytes,
            direct: true,
            handoff,
            backend,
            direct_at_bytes,
            handoff_delay_us,
            pipe_downgrade,
        }
    }
}

/// Combines both directions' counters into per-session relay statistics.
pub(super) fn session_stats(uplink: DirectionStats, downlink: DirectionStats) -> VisionRelayStats {
    let handed_off = uplink.handoff.or(downlink.handoff);
    let (handed_up, handed_down) = handed_off.map_or((0, 0), |outcome| {
        (outcome.inbound_to_outbound(), outcome.outbound_to_inbound())
    });
    let pair_backend = handed_off.map(RelayOutcome::backend);
    VisionRelayStats {
        uplink_bytes: uplink.bytes.saturating_add(handed_up),
        downlink_bytes: downlink.bytes.saturating_add(handed_down),
        uplink_direct: uplink.direct,
        downlink_direct: downlink.direct,
        relay_backend: pair_backend,
        uplink_direct_at_bytes: uplink.direct_at_bytes,
        downlink_direct_at_bytes: downlink.direct_at_bytes,
        // A pair outcome exists only when both directions committed to the
        // bilateral handoff, so a directional backend and the pair backend
        // can never both be present for one direction.
        uplink_backend: uplink.backend.or(pair_backend),
        downlink_backend: downlink.backend.or(pair_backend),
        uplink_handoff_delay_us: uplink.handoff_delay_us,
        downlink_handoff_delay_us: downlink.handoff_delay_us,
        handoff_server_sequence: None,
        pipe_capacity_downgraded: handed_off.and_then(RelayOutcome::pipe_downgrade).is_some()
            || uplink.pipe_downgrade
            || downlink.pipe_downgrade,
    }
}

/// Byte counters at a raw boundary.
///
/// `total` is every byte the direction delivered, including pending bytes
/// drained out of a socket buffer; `direct_at` is the framed-only count the
/// direction had delivered when it reached its Direct boundary, which excludes
/// the raw phase whether the bytes were drained or relayed.
#[derive(Clone, Copy)]
pub(super) struct BoundaryBytes {
    pub(super) total: u64,
    pub(super) direct_at: u64,
}
