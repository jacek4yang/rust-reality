//! Runtime-independent Vision direction lifecycle.

use core::fmt;

/// One Vision relay direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Direction {
    /// Client to destination.
    Uplink,
    /// Destination to client.
    Downlink,
}

impl fmt::Display for Direction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Uplink => "uplink",
            Self::Downlink => "downlink",
        })
    }
}

/// The bounded lifecycle of one Vision direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DirectionState {
    /// TLS and Vision processing continues.
    Framed = 0,
    /// An authenticated Direct command was accepted, but already decoded or
    /// encoded bytes still have to be flushed in order.
    DirectPending = 1,
    /// This direction sits at the exact raw boundary and has not consumed any
    /// byte belonging to the raw phase without transferring it.
    RawReady = 2,
    /// Vision End selected continued outer TLS behaviour.
    Outer = 3,
    /// Normal EOF or a completed half-close.
    Closed = 4,
    /// Protocol, I/O, timeout, cancellation, or invariant failure.
    Failed = 5,
    /// This direction committed to the bilateral pair handoff and deposited —
    /// or is about to deposit — its socket halves for the peer to reunite.
    PairPending = 6,
    /// This direction claimed its halves for an independent directional relay.
    Relaying = 7,
}

impl DirectionState {
    /// Decodes the compact atomic representation used by a runtime adapter.
    #[must_use]
    pub const fn from_repr(value: u8) -> Self {
        match value {
            1 => Self::DirectPending,
            2 => Self::RawReady,
            3 => Self::Outer,
            4 => Self::Closed,
            5 => Self::Failed,
            6 => Self::PairPending,
            7 => Self::Relaying,
            _ => Self::Framed,
        }
    }

    /// Returns whether `next` is a permitted successor of `self`.
    ///
    /// The forbidden set is exhaustive rather than a default: `Outer` never
    /// becomes `RawReady`, `RawReady` never returns to `Framed`, and neither
    /// `Closed` nor `Failed` ever becomes active again.
    #[must_use]
    pub const fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Framed, Self::DirectPending)
                | (Self::Framed, Self::Outer)
                | (Self::Framed, Self::Closed)
                | (Self::Framed, Self::Failed)
                | (Self::DirectPending, Self::RawReady)
                | (Self::DirectPending, Self::Closed)
                | (Self::DirectPending, Self::Failed)
                | (Self::RawReady, Self::PairPending)
                | (Self::RawReady, Self::Relaying)
                | (Self::RawReady, Self::Closed)
                | (Self::RawReady, Self::Failed)
                | (Self::PairPending, Self::Closed)
                | (Self::PairPending, Self::Failed)
                | (Self::Relaying, Self::Closed)
                | (Self::Relaying, Self::Failed)
                | (Self::Outer, Self::Closed)
                | (Self::Outer, Self::Failed)
        )
    }
}

impl fmt::Display for DirectionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Framed => "framed",
            Self::DirectPending => "directPending",
            Self::RawReady => "rawReady",
            Self::Outer => "outer",
            Self::Closed => "closed",
            Self::Failed => "failed",
            Self::PairPending => "pairPending",
            Self::Relaying => "relaying",
        })
    }
}

/// A state-machine transition that the Vision direction lifecycle forbids.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidTransition {
    /// The direction whose transition was rejected.
    pub direction: Direction,
    /// The state the direction was in.
    pub from: DirectionState,
    /// The state the caller attempted to enter.
    pub to: DirectionState,
}

impl fmt::Display for InvalidTransition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} direction cannot move from {} to {}",
            self.direction, self.from, self.to
        )
    }
}

impl core::error::Error for InvalidTransition {}

/// The raw-relay form one direction committed to at its boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RawDecision {
    /// Both directions will deposit their halves for the bilateral pair relay.
    Pair,
    /// This direction relays its own halves independently.
    Directional,
}

/// A validated state transition that will issue one raw-relay grant.
///
/// Planning is pure and does not change runtime-owned atomic state. The runtime
/// adapter must commit [`Self::next_state`] first and may only then consume the
/// transition with [`Self::into_grant`]. This keeps the semantic choice in the
/// Session Engine without moving synchronization or sockets across the layer.
#[derive(Debug, Eq, PartialEq)]
pub struct RawRelayTransition {
    grant: RawRelayGrant,
    next_state: DirectionState,
}

impl RawRelayTransition {
    /// Plans the only legal raw-relay successor from `current`.
    ///
    /// A peer at its raw boundary, or one already committed to a pair, selects
    /// the bilateral pair. Every other peer state selects an independent
    /// directional relay so neither direction waits for the other.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTransition`] unless `current` is exactly `RawReady`.
    pub const fn plan(
        direction: Direction,
        current: DirectionState,
        peer: DirectionState,
    ) -> Result<Self, InvalidTransition> {
        let (decision, next_state) = match peer {
            DirectionState::RawReady | DirectionState::PairPending => {
                (RawDecision::Pair, DirectionState::PairPending)
            }
            _ => (RawDecision::Directional, DirectionState::Relaying),
        };
        if !current.permits(next_state) {
            return Err(InvalidTransition {
                direction,
                from: current,
                to: next_state,
            });
        }
        Ok(Self {
            grant: RawRelayGrant {
                direction,
                decision,
            },
            next_state,
        })
    }

    /// Returns the state the runtime adapter must atomically commit.
    #[must_use]
    pub const fn next_state(&self) -> DirectionState {
        self.next_state
    }

    /// Consumes the committed transition and issues its one-shot relay grant.
    #[must_use = "a committed raw-relay grant must be consumed by the transport adapter"]
    pub const fn into_grant(self) -> RawRelayGrant {
        self.grant
    }
}

/// One-shot authority to transfer a direction into the raw transport backend.
///
/// This value is deliberately neither `Copy` nor `Clone`. It is issued only by
/// a valid [`RawRelayTransition`] and is consumed before the runtime transfers
/// socket ownership. It never wraps or observes relay buffers after handoff.
#[derive(Debug, Eq, PartialEq)]
pub struct RawRelayGrant {
    direction: Direction,
    decision: RawDecision,
}

impl RawRelayGrant {
    /// Returns the direction whose transport ownership is being transferred.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// Consumes the one-shot authority and returns the selected relay form.
    #[must_use]
    pub const fn into_decision(self) -> RawDecision {
        self.decision
    }
}

#[cfg(test)]
mod tests {
    use super::{Direction, DirectionState, InvalidTransition, RawDecision, RawRelayTransition};

    #[test]
    fn representation_round_trips_every_state() {
        for state in [
            DirectionState::Framed,
            DirectionState::DirectPending,
            DirectionState::RawReady,
            DirectionState::Outer,
            DirectionState::Closed,
            DirectionState::Failed,
            DirectionState::PairPending,
            DirectionState::Relaying,
        ] {
            assert_eq!(DirectionState::from_repr(state as u8), state);
        }
    }

    #[test]
    fn terminal_states_never_revive() {
        for terminal in [DirectionState::Closed, DirectionState::Failed] {
            for next in [
                DirectionState::Framed,
                DirectionState::DirectPending,
                DirectionState::RawReady,
                DirectionState::Outer,
                DirectionState::Closed,
                DirectionState::Failed,
                DirectionState::PairPending,
                DirectionState::Relaying,
            ] {
                assert!(!terminal.permits(next));
            }
        }
    }

    #[test]
    fn invalid_transition_is_core_error() {
        fn assert_error<T: core::error::Error>() {}
        assert_error::<InvalidTransition>();
    }

    #[test]
    fn raw_relay_transition_issues_one_direction_bound_grant() {
        let pair = RawRelayTransition::plan(
            Direction::Uplink,
            DirectionState::RawReady,
            DirectionState::PairPending,
        )
        .expect("raw-ready direction may pair");
        assert_eq!(pair.next_state(), DirectionState::PairPending);
        let pair = pair.into_grant();
        assert_eq!(pair.direction(), Direction::Uplink);
        assert_eq!(pair.into_decision(), RawDecision::Pair);

        let directional = RawRelayTransition::plan(
            Direction::Downlink,
            DirectionState::RawReady,
            DirectionState::Framed,
        )
        .expect("raw-ready direction may relay independently");
        assert_eq!(directional.next_state(), DirectionState::Relaying);
        assert_eq!(
            directional.into_grant().into_decision(),
            RawDecision::Directional
        );
    }

    #[test]
    fn raw_relay_grant_cannot_be_planned_before_or_after_the_boundary() {
        for state in [
            DirectionState::Framed,
            DirectionState::DirectPending,
            DirectionState::Outer,
            DirectionState::Closed,
            DirectionState::Failed,
            DirectionState::PairPending,
            DirectionState::Relaying,
        ] {
            assert!(
                RawRelayTransition::plan(Direction::Uplink, state, DirectionState::Framed).is_err(),
                "{state:?} unexpectedly issued a raw grant"
            );
        }
    }

    #[test]
    fn raw_relay_values_remain_compact_and_allocation_free() {
        assert_eq!(core::mem::size_of::<Direction>(), 1);
        assert_eq!(core::mem::size_of::<DirectionState>(), 1);
        assert_eq!(core::mem::size_of::<RawDecision>(), 1);
        assert_eq!(core::mem::size_of::<super::RawRelayGrant>(), 2);
        assert_eq!(core::mem::size_of::<RawRelayTransition>(), 3);
    }
}
