//! Runtime-independent Vision direction lifecycle.

use core::fmt;

/// One Vision relay direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
pub enum RawDecision {
    /// Both directions will deposit their halves for the bilateral pair relay.
    Pair,
    /// This direction relays its own halves independently.
    Directional,
}

#[cfg(test)]
mod tests {
    use super::{DirectionState, InvalidTransition};

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
}
