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

    /// Every state in the lifecycle, for exhaustive enumeration.
    const ALL_STATES: [DirectionState; 8] = [
        DirectionState::Framed,
        DirectionState::DirectPending,
        DirectionState::RawReady,
        DirectionState::Outer,
        DirectionState::Closed,
        DirectionState::Failed,
        DirectionState::PairPending,
        DirectionState::Relaying,
    ];

    /// The legal transitions, written out independently of [`DirectionState::permits`].
    ///
    /// This is a reference model, not a restatement: it is an explicit edge list
    /// derived from ADR 0008's boundary rules, while production expresses the
    /// same relation as a single `matches!` pattern. Checking one against the
    /// other over the full 8x8 product is what makes an accidental extra or
    /// missing edge a test failure instead of a silent behaviour change.
    const REFERENCE_EDGES: [(DirectionState, DirectionState); 17] = [
        (DirectionState::Framed, DirectionState::DirectPending),
        (DirectionState::Framed, DirectionState::Outer),
        (DirectionState::Framed, DirectionState::Closed),
        (DirectionState::Framed, DirectionState::Failed),
        (DirectionState::DirectPending, DirectionState::RawReady),
        (DirectionState::DirectPending, DirectionState::Closed),
        (DirectionState::DirectPending, DirectionState::Failed),
        (DirectionState::RawReady, DirectionState::PairPending),
        (DirectionState::RawReady, DirectionState::Relaying),
        (DirectionState::RawReady, DirectionState::Closed),
        (DirectionState::RawReady, DirectionState::Failed),
        (DirectionState::PairPending, DirectionState::Closed),
        (DirectionState::PairPending, DirectionState::Failed),
        (DirectionState::Relaying, DirectionState::Closed),
        (DirectionState::Relaying, DirectionState::Failed),
        (DirectionState::Outer, DirectionState::Closed),
        (DirectionState::Outer, DirectionState::Failed),
    ];

    /// Independently assigned progress rank; a legal transition must raise it.
    fn reference_rank(state: DirectionState) -> u8 {
        match state {
            DirectionState::Framed => 0,
            DirectionState::DirectPending => 1,
            DirectionState::RawReady | DirectionState::Outer => 2,
            DirectionState::PairPending | DirectionState::Relaying => 3,
            DirectionState::Closed | DirectionState::Failed => 4,
        }
    }

    fn reference_permits(from: DirectionState, to: DirectionState) -> bool {
        REFERENCE_EDGES
            .iter()
            .any(|&(edge_from, edge_to)| edge_from == from && edge_to == to)
    }

    /// Independently restated bilateral pair rule.
    fn reference_decision(peer: DirectionState) -> RawDecision {
        match peer {
            DirectionState::RawReady | DirectionState::PairPending => RawDecision::Pair,
            _ => RawDecision::Directional,
        }
    }

    #[test]
    fn the_transition_table_matches_the_reference_model_exhaustively() {
        for from in ALL_STATES {
            for to in ALL_STATES {
                assert_eq!(
                    from.permits(to),
                    reference_permits(from, to),
                    "production and reference disagree about {from:?} -> {to:?}"
                );
            }
        }
    }

    #[test]
    fn every_legal_transition_strictly_advances_progress() {
        // Strict monotonicity is the property that makes the lifecycle acyclic,
        // makes terminal states absorbing, and bounds the number of transitions
        // a direction can accept. Production never states it directly.
        for from in ALL_STATES {
            for to in ALL_STATES {
                if from.permits(to) {
                    assert!(
                        reference_rank(to) > reference_rank(from),
                        "{from:?} -> {to:?} did not strictly advance progress"
                    );
                }
            }
        }
    }

    #[test]
    fn no_state_permits_itself() {
        for state in ALL_STATES {
            assert!(!state.permits(state), "{state:?} permits itself");
        }
    }

    #[test]
    fn the_lifecycle_is_bounded_by_the_rank_ladder() {
        // The longest legal chain cannot exceed the number of distinct ranks,
        // so a direction accepts at most that many transitions in any run.
        let ranks = ALL_STATES.map(reference_rank);
        let highest = ranks.iter().copied().max().expect("states exist");
        for from in ALL_STATES {
            for to in ALL_STATES {
                if from.permits(to) {
                    assert!(reference_rank(to) <= highest);
                }
            }
        }
        assert_eq!(highest, 4, "the rank ladder changed; revisit the bound");
    }

    #[test]
    fn representation_round_trips_every_state() {
        for state in ALL_STATES {
            assert_eq!(DirectionState::from_repr(state as u8), state);
        }
    }

    #[test]
    fn out_of_range_representations_decode_to_the_initial_state() {
        // The runtime stores this in one atomic byte; an unexpected value must
        // not be interpreted as an advanced or terminal state.
        for value in 8_u8..=u8::MAX {
            assert_eq!(DirectionState::from_repr(value), DirectionState::Framed);
        }
    }

    #[test]
    fn terminal_states_never_revive() {
        for terminal in [DirectionState::Closed, DirectionState::Failed] {
            for next in ALL_STATES {
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
    fn a_grant_is_planned_only_at_the_raw_boundary_for_every_peer_state() {
        // Exhaustive over both directions, all own states, and all peer states.
        for direction in [Direction::Uplink, Direction::Downlink] {
            for current in ALL_STATES {
                for peer in ALL_STATES {
                    let planned = RawRelayTransition::plan(direction, current, peer);
                    if current == DirectionState::RawReady {
                        let transition =
                            planned.expect("the raw boundary must plan a legal successor");
                        let expected = reference_decision(peer);
                        let next = transition.next_state();
                        assert_eq!(
                            next,
                            match expected {
                                RawDecision::Pair => DirectionState::PairPending,
                                RawDecision::Directional => DirectionState::Relaying,
                            },
                            "planned successor disagrees with the reference decision \
                             for peer {peer:?}"
                        );
                        assert!(current.permits(next));
                        let grant = transition.into_grant();
                        assert_eq!(grant.direction(), direction);
                        assert_eq!(
                            grant.into_decision(),
                            expected,
                            "grant decision disagrees with the reference rule \
                             for peer {peer:?}"
                        );
                    } else {
                        let error =
                            planned.expect_err("a grant was issued away from the raw boundary");
                        assert_eq!(error.direction, direction);
                        assert_eq!(error.from, current);
                    }
                }
            }
        }
    }

    #[test]
    fn a_paired_peer_always_pairs_back() {
        // This is what makes the runtime rule "never leave PairPending before
        // the peer decides" sufficient to keep a bilateral pair from splitting.
        for direction in [Direction::Uplink, Direction::Downlink] {
            for peer in [DirectionState::RawReady, DirectionState::PairPending] {
                let grant = RawRelayTransition::plan(direction, DirectionState::RawReady, peer)
                    .expect("the raw boundary must plan")
                    .into_grant();
                assert_eq!(grant.into_decision(), RawDecision::Pair);
            }
        }
    }

    #[test]
    fn leaving_the_raw_boundary_is_irreversible() {
        // A committed direction can never plan a second grant, which is the
        // "exactly one transport owner" rule.
        for committed in [DirectionState::PairPending, DirectionState::Relaying] {
            assert!(!committed.permits(DirectionState::RawReady));
            for peer in ALL_STATES {
                assert!(RawRelayTransition::plan(Direction::Uplink, committed, peer).is_err());
            }
        }
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
    fn raw_relay_values_remain_compact_and_allocation_free() {
        assert_eq!(core::mem::size_of::<Direction>(), 1);
        assert_eq!(core::mem::size_of::<DirectionState>(), 1);
        assert_eq!(core::mem::size_of::<RawDecision>(), 1);
        assert_eq!(core::mem::size_of::<super::RawRelayGrant>(), 2);
        assert_eq!(core::mem::size_of::<RawRelayTransition>(), 3);
    }
}
