#![no_main]

//! Deterministic semantic state-machine fuzzing for the Session Engine.
//!
//! This target does not parse bytes and does not touch a socket, a clock, or
//! Tokio. It drives the extracted pure session semantics with arbitrary
//! *event sequences* and checks the ownership invariants that only a sequence
//! can violate.
//!
//! Division of labour, so that neither layer is a tautology:
//!
//! * The **static** relations — the legal transition table, the strict progress
//!   ordering, the pair/directional rule, and where a grant may be planned — are
//!   proven *exhaustively* against a hand-written reference model by the unit
//!   tests in `crates/rr-session/src/vision.rs`. Those enumerate the whole 8x8
//!   state product, so sampling them here would add nothing.
//! * This target owns the **path-dependent** properties that exhaustive
//!   enumeration of single steps cannot reach: that a direction can never obtain
//!   a second transport grant, that the two directions never split a bilateral
//!   pair across arbitrary interleavings, that per-direction state growth stays
//!   bounded, that a terminal direction stays terminal for the rest of an
//!   arbitrary sequence, and that an authenticated transfer never authorizes an
//!   attempt after its irreversible boundary.
//!
//! `reference_rank` is kept here because it is the oracle for the bounded-growth
//! property: production nowhere states a progress rank, so counting accepted
//! transitions against the rank ladder is a real cross-check rather than a
//! restatement of a production expression.
//!
//! Byte-level and parser fuzzing is unchanged and still authoritative for wire
//! behaviour; this target is additive.

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use rr_session::{
    AttemptTransport, Direction, DirectionState, RawDecision, RawRelayTransition,
    RetryableProgress, WriteProgress,
};

/// Bound on driven events so a single input cannot run unboundedly long.
const MAX_EVENTS: usize = 256;

/// Every state in the direction lifecycle.
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

/// Independently assigned progress rank.
///
/// A direction may only ever move to a strictly higher rank. Production does not
/// express the rule this way, so using it as the oracle for bounded state growth
/// is a genuine cross-check.
fn reference_rank(state: DirectionState) -> u8 {
    match state {
        DirectionState::Framed => 0,
        DirectionState::DirectPending => 1,
        DirectionState::RawReady | DirectionState::Outer => 2,
        DirectionState::PairPending | DirectionState::Relaying => 3,
        DirectionState::Closed | DirectionState::Failed => 4,
    }
}

/// The highest rank, and therefore the bound on transitions per direction.
const MAX_RANK: u8 = 4;

/// Independently restated pair/directional rule, used to check cross-direction
/// agreement along a fuzzed interleaving.
fn reference_decision(peer: DirectionState) -> RawDecision {
    match peer {
        DirectionState::RawReady | DirectionState::PairPending => RawDecision::Pair,
        _ => RawDecision::Directional,
    }
}

fn reference_terminal(state: DirectionState) -> bool {
    matches!(state, DirectionState::Closed | DirectionState::Failed)
}

#[derive(Arbitrary, Debug)]
enum Event {
    /// The runtime attempts to commit an arbitrary lifecycle transition.
    Advance { direction: bool, state: u8 },
    /// The runtime asks the engine to plan the raw-relay transition.
    PlanRawRelay { direction: bool },
    /// A new authenticated single-message transfer starts. `warm` models whether
    /// a warm pool offered a prepaid socket for the first attempt.
    BeginTransfer { warm: bool },
    /// The current transfer's next authorized attempt reaches a write boundary.
    WriteBoundary { written: u16, length: u16 },
}

#[derive(Arbitrary, Debug)]
struct Input {
    events: Vec<Event>,
}

fn direction_of(flag: bool) -> Direction {
    if flag {
        Direction::Uplink
    } else {
        Direction::Downlink
    }
}

/// The modelled state of one authenticated single-message transfer.
///
/// Production permits at most one prepaid warm attempt followed by the mandatory
/// cold dial. The whole attempt sequence is driven by the engine's own
/// functions: `AttemptTransport::alternate_attempt` decides whether another
/// attempt exists, and `WriteProgress::permits_fresh_attempt` decides whether the
/// irreversible boundary forbids one. Nothing here restates those answers, so an
/// engine regression changes the model's behaviour and trips an assertion.
struct Transfer {
    /// Transport the next authorized attempt would use, `None` once exhausted.
    next: Option<AttemptTransport>,
    /// Transport used by the most recent attempt, if any.
    last_transport: Option<AttemptTransport>,
    /// Progress reported by the most recent attempt, if any.
    last: Option<WriteProgress>,
    /// Whether this transfer reached its irreversible boundary.
    committed: bool,
    /// Attempts actually run, bounded by the warm-then-cold chain.
    attempts: u8,
}

/// Warm-then-cold is two attempts; cold-only is one.
const MAX_ATTEMPTS: u8 = 2;

impl Transfer {
    const fn begin(warm: bool) -> Self {
        Self {
            next: Some(if warm {
                AttemptTransport::Warm
            } else {
                AttemptTransport::Cold
            }),
            last_transport: None,
            last: None,
            committed: false,
            attempts: 0,
        }
    }

    /// Runs one attempt if the engine authorizes it, and checks what that implies.
    fn write_boundary(&mut self, written: usize, length: usize) {
        // The runtime consults the engine before authorizing another attempt.
        let permitted_by_boundary = self.last.is_none_or(WriteProgress::permits_fresh_attempt);
        let Some(transport) = self.next else {
            // Invariant: the chain only ends for a reason the engine gave —
            // either the irreversible boundary was reached, or the last
            // attempt's transport had no alternate. A cold-only transfer is
            // legitimately exhausted after a single failed attempt.
            assert!(
                self.committed
                    || self
                        .last_transport
                        .is_some_and(|used| !used.permits_alternate_attempt()),
                "the attempt chain ended without a commit or an exhausted alternate"
            );
            assert!(
                self.committed || !permitted_by_boundary || self.attempts > 0,
                "the attempt chain was exhausted before running any attempt"
            );
            return;
        };
        // Invariant: no retry after an irreversible complete write. If the engine
        // ever reported that a committed write permits a fresh attempt, the chain
        // would still be open here and this assertion would fail.
        assert!(
            permitted_by_boundary,
            "the engine authorized an attempt after its irreversible boundary"
        );
        assert!(
            !self.committed,
            "an attempt was authorized after this transfer already committed"
        );

        self.attempts += 1;
        self.last_transport = Some(transport);
        // Invariant: bounded attempts. The warm-then-cold chain cannot grow.
        assert!(
            self.attempts <= MAX_ATTEMPTS,
            "transfer ran {} attempts, above the {MAX_ATTEMPTS} bound",
            self.attempts
        );

        let progress = WriteProgress::from_written(written, length);
        self.last = Some(progress);
        match progress.split() {
            Ok(committed) => {
                assert!(
                    !progress.permits_fresh_attempt(),
                    "a committed write claimed to permit a fresh attempt"
                );
                // Consuming the witness is what binds the session to this
                // transport; the transfer is over.
                committed.commit_transport_ownership();
                self.committed = true;
                self.next = None;
            }
            Err(retryable) => {
                assert!(
                    progress.permits_fresh_attempt(),
                    "retryable progress forbade a fresh attempt"
                );
                assert_eq!(
                    retryable.progress(),
                    progress,
                    "projection lost information"
                );
                // Invariant: a permitted retry never resumes from an offset; the
                // discarded prefix is reported for accounting only.
                assert_eq!(
                    retryable.bytes_discarded(),
                    written,
                    "discarded byte count disagreed with the failed attempt"
                );
                assert!(
                    matches!(
                        retryable,
                        RetryableProgress::NoBytesWritten | RetryableProgress::PartialWrite { .. }
                    ),
                    "retryable progress reached an impossible variant"
                );
                // Only the speculative warm attempt has an alternate.
                let alternate = transport.alternate_attempt();
                assert_eq!(
                    alternate.is_some(),
                    transport.permits_alternate_attempt(),
                    "alternate availability disagreed with the transport predicate"
                );
                if let Some(next) = alternate {
                    assert_eq!(
                        next,
                        AttemptTransport::Cold,
                        "warm fell back to a non-cold attempt"
                    );
                    assert!(
                        !next.permits_alternate_attempt(),
                        "the cold dial offered a further alternate"
                    );
                }
                self.next = alternate;
            }
        }
    }

    fn check_final(&self) {
        assert!(self.attempts <= MAX_ATTEMPTS);
        // A warm-started chain is the only one that can run two attempts.
        if self.attempts == MAX_ATTEMPTS {
            assert_eq!(
                self.last_transport,
                Some(AttemptTransport::Cold),
                "a second attempt ran on a transport other than the cold dial"
            );
        }
        if self.committed {
            assert!(
                self.next.is_none(),
                "a committed transfer kept an open attempt"
            );
            assert!(
                self.last
                    .is_some_and(|progress| !progress.permits_fresh_attempt()),
                "a committed transfer did not record an irreversible boundary"
            );
        }
    }
}

/// The whole observable state of one modelled session.
struct Session {
    uplink: DirectionState,
    downlink: DirectionState,
    /// Accepted transitions per direction, bounded by `MAX_RANK`.
    transitions: [u8; 2],
    /// Grants issued per direction. Never more than one.
    grants: [u8; 2],
    /// The decision each direction committed to, if it reached the boundary.
    decisions: [Option<RawDecision>; 2],
    /// The authenticated transfer currently modelled, if one has begun.
    transfer: Option<Transfer>,
}

impl Session {
    const fn new() -> Self {
        Self {
            uplink: DirectionState::Framed,
            downlink: DirectionState::Framed,
            transitions: [0, 0],
            grants: [0, 0],
            decisions: [None, None],
            transfer: None,
        }
    }

    const fn slot(direction: Direction) -> usize {
        match direction {
            Direction::Uplink => 0,
            Direction::Downlink => 1,
        }
    }

    const fn state(&self, direction: Direction) -> DirectionState {
        match direction {
            Direction::Uplink => self.uplink,
            Direction::Downlink => self.downlink,
        }
    }

    const fn peer_state(&self, direction: Direction) -> DirectionState {
        match direction {
            Direction::Uplink => self.downlink,
            Direction::Downlink => self.uplink,
        }
    }

    fn set_state(&mut self, direction: Direction, next: DirectionState) {
        match direction {
            Direction::Uplink => self.uplink = next,
            Direction::Downlink => self.downlink = next,
        }
    }

    /// Commits a transition exactly as the runtime adapter would, and checks the
    /// sequence-level invariants that commit implies.
    fn advance(&mut self, direction: Direction, next: DirectionState) {
        let current = self.state(direction);
        if !current.permits(next) {
            return;
        }

        // Invariant: a terminal direction never revives, and no state
        // transition happens after a final close. Exhaustive single-step
        // coverage lives in the crate's unit tests; what this adds is that the
        // property survives an arbitrary sequence that reached `current`.
        assert!(
            !reference_terminal(current),
            "terminal state {current:?} accepted a transition to {next:?}"
        );
        // Invariant: progress is strictly monotonic, so the lifecycle cannot
        // loop back to inflate state along this sequence.
        assert!(
            reference_rank(next) > reference_rank(current),
            "transition {current:?} -> {next:?} did not strictly advance progress"
        );

        let slot = Self::slot(direction);
        // Runtime discipline that the pure engine cannot enforce, audited in
        // `src/server/vision.rs`: a direction that committed to the bilateral
        // pair is never advanced again by the first depositor. `run_handoff`
        // returns without settling when `recovered` is `None`, and the only
        // `settle` calls reachable from a `PairPending` direction live after the
        // `Some(sockets)` binding, i.e. in the last depositor, which runs after
        // both directions already committed to `Pair`.
        //
        // The model honours that discipline deliberately. The lifecycle table
        // does allow `PairPending -> Closed`, and taking that edge before the
        // peer plans would let the peer observe a terminal state, choose
        // `Directional`, and split the pair. Enforcing "do not leave
        // `PairPending` early" is a Runtime Adapter obligation, and
        // `session_pair_commitment_is_not_settled_by_the_first_depositor` in
        // `src/server/direct.rs` pins it on the runtime side.
        if self.decisions[slot] == Some(RawDecision::Pair) && reference_terminal(next) {
            return;
        }

        self.transitions[slot] += 1;
        // Invariant: bounded state growth. Strict rank monotonicity caps the
        // number of accepted transitions per direction at MAX_RANK.
        assert!(
            self.transitions[slot] <= MAX_RANK,
            "{direction:?} accepted {} transitions, above the {MAX_RANK} bound",
            self.transitions[slot]
        );
        self.set_state(direction, next);
    }

    /// Plans and, when legal, commits the one-shot raw-relay transition.
    fn plan_raw_relay(&mut self, direction: Direction) {
        let current = self.state(direction);
        let peer = self.peer_state(direction);
        let planned = RawRelayTransition::plan(direction, current, peer);

        if current != DirectionState::RawReady {
            // Invariant: no transport ownership can be granted before or after
            // the exact raw boundary.
            let error = planned.expect_err("a grant was issued away from the raw boundary");
            assert_eq!(error.direction, direction);
            assert_eq!(error.from, current);
            return;
        }

        let transition = planned.expect("the raw boundary must plan a legal successor");
        let next = transition.next_state();
        let expected = reference_decision(peer);
        assert_eq!(
            next,
            match expected {
                RawDecision::Pair => DirectionState::PairPending,
                RawDecision::Directional => DirectionState::Relaying,
            },
            "planned successor disagrees with the reference decision for peer {peer:?}"
        );

        // The runtime commits the state first and only then consumes the grant.
        self.advance(direction, next);
        let grant = transition.into_grant();
        assert_eq!(grant.direction(), direction, "grant lost its direction");
        let decision = grant.into_decision();
        assert_eq!(
            decision, expected,
            "grant decision disagrees with the reference rule for peer {peer:?}"
        );

        let slot = Self::slot(direction);
        self.grants[slot] += 1;
        // Invariant: exactly one transport owner. A direction can never obtain a
        // second grant, because leaving RawReady is irreversible.
        assert_eq!(
            self.grants[slot], 1,
            "{direction:?} obtained {} raw-relay grants",
            self.grants[slot]
        );
        self.decisions[slot] = Some(decision);

        // Invariant: the bilateral decision can never split. If both directions
        // reached the boundary, they must have chosen the same relay form,
        // otherwise one would deposit its halves for a pair the other declined.
        if let (Some(uplink), Some(downlink)) = (self.decisions[0], self.decisions[1]) {
            assert_eq!(
                uplink, downlink,
                "the two directions split the raw relay decision"
            );
        }
    }

    /// Checks the properties that must hold for the whole finished sequence.
    fn check_final(&self) {
        for state in ALL_STATES {
            // Terminal absorption, rechecked exhaustively rather than only along
            // the fuzzed path.
            if reference_terminal(state) {
                for next in ALL_STATES {
                    assert!(!state.permits(next), "terminal {state:?} permits {next:?}");
                }
            }
            // Representation round trip: the runtime stores this state in one
            // atomic byte, so decoding must be lossless.
            assert_eq!(DirectionState::from_repr(state as u8), state);
        }

        for direction in [Direction::Uplink, Direction::Downlink] {
            let slot = Self::slot(direction);
            assert!(self.grants[slot] <= 1, "more than one grant survived");
            // A committed decision implies the direction actually left the raw
            // boundary, so it can never return to plan a second grant.
            if self.decisions[slot].is_some() {
                assert!(
                    !self.state(direction).permits(DirectionState::PairPending)
                        && !self.state(direction).permits(DirectionState::Relaying),
                    "{direction:?} can still re-enter a raw-relay commitment"
                );
            }
        }

        if let Some(transfer) = &self.transfer {
            transfer.check_final();
        }
    }
}

fuzz_target!(|bytes: &[u8]| {
    let mut unstructured = Unstructured::new(bytes);
    let Ok(input) = Input::arbitrary(&mut unstructured) else {
        return;
    };

    let mut session = Session::new();
    for event in input.events.into_iter().take(MAX_EVENTS) {
        match event {
            Event::Advance { direction, state } => {
                session.advance(
                    direction_of(direction),
                    DirectionState::from_repr(state % 8),
                );
            }
            Event::PlanRawRelay { direction } => {
                session.plan_raw_relay(direction_of(direction));
            }
            Event::BeginTransfer { warm } => {
                if let Some(previous) = &session.transfer {
                    previous.check_final();
                }
                session.transfer = Some(Transfer::begin(warm));
            }
            Event::WriteBoundary { written, length } => {
                if let Some(transfer) = &mut session.transfer {
                    transfer.write_boundary(usize::from(written), usize::from(length));
                }
            }
        }
    }
    session.check_final();
});
