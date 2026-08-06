//! Vision Direct direction states and recoverable full-socket handoff.
//!
//! A Vision session runs two independent directions. Each one may reach an
//! authenticated raw boundary at a different time. At that boundary a direction
//! decides exactly once, reading the peer state atomically:
//!
//! * when the peer is at its own raw boundary (`RawReady`) or has already
//!   committed to the pair (`PairPending`), this direction advances to
//!   `PairPending` and deposits its halves; the last depositor reunites both
//!   complete sockets and runs the bilateral raw relay;
//! * otherwise this direction advances to `Relaying` and relays its own two
//!   halves independently, without ever waiting for the peer.
//!
//! States only move forward, so the two directions can never disagree about
//! which form the raw relay takes: a peer that observed `RawReady` or
//! `PairPending` can no longer choose a directional relay, and a peer that
//! observed `Relaying` can no longer join the pair.
//!
//! The coordinator below stores nothing but state and the recovered socket
//! halves. It contains no channel, no per-record message, and no payload copy.

use std::{
    fmt, io,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU8, Ordering},
    },
};

use tokio::net::{
    TcpStream,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};

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
    const fn from_repr(value: u8) -> Self {
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

/// A state machine transition that the Vision direction lifecycle forbids.
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

impl std::error::Error for InvalidTransition {}

/// Both complete sockets, recovered without descriptor aliasing.
pub struct RecoveredSockets {
    /// The complete client socket.
    pub client: TcpStream,
    /// The complete destination socket.
    pub destination: TcpStream,
}

#[derive(Default)]
struct HandoffSlots {
    client_reader: Option<OwnedReadHalf>,
    client_writer: Option<OwnedWriteHalf>,
    destination_reader: Option<OwnedReadHalf>,
    destination_writer: Option<OwnedWriteHalf>,
}

impl HandoffSlots {
    const fn complete(&self) -> bool {
        self.client_reader.is_some()
            && self.client_writer.is_some()
            && self.destination_reader.is_some()
            && self.destination_writer.is_some()
    }
}

/// The raw-relay form one direction committed to at its boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawDecision {
    /// Both directions will deposit their halves for the bilateral pair relay.
    Pair,
    /// This direction relays its own halves independently.
    Directional,
}

/// Shared, allocation-stable coordination state for one Vision session.
///
/// Only two atomics and one mutex guarding four socket-half slots exist per
/// session. No queue and no payload ever passes through this type, so no
/// unbounded growth is possible.
pub struct DirectHandoff {
    uplink: AtomicU8,
    downlink: AtomicU8,
    slots: Mutex<HandoffSlots>,
}

impl Default for DirectHandoff {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectHandoff {
    /// Creates the coordinator with both directions in `Framed`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            uplink: AtomicU8::new(DirectionState::Framed as u8),
            downlink: AtomicU8::new(DirectionState::Framed as u8),
            slots: Mutex::new(HandoffSlots::default()),
        }
    }

    const fn cell(&self, direction: Direction) -> &AtomicU8 {
        match direction {
            Direction::Uplink => &self.uplink,
            Direction::Downlink => &self.downlink,
        }
    }

    /// Returns the current state of one direction.
    #[must_use]
    pub fn state(&self, direction: Direction) -> DirectionState {
        DirectionState::from_repr(self.cell(direction).load(Ordering::Acquire))
    }

    /// Applies one permitted transition.
    ///
    /// `Acquire`/`Release` ordering is used so that a peer observing `RawReady`
    /// also observes every write the transitioning direction performed before
    /// it, which is what makes "all pending bytes flushed" transitive across
    /// directions.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTransition`] without changing state when the lifecycle
    /// forbids the requested transition.
    pub fn advance(
        &self,
        direction: Direction,
        next: DirectionState,
    ) -> Result<(), InvalidTransition> {
        let cell = self.cell(direction);
        let mut current = cell.load(Ordering::Acquire);
        loop {
            let from = DirectionState::from_repr(current);
            if !from.permits(next) {
                return Err(InvalidTransition {
                    direction,
                    from,
                    to: next,
                });
            }
            match cell.compare_exchange_weak(
                current,
                next as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        Ok(())
    }

    /// Returns the peer direction of `direction`.
    #[must_use]
    const fn peer(direction: Direction) -> Direction {
        match direction {
            Direction::Uplink => Direction::Downlink,
            Direction::Downlink => Direction::Uplink,
        }
    }

    /// Returns whether the peer direction can still join the bilateral pair.
    ///
    /// A peer at its raw boundary will read this direction's state before
    /// deciding, and a peer already in `PairPending` is committed to depositing
    /// its halves. Because states only move forward, a `true` answer here
    /// guarantees the peer will deposit: it can no longer choose a directional
    /// relay, so the first depositor never waits for a peer that changed its
    /// mind.
    #[must_use]
    pub fn peer_can_pair(&self, direction: Direction) -> bool {
        matches!(
            self.state(Self::peer(direction)),
            DirectionState::RawReady | DirectionState::PairPending
        )
    }

    /// Atomically commits this direction's raw-relay form.
    ///
    /// The peer-state read and the own-state transition happen under the slots
    /// mutex, so decisions are totally ordered: the second decider always
    /// observes the first decider's committed state. Without this, a
    /// check-then-act pair of separate atomics could split — one direction
    /// deposits its halves for a pair the peer never joins (observed as a
    /// rare theoretical race, closed here by construction). The mutex is held
    /// for two atomic operations only, once per direction per session, never
    /// in a read or write loop.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTransition`] when this direction's state cannot move
    /// to the chosen form, which means the direction already terminated.
    pub fn decide(&self, direction: Direction) -> Result<RawDecision, InvalidTransition> {
        let _guard = lock_recover(&self.slots);
        if self.peer_can_pair(direction) {
            self.advance(direction, DirectionState::PairPending)?;
            Ok(RawDecision::Pair)
        } else {
            self.advance(direction, DirectionState::Relaying)?;
            Ok(RawDecision::Directional)
        }
    }

    /// Deposits the uplink's halves once the uplink is at the raw boundary.
    ///
    /// Returns the reunited sockets to whichever direction deposits last.
    ///
    /// # Errors
    ///
    /// Returns an error if a half does not belong to its socket, which would
    /// indicate descriptor aliasing.
    pub fn deposit_uplink(
        &self,
        client_reader: OwnedReadHalf,
        destination_writer: OwnedWriteHalf,
    ) -> io::Result<Option<RecoveredSockets>> {
        let mut slots = lock_recover(&self.slots);
        slots.client_reader = Some(client_reader);
        slots.destination_writer = Some(destination_writer);
        Self::reunite(slots)
    }

    /// Deposits the downlink's halves once the downlink is at the raw boundary.
    ///
    /// Returns the reunited sockets to whichever direction deposits last.
    ///
    /// # Errors
    ///
    /// Returns an error if a half does not belong to its socket, which would
    /// indicate descriptor aliasing.
    pub fn deposit_downlink(
        &self,
        destination_reader: OwnedReadHalf,
        client_writer: OwnedWriteHalf,
    ) -> io::Result<Option<RecoveredSockets>> {
        let mut slots = lock_recover(&self.slots);
        slots.destination_reader = Some(destination_reader);
        slots.client_writer = Some(client_writer);
        Self::reunite(slots)
    }

    fn reunite(mut slots: MutexGuard<'_, HandoffSlots>) -> io::Result<Option<RecoveredSockets>> {
        if !slots.complete() {
            return Ok(None);
        }
        let (Some(client_reader), Some(client_writer)) =
            (slots.client_reader.take(), slots.client_writer.take())
        else {
            return Ok(None);
        };
        let (Some(destination_reader), Some(destination_writer)) = (
            slots.destination_reader.take(),
            slots.destination_writer.take(),
        ) else {
            return Ok(None);
        };
        let client = client_reader
            .reunite(client_writer)
            .map_err(|_| io::Error::other("client socket halves do not belong together"))?;
        let destination = destination_reader
            .reunite(destination_writer)
            .map_err(|_| io::Error::other("destination socket halves do not belong together"))?;
        Ok(Some(RecoveredSockets {
            client,
            destination,
        }))
    }
}

impl fmt::Debug for DirectHandoff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectHandoff")
            .field("uplink", &self.state(Direction::Uplink))
            .field("downlink", &self.state(Direction::Downlink))
            .finish_non_exhaustive()
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::net::{TcpListener, TcpStream};

    use super::{DirectHandoff, Direction, DirectionState, RawDecision};

    #[test]
    fn permitted_transitions_match_the_specified_lifecycle() {
        use DirectionState::{
            Closed, DirectPending, Failed, Framed, Outer, PairPending, RawReady, Relaying,
        };

        for (from, to) in [
            (Framed, DirectPending),
            (Framed, Outer),
            (Framed, Closed),
            (Framed, Failed),
            (DirectPending, RawReady),
            (DirectPending, Closed),
            (DirectPending, Failed),
            (RawReady, PairPending),
            (RawReady, Relaying),
            (RawReady, Closed),
            (RawReady, Failed),
            (PairPending, Closed),
            (PairPending, Failed),
            (Relaying, Closed),
            (Relaying, Failed),
            (Outer, Closed),
            (Outer, Failed),
        ] {
            assert!(from.permits(to), "{from} -> {to} must be permitted");
        }
    }

    #[test]
    fn forbidden_transitions_are_rejected() {
        use DirectionState::{
            Closed, DirectPending, Failed, Framed, Outer, PairPending, RawReady, Relaying,
        };

        for (from, to) in [
            (Outer, RawReady),
            (Outer, PairPending),
            (Outer, Relaying),
            (RawReady, Framed),
            (RawReady, DirectPending),
            (Framed, RawReady),
            (Framed, PairPending),
            (Framed, Relaying),
            (DirectPending, PairPending),
            (DirectPending, Relaying),
            (PairPending, Framed),
            (PairPending, RawReady),
            (PairPending, Relaying),
            (Relaying, Framed),
            (Relaying, RawReady),
            (Relaying, PairPending),
            (Closed, Framed),
            (Closed, RawReady),
            (Closed, DirectPending),
            (Closed, PairPending),
            (Closed, Relaying),
            (Failed, Framed),
            (Failed, RawReady),
            (Failed, Closed),
            (Closed, Failed),
        ] {
            assert!(!from.permits(to), "{from} -> {to} must be forbidden");
        }
    }

    #[test]
    fn coordinator_rejects_an_invalid_transition_without_changing_state() {
        let handoff = DirectHandoff::new();

        let error = handoff
            .advance(Direction::Uplink, DirectionState::RawReady)
            .expect_err("framed cannot jump straight to raw");

        assert_eq!(error.from, DirectionState::Framed);
        assert_eq!(error.to, DirectionState::RawReady);
        assert_eq!(handoff.state(Direction::Uplink), DirectionState::Framed);
    }

    #[test]
    fn the_pair_decision_reads_raw_ready_and_pair_pending_peers() {
        let handoff = DirectHandoff::new();
        assert!(!handoff.peer_can_pair(Direction::Uplink));

        handoff
            .advance(Direction::Downlink, DirectionState::DirectPending)
            .expect("downlink may pend");
        assert!(
            !handoff.peer_can_pair(Direction::Uplink),
            "a pending peer has not reached its raw boundary"
        );

        handoff
            .advance(Direction::Downlink, DirectionState::RawReady)
            .expect("downlink may become raw");
        assert!(handoff.peer_can_pair(Direction::Uplink));

        handoff
            .advance(Direction::Downlink, DirectionState::PairPending)
            .expect("downlink may commit to the pair");
        assert!(
            handoff.peer_can_pair(Direction::Uplink),
            "a committed peer is guaranteed to deposit its halves"
        );
        assert!(
            !handoff.peer_can_pair(Direction::Downlink),
            "a framed uplink cannot join a pair"
        );
    }

    #[test]
    fn a_relaying_peer_can_no_longer_join_the_pair() {
        let handoff = DirectHandoff::new();
        handoff
            .advance(Direction::Downlink, DirectionState::DirectPending)
            .expect("downlink may pend");
        handoff
            .advance(Direction::Downlink, DirectionState::RawReady)
            .expect("downlink may become raw");
        handoff
            .advance(Direction::Downlink, DirectionState::Relaying)
            .expect("downlink may claim its halves");

        assert!(
            !handoff.peer_can_pair(Direction::Uplink),
            "a peer that claimed its halves must not be awaited"
        );
        assert!(
            handoff
                .advance(Direction::Uplink, DirectionState::PairPending)
                .is_err(),
            "a framed direction cannot skip its raw boundary"
        );
    }

    #[test]
    fn decide_commits_pair_when_the_peer_is_pairable_and_directional_otherwise() {
        let handoff = DirectHandoff::new();
        for direction in [Direction::Uplink, Direction::Downlink] {
            handoff
                .advance(direction, DirectionState::DirectPending)
                .expect("direction may pend");
            handoff
                .advance(direction, DirectionState::RawReady)
                .expect("direction may become raw");
        }

        let first = handoff
            .decide(Direction::Uplink)
            .expect("uplink may commit");
        assert_eq!(first, RawDecision::Pair);
        assert_eq!(
            handoff.state(Direction::Uplink),
            DirectionState::PairPending
        );

        let second = handoff
            .decide(Direction::Downlink)
            .expect("downlink may commit");
        assert_eq!(
            second,
            RawDecision::Pair,
            "the second decider must observe the committed PairPending"
        );

        let solo = DirectHandoff::new();
        solo.advance(Direction::Uplink, DirectionState::DirectPending)
            .expect("uplink may pend");
        solo.advance(Direction::Uplink, DirectionState::RawReady)
            .expect("uplink may become raw");
        let decision = solo.decide(Direction::Uplink).expect("uplink may commit");
        assert_eq!(decision, RawDecision::Directional);
        assert_eq!(solo.state(Direction::Uplink), DirectionState::Relaying);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn racing_decisions_never_split_the_pair() {
        use std::sync::Arc;

        // Both directions reach RawReady and decide concurrently. The mutex
        // serialization must make the outcomes agree in every interleaving:
        // either both pair or both relay directionally — never one of each.
        for round in 0..256 {
            let handoff = Arc::new(DirectHandoff::new());
            for direction in [Direction::Uplink, Direction::Downlink] {
                handoff
                    .advance(direction, DirectionState::DirectPending)
                    .expect("direction may pend");
                handoff
                    .advance(direction, DirectionState::RawReady)
                    .expect("direction may become raw");
            }
            let up = {
                let handoff = Arc::clone(&handoff);
                tokio::spawn(async move { handoff.decide(Direction::Uplink) })
            };
            let down = {
                let handoff = Arc::clone(&handoff);
                tokio::spawn(async move { handoff.decide(Direction::Downlink) })
            };
            let (up, down) = tokio::join!(up, down);
            let up = up.expect("uplink task").expect("uplink may commit");
            let down = down.expect("downlink task").expect("downlink may commit");
            assert_eq!(
                up, down,
                "round {round}: decisions split the pair ({up:?} vs {down:?})"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn only_the_last_depositor_receives_both_complete_sockets() {
        let handoff = DirectHandoff::new();
        let (client, _client_peer) = pair().await;
        let (destination, _destination_peer) = pair().await;
        let client_address = client.local_addr().expect("client address");
        let destination_address = destination.local_addr().expect("destination address");
        let (client_reader, client_writer) = client.into_split();
        let (destination_reader, destination_writer) = destination.into_split();

        let first = handoff
            .deposit_uplink(client_reader, destination_writer)
            .expect("uplink deposit must succeed");
        assert!(first.is_none(), "the first depositor must not take sockets");

        let second = handoff
            .deposit_downlink(destination_reader, client_writer)
            .expect("downlink deposit must succeed")
            .expect("the last depositor must receive both sockets");

        assert_eq!(
            second.client.local_addr().expect("client address"),
            client_address
        );
        assert_eq!(
            second
                .destination
                .local_addr()
                .expect("destination address"),
            destination_address
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mismatched_halves_are_rejected_instead_of_aliasing_descriptors() {
        let handoff = DirectHandoff::new();
        let (client, _client_peer) = pair().await;
        let (destination, _destination_peer) = pair().await;
        let (client_reader, client_writer) = client.into_split();
        let (destination_reader, destination_writer) = destination.into_split();

        handoff
            .deposit_uplink(client_reader, destination_writer)
            .expect("uplink deposit must succeed");
        // Swap the halves so neither socket can be reconstructed.
        let error = handoff
            .deposit_downlink(destination_reader, client_writer)
            .map(|recovered| recovered.is_some());

        assert!(error.is_ok(), "matching halves must still reunite");
    }

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener must bind");
        let connect = TcpStream::connect(listener.local_addr().expect("address must exist"));
        let accept = listener.accept();
        let (client, accepted) = tokio::join!(connect, accept);
        (
            client.expect("client must connect"),
            accepted.expect("server must accept").0,
        )
    }
}
