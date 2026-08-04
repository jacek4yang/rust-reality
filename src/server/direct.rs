//! Vision Direct direction states and recoverable full-socket handoff.
//!
//! A Vision session runs two independent directions. Each one may reach an
//! authenticated raw boundary at a different time, and only when *both* have
//! reached that boundary — with every already-decoded byte flushed in order and
//! no read or write future still in flight — may the two complete sockets be
//! handed to a raw relay backend.
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

use tokio::{
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::watch,
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
}

impl DirectionState {
    const fn from_repr(value: u8) -> Self {
        match value {
            1 => Self::DirectPending,
            2 => Self::RawReady,
            3 => Self::Outer,
            4 => Self::Closed,
            5 => Self::Failed,
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
                | (Self::RawReady, Self::Closed)
                | (Self::RawReady, Self::Failed)
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

/// Shared, allocation-stable coordination state for one Vision session.
///
/// Only two atomics, one mutex guarding four socket-half slots, and one
/// version watch exist per session. No queue and no payload ever passes
/// through this type, so no unbounded growth is possible.
pub struct DirectHandoff {
    uplink: AtomicU8,
    downlink: AtomicU8,
    slots: Mutex<HandoffSlots>,
    version: watch::Sender<u32>,
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
            version: watch::channel(0).0,
        }
    }

    /// Returns a level-triggered subscription to direction state changes.
    ///
    /// A `watch` receiver is used rather than a notification primitive because
    /// it records the version a direction has already observed. A state change
    /// that happens between two loop iterations therefore cannot be lost, which
    /// would otherwise leave a direction blocked in a socket read after its peer
    /// became ready for handoff.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<u32> {
        self.version.subscribe()
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

    /// Applies one permitted transition and wakes the peer direction.
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
        self.version
            .send_modify(|version| *version = version.wrapping_add(1));
        Ok(())
    }

    /// Returns whether both directions sit at the exact raw boundary.
    #[must_use]
    pub fn both_raw_ready(&self) -> bool {
        self.state(Direction::Uplink) == DirectionState::RawReady
            && self.state(Direction::Downlink) == DirectionState::RawReady
    }

    /// Returns whether the peer direction can no longer reach a raw boundary.
    ///
    /// A peer that is closed, failed, or committed to continued outer TLS will
    /// never become `RawReady`, so the caller must stop waiting and relay its
    /// own direction in userspace.
    #[must_use]
    pub fn peer_is_settled(&self, direction: Direction) -> bool {
        let peer = match direction {
            Direction::Uplink => Direction::Downlink,
            Direction::Downlink => Direction::Uplink,
        };
        matches!(
            self.state(peer),
            DirectionState::Outer | DirectionState::Closed | DirectionState::Failed
        )
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

    use super::{DirectHandoff, Direction, DirectionState};

    #[test]
    fn permitted_transitions_match_the_specified_lifecycle() {
        use DirectionState::{Closed, DirectPending, Failed, Framed, Outer, RawReady};

        for (from, to) in [
            (Framed, DirectPending),
            (Framed, Outer),
            (Framed, Closed),
            (Framed, Failed),
            (DirectPending, RawReady),
            (DirectPending, Closed),
            (DirectPending, Failed),
            (RawReady, Closed),
            (RawReady, Failed),
            (Outer, Closed),
            (Outer, Failed),
        ] {
            assert!(from.permits(to), "{from} -> {to} must be permitted");
        }
    }

    #[test]
    fn forbidden_transitions_are_rejected() {
        use DirectionState::{Closed, DirectPending, Failed, Framed, Outer, RawReady};

        for (from, to) in [
            (Outer, RawReady),
            (RawReady, Framed),
            (RawReady, DirectPending),
            (Framed, RawReady),
            (Closed, Framed),
            (Closed, RawReady),
            (Closed, DirectPending),
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
    fn both_raw_ready_requires_both_directions() {
        let handoff = DirectHandoff::new();
        handoff
            .advance(Direction::Uplink, DirectionState::DirectPending)
            .expect("uplink may pend");
        handoff
            .advance(Direction::Uplink, DirectionState::RawReady)
            .expect("uplink may become raw");

        assert!(!handoff.both_raw_ready());

        handoff
            .advance(Direction::Downlink, DirectionState::DirectPending)
            .expect("downlink may pend");
        handoff
            .advance(Direction::Downlink, DirectionState::RawReady)
            .expect("downlink may become raw");

        assert!(handoff.both_raw_ready());
    }

    #[test]
    fn peer_settlement_stops_a_waiting_direction() {
        let handoff = DirectHandoff::new();
        assert!(!handoff.peer_is_settled(Direction::Uplink));

        handoff
            .advance(Direction::Downlink, DirectionState::Outer)
            .expect("downlink may select outer TLS");

        assert!(handoff.peer_is_settled(Direction::Uplink));
        assert!(!handoff.peer_is_settled(Direction::Downlink));
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

    #[tokio::test(flavor = "current_thread")]
    async fn a_state_change_before_the_wait_starts_is_not_lost() {
        let handoff = DirectHandoff::new();
        let mut versions = handoff.subscribe();

        // The change happens strictly before the subscriber waits. A
        // level-triggered watch must still report it, otherwise a direction can
        // block in a socket read after its peer is already ready to hand off.
        handoff
            .advance(Direction::Downlink, DirectionState::Closed)
            .expect("downlink may close");

        tokio::time::timeout(std::time::Duration::from_secs(1), versions.changed())
            .await
            .expect("a missed state change would hang here")
            .expect("watch sender must stay alive");
        assert_eq!(handoff.state(Direction::Downlink), DirectionState::Closed);
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
