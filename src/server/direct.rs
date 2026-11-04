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

pub use rr_session::{
    Direction, DirectionState, InvalidTransition, RawDecision, RawRelayGrant, RawRelayTransition,
};
use tokio::net::{
    TcpStream,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};

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
    pub fn decide(&self, direction: Direction) -> Result<RawRelayGrant, InvalidTransition> {
        let _guard = lock_recover(&self.slots);
        let transition = RawRelayTransition::plan(
            direction,
            self.state(direction),
            self.state(Self::peer(direction)),
        )?;
        self.advance(direction, transition.next_state())?;
        Ok(transition.into_grant())
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
mod tests;
