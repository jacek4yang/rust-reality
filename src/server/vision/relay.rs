//! Vision directional relay helpers (session context + raw Direct runners).
//!
//! Internal to [`crate::server::vision`]: owns per-session relay context, direction
//! join, and raw Direct handoff runners. Framed uplink/downlink loops live in
//! `relay_uplink` / `relay_downlink`. Behavior-preserving modularization only —
//! no wire, crypto, or trust changes.

use std::{sync::Arc, time::Duration};

use tokio::{
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    time::Instant,
};

use rr_session::{PairRendezvous, RendezvousStep};

use crate::io_activity::{SESSION_IDLE_WINDOW, SessionActivity};
use crate::server::direct::{
    DirectHandoff, Direction, DirectionState, InvalidTransition, RawRelayGrant,
};
use crate::transport::{DirectionalRelayContext, RelayContext, RelayDirection, TcpRelay};

use super::error::{VisionSessionError, is_benign_teardown};
use super::stats::{BoundaryBytes, DirectionStats};

pub(super) async fn join_directions(
    uplink: impl std::future::Future<Output = Result<DirectionStats, VisionSessionError>>,
    downlink: impl std::future::Future<Output = Result<DirectionStats, VisionSessionError>>,
    activity: &SessionActivity,
) -> Result<(DirectionStats, DirectionStats), VisionSessionError> {
    // A real EOF completes only its direction. Errors still cancel the pair
    // under the existing abort guards; quiet reads never manufacture an EOF.
    tokio::select! {
        biased;
        result = async { tokio::try_join!(uplink, downlink) } => result,
        () = activity.expired(SESSION_IDLE_WINDOW) => Err(VisionSessionError::Timeout),
    }
}

/// Immutable per-session state shared by both relay directions.
///
/// Bundling these three keeps the direction entry points inside the repository's
/// argument-count lint without hiding anything: the coordinator and the relay
/// are borrowed, never cloned per connection.
pub(super) struct SessionContext<'session> {
    pub(super) activity: &'session Arc<SessionActivity>,
    pub(super) timeout: Duration,
    pub(super) handoff: &'session DirectHandoff,
    pub(super) relay: &'session TcpRelay,
}

/// Runs one independent directional raw relay at a Direct boundary.
///
/// A benign peer-teardown race (`BrokenPipe`, `ConnectionReset`, or the raw
/// stage's idle-policy `TimedOut` on an untouched ledger) closes the
/// direction cleanly with its accumulated stats instead of failing the whole
/// session; a write_stall timeout after bytes moved aborts both sockets and
/// arrives as `ConnectionAborted`, failing the session. Errors from the
/// framed and authentication phases never reach here.
pub(super) async fn run_directional(
    context: &SessionContext<'_>,
    direction: Direction,
    source: OwnedReadHalf,
    destination: OwnedWriteHalf,
    bytes: BoundaryBytes,
    handoff_started: Instant,
) -> Result<DirectionStats, VisionSessionError> {
    let SessionContext {
        timeout,
        handoff,
        relay,
        ..
    } = *context;
    let delay_us = micros(handoff_started.elapsed());
    let relay_direction = match direction {
        Direction::Uplink => RelayDirection::Uplink,
        Direction::Downlink => RelayDirection::Downlink,
    };
    match relay
        .relay_direction(
            source,
            destination,
            relay_direction,
            DirectionalRelayContext::owned_direction()
                .with_write_stall(timeout)
                .with_activity(Arc::clone(context.activity)),
        )
        .await
    {
        Ok(outcome) => {
            settle(handoff, direction, DirectionState::Closed);
            Ok(DirectionStats::direct(
                bytes.total.saturating_add(outcome.bytes()),
                None,
                Some(outcome.backend()),
                bytes.direct_at,
                delay_us,
                outcome.pipe_downgrade().is_some(),
            ))
        }
        Err(error) if is_benign_teardown(&error) => {
            settle(handoff, direction, DirectionState::Closed);
            Ok(DirectionStats::direct(
                bytes.total,
                None,
                None,
                bytes.direct_at,
                delay_us,
                false,
            ))
        }
        Err(error) => {
            settle(handoff, direction, DirectionState::Failed);
            Err(VisionSessionError::Relay(error))
        }
    }
}

/// Runs the unified relay when this direction deposited its sockets last.
///
/// A `None` deposit means the peer direction still holds one half pair; that
/// peer becomes the last depositor and runs the relay instead. Exactly one of
/// the two directions therefore ever drives the raw relay. The first depositor
/// deliberately remains in `PairPending` rather than transitioning `Closed`:
/// a peer still inside its pair window must keep observing a pairable state
/// until it deposits — transitioning `Closed` here would strand the deposited
/// halves with no runner. The coordinator is per-session, so the lingering
/// state is dropped with it.
pub(super) async fn run_handoff(
    context: &SessionContext<'_>,
    direction: Direction,
    recovered: Option<crate::server::direct::RecoveredSockets>,
    bytes: BoundaryBytes,
    handoff_started: Instant,
) -> Result<DirectionStats, VisionSessionError> {
    let SessionContext {
        timeout,
        handoff,
        relay,
        ..
    } = *context;
    let delay_us = micros(handoff_started.elapsed());
    let Some(sockets) = recovered else {
        return Ok(DirectionStats::direct(
            bytes.total,
            None,
            None,
            bytes.direct_at,
            delay_us,
            false,
        ));
    };
    match relay
        .relay_owned(
            sockets.client,
            sockets.destination,
            RelayContext::owned()
                .with_write_stall(timeout)
                .with_activity(Arc::clone(context.activity)),
        )
        .await
    {
        Ok(outcome) => {
            settle(handoff, direction, DirectionState::Closed);
            Ok(DirectionStats::direct(
                bytes.total,
                Some(outcome),
                Some(outcome.backend()),
                bytes.direct_at,
                delay_us,
                outcome.pipe_downgrade().is_some(),
            ))
        }
        Err(error) if is_benign_teardown(&error) => {
            settle(handoff, direction, DirectionState::Closed);
            Ok(DirectionStats::direct(
                bytes.total,
                None,
                None,
                bytes.direct_at,
                delay_us,
                false,
            ))
        }
        Err(error) => {
            settle(handoff, direction, DirectionState::Failed);
            Err(VisionSessionError::Relay(error))
        }
    }
}

/// Converts a duration to microseconds, saturating at the representable bound.
fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

/// Records a terminal direction state without masking the original failure.
///
/// A rejected transition here means the direction was already terminal, which is
/// not itself an error worth replacing the real cause with.
pub(super) fn settle(handoff: &DirectHandoff, direction: Direction, state: DirectionState) {
    let _ignored = handoff.advance(direction, state);
}

/// Gives the peer a bounded chance to reach a pairable state, then commits.
///
/// This is the Runtime Adapter shape: the adapter observes shared state, the
/// Session Engine decides, the adapter performs the OS or executor operation.
/// [`PairRendezvous`] owns the policy — how many cooperative scheduling points
/// may be spent and when to stop observing — and this function owns only the
/// `yield_now` that the policy asks for. Never a sleep, a timer, or a wait on
/// the peer, so no direction depends on its peer for write_stall.
///
/// The commit itself is the mutex-serialized [`DirectHandoff::decide`]: the peer
/// read and the state transition are one critical section, so the two directions
/// can never disagree about the relay form — a peer that observed `RawReady` or
/// `PairPending` pairs, and a peer that observed `Relaying` relays
/// directionally, with no interleaving in between.
pub(super) async fn decide_raw_relay(
    handoff: &DirectHandoff,
    direction: Direction,
) -> Result<RawRelayGrant, InvalidTransition> {
    let mut rendezvous = PairRendezvous::new();
    while rendezvous.step(handoff.peer_can_pair(direction)) == RendezvousStep::Yield {
        tokio::task::yield_now().await;
    }
    handoff.decide(direction)
}
