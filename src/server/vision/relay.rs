//! Vision directional relay helpers (framed + Direct handoff).
//!
//! Internal to [`crate::server::vision`]: owns per-session relay context and the
//! uplink/downlink framed loops, Direct transition, and raw handoff runners.
//! Behavior-preserving modularization only — no wire, crypto, or trust changes.

use std::{ops::Range, sync::Arc, time::Duration};

use tokio::{
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    time::Instant,
};

use rr_session::{PairRendezvous, RendezvousStep};

use crate::io_activity::{SESSION_IDLE_WINDOW, SessionActivity};
use crate::protocol::{
    reality::tls13::{
        IdleDeadline, MAX_PLAINTEXT_LEN, TlsApplicationIoError, TlsApplicationReader,
        TlsApplicationWriter,
    },
    vless::{UserId, VisionCommand, VisionDecoder, VisionEncoder, VisionMode, VisionPayload},
};
use crate::server::direct::{
    DirectHandoff, Direction, DirectionState, InvalidTransition, RawDecision, RawRelayGrant,
};
use crate::transport::{DirectionalRelayContext, RelayContext, RelayDirection, TcpRelay};

use super::abort::{AbortableSocket as _, DirectionAbortGuard};
use super::error::{VisionSessionError, idle_failure, is_benign_teardown};
use super::framing::{length_u64, relay_outer_downlink, write_vision_content};
use super::stats::{BoundaryBytes, DirectionStats};
use super::{NestedRead, NestedRecordReader, NestedTlsDetector, PaddingDecision};

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

/// Owns the uplink sockets so the abort guard can only ever borrow live ones.
///
/// The framed loop borrows them; on error or cancellation the guard drops
/// first — the borrow checker guarantees it cannot outlive what it borrows —
/// and resets sockets that are still open. Only when the framed phase asks for
/// the Direct transition does ownership leave this frame, and by then the
/// guard is gone and the raw relay owns abort semantics.
pub(super) async fn relay_uplink(
    mut client: TlsApplicationReader<OwnedReadHalf>,
    mut destination: OwnedWriteHalf,
    user_id: UserId,
    request_buffer: Vec<u8>,
    prefetched: Range<usize>,
    context: &SessionContext<'_>,
) -> Result<DirectionStats, VisionSessionError> {
    client.set_activity(Arc::clone(context.activity));
    let step = {
        let mut guard = DirectionAbortGuard::new(&mut client, &mut destination);
        let (client, destination) = guard.parts_mut();
        let step = relay_uplink_framed(
            client,
            destination,
            user_id,
            request_buffer,
            prefetched,
            context,
        )
        .await;
        if step.is_ok() {
            guard.disarm();
        }
        step
    };
    match step {
        Ok(UplinkStep::Framed(stats)) => Ok(stats),
        Ok(UplinkStep::Direct { bytes }) => {
            finish_uplink_direct(client, destination, bytes, context).await
        }
        Err(error) => {
            // The guard reset both sockets while they were provably live.
            // Release them without tokio's shutdown-on-drop so the abortive
            // close is not preceded by a FIN the peer would read as a clean
            // end of stream.
            client.release_aborted();
            destination.release_aborted();
            Err(error)
        }
    }
}

/// What the framed uplink phase decided.
enum UplinkStep {
    /// The direction finished inside the framed protocol.
    Framed(DirectionStats),
    /// An authenticated Direct boundary was reached after `bytes` framed bytes;
    /// the caller owns the sockets and performs the raw transfer.
    Direct { bytes: u64 },
}

async fn relay_uplink_framed(
    client: &mut TlsApplicationReader<OwnedReadHalf>,
    destination: &mut OwnedWriteHalf,
    user_id: UserId,
    request_buffer: Vec<u8>,
    prefetched: Range<usize>,
    context: &SessionContext<'_>,
) -> Result<UplinkStep, VisionSessionError> {
    let SessionContext {
        timeout, handoff, ..
    } = *context;
    let mut decoder = VisionDecoder::new(user_id);
    // Decoded uplink payloads are staged across records and leave in one
    // destination write per batch: Xray's Vision client emits one 8 KiB
    // frame per record, so an unbatched framed uplink costs one 8 KiB write
    // syscall per record while the batched downlink writes four records per
    // syscall. The staging buffer starts at one record payload and only a
    // completely-full staging buffer — evidence of a bulk flow — grows the
    // connection to the batched layout once, following the lazy-growth
    // discipline of the downlink's batched record storage; idle or
    // small-flow connections never pay the extra capacity.
    let mut stage = Vec::new();
    stage
        .try_reserve_exact(MAX_PLAINTEXT_LEN)
        .map_err(|_| VisionSessionError::AllocationFailed)?;
    let mut idle = IdleDeadline::new();
    idle.set_activity(Arc::clone(context.activity));
    let mut bytes = 0_u64;

    // The prefetched payload is a borrowed range inside the retained request
    // buffer. It is decoded before the record loop starts so that the loop below
    // never has to reconcile two different input lifetimes, and so that no copy
    // of the payload is ever made.
    if let Some(initial) = request_buffer.get(prefetched.clone())
        && !initial.is_empty()
    {
        let mode = decoder
            .decode_append(initial, &mut stage)
            .map_err(VisionSessionError::VisionDecode)?;
        flush_uplink(&mut stage, destination, &mut idle, timeout, &mut bytes).await?;
        if mode == VisionMode::Direct {
            // The caller owns the sockets and performs the transfer; the guard
            // it holds is disarmed on this `Ok`, so abort authority passes to
            // the raw relay with no window in which nobody owns it.
            return Ok(UplinkStep::Direct { bytes });
        }
    }
    drop(request_buffer);

    loop {
        // Flush before any read that could block: while a complete record is
        // still buffered the loop keeps batching, and a sparse flow never
        // waits behind staged bytes.
        if !client.has_buffered_record() {
            flush_uplink(&mut stage, destination, &mut idle, timeout, &mut bytes).await?;
        }
        let record = match client.read_application(timeout).await {
            Ok(record) => record,
            Err(TlsApplicationIoError::PeerAlert {
                level: _,
                description: 0,
            }) => {
                flush_uplink(&mut stage, destination, &mut idle, timeout, &mut bytes).await?;
                idle.reset(timeout).map_err(idle_failure)?;
                idle.shutdown(destination).await.map_err(idle_failure)?;
                settle(handoff, Direction::Uplink, DirectionState::Closed);
                return Ok(UplinkStep::Framed(DirectionStats::framed(bytes)));
            }
            Err(error) => {
                settle(handoff, Direction::Uplink, DirectionState::Failed);
                return Err(VisionSessionError::Tls(error));
            }
        };
        if record.is_empty() {
            continue;
        }
        if stage.len() + record.len() > stage.capacity() {
            flush_uplink(&mut stage, destination, &mut idle, timeout, &mut bytes).await?;
            // A completely-full staging buffer is bulk-flow evidence: grow to
            // the batched layout exactly once and never shrink back.
            if stage.capacity() < UPLINK_STAGE_CAPACITY {
                stage
                    .try_reserve_exact(UPLINK_STAGE_CAPACITY - stage.capacity())
                    .map_err(|_| VisionSessionError::AllocationFailed)?;
            }
        }
        let (mode, payload) = decoder
            .decode_borrowed_append(record.plaintext(), &mut stage)
            .map_err(VisionSessionError::VisionDecode)?;
        if let VisionPayload::Borrowed(content) = payload {
            // Raw-mode records join the batch as well: one bounded copy per
            // record replaces one destination write syscall per record. The
            // borrow of the record storage ends before the next read or the
            // socket handoff.
            stage.extend_from_slice(content);
        }
        if mode == VisionMode::Direct {
            // The decoded bytes precede every raw byte finish_uplink_direct
            // drains, so the staging buffer is flushed first; see the
            // prefetched branch above for the ownership handoff.
            flush_uplink(&mut stage, destination, &mut idle, timeout, &mut bytes).await?;
            return Ok(UplinkStep::Direct { bytes });
        }
    }
}

/// Capacity of the uplink staging buffer after a bulk flow grows it.
///
/// Four maximum-sized record payloads per destination write, mirroring the
/// downlink's four-slot batching (experiment D11).
const UPLINK_STAGE_CAPACITY: usize = 4 * MAX_PLAINTEXT_LEN;

/// Writes the staged uplink payloads to the destination in one operation.
///
/// Staged bytes are counted exactly once, when they are on the wire; the
/// staging buffer keeps its capacity across flushes. An empty staging buffer
/// costs no timer registration and no syscall.
async fn flush_uplink(
    stage: &mut Vec<u8>,
    destination: &mut OwnedWriteHalf,
    idle: &mut IdleDeadline,
    timeout: Duration,
    bytes: &mut u64,
) -> Result<(), VisionSessionError> {
    if stage.is_empty() {
        return Ok(());
    }
    idle.reset(timeout).map_err(idle_failure)?;
    idle.write_all(destination, stage.as_slice())
        .await
        .map_err(idle_failure)?;
    *bytes = bytes.saturating_add(length_u64(stage.len()));
    stage.clear();
    Ok(())
}

/// Relays the raw uplink after an authenticated Direct boundary.
///
/// Every decoded plaintext byte was already written to the destination in order
/// by the caller, so this direction is at the exact raw boundary. The buffered
/// reader behind `client` may already hold post-boundary raw bytes the client
/// pipelined after its boundary record; this is the re-derived equivalent of
/// Xray's input/rawInput drain: those pending bytes are written to the
/// destination first, so they arrive ahead of every byte any raw relay moves.
///
/// The direction then decides exactly once, after the bounded pair window
/// [`decide_raw_relay`]: when the peer is at its own raw boundary or already
/// committed to the pair, this direction deposits its halves for the bilateral
/// relay; otherwise it relays the direction independently. Neither branch ever
/// waits for the peer.
async fn finish_uplink_direct(
    client: TlsApplicationReader<OwnedReadHalf>,
    mut destination: OwnedWriteHalf,
    bytes: u64,
    context: &SessionContext<'_>,
) -> Result<DirectionStats, VisionSessionError> {
    let SessionContext {
        timeout, handoff, ..
    } = *context;
    let handoff_started = Instant::now();
    handoff
        .advance(Direction::Uplink, DirectionState::DirectPending)
        .map_err(VisionSessionError::DirectTransition)?;

    // Drain first, then declare the raw boundary: the pending bytes precede
    // every byte the pair or directional relay will move.
    let (pending, raw_client) = client.into_inner_with_pending();
    if !pending.is_empty() {
        let mut idle = IdleDeadline::new();
        idle.set_activity(Arc::clone(context.activity));
        idle.reset(timeout).map_err(idle_failure)?;
        idle.write_all(&mut destination, &pending)
            .await
            .map_err(idle_failure)?;
    }
    let total = bytes.saturating_add(length_u64(pending.len()));
    handoff
        .advance(Direction::Uplink, DirectionState::RawReady)
        .map_err(VisionSessionError::DirectTransition)?;

    match decide_raw_relay(handoff, Direction::Uplink)
        .await
        .map_err(VisionSessionError::DirectTransition)?
        .into_decision()
    {
        RawDecision::Pair => {
            let recovered = handoff
                .deposit_uplink(raw_client, destination)
                .map_err(VisionSessionError::Handoff)?;
            run_handoff(
                context,
                Direction::Uplink,
                recovered,
                BoundaryBytes {
                    total,
                    direct_at: bytes,
                },
                handoff_started,
            )
            .await
        }
        RawDecision::Directional => {
            run_directional(
                context,
                Direction::Uplink,
                raw_client,
                destination,
                BoundaryBytes {
                    total,
                    direct_at: bytes,
                },
                handoff_started,
            )
            .await
        }
    }
}

/// Owns the downlink sockets so the abort guard can only ever borrow live ones.
///
/// The mirror of [`relay_uplink`]: the framed phase borrows, the guard cannot
/// outlive what it borrows, and ownership leaves this frame only for the
/// Direct transition, after the guard is gone.
pub(super) async fn relay_downlink(
    destination: OwnedReadHalf,
    mut client: TlsApplicationWriter<OwnedWriteHalf>,
    user_id: UserId,
    response_header: &[u8],
    context: &SessionContext<'_>,
) -> Result<DirectionStats, VisionSessionError> {
    client.set_activity(Arc::clone(context.activity));
    let mut nested = NestedRecordReader::new(destination);
    nested.idle.set_activity(Arc::clone(context.activity));
    let step = {
        let mut guard = DirectionAbortGuard::new(&mut client, &mut nested);
        let (client, destination) = guard.parts_mut();
        let step =
            relay_downlink_framed(destination, client, user_id, response_header, context).await;
        if step.is_ok() {
            guard.disarm();
        }
        step
    };
    match step {
        Ok(DownlinkStep::Framed(stats)) => Ok(stats),
        Ok(DownlinkStep::Direct { bytes }) => {
            finish_downlink_direct(nested, client, bytes, context).await
        }
        Err(error) => {
            // See `relay_uplink`: the reset is already armed, and this is what
            // keeps a FIN from reaching the peer ahead of it.
            client.release_aborted();
            nested.release_aborted();
            Err(error)
        }
    }
}

/// What the framed downlink phase decided.
enum DownlinkStep {
    /// The direction finished inside the framed protocol.
    Framed(DirectionStats),
    /// An authenticated Direct boundary was reached after `bytes` framed bytes;
    /// the caller owns the sockets and performs the raw transfer.
    Direct { bytes: u64 },
}

async fn relay_downlink_framed(
    destination: &mut NestedRecordReader,
    client: &mut TlsApplicationWriter<OwnedWriteHalf>,
    user_id: UserId,
    response_header: &[u8],
    context: &SessionContext<'_>,
) -> Result<DownlinkStep, VisionSessionError> {
    let SessionContext {
        timeout, handoff, ..
    } = *context;
    let mut encoder = VisionEncoder::new(user_id).map_err(VisionSessionError::VisionEncode)?;
    // The VLESS response header and the opening Vision frame are assembled once,
    // directly inside the final AEAD plaintext region.
    let preamble = encoder
        .plan(0, VisionCommand::Continue, true)
        .map_err(VisionSessionError::VisionEncode)?;
    let preamble_len = response_header
        .len()
        .checked_add(preamble.wire_len())
        .ok_or(VisionSessionError::AllocationFailed)?;
    client
        .write_assembled(
            preamble_len,
            |destination| {
                let Some((header, frame)) = destination.split_at_mut_checked(response_header.len())
                else {
                    return;
                };
                header.copy_from_slice(response_header);
                encoder.assemble(&preamble, &[], frame);
            },
            timeout,
        )
        .await
        .map_err(VisionSessionError::Tls)?;
    encoder.commit(&preamble);

    let mut detector = NestedTlsDetector::new();
    let mut bytes = 0_u64;
    loop {
        match destination.next(timeout).await? {
            NestedRead::Eof => {
                client
                    .shutdown(timeout)
                    .await
                    .map_err(VisionSessionError::Tls)?;
                settle(handoff, Direction::Downlink, DirectionState::Closed);
                return Ok(DownlinkStep::Framed(DirectionStats::framed(bytes)));
            }
            NestedRead::Unframed(content) => {
                bytes = bytes.saturating_add(length_u64(content.len()));
                write_vision_content(
                    client,
                    &mut encoder,
                    content,
                    VisionCommand::End,
                    false,
                    timeout,
                )
                .await?;
                settle(handoff, Direction::Downlink, DirectionState::Outer);
                bytes =
                    bytes.saturating_add(relay_outer_downlink(destination, client, timeout).await?);
                settle(handoff, Direction::Downlink, DirectionState::Closed);
                return Ok(DownlinkStep::Framed(DirectionStats::framed(bytes)));
            }
            NestedRead::Record(record) => {
                bytes = bytes.saturating_add(length_u64(record.len()));
                let decision = detector.observe(record);
                let command = match decision {
                    PaddingDecision::Continue => VisionCommand::Continue,
                    PaddingDecision::End => VisionCommand::End,
                    PaddingDecision::Direct => VisionCommand::Direct,
                };
                write_vision_content(client, &mut encoder, record, command, true, timeout).await?;

                match decision {
                    PaddingDecision::Continue => {}
                    PaddingDecision::End => {
                        settle(handoff, Direction::Downlink, DirectionState::Outer);
                        bytes = bytes.saturating_add(
                            relay_outer_downlink(destination, client, timeout).await?,
                        );
                        settle(handoff, Direction::Downlink, DirectionState::Closed);
                        return Ok(DownlinkStep::Framed(DirectionStats::framed(bytes)));
                    }
                    PaddingDecision::Direct => {
                        // The caller owns the sockets and performs the
                        // transfer; the guard it holds is disarmed on this
                        // `Ok`, so abort authority passes to the raw relay
                        // with no window in which nobody owns it.
                        return Ok(DownlinkStep::Direct { bytes });
                    }
                }
            }
        }
    }
}

/// Relays the raw downlink after an authenticated Direct boundary.
///
/// The Direct-carrying Vision frame has already been sealed and written to the
/// client, so this direction is at its exact raw boundary. Starting the raw
/// relay only after that final framed write has fully completed is the ordering
/// Xray commit f926ee4a protects: a splice that raced the frame would
/// interleave raw bytes with framed ciphertext. The buffered nested reader may
/// already hold post-boundary raw bytes the destination pipelined after its
/// boundary record; like the uplink drain (the re-derived equivalent of Xray's
/// input/rawInput handling) those pending bytes are written to the client
/// first, ahead of every byte any raw relay moves.
///
/// The direction then decides exactly once, after the bounded pair window
/// [`decide_raw_relay`]: when the peer is at its own raw boundary or already
/// committed to the pair, this direction deposits its halves for the bilateral
/// relay; otherwise it relays the direction independently. Neither branch ever
/// waits for the peer.
async fn finish_downlink_direct(
    destination: NestedRecordReader,
    client: TlsApplicationWriter<OwnedWriteHalf>,
    bytes: u64,
    context: &SessionContext<'_>,
) -> Result<DirectionStats, VisionSessionError> {
    let SessionContext {
        timeout, handoff, ..
    } = *context;
    let handoff_started = Instant::now();
    handoff
        .advance(Direction::Downlink, DirectionState::DirectPending)
        .map_err(VisionSessionError::DirectTransition)?;

    // Drain first, then declare the raw boundary: the pending bytes precede
    // every byte the pair or directional relay will move.
    let (pending, raw_destination) = destination.into_inner_with_pending();
    let mut raw_client = client.into_inner();
    if !pending.is_empty() {
        let mut idle = IdleDeadline::new();
        idle.set_activity(Arc::clone(context.activity));
        idle.reset(timeout).map_err(idle_failure)?;
        idle.write_all(&mut raw_client, &pending)
            .await
            .map_err(idle_failure)?;
    }
    let total = bytes.saturating_add(length_u64(pending.len()));
    handoff
        .advance(Direction::Downlink, DirectionState::RawReady)
        .map_err(VisionSessionError::DirectTransition)?;

    match decide_raw_relay(handoff, Direction::Downlink)
        .await
        .map_err(VisionSessionError::DirectTransition)?
        .into_decision()
    {
        RawDecision::Pair => {
            let recovered = handoff
                .deposit_downlink(raw_destination, raw_client)
                .map_err(VisionSessionError::Handoff)?;
            run_handoff(
                context,
                Direction::Downlink,
                recovered,
                BoundaryBytes {
                    total,
                    direct_at: bytes,
                },
                handoff_started,
            )
            .await
        }
        RawDecision::Directional => {
            run_directional(
                context,
                Direction::Downlink,
                raw_destination,
                raw_client,
                BoundaryBytes {
                    total,
                    direct_at: bytes,
                },
                handoff_started,
            )
            .await
        }
    }
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
async fn run_handoff(
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
fn settle(handoff: &DirectHandoff, direction: Direction, state: DirectionState) {
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
async fn decide_raw_relay(
    handoff: &DirectHandoff,
    direction: Direction,
) -> Result<RawRelayGrant, InvalidTransition> {
    let mut rendezvous = PairRendezvous::new();
    while rendezvous.step(handoff.peer_can_pair(direction)) == RendezvousStep::Yield {
        tokio::task::yield_now().await;
    }
    handoff.decide(direction)
}
