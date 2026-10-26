//! Vision uplink framed + Direct-transition helpers.
//!
//! Internal to [`crate::server::vision`]: owns the uplink Vision-framed loop,
//! staging flush, and raw Direct handoff entry. Behavior-preserving
//! modularization only — no wire, crypto, or trust changes.

use std::{ops::Range, sync::Arc, time::Duration};

use tokio::{
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    time::Instant,
};

use crate::protocol::{
    reality::tls13::{
        IdleDeadline, MAX_PLAINTEXT_LEN, TlsApplicationIoError, TlsApplicationReader,
    },
    vless::{UserId, VisionDecoder, VisionMode, VisionPayload},
};
use crate::server::direct::{Direction, DirectionState, RawDecision};

use super::abort::{AbortableSocket as _, DirectionAbortGuard};
use super::error::{VisionSessionError, idle_failure};
use super::framing::length_u64;
use super::relay::{SessionContext, decide_raw_relay, run_directional, run_handoff, settle};
use super::stats::{BoundaryBytes, DirectionStats};

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
