//! Vision downlink framed + Direct-transition helpers.
//!
//! Internal to [`crate::server::vision`]: owns the downlink Vision-framed loop,
//! nested TLS observation, and raw Direct handoff entry. Behavior-preserving
//! modularization only — no wire, crypto, or trust changes.

use std::sync::Arc;

use tokio::{
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    time::Instant,
};

use crate::protocol::{
    reality::tls13::{IdleDeadline, TlsApplicationWriter},
    vless::{UserId, VisionCommand, VisionEncoder},
};
use crate::server::direct::{Direction, DirectionState, RawDecision};

use super::abort::{AbortableSocket as _, DirectionAbortGuard};
use super::error::{VisionSessionError, idle_failure};
use super::framing::{length_u64, relay_outer_downlink, write_vision_content};
use super::relay::{SessionContext, decide_raw_relay, run_directional, run_handoff, settle};
use super::stats::{BoundaryBytes, DirectionStats};
use super::{NestedRead, NestedRecordReader, NestedTlsDetector, PaddingDecision};

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
