//! Vision frame write and outer-record packing helpers.
//!
//! Internal to [`crate::server::vision`]: packs authenticated Vision frames into
//! TLS application records and relays post-`End` outer downlink bytes without
//! changing wire image or steady-state allocation behavior.

use std::time::Duration;

use tokio::io::AsyncWrite;

use crate::protocol::{
    reality::tls13::{MAX_PLAINTEXT_LEN, TlsApplicationWriter, VectoredRead},
    vless::{VISION_FRAME_SIZE, VisionCommand, VisionEncoder},
};

use super::error::VisionSessionError;

const VISION_HEADER_SIZE: usize = 5;
const MAX_VISION_CONTENT_AFTER_FIRST_FRAME: usize = VISION_FRAME_SIZE - VISION_HEADER_SIZE;

/// Upper bound of Vision frames packed into one outer TLS record.
///
/// Full content chunks are `MAX_VISION_CONTENT_AFTER_FIRST_FRAME` bytes, so at
/// most two full frames ever fit one maximum-sized record; the constant only
/// bounds the on-stack plan storage, never the wire image.
const MAX_FRAMES_PER_OUTER_RECORD: usize = 4;

pub(super) async fn write_vision_content<W>(
    writer: &mut TlsApplicationWriter<W>,
    encoder: &mut VisionEncoder,
    content: &[u8],
    final_command: VisionCommand,
    long_padding: bool,
    timeout: Duration,
) -> Result<(), VisionSessionError>
where
    W: AsyncWrite + Unpin,
{
    if content.is_empty() {
        return write_vision_frame(writer, encoder, &[], final_command, long_padding, timeout)
            .await;
    }

    let chunk_count = content.len().div_ceil(MAX_VISION_CONTENT_AFTER_FIRST_FRAME);
    let mut index = 0;
    while index < chunk_count {
        // Pack as many complete frames as fit one maximum-sized outer record.
        // Every frame stays a complete Xray padding block, so the plaintext
        // byte stream a client decoder sees is identical; only the outer
        // record boundaries move, which TLS explicitly does not preserve.
        let mut plans = [None; MAX_FRAMES_PER_OUTER_RECORD];
        let mut ranges = [(0_usize, 0_usize); MAX_FRAMES_PER_OUTER_RECORD];
        let mut wire_len = 0_usize;
        let mut packed = 0_usize;
        while packed < MAX_FRAMES_PER_OUTER_RECORD && index + packed < chunk_count {
            let start = (index + packed) * MAX_VISION_CONTENT_AFTER_FIRST_FRAME;
            let end = content
                .len()
                .min(start + MAX_VISION_CONTENT_AFTER_FIRST_FRAME);
            let command = if index + packed + 1 == chunk_count {
                final_command
            } else {
                VisionCommand::Continue
            };
            let Some(plan) = encoder
                .plan_within(
                    end - start,
                    command,
                    long_padding,
                    MAX_PLAINTEXT_LEN - wire_len,
                )
                .map_err(VisionSessionError::VisionEncode)?
            else {
                break;
            };
            wire_len = wire_len.saturating_add(plan.wire_len());
            plans[packed] = Some(plan);
            ranges[packed] = (start, end);
            packed += 1;
        }
        writer
            .write_assembled(
                wire_len,
                |destination| {
                    let mut cursor = 0;
                    for slot in 0..packed {
                        let Some(plan) = plans[slot] else {
                            continue;
                        };
                        let (start, end) = ranges[slot];
                        let Some(frame) = destination.get_mut(cursor..cursor + plan.wire_len())
                        else {
                            return;
                        };
                        let Some(chunk) = content.get(start..end) else {
                            return;
                        };
                        encoder.assemble(&plan, chunk, frame);
                        cursor += plan.wire_len();
                    }
                },
                timeout,
            )
            .await
            .map_err(VisionSessionError::Tls)?;
        for plan in plans.iter().take(packed).flatten() {
            encoder.commit(plan);
        }
        index += packed;
    }
    Ok(())
}

/// Writes exactly one Vision frame straight into the final TLS AEAD plaintext.
///
/// No intermediate frame buffer exists: the frame is planned, the record layer
/// reserves the plaintext region inside the writer's retained ciphertext buffer,
/// and the encoder assembles UUID, header, content and padding in place.
pub(super) async fn write_vision_frame<W>(
    writer: &mut TlsApplicationWriter<W>,
    encoder: &mut VisionEncoder,
    content: &[u8],
    command: VisionCommand,
    long_padding: bool,
    timeout: Duration,
) -> Result<(), VisionSessionError>
where
    W: AsyncWrite + Unpin,
{
    let plan = encoder
        .plan(content.len(), command, long_padding)
        .map_err(VisionSessionError::VisionEncode)?;
    writer
        .write_assembled(
            plan.wire_len(),
            |frame| encoder.assemble(&plan, content, frame),
            timeout,
        )
        .await
        .map_err(VisionSessionError::Tls)?;
    encoder.commit(&plan);
    Ok(())
}

pub(super) async fn relay_outer_downlink<R, W>(
    reader: &mut R,
    writer: &mut TlsApplicationWriter<W>,
    timeout: Duration,
) -> Result<u64, VisionSessionError>
where
    R: VectoredRead,
    W: AsyncWrite + Unpin,
{
    let mut copied = 0_u64;
    loop {
        // The batched variant (experiment D11) lands one vectored destination
        // read in the plaintext regions of up to four record slots of the
        // connection's grow-only buffer, seals each filled slot in place, and
        // writes the contiguous sealed prefix with one write: no scratch
        // buffer and no per-chunk copy exist on this path, and a full batch
        // costs one read plus one write syscall instead of one per record.
        let read = writer
            .write_application_read_from_batched(reader, timeout)
            .await
            .map_err(VisionSessionError::Tls)?;
        if read == 0 {
            writer
                .shutdown(timeout)
                .await
                .map_err(VisionSessionError::Tls)?;
            return Ok(copied);
        }
        copied = copied.saturating_add(length_u64(read));
    }
}

pub(super) fn length_u64(length: usize) -> u64 {
    u64::try_from(length).unwrap_or(u64::MAX)
}
