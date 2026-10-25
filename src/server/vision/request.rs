//! Vision request acceptance: header decode bounds and accepted variants.
//!
//! Internal to [`crate::server::vision`]: parses the authenticated VLESS/Vision
//! request after REALITY and yields [`AcceptedVisionRequest`].

use std::{ops::Range, time::Duration};

use tokio::{io::AsyncRead, time::Instant};

use crate::protocol::{
    reality::tls13::{MAX_PLAINTEXT_LEN, TlsApplicationReader},
    vless::{
        Command, DecodeError, Destination, RequestValidationError, UserId,
        authorize_authenticated_vision_xudp, decode_request, decode_request_ref,
        validate_authenticated_vision_fields,
    },
};

use super::error::{VisionSessionError, operation_deadline};

const MAX_REQUEST_HEADER_SIZE: usize = 533;
const MAX_REQUEST_BUFFER_SIZE: usize = MAX_REQUEST_HEADER_SIZE + MAX_PLAINTEXT_LEN;

pub(super) enum AcceptedVisionRequest {
    /// Ordinary Vision TCP with a VLESS destination.
    Tcp {
        user_id: UserId,
        destination: Destination,
        /// The retained request buffer. Prefetched payload is a range inside it.
        buffer: Vec<u8>,
        prefetched: Range<usize>,
    },
    /// Vision XUDP (Mux command) — destination comes from the first XUDP New frame.
    Xudp {
        user_id: UserId,
        buffer: Vec<u8>,
        prefetched: Range<usize>,
    },
}

pub(super) async fn read_vision_request<R>(
    reader: &mut TlsApplicationReader<R>,
    authenticated_user_id: UserId,
    timeout: Duration,
) -> Result<AcceptedVisionRequest, VisionSessionError>
where
    R: AsyncRead + Unpin,
{
    let deadline = operation_deadline(timeout)?;
    // Small/setup-only sessions pay for the maximum header, not a speculative
    // full TLS record. A coalesced payload grows this same retained buffer on
    // demand and still stays under MAX_REQUEST_BUFFER_SIZE.
    let mut buffer = Vec::with_capacity(MAX_REQUEST_HEADER_SIZE);

    loop {
        match decode_request_ref(&buffer) {
            Ok(decoded) => {
                let payload_len = decoded.payload().len();
                let user_id = decoded.user_id();
                let command = decoded.command();
                let prefetched_start = buffer.len().saturating_sub(payload_len);
                let prefetched = prefetched_start..buffer.len();
                match command {
                    Command::Tcp => {
                        validate_authenticated_vision_fields(
                            user_id,
                            decoded.addons(),
                            command,
                            decoded.destination().is_some(),
                            authenticated_user_id,
                        )
                        .map_err(VisionSessionError::Validate)?;
                        let destination = decoded
                            .destination()
                            .map(|destination| destination.into_owned())
                            .ok_or(VisionSessionError::Validate(
                                RequestValidationError::MissingDestination,
                            ))?;
                        return Ok(AcceptedVisionRequest::Tcp {
                            user_id,
                            destination,
                            prefetched,
                            buffer,
                        });
                    }
                    Command::Mux => {
                        // Re-parse owned header for the shared XUDP authorizer.
                        let owned = decode_request(&buffer).map_err(VisionSessionError::Decode)?;
                        authorize_authenticated_vision_xudp(owned.header(), authenticated_user_id)
                            .map_err(VisionSessionError::Validate)?;
                        return Ok(AcceptedVisionRequest::Xudp {
                            user_id,
                            prefetched,
                            buffer,
                        });
                    }
                    other => {
                        return Err(VisionSessionError::Validate(
                            RequestValidationError::UnsupportedCommand(other),
                        ));
                    }
                }
            }
            Err(DecodeError::UnexpectedEnd { .. }) if buffer.len() < MAX_REQUEST_HEADER_SIZE => {}
            Err(DecodeError::UnexpectedEnd { .. }) => {
                return Err(VisionSessionError::RequestTooLarge {
                    limit: MAX_REQUEST_HEADER_SIZE,
                });
            }
            Err(error) => return Err(VisionSessionError::Decode(error)),
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(VisionSessionError::Timeout);
        }
        let record = reader
            .read_application(remaining)
            .await
            .map_err(VisionSessionError::Tls)?;
        let next_length =
            buffer
                .len()
                .checked_add(record.len())
                .ok_or(VisionSessionError::RequestTooLarge {
                    limit: MAX_REQUEST_BUFFER_SIZE,
                })?;
        if next_length > MAX_REQUEST_BUFFER_SIZE {
            return Err(VisionSessionError::RequestTooLarge {
                limit: MAX_REQUEST_BUFFER_SIZE,
            });
        }
        buffer
            .try_reserve(record.len())
            .map_err(|_| VisionSessionError::AllocationFailed)?;
        buffer.extend_from_slice(record.plaintext());
    }
}
