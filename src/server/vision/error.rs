//! Vision session error types and idle/deadline mapping helpers.
//!
//! Internal to [`crate::server::vision`]: the public [`VisionSessionError`]
//! surface plus the small converters used by framed and raw relay paths.

use std::{error::Error, fmt, io, time::Duration};

use tokio::time::Instant;

use crate::protocol::{
    reality::tls13::{IdleError, TlsApplicationIoError},
    vless::{DecodeError, RequestValidationError, VisionDecodeError, VisionEncodeError},
};

use crate::server::{
    direct::InvalidTransition, handoff::HandoffLineError, outbound::OutboundConnectError,
    routing::RouteResolutionError, xudp::XudpSessionError,
};

/// A Vision data session failed after REALITY authentication.
#[derive(Debug)]
pub enum VisionSessionError {
    Timeout,
    AllocationFailed,
    RequestTooLarge { limit: usize },
    Decode(DecodeError),
    Validate(RequestValidationError),
    Route(RouteResolutionError),
    Outbound(OutboundConnectError),
    Tls(TlsApplicationIoError),
    VisionDecode(VisionDecodeError),
    VisionEncode(VisionEncodeError),
    DestinationTruncatedTlsRecord,
    DirectTransition(InvalidTransition),
    Handoff(io::Error),
    HandoffLine(HandoffLineError),
    Relay(io::Error),
    Io(io::Error),
    Xudp(XudpSessionError),
}

impl fmt::Display for VisionSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("Vision session operation timed out"),
            Self::AllocationFailed => formatter.write_str("bounded Vision allocation failed"),
            Self::RequestTooLarge { limit } => {
                write!(formatter, "VLESS request exceeds {limit}-byte bound")
            }
            Self::Decode(source) => source.fmt(formatter),
            Self::Validate(source) => source.fmt(formatter),
            Self::Route(source) => source.fmt(formatter),
            Self::Outbound(source) => source.fmt(formatter),
            Self::Tls(source) => source.fmt(formatter),
            Self::VisionDecode(source) => source.fmt(formatter),
            Self::VisionEncode(source) => source.fmt(formatter),
            Self::DestinationTruncatedTlsRecord => {
                formatter.write_str("destination closed inside a TLS record")
            }
            Self::DirectTransition(source) => source.fmt(formatter),
            Self::Handoff(_) => formatter.write_str("Vision Direct socket recovery failed"),
            Self::HandoffLine(source) => source.fmt(formatter),
            Self::Relay(_) => formatter.write_str("unified raw relay failed"),
            Self::Io(_) => formatter.write_str("Vision relay socket I/O failed"),
            Self::Xudp(source) => source.fmt(formatter),
        }
    }
}

impl Error for VisionSessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode(source) => Some(source),
            Self::Validate(source) => Some(source),
            Self::Route(source) => Some(source),
            Self::Outbound(source) => Some(source),
            Self::Tls(source) => Some(source),
            Self::VisionDecode(source) => Some(source),
            Self::VisionEncode(source) => Some(source),
            Self::DirectTransition(source) => Some(source),
            Self::Handoff(source) | Self::Relay(source) | Self::Io(source) => Some(source),
            Self::HandoffLine(source) => Some(source),
            Self::Xudp(source) => Some(source),
            Self::Timeout
            | Self::AllocationFailed
            | Self::RequestTooLarge { .. }
            | Self::DestinationTruncatedTlsRecord => None,
        }
    }
}

pub(super) fn operation_deadline(timeout: Duration) -> Result<Instant, VisionSessionError> {
    Instant::now()
        .checked_add(timeout)
        .ok_or(VisionSessionError::Timeout)
}

/// Maps an idle-guarded operation failure to the session error.
pub(super) fn idle_failure(error: IdleError) -> VisionSessionError {
    match error {
        IdleError::Timeout => VisionSessionError::Timeout,
        IdleError::Io(source) => VisionSessionError::Io(source),
    }
}

/// Returns whether a raw-stage I/O error is a benign peer-teardown race.
///
/// A reset or broken pipe once the raw relay owns the sockets means the peer
/// tore the connection down mid-transfer. An idle `TimedOut` reaching here
/// never moved a byte: the relay reclassifies a write_stall timeout that
/// truncated a live transfer as `ConnectionAborted` after resetting both
/// sockets, so a `TimedOut` is always the relay's own write_stall policy ending
/// a stalled, untouched direction — a clean teardown from the session's
/// perspective, never a transport failure. In all three cases the session's
/// accumulated counts stay valid and must not be suppressed by a
/// session-level relay error.
pub(super) fn is_benign_teardown(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::TimedOut
    )
}
