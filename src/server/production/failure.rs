//! Secret-free diagnostic projection, only on a failed authenticated operation.

use std::io;

use crate::{
    logging::{FailureCause as Cause, FailureDetail, FailureStage as Stage},
    protocol::reality::tls13::{Tls13RecordError, TlsApplicationIoError, TlsRecordReadErrorKind},
    server::{
        connector::DestinationConnectError,
        handoff::{HandoffLandingError, HandoffLineError},
        nxr::NxrLandingError,
        outbound::OutboundConnectError,
        vision::VisionSessionError,
    },
    transport::tcp_relay::is_write_stall_timeout_abort,
};

use super::connection::ConnectionRunError;

type CauseAndErrno = (Cause, Option<i32>);

pub(super) fn detail(error: &ConnectionRunError) -> Option<FailureDetail> {
    let (stage, (cause, errno)) = match error {
        ConnectionRunError::Vision(VisionSessionError::HandoffLine(error)) => {
            let stage = match error {
                HandoffLineError::LandingRejected => Stage::HandoffFirstDownlink,
                HandoffLineError::Relay(_) => Stage::HandoffRelay,
                _ => Stage::HandoffTransfer,
            };
            (stage, handoff(error))
        }
        ConnectionRunError::Vision(VisionSessionError::Outbound(error)) => {
            (Stage::OutboundConnect, outbound(error))
        }
        ConnectionRunError::Handoff(HandoffLandingError::Destination(error))
        | ConnectionRunError::Nxr(NxrLandingError::Destination(error)) => {
            (Stage::LandingDestination, destination(error))
        }
        ConnectionRunError::Handoff(HandoffLandingError::Egress(error)) => {
            (Stage::LandingEgress, outbound(error))
        }
        ConnectionRunError::Handoff(HandoffLandingError::Session(error)) => {
            (Stage::SessionRelay, session(error))
        }
        ConnectionRunError::Nxr(NxrLandingError::Relay(error))
        | ConnectionRunError::Vision(
            VisionSessionError::Relay(error) | VisionSessionError::Io(error),
        ) => (Stage::SessionRelay, io_cause(error)),
        _ => return None,
    };
    Some(FailureDetail {
        stage,
        cause,
        errno,
    })
}

fn io_cause(error: &io::Error) -> CauseAndErrno {
    let cause = if is_write_stall_timeout_abort(error) {
        Cause::Timeout
    } else {
        match error.kind() {
            io::ErrorKind::TimedOut => Cause::Timeout,
            io::ErrorKind::ConnectionRefused => Cause::ConnectionRefused,
            io::ErrorKind::ConnectionReset => Cause::ConnectionReset,
            io::ErrorKind::ConnectionAborted => Cause::ConnectionAborted,
            io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => {
                Cause::Unreachable
            }
            io::ErrorKind::PermissionDenied => Cause::PermissionDenied,
            io::ErrorKind::AddrNotAvailable => Cause::AddressUnavailable,
            io::ErrorKind::UnexpectedEof => Cause::UnexpectedEof,
            io::ErrorKind::OutOfMemory => Cause::Allocation,
            _ => Cause::Io,
        }
    };
    (cause, error.raw_os_error())
}

fn destination(error: &DestinationConnectError) -> CauseAndErrno {
    let cause = match error {
        DestinationConnectError::Io(error) => return io_cause(error),
        DestinationConnectError::TimedOut { .. } => Cause::Timeout,
        DestinationConnectError::DescriptorBudget => Cause::DescriptorBudget,
        DestinationConnectError::Allocation => Cause::Allocation,
        DestinationConnectError::NoAddressesForPolicy
        | DestinationConnectError::TooManyResolvedAddresses => Cause::Policy,
    };
    (cause, None)
}

fn outbound(error: &OutboundConnectError) -> CauseAndErrno {
    let cause = match error {
        OutboundConnectError::Direct(error) => return destination(error),
        OutboundConnectError::SocksConnect(error) | OutboundConnectError::NxrConnect(error) => {
            return io_cause(error);
        }
        OutboundConnectError::Admission(_) => Cause::Admission,
        OutboundConnectError::DescriptorBudget => Cause::DescriptorBudget,
        OutboundConnectError::SocksTimeout | OutboundConnectError::NxrTimeout => Cause::Timeout,
        OutboundConnectError::SocksProtocol(_) | OutboundConnectError::NxrProtocol(_) => {
            Cause::Protocol
        }
        OutboundConnectError::NxrClock => Cause::Clock,
        OutboundConnectError::NxrRandom => Cause::Entropy,
        OutboundConnectError::UnknownTag(_)
        | OutboundConnectError::NxrOutboundConfig
        | OutboundConnectError::HandoffUnsupported => Cause::Policy,
    };
    (cause, None)
}

fn handoff(error: &HandoffLineError) -> CauseAndErrno {
    let cause = match error {
        HandoffLineError::Connect(error) | HandoffLineError::Relay(error) => {
            return io_cause(error);
        }
        HandoffLineError::DescriptorBudget => Cause::DescriptorBudget,
        HandoffLineError::Timeout => Cause::Timeout,
        HandoffLineError::Clock => Cause::Clock,
        HandoffLineError::Transfer(_) => Cause::Protocol,
        HandoffLineError::Reunite => Cause::Internal,
        HandoffLineError::LandingRejected => Cause::LandingRejected,
    };
    (cause, None)
}

pub(super) fn tls_cause(error: &TlsApplicationIoError) -> (Cause, Option<i32>) {
    let cause = match error {
        TlsApplicationIoError::Timeout => Cause::Timeout,
        TlsApplicationIoError::Io(error) => return io_cause(error),
        TlsApplicationIoError::Read(error) => match error.kind() {
            TlsRecordReadErrorKind::Timeout => Cause::Timeout,
            TlsRecordReadErrorKind::Io(error) => return io_cause(error),
            TlsRecordReadErrorKind::UnexpectedEof => Cause::UnexpectedEof,
            TlsRecordReadErrorKind::RecordTooLarge => Cause::Protocol,
        },
        TlsApplicationIoError::Record(Tls13RecordError::BufferAllocation) => Cause::Allocation,
        _ => Cause::Protocol,
    };
    (cause, None)
}

fn session(error: &VisionSessionError) -> CauseAndErrno {
    let cause = match error {
        VisionSessionError::Outbound(error) => return outbound(error),
        VisionSessionError::Tls(error) => return tls_cause(error),
        VisionSessionError::HandoffLine(error) => return handoff(error),
        VisionSessionError::Relay(error)
        | VisionSessionError::Io(error)
        | VisionSessionError::Handoff(error) => return io_cause(error),
        VisionSessionError::Timeout => Cause::Timeout,
        VisionSessionError::AllocationFailed => Cause::Allocation,
        VisionSessionError::Route(_) => Cause::Policy,
        _ => Cause::Protocol,
    };
    (cause, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::{LogEvent, RejectionReason};

    #[test]
    fn diagnostics_never_serialize_io_messages_or_outbound_tags() {
        let secret = "SECRET destination.example UUID PSK payload";
        for error in [
            ConnectionRunError::Handoff(HandoffLandingError::Destination(
                DestinationConnectError::Io(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    secret,
                )),
            )),
            ConnectionRunError::Handoff(HandoffLandingError::Egress(
                OutboundConnectError::UnknownTag(secret.to_owned()),
            )),
        ] {
            let event = LogEvent::ConnectionRejected {
                peer: "127.0.0.1:12345".parse().expect("fixture address"),
                reason: RejectionReason::Outbound,
                failure: detail(&error),
            };
            let json = serde_json::to_string(&event).expect("event serializes");
            assert!(!json.contains(secret));
            assert!(!json.contains("destination.example"));
            assert!(json.contains("landing_"));
        }
    }

    #[test]
    fn framed_session_errors_keep_typed_causes_without_retained_wire_bytes() {
        use crate::protocol::reality::tls13::buffered_failure;
        let secret = b"PRIVATE-WIRE-PREFIX";
        let cases = [
            (
                TlsApplicationIoError::Timeout,
                Cause::Timeout,
                RejectionReason::Timeout,
            ),
            (
                TlsApplicationIoError::Read(buffered_failure(
                    TlsRecordReadErrorKind::Timeout,
                    secret,
                )),
                Cause::Timeout,
                RejectionReason::Timeout,
            ),
            (
                TlsApplicationIoError::Record(Tls13RecordError::BufferAllocation),
                Cause::Allocation,
                RejectionReason::ResourceLimit,
            ),
            (
                TlsApplicationIoError::Io(io::Error::from_raw_os_error(104)),
                Cause::ConnectionReset,
                RejectionReason::Protocol,
            ),
            (
                TlsApplicationIoError::Read(buffered_failure(
                    TlsRecordReadErrorKind::Io(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "PRIVATE-IO-TEXT",
                    )),
                    secret,
                )),
                Cause::ConnectionReset,
                RejectionReason::Protocol,
            ),
            (
                TlsApplicationIoError::Read(buffered_failure(
                    TlsRecordReadErrorKind::UnexpectedEof,
                    secret,
                )),
                Cause::UnexpectedEof,
                RejectionReason::Protocol,
            ),
        ];
        for (tls, cause, reason) in cases {
            let error = ConnectionRunError::Handoff(HandoffLandingError::Session(
                VisionSessionError::Tls(tls),
            ));
            let failure = detail(&error).expect("session detail");
            assert_eq!(failure.stage, Stage::SessionRelay);
            assert_eq!(failure.cause, cause);
            assert_eq!(error.rejection_reason(), reason);
            let json = serde_json::to_string(&failure).expect("serialize detail");
            assert!(!json.contains("PRIVATE"));
            // Serialization has a fixed three-field schema: there is no
            // alternate numeric/escaped representation of retained bytes.
            let value: serde_json::Value = serde_json::from_str(&json).expect("JSON detail");
            assert!(
                value
                    .as_object()
                    .expect("object")
                    .keys()
                    .all(|key| matches!(key.as_str(), "stage" | "cause" | "errno"))
            );
        }
    }

    #[test]
    fn landing_errno_and_line_rejection_have_distinct_stages() {
        let error = ConnectionRunError::Handoff(HandoffLandingError::Destination(
            DestinationConnectError::Io(io::Error::from_raw_os_error(111)),
        ));
        assert_eq!(
            detail(&error),
            Some(FailureDetail {
                stage: Stage::LandingDestination,
                cause: Cause::ConnectionRefused,
                errno: Some(111),
            })
        );
        let error = ConnectionRunError::Vision(VisionSessionError::HandoffLine(
            HandoffLineError::LandingRejected,
        ));
        assert_eq!(
            detail(&error),
            Some(FailureDetail {
                stage: Stage::HandoffFirstDownlink,
                cause: Cause::LandingRejected,
                errno: None,
            })
        );
    }
}
