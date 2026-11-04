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
        ConnectionRunError::Nxr(NxrLandingError::Relay(error) | NxrLandingError::UdpIo(error))
        | ConnectionRunError::Vision(
            VisionSessionError::Relay(error) | VisionSessionError::Io(error),
        ) => (Stage::SessionRelay, io_cause(error)),
        // LANDING pre-auth: socket accepted, peer not yet authenticated.
        ConnectionRunError::Handoff(
            HandoffLandingError::Admission(_)
            | HandoffLandingError::Reclaimed
            | HandoffLandingError::DescriptorBudget
            | HandoffLandingError::Timeout,
        )
        | ConnectionRunError::Nxr(
            NxrLandingError::Admission(_)
            | NxrLandingError::Reclaimed
            | NxrLandingError::DescriptorBudget
            | NxrLandingError::Timeout,
        ) => (Stage::LandingPreAuth, landing_pre_auth(error)),
        // LANDING authenticate: transfer/request body before destination dial.
        ConnectionRunError::Handoff(
            HandoffLandingError::Protocol(_)
            | HandoffLandingError::Read(_)
            | HandoffLandingError::Allocation
            | HandoffLandingError::Clock,
        )
        | ConnectionRunError::Nxr(
            NxrLandingError::Protocol(_)
            | NxrLandingError::Authentication(_)
            | NxrLandingError::UdpProtocol(_)
            | NxrLandingError::Read(_)
            | NxrLandingError::Allocation
            | NxrLandingError::Clock,
        ) => (Stage::LandingAuthenticate, landing_authenticate(error)),
        // Quiet pre-auth peer-close / generation retirement intentionally stay
        // unprojected; Reality accept remains out of this projection until a
        // dedicated public-node stage is defined.
        _ => return None,
    };
    Some(FailureDetail {
        stage,
        cause,
        errno,
    })
}

fn landing_pre_auth(error: &ConnectionRunError) -> CauseAndErrno {
    match error {
        ConnectionRunError::Handoff(HandoffLandingError::Admission(_))
        | ConnectionRunError::Nxr(NxrLandingError::Admission(_))
        | ConnectionRunError::Handoff(HandoffLandingError::Reclaimed)
        | ConnectionRunError::Nxr(NxrLandingError::Reclaimed) => (Cause::Admission, None),
        ConnectionRunError::Handoff(HandoffLandingError::DescriptorBudget)
        | ConnectionRunError::Nxr(NxrLandingError::DescriptorBudget) => {
            (Cause::DescriptorBudget, None)
        }
        ConnectionRunError::Handoff(HandoffLandingError::Timeout)
        | ConnectionRunError::Nxr(NxrLandingError::Timeout) => (Cause::Timeout, None),
        _ => (Cause::Internal, None),
    }
}

fn landing_authenticate(error: &ConnectionRunError) -> CauseAndErrno {
    match error {
        ConnectionRunError::Handoff(HandoffLandingError::Read(error))
        | ConnectionRunError::Nxr(NxrLandingError::Read(error)) => io_cause(error),
        ConnectionRunError::Handoff(HandoffLandingError::Allocation)
        | ConnectionRunError::Nxr(NxrLandingError::Allocation) => (Cause::Allocation, None),
        ConnectionRunError::Handoff(HandoffLandingError::Clock)
        | ConnectionRunError::Nxr(NxrLandingError::Clock) => (Cause::Clock, None),
        ConnectionRunError::Handoff(HandoffLandingError::Protocol(_))
        | ConnectionRunError::Nxr(
            NxrLandingError::Protocol(_)
            | NxrLandingError::Authentication(_)
            | NxrLandingError::UdpProtocol(_),
        ) => (Cause::Protocol, None),
        _ => (Cause::Internal, None),
    }
}

pub(super) fn io_cause(error: &io::Error) -> CauseAndErrno {
    // Connector adapters retain the typed error inside io::Error. Project
    // that type before the generic ErrorKind, without reading display text.
    if let Some(source) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<DestinationConnectError>())
    {
        return destination(source);
    }
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
mod tests;
