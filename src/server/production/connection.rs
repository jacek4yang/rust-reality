//! One accepted connection, from handler dispatch to its closing log line.
//!
//! Everything a connection can fail with collapses here into one bounded
//! [`RejectionReason`]. That classification is the whole reason this type
//! exists: an operator reading the log must be able to tell a resource limit
//! from an authentication failure from a liveness timeout, and the protocol
//! modules each have their own error vocabulary.

use std::{error::Error, fmt, io, net::SocketAddr, sync::Arc};

use sha2::{Digest, Sha256};
use std::fmt::Write as _;

use crate::{
    logging::{LogEvent, Logger, RejectionReason},
    runtime::{AdmissionDenied, AdmissionPermit},
    transport::{RelayBackend, tcp_relay::is_write_stall_timeout_abort},
};

use super::{
    event::{emit, emit_admission, emit_debug},
    snapshot::{ConnectionHandler, ConnectionRuntime},
};
use crate::server::{
    handoff::HandoffLandingError,
    nxr::NxrLandingError,
    reality::{RealityAcceptError, RealityAcceptOutcome},
    vision::VisionSessionError,
};

pub(super) async fn run_connection(
    state: Arc<ConnectionRuntime>,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    connection_permit: AdmissionPermit,
    logger: &Logger,
) -> io::Result<()> {
    let started = std::time::Instant::now();
    let mut completion = None;
    let result = async {
        match &state.handler {
            ConnectionHandler::Public { reality, vision } => {
                match reality.accept(stream, peer).await? {
                    RealityAcceptOutcome::Established(mut established) => {
                        if logger.debug_enabled()
                            && let Some(evidence) = established.take_cover_flight_evidence()
                        {
                            let digest = Sha256::digest(&evidence.retained_prefix);
                            let mut retained_prefix_sha256 = String::with_capacity(64);
                            for byte in digest {
                                let _ = write!(&mut retained_prefix_sha256, "{byte:02x}");
                            }
                            emit(
                                logger,
                                &LogEvent::CoverFlightSelected {
                                    emit_ccs: evidence.emit_ccs,
                                    layout: evidence.layout,
                                    wire_lens: evidence.wire_lens,
                                    nst_wire_len: evidence.nst_wire_len,
                                    retained_prefix_bytes: evidence.retained_prefix.len(),
                                    retained_prefix_sha256,
                                },
                            );
                        }
                        let stats = vision.handle(*established).await?;
                        completion = Some(stats);
                    }
                    RealityAcceptOutcome::Fallback(_) => {}
                }
            }
            ConnectionHandler::Nxr(handler) => {
                handler.handle(stream).await?;
            }
            ConnectionHandler::Handoff(handler) => {
                handler.handle(stream).await?;
            }
        }
        Ok::<(), ConnectionRunError>(())
    }
    .await;
    drop(connection_permit);
    match result {
        Ok(()) => {
            if let Some(stats) = completion {
                emit_debug(logger, || LogEvent::ConnectionCompleted {
                    duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    uplink_bytes: stats.uplink_bytes(),
                    downlink_bytes: stats.downlink_bytes(),
                    uplink_direct: stats.uplink_direct(),
                    downlink_direct: stats.downlink_direct(),
                    relay_backend: stats.relay_backend().map(RelayBackend::as_str),
                    uplink_direct_at_bytes: stats.uplink_direct_at_bytes(),
                    downlink_direct_at_bytes: stats.downlink_direct_at_bytes(),
                    uplink_backend: stats.uplink_backend().map(RelayBackend::as_str),
                    downlink_backend: stats.downlink_backend().map(RelayBackend::as_str),
                    uplink_handoff_delay_us: stats.uplink_handoff_delay_us(),
                    downlink_handoff_delay_us: stats.downlink_handoff_delay_us(),
                    handoff_server_sequence: stats.handoff_server_sequence(),
                    pipe_capacity_downgraded: stats.pipe_capacity_downgraded(),
                });
            }
            emit_debug(logger, || LogEvent::ConnectionClosed { peer });
            Ok(())
        }
        Err(error) if error.is_quiet_pre_auth_retirement() => {
            // READY-socket lifetime rotation closes a zero-byte transport by
            // design. It granted no authority and started no authentication,
            // so reporting it as a warn-level authentication rejection would
            // turn ordinary idle maintenance into unbounded log I/O.
            emit_debug(logger, || LogEvent::ConnectionClosed { peer });
            Ok(())
        }
        Err(error) => {
            emit_connection_failure(logger, peer, &error);
            Err(io::Error::other(error))
        }
    }
}

pub(super) fn emit_connection_failure(
    logger: &Logger,
    peer: SocketAddr,
    error: &ConnectionRunError,
) {
    // A direct-barrier denial is a resource-limit event, not an ordinary
    // outbound failure: report the bounded resource next to the rejection so
    // operators can tell the two apart.
    if let Some(denied) = error.admission_denial() {
        emit_admission(logger, denied);
    }
    emit(
        logger,
        &LogEvent::ConnectionRejected {
            peer,
            reason: error.rejection_reason(),
            failure: super::failure::detail(error),
        },
    );
}

#[derive(Debug)]
pub(super) enum ConnectionRunError {
    Reality(RealityAcceptError),
    Vision(VisionSessionError),
    Nxr(NxrLandingError),
    Handoff(HandoffLandingError),
}

impl ConnectionRunError {
    pub(super) const fn is_quiet_pre_auth_retirement(&self) -> bool {
        matches!(
            self,
            Self::Nxr(
                NxrLandingError::PreAuthPeerClosed | NxrLandingError::PreAuthGenerationRetired,
            ) | Self::Handoff(
                HandoffLandingError::PreAuthPeerClosed
                    | HandoffLandingError::PreAuthGenerationRetired,
            )
        )
    }

    pub(super) fn rejection_reason(&self) -> RejectionReason {
        match self {
            Self::Reality(RealityAcceptError::Admission(_)) => RejectionReason::ResourceLimit,
            Self::Nxr(NxrLandingError::Admission(_) | NxrLandingError::Reclaimed)
            | Self::Handoff(HandoffLandingError::Admission(_) | HandoffLandingError::Reclaimed) => {
                RejectionReason::ResourceLimit
            }
            Self::Reality(RealityAcceptError::HandshakeWriteTimeout)
            | Self::Nxr(NxrLandingError::Timeout)
            | Self::Handoff(HandoffLandingError::Timeout) => RejectionReason::Timeout,
            Self::Reality(RealityAcceptError::Fallback(_)) => RejectionReason::Outbound,
            Self::Reality(_) => RejectionReason::Authentication,
            Self::Vision(error) | Self::Handoff(HandoffLandingError::Session(error)) => {
                vision_rejection_reason(error)
            }
            Self::Handoff(HandoffLandingError::Egress(error)) => outbound_rejection_reason(error),
            Self::Nxr(NxrLandingError::DescriptorBudget)
            | Self::Handoff(HandoffLandingError::DescriptorBudget) => {
                RejectionReason::ResourceLimit
            }
            Self::Nxr(NxrLandingError::Destination(error))
            | Self::Handoff(HandoffLandingError::Destination(error)) => {
                destination_rejection_reason(error)
            }
            Self::Nxr(NxrLandingError::Relay(error)) if is_write_stall_timeout_abort(error) => {
                RejectionReason::Timeout
            }
            Self::Nxr(NxrLandingError::Relay(_)) => RejectionReason::Outbound,
            Self::Nxr(_) | Self::Handoff(_) => RejectionReason::Authentication,
        }
    }

    pub(super) const fn admission_denial(&self) -> Option<AdmissionDenied> {
        use crate::server::outbound::OutboundConnectError;
        match self {
            Self::Vision(VisionSessionError::Outbound(OutboundConnectError::Admission(denied)))
            | Self::Handoff(HandoffLandingError::Egress(OutboundConnectError::Admission(denied)))
            | Self::Handoff(HandoffLandingError::Session(VisionSessionError::Outbound(
                OutboundConnectError::Admission(denied),
            ))) => Some(*denied),
            Self::Nxr(NxrLandingError::Admission(denied))
            | Self::Handoff(HandoffLandingError::Admission(denied)) => Some(*denied),
            _ => None,
        }
    }
}

fn destination_rejection_reason(
    error: &crate::server::connector::DestinationConnectError,
) -> RejectionReason {
    use crate::server::connector::DestinationConnectError;
    match error {
        DestinationConnectError::DescriptorBudget | DestinationConnectError::Allocation => {
            RejectionReason::ResourceLimit
        }
        DestinationConnectError::TimedOut { .. } => RejectionReason::Timeout,
        _ => RejectionReason::Outbound,
    }
}

fn connect_io_rejection_reason(error: &io::Error) -> RejectionReason {
    use crate::logging::FailureCause;
    match super::failure::io_cause(error).0 {
        FailureCause::Timeout => RejectionReason::Timeout,
        FailureCause::Allocation | FailureCause::DescriptorBudget | FailureCause::Admission => {
            RejectionReason::ResourceLimit
        }
        _ => RejectionReason::Outbound,
    }
}

fn outbound_rejection_reason(
    error: &crate::server::outbound::OutboundConnectError,
) -> RejectionReason {
    use crate::server::outbound::OutboundConnectError;
    match error {
        OutboundConnectError::Admission(_) | OutboundConnectError::DescriptorBudget => {
            RejectionReason::ResourceLimit
        }
        OutboundConnectError::Direct(error) => destination_rejection_reason(error),
        OutboundConnectError::SocksConnect(error) | OutboundConnectError::NxrConnect(error) => {
            connect_io_rejection_reason(error)
        }
        OutboundConnectError::SocksTimeout | OutboundConnectError::NxrTimeout => {
            RejectionReason::Timeout
        }
        _ => RejectionReason::Outbound,
    }
}

fn vision_rejection_reason(error: &VisionSessionError) -> RejectionReason {
    use crate::server::handoff::HandoffLineError;
    match error {
        VisionSessionError::Timeout
        | VisionSessionError::HandoffLine(HandoffLineError::Timeout) => RejectionReason::Timeout,
        VisionSessionError::AllocationFailed
        | VisionSessionError::HandoffLine(HandoffLineError::DescriptorBudget) => {
            RejectionReason::ResourceLimit
        }
        VisionSessionError::Outbound(error) => outbound_rejection_reason(error),
        VisionSessionError::HandoffLine(HandoffLineError::Connect(error)) => {
            connect_io_rejection_reason(error)
        }
        VisionSessionError::Tls(error) => match super::failure::tls_cause(error).0 {
            crate::logging::FailureCause::Timeout => RejectionReason::Timeout,
            crate::logging::FailureCause::Allocation => RejectionReason::ResourceLimit,
            _ => RejectionReason::Protocol,
        },
        VisionSessionError::Relay(error)
        | VisionSessionError::HandoffLine(HandoffLineError::Relay(error))
            if is_write_stall_timeout_abort(error) =>
        {
            RejectionReason::Timeout
        }
        VisionSessionError::Route(_) | VisionSessionError::HandoffLine(_) => {
            RejectionReason::Outbound
        }
        _ => RejectionReason::Protocol,
    }
}

impl From<RealityAcceptError> for ConnectionRunError {
    fn from(source: RealityAcceptError) -> Self {
        Self::Reality(source)
    }
}

impl From<VisionSessionError> for ConnectionRunError {
    fn from(source: VisionSessionError) -> Self {
        Self::Vision(source)
    }
}

impl From<NxrLandingError> for ConnectionRunError {
    fn from(source: NxrLandingError) -> Self {
        Self::Nxr(source)
    }
}

impl From<HandoffLandingError> for ConnectionRunError {
    fn from(source: HandoffLandingError) -> Self {
        Self::Handoff(source)
    }
}

impl fmt::Display for ConnectionRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reality(source) => source.fmt(formatter),
            Self::Vision(source) => source.fmt(formatter),
            Self::Nxr(source) => source.fmt(formatter),
            Self::Handoff(source) => source.fmt(formatter),
        }
    }
}

impl Error for ConnectionRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Reality(source) => Some(source),
            Self::Vision(source) => Some(source),
            Self::Nxr(source) => Some(source),
            Self::Handoff(source) => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{io, net::Ipv4Addr};

    use super::ConnectionRunError;
    use crate::{
        config::node::log::{LogConfig, LogLevel, LogOutput},
        server::{handoff::HandoffLandingError, nxr::NxrLandingError},
    };

    #[test]
    fn nested_landing_failures_retain_resource_and_timeout_categories() {
        use crate::{
            logging::RejectionReason,
            runtime::AdmissionDenied,
            server::{
                connector::DestinationConnectError, outbound::OutboundConnectError,
                vision::VisionSessionError,
            },
        };
        let cases = [
            (
                HandoffLandingError::Egress(OutboundConnectError::DescriptorBudget),
                RejectionReason::ResourceLimit,
            ),
            (
                HandoffLandingError::Egress(OutboundConnectError::Admission(
                    AdmissionDenied::DirectConcurrency,
                )),
                RejectionReason::ResourceLimit,
            ),
            (
                HandoffLandingError::Egress(OutboundConnectError::SocksTimeout),
                RejectionReason::Timeout,
            ),
            (
                HandoffLandingError::Session(VisionSessionError::Timeout),
                RejectionReason::Timeout,
            ),
            (
                HandoffLandingError::Session(VisionSessionError::Relay(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    io::Error::new(io::ErrorKind::TimedOut, "stall"),
                ))),
                RejectionReason::Timeout,
            ),
            (
                HandoffLandingError::Destination(DestinationConnectError::TimedOut {
                    timeout: std::time::Duration::from_secs(1),
                }),
                RejectionReason::Timeout,
            ),
            (
                HandoffLandingError::Destination(DestinationConnectError::Io(io::Error::from(
                    io::ErrorKind::ConnectionRefused,
                ))),
                RejectionReason::Outbound,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(
                ConnectionRunError::Handoff(error).rejection_reason(),
                expected
            );
        }
        for error in [
            HandoffLandingError::Egress(OutboundConnectError::Admission(
                AdmissionDenied::DirectRate,
            )),
            HandoffLandingError::Session(VisionSessionError::Outbound(
                OutboundConnectError::Admission(AdmissionDenied::DirectRate),
            )),
        ] {
            assert_eq!(
                ConnectionRunError::Handoff(error).admission_denial(),
                Some(AdmissionDenied::DirectRate)
            );
        }
    }

    #[test]
    fn zero_byte_warm_retirement_is_quiet_for_both_landing_protocols() {
        assert!(
            ConnectionRunError::Handoff(HandoffLandingError::PreAuthPeerClosed)
                .is_quiet_pre_auth_retirement()
        );
        assert!(
            ConnectionRunError::Nxr(NxrLandingError::PreAuthPeerClosed)
                .is_quiet_pre_auth_retirement()
        );
        assert!(
            ConnectionRunError::Handoff(HandoffLandingError::PreAuthGenerationRetired)
                .is_quiet_pre_auth_retirement()
        );
        assert!(
            !ConnectionRunError::Nxr(NxrLandingError::Read(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer stalled after byte one",
            )))
            .is_quiet_pre_auth_retirement(),
            "EOF after authentication starts must remain a rejection"
        );
    }

    #[test]
    fn a_denied_direct_dial_is_reported_as_a_resource_limit() {
        use std::{fs, net::SocketAddr, sync::atomic::AtomicU64};

        use crate::{
            logging::{Logger, RejectionReason},
            runtime::AdmissionDenied,
            server::{outbound::OutboundConnectError, vision::VisionSessionError},
        };

        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rust-reality-barrier-log-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&directory).expect("unique log directory must be created");
        let path = directory.join("events.log");
        let logger = Logger::new(&LogConfig {
            level: Some(LogLevel::Debug),
            output: Some(LogOutput::File),
            file: Some(crate::config::node::log::FileLogConfig {
                path: path.clone(),
                max_bytes: Some(64 * 1024),
                max_files: Some(1),
                max_total_bytes: Some(64 * 1024),
            }),
        })
        .expect("file logger must initialize");

        let error = ConnectionRunError::Vision(VisionSessionError::Outbound(
            OutboundConnectError::Admission(AdmissionDenied::DirectConcurrency),
        ));
        assert_eq!(
            error.rejection_reason(),
            RejectionReason::ResourceLimit,
            "a barrier denial must not look like an ordinary outbound failure"
        );
        assert_eq!(
            error.admission_denial(),
            Some(AdmissionDenied::DirectConcurrency),
            "the denial category must flow to the admission event"
        );

        super::emit_connection_failure(
            &logger,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 40_000)),
            &error,
        );
        let contents = fs::read_to_string(&path).expect("the log file must be readable");
        assert!(
            contents.contains("\"event\":\"admission_limited\""),
            "expected an admission_limited event, got {contents}"
        );
        assert!(
            contents.contains("\"resource\":\"direct_connections\""),
            "expected the direct_connections resource, got {contents}"
        );
        assert!(
            contents.contains("\"event\":\"connection_rejected\""),
            "expected a connection_rejected event, got {contents}"
        );
        assert!(
            contents.contains("\"reason\":\"resource_limit\""),
            "expected the resource_limit reason, got {contents}"
        );
        fs::remove_dir_all(&directory).expect("log directory must be removed");
    }

    #[test]
    fn a_mid_transfer_liveness_abort_is_reported_as_a_timeout() {
        use crate::{logging::RejectionReason, server::vision::VisionSessionError};

        // A healthy transfer whose peer direction stalls past the liveness
        // deadline aborts both sockets with RST and surfaces as
        // ConnectionAborted carrying the original TimedOut (the exact shape
        // classify_abort produces). That is a liveness-policy kill: the
        // rejection log must say timeout, not protocol.
        let abort = io::Error::new(
            io::ErrorKind::ConnectionAborted,
            io::Error::new(io::ErrorKind::TimedOut, "raw relay idle timeout"),
        );
        let error = ConnectionRunError::Vision(VisionSessionError::Relay(abort));
        assert_eq!(
            error.rejection_reason(),
            RejectionReason::Timeout,
            "a liveness timeout that truncated a live transfer is still a timeout"
        );

        let error = ConnectionRunError::Vision(VisionSessionError::Relay(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "peer abort",
        )));
        assert_eq!(
            error.rejection_reason(),
            RejectionReason::Protocol,
            "a plain relay abort without a timeout payload stays a protocol rejection"
        );
    }
}
