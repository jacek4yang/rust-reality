use super::*;
use crate::logging::{LogEvent, RejectionReason};

#[test]
fn wrapped_connector_failures_keep_resource_and_policy_classification() {
    type Case = (fn() -> DestinationConnectError, Cause, RejectionReason);
    let cases: [Case; 3] = [
        (
            || DestinationConnectError::Allocation,
            Cause::Allocation,
            RejectionReason::ResourceLimit,
        ),
        (
            || DestinationConnectError::NoAddressesForPolicy,
            Cause::Policy,
            RejectionReason::Outbound,
        ),
        (
            || DestinationConnectError::TooManyResolvedAddresses,
            Cause::Policy,
            RejectionReason::Outbound,
        ),
    ];
    for (make, cause, reason) in cases {
        for error in [
            ConnectionRunError::Vision(VisionSessionError::Outbound(
                OutboundConnectError::SocksConnect(make().into_io()),
            )),
            ConnectionRunError::Vision(VisionSessionError::Outbound(
                OutboundConnectError::NxrConnect(make().into_io()),
            )),
            ConnectionRunError::Vision(VisionSessionError::HandoffLine(HandoffLineError::Connect(
                make().into_io(),
            ))),
        ] {
            assert_eq!(detail(&error).expect("typed failure").cause, cause);
            assert_eq!(error.rejection_reason(), reason);
        }
    }
}

#[test]
fn untyped_io_errors_do_not_gain_a_policy_cause_from_kind_or_text() {
    let text = "PRIVATE destination NoAddressesForPolicy DescriptorBudget";
    assert_eq!(
        io_cause(&io::Error::new(io::ErrorKind::InvalidInput, text)),
        (Cause::Io, None),
    );
    assert_eq!(
        io_cause(&io::Error::from_raw_os_error(111)),
        (Cause::ConnectionRefused, Some(111)),
    );
    let failure = detail(&ConnectionRunError::Vision(VisionSessionError::Outbound(
        OutboundConnectError::SocksConnect(io::Error::new(io::ErrorKind::InvalidInput, text)),
    )))
    .expect("outbound detail");
    let json = serde_json::to_string(&failure).expect("serialize detail");
    assert!(!json.contains("PRIVATE"));
    assert!(!json.contains("destination"));
}

#[test]
fn diagnostics_never_serialize_io_messages_or_outbound_tags() {
    let secret = "SECRET destination.example UUID PSK payload";
    for error in [
        ConnectionRunError::Handoff(HandoffLandingError::Destination(
            DestinationConnectError::Io(io::Error::new(io::ErrorKind::ConnectionRefused, secret)),
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
            TlsApplicationIoError::Read(buffered_failure(TlsRecordReadErrorKind::Timeout, secret)),
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
        let error =
            ConnectionRunError::Handoff(HandoffLandingError::Session(VisionSessionError::Tls(tls)));
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
fn xudp_failures_carry_a_stage_and_cause() {
    let open_timeout = ConnectionRunError::Vision(VisionSessionError::Xudp(
        XudpSessionError::HandoffUdpOpenTimeout,
    ));
    assert_eq!(
        detail(&open_timeout),
        Some(FailureDetail {
            stage: Stage::XudpRelay,
            cause: Cause::Timeout,
            errno: None,
        })
    );
    let io = ConnectionRunError::Vision(VisionSessionError::Xudp(XudpSessionError::Io(
        io::Error::from_raw_os_error(101),
    )));
    assert_eq!(
        detail(&io),
        Some(FailureDetail {
            stage: Stage::XudpRelay,
            cause: Cause::Unreachable,
            errno: Some(101),
        })
    );
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

/// Phase 2 gap: LANDING pre-auth / auth used to return `detail=None`, so
/// operators only saw coarse `reason=authentication|resource_limit|timeout`
/// and could not tell pre-auth idle from transfer auth from destination.
#[test]
fn landing_pre_auth_and_authenticate_are_not_lumped_as_outbound() {
    use crate::protocol::handoff::HandoffError;
    use crate::protocol::nxr::NxrProtocolError;
    use crate::runtime::{AdmissionDenied, AdmissionKind};
    use crate::server::nxr::NxrAuthenticationError;

    let cases: &[(ConnectionRunError, Stage, Cause, Option<i32>)] = &[
        (
            ConnectionRunError::Handoff(HandoffLandingError::Admission(AdmissionDenied::Limit(
                AdmissionKind::PreAuthIdle,
            ))),
            Stage::LandingPreAuth,
            Cause::Admission,
            None,
        ),
        (
            ConnectionRunError::Nxr(NxrLandingError::Reclaimed),
            Stage::LandingPreAuth,
            Cause::Admission,
            None,
        ),
        (
            ConnectionRunError::Handoff(HandoffLandingError::DescriptorBudget),
            Stage::LandingPreAuth,
            Cause::DescriptorBudget,
            None,
        ),
        (
            ConnectionRunError::Nxr(NxrLandingError::Timeout),
            Stage::LandingPreAuth,
            Cause::Timeout,
            None,
        ),
        (
            ConnectionRunError::Handoff(HandoffLandingError::Protocol(
                HandoffError::Authentication,
            )),
            Stage::LandingAuthenticate,
            Cause::Protocol,
            None,
        ),
        (
            ConnectionRunError::Nxr(NxrLandingError::Authentication(
                NxrAuthenticationError::Protocol(NxrProtocolError::Authentication),
            )),
            Stage::LandingAuthenticate,
            Cause::Protocol,
            None,
        ),
        (
            ConnectionRunError::Handoff(HandoffLandingError::Read(io::Error::from_raw_os_error(
                104,
            ))),
            Stage::LandingAuthenticate,
            Cause::ConnectionReset,
            Some(104),
        ),
        (
            ConnectionRunError::Nxr(NxrLandingError::Allocation),
            Stage::LandingAuthenticate,
            Cause::Allocation,
            None,
        ),
        (
            ConnectionRunError::Handoff(HandoffLandingError::Clock),
            Stage::LandingAuthenticate,
            Cause::Clock,
            None,
        ),
    ];
    for (error, stage, cause, errno) in cases {
        assert_eq!(
            detail(error),
            Some(FailureDetail {
                stage: *stage,
                cause: *cause,
                errno: *errno,
            }),
            "expected typed stage for {error:?}"
        );
        // Must not look like a destination / LINE outbound dial failure.
        assert_ne!(stage, &Stage::LandingDestination);
        assert_ne!(stage, &Stage::OutboundConnect);
        assert_ne!(stage, &Stage::LandingEgress);
        let json = serde_json::to_string(&detail(error).expect("detail")).expect("json");
        assert!(!json.contains("PRIVATE"));
        assert!(!json.contains("destination"));
    }
}

/// Quiet pre-auth peer-close / generation retirement must stay unprojected
/// so ordinary warm lifecycle does not become rejection noise.
#[test]
fn quiet_pre_auth_retirement_stays_without_failure_detail() {
    for error in [
        ConnectionRunError::Handoff(HandoffLandingError::PreAuthPeerClosed),
        ConnectionRunError::Handoff(HandoffLandingError::PreAuthGenerationRetired),
        ConnectionRunError::Nxr(NxrLandingError::PreAuthPeerClosed),
        ConnectionRunError::Nxr(NxrLandingError::PreAuthGenerationRetired),
    ] {
        assert!(error.is_quiet_pre_auth_retirement());
        assert_eq!(detail(&error), None);
    }
}

/// Phase 2 H1: LINE cold dial after listen-down must surface ECONNREFUSED
/// with errno on both Handoff and NXR LINE paths (not only LANDING egress).
#[test]
fn line_cold_dial_connection_refused_keeps_errno_and_stage() {
    let refused = io::Error::from_raw_os_error(111);
    assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
    assert_eq!(refused.raw_os_error(), Some(111));

    let handoff = ConnectionRunError::Vision(VisionSessionError::HandoffLine(
        HandoffLineError::Connect(io::Error::from_raw_os_error(111)),
    ));
    assert_eq!(
        detail(&handoff),
        Some(FailureDetail {
            stage: Stage::HandoffTransfer,
            cause: Cause::ConnectionRefused,
            errno: Some(111),
        })
    );
    assert_eq!(handoff.rejection_reason(), RejectionReason::Outbound);

    let nxr = ConnectionRunError::Vision(VisionSessionError::Outbound(
        OutboundConnectError::NxrConnect(io::Error::from_raw_os_error(111)),
    ));
    assert_eq!(
        detail(&nxr),
        Some(FailureDetail {
            stage: Stage::OutboundConnect,
            cause: Cause::ConnectionRefused,
            errno: Some(111),
        })
    );
    assert_eq!(nxr.rejection_reason(), RejectionReason::Outbound);

    // DestinationConnectError::Io → into_io preserves errno on Handoff connect.
    let wrapped = DestinationConnectError::Io(io::Error::from_raw_os_error(111)).into_io();
    let via_into_io = ConnectionRunError::Vision(VisionSessionError::HandoffLine(
        HandoffLineError::Connect(wrapped),
    ));
    assert_eq!(
        detail(&via_into_io),
        Some(FailureDetail {
            stage: Stage::HandoffTransfer,
            cause: Cause::ConnectionRefused,
            errno: Some(111),
        })
    );

    // Distinct from LANDING destination refuse (same errno, different stage).
    let landing = ConnectionRunError::Handoff(HandoffLandingError::Destination(
        DestinationConnectError::Io(io::Error::from_raw_os_error(111)),
    ));
    assert_eq!(
        detail(&landing).expect("landing").stage,
        Stage::LandingDestination
    );
}
