//! Silent-close error types for the LINE and LANDING Handoff endpoints.

use std::{error::Error, fmt, io};

use crate::{
    protocol::handoff::HandoffError, runtime::AdmissionDenied,
    transport::tcp_relay::TcpRelayConfigError,
};

use super::super::{
    connector::DestinationConnectError, outbound::OutboundConnectError, pre_auth::PreAuthError,
    vision::VisionSessionError,
};

/// Validated Handoff listener state could not be compiled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffLandingConfigError {
    /// PSK or static-key decoding or length did not match the protocol contract.
    Key,
    /// Replay capacity could not be represented on this target.
    Capacity,
    /// Replay cache initialization failed.
    Replay(HandoffError),
    /// Bounded plaintext relay state could not be compiled.
    Relay(TcpRelayConfigError),
}

impl fmt::Display for HandoffLandingConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid Handoff landing listener configuration")
    }
}

impl Error for HandoffLandingConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Replay(source) => Some(source),
            Self::Relay(source) => Some(source),
            Self::Key | Self::Capacity => None,
        }
    }
}

/// One Handoff landing connection failed and must close silently.
#[derive(Debug)]
pub enum HandoffLandingError {
    /// Pre-auth idle or authentication admission was refused.
    Admission(AdmissionDenied),
    /// An unused socket was reclaimed by pressure or generation retirement.
    Reclaimed,
    /// The LINE retired an unused zero-byte warm transport normally.
    PreAuthPeerClosed,
    /// Runtime reload retired this unused pre-auth generation normally.
    PreAuthGenerationRetired,
    Timeout,
    Read(io::Error),
    Protocol(HandoffError),
    Allocation,
    Clock,
    Destination(DestinationConnectError),
    /// The configured egress outbound could not serve the transferred
    /// destination dial.
    Egress(OutboundConnectError),
    Session(VisionSessionError),
    DescriptorBudget,
}

impl HandoffLandingError {
    pub(super) fn from_pre_auth(error: PreAuthError) -> Self {
        match error {
            PreAuthError::Admission(error) => Self::Admission(error),
            PreAuthError::Timeout => Self::Timeout,
            PreAuthError::PeerClosed => Self::PreAuthPeerClosed,
            PreAuthError::Read(error) => Self::Read(error),
            PreAuthError::PressureReclaimed => Self::Reclaimed,
            PreAuthError::GenerationRetired => Self::PreAuthGenerationRetired,
        }
    }
}

impl fmt::Display for HandoffLandingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Handoff landing connection closed")
    }
}

impl Error for HandoffLandingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read(source) => Some(source),
            Self::Protocol(source) => Some(source),
            Self::Destination(source) => Some(source),
            Self::Egress(source) => Some(source),
            Self::Session(source) => Some(source),
            Self::Admission(source) => Some(source),
            Self::Reclaimed
            | Self::PreAuthPeerClosed
            | Self::PreAuthGenerationRetired
            | Self::Timeout
            | Self::Allocation
            | Self::Clock
            | Self::DescriptorBudget => None,
        }
    }
}

impl From<DestinationConnectError> for HandoffLandingError {
    fn from(source: DestinationConnectError) -> Self {
        Self::Destination(source)
    }
}

/// One LINE-side session transfer failed; the client socket must be reset.
#[derive(Debug)]
pub enum HandoffLineError {
    /// The descriptor budget denied the handoff connection.
    DescriptorBudget,
    /// The shared dial/write deadline elapsed.
    Timeout,
    /// The landing dial, socket configuration, or transfer write failed.
    Connect(io::Error),
    /// The system clock is before the Unix epoch.
    Clock,
    /// Sealing the continuation state failed.
    Transfer(HandoffError),
    /// The handoff socket halves could not be reunited (unreachable in practice).
    Reunite,
    /// LANDING produced no TLS downlink byte within the first-byte deadline:
    /// it closed silently, stalled, or answered with non-session bytes — the
    /// only failure signal the silent protocol carries.
    LandingRejected,
    /// The raw client-to-landing relay failed mid-session.
    Relay(io::Error),
}

impl fmt::Display for HandoffLineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DescriptorBudget => {
                formatter.write_str("descriptor budget denied the handoff connection")
            }
            Self::Timeout => formatter.write_str("handoff transfer timed out"),
            Self::Connect(_) => formatter.write_str("failed to reach the handoff landing node"),
            Self::Clock => formatter.write_str("system clock is before the Unix epoch"),
            Self::Transfer(source) => source.fmt(formatter),
            Self::Reunite => formatter.write_str("handoff socket halves did not reunite"),
            Self::LandingRejected => {
                formatter.write_str("handoff landing node closed without serving the session")
            }
            Self::Relay(_) => formatter.write_str("handoff raw relay failed"),
        }
    }
}

impl Error for HandoffLineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Connect(source) | Self::Relay(source) => Some(source),
            Self::Transfer(source) => Some(source),
            Self::DescriptorBudget
            | Self::Timeout
            | Self::Clock
            | Self::Reunite
            | Self::LandingRejected => None,
        }
    }
}
