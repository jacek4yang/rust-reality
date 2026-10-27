//! Closed-vocabulary error types for the NXR landing path.
//!
//! Behavior is unchanged; this module only owns the typed failure vocabulary
//! used by replay admission, authentication, and landing I/O.

use std::{error::Error, fmt, io};

use crate::{
    protocol::{nxr::NxrProtocolError, nxr_udp::NxrUdpError},
    runtime::AdmissionDenied,
    server::{connector::DestinationConnectError, pre_auth::PreAuthError},
    transport::tcp_relay::TcpRelayConfigError,
};

/// Validated NXR listener state could not be compiled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NxrLandingConfigError {
    /// PSK decoding or length did not match the protocol contract.
    Key,
    /// Replay capacity could not be represented on this target.
    Capacity,
    /// Replay cache initialization failed.
    Replay(NxrReplayError),
    /// Bounded plaintext relay state could not be compiled.
    Relay(TcpRelayConfigError),
}

impl fmt::Display for NxrLandingConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid NXR landing listener configuration")
    }
}

impl Error for NxrLandingConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Replay(source) => Some(source),
            Self::Relay(source) => Some(source),
            Self::Key | Self::Capacity => None,
        }
    }
}

/// A verified nonce could not be admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NxrReplayError {
    Duplicate,
    Capacity,
    Unavailable,
}

impl fmt::Display for NxrReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NXR replay admission failed")
    }
}

impl Error for NxrReplayError {}

/// One NXR HMAC, time, or nonce check failed.
#[derive(Debug)]
pub enum NxrAuthenticationError {
    Protocol(NxrProtocolError),
    Replay(NxrReplayError),
}

impl fmt::Display for NxrAuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NXR authentication rejected")
    }
}

impl Error for NxrAuthenticationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(source) => Some(source),
            Self::Replay(source) => Some(source),
        }
    }
}

impl From<NxrProtocolError> for NxrAuthenticationError {
    fn from(source: NxrProtocolError) -> Self {
        Self::Protocol(source)
    }
}

impl From<NxrReplayError> for NxrAuthenticationError {
    fn from(source: NxrReplayError) -> Self {
        Self::Replay(source)
    }
}

/// One NXR landing connection failed and must close silently.
#[derive(Debug)]
pub enum NxrLandingError {
    Admission(AdmissionDenied),
    Reclaimed,
    /// The LINE retired an unused zero-byte warm transport normally.
    PreAuthPeerClosed,
    /// Runtime reload retired this unused pre-auth generation normally.
    PreAuthGenerationRetired,
    Timeout,
    Read(io::Error),
    Protocol(NxrProtocolError),
    Allocation,
    Clock,
    Authentication(NxrAuthenticationError),
    Destination(DestinationConnectError),
    Relay(io::Error),
    DescriptorBudget,
    /// UDP socket I/O on the NXR UDP association path.
    UdpIo(io::Error),
    /// NXR UDP framing / session protocol failure.
    UdpProtocol(NxrUdpError),
}

impl NxrLandingError {
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

impl fmt::Display for NxrLandingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NXR landing connection closed")
    }
}

impl Error for NxrLandingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::DescriptorBudget => None,
            Self::Admission(source) => Some(source),
            Self::Read(source) | Self::Relay(source) | Self::UdpIo(source) => Some(source),
            Self::Protocol(source) => Some(source),
            Self::UdpProtocol(source) => Some(source),
            Self::Authentication(source) => Some(source),
            Self::Destination(source) => Some(source),
            Self::Reclaimed
            | Self::PreAuthPeerClosed
            | Self::PreAuthGenerationRetired
            | Self::Timeout
            | Self::Allocation
            | Self::Clock => None,
        }
    }
}

impl From<NxrAuthenticationError> for NxrLandingError {
    fn from(source: NxrAuthenticationError) -> Self {
        Self::Authentication(source)
    }
}

impl From<DestinationConnectError> for NxrLandingError {
    fn from(source: DestinationConnectError) -> Self {
        Self::Destination(source)
    }
}
