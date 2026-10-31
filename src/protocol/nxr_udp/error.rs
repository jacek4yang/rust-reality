//! NXR UDP association error surface.
//!
//! Kept in its own module so open / frame / session-key stay focused on their
//! own concerns while callers keep importing [`NxrUdpError`] from
//! `protocol::nxr_udp`.

use std::error::Error;
use std::fmt;

/// NXR UDP open / framing / session errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NxrUdpError {
    Length,
    Truncated,
    Version,
    Flags,
    WrongMode,
    Address,
    Port,
    TimeWindow,
    Authentication,
    Allocation,
    Payload,
    FrameType,
    Direction,
    Sequence,
}

impl fmt::Display for NxrUdpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length => formatter.write_str("NXR UDP length is invalid"),
            Self::Truncated => formatter.write_str("NXR UDP frame is truncated"),
            Self::Version => formatter.write_str("NXR UDP version is invalid"),
            Self::Flags => formatter.write_str("NXR UDP flags are unsupported"),
            Self::WrongMode => formatter.write_str("NXR open mode is not UDP"),
            Self::Address => formatter.write_str("NXR UDP address is invalid"),
            Self::Port => formatter.write_str("NXR UDP port is invalid"),
            Self::TimeWindow => formatter.write_str("NXR UDP timestamp is outside policy"),
            Self::Authentication => formatter.write_str("NXR UDP authentication failed"),
            Self::Allocation => formatter.write_str("NXR UDP allocation failed"),
            Self::Payload => formatter.write_str("NXR UDP payload exceeds bound"),
            Self::FrameType => formatter.write_str("NXR UDP frame type is invalid"),
            Self::Direction => formatter.write_str("NXR UDP frame direction is invalid"),
            Self::Sequence => formatter.write_str("NXR UDP frame sequence is invalid or exhausted"),
        }
    }
}

impl Error for NxrUdpError {}

impl From<NxrUdpError> for crate::protocol::nxr::NxrProtocolError {
    fn from(error: NxrUdpError) -> Self {
        match error {
            NxrUdpError::Length | NxrUdpError::Truncated | NxrUdpError::Payload => Self::Length,
            NxrUdpError::Version => Self::Version,
            NxrUdpError::Flags
            | NxrUdpError::WrongMode
            | NxrUdpError::FrameType
            | NxrUdpError::Direction
            | NxrUdpError::Sequence => Self::Flags,
            NxrUdpError::Address => Self::Address,
            NxrUdpError::Port => Self::Port,
            NxrUdpError::TimeWindow => Self::TimeWindow,
            NxrUdpError::Authentication => Self::Authentication,
            NxrUdpError::Allocation => Self::Allocation,
        }
    }
}
