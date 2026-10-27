//! NXR authentication-request error surface.
//!
//! Kept in its own module so key / layout / encode-decode stay focused on
//! their own concerns while callers keep importing `NxrProtocolError` from
//! `protocol::nxr`.

use std::error::Error;
use std::fmt;

/// NXR request construction or authentication failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NxrProtocolError {
    Length,
    Version,
    Flags,
    Address,
    Port,
    TimeWindow,
    Authentication,
    Allocation,
}

impl fmt::Display for NxrProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length => formatter.write_str("NXR authentication request length is invalid"),
            Self::Version => formatter.write_str("NXR authentication version is invalid"),
            Self::Flags => formatter.write_str("NXR authentication flags are unsupported"),
            Self::Address => formatter.write_str("NXR destination address is invalid"),
            Self::Port => formatter.write_str("NXR destination port is invalid"),
            Self::TimeWindow => {
                formatter.write_str("NXR authentication timestamp is outside policy")
            }
            Self::Authentication => formatter.write_str("NXR authentication failed"),
            Self::Allocation => formatter.write_str("NXR request allocation failed"),
        }
    }
}

impl Error for NxrProtocolError {}
