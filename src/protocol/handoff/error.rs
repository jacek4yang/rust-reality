//! Handoff control-channel error surface.
//!
//! Kept in its own module so wire codec / keys / replay / seal stay focused on
//! their own concerns while callers keep importing `HandoffError` from
//! `protocol::handoff`.

use std::error::Error;
use std::fmt;

/// Handoff transfer construction or verification failed.
///
/// This is the entire error vocabulary a LANDING handler may log; no variant
/// carries detail beyond the failure class, and nothing is ever written back
/// to the control connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffError {
    /// The message or blob length is outside the fixed bounds.
    Length,
    /// The magic, protocol version, or state version is unsupported.
    Version,
    /// The timestamp is outside the accepted clock window.
    TimeWindow,
    /// The transfer nonce was already seen or the replay cache is full.
    Replay,
    /// The ephemeral key agreement or AEAD authentication failed.
    Authentication,
    /// A decrypted continuation field failed a consistency check.
    State,
    /// A bounded buffer reservation failed.
    Allocation,
    /// Secure ephemeral randomness was unavailable.
    Random,
    /// A mature cryptographic primitive rejected an invariant.
    Crypto,
}

impl fmt::Display for HandoffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length => formatter.write_str("handoff transfer length is invalid"),
            Self::Version => formatter.write_str("handoff transfer version is unsupported"),
            Self::TimeWindow => formatter.write_str("handoff transfer timestamp is outside policy"),
            Self::Replay => formatter.write_str("handoff transfer nonce was rejected"),
            Self::Authentication => formatter.write_str("handoff transfer authentication failed"),
            Self::State => formatter.write_str("handoff continuation state is invalid"),
            Self::Allocation => formatter.write_str("handoff transfer allocation failed"),
            Self::Random => formatter.write_str("handoff randomness is unavailable"),
            Self::Crypto => formatter.write_str("handoff cryptographic primitive failed"),
        }
    }
}

impl Error for HandoffError {}
