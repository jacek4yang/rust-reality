//! NXR request authenticator: HMAC/time verify, then replay reserve.
//!
//! Behavior is unchanged; this module owns `NxrAuthenticator` so landing I/O
//! stays in the parent module.

use crate::protocol::{
    nxr::{NxrKey, NxrProtocolError, decode_authenticated_request},
    nxr_udp::{NxrUdpSessionKey, UdpAuthenticatedOpen, decode_udp_open, open_authenticated_prefix},
    vless::Destination,
};

use super::{error::NxrAuthenticationError, replay::NxrReplayCache};

/// Verified NXR request policy with an independent HMAC key and replay cache.
#[derive(Clone)]
pub struct NxrAuthenticator {
    key: NxrKey,
    replay: NxrReplayCache,
    maximum_time_difference: u64,
}

impl NxrAuthenticator {
    /// Binds a PSK, time window in seconds, and bounded nonce cache.
    #[must_use]
    pub const fn new(key: NxrKey, replay: NxrReplayCache, maximum_time_difference: u64) -> Self {
        Self {
            key,
            replay,
            maximum_time_difference,
        }
    }

    /// Verifies HMAC and time first, reserves the nonce second, and only then
    /// returns a parsed destination that callers may resolve or connect.
    ///
    /// # Errors
    ///
    /// Rejects malformed or unauthenticated requests, stale timestamps, duplicate
    /// nonces, and exhausted replay capacity.
    pub fn authenticate(
        &self,
        request: &[u8],
        now: u64,
    ) -> Result<Destination, NxrAuthenticationError> {
        let authenticated =
            decode_authenticated_request(request, &self.key, now, self.maximum_time_difference)?;
        self.replay.reserve(*authenticated.nonce())?;
        let (_, destination) = authenticated.into_parts();
        Ok(destination)
    }

    /// Verifies a UDP-mode open, reserves the nonce, and derives the session MAC key.
    ///
    /// # Errors
    ///
    /// Rejects TCP-mode opens, HMAC/time failures, and replay admission failures.
    pub fn authenticate_udp(
        &self,
        request: &[u8],
        now: u64,
    ) -> Result<(UdpAuthenticatedOpen, NxrUdpSessionKey), NxrAuthenticationError> {
        let open = decode_udp_open(request, &self.key, now, self.maximum_time_difference)
            .map_err(|error| NxrAuthenticationError::Protocol(NxrProtocolError::from(error)))?;
        self.replay.reserve(*open.nonce())?;
        let prefix = open_authenticated_prefix(request)
            .ok_or(NxrAuthenticationError::Protocol(NxrProtocolError::Length))?;
        let session = NxrUdpSessionKey::derive(&self.key, prefix);
        Ok((open, session))
    }
}
