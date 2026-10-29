//! NXR UDP session MAC key material and open-tag helpers.
//!
//! Wire encode/decode stays in the parent module; this submodule owns the
//! session-MAC derivation labels, [`NxrUdpSessionKey`], and open HMAC helpers.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::super::nxr::NxrKey;
use super::error::NxrUdpError;
use super::layout::{OPEN_TAG_LEN, SESSION_TAG_LEN};

type SessionHmac = Hmac<sha2::Sha256>;

/// Domain separation for UDP session-MAC key derivation.
const SESSION_MAC_LABEL: &[u8] = b"rust-reality/nxr-udp/v1/session-mac\0";

/// Domain separation for per-frame MACs (direction byte follows the label).
const FRAME_MAC_LABEL: &[u8] = b"rust-reality/nxr-udp/v1/frame-mac\0";

/// Session MAC key for one NXR UDP association.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct NxrUdpSessionKey(Zeroizing<[u8; SESSION_TAG_LEN]>);

impl fmt::Debug for NxrUdpSessionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NxrUdpSessionKey([REDACTED])")
    }
}

impl PartialEq for NxrUdpSessionKey {
    fn eq(&self, other: &Self) -> bool {
        // Equality only for tests; not used on hot paths.
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for NxrUdpSessionKey {}

impl NxrUdpSessionKey {
    /// Derives the session MAC key from the PSK and authenticated open prefix.
    #[must_use]
    pub fn derive(key: &NxrKey, open_authenticated_prefix: &[u8]) -> Self {
        Self(Zeroizing::new(
            key.derive(SESSION_MAC_LABEL, open_authenticated_prefix),
        ))
    }

    fn mac(&self) -> SessionHmac {
        SessionHmac::new_from_slice(self.0.as_slice()).expect("HMAC-SHA256 accepts 32-byte key")
    }

    /// Computes the frame MAC for `direction` over `body`.
    #[must_use]
    pub fn frame_tag(&self, direction: u8, body: &[u8]) -> [u8; SESSION_TAG_LEN] {
        let mut mac = self.mac();
        mac.update(FRAME_MAC_LABEL);
        mac.update(&[direction]);
        mac.update(body);
        mac.finalize().into_bytes().into()
    }

    /// Verifies a frame MAC in constant time.
    ///
    /// # Errors
    ///
    /// [`NxrUdpError::Authentication`] on mismatch.
    pub fn verify_frame(&self, direction: u8, body: &[u8], tag: &[u8]) -> Result<(), NxrUdpError> {
        let mut mac = self.mac();
        mac.update(FRAME_MAC_LABEL);
        mac.update(&[direction]);
        mac.update(body);
        mac.verify_slice(tag)
            .map_err(|_| NxrUdpError::Authentication)
    }
}

pub(super) fn open_tag(key: &NxrKey, authenticated: &[u8]) -> [u8; OPEN_TAG_LEN] {
    // Same construction as TCP NXR open tags: HMAC(psk, authenticated_bytes).
    // Mode separation is the FLAG_UDP byte inside `authenticated`.
    key.tag(authenticated)
}

pub(super) fn verify_open_tag(
    key: &NxrKey,
    authenticated: &[u8],
    tag: &[u8],
) -> Result<(), NxrUdpError> {
    let expected = open_tag(key, authenticated);
    use subtle::ConstantTimeEq;
    if bool::from(expected.as_slice().ct_eq(tag)) {
        Ok(())
    } else {
        Err(NxrUdpError::Authentication)
    }
}
