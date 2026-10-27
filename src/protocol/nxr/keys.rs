//! NXR HMAC key material and authenticate/verify helpers.
//!
//! Wire encode/decode stays in the parent module; this submodule owns the
//! independently generated PSK template and the HMAC tag operations.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::error::NxrProtocolError;
use super::layout::TAG_LEN;

type NxrHmac = Hmac<Sha256>;

/// Independent NXR HMAC key, held as a keyed HMAC template so authenticating
/// and verifying clone precomputed ipad/opad SHA-256 cores instead of deriving
/// them per request. Debug output never reveals its bytes.
///
/// `Hmac<Sha256>` carries no `ZeroizeOnDrop` marker, because `hmac` builds it
/// through `digest::buffer_fixed!` with `MacTraits` and only `FixedHashTraits`
/// requests that marker. Erasure is nonetheless complete through the composed
/// drop path that the enabled `hmac/zeroize` and `sha2/zeroize` features turn
/// on: `BlockBuffer` zeroizes its whole block and position, and each
/// `Sha256VarCore` zeroizes its chaining state and block length, reached by
/// field recursion through `HmacCore` and `CtOutWrapper`. Do not re-add a
/// `ZeroizeOnDrop` bound here; it fails to compile and proves nothing. See the
/// [performance investigation record] for the measured evidence.
///
/// [performance investigation record]:
///     https://github.com/jacek4yang/rust-reality/blob/main/docs/en/operations/performance-investigation-record.md
#[derive(Clone)]
pub struct NxrKey(NxrHmac);

impl NxrKey {
    /// Creates a key from exactly 256 bits of independently generated entropy.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        let bytes = Zeroizing::new(bytes);
        let template =
            NxrHmac::new_from_slice(bytes.as_slice()).expect("HMAC-SHA256 accepts a 32-byte key");
        Self(template)
    }

    fn mac(&self) -> NxrHmac {
        self.0.clone()
    }

    /// Raw `HMAC-SHA256(psk, message)` — used for open tags (TCP and UDP).
    #[must_use]
    pub fn tag(&self, message: &[u8]) -> [u8; TAG_LEN] {
        let mut mac = self.mac();
        mac.update(message);
        mac.finalize().into_bytes().into()
    }

    /// Domain-separated HMAC derivation used by NXR UDP session MACs (ADR 0060).
    ///
    /// Computes `HMAC-SHA256(psk, label || data)`. Labels must be unique per
    /// purpose so TCP open tags and UDP session keys cannot be confused.
    #[must_use]
    pub fn derive(&self, label: &[u8], data: &[u8]) -> [u8; TAG_LEN] {
        let mut mac = self.mac();
        mac.update(label);
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
}

impl fmt::Debug for NxrKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NxrKey([REDACTED])")
    }
}

pub(super) fn authenticate(key: &NxrKey, input: &[u8]) -> [u8; TAG_LEN] {
    let mut mac = key.mac();
    mac.update(input);
    mac.finalize().into_bytes().into()
}

pub(super) fn verify(key: &NxrKey, input: &[u8], tag: &[u8]) -> Result<(), NxrProtocolError> {
    let mut mac = key.mac();
    mac.update(input);
    mac.verify_slice(tag)
        .map_err(|_| NxrProtocolError::Authentication)
}
