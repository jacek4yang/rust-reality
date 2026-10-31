//! Native Windows browser profiles, pinned to the authenticated capture corpus.
//!
//! Browser selection changes the offer only. REALITY authentication and TLS
//! transcript processing continue through the single client handshake path.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Browser version reproduced by the outbound ClientHello.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum BrowserFingerprint {
    /// Chrome 156.0.8078.74 on Windows (the default).
    #[default]
    Chrome,
    /// Firefox 159.0 on Windows.
    Firefox,
}

impl BrowserFingerprint {
    pub(super) const fn ciphers(self) -> &'static [u16] {
        match self {
            Self::Chrome => &[
                4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157,
                47, 53,
            ],
            Self::Firefox => &[
                4865, 4867, 4866, 49195, 49199, 52393, 52392, 49196, 49200, 49171, 49172, 156, 157,
                47, 53,
            ],
        }
    }
    pub(super) const fn signatures(self) -> &'static [u16] {
        match self {
            Self::Chrome => &[
                2308, 2309, 2310, 1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537,
            ],
            Self::Firefox => &[
                1027, 1283, 1539, 2052, 2053, 2054, 1025, 1281, 1537, 515, 513,
            ],
        }
    }
}

// Chrome 156 Chrome Root Store trust-anchor identifiers (not certificates).
pub(super) const CHROME_TRUST_ANCHORS: &[u8] = &[
    0, 184, 5, 130, 223, 19, 2, 1, 5, 130, 223, 19, 2, 6, 5, 130, 223, 19, 2, 13, 5, 130, 223, 19,
    2, 14, 5, 130, 223, 19, 2, 15, 5, 130, 223, 19, 2, 18, 5, 130, 223, 19, 2, 19, 5, 130, 223, 19,
    2, 20, 8, 131, 154, 100, 140, 155, 45, 1, 7, 8, 131, 154, 100, 140, 155, 45, 1, 8, 8, 131, 154,
    100, 140, 155, 45, 1, 9, 8, 131, 154, 100, 140, 155, 45, 1, 10, 8, 131, 154, 100, 140, 155, 45,
    1, 11, 8, 131, 154, 100, 140, 155, 45, 1, 12, 8, 131, 154, 100, 140, 155, 45, 1, 13, 8, 131,
    154, 100, 140, 155, 45, 1, 18, 8, 131, 154, 100, 140, 155, 45, 1, 19, 4, 214, 121, 9, 1, 4,
    214, 121, 9, 4, 4, 214, 121, 9, 5, 4, 214, 121, 9, 6, 4, 214, 121, 9, 7, 4, 214, 121, 9, 8, 4,
    214, 121, 9, 10, 4, 214, 121, 9, 11, 4, 214, 121, 9, 12, 4, 214, 121, 9, 13, 4, 214, 121, 9,
    15,
];
