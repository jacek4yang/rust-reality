//! GeoIP and GeoSite data.
//!
//! Needed only by an entry node, and only when a routing rule names a `geoip:`
//! or `geosite:` condition. A node whose rules use plain domains and CIDRs
//! never downloads anything.

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Where geo data comes from and how long a snapshot is kept.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AssetsConfig {
    /// HTTPS URL of an Xray-compatible `geoip.dat`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geoip: Option<String>,
    /// HTTPS URL of an Xray-compatible `geosite.dat`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geosite: Option<String>,
    /// Directory holding validated downloads. Absent means
    /// `/var/lib/rust-reality/assets`, which the service account must own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_directory: Option<PathBuf>,
    /// How often a new snapshot is polled for, in seconds. Absent means one
    /// day. A running server keeps serving its last good snapshot when a poll
    /// fails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reload_interval_seconds: Option<u64>,
}

/// The default GeoIP source.
pub const DEFAULT_GEOIP_URL: &str =
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat";

/// The default GeoSite source.
pub const DEFAULT_GEOSITE_URL: &str =
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat";

/// The default asset cache directory.
pub const DEFAULT_CACHE_DIRECTORY: &str = "/var/lib/rust-reality/assets";

/// The default snapshot poll interval, in seconds.
pub const DEFAULT_RELOAD_INTERVAL_SECONDS: u64 = 86_400;

impl AssetsConfig {
    /// The GeoIP source, applying the default.
    #[must_use]
    pub fn geoip(&self) -> &str {
        self.geoip.as_deref().unwrap_or(DEFAULT_GEOIP_URL)
    }

    /// The GeoSite source, applying the default.
    #[must_use]
    pub fn geosite(&self) -> &str {
        self.geosite.as_deref().unwrap_or(DEFAULT_GEOSITE_URL)
    }

    /// The cache directory, applying the default.
    #[must_use]
    pub fn cache_directory(&self) -> PathBuf {
        self.cache_directory
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CACHE_DIRECTORY))
    }

    /// The snapshot poll interval, applying the default.
    #[must_use]
    pub fn reload_interval_seconds(&self) -> u64 {
        self.reload_interval_seconds
            .unwrap_or(DEFAULT_RELOAD_INTERVAL_SECONDS)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        AssetsConfig, DEFAULT_CACHE_DIRECTORY, DEFAULT_GEOIP_URL, DEFAULT_RELOAD_INTERVAL_SECONDS,
    };

    #[test]
    fn an_empty_assets_block_takes_every_default() {
        let assets: AssetsConfig = serde_json::from_str("{}").expect("assets must decode");

        assert_eq!(assets.geoip(), DEFAULT_GEOIP_URL);
        assert_eq!(
            assets.cache_directory(),
            PathBuf::from(DEFAULT_CACHE_DIRECTORY)
        );
        assert_eq!(
            assets.reload_interval_seconds(),
            DEFAULT_RELOAD_INTERVAL_SECONDS
        );
    }

    #[test]
    fn the_removed_transfer_bounds_are_rejected() {
        for removed in [r#"{"requestTimeoutSeconds":120}"#, r#"{"maxBytes":1024}"#] {
            assert!(
                serde_json::from_str::<AssetsConfig>(removed).is_err(),
                "{removed} bounds the implementation, not the deployment"
            );
        }
    }
}
