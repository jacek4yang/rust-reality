//! REALITY identity and cover target.
//!
//! Two values are irreducible operator input: the cover target, which must be
//! a real TLS 1.3 host the operator has chosen and verified, and the private
//! key, which `rust-reality generate x25519` produces. Everything else has a
//! defensible default derived from those two.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::config::secret::SecretString;

/// REALITY server identity.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RealityConfig {
    /// Cover target in `host:port` form.
    ///
    /// Required: only the operator can choose a host that is plausible for
    /// this server to be fronting, and `rust-reality check-cover` exists to
    /// evaluate candidates before one is committed here.
    pub cover: String,
    /// X25519 private key, URL-safe unpadded base64.
    ///
    /// Required and secret. The matching public key goes to clients.
    pub private_key: SecretString,
    /// Client SNI values accepted for this identity.
    ///
    /// Absent means the host part of `cover`, which is what a client fronting
    /// that cover sends. Supply this only to accept additional names, such as
    /// a leftmost single-label wildcard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_names: Option<Vec<String>>,
    /// Largest accepted client-clock difference in milliseconds.
    ///
    /// Absent means 60000. Zero disables the check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_time_diff_ms: Option<u64>,
    /// Authenticated-only cover latency optimizations.
    ///
    /// Expert surface. These change what this server does toward the cover
    /// host, so they are operator policy rather than internal tuning, and each
    /// switch exists so a misbehaving cover can be isolated. Rejected
    /// handshakes always use the live cover path regardless of these settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cover_optimization: Option<CoverOptimizationConfig>,
}

/// The default largest accepted client-clock difference, in milliseconds.
pub const DEFAULT_MAX_TIME_DIFF_MS: u64 = 60_000;

impl RealityConfig {
    /// The accepted client-clock skew, applying the default.
    #[must_use]
    pub fn max_time_diff_ms(&self) -> u64 {
        self.max_time_diff_ms.unwrap_or(DEFAULT_MAX_TIME_DIFF_MS)
    }

    /// The host part of `cover`, without the port.
    ///
    /// Returns `None` when `cover` has no `:port` suffix, which semantic
    /// validation rejects with a precise message.
    #[must_use]
    pub fn cover_host(&self) -> Option<&str> {
        self.cover.rsplit_once(':').map(|(host, _)| host)
    }

    /// The accepted client SNI values, applying the cover-host default.
    #[must_use]
    pub fn effective_server_names(&self) -> Vec<&str> {
        match &self.server_names {
            Some(names) => names.iter().map(String::as_str).collect(),
            None => self.cover_host().into_iter().collect(),
        }
    }
}

/// Switches for authenticated-only cover optimizations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CoverOptimizationConfig {
    /// Master switch. Absent means enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Keep TCP-established cover sockets ready. No TLS bytes are sent before
    /// checkout. Absent means enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warm_tcp: Option<bool>,
    /// Build cover-derived TLS profiles in the background and use them only
    /// after successful authentication and replay reservation. Unknown, stale,
    /// or unstable classes fall back to the live cover. Absent means enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prebuilt_profiles: Option<bool>,
}

impl CoverOptimizationConfig {
    /// Whether cover optimizations run at all.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }

    /// Whether warm cover sockets are kept, honouring the master switch.
    #[must_use]
    pub fn warm_tcp(&self) -> bool {
        self.enabled() && self.warm_tcp.unwrap_or(true)
    }

    /// Whether prebuilt profiles are used, honouring the master switch.
    #[must_use]
    pub fn prebuilt_profiles(&self) -> bool {
        self.enabled() && self.prebuilt_profiles.unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::{CoverOptimizationConfig, DEFAULT_MAX_TIME_DIFF_MS, RealityConfig};

    fn parse(json: &str) -> RealityConfig {
        serde_json::from_str(json).expect("reality settings must decode")
    }

    const MINIMAL: &str = r#"{"cover":"www.example.com:443","privateKey":"k"}"#;

    #[test]
    fn server_names_default_to_the_cover_host() {
        let reality = parse(MINIMAL);

        assert_eq!(reality.cover_host(), Some("www.example.com"));
        assert_eq!(reality.effective_server_names(), ["www.example.com"]);
        assert_eq!(reality.max_time_diff_ms(), DEFAULT_MAX_TIME_DIFF_MS);
    }

    #[test]
    fn explicit_server_names_replace_the_default() {
        let reality = parse(
            r#"{"cover":"www.example.com:443","privateKey":"k",
                "serverNames":["a.example.com","*.example.com"]}"#,
        );

        assert_eq!(
            reality.effective_server_names(),
            ["a.example.com", "*.example.com"]
        );
    }

    #[test]
    fn an_ipv6_cover_keeps_its_bracketed_host() {
        let reality = parse(r#"{"cover":"[2001:db8::1]:443","privateKey":"k"}"#);

        assert_eq!(reality.cover_host(), Some("[2001:db8::1]"));
    }

    #[test]
    fn a_cover_without_a_port_yields_no_host() {
        let reality = parse(r#"{"cover":"www.example.com","privateKey":"k"}"#);

        assert_eq!(
            reality.cover_host(),
            None,
            "semantic validation reports the missing port"
        );
    }

    #[test]
    fn the_master_switch_disables_every_optimization() {
        let disabled = CoverOptimizationConfig {
            enabled: Some(false),
            warm_tcp: Some(true),
            prebuilt_profiles: Some(true),
        };

        assert!(!disabled.enabled());
        assert!(
            !disabled.warm_tcp(),
            "the master switch must override a sub-switch"
        );
        assert!(!disabled.prebuilt_profiles());

        let default = CoverOptimizationConfig::default();
        assert!(default.enabled() && default.warm_tcp() && default.prebuilt_profiles());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        assert!(
            serde_json::from_str::<RealityConfig>(
                r#"{"cover":"a:443","privateKey":"k","target":"b:443"}"#
            )
            .is_err()
        );
        assert!(serde_json::from_str::<RealityConfig>(r#"{"cover":"a:443"}"#).is_err());
    }
}
