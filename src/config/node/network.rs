//! Outbound address-family policy.
//!
//! The previous model exposed four timing heuristics here — the happy-eyeballs
//! delay, a route-observation lifetime, a family penalty, and a latency memory.
//! None of them is a decision an operator has information to make better than
//! the process does, so they are derived and only the family preference
//! remains configurable.
//!
//! This policy governs destinations this process resolves and dials itself.
//! Destinations delegated to a SOCKS5, NXR, or Handoff peer keep their original
//! address and are that peer's concern.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Process-wide dialing behaviour.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NetworkConfig {
    /// Which address families to dial, and which to prefer.
    ///
    /// Absent means [`DialPolicy::Auto`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<DialPolicy>,
}

impl NetworkConfig {
    /// The dial policy, applying the default.
    #[must_use]
    pub fn ip(&self) -> DialPolicy {
        self.ip.unwrap_or_default()
    }
}

/// Address families enabled for locally resolved connection setup.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DialPolicy {
    /// Both families, preferring whichever the process observes to be healthy.
    #[default]
    Auto,
    /// Both families, starting from IPv4 unless it is unhealthy.
    PreferIpv4,
    /// Both families, starting from IPv6 unless it is unhealthy.
    PreferIpv6,
    /// IPv4 only.
    Ipv4Only,
    /// IPv6 only.
    Ipv6Only,
}

impl DialPolicy {
    /// The stable name used in configuration, logs, and reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::PreferIpv4 => "preferIpv4",
            Self::PreferIpv6 => "preferIpv6",
            Self::Ipv4Only => "ipv4Only",
            Self::Ipv6Only => "ipv6Only",
        }
    }

    /// Whether IPv4 may be dialled.
    #[must_use]
    pub const fn allows_ipv4(self) -> bool {
        !matches!(self, Self::Ipv6Only)
    }

    /// Whether IPv6 may be dialled.
    #[must_use]
    pub const fn allows_ipv6(self) -> bool {
        !matches!(self, Self::Ipv4Only)
    }

    /// The stated family preference, when the operator stated one.
    #[must_use]
    pub const fn prefers_ipv4(self) -> Option<bool> {
        match self {
            Self::PreferIpv4 | Self::Ipv4Only => Some(true),
            Self::PreferIpv6 | Self::Ipv6Only => Some(false),
            Self::Auto => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DialPolicy, NetworkConfig};

    #[test]
    fn an_empty_network_block_dials_both_families() {
        let network: NetworkConfig = serde_json::from_str("{}").expect("network must decode");

        assert_eq!(network.ip(), DialPolicy::Auto);
        assert!(network.ip().allows_ipv4() && network.ip().allows_ipv6());
        assert_eq!(network.ip().prefers_ipv4(), None);
    }

    #[test]
    fn single_family_policies_disable_the_other_family() {
        let v6: NetworkConfig =
            serde_json::from_str(r#"{"ip":"ipv6Only"}"#).expect("network must decode");

        assert!(!v6.ip().allows_ipv4() && v6.ip().allows_ipv6());
        assert_eq!(v6.ip().prefers_ipv4(), Some(false));
    }

    #[test]
    fn the_removed_dial_heuristics_are_rejected() {
        for removed in [
            r#"{"dial":{"mode":"auto"}}"#,
            r#"{"fallbackDelayMs":250}"#,
            r#"{"routeRefreshSeconds":30}"#,
            r#"{"hardFailurePenaltySeconds":30}"#,
            r#"{"latencyMemorySeconds":300}"#,
        ] {
            assert!(
                serde_json::from_str::<NetworkConfig>(removed).is_err(),
                "{removed} is derived, not configured"
            );
        }
    }
}
