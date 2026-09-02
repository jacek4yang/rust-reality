//! Name resolution.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Resolvers and the shared resolution cache.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DnsConfig {
    /// Upstream resolvers in priority order.
    ///
    /// Exactly `["system"]` — the default — uses the operating system resolver
    /// through `getaddrinfo`, which honours `/etc/hosts`, `/etc/resolv.conf`,
    /// and any local stub resolver. Any other list selects the built-in
    /// resolver, where each entry is an address (`1.1.1.1`,
    /// `[2606:4700:4700::1111]:53`) or a hostname resolved once through the
    /// system resolver at startup, with an optional `:port` defaulting to 53.
    /// UDP is used, falling back to TCP on truncation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servers: Option<Vec<String>>,
    /// Deadline for one resolution attempt, in milliseconds. Absent means 5000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Cache bounds. Expert surface: every field derives a safe value, and an
    /// ordinary deployment has no reason to state any of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<DnsCacheConfig>,
}

/// The resolver list that selects the operating system resolver.
pub const SYSTEM_RESOLVER: &str = "system";

/// The default resolution deadline, in milliseconds.
pub const DEFAULT_DNS_TIMEOUT_MS: u64 = 5_000;

impl DnsConfig {
    /// The configured resolvers, applying the system-resolver default.
    #[must_use]
    pub fn servers(&self) -> Vec<&str> {
        match &self.servers {
            Some(servers) => servers.iter().map(String::as_str).collect(),
            None => vec![SYSTEM_RESOLVER],
        }
    }

    /// The resolution deadline, applying the default.
    #[must_use]
    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms.unwrap_or(DEFAULT_DNS_TIMEOUT_MS)
    }

    /// Whether the effective resolver list selects the operating system
    /// resolver.
    #[must_use]
    pub fn uses_system_resolver(&self) -> bool {
        self.servers() == [SYSTEM_RESOLVER]
    }
}

/// Bounds for the shared resolution cache.
///
/// Dynamic answers are cached only when the upstream resolver supplies a TTL.
/// With the system resolver there are no TTLs, so only single-flight
/// coalescing applies and nothing is cached, unless `systemReuseMs` opens a
/// short reuse window. With real resolvers every cached answer carries the
/// upstream TTL clamped to these bounds. Statically configured peers — the
/// REALITY cover and fixed SOCKS5, NXR, or Handoff endpoints — are the
/// exception and are cached in every mode, because the operator owns their
/// staleness through `staticTtlSeconds`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DnsCacheConfig {
    /// Largest number of cached names, counting positive, negative, and
    /// in-flight entries. Absent means a value derived from the memory the
    /// process may use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_entries: Option<u32>,
    /// Floor clamp on upstream positive TTLs, in seconds. Absent means 5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_ttl_seconds: Option<u32>,
    /// Ceiling clamp on upstream positive TTLs, in seconds. Absent means 3600.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ttl_seconds: Option<u32>,
    /// Ceiling clamp on upstream negative TTLs, in seconds. Answers without an
    /// SOA TTL are never cached. Absent means 60.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negative_ttl_seconds: Option<u32>,
    /// Cache duration for statically configured peers, in every resolver mode.
    /// Absent means 300.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_ttl_seconds: Option<u32>,
    /// Reuse window for positive system-resolver answers, in milliseconds.
    ///
    /// This is not authoritative TTL caching: an upstream change becomes
    /// visible only when the window expires, negative answers are never
    /// cached, and there is no stale-while-revalidate. Ignored when real
    /// resolvers are configured, where upstream TTLs govern. Absent means 0,
    /// which disables it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_reuse_ms: Option<u64>,
}

/// The default floor clamp on positive TTLs, in seconds.
pub const DEFAULT_MIN_TTL_SECONDS: u32 = 5;

/// The default ceiling clamp on positive TTLs, in seconds.
pub const DEFAULT_MAX_TTL_SECONDS: u32 = 3_600;

/// The default ceiling clamp on negative TTLs, in seconds.
pub const DEFAULT_NEGATIVE_TTL_SECONDS: u32 = 60;

/// The default cache duration for statically configured peers, in seconds.
pub const DEFAULT_STATIC_TTL_SECONDS: u32 = 300;

impl DnsCacheConfig {
    /// The positive-TTL floor, applying the default.
    #[must_use]
    pub fn min_ttl_seconds(&self) -> u32 {
        self.min_ttl_seconds.unwrap_or(DEFAULT_MIN_TTL_SECONDS)
    }

    /// The positive-TTL ceiling, applying the default.
    #[must_use]
    pub fn max_ttl_seconds(&self) -> u32 {
        self.max_ttl_seconds.unwrap_or(DEFAULT_MAX_TTL_SECONDS)
    }

    /// The negative-TTL ceiling, applying the default.
    #[must_use]
    pub fn negative_ttl_seconds(&self) -> u32 {
        self.negative_ttl_seconds
            .unwrap_or(DEFAULT_NEGATIVE_TTL_SECONDS)
    }

    /// The static-peer cache duration, applying the default.
    #[must_use]
    pub fn static_ttl_seconds(&self) -> u32 {
        self.static_ttl_seconds
            .unwrap_or(DEFAULT_STATIC_TTL_SECONDS)
    }

    /// The system-resolver reuse window, applying the disabled default.
    #[must_use]
    pub fn system_reuse_ms(&self) -> u64 {
        self.system_reuse_ms.unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_DNS_TIMEOUT_MS, DEFAULT_STATIC_TTL_SECONDS, DnsCacheConfig, DnsConfig};

    #[test]
    fn an_empty_dns_block_uses_the_system_resolver() {
        let dns: DnsConfig = serde_json::from_str("{}").expect("dns must decode");

        assert_eq!(dns.servers(), ["system"]);
        assert!(dns.uses_system_resolver());
        assert_eq!(dns.timeout_ms(), DEFAULT_DNS_TIMEOUT_MS);
        assert!(dns.cache.is_none());
    }

    #[test]
    fn explicit_resolvers_leave_the_system_resolver_behind() {
        let dns: DnsConfig =
            serde_json::from_str(r#"{"servers":["1.1.1.1","[2606:4700:4700::1111]:53"]}"#)
                .expect("dns must decode");

        assert!(!dns.uses_system_resolver());
        assert_eq!(dns.servers(), ["1.1.1.1", "[2606:4700:4700::1111]:53"]);
    }

    #[test]
    fn cache_bounds_default_individually() {
        let cache = DnsCacheConfig {
            min_ttl_seconds: Some(30),
            ..DnsCacheConfig::default()
        };

        assert_eq!(cache.min_ttl_seconds(), 30);
        assert_eq!(cache.static_ttl_seconds(), DEFAULT_STATIC_TTL_SECONDS);
        assert_eq!(cache.system_reuse_ms(), 0);
        assert!(
            cache.max_entries.is_none(),
            "an absent entry bound derives from available memory"
        );
    }

    #[test]
    fn unknown_dns_fields_are_rejected() {
        assert!(serde_json::from_str::<DnsConfig>(r#"{"strategy":"asIs"}"#).is_err());
        assert!(serde_json::from_str::<DnsConfig>(r#"{"cache":{"maxSize":10}}"#).is_err());
    }
}
