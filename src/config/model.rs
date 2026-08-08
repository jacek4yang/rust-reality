use std::{fmt, net::IpAddr, path::PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Complete runtime configuration.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Logging destination and retention.
    #[serde(default)]
    pub log: LogConfig,
    /// GeoIP and GeoSite asset locations.
    #[serde(default)]
    pub assets: AssetsConfig,
    /// Name-resolution behavior.
    #[serde(default)]
    pub dns: DnsConfig,
    /// Protected inbound listeners.
    pub inbounds: Vec<InboundConfig>,
    /// Available outbound transports.
    pub outbounds: Vec<OutboundConfig>,
    /// Global and per-user first-match routing.
    pub routing: RoutingConfig,
    /// Resource and relay limits.
    #[serde(default)]
    pub policy: PolicyConfig,
    /// Process resource mode.
    #[serde(default)]
    pub runtime: RuntimeConfig,
}

/// Process-level resource posture.
///
/// The resource mode is a cold setting: it shapes the process-lifetime
/// descriptor budget and the memory monitor, so changing it requires a
/// process restart and is rejected on hot reload.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeConfig {
    /// How conservatively the process treats machine resources.
    ///
    /// `standard` (default) derives every budget from the inherited limits
    /// exactly as documented in the descriptor-budget reference and assumes
    /// nothing about what else runs on the machine.
    ///
    /// `dedicated` declares that this process owns the machine (or its
    /// cgroup): at startup it raises the soft `RLIMIT_NOFILE` to the hard
    /// limit when possible, relaxes the descriptor safety headroom from
    /// `limit/16` to `limit/10`, and runs a bounded memory-pressure monitor
    /// that pauses new setup work before the kernel or the cgroup OOM killer
    /// is reached. See `docs/configuration.md#dedicated-resource-mode`.
    #[serde(default)]
    pub resource_mode: ResourceMode,
}

/// Supported process resource modes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourceMode {
    /// Shared-machine posture; every budget derives from inherited limits.
    #[default]
    Standard,
    /// Single-tenant posture; the process budgets against the whole machine
    /// or cgroup and supervises its own memory pressure.
    Dedicated,
}

impl ResourceMode {
    /// Returns the stable identifier used in logs and reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Dedicated => "dedicated",
        }
    }
}

/// A string whose debug representation never reveals its contents.
#[derive(Clone, Eq, PartialEq, Deserialize, JsonSchema, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    /// Creates a protected string.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Exposes the secret to code that explicitly needs it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Returns whether the secret is empty without revealing it.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

/// Logging configuration.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LogConfig {
    /// Minimum emitted severity.
    #[serde(default)]
    pub level: LogLevel,
    /// Log sink.
    #[serde(default)]
    pub output: LogOutput,
    /// Required only for file output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<FileLogConfig>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            output: LogOutput::Stderr,
            file: None,
        }
    }
}

/// Supported log severities.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Only startup and fatal errors.
    Error,
    /// Warnings and errors.
    Warn,
    /// Normal operational messages.
    #[default]
    Info,
    /// Diagnostic messages that never include configuration or keys.
    Debug,
}

/// Supported log destinations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogOutput {
    /// Process standard error.
    #[default]
    Stderr,
    /// Standard error captured by systemd-journald.
    Journald,
    /// A size-bounded rotating file set.
    File,
}

/// File-log rotation and retention limits.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FileLogConfig {
    /// Active log path.
    pub path: PathBuf,
    /// Rotate before one file exceeds this size.
    pub max_bytes: u64,
    /// Maximum number of active and rotated files.
    pub max_files: u16,
    /// Maximum combined bytes retained across all files.
    pub max_total_bytes: u64,
}

/// Geo asset configuration.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AssetsConfig {
    /// HTTPS URL of an Xray-compatible `geoip.dat` file.
    #[serde(default = "default_geoip_url")]
    pub geoip: String,
    /// HTTPS URL of an Xray-compatible `geosite.dat` file.
    #[serde(default = "default_geosite_url")]
    pub geosite: String,
    /// Persistent directory containing validated asset downloads and validators.
    #[serde(default = "default_asset_cache_directory")]
    pub cache_directory: PathBuf,
    /// Poll interval for immutable last-good asset snapshots.
    #[serde(default = "default_asset_reload_interval_seconds")]
    pub reload_interval_seconds: u64,
    /// Absolute timeout for one asset HTTP request including its response body.
    #[serde(default = "default_asset_request_timeout_seconds")]
    pub request_timeout_seconds: u64,
    /// Maximum bytes accepted from any one GeoIP, GeoSite, or external file.
    #[serde(default = "default_asset_max_bytes")]
    pub max_bytes: u64,
}

impl Default for AssetsConfig {
    fn default() -> Self {
        Self {
            geoip: default_geoip_url(),
            geosite: default_geosite_url(),
            cache_directory: default_asset_cache_directory(),
            reload_interval_seconds: default_asset_reload_interval_seconds(),
            request_timeout_seconds: default_asset_request_timeout_seconds(),
            max_bytes: default_asset_max_bytes(),
        }
    }
}

fn default_geoip_url() -> String {
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat".to_owned()
}

fn default_geosite_url() -> String {
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat".to_owned()
}

fn default_asset_cache_directory() -> PathBuf {
    PathBuf::from("/var/lib/rust-reality/assets")
}

const fn default_asset_reload_interval_seconds() -> u64 {
    86_400
}

const fn default_asset_request_timeout_seconds() -> u64 {
    120
}

const fn default_asset_max_bytes() -> u64 {
    128 * 1024 * 1024
}

/// DNS routing strategy and resolvers.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DnsConfig {
    /// Resolver addresses or URLs in priority order.
    #[serde(default = "default_dns_servers")]
    pub servers: Vec<String>,
    /// Absolute timeout for one resolution attempt.
    #[serde(default = "default_dns_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            servers: default_dns_servers(),
            timeout_ms: default_dns_timeout_ms(),
        }
    }
}

fn default_dns_servers() -> Vec<String> {
    vec!["system".to_owned()]
}

const fn default_dns_timeout_ms() -> u64 {
    5_000
}

/// Xray-compatible DNS resolution modes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
pub enum DnsStrategy {
    /// Preserve domains and resolve only in the selected outbound.
    #[serde(rename = "AsIs")]
    AsIs,
    /// Resolve only when domain rules do not produce a match.
    #[default]
    #[serde(rename = "IPIfNonMatch")]
    IpIfNonMatch,
    /// Resolve before rules that may depend on an IP address.
    #[serde(rename = "IPOnDemand")]
    IpOnDemand,
}

/// One strictly typed listener.
///
/// Public clients may enter only through the VLESS variant, whose validation
/// requires REALITY and Vision. The NXR variant is an internal landing-node
/// listener and is intentionally a separate protocol boundary.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, tag = "protocol", rename_all = "lowercase")]
pub enum InboundConfig {
    /// Public VLESS + REALITY + Vision listener.
    Vless(VlessInboundConfig),
    /// Firewall-restricted internal NXR landing listener.
    Nxr(NxrInboundConfig),
    /// Firewall-restricted internal Handoff landing listener.
    Handoff(HandoffInboundConfig),
}

impl InboundConfig {
    /// Returns the unique routing tag.
    #[must_use]
    pub fn tag(&self) -> &str {
        match self {
            Self::Vless(inbound) => &inbound.tag,
            Self::Nxr(inbound) => &inbound.tag,
            Self::Handoff(inbound) => &inbound.tag,
        }
    }

    /// Returns the configured bind address.
    #[must_use]
    pub const fn listen(&self) -> IpAddr {
        match self {
            Self::Vless(inbound) => inbound.listen,
            Self::Nxr(inbound) => inbound.listen,
            Self::Handoff(inbound) => inbound.listen,
        }
    }

    /// Returns the configured TCP port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        match self {
            Self::Vless(inbound) => inbound.port,
            Self::Nxr(inbound) => inbound.port,
            Self::Handoff(inbound) => inbound.port,
        }
    }

    /// Returns public VLESS state only for a public listener.
    #[must_use]
    pub const fn as_vless(&self) -> Option<&VlessInboundConfig> {
        match self {
            Self::Vless(inbound) => Some(inbound),
            Self::Nxr(_) | Self::Handoff(_) => None,
        }
    }

    /// Returns mutable public VLESS state only for a public listener.
    #[must_use]
    pub const fn as_vless_mut(&mut self) -> Option<&mut VlessInboundConfig> {
        match self {
            Self::Vless(inbound) => Some(inbound),
            Self::Nxr(_) | Self::Handoff(_) => None,
        }
    }
}

/// One public VLESS + REALITY + Vision listener.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VlessInboundConfig {
    /// Unique routing tag.
    pub tag: String,
    /// Address to bind.
    pub listen: IpAddr,
    /// TCP port to bind.
    pub port: u16,
    /// Authorized VLESS users.
    pub settings: VlessInboundSettings,
    /// Mandatory TCP, REALITY, and Vision settings.
    pub stream_settings: StreamSettings,
}

/// One internal NXR landing listener.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NxrInboundConfig {
    /// Unique routing and operational tag.
    pub tag: String,
    /// Firewall-restricted address to bind.
    pub listen: IpAddr,
    /// Raw NXR TCP port to bind.
    pub port: u16,
    /// Independent per-flow authentication and replay policy.
    pub settings: NxrInboundSettings,
}

/// Authentication and bounded replay policy for one NXR landing listener.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NxrInboundSettings {
    /// URL-safe unpadded base64 encoding of an independent 32-byte PSK.
    pub pre_shared_key: SecretString,
    /// Maximum accepted absolute wall-clock difference in seconds.
    #[serde(default = "default_nxr_time_difference_seconds")]
    pub max_time_difference_seconds: u64,
    /// Maximum retained verified nonces for this listener.
    #[serde(default = "default_nxr_nonce_entries")]
    pub max_nonce_entries: u32,
    /// Monotonic replay retention in seconds.
    #[serde(default = "default_nxr_nonce_retention_seconds")]
    pub nonce_retention_seconds: u64,
    /// Absolute deadline for reading the one authentication request.
    #[serde(default = "default_nxr_authentication_timeout_ms")]
    pub authentication_timeout_ms: u64,
    /// Absolute deadline for connecting to the authenticated destination.
    #[serde(default = "default_nxr_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
}

const fn default_nxr_time_difference_seconds() -> u64 {
    30
}

const fn default_nxr_nonce_entries() -> u32 {
    65_536
}

const fn default_nxr_nonce_retention_seconds() -> u64 {
    120
}

const fn default_nxr_authentication_timeout_ms() -> u64 {
    3_000
}

const fn default_nxr_connect_timeout_ms() -> u64 {
    10_000
}

/// One internal Handoff landing listener.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HandoffInboundConfig {
    /// Unique routing and operational tag.
    pub tag: String,
    /// Firewall-restricted address to bind.
    pub listen: IpAddr,
    /// Raw Handoff TCP port to bind.
    pub port: u16,
    /// Independent per-transfer authentication and replay policy.
    pub settings: HandoffInboundSettings,
}

/// Authentication and bounded replay policy for one Handoff landing listener.
///
/// The pre-shared key and the static X25519 key are independent of the NXR
/// pre-shared key and of any REALITY private key; reusing key material across
/// those boundaries is a configuration error the operator must avoid.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HandoffInboundSettings {
    /// URL-safe unpadded base64 encoding of an independent 32-byte PSK.
    pub pre_shared_key: SecretString,
    /// URL-safe unpadded base64 encoding of the listener's independent static
    /// X25519 private key.
    pub private_key: SecretString,
    /// Maximum accepted absolute wall-clock difference in seconds.
    #[serde(default = "default_handoff_time_difference_seconds")]
    pub max_time_difference_seconds: u64,
    /// Maximum retained verified nonces for this listener.
    #[serde(default = "default_handoff_nonce_entries")]
    pub max_nonce_entries: u32,
    /// Monotonic replay retention in seconds.
    #[serde(default = "default_handoff_nonce_retention_seconds")]
    pub nonce_retention_seconds: u64,
    /// Absolute deadline for reading the one sealed transfer message.
    #[serde(default = "default_handoff_authentication_timeout_ms")]
    pub authentication_timeout_ms: u64,
    /// Absolute deadline for connecting to the transferred destination.
    #[serde(default = "default_handoff_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// Optional outbound tag selecting how the landing reaches transferred
    /// destinations. Absent means the landing dials directly; a tag must name
    /// a `direct`, `socks5`, `nxr`, or `blackhole` outbound — never another
    /// `handoff` outbound, so landings cannot be chained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<String>,
    /// Retired pair PSKs still accepted during a bounded zero-downtime
    /// rotation window: at most two URL-safe unpadded base64 values decoding
    /// to exactly 32 bytes each, none equal to `preSharedKey`. Senders always
    /// seal with the active key only; drop each retired key promptly — while
    /// it stays accepted, the rotation window it opens is reported at
    /// startup and on every reload, and the forward-secrecy bound of the
    /// retired material has not yet taken hold.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub previous_pre_shared_keys: Vec<SecretString>,
    /// Retired static X25519 private keys still accepted during a bounded
    /// rotation window: at most two URL-safe unpadded base64 values decoding
    /// to exactly 32 bytes each, none equal to `privateKey`. The same
    /// drop-promptly rule as `previousPreSharedKeys` applies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub previous_private_keys: Vec<SecretString>,
}

const fn default_handoff_time_difference_seconds() -> u64 {
    30
}

const fn default_handoff_nonce_entries() -> u32 {
    65_536
}

const fn default_handoff_nonce_retention_seconds() -> u64 {
    120
}

const fn default_handoff_authentication_timeout_ms() -> u64 {
    3_000
}

const fn default_handoff_connect_timeout_ms() -> u64 {
    10_000
}

const fn default_handoff_first_byte_timeout_ms() -> u64 {
    15_000
}

/// VLESS users for one inbound.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VlessInboundSettings {
    /// Authorized clients.
    pub clients: Vec<VlessClient>,
    /// Must be `none`; retained for Xray-shaped configuration.
    #[serde(default = "default_decryption")]
    pub decryption: String,
}

fn default_decryption() -> String {
    "none".to_owned()
}

/// One VLESS identity.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VlessClient {
    /// Canonical UUID string.
    pub id: String,
    /// Optional non-secret operator label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Must be `xtls-rprx-vision`.
    pub flow: String,
}

/// Mandatory protected stream configuration.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StreamSettings {
    /// Must be `tcp`.
    pub network: Network,
    /// Must be `reality`.
    pub security: String,
    /// REALITY authentication and cover target.
    pub reality_settings: RealityConfig,
}

/// Supported proxy networks.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// TCP byte streams.
    Tcp,
    /// UDP datagrams, currently accepted only as a route matcher.
    Udp,
}

/// REALITY server settings.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RealityConfig {
    /// Cover target in `host:port` form.
    pub target: String,
    /// Allowed concrete client SNI values or leftmost single-label wildcard patterns.
    pub server_names: Vec<String>,
    /// X25519 private key encoded as URL-safe base64 without padding.
    pub private_key: SecretString,
    /// Accepted hexadecimal REALITY short IDs.
    pub short_ids: Vec<String>,
    /// Maximum accepted client-clock difference; zero disables the check.
    #[serde(default = "default_reality_time_diff_ms")]
    pub max_time_diff_ms: u64,
}

const fn default_reality_time_diff_ms() -> u64 {
    60_000
}

/// One configured outbound transport.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, tag = "protocol", rename_all = "lowercase")]
pub enum OutboundConfig {
    /// Connect directly to the requested destination.
    Direct {
        /// Unique routing tag.
        tag: String,
    },
    /// Complete and discard the connection.
    Blackhole {
        /// Unique routing tag.
        tag: String,
        /// Optional close behavior.
        #[serde(default)]
        settings: BlackholeSettings,
    },
    /// Connect through a SOCKS5 server.
    Socks5 {
        /// Unique routing tag.
        tag: String,
        /// SOCKS5 endpoint and optional credentials.
        settings: Socks5Settings,
    },
    /// Connect one user flow through one authenticated NXR TCP connection.
    Nxr {
        /// Unique routing tag.
        tag: String,
        /// NXR endpoint and independent pre-shared authentication key.
        settings: NxrSettings,
    },
    /// Transfer one authenticated session to a Handoff landing node.
    Handoff {
        /// Unique routing tag.
        tag: String,
        /// Handoff landing endpoint, independent PSK, and landing public key.
        settings: HandoffSettings,
    },
}

impl OutboundConfig {
    /// Returns the unique routing tag.
    #[must_use]
    pub fn tag(&self) -> &str {
        match self {
            Self::Direct { tag }
            | Self::Blackhole { tag, .. }
            | Self::Socks5 { tag, .. }
            | Self::Nxr { tag, .. }
            | Self::Handoff { tag, .. } => tag,
        }
    }
}

/// Blackhole close behavior.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BlackholeSettings {
    /// Optional delay before closing, capped during validation.
    #[serde(default)]
    pub response_delay_ms: u64,
}

/// SOCKS5 outbound configuration.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Socks5Settings {
    /// SOCKS5 server address.
    pub address: String,
    /// SOCKS5 server port.
    pub port: u16,
    /// Optional username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<SecretString>,
    /// Optional password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretString>,
}

/// NXR landing-node outbound configuration.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NxrSettings {
    /// Landing node address.
    pub address: String,
    /// Firewall-restricted raw NXR TCP port.
    pub port: u16,
    /// URL-safe unpadded base64 encoding of an independent 32-byte PSK.
    pub pre_shared_key: SecretString,
}

/// Handoff landing-node outbound configuration.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HandoffSettings {
    /// Landing node address.
    pub address: String,
    /// Firewall-restricted raw Handoff TCP port.
    pub port: u16,
    /// URL-safe unpadded base64 encoding of an independent 32-byte PSK.
    pub pre_shared_key: SecretString,
    /// URL-safe unpadded base64 encoding of the landing node's static X25519
    /// public key. This is public material, not a secret.
    pub landing_public_key: String,
    /// Absolute deadline for dialing the landing node and writing the one
    /// sealed transfer message.
    #[serde(default = "default_handoff_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// Deadline for the landing node's first downlink byte after the
    /// transfer write — LINE's rejection-detection window for the silent
    /// protocol. A successful transfer produces immediate downlink (the
    /// resumed response header and opening Vision frame are LANDING's first
    /// sealed record), while every rejection closes the connection silently.
    /// This must exceed the landing node's `authenticationTimeoutMs` +
    /// `connectTimeoutMs` headroom: the first sealed record is produced only
    /// after the transfer is read, authenticated, and the destination
    /// dialed, so a shorter deadline resets viable sessions whose landing
    /// node is slow or congested.
    #[serde(default = "default_handoff_first_byte_timeout_ms")]
    pub first_byte_timeout_ms: u64,
}

/// User-group routing with a small global prelude.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RoutingConfig {
    /// DNS behavior while evaluating IP conditions.
    #[serde(default)]
    pub domain_strategy: DnsStrategy,
    /// Small first-match rule list evaluated before user rules.
    #[serde(default)]
    pub global_rules: Vec<GlobalRule>,
    /// Explicit policies grouping one or more UUIDs.
    pub users: Vec<UserPolicy>,
}

/// A global first-match route rule.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GlobalRule {
    /// Operator-facing rule name.
    pub name: String,
    /// Selected outbound tag.
    pub outbound: String,
    /// Domain and GeoSite conditions.
    #[serde(default)]
    pub domain: Vec<String>,
    /// IP, CIDR, and GeoIP conditions.
    #[serde(default)]
    pub ip: Vec<String>,
    /// Destination port conditions.
    #[serde(default)]
    pub port: Vec<PortMatcher>,
    /// Network conditions.
    #[serde(default)]
    pub network: Vec<Network>,
    /// Inbound tag conditions.
    #[serde(default)]
    pub inbound_tag: Vec<String>,
}

/// One readable policy group for a set of UUIDs.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UserPolicy {
    /// Operator-facing group name.
    pub name: String,
    /// UUIDs assigned to this policy exactly once.
    pub user_ids: Vec<String>,
    /// Fallback outbound when no group rule matches.
    pub default_outbound: String,
    /// Ordered first-match group rules.
    #[serde(default)]
    pub rules: Vec<RouteRule>,
}

/// One user-group first-match route rule.
pub type RouteRule = GlobalRule;

/// One destination port or inclusive range.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(transparent)]
pub struct PortMatcher(pub String);

/// Resource and data-path policy.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PolicyConfig {
    /// Global resource admission limits.
    #[serde(default)]
    pub resource_governor: ResourceGovernorConfig,
    /// Direct outbound isolation.
    #[serde(default)]
    pub direct_barrier: DirectBarrierConfig,
    /// Buffered and Linux-accelerated relay controls.
    #[serde(default)]
    pub relay: RelayPolicy,
}

/// Bounded connection and pre-authentication resource limits.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResourceGovernorConfig {
    /// Total accepted connections.
    pub max_connections: u32,
    /// Concurrent pre-authentication handshakes.
    pub max_handshakes: u32,
    /// Concurrent cover fallbacks.
    pub max_fallbacks: u32,
    /// Concurrent expensive cryptographic operations.
    pub max_crypto_operations: u32,
    /// Replay entries across pending and committed states.
    pub max_replay_entries: u32,
    /// Concurrent DNS resolutions, bounded until the underlying lookup
    /// finishes rather than until the async wait ends.
    #[serde(default = "default_max_dns_lookups")]
    pub max_dns_lookups: u32,
    /// Retention after a verified TLS ClientFinished.
    #[serde(default = "default_replay_retention_ms")]
    pub replay_retention_ms: u64,
    /// Absolute ClientHello read deadline.
    pub client_hello_timeout_ms: u64,
    /// Absolute authenticated handshake deadline.
    pub handshake_timeout_ms: u64,
    /// Cover and outbound connection deadline.
    pub connect_timeout_ms: u64,
    /// Maximum fallback lifetime.
    pub fallback_timeout_ms: u64,
}

impl Default for ResourceGovernorConfig {
    fn default() -> Self {
        Self {
            max_connections: 16_384,
            max_handshakes: 1_024,
            max_fallbacks: 512,
            max_crypto_operations: 128,
            max_replay_entries: 65_536,
            max_dns_lookups: default_max_dns_lookups(),
            replay_retention_ms: default_replay_retention_ms(),
            client_hello_timeout_ms: 3_000,
            handshake_timeout_ms: 10_000,
            connect_timeout_ms: 10_000,
            fallback_timeout_ms: 120_000,
        }
    }
}

const fn default_replay_retention_ms() -> u64 {
    120_000
}

const fn default_max_dns_lookups() -> u32 {
    64
}

/// Direct outbound admission isolation.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DirectBarrierConfig {
    /// Concurrent direct dials.
    pub max_concurrent: u32,
    /// New direct dials allowed per second.
    pub max_per_second: u32,
}

impl Default for DirectBarrierConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 2_048,
            max_per_second: 4_096,
        }
    }
}

/// Bounded relay buffer and Linux acceleration policy.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RelayPolicy {
    /// Bytes per pooled userspace buffer.
    pub buffer_bytes: usize,
    /// Maximum pooled buffers.
    pub max_pooled_buffers: usize,
    /// Maximum concurrent Linux splice relays and their two pipe pairs.
    #[serde(default = "default_max_splice_relays")]
    pub max_splice_relays: u32,
    /// Ceiling on relay buffer memory across every backend.
    #[serde(default = "default_max_relay_memory_bytes")]
    pub max_relay_memory_bytes: u64,
    /// Permit nonblocking splice on plaintext TCP boundaries.
    pub splice: bool,
    /// Reuse splice pipes process-wide instead of creating and destroying
    /// them per relay (the Go/Xray model: size once at creation, zero pipe
    /// syscalls on a pool hit).
    #[serde(default = "default_pipe_pool")]
    pub pipe_pool: bool,
    /// Maximum retained pipe pairs in the process pool.
    #[serde(default = "default_max_pooled_pipes")]
    pub max_pooled_pipes: u32,
}

impl Default for RelayPolicy {
    fn default() -> Self {
        Self {
            buffer_bytes: 32 * 1024,
            max_pooled_buffers: 4_096,
            max_splice_relays: default_max_splice_relays(),
            max_relay_memory_bytes: default_max_relay_memory_bytes(),
            splice: true,
            pipe_pool: default_pipe_pool(),
            max_pooled_pipes: default_max_pooled_pipes(),
        }
    }
}

const fn default_max_splice_relays() -> u32 {
    256
}

const fn default_max_relay_memory_bytes() -> u64 {
    536_870_912
}

const fn default_pipe_pool() -> bool {
    true
}

const fn default_max_pooled_pipes() -> u32 {
    512
}
