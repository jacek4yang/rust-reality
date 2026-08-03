use std::{fmt, net::IpAddr, path::PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
}

/// A string whose debug representation never reveals its contents.
#[derive(Clone, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
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
    /// Community-compatible `geoip.dat` path.
    pub geoip: PathBuf,
    /// Community-compatible `geosite.dat` path.
    pub geosite: PathBuf,
    /// Poll interval for immutable last-good asset snapshots.
    pub reload_interval_seconds: u64,
}

impl Default for AssetsConfig {
    fn default() -> Self {
        Self {
            geoip: PathBuf::from("geoip.dat"),
            geosite: PathBuf::from("geosite.dat"),
            reload_interval_seconds: 300,
        }
    }
}

/// DNS routing strategy and resolvers.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DnsConfig {
    /// Xray-compatible domain resolution strategy.
    #[serde(default)]
    pub strategy: DnsStrategy,
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
            strategy: DnsStrategy::IpIfNonMatch,
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

/// One public VLESS + REALITY + Vision listener.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InboundConfig {
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
    /// Allowed client SNI values.
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
    /// Connect through a REALITY-protected NXR landing node.
    Nxr {
        /// Unique routing tag.
        tag: String,
        /// NXR endpoint, identity, and pool policy.
        settings: NxrSettings,
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
            | Self::Nxr { tag, .. } => tag,
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
    /// Landing node REALITY port.
    pub port: u16,
    /// Expected landing-node public identity.
    pub node_public_key: String,
    /// REALITY server name used on the inter-node link.
    pub server_name: String,
    /// Short-flow pool and large-flow switching policy.
    #[serde(default)]
    pub pool: NxrPoolConfig,
}

/// NXR pool policy optimized for same-city nodes.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NxrPoolConfig {
    /// Warm multiplexed connections.
    pub min_connections: u16,
    /// Maximum pooled multiplexed connections.
    pub max_connections: u16,
    /// Maximum concurrent short streams per pooled connection.
    pub max_streams_per_connection: u16,
    /// Bytes after which a stream switches to a dedicated connection.
    pub dedicated_after_bytes: u64,
    /// Idle lifetime of an unused pooled connection.
    pub idle_timeout_seconds: u64,
}

impl Default for NxrPoolConfig {
    fn default() -> Self {
        Self {
            min_connections: 1,
            max_connections: 4,
            max_streams_per_connection: 64,
            dedicated_after_bytes: 4 * 1024 * 1024,
            idle_timeout_seconds: 30,
        }
    }
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
            client_hello_timeout_ms: 3_000,
            handshake_timeout_ms: 10_000,
            connect_timeout_ms: 10_000,
            fallback_timeout_ms: 120_000,
        }
    }
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
    /// Permit nonblocking splice on plaintext TCP boundaries.
    pub splice: bool,
    /// Permit io_uring when the runtime probe accepts the kernel.
    pub io_uring: bool,
    /// Permit optional sockhash acceleration after capability probing.
    pub sockhash: bool,
}

impl Default for RelayPolicy {
    fn default() -> Self {
        Self {
            buffer_bytes: 32 * 1024,
            max_pooled_buffers: 4_096,
            splice: true,
            io_uring: false,
            sockhash: false,
        }
    }
}
