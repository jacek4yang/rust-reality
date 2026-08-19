use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::ConfigError;

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
    /// Process-wide locally resolved outbound dialing behavior.
    #[serde(default)]
    pub network: NetworkConfig,
    /// Protected inbound listeners.
    pub inbounds: Vec<InboundConfig>,
    /// Available outbound transports.
    pub outbounds: Vec<OutboundConfig>,
    /// Global and per-user first-match routing.
    pub routing: RoutingConfig,
    /// Deprecated alias for `advanced.limits`.
    ///
    /// A v1.5 `policy` object still parses: while loading, its non-default
    /// values merge into `advanced.limits` and `runtime.tuning.mode` is
    /// forced to `fixed` unless explicitly set (see [`Config::normalize`]).
    /// The alias never serializes — `config format` rewrites it to the
    /// canonical location — and new configurations must use
    /// `advanced.limits`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyConfig>,
    /// Expert escape hatch holding the numeric resource and relay policy.
    #[serde(default)]
    pub advanced: AdvancedConfig,
    /// Process resource mode.
    #[serde(default)]
    pub runtime: RuntimeConfig,
}

impl Config {
    /// Merges the deprecated top-level `policy` alias into
    /// `advanced.limits` and applies the alias's tuning-mode rule.
    ///
    /// Every `policy` field whose value differs from its default pins the
    /// same field of `advanced.limits`; a field set in both places to
    /// different non-default values is a conflict error naming both
    /// locations. When the alias section is present at all and
    /// `runtime.tuning.mode` is not explicitly set, the mode is forced to
    /// `fixed`, preserving v1.5 behavior byte-for-byte.
    ///
    /// Returns whether the alias section was present, so the caller can
    /// report the deprecation exactly once per load. Idempotent: the alias
    /// is cleared by a successful merge.
    ///
    /// # Errors
    ///
    /// Returns an error when one field carries different non-default values
    /// in `policy` and `advanced.limits`.
    pub fn normalize(&mut self) -> Result<bool, ConfigError> {
        let Some(alias) = self.policy.take() else {
            return Ok(false);
        };
        let defaults = PolicyConfig::default();
        let limits = &mut self.advanced.limits;
        macro_rules! merge_alias_field {
            ($section:ident, $field:ident, $path:literal) => {{
                let value = alias.$section.$field;
                if value != defaults.$section.$field {
                    if limits.$section.$field != defaults.$section.$field
                        && limits.$section.$field != value
                    {
                        return Err(ConfigError::new(
                            $path,
                            concat!(
                                "conflicts with advanced.limits; ",
                                "set the field in only one place"
                            ),
                        ));
                    }
                    limits.$section.$field = value;
                }
            }};
        }
        merge_alias_field!(
            resource_governor,
            max_connections,
            "policy.resourceGovernor.maxConnections"
        );
        merge_alias_field!(
            resource_governor,
            max_handshakes,
            "policy.resourceGovernor.maxHandshakes"
        );
        merge_alias_field!(
            resource_governor,
            max_fallbacks,
            "policy.resourceGovernor.maxFallbacks"
        );
        merge_alias_field!(
            resource_governor,
            max_crypto_operations,
            "policy.resourceGovernor.maxCryptoOperations"
        );
        merge_alias_field!(
            resource_governor,
            max_replay_entries,
            "policy.resourceGovernor.maxReplayEntries"
        );
        merge_alias_field!(
            resource_governor,
            max_dns_lookups,
            "policy.resourceGovernor.maxDnsLookups"
        );
        merge_alias_field!(
            resource_governor,
            replay_retention_ms,
            "policy.resourceGovernor.replayRetentionMs"
        );
        merge_alias_field!(
            resource_governor,
            client_hello_timeout_ms,
            "policy.resourceGovernor.clientHelloTimeoutMs"
        );
        merge_alias_field!(
            resource_governor,
            handshake_timeout_ms,
            "policy.resourceGovernor.handshakeTimeoutMs"
        );
        merge_alias_field!(
            resource_governor,
            connect_timeout_ms,
            "policy.resourceGovernor.connectTimeoutMs"
        );
        merge_alias_field!(
            resource_governor,
            fallback_timeout_ms,
            "policy.resourceGovernor.fallbackTimeoutMs"
        );
        merge_alias_field!(
            direct_barrier,
            max_concurrent,
            "policy.directBarrier.maxConcurrent"
        );
        merge_alias_field!(
            direct_barrier,
            max_per_second,
            "policy.directBarrier.maxPerSecond"
        );
        merge_alias_field!(relay, buffer_bytes, "policy.relay.bufferBytes");
        merge_alias_field!(relay, max_pooled_buffers, "policy.relay.maxPooledBuffers");
        merge_alias_field!(relay, max_splice_relays, "policy.relay.maxSpliceRelays");
        merge_alias_field!(
            relay,
            max_relay_memory_bytes,
            "policy.relay.maxRelayMemoryBytes"
        );
        merge_alias_field!(relay, splice, "policy.relay.splice");
        merge_alias_field!(relay, pipe_pool, "policy.relay.pipePool");
        merge_alias_field!(relay, max_pooled_pipes, "policy.relay.maxPooledPipes");
        if self.runtime.tuning.mode.is_none() {
            self.runtime.tuning.mode = Some(TuningMode::Fixed);
        }
        Ok(true)
    }
}

/// Process-wide network behavior.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NetworkConfig {
    /// Strategy for proxy endpoints resolved and dialed by this process.
    #[serde(default)]
    pub dial: DialConfig,
}

/// Bounded locally resolved outbound dialing controls.
///
/// Destinations intentionally delegated to a SOCKS5, NXR, or Handoff peer
/// retain their original address and do not use this policy.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DialConfig {
    /// Enabled families and the initial process-wide preference.
    #[serde(default)]
    pub mode: DialMode,
    /// Delay before the first alternate-family connection attempt.
    #[serde(default = "default_fallback_delay_ms")]
    pub fallback_delay_ms: u64,
    /// Lifetime of the cached route/local-address observation.
    #[serde(default = "default_route_refresh_seconds")]
    pub route_refresh_seconds: u64,
    /// Time a family-level reachability error deprioritizes that family.
    #[serde(default = "default_hard_failure_penalty_seconds")]
    pub hard_failure_penalty_seconds: u64,
    /// Lifetime of learned family latency before it expires.
    #[serde(default = "default_latency_memory_seconds")]
    pub latency_memory_seconds: u64,
}

impl Default for DialConfig {
    fn default() -> Self {
        Self {
            mode: DialMode::Auto,
            fallback_delay_ms: default_fallback_delay_ms(),
            route_refresh_seconds: default_route_refresh_seconds(),
            hard_failure_penalty_seconds: default_hard_failure_penalty_seconds(),
            latency_memory_seconds: default_latency_memory_seconds(),
        }
    }
}

const fn default_fallback_delay_ms() -> u64 {
    250
}

const fn default_route_refresh_seconds() -> u64 {
    30
}

const fn default_hard_failure_penalty_seconds() -> u64 {
    30
}

const fn default_latency_memory_seconds() -> u64 {
    300
}

/// IP families enabled for locally resolved connection setup.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DialMode {
    /// Enable both families and use the stable process-wide network decision.
    #[default]
    Auto,
    /// Enable both families, initially preferring IPv4 unless it is unhealthy.
    PreferIpv4,
    /// Enable both families, initially preferring IPv6 unless it is unhealthy.
    PreferIpv6,
    /// Dial IPv4 only.
    Ipv4Only,
    /// Dial IPv6 only.
    Ipv6Only,
}

impl DialMode {
    /// Returns the stable configuration/log name.
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

    /// Returns whether IPv4 is enabled.
    #[must_use]
    pub const fn allows_ipv4(self) -> bool {
        !matches!(self, Self::Ipv6Only)
    }

    /// Returns whether IPv6 is enabled.
    #[must_use]
    pub const fn allows_ipv6(self) -> bool {
        !matches!(self, Self::Ipv4Only)
    }

    /// Returns the configured family preference, when explicit.
    #[must_use]
    pub const fn preferred_family_is_ipv4(self) -> Option<bool> {
        match self {
            Self::PreferIpv4 | Self::Ipv4Only => Some(true),
            Self::PreferIpv6 | Self::Ipv6Only => Some(false),
            Self::Auto => None,
        }
    }
}

/// Listener topology for one logical inbound.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ListenConfig {
    /// Startup binding requirements for this inbound.
    #[serde(default)]
    pub mode: ListenMode,
    /// IPv4 address used by `auto`, `dualStack`, and `ipv4Only`.
    #[serde(default = "default_listen_ipv4")]
    pub ipv4: Ipv4Addr,
    /// IPv6 address used by `auto`, `dualStack`, and `ipv6Only`.
    #[serde(default = "default_listen_ipv6")]
    pub ipv6: Ipv6Addr,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            mode: ListenMode::Auto,
            ipv4: default_listen_ipv4(),
            ipv6: default_listen_ipv6(),
        }
    }
}

impl From<IpAddr> for ListenConfig {
    fn from(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(address) if address.is_unspecified() => Self::default(),
            IpAddr::V6(address) if address.is_unspecified() => Self::default(),
            IpAddr::V4(address) => Self {
                mode: ListenMode::Ipv4Only,
                ipv4: address,
                ipv6: default_listen_ipv6(),
            },
            IpAddr::V6(address) => Self {
                mode: ListenMode::Ipv6Only,
                ipv4: default_listen_ipv4(),
                ipv6: address,
            },
        }
    }
}

const fn default_listen_ipv4() -> Ipv4Addr {
    Ipv4Addr::UNSPECIFIED
}

const fn default_listen_ipv6() -> Ipv6Addr {
    Ipv6Addr::UNSPECIFIED
}

/// Startup requirements for one logical inbound listener.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ListenMode {
    /// Try both families and continue when at least one family is available.
    #[default]
    Auto,
    /// Require both independent family sockets.
    DualStack,
    /// Bind only IPv4.
    Ipv4Only,
    /// Bind only IPv6.
    Ipv6Only,
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
    /// `standard` derives every budget from the inherited limits exactly as
    /// documented in the descriptor-budget reference and assumes nothing
    /// about what else runs on the machine; it is the effective mode when
    /// neither `resourceMode` nor `profile` is set.
    ///
    /// `dedicated` declares that this process owns the machine (or its
    /// cgroup): at startup it raises the soft `RLIMIT_NOFILE` to the hard
    /// limit when possible, relaxes the descriptor safety headroom from
    /// `limit/16` to `limit/10`, and runs a bounded memory-pressure monitor
    /// that pauses new setup work before the kernel or the cgroup OOM killer
    /// is reached. See `docs/configuration.md#dedicated-resource-mode`.
    ///
    /// When set, `resourceMode` is authoritative over `profile`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_mode: Option<ResourceMode>,
    /// Who owns this machine.
    ///
    /// `shared` maps onto `resourceMode: standard` and `dedicated` onto
    /// `resourceMode: dedicated`; a non-`auto` profile that contradicts an
    /// explicit `resourceMode` is a validation error. `auto` (the default)
    /// defers to `resourceMode` when set and otherwise detects
    /// single-tenancy from the cgroup v2 boundaries — it never guesses
    /// dedicated on bare metal.
    #[serde(default)]
    pub profile: RuntimeProfile,
    /// How the numeric policy is produced and maintained.
    #[serde(default)]
    pub tuning: TuningConfig,
}

impl RuntimeConfig {
    /// Returns the configured resource mode, or `standard` when unset.
    ///
    /// This is the explicit-mode view only: it ignores `profile`. The serve
    /// path resolves the effective mode — profile mapping and `auto`
    /// detection included — through
    /// [`RuntimeConfig::resolve_resource_mode`].
    #[must_use]
    pub const fn resource_mode(&self) -> ResourceMode {
        match self.resource_mode {
            Some(mode) => mode,
            None => ResourceMode::Standard,
        }
    }

    /// Resolves the effective resource mode from `resourceMode`, `profile`,
    /// and the detected machine view.
    ///
    /// An explicit `resourceMode` is authoritative. Otherwise a non-`auto`
    /// profile maps onto the mode, and `auto` resolves to `dedicated` only
    /// when the cgroup v2 tenancy boundary is fully observable (a finite
    /// `cpu.max` quota and a finite `memory.max`); `auto` never guesses
    /// dedicated on bare metal.
    #[must_use]
    pub fn resolve_resource_mode(
        &self,
        machine: &crate::runtime::machine::MachineReport,
    ) -> ResourceMode {
        if let Some(mode) = self.resource_mode {
            return mode;
        }
        match self.profile {
            RuntimeProfile::Shared => ResourceMode::Standard,
            RuntimeProfile::Dedicated => ResourceMode::Dedicated,
            RuntimeProfile::Auto => {
                if machine.tenancy_boundary_observable() {
                    ResourceMode::Dedicated
                } else {
                    ResourceMode::Standard
                }
            }
        }
    }

    /// Returns whether hot-reloading from `self` to `other` preserves the
    /// cold runtime posture.
    ///
    /// The resource-mode comparison keys off effective values rather than raw
    /// options, so representations that behave identically do not reject a
    /// reload: an explicit `resourceMode: standard` and an unset
    /// `resourceMode` both resolve to `standard`. Both resource modes are
    /// resolved against the same machine view, so a profile flip that changes
    /// the resolved mode still rejects; `profile` and `objective` compare
    /// directly. The tuning mode compares strictly through
    /// [`TuningConfig::mode`]: `fixed`, `startup`, and `adaptive` produce
    /// different effective policies, so any drift between them — including a
    /// `policy`-alias-forced `fixed` drifting to an unset (`startup`) mode —
    /// requires a process restart.
    #[must_use]
    pub fn hot_compatible_with(
        &self,
        other: &Self,
        machine: &crate::runtime::machine::MachineReport,
    ) -> bool {
        self.resolve_resource_mode(machine) == other.resolve_resource_mode(machine)
            && self.profile == other.profile
            && self.tuning.objective == other.tuning.objective
            && self.tuning.mode() == other.tuning.mode()
    }
}

/// Machine-tenancy declaration used to resolve the resource mode.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeProfile {
    /// Defer to `resourceMode` when set, else detect single-tenancy from the
    /// cgroup v2 boundaries; never guesses dedicated on bare metal.
    #[default]
    Auto,
    /// Shared machine; maps onto `resourceMode: standard`.
    Shared,
    /// This process owns the machine or cgroup; maps onto
    /// `resourceMode: dedicated`.
    Dedicated,
}

impl RuntimeProfile {
    /// Returns the stable configuration/log name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Shared => "shared",
            Self::Dedicated => "dedicated",
        }
    }

    /// Returns the resource mode a non-`auto` profile maps onto.
    #[must_use]
    pub const fn resource_mode(self) -> Option<ResourceMode> {
        match self {
            Self::Auto => None,
            Self::Shared => Some(ResourceMode::Standard),
            Self::Dedicated => Some(ResourceMode::Dedicated),
        }
    }
}

/// How the numeric policy is produced and maintained.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TuningMode {
    /// Numbers come from `advanced.limits` (or the built-in defaults) and
    /// never move. v1.5 behavior.
    Fixed,
    /// Derived once at startup from the detected machine; static for the
    /// process lifetime. Default.
    #[default]
    Startup,
    /// Startup derivation plus a controller adjusting soft ceilings within
    /// startup-derived hard bounds. Reserved; currently behaves as
    /// `startup`.
    Adaptive,
}

impl TuningMode {
    /// Returns the stable configuration/log name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::Startup => "startup",
            Self::Adaptive => "adaptive",
        }
    }
}

/// Shape of the derived policy numbers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Objective {
    /// Prefer lower latency: tighter concurrency ceilings.
    Latency,
    /// Balanced derivation. Default.
    #[default]
    Balanced,
    /// Prefer throughput: wider ceilings within machine-derived caps.
    Throughput,
}

impl Objective {
    /// Returns the stable configuration/log name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Latency => "latency",
            Self::Balanced => "balanced",
            Self::Throughput => "throughput",
        }
    }
}

/// Policy production and maintenance settings.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TuningConfig {
    /// How policy numbers are produced and maintained.
    ///
    /// Absent means `startup`, unless a deprecated top-level `policy`
    /// object was present, which forces `fixed` (see
    /// [`Config::normalize`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<TuningMode>,
    /// Shape of the derived numbers; consulted only by derived modes.
    #[serde(default)]
    pub objective: Objective,
}

impl TuningConfig {
    /// Returns the tuning mode, applying the `startup` default.
    #[must_use]
    pub const fn mode(&self) -> TuningMode {
        match self.mode {
            Some(mode) => mode,
            None => TuningMode::Startup,
        }
    }
}

/// Expert escape hatch: the numeric resource and relay limits.
///
/// Every field of `limits` carries the v1.5 default; a field whose value
/// differs from the default is operator-pinned. In `fixed` tuning mode the
/// limits are the complete effective policy; the derived modes (`startup`,
/// `adaptive`) derive every unpinned field from the detected machine at
/// startup and keep pinned fields verbatim.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AdvancedConfig {
    /// Numeric admission, direct-dial, buffer, and relay limits.
    #[serde(default)]
    pub limits: PolicyConfig,
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
    /// No sink at all: every event is dropped before any encoding or I/O.
    None,
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
    /// Upstream resolvers in priority order.
    ///
    /// Exactly `["system"]` selects the operating system resolver (getaddrinfo).
    /// Any other list selects the built-in DNS protocol resolver; each entry is
    /// an IP literal (`1.1.1.1`, `[2606:4700:4700::1111]:53`) or a hostname
    /// resolved once through the system resolver at startup, with an optional
    /// `:port` (default 53). Plain UDP with TCP fallback is used.
    #[serde(default = "default_dns_servers")]
    pub servers: Vec<String>,
    /// Absolute timeout for one resolution attempt.
    #[serde(default = "default_dns_timeout_ms")]
    pub timeout_ms: u64,
    /// Shared resolution cache bounds.
    #[serde(default)]
    pub cache: DnsCacheConfig,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            servers: default_dns_servers(),
            timeout_ms: default_dns_timeout_ms(),
            cache: DnsCacheConfig::default(),
        }
    }
}

fn default_dns_servers() -> Vec<String> {
    vec!["system".to_owned()]
}

const fn default_dns_timeout_ms() -> u64 {
    5_000
}

/// Bounds for the shared DNS resolution cache.
///
/// Dynamic answers are cached only when their TTL is backed by the upstream
/// resolver: with `dns.servers = ["system"]` the system resolver exposes no
/// TTLs, so only singleflight coalescing applies and nothing is cached —
/// unless the optional `systemReuseMs` recent-completion window reuses
/// positive answers for a short bounded time (not authoritative TTL caching;
/// negative answers are never cached). With real DNS servers every cached
/// positive or negative answer carries the upstream TTL clamped to these
/// bounds. Static configured peers (REALITY cover target, fixed
/// SOCKS5/NXR/Handoff endpoints) are the explicit exception: the operator
/// owns their staleness through `staticTtlSeconds`, so they are cached in
/// every resolver mode.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DnsCacheConfig {
    /// Maximum number of cached names, counting positive, negative, and
    /// in-flight entries. Memory stays bounded at this many entries.
    #[serde(default = "default_dns_cache_max_entries")]
    pub max_entries: u32,
    /// Floor clamp applied to upstream positive TTLs.
    #[serde(default = "default_dns_cache_min_ttl_seconds")]
    pub min_ttl_seconds: u32,
    /// Ceiling clamp applied to upstream positive TTLs.
    #[serde(default = "default_dns_cache_max_ttl_seconds")]
    pub max_ttl_seconds: u32,
    /// Ceiling clamp applied to upstream negative (SOA) TTLs. NXDOMAIN and
    /// NODATA answers without an SOA TTL are never cached.
    #[serde(default = "default_dns_cache_negative_ttl_seconds")]
    pub negative_ttl_seconds: u32,
    /// Cache duration for static configured peers, in every resolver mode.
    #[serde(default = "default_dns_cache_static_ttl_seconds")]
    pub static_ttl_seconds: u32,
    /// Optional recent-completion reuse window, in milliseconds, applied only
    /// with `dns.servers = ["system"]`: positive getaddrinfo answers (which
    /// carry no TTL) are reused for at most this long. This is NOT
    /// authoritative TTL caching: an upstream change becomes visible only
    /// when the window expires, negative answers are never cached, and there
    /// is no stale-while-revalidate. `0` (the default) disables it; ignored
    /// with real DNS servers, where upstream TTLs govern.
    #[serde(default)]
    pub system_reuse_ms: u64,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: default_dns_cache_max_entries(),
            min_ttl_seconds: default_dns_cache_min_ttl_seconds(),
            max_ttl_seconds: default_dns_cache_max_ttl_seconds(),
            negative_ttl_seconds: default_dns_cache_negative_ttl_seconds(),
            static_ttl_seconds: default_dns_cache_static_ttl_seconds(),
            system_reuse_ms: 0,
        }
    }
}

const fn default_dns_cache_max_entries() -> u32 {
    1_024
}

const fn default_dns_cache_min_ttl_seconds() -> u32 {
    5
}

const fn default_dns_cache_max_ttl_seconds() -> u32 {
    3_600
}

const fn default_dns_cache_negative_ttl_seconds() -> u32 {
    60
}

const fn default_dns_cache_static_ttl_seconds() -> u32 {
    300
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

    /// Returns the configured listener topology.
    #[must_use]
    pub const fn listen(&self) -> &ListenConfig {
        match self {
            Self::Vless(inbound) => &inbound.listen,
            Self::Nxr(inbound) => &inbound.listen,
            Self::Handoff(inbound) => &inbound.listen,
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
    /// Per-inbound listener topology and family requirements.
    pub listen: ListenConfig,
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
    /// Firewall-restricted listener topology and family requirements.
    pub listen: ListenConfig,
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
    /// Firewall-restricted listener topology and family requirements.
    pub listen: ListenConfig,
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
    /// REALITY short IDs owned exclusively by this UUID.
    ///
    /// A client selects one value for each connection. Multiple values allow
    /// staged client-side rotation without sharing an authentication identity
    /// with another UUID.
    pub short_ids: Vec<String>,
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

#[cfg(test)]
mod tests {
    use super::{
        Config, Objective, ResourceMode, RuntimeConfig, RuntimeProfile, TuningConfig, TuningMode,
    };
    use crate::runtime::machine::MachineReport;

    fn machine_with(quota: Option<u64>, memory_max: Option<u64>) -> MachineReport {
        let mut machine = MachineReport::conservative();
        machine.cpu_quota_us = quota;
        machine.cpu_period_us = quota.map(|_| 100_000);
        machine.memory_max = memory_max;
        machine
    }

    #[test]
    fn an_explicit_resource_mode_is_authoritative_over_the_profile() {
        for profile in [
            RuntimeProfile::Auto,
            RuntimeProfile::Shared,
            RuntimeProfile::Dedicated,
        ] {
            let runtime = RuntimeConfig {
                resource_mode: Some(ResourceMode::Standard),
                profile,
                tuning: TuningConfig::default(),
            };
            assert_eq!(
                runtime.resolve_resource_mode(&machine_with(Some(400_000), Some(1 << 30))),
                ResourceMode::Standard,
                "resourceMode must win over profile {profile:?}"
            );
        }
    }

    #[test]
    fn a_non_auto_profile_maps_onto_the_resource_mode() {
        let machine = machine_with(None, None);
        for (profile, expected) in [
            (RuntimeProfile::Shared, ResourceMode::Standard),
            (RuntimeProfile::Dedicated, ResourceMode::Dedicated),
        ] {
            let runtime = RuntimeConfig {
                resource_mode: None,
                profile,
                tuning: TuningConfig::default(),
            };
            assert_eq!(runtime.resolve_resource_mode(&machine), expected);
        }
    }

    #[test]
    fn auto_resolves_dedicated_only_when_the_tenancy_boundary_is_observable() {
        let auto = RuntimeConfig::default();
        assert_eq!(auto.profile, RuntimeProfile::Auto);
        assert_eq!(
            auto.resolve_resource_mode(&machine_with(Some(400_000), Some(1 << 30))),
            ResourceMode::Dedicated,
            "a finite cpu.max quota and memory.max make single-tenancy observable"
        );
        for machine in [
            machine_with(Some(400_000), None),
            machine_with(None, Some(1 << 30)),
            machine_with(None, None),
        ] {
            assert_eq!(
                auto.resolve_resource_mode(&machine),
                ResourceMode::Standard,
                "auto never guesses dedicated without the full cgroup boundary"
            );
        }
    }

    #[test]
    fn hot_compatibility_compares_effective_values_not_raw_options() {
        let machine = machine_with(None, None);
        let explicit_standard = RuntimeConfig {
            resource_mode: Some(ResourceMode::Standard),
            profile: RuntimeProfile::Auto,
            tuning: TuningConfig::default(),
        };
        let unset = RuntimeConfig::default();
        assert!(
            explicit_standard.hot_compatible_with(&unset, &machine),
            "an explicit standard mode and an unset mode both resolve to standard"
        );
        assert!(unset.hot_compatible_with(&explicit_standard, &machine));
    }

    #[test]
    fn hot_compatibility_compares_the_tuning_mode_strictly() {
        let machine = machine_with(None, None);
        let unset = RuntimeConfig::default();
        for mode in [TuningMode::Fixed, TuningMode::Startup, TuningMode::Adaptive] {
            let explicit = RuntimeConfig {
                resource_mode: None,
                profile: RuntimeProfile::Auto,
                tuning: TuningConfig {
                    mode: Some(mode),
                    objective: Objective::Balanced,
                },
            };
            if mode == TuningMode::Startup {
                assert!(
                    unset.hot_compatible_with(&explicit, &machine),
                    "an explicit startup mode and an unset mode are the same mode"
                );
            } else {
                assert!(
                    !unset.hot_compatible_with(&explicit, &machine),
                    "drift between startup and {mode:?} must reject: the modes derive differently"
                );
            }
        }

        // The `policy` alias forces `fixed` on load, so a hand-migrated
        // config with an unset (startup) mode is a behavior change, never a
        // reloadable no-op.
        let alias_forced_fixed = RuntimeConfig {
            resource_mode: None,
            profile: RuntimeProfile::Auto,
            tuning: TuningConfig {
                mode: Some(TuningMode::Fixed),
                objective: Objective::Balanced,
            },
        };
        assert!(!alias_forced_fixed.hot_compatible_with(&unset, &machine));
        assert!(!unset.hot_compatible_with(&alias_forced_fixed, &machine));
    }

    #[test]
    fn hot_compatibility_still_rejects_cold_drift() {
        let machine = machine_with(None, None);
        let shared = RuntimeConfig {
            resource_mode: None,
            profile: RuntimeProfile::Shared,
            tuning: TuningConfig::default(),
        };
        let dedicated_profile = RuntimeConfig {
            resource_mode: None,
            profile: RuntimeProfile::Dedicated,
            tuning: TuningConfig::default(),
        };
        assert!(
            !shared.hot_compatible_with(&dedicated_profile, &machine),
            "a profile flip that changes the resolved mode must reject"
        );

        let dedicated_mode = RuntimeConfig {
            resource_mode: Some(ResourceMode::Dedicated),
            profile: RuntimeProfile::Auto,
            tuning: TuningConfig::default(),
        };
        assert!(
            !shared.hot_compatible_with(&dedicated_mode, &machine),
            "an explicit mode change must reject"
        );

        let other_objective = RuntimeConfig {
            resource_mode: None,
            profile: RuntimeProfile::Auto,
            tuning: TuningConfig {
                mode: None,
                objective: Objective::Throughput,
            },
        };
        assert!(
            !RuntimeConfig::default().hot_compatible_with(&other_objective, &machine),
            "objective drift must reject"
        );
    }

    #[test]
    fn tuning_defaults_match_the_documented_model() {
        let tuning = TuningConfig::default();
        assert_eq!(tuning.mode(), TuningMode::Startup);
        assert_eq!(tuning.mode, None, "an unset mode must stay distinguishable");
        assert_eq!(tuning.objective, Objective::Balanced);
        assert_eq!(TuningMode::Fixed.as_str(), "fixed");
        assert_eq!(TuningMode::Startup.as_str(), "startup");
        assert_eq!(TuningMode::Adaptive.as_str(), "adaptive");
        assert_eq!(Objective::Latency.as_str(), "latency");
        assert_eq!(Objective::Balanced.as_str(), "balanced");
        assert_eq!(Objective::Throughput.as_str(), "throughput");
        assert_eq!(RuntimeProfile::Auto.as_str(), "auto");
        assert_eq!(RuntimeProfile::Shared.as_str(), "shared");
        assert_eq!(RuntimeProfile::Dedicated.as_str(), "dedicated");
    }

    #[test]
    fn normalize_without_an_alias_is_a_noop() {
        let mut config = Config {
            policy: None,
            runtime: RuntimeConfig {
                resource_mode: None,
                profile: RuntimeProfile::Dedicated,
                tuning: TuningConfig::default(),
            },
            ..serde_json::from_str(crate::config::test_config_json()).expect("fixture must decode")
        };
        let before = config.clone();
        assert!(!config.normalize().expect("normalize must succeed"));
        assert_eq!(config, before);
    }
}
