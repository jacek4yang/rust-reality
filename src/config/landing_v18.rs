//! Bounded read support for an existing v1.8 Handoff landing deployment.
//!
//! This is the explicit v2 release exception to ADR 0019: one Handoff
//! listener, direct egress, no routing rules, and startup/adaptive resource
//! derivation with the v1.8 default numeric policy. Anything outside that
//! subset fails closed. No file is rewritten and no identity is generated.
//! All runtime execution still uses the current validated node model.

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

use serde::{
    Deserialize, Deserializer,
    de::{self, IgnoredAny},
};

use super::{
    SecretString,
    node::{
        LandingConfig, NodeConfig,
        dns::DnsConfig,
        landing::{HandoffLandingConfig, LandingProtocol, LandingRole},
        listener::{ListenFamily, ListenerConfig},
        log::LogConfig,
        network::{DialPolicy, NetworkConfig},
        runtime::{Objective, RuntimeConfig, RuntimeProfile, TuningMode},
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LandingV18 {
    inbounds: [Inbound; 1],
    outbounds: [DirectOutbound; 1],
    routing: EmptyRouting,
    #[serde(default)]
    log: Option<LogConfig>,
    #[serde(default)]
    dns: Option<DnsConfig>,
    #[serde(default)]
    network: Network,
    #[serde(default)]
    runtime: Runtime,
    #[serde(default, rename = "advanced")]
    _advanced: DerivedAdvanced,
    #[serde(default, rename = "assets")]
    _assets: Option<UnusedAssets>,
}

impl LandingV18 {
    pub(super) fn into_node(self) -> Result<NodeConfig, &'static str> {
        let [inbound] = self.inbounds;
        let [outbound] = self.outbounds;
        if inbound.tag.is_empty() || outbound.tag.is_empty() {
            return Err("v1.8 landing tags must not be empty");
        }
        let settings = inbound.settings;
        if settings
            .egress
            .as_ref()
            .is_some_and(|name| name != &outbound.tag)
        {
            return Err("v1.8 landing egress must name the declared direct outbound");
        }
        // Empty routing makes the asset section inert, as in v1.8. The
        // landing's explicit/default direct egress decides every destination.
        let _ = self.routing;
        Ok(NodeConfig::Landing(Box::new(LandingConfig {
            role: LandingRole::Landing,
            listeners: vec![ListenerConfig {
                port: inbound.port,
                ip: inbound.listen.mode,
                ipv4: inbound.listen.ipv4,
                ipv6: inbound.listen.ipv6,
            }],
            landing: LandingProtocol::Handoff(HandoffLandingConfig {
                psk: settings.pre_shared_key,
                private_key: settings.private_key,
                previous_psks: settings.previous_pre_shared_keys,
                previous_private_keys: settings.previous_private_keys,
                max_time_difference_seconds: settings.max_time_difference_seconds,
                pre_auth_idle_timeout_ms: settings.pre_auth_idle_timeout_ms,
                authentication_timeout_ms: settings.authentication_timeout_ms,
                connect_timeout_ms: settings.connect_timeout_ms,
                // Unlike resource defaults, v1.8's replay lifetime was an
                // effective security parameter. Preserve its 120s default.
                nonce_retention_seconds: Some(settings.nonce_retention_seconds.unwrap_or(120)),
            }),
            egress: None,
            outbounds: None,
            dns: self.dns,
            log: self.log,
            network: Some(NetworkConfig {
                ip: self.network.dial.mode,
            }),
            runtime: Some(RuntimeConfig {
                profile: self.runtime.profile,
                tuning: self.runtime.tuning.mode,
                objective: self.runtime.tuning.objective,
                status_file: self.runtime.status_file,
                limits: None,
            }),
        })))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inbound {
    #[serde(rename = "protocol")]
    _protocol: HandoffOnly,
    tag: String,
    listen: Listen,
    port: u16,
    settings: Settings,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum HandoffOnly {
    Handoff,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Listen {
    #[serde(default)]
    mode: Option<ListenFamily>,
    #[serde(default)]
    ipv4: Option<Ipv4Addr>,
    #[serde(default)]
    ipv6: Option<Ipv6Addr>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Settings {
    pre_shared_key: SecretString,
    private_key: SecretString,
    #[serde(default)]
    previous_pre_shared_keys: Option<Vec<SecretString>>,
    #[serde(default)]
    previous_private_keys: Option<Vec<SecretString>>,
    #[serde(default)]
    max_time_difference_seconds: Option<u64>,
    #[serde(default, rename = "maxNonceEntries")]
    _max_nonce_entries: DefaultNumber<65_536>,
    #[serde(default)]
    nonce_retention_seconds: Option<u64>,
    #[serde(default)]
    pre_auth_idle_timeout_ms: Option<u64>,
    #[serde(default)]
    authentication_timeout_ms: Option<u64>,
    #[serde(default)]
    connect_timeout_ms: Option<u64>,
    #[serde(default)]
    egress: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectOutbound {
    #[serde(rename = "protocol")]
    _protocol: DirectOnly,
    tag: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum DirectOnly {
    Direct,
}

#[derive(Deserialize)]
enum AsIsOnly {
    AsIs,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EmptyRouting {
    #[serde(default, rename = "domainStrategy")]
    _domain_strategy: Option<AsIsOnly>,
    #[serde(default, rename = "globalRules")]
    _global_rules: [IgnoredAny; 0],
    #[serde(rename = "users")]
    _users: [IgnoredAny; 0],
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Network {
    dial: Dial,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Dial {
    mode: Option<DialPolicy>,
    #[serde(rename = "fallbackDelayMs")]
    _fallback_delay_ms: DefaultNumber<250>,
    #[serde(rename = "routeRefreshSeconds")]
    _route_refresh_seconds: DefaultNumber<30>,
    #[serde(rename = "hardFailurePenaltySeconds")]
    _hard_failure_penalty_seconds: DefaultNumber<30>,
    #[serde(rename = "latencyMemorySeconds")]
    _latency_memory_seconds: DefaultNumber<300>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct Runtime {
    profile: Option<RuntimeProfile>,
    tuning: Tuning,
    status_file: Option<PathBuf>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Tuning {
    // Fixed mode and custom numeric policies cannot be silently reinterpreted.
    mode: Option<TuningMode>,
    objective: Option<Objective>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnusedAssets {
    #[serde(default, rename = "geoip")]
    _geoip: Option<String>,
    #[serde(default, rename = "geosite")]
    _geosite: Option<String>,
    #[serde(default, rename = "cacheDirectory")]
    _cache_directory: Option<PathBuf>,
    #[serde(default, rename = "reloadIntervalSeconds")]
    _reload_interval_seconds: DefaultNumber<86_400>,
    #[serde(default, rename = "requestTimeoutSeconds")]
    _request_timeout_seconds: DefaultNumber<120>,
    #[serde(default, rename = "maxBytes")]
    _max_bytes: DefaultNumber<134_217_728>,
}

// v1.8 source of these values: src/config/model.rs at tag v1.8.0.
// That release inferred pins by inequality with the default. Thus these
// exact numbers select derivation; accepting any other number here would
// discard an operator pin and is deliberately rejected.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DerivedAdvanced {
    #[serde(rename = "limits")]
    _limits: DerivedLimits,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DerivedLimits {
    #[serde(rename = "resourceGovernor")]
    _resource_governor: DerivedGovernor,
    #[serde(rename = "directBarrier")]
    _direct_barrier: DerivedBarrier,
    #[serde(rename = "relay")]
    _relay: DerivedRelay,
    #[serde(rename = "warmConnections")]
    _warm_connections: DerivedWarm,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DerivedGovernor {
    #[serde(rename = "maxConnections")]
    _max_connections: DefaultNumber<16_384>,
    #[serde(rename = "maxHandshakes")]
    _max_handshakes: DefaultNumber<1_024>,
    #[serde(rename = "maxPreAuthIdleConnections")]
    _max_pre_auth_idle_connections: DefaultNumber<1_024>,
    #[serde(rename = "maxFallbacks")]
    _max_fallbacks: DefaultNumber<512>,
    #[serde(rename = "maxCryptoOperations")]
    _max_crypto_operations: DefaultNumber<128>,
    #[serde(rename = "maxReplayEntries")]
    _max_replay_entries: DefaultNumber<65_536>,
    #[serde(rename = "maxDnsLookups")]
    _max_dns_lookups: DefaultNumber<64>,
    #[serde(rename = "replayRetentionMs")]
    _replay_retention_ms: DefaultNumber<120_000>,
    #[serde(rename = "clientHelloTimeoutMs")]
    _client_hello_timeout_ms: DefaultNumber<3_000>,
    #[serde(rename = "handshakeTimeoutMs")]
    _handshake_timeout_ms: DefaultNumber<10_000>,
    #[serde(rename = "connectTimeoutMs")]
    _connect_timeout_ms: DefaultNumber<10_000>,
    #[serde(rename = "fallbackTimeoutMs")]
    _fallback_timeout_ms: DefaultNumber<120_000>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DerivedBarrier {
    #[serde(rename = "maxConcurrent")]
    _max_concurrent: DefaultNumber<2_048>,
    #[serde(rename = "maxPerSecond")]
    _max_per_second: DefaultNumber<4_096>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DerivedRelay {
    #[serde(rename = "bufferBytes")]
    _buffer_bytes: DefaultNumber<32_768>,
    #[serde(rename = "maxPooledBuffers")]
    _max_pooled_buffers: DefaultNumber<4_096>,
    #[serde(rename = "maxSpliceRelays")]
    _max_splice_relays: DefaultNumber<256>,
    #[serde(rename = "maxRelayMemoryBytes")]
    _max_relay_memory_bytes: DefaultNumber<536_870_912>,
    #[serde(rename = "splice")]
    _splice: DefaultTrue,
    #[serde(rename = "pipePool")]
    _pipe_pool: DefaultTrue,
    #[serde(rename = "maxPooledPipes")]
    _max_pooled_pipes: DefaultNumber<256>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DerivedWarm {
    #[serde(rename = "minReady")]
    _min_ready: DefaultNumber<4>,
    #[serde(rename = "maxReady")]
    _max_ready: DefaultNumber<256>,
    #[serde(rename = "maxConnecting")]
    _max_connecting: DefaultNumber<64>,
    #[serde(rename = "refillBatch")]
    _refill_batch: DefaultNumber<16>,
    #[serde(rename = "idleTimeoutMs")]
    _idle_timeout_ms: DefaultNumber<30_000>,
    #[serde(rename = "maxLifetimeMs")]
    _max_lifetime_ms: DefaultNumber<300_000>,
    #[serde(rename = "shrinkDelayMs")]
    _shrink_delay_ms: DefaultNumber<30_000>,
}

#[derive(Default)]
struct DefaultNumber<const EXPECTED: u64>;

impl<'de, const EXPECTED: u64> Deserialize<'de> for DefaultNumber<EXPECTED> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if u64::deserialize(deserializer)? == EXPECTED {
            Ok(Self)
        } else {
            Err(de::Error::custom(
                "v1.8 landing support requires the unchanged default for this numeric setting",
            ))
        }
    }
}

#[derive(Default)]
struct DefaultTrue;

impl<'de> Deserialize<'de> for DefaultTrue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if bool::deserialize(deserializer)? {
            Ok(Self)
        } else {
            Err(de::Error::custom(
                "v1.8 landing support requires the unchanged true default for this setting",
            ))
        }
    }
}
