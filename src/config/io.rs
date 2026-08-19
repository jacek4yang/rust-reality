use std::{
    error::Error,
    fmt,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
};

use super::{Config, ConfigError, validate_config};

/// Maximum accepted JSON configuration size.
pub const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;

/// An error produced while loading a strict JSON configuration.
#[derive(Debug)]
pub enum ConfigLoadError {
    /// The file could not be opened or read.
    Io {
        /// Configuration path.
        path: PathBuf,
        /// Underlying I/O failure.
        source: io::Error,
    },
    /// The file exceeds [`MAX_CONFIG_BYTES`].
    TooLarge {
        /// Configuration path.
        path: PathBuf,
        /// Observed or lower-bound byte count.
        bytes: u64,
    },
    /// JSON syntax or shape is invalid.
    Decode {
        /// Configuration path.
        path: PathBuf,
        /// Parser failure. Its public display is deliberately reduced to location data.
        source: serde_json::Error,
    },
    /// JSON decoded successfully but violates runtime invariants.
    Invalid(ConfigError),
}

impl fmt::Display for ConfigLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, .. } => {
                write!(formatter, "failed to read configuration {}", path.display())
            }
            Self::TooLarge { path, bytes } => write!(
                formatter,
                "configuration {} is too large ({bytes} bytes; maximum {MAX_CONFIG_BYTES})",
                path.display()
            ),
            Self::Decode { path, source } => write!(
                formatter,
                "invalid JSON configuration {} at line {} column {}",
                path.display(),
                source.line(),
                source.column()
            ),
            Self::Invalid(source) => source.fmt(formatter),
        }
    }
}

impl Error for ConfigLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Decode { source, .. } => Some(source),
            Self::Invalid(source) => Some(source),
            Self::TooLarge { .. } => None,
        }
    }
}

/// Deprecations applied while loading one configuration.
///
/// Loading never stays silent about a deprecated key: every load API that
/// can surface a warning receives this report alongside the configuration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConfigLoadReport {
    /// A deprecated top-level `policy` object was merged into
    /// `advanced.limits`, forcing `runtime.tuning.mode` to `fixed` unless
    /// explicitly set.
    pub policy_alias_used: bool,
}

/// Loads, size-bounds, decodes, and validates one JSON configuration.
///
/// # Errors
///
/// Returns an error when the file cannot be read, exceeds the hard size limit,
/// contains invalid JSON, contains unknown fields, or violates a runtime invariant.
pub fn load_config(path: impl AsRef<Path>) -> Result<Config, ConfigLoadError> {
    load_config_with_report(path).map(|(config, _)| config)
}

/// Loads one JSON configuration and reports applied deprecations.
///
/// Identical to [`load_config`], additionally returning whether deprecated
/// aliases were rewritten so the caller can warn exactly once per load.
///
/// # Errors
///
/// Returns an error under the same conditions as [`load_config`].
pub fn load_config_with_report(
    path: impl AsRef<Path>,
) -> Result<(Config, ConfigLoadReport), ConfigLoadError> {
    let path = path.as_ref();
    let file = File::open(path).map_err(|source| ConfigLoadError::Io {
        path: path.to_owned(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| ConfigLoadError::Io {
        path: path.to_owned(),
        source,
    })?;

    if metadata.len() > MAX_CONFIG_BYTES as u64 {
        return Err(ConfigLoadError::TooLarge {
            path: path.to_owned(),
            bytes: metadata.len(),
        });
    }

    let capacity = usize::try_from(metadata.len())
        .map_or(MAX_CONFIG_BYTES, |bytes| bytes.min(MAX_CONFIG_BYTES));
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_CONFIG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| ConfigLoadError::Io {
            path: path.to_owned(),
            source,
        })?;

    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(ConfigLoadError::TooLarge {
            path: path.to_owned(),
            bytes: bytes.len() as u64,
        });
    }

    decode_config(path, &bytes)
}

fn decode_config(path: &Path, bytes: &[u8]) -> Result<(Config, ConfigLoadReport), ConfigLoadError> {
    let mut config: Config =
        serde_json::from_slice(bytes).map_err(|source| ConfigLoadError::Decode {
            path: path.to_owned(),
            source,
        })?;
    let report = ConfigLoadReport {
        policy_alias_used: config.normalize().map_err(ConfigLoadError::Invalid)?,
    };
    validate_config(&config).map_err(ConfigLoadError::Invalid)?;
    Ok((config, report))
}

/// Serializes a validated configuration as deterministic pretty JSON.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn format_config(config: &Config) -> Result<String, serde_json::Error> {
    let mut output = serde_json::to_string_pretty(config)?;
    output.push('\n');
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{ConfigLoadError, decode_config, format_config};
    use crate::config::test_config_json;

    #[test]
    fn rejects_unknown_top_level_fields() {
        let json = test_config_json().replace("\"policy\": {}", "\"policy\": {}, \"metrics\": {} ");
        let error = decode_config(Path::new("test.json"), json.as_bytes())
            .expect_err("unknown fields must be rejected");

        assert!(matches!(error, ConfigLoadError::Decode { .. }));
    }

    #[test]
    fn rejects_removed_io_uring_relay_fields() {
        // The io_uring backend was removed; its former keys must fail decoding
        // rather than being silently accepted.
        let json = test_config_json().replace(
            "\"policy\": {}",
            "\"policy\": { \"relay\": { \"ioUring\": true, \"maxIoUringRelays\": 256 } }",
        );
        let error = decode_config(Path::new("test.json"), json.as_bytes())
            .expect_err("removed io_uring fields must be rejected");

        assert!(matches!(error, ConfigLoadError::Decode { .. }));
    }

    #[test]
    fn rejects_removed_combined_address_family_and_scalar_listener() {
        let mut value: serde_json::Value =
            serde_json::from_str(test_config_json()).expect("fixture must parse");
        value["network"] = serde_json::json!({ "addressFamily": "auto" });
        let json = serde_json::to_vec(&value).expect("obsolete network shape must encode");
        assert!(matches!(
            decode_config(Path::new("obsolete-network.json"), &json),
            Err(ConfigLoadError::Decode { .. })
        ));

        let mut value: serde_json::Value =
            serde_json::from_str(test_config_json()).expect("fixture must parse");
        value["inbounds"][0]["listen"] = "0.0.0.0".into();
        let json = serde_json::to_vec(&value).expect("obsolete listener shape must encode");
        assert!(matches!(
            decode_config(Path::new("obsolete-listen.json"), &json),
            Err(ConfigLoadError::Decode { .. })
        ));
    }

    #[test]
    fn accepts_every_listener_and_dial_mode() {
        for dial_mode in ["auto", "preferIpv4", "preferIpv6", "ipv4Only", "ipv6Only"] {
            let mut value: serde_json::Value =
                serde_json::from_str(test_config_json()).expect("fixture must parse");
            value["network"]["dial"]["mode"] = dial_mode.into();
            let json = serde_json::to_vec(&value).expect("dial mode must encode");
            decode_config(Path::new("dial-mode.json"), &json)
                .unwrap_or_else(|error| panic!("dial mode {dial_mode} must decode: {error}"));
        }
        for listen_mode in ["auto", "dualStack", "ipv4Only", "ipv6Only"] {
            let mut value: serde_json::Value =
                serde_json::from_str(test_config_json()).expect("fixture must parse");
            value["inbounds"][0]["listen"]["mode"] = listen_mode.into();
            let json = serde_json::to_vec(&value).expect("listen mode must encode");
            decode_config(Path::new("listen-mode.json"), &json)
                .unwrap_or_else(|error| panic!("listener mode {listen_mode} must decode: {error}"));
        }
    }

    #[test]
    fn rejects_ambiguous_pre_v13_shared_short_ids() {
        let mut value: serde_json::Value =
            serde_json::from_str(test_config_json()).expect("fixture must parse");
        let shared = value["inbounds"][0]["settings"]["clients"][0]
            .as_object_mut()
            .expect("client must be an object")
            .remove("shortIds")
            .expect("fixture must contain owned short IDs");
        value["inbounds"][0]["streamSettings"]["realitySettings"]["shortIds"] = shared;
        let json = serde_json::to_vec(&value).expect("legacy shape must encode");

        let error = decode_config(Path::new("v1.2.json"), &json)
            .expect_err("the server must not guess ownership of a shared credential list");
        assert!(matches!(error, ConfigLoadError::Decode { .. }));
    }

    #[test]
    fn existing_configuration_without_max_dns_lookups_uses_the_default() {
        // The fixture predates maxDnsLookups: decoding must succeed and apply
        // the default rather than failing or silently disabling the bound.
        let (config, _) = decode_config(Path::new("test.json"), test_config_json().as_bytes())
            .expect("existing configuration must remain valid");
        assert_eq!(config.advanced.limits.resource_governor.max_dns_lookups, 64);

        let mut value: serde_json::Value =
            serde_json::from_str(test_config_json()).expect("fixture must parse");
        let mut governor = serde_json::to_value(&config.advanced.limits.resource_governor)
            .expect("governor must encode");
        governor["maxDnsLookups"] = 17.into();
        value["policy"]["resourceGovernor"] = governor;
        let json = serde_json::to_string(&value).expect("config must encode");
        let (config, report) = decode_config(Path::new("test.json"), json.as_bytes())
            .expect("an explicit maxDnsLookups must decode");
        assert_eq!(config.advanced.limits.resource_governor.max_dns_lookups, 17);
        assert!(report.policy_alias_used);
    }

    #[test]
    fn formatted_configuration_round_trips() {
        let (config, _) = decode_config(Path::new("test.json"), test_config_json().as_bytes())
            .expect("fixture must be valid");
        let formatted = format_config(&config).expect("configuration must serialize");
        let (reparsed, _) = decode_config(Path::new("formatted.json"), formatted.as_bytes())
            .expect("formatted configuration must be valid");

        assert_eq!(reparsed, config);
        assert!(formatted.ends_with('\n'));
    }

    /// A complete v1.5 `policy` object, valid against every cross-field
    /// invariant.
    fn v15_policy_json() -> serde_json::Value {
        serde_json::json!({
            "resourceGovernor": {
                "maxConnections": 2048,
                "maxHandshakes": 512,
                "maxFallbacks": 256,
                "maxCryptoOperations": 64,
                "maxReplayEntries": 4096,
                "maxDnsLookups": 16,
                "replayRetentionMs": 60000,
                "clientHelloTimeoutMs": 1000,
                "handshakeTimeoutMs": 5000,
                "connectTimeoutMs": 4000,
                "fallbackTimeoutMs": 60000
            },
            "directBarrier": { "maxConcurrent": 1024, "maxPerSecond": 2000 },
            "relay": {
                "bufferBytes": 16384,
                "maxPooledBuffers": 1024,
                "maxSpliceRelays": 128,
                "maxRelayMemoryBytes": 268435456,
                "splice": true,
                "pipePool": true,
                "maxPooledPipes": 256
            }
        })
    }

    fn v15_policy_config() -> crate::config::PolicyConfig {
        crate::config::PolicyConfig {
            resource_governor: crate::config::ResourceGovernorConfig {
                max_connections: 2048,
                max_handshakes: 512,
                max_fallbacks: 256,
                max_crypto_operations: 64,
                max_replay_entries: 4096,
                max_dns_lookups: 16,
                replay_retention_ms: 60_000,
                client_hello_timeout_ms: 1_000,
                handshake_timeout_ms: 5_000,
                connect_timeout_ms: 4_000,
                fallback_timeout_ms: 60_000,
            },
            direct_barrier: crate::config::DirectBarrierConfig {
                max_concurrent: 1_024,
                max_per_second: 2_000,
            },
            relay: crate::config::RelayPolicy {
                buffer_bytes: 16_384,
                max_pooled_buffers: 1_024,
                max_splice_relays: 128,
                max_relay_memory_bytes: 268_435_456,
                splice: true,
                pipe_pool: true,
                max_pooled_pipes: 256,
            },
        }
    }

    #[test]
    fn v15_policy_parses_byte_identically_through_the_alias() {
        // Back-compat hard requirement: a v1.5 config with an explicit
        // `policy` object yields exactly the same effective numbers.
        let mut value: serde_json::Value =
            serde_json::from_str(test_config_json()).expect("fixture must parse");
        value["policy"] = v15_policy_json();
        let json = serde_json::to_vec(&value).expect("config must encode");
        let (config, report) =
            decode_config(Path::new("v1.5.json"), &json).expect("a v1.5 policy must keep parsing");

        assert_eq!(
            config.advanced.limits,
            v15_policy_config(),
            "every v1.5 policy number must survive the merge unchanged"
        );
        assert_eq!(config.policy, None, "the alias is consumed by the merge");
        assert!(report.policy_alias_used, "the rewrite is reported");
        assert_eq!(
            config.runtime.tuning.mode,
            Some(crate::config::TuningMode::Fixed),
            "an alias without an explicit mode forces fixed"
        );

        // The rewrite is stable: formatting emits the canonical location and
        // reparsing reproduces the identical configuration.
        let formatted = format_config(&config).expect("configuration must serialize");
        assert!(!formatted.contains("\"policy\""));
        assert!(formatted.contains("\"advanced\""));
        assert!(formatted.contains("\"mode\": \"fixed\""));
        let (reparsed, reparsed_report) =
            decode_config(Path::new("formatted.json"), formatted.as_bytes())
                .expect("the rewritten configuration must parse");
        assert_eq!(reparsed, config);
        assert!(!reparsed_report.policy_alias_used);
    }

    /// A complete v1.5 `policy.resourceGovernor` object (fields without
    /// serde defaults are required when the object is present).
    fn governor_json(max_connections: u32) -> serde_json::Value {
        serde_json::json!({
            "maxConnections": max_connections,
            "maxHandshakes": 1024,
            "maxFallbacks": 512,
            "maxCryptoOperations": 128,
            "maxReplayEntries": 65536,
            "maxDnsLookups": 64,
            "replayRetentionMs": 120000,
            "clientHelloTimeoutMs": 3000,
            "handshakeTimeoutMs": 10000,
            "connectTimeoutMs": 10000,
            "fallbackTimeoutMs": 120000
        })
    }

    /// A complete v1.5 `policy.relay` object.
    fn relay_json(buffer_bytes: u32, splice: bool) -> serde_json::Value {
        serde_json::json!({
            "bufferBytes": buffer_bytes,
            "maxPooledBuffers": 4096,
            "splice": splice
        })
    }

    #[test]
    fn alias_merges_field_by_field_over_the_new_location() {
        let mut value: serde_json::Value =
            serde_json::from_str(test_config_json()).expect("fixture must parse");
        value["policy"] = serde_json::json!({
            "resourceGovernor": governor_json(2048),
            "relay": relay_json(32768, false)
        });
        value["advanced"] = serde_json::json!({
            "limits": { "directBarrier": { "maxConcurrent": 1024, "maxPerSecond": 2000 } }
        });
        let json = serde_json::to_vec(&value).expect("config must encode");
        let (config, report) =
            decode_config(Path::new("merged.json"), &json).expect("the merge must succeed");

        let limits = &config.advanced.limits;
        assert_eq!(limits.resource_governor.max_connections, 2_048);
        assert!(!limits.relay.splice);
        assert_eq!(limits.direct_barrier.max_per_second, 2_000);
        assert_eq!(
            limits.resource_governor.max_handshakes,
            crate::config::ResourceGovernorConfig::default().max_handshakes,
            "fields set nowhere keep their defaults"
        );
        assert!(report.policy_alias_used);
    }

    #[test]
    fn equal_values_in_both_locations_are_not_a_conflict() {
        let mut value: serde_json::Value =
            serde_json::from_str(test_config_json()).expect("fixture must parse");
        value["policy"] = serde_json::json!({ "relay": relay_json(16384, true) });
        value["advanced"] = serde_json::json!({ "limits": { "relay": relay_json(16384, true) } });
        let json = serde_json::to_vec(&value).expect("config must encode");
        let (config, _) =
            decode_config(Path::new("equal.json"), &json).expect("agreeing locations must merge");

        assert_eq!(config.advanced.limits.relay.buffer_bytes, 16_384);
    }

    #[test]
    fn conflicting_alias_and_limits_are_rejected() {
        let mut value: serde_json::Value =
            serde_json::from_str(test_config_json()).expect("fixture must parse");
        value["policy"] = serde_json::json!({ "relay": relay_json(16384, true) });
        value["advanced"] = serde_json::json!({ "limits": { "relay": relay_json(65536, true) } });
        let json = serde_json::to_vec(&value).expect("config must encode");
        let error = decode_config(Path::new("conflict.json"), &json)
            .expect_err("contradictory numbers must fail closed");

        let ConfigLoadError::Invalid(source) = error else {
            panic!("a merge conflict must be a validation error");
        };
        assert_eq!(source.path(), "policy.relay.bufferBytes");
    }

    #[test]
    fn an_explicit_tuning_mode_survives_the_alias_merge() {
        let mut value: serde_json::Value =
            serde_json::from_str(test_config_json()).expect("fixture must parse");
        value["policy"] = v15_policy_json();
        value["runtime"] = serde_json::json!({ "tuning": { "mode": "startup" } });
        let json = serde_json::to_vec(&value).expect("config must encode");
        let (config, report) =
            decode_config(Path::new("explicit-mode.json"), &json).expect("config must load");

        assert!(report.policy_alias_used);
        assert_eq!(
            config.runtime.tuning.mode,
            Some(crate::config::TuningMode::Startup),
            "fixed is forced only when the mode was not explicitly set"
        );
    }

    #[test]
    fn the_new_model_alone_reports_no_deprecation() {
        let mut value: serde_json::Value =
            serde_json::from_str(test_config_json()).expect("fixture must parse");
        value.as_object_mut().expect("object").remove("policy");
        value["runtime"] = serde_json::json!({
            "profile": "shared",
            "tuning": { "mode": "fixed", "objective": "throughput" }
        });
        value["advanced"] = serde_json::json!({
            "limits": { "resourceGovernor": governor_json(2048) }
        });
        let json = serde_json::to_vec(&value).expect("config must encode");
        let (config, report) =
            decode_config(Path::new("v1.6.json"), &json).expect("the new model must load");

        assert!(!report.policy_alias_used);
        assert_eq!(config.policy, None);
        assert_eq!(
            config.runtime.profile,
            crate::config::RuntimeProfile::Shared
        );
        assert_eq!(
            config.runtime.tuning.mode(),
            crate::config::TuningMode::Fixed
        );
        assert_eq!(
            config.runtime.tuning.objective,
            crate::config::Objective::Throughput
        );
        assert_eq!(
            config.advanced.limits.resource_governor.max_connections,
            2_048
        );
    }

    #[test]
    fn unknown_fields_are_rejected_in_the_new_sections() {
        for (section, body) in [
            (
                "runtime",
                serde_json::json!({ "tuning": { "mode": "fixed", "curve": "x" } }),
            ),
            ("runtime", serde_json::json!({ "profile": "exclusive" })),
            (
                "advanced",
                serde_json::json!({ "limits": {}, "tuning": {} }),
            ),
            (
                "advanced",
                serde_json::json!({ "limits": { "resourceGovernor": {}, "bogus": 1 } }),
            ),
        ] {
            let mut value: serde_json::Value =
                serde_json::from_str(test_config_json()).expect("fixture must parse");
            value[section] = body;
            let json = serde_json::to_vec(&value).expect("config must encode");
            assert!(
                matches!(
                    decode_config(Path::new("unknown.json"), &json),
                    Err(ConfigLoadError::Decode { .. })
                ),
                "unknown fields must be rejected in {section}: {json:?}"
            );
        }
    }
}
