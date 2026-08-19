use std::{
    error::Error,
    fmt,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
};

use super::{Config, ConfigError, diagnostic::Diagnostic, validate_config};

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
        /// Source-oriented rendering of the failure.
        diagnostic: Box<Diagnostic>,
        /// Parser failure, retained as the programmatic cause.
        source: serde_json::Error,
    },
    /// JSON decoded successfully but violates runtime invariants.
    Invalid {
        /// Source-oriented rendering of the failure.
        diagnostic: Box<Diagnostic>,
        /// Validation failure, retained as the programmatic cause.
        source: ConfigError,
    },
}

impl ConfigLoadError {
    /// Returns the source-oriented diagnostic, when the failure carries one.
    #[must_use]
    pub fn diagnostic(&self) -> Option<&Diagnostic> {
        match self {
            Self::Decode { diagnostic, .. } | Self::Invalid { diagnostic, .. } => Some(diagnostic),
            Self::Io { .. } | Self::TooLarge { .. } => None,
        }
    }
}

impl fmt::Display for ConfigLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(
                formatter,
                "failed to read configuration {}: {source}",
                path.display()
            ),
            Self::TooLarge { path, bytes } => write!(
                formatter,
                "configuration {} is too large ({bytes} bytes; maximum {MAX_CONFIG_BYTES})",
                path.display()
            ),
            Self::Decode { diagnostic, .. } | Self::Invalid { diagnostic, .. } => {
                diagnostic.fmt(formatter)
            }
        }
    }
}

impl Error for ConfigLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Decode { source, .. } => Some(source),
            Self::Invalid { source, .. } => Some(source),
            Self::TooLarge { .. } => None,
        }
    }
}

/// Loads, size-bounds, decodes, and validates one JSON configuration.
///
/// # Errors
///
/// Returns an error when the file cannot be read, exceeds the hard size limit,
/// contains invalid JSON, contains unknown fields, or violates a runtime invariant.
pub fn load_config(path: impl AsRef<Path>) -> Result<Config, ConfigLoadError> {
    let path = path.as_ref();
    let bytes = read_config_bytes(path)?;
    decode_config(path, &bytes)
}

/// Reads one configuration file into memory, enforcing the hard size limit.
pub(super) fn read_config_bytes(path: &Path) -> Result<Vec<u8>, ConfigLoadError> {
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

    Ok(bytes)
}

pub(super) fn decode_config(path: &Path, bytes: &[u8]) -> Result<Config, ConfigLoadError> {
    // The source text backs every excerpt and span. Lossy decoding is safe:
    // offsets are always clamped to line and character boundaries, and valid
    // configurations (the common error case: semantic failures) are UTF-8.
    let text = String::from_utf8_lossy(bytes);
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let config: Config = match serde_path_to_error::deserialize(&mut deserializer) {
        Ok(config) => config,
        Err(tracked) => {
            let serde_path = tracked.path().to_string();
            let source = tracked.into_inner();
            return Err(ConfigLoadError::Decode {
                diagnostic: Box::new(Diagnostic::decode(path, &text, &serde_path, &source)),
                source,
            });
        }
    };
    if let Err(source) = deserializer.end() {
        return Err(ConfigLoadError::Decode {
            diagnostic: Box::new(Diagnostic::decode(path, &text, "", &source)),
            source,
        });
    }
    validate_config(&config).map_err(|source| ConfigLoadError::Invalid {
        diagnostic: Box::new(Diagnostic::validation(path, &text, &source)),
        source,
    })?;
    Ok(config)
}

/// Fuzz entry point: decodes and validates raw configuration bytes.
///
/// Exercises the exact `load_config` decode path without touching the file
/// system. Gated behind the `fuzzing` feature, which the `fuzz/` workspace
/// enables on this crate; never part of a production build.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_decode_config(bytes: &[u8]) -> Result<Config, ConfigLoadError> {
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(ConfigLoadError::TooLarge {
            path: PathBuf::from("<fuzz>"),
            bytes: bytes.len() as u64,
        });
    }
    decode_config(Path::new("<fuzz>"), bytes)
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
        let json = test_config_json().replace("\"log\": {", "\"metrics\": {}, \"log\": {");
        let error = decode_config(Path::new("test.json"), json.as_bytes())
            .expect_err("unknown fields must be rejected");

        assert!(matches!(error, ConfigLoadError::Decode { .. }));
    }

    #[test]
    fn rejects_removed_io_uring_relay_fields() {
        // The io_uring backend was removed; its former keys must fail decoding
        // rather than being silently accepted.
        let mut value: serde_json::Value =
            serde_json::from_str(test_config_json()).expect("fixture must parse");
        value["advanced"] = serde_json::json!({
            "limits": { "relay": { "ioUring": true, "maxIoUringRelays": 256 } }
        });
        let json = serde_json::to_vec(&value).expect("config must encode");
        let error = decode_config(Path::new("test.json"), &json)
            .expect_err("removed io_uring fields must be rejected");

        assert!(matches!(error, ConfigLoadError::Decode { .. }));
    }

    #[test]
    fn rejects_removed_policy_alias() {
        // The v1.5 top-level `policy` object was removed; its former key must
        // fail decoding rather than being silently accepted.
        let mut value: serde_json::Value =
            serde_json::from_str(test_config_json()).expect("fixture must parse");
        value["policy"] = serde_json::json!({ "relay": { "bufferBytes": 16384 } });
        let json = serde_json::to_vec(&value).expect("config must encode");
        let error = decode_config(Path::new("v1.5.json"), &json)
            .expect_err("the removed policy alias must be rejected");

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
        let config = decode_config(Path::new("test.json"), test_config_json().as_bytes())
            .expect("existing configuration must remain valid");
        assert_eq!(config.advanced.limits.resource_governor.max_dns_lookups, 64);

        let mut value: serde_json::Value =
            serde_json::from_str(test_config_json()).expect("fixture must parse");
        let mut governor = serde_json::to_value(&config.advanced.limits.resource_governor)
            .expect("governor must encode");
        governor["maxDnsLookups"] = 17.into();
        value["advanced"] = serde_json::json!({ "limits": { "resourceGovernor": governor } });
        let json = serde_json::to_string(&value).expect("config must encode");
        let config = decode_config(Path::new("test.json"), json.as_bytes())
            .expect("an explicit maxDnsLookups must decode");
        assert_eq!(config.advanced.limits.resource_governor.max_dns_lookups, 17);
    }

    #[test]
    fn formatted_configuration_round_trips() {
        let config = decode_config(Path::new("test.json"), test_config_json().as_bytes())
            .expect("fixture must be valid");
        let formatted = format_config(&config).expect("configuration must serialize");
        let reparsed = decode_config(Path::new("formatted.json"), formatted.as_bytes())
            .expect("formatted configuration must be valid");

        assert_eq!(reparsed, config);
        assert!(formatted.ends_with('\n'));
    }

    /// A complete `advanced.limits.resourceGovernor` object (fields without
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

    #[test]
    fn the_new_model_alone_loads() {
        let mut value: serde_json::Value =
            serde_json::from_str(test_config_json()).expect("fixture must parse");
        value["runtime"] = serde_json::json!({
            "profile": "shared",
            "tuning": { "mode": "fixed", "objective": "throughput" }
        });
        value["advanced"] = serde_json::json!({
            "limits": { "resourceGovernor": governor_json(2048) }
        });
        let json = serde_json::to_vec(&value).expect("config must encode");
        let config = decode_config(Path::new("v1.6.json"), &json).expect("the new model must load");

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
