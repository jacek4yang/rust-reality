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

/// Loads, size-bounds, decodes, and validates one JSON configuration.
///
/// # Errors
///
/// Returns an error when the file cannot be read, exceeds the hard size limit,
/// contains invalid JSON, contains unknown fields, or violates a runtime invariant.
pub fn load_config(path: impl AsRef<Path>) -> Result<Config, ConfigLoadError> {
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

fn decode_config(path: &Path, bytes: &[u8]) -> Result<Config, ConfigLoadError> {
    let config = serde_json::from_slice(bytes).map_err(|source| ConfigLoadError::Decode {
        path: path.to_owned(),
        source,
    })?;
    validate_config(&config).map_err(ConfigLoadError::Invalid)?;
    Ok(config)
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
    fn existing_configuration_without_max_dns_lookups_uses_the_default() {
        // The fixture predates maxDnsLookups: decoding must succeed and apply
        // the default rather than failing or silently disabling the bound.
        let config = decode_config(Path::new("test.json"), test_config_json().as_bytes())
            .expect("existing configuration must remain valid");
        assert_eq!(config.policy.resource_governor.max_dns_lookups, 64);

        let mut value: serde_json::Value =
            serde_json::from_str(test_config_json()).expect("fixture must parse");
        let mut governor =
            serde_json::to_value(&config.policy.resource_governor).expect("governor must encode");
        governor["maxDnsLookups"] = 17.into();
        value["policy"]["resourceGovernor"] = governor;
        let json = serde_json::to_string(&value).expect("config must encode");
        let config = decode_config(Path::new("test.json"), json.as_bytes())
            .expect("an explicit maxDnsLookups must decode");
        assert_eq!(config.policy.resource_governor.max_dns_lookups, 17);
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
}
