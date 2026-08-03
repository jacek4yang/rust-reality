use std::{
    error::Error,
    fmt,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use arc_swap::ArcSwap;

use super::{Config, ConfigError, ConfigLoadError, load_config, validate_config};

/// One immutable configuration generation held by active connections.
#[derive(Debug)]
pub struct ConfigSnapshot {
    generation: u64,
    config: Config,
}

impl ConfigSnapshot {
    /// Returns the monotonically increasing publication generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the immutable configuration.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }
}

/// A publication failure. The previous snapshot remains active.
#[derive(Debug)]
pub enum ConfigUpdateError {
    /// Loading or decoding failed.
    Load(ConfigLoadError),
    /// A programmatically supplied configuration is invalid.
    Invalid(ConfigError),
    /// The 64-bit publication counter is exhausted.
    GenerationExhausted,
}

impl fmt::Display for ConfigUpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Load(source) => source.fmt(formatter),
            Self::Invalid(source) => source.fmt(formatter),
            Self::GenerationExhausted => formatter.write_str("configuration generation exhausted"),
        }
    }
}

impl Error for ConfigUpdateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Load(source) => Some(source),
            Self::Invalid(source) => Some(source),
            Self::GenerationExhausted => None,
        }
    }
}

impl From<ConfigLoadError> for ConfigUpdateError {
    fn from(source: ConfigLoadError) -> Self {
        Self::Load(source)
    }
}

impl From<ConfigError> for ConfigUpdateError {
    fn from(source: ConfigError) -> Self {
        Self::Invalid(source)
    }
}

/// Lock-free read-mostly publication of complete, validated snapshots.
pub struct ConfigStore {
    current: ArcSwap<ConfigSnapshot>,
    generation: AtomicU64,
}

impl ConfigStore {
    /// Creates a store at generation zero.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial configuration is invalid.
    pub fn new(config: Config) -> Result<Self, ConfigError> {
        validate_config(&config)?;
        Ok(Self {
            current: ArcSwap::from_pointee(ConfigSnapshot {
                generation: 0,
                config,
            }),
            generation: AtomicU64::new(0),
        })
    }

    /// Acquires the current immutable snapshot for a connection or request.
    #[must_use]
    pub fn load(&self) -> Arc<ConfigSnapshot> {
        self.current.load_full()
    }

    /// Validates and atomically publishes a complete configuration.
    ///
    /// Existing readers retain their old snapshot until they release it.
    ///
    /// # Errors
    ///
    /// Returns an error without changing the active snapshot if validation fails
    /// or the generation counter is exhausted.
    pub fn publish(&self, config: Config) -> Result<u64, ConfigUpdateError> {
        validate_config(&config)?;
        let generation = self.next_generation()?;
        self.current
            .store(Arc::new(ConfigSnapshot { generation, config }));
        Ok(generation)
    }

    /// Loads and atomically publishes a JSON configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error without changing the active snapshot if reading, decoding,
    /// validation, or publication fails.
    pub fn reload(&self, path: impl AsRef<Path>) -> Result<u64, ConfigUpdateError> {
        self.publish(load_config(path)?)
    }

    fn next_generation(&self) -> Result<u64, ConfigUpdateError> {
        let mut observed = self.generation.load(Ordering::Acquire);
        loop {
            let next = observed
                .checked_add(1)
                .ok_or(ConfigUpdateError::GenerationExhausted)?;
            match self.generation.compare_exchange_weak(
                observed,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(next),
                Err(current) => observed = current,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::config::{Config, ConfigStore};

    fn valid_config() -> Config {
        serde_json::from_str(crate::config::test_config_json()).expect("fixture must decode")
    }

    #[test]
    fn publication_preserves_existing_readers() {
        let store = ConfigStore::new(valid_config()).expect("fixture must validate");
        let old = store.load();
        let mut replacement = valid_config();
        replacement.dns.timeout_ms = 1_234;

        assert_eq!(store.publish(replacement).expect("publish must succeed"), 1);
        let current = store.load();

        assert_eq!(old.generation(), 0);
        assert_eq!(old.config().dns.timeout_ms, 5_000);
        assert_eq!(current.generation(), 1);
        assert_eq!(current.config().dns.timeout_ms, 1_234);
        assert!(!Arc::ptr_eq(&old, &current));
    }

    #[test]
    fn failed_publication_keeps_last_good_snapshot() {
        let store = ConfigStore::new(valid_config()).expect("fixture must validate");
        let before = store.load();
        let mut invalid = valid_config();
        invalid.inbounds[0].stream_settings.security = "none".to_owned();

        store
            .publish(invalid)
            .expect_err("invalid update must fail");
        let after = store.load();

        assert!(Arc::ptr_eq(&before, &after));
        assert_eq!(after.generation(), 0);
    }
}
