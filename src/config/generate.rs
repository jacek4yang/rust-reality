use std::net::IpAddr;

use super::{
    AssetsConfig, Config, ConfigError, DnsConfig, InboundConfig, LogConfig, Network,
    OutboundConfig, PolicyConfig, RealityConfig, RoutingConfig, StreamSettings, UserPolicy,
    VlessClient, VlessInboundConfig, VlessInboundSettings, validate_config,
};
use crate::crypto::{
    KeyGenerationError, generate_short_id, generate_uuid, generate_x25519_key_pair,
};

/// Inputs that cannot safely be guessed for a REALITY server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerateConfigInput {
    /// Address exposed by the public listener.
    pub listen: IpAddr,
    /// Port exposed by the public listener.
    pub port: u16,
    /// REALITY cover endpoint in `host:port` form.
    pub target: String,
    /// Client-facing REALITY SNI.
    pub server_name: String,
}

/// A directly usable server configuration and its client-facing public values.
#[derive(Debug)]
pub struct GeneratedConfig {
    config: Config,
    reality_public_key: String,
}

impl GeneratedConfig {
    /// Returns the generated server configuration.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Returns the REALITY public key clients must use.
    #[must_use]
    pub fn reality_public_key(&self) -> &str {
        &self.reality_public_key
    }

    /// Separates the generated configuration and client-facing public key.
    #[must_use]
    pub fn into_parts(self) -> (Config, String) {
        (self.config, self.reality_public_key)
    }
}

/// A generated configuration could not be produced.
#[derive(Debug)]
pub enum GenerateConfigError {
    /// Operating-system entropy was unavailable.
    Random(KeyGenerationError),
    /// User-supplied generation inputs violate configuration invariants.
    Invalid(ConfigError),
}

impl std::fmt::Display for GenerateConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Random(source) => source.fmt(formatter),
            Self::Invalid(source) => source.fmt(formatter),
        }
    }
}

impl std::error::Error for GenerateConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Random(source) => Some(source),
            Self::Invalid(source) => Some(source),
        }
    }
}

impl From<KeyGenerationError> for GenerateConfigError {
    fn from(source: KeyGenerationError) -> Self {
        Self::Random(source)
    }
}

impl From<ConfigError> for GenerateConfigError {
    fn from(source: ConfigError) -> Self {
        Self::Invalid(source)
    }
}

/// Generates a minimal VLESS + REALITY + Vision server using direct routing.
///
/// # Errors
///
/// Returns an error when OS entropy is unavailable or the supplied target, SNI,
/// listener, or port fails strict validation.
pub fn generate_minimal_config(
    input: GenerateConfigInput,
) -> Result<GeneratedConfig, GenerateConfigError> {
    let uuid = generate_uuid()?.to_string();
    let short_id = generate_short_id()?;
    let key_pair = generate_x25519_key_pair()?;
    let (private_key, public_key) = key_pair.into_parts();
    let config = Config {
        log: LogConfig::default(),
        assets: AssetsConfig::default(),
        dns: DnsConfig::default(),
        inbounds: vec![InboundConfig::Vless(VlessInboundConfig {
            tag: "public-reality".to_owned(),
            listen: input.listen,
            port: input.port,
            settings: VlessInboundSettings {
                clients: vec![VlessClient {
                    id: uuid.clone(),
                    email: Some("default-user".to_owned()),
                    flow: "xtls-rprx-vision".to_owned(),
                }],
                decryption: "none".to_owned(),
            },
            stream_settings: StreamSettings {
                network: Network::Tcp,
                security: "reality".to_owned(),
                reality_settings: RealityConfig {
                    target: input.target,
                    server_names: vec![input.server_name],
                    private_key,
                    short_ids: vec![short_id],
                    max_time_diff_ms: 60_000,
                },
            },
        })],
        outbounds: vec![OutboundConfig::Direct {
            tag: "direct".to_owned(),
        }],
        routing: RoutingConfig {
            domain_strategy: super::DnsStrategy::IpIfNonMatch,
            global_rules: Vec::new(),
            users: vec![UserPolicy {
                name: "direct-users".to_owned(),
                user_ids: vec![uuid],
                default_outbound: "direct".to_owned(),
                rules: Vec::new(),
            }],
        },
        policy: PolicyConfig::default(),
    };
    validate_config(&config)?;
    Ok(GeneratedConfig {
        config,
        reality_public_key: public_key,
    })
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr};

    use super::{GenerateConfigInput, generate_minimal_config};
    use crate::config::{format_config, load_config};

    #[test]
    fn generated_json_is_directly_loadable() {
        let generated = generate_minimal_config(GenerateConfigInput {
            listen: IpAddr::from_str("0.0.0.0").expect("address must parse"),
            port: 443,
            target: "www.example.com:443".to_owned(),
            server_name: "www.example.com".to_owned(),
        })
        .expect("generation must succeed");
        let json = format_config(generated.config()).expect("configuration must serialize");

        assert!(json.contains("xtls-rprx-vision"));
        assert!(json.contains("\"security\": \"reality\""));
        assert_eq!(generated.reality_public_key().len(), 43);

        let path = std::env::temp_dir().join(format!(
            "rust-reality-generated-config-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, json).expect("temporary configuration must be written");
        let loaded = load_config(&path).expect("generated configuration must load");
        std::fs::remove_file(&path).expect("temporary configuration must be removed");

        assert_eq!(&loaded, generated.config());
    }
}
