use std::net::IpAddr;

use serde_json::json;

use super::{
    AssetsConfig, BlackholeSettings, Config, ConfigError, DnsConfig, DnsStrategy,
    HandoffInboundConfig, HandoffInboundSettings, HandoffSettings, InboundConfig, LogConfig,
    Network, NxrInboundConfig, NxrInboundSettings, NxrSettings, OutboundConfig, PolicyConfig,
    RealityConfig, RoutingConfig, RuntimeConfig, SecretString, StreamSettings, UserPolicy,
    VlessClient, VlessInboundConfig, VlessInboundSettings, validate_config,
};
use crate::crypto::{
    KeyGenerationError, generate_node_key, generate_short_id, generate_uuid,
    generate_x25519_key_pair,
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

/// Inputs for a public line node whose default outbound is one NXR landing node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerateLineConfigInput {
    /// Public VLESS + REALITY + Vision listener settings.
    pub public: GenerateConfigInput,
    /// Internal landing-node address reachable by the line node.
    pub nxr_address: String,
    /// Firewall-restricted NXR port on the landing node.
    pub nxr_port: u16,
    /// Independent 32-byte NXR PSK shared only with the landing node.
    pub pre_shared_key: SecretString,
}

/// Inputs for a firewall-restricted NXR landing node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerateLandingConfigInput {
    /// Address exposed only to trusted line-node addresses.
    pub listen: IpAddr,
    /// Firewall-restricted NXR listener port.
    pub port: u16,
    /// Independent 32-byte NXR PSK shared only with the line node.
    pub pre_shared_key: SecretString,
}

/// Inputs for a Handoff line/landing node pair and its Xray client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerateHandoffConfigInput {
    /// Public VLESS + REALITY + Vision listener settings of the line node.
    pub public: GenerateConfigInput,
    /// Public address of the line node that clients dial.
    pub server_address: String,
    /// Internal landing-node address reachable by the line node.
    pub landing_address: String,
    /// Firewall-restricted Handoff port on the landing node.
    pub landing_port: u16,
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

/// A generated Handoff deployment: line node, landing node, and Xray client.
#[derive(Debug)]
pub struct GeneratedHandoffConfigs {
    line: GeneratedConfig,
    landing: Config,
    client: serde_json::Value,
    client_uuid: String,
}

impl GeneratedHandoffConfigs {
    /// Returns the generated line-node configuration and its REALITY public key.
    #[must_use]
    pub const fn line(&self) -> &GeneratedConfig {
        &self.line
    }

    /// Returns the generated landing-node configuration.
    #[must_use]
    pub const fn landing(&self) -> &Config {
        &self.landing
    }

    /// Returns the generated Xray client configuration.
    #[must_use]
    pub const fn client(&self) -> &serde_json::Value {
        &self.client
    }

    /// Returns the generated client UUID.
    #[must_use]
    pub fn client_uuid(&self) -> &str {
        &self.client_uuid
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
        runtime: RuntimeConfig::default(),
    };
    validate_config(&config)?;
    Ok(GeneratedConfig {
        config,
        reality_public_key: public_key,
    })
}

/// Generates a public VLESS + REALITY + Vision line node routed to NXR.
///
/// Direct and blackhole outbounds are included for explicit per-UUID rules,
/// while NXR remains the generated user's default. NXR is never exposed as the
/// public client protocol.
///
/// # Errors
///
/// Returns an error when entropy is unavailable or any public or NXR setting
/// violates strict configuration invariants.
pub fn generate_line_config(
    input: GenerateLineConfigInput,
) -> Result<GeneratedConfig, GenerateConfigError> {
    let uuid = generate_uuid()?.to_string();
    let short_id = generate_short_id()?;
    let key_pair = generate_x25519_key_pair()?;
    let (private_key, public_key) = key_pair.into_parts();
    let config = Config {
        log: LogConfig::default(),
        assets: AssetsConfig::default(),
        dns: DnsConfig::default(),
        inbounds: vec![public_inbound(
            &input.public,
            uuid.clone(),
            short_id,
            private_key,
        )],
        outbounds: vec![
            OutboundConfig::Nxr {
                tag: "landing".to_owned(),
                settings: NxrSettings {
                    address: input.nxr_address,
                    port: input.nxr_port,
                    pre_shared_key: input.pre_shared_key,
                },
            },
            OutboundConfig::Direct {
                tag: "direct".to_owned(),
            },
            OutboundConfig::Blackhole {
                tag: "block".to_owned(),
                settings: BlackholeSettings::default(),
            },
        ],
        routing: RoutingConfig {
            domain_strategy: DnsStrategy::IpIfNonMatch,
            global_rules: Vec::new(),
            users: vec![UserPolicy {
                name: "landing-users".to_owned(),
                user_ids: vec![uuid],
                default_outbound: "landing".to_owned(),
                rules: Vec::new(),
            }],
        },
        policy: PolicyConfig::default(),
        runtime: RuntimeConfig::default(),
    };
    validate_config(&config)?;
    Ok(GeneratedConfig {
        config,
        reality_public_key: public_key,
    })
}

/// Generates a firewall-restricted internal NXR landing node.
///
/// The result contains no public VLESS listener and no REALITY/TLS settings.
/// Each authenticated NXR connection is switched directly to raw TCP relay.
///
/// # Errors
///
/// Returns an error when the listener or PSK violates strict configuration
/// invariants.
pub fn generate_landing_config(
    input: GenerateLandingConfigInput,
) -> Result<Config, GenerateConfigError> {
    let config = Config {
        log: LogConfig::default(),
        assets: AssetsConfig::default(),
        dns: DnsConfig::default(),
        inbounds: vec![InboundConfig::Nxr(NxrInboundConfig {
            tag: "internal-nxr".to_owned(),
            listen: input.listen,
            port: input.port,
            settings: NxrInboundSettings {
                pre_shared_key: input.pre_shared_key,
                max_time_difference_seconds: 30,
                max_nonce_entries: 65_536,
                nonce_retention_seconds: 120,
                authentication_timeout_ms: 3_000,
                connect_timeout_ms: 10_000,
            },
        })],
        outbounds: vec![OutboundConfig::Direct {
            tag: "direct".to_owned(),
        }],
        routing: RoutingConfig {
            domain_strategy: DnsStrategy::AsIs,
            global_rules: Vec::new(),
            users: Vec::new(),
        },
        policy: PolicyConfig::default(),
        runtime: RuntimeConfig::default(),
    };
    validate_config(&config)?;
    Ok(config)
}

/// Generates a Handoff deployment: a public line node that transfers every
/// accepted session to a firewall-restricted landing node, the landing node
/// itself, and the matching Xray client configuration.
///
/// Every piece of key material is generated independently: the REALITY
/// X25519 pair, the Handoff pre-shared key, and the landing node's static
/// X25519 pair. The landing listener binds the wildcard address; the port is
/// expected to be restricted to line-node addresses at the firewall. Direct
/// and blackhole outbounds are included for explicit per-UUID rules, while
/// the Handoff transfer remains the generated user's default.
///
/// # Errors
///
/// Returns an error when entropy is unavailable or any public or Handoff
/// setting violates strict configuration invariants.
pub fn generate_handoff_configs(
    input: GenerateHandoffConfigInput,
) -> Result<GeneratedHandoffConfigs, GenerateConfigError> {
    let uuid = generate_uuid()?.to_string();
    let short_id = generate_short_id()?;
    let (private_key, public_key) = generate_x25519_key_pair()?.into_parts();
    let pre_shared_key = generate_node_key()?;
    let (landing_private_key, landing_public_key) = generate_x25519_key_pair()?.into_parts();
    let line = Config {
        log: LogConfig::default(),
        assets: AssetsConfig::default(),
        dns: DnsConfig::default(),
        inbounds: vec![public_inbound(
            &input.public,
            uuid.clone(),
            short_id.clone(),
            private_key,
        )],
        outbounds: vec![
            OutboundConfig::Handoff {
                tag: "landing".to_owned(),
                settings: HandoffSettings {
                    address: input.landing_address,
                    port: input.landing_port,
                    pre_shared_key: pre_shared_key.clone(),
                    landing_public_key,
                    connect_timeout_ms: 10_000,
                    first_byte_timeout_ms: 15_000,
                },
            },
            OutboundConfig::Direct {
                tag: "direct".to_owned(),
            },
            OutboundConfig::Blackhole {
                tag: "block".to_owned(),
                settings: BlackholeSettings::default(),
            },
        ],
        routing: RoutingConfig {
            domain_strategy: DnsStrategy::IpIfNonMatch,
            global_rules: Vec::new(),
            users: vec![UserPolicy {
                name: "landing-users".to_owned(),
                user_ids: vec![uuid.clone()],
                default_outbound: "landing".to_owned(),
                rules: Vec::new(),
            }],
        },
        policy: PolicyConfig::default(),
        runtime: RuntimeConfig::default(),
    };
    validate_config(&line)?;
    let landing = Config {
        log: LogConfig::default(),
        assets: AssetsConfig::default(),
        dns: DnsConfig::default(),
        inbounds: vec![InboundConfig::Handoff(HandoffInboundConfig {
            tag: "internal-handoff".to_owned(),
            listen: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            port: input.landing_port,
            settings: HandoffInboundSettings {
                pre_shared_key,
                private_key: landing_private_key,
                max_time_difference_seconds: 30,
                max_nonce_entries: 65_536,
                nonce_retention_seconds: 120,
                authentication_timeout_ms: 3_000,
                connect_timeout_ms: 10_000,
                egress: None,
                previous_pre_shared_keys: Vec::new(),
                previous_private_keys: Vec::new(),
            },
        })],
        outbounds: vec![OutboundConfig::Direct {
            tag: "direct".to_owned(),
        }],
        routing: RoutingConfig {
            domain_strategy: DnsStrategy::AsIs,
            global_rules: Vec::new(),
            users: Vec::new(),
        },
        policy: PolicyConfig::default(),
        runtime: RuntimeConfig::default(),
    };
    validate_config(&landing)?;
    let client = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": 1080,
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": false },
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": { "vnext": [{
                "address": input.server_address,
                "port": input.public.port,
                "users": [{
                    "id": uuid.clone(),
                    "encryption": "none",
                    "flow": "xtls-rprx-vision",
                }],
            }]},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "fingerprint": "chrome",
                    "serverName": input.public.server_name,
                    "publicKey": public_key.clone(),
                    "shortId": short_id,
                    "spiderX": "/",
                },
            },
        }],
    });
    Ok(GeneratedHandoffConfigs {
        line: GeneratedConfig {
            config: line,
            reality_public_key: public_key,
        },
        landing,
        client,
        client_uuid: uuid,
    })
}

fn public_inbound(
    input: &GenerateConfigInput,
    uuid: String,
    short_id: String,
    private_key: SecretString,
) -> InboundConfig {
    InboundConfig::Vless(VlessInboundConfig {
        tag: "public-reality".to_owned(),
        listen: input.listen,
        port: input.port,
        settings: VlessInboundSettings {
            clients: vec![VlessClient {
                id: uuid,
                email: Some("default-user".to_owned()),
                flow: "xtls-rprx-vision".to_owned(),
            }],
            decryption: "none".to_owned(),
        },
        stream_settings: StreamSettings {
            network: Network::Tcp,
            security: "reality".to_owned(),
            reality_settings: RealityConfig {
                target: input.target.clone(),
                server_names: vec![input.server_name.clone()],
                private_key,
                short_ids: vec![short_id],
                max_time_diff_ms: 60_000,
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr};

    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::{
        GenerateConfigInput, GenerateHandoffConfigInput, GenerateLandingConfigInput,
        GenerateLineConfigInput, generate_handoff_configs, generate_landing_config,
        generate_line_config, generate_minimal_config,
    };
    use crate::config::{
        Config, InboundConfig, OutboundConfig, SecretString, format_config, load_config,
        validate_config,
    };

    fn assert_loadable_and_valid(config: &Config, name: &str) {
        let json = format_config(config).expect("configuration must serialize");
        let path = std::env::temp_dir().join(format!(
            "rust-reality-generated-{name}-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, json).expect("temporary configuration must be written");
        let loaded = load_config(&path).expect("generated configuration must load");
        std::fs::remove_file(&path).expect("temporary configuration must be removed");
        assert_eq!(&loaded, config);
        validate_config(&loaded).expect("generated configuration must validate");
    }

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

    #[test]
    fn line_template_keeps_reality_public_and_nxr_internal() {
        let generated = generate_line_config(GenerateLineConfigInput {
            public: GenerateConfigInput {
                listen: IpAddr::from_str("0.0.0.0").expect("address must parse"),
                port: 443,
                target: "www.example.com:443".to_owned(),
                server_name: "www.example.com".to_owned(),
            },
            nxr_address: "10.0.0.2".to_owned(),
            nxr_port: 7443,
            pre_shared_key: SecretString::new("IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"),
        })
        .expect("line generation must succeed");

        assert!(matches!(
            generated.config().inbounds[0],
            InboundConfig::Vless(_)
        ));
        assert!(matches!(
            generated.config().outbounds[0],
            OutboundConfig::Nxr { .. }
        ));
        assert_eq!(
            generated.config().routing.users[0].default_outbound,
            "landing"
        );
    }

    #[test]
    fn landing_template_exposes_only_nxr() {
        let config = generate_landing_config(GenerateLandingConfigInput {
            listen: IpAddr::from_str("10.0.0.2").expect("address must parse"),
            port: 7443,
            pre_shared_key: SecretString::new("IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"),
        })
        .expect("landing generation must succeed");
        let json = format_config(&config).expect("configuration must serialize");

        assert!(matches!(config.inbounds[0], InboundConfig::Nxr(_)));
        assert!(config.routing.users.is_empty());
        assert!(!json.contains("\"security\": \"reality\""));
        assert!(!json.contains("\"protocol\": \"vless\""));
        assert!(!json.contains("xtls-rprx-vision"));
    }

    #[test]
    fn handoff_templates_validate_with_independent_key_material() {
        let generated = generate_handoff_configs(GenerateHandoffConfigInput {
            public: GenerateConfigInput {
                listen: IpAddr::from_str("0.0.0.0").expect("address must parse"),
                port: 443,
                target: "cover.example.com:443".to_owned(),
                server_name: "cover.example.com".to_owned(),
            },
            server_address: "line.example.com".to_owned(),
            landing_address: "10.0.0.2".to_owned(),
            landing_port: 7_443,
        })
        .expect("handoff generation must succeed");
        let line = generated.line().config();
        let landing = generated.landing();
        assert_loadable_and_valid(line, "handoff-line");
        assert_loadable_and_valid(landing, "handoff-landing");

        // The line routes its user to the handoff outbound; the landing
        // exposes only the internal handoff listener.
        let InboundConfig::Vless(public) = &line.inbounds[0] else {
            panic!("line must keep the public VLESS inbound");
        };
        let OutboundConfig::Handoff {
            settings: line_handoff,
            ..
        } = &line.outbounds[0]
        else {
            panic!("line default outbound must be the handoff transfer");
        };
        assert_eq!(line.routing.users[0].default_outbound, "landing");
        let InboundConfig::Handoff(landing_inbound) = &landing.inbounds[0] else {
            panic!("landing must expose the handoff inbound");
        };
        assert!(landing.routing.users.is_empty());
        let landing_json = format_config(landing).expect("landing must serialize");
        assert!(!landing_json.contains("\"security\": \"reality\""));
        assert!(!landing_json.contains("xtls-rprx-vision"));

        // The pair shares exactly the Handoff PSK; every other key material
        // is generated independently.
        let reality = &public.stream_settings.reality_settings;
        assert_eq!(
            line_handoff.pre_shared_key, landing_inbound.settings.pre_shared_key,
            "the pair PSK must match on both sides"
        );
        assert_ne!(line_handoff.pre_shared_key, reality.private_key);
        assert_ne!(landing_inbound.settings.private_key, reality.private_key);
        assert_ne!(
            landing_inbound.settings.private_key,
            line_handoff.pre_shared_key
        );
        let landing_secret: [u8; 32] = BASE64_URL_SAFE_NO_PAD
            .decode(landing_inbound.settings.private_key.expose())
            .expect("landing private key must decode")
            .try_into()
            .expect("landing private key must be 32 bytes");
        let landing_public = PublicKey::from(&StaticSecret::from(landing_secret));
        assert_eq!(
            line_handoff.landing_public_key,
            BASE64_URL_SAFE_NO_PAD.encode(landing_public.as_bytes()),
            "the line must pin the landing's static public key"
        );

        // The client references the generated server identity exactly.
        let client = generated.client();
        let vnext = &client["outbounds"][0]["settings"]["vnext"][0];
        assert_eq!(vnext["address"], "line.example.com");
        assert_eq!(vnext["port"], 443);
        assert_eq!(
            vnext["users"][0]["id"].as_str(),
            Some(generated.client_uuid())
        );
        assert_eq!(generated.client_uuid(), public.settings.clients[0].id);
        let client_reality = &client["outbounds"][0]["streamSettings"]["realitySettings"];
        assert_eq!(
            client_reality["publicKey"].as_str(),
            Some(generated.line().reality_public_key())
        );
        assert_eq!(
            client_reality["shortId"].as_str(),
            Some(reality.short_ids[0].as_str())
        );
        assert_eq!(client_reality["serverName"], "cover.example.com");
    }
}
