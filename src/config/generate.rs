use std::net::IpAddr;

use serde_json::json;

use super::{
    AdvancedConfig, AssetsConfig, BlackholeSettings, Config, ConfigError, CoverOptimizationConfig,
    DnsConfig, DnsStrategy, HandoffInboundConfig, HandoffInboundSettings, HandoffSettings,
    InboundConfig, LogConfig, Network, NetworkConfig, NxrInboundConfig, NxrInboundSettings,
    NxrSettings, OutboundConfig, RealityConfig, RoutingConfig, RuntimeConfig, SecretString,
    StreamSettings, UserPolicy, VlessClient, VlessInboundConfig, VlessInboundSettings,
    validate_config,
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

/// One landing node of a generated multi-landing Handoff deployment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffLandingInput {
    /// Internal landing-node address reachable by the line node.
    pub address: String,
    /// Firewall-restricted Handoff port on the landing node.
    pub port: u16,
}

/// Inputs for a Handoff line node with one or more landing nodes, plus its
/// Xray client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerateMultiHandoffConfigInput {
    /// Public VLESS + REALITY + Vision listener settings of the line node.
    pub public: GenerateConfigInput,
    /// Public address of the line node that clients dial.
    pub server_address: String,
    /// Landing nodes the line transfers to, in `landing-N` order.
    pub landings: Vec<HandoffLandingInput>,
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

/// A generated multi-landing Handoff deployment: one line node, one
/// configuration per landing node, and the Xray client.
#[derive(Debug)]
pub struct GeneratedMultiHandoffConfigs {
    line: GeneratedConfig,
    landings: Vec<Config>,
    client: serde_json::Value,
    client_uuid: String,
}

impl GeneratedMultiHandoffConfigs {
    /// Returns the generated line-node configuration and its REALITY public key.
    #[must_use]
    pub const fn line(&self) -> &GeneratedConfig {
        &self.line
    }

    /// Returns the generated landing-node configurations, in `landing-N` order.
    #[must_use]
    pub fn landings(&self) -> &[Config] {
        &self.landings
    }

    /// Returns the generated Xray client configuration.
    #[must_use]
    pub const fn client(&self) -> &serde_json::Value {
        &self.client
    }

    /// Returns the generated client UUID (the first landing's group).
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
    let short_ids = generate_client_short_ids()?;
    let key_pair = generate_x25519_key_pair()?;
    let (private_key, public_key) = key_pair.into_parts();
    let config = Config {
        log: LogConfig::default(),
        assets: AssetsConfig::default(),
        dns: DnsConfig::default(),
        network: NetworkConfig::default(),
        inbounds: vec![InboundConfig::Vless(VlessInboundConfig {
            tag: "public-reality".to_owned(),
            listen: input.listen.into(),
            port: input.port,
            settings: VlessInboundSettings {
                clients: vec![VlessClient {
                    id: uuid.clone(),
                    short_ids,
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
                    max_time_diff_ms: 60_000,
                    cover_optimization: CoverOptimizationConfig::default(),
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
        advanced: AdvancedConfig::default(),
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
    let short_ids = generate_client_short_ids()?;
    let key_pair = generate_x25519_key_pair()?;
    let (private_key, public_key) = key_pair.into_parts();
    let config = Config {
        log: LogConfig::default(),
        assets: AssetsConfig::default(),
        dns: DnsConfig::default(),
        network: NetworkConfig::default(),
        inbounds: vec![public_inbound(
            &input.public,
            uuid.clone(),
            short_ids,
            private_key,
        )],
        outbounds: vec![
            OutboundConfig::Nxr {
                tag: "landing".to_owned(),
                settings: NxrSettings {
                    address: input.nxr_address,
                    port: input.nxr_port,
                    pre_shared_key: input.pre_shared_key,
                    warm_tcp: true,
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
        advanced: AdvancedConfig::default(),
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
        network: NetworkConfig::default(),
        inbounds: vec![InboundConfig::Nxr(NxrInboundConfig {
            tag: "internal-nxr".to_owned(),
            listen: input.listen.into(),
            port: input.port,
            settings: NxrInboundSettings {
                pre_shared_key: input.pre_shared_key,
                max_time_difference_seconds: 30,
                max_nonce_entries: 65_536,
                nonce_retention_seconds: 120,
                pre_auth_idle_timeout_ms: 60_000,
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
        advanced: AdvancedConfig::default(),
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
    let generated = generate_multi_handoff_configs(GenerateMultiHandoffConfigInput {
        public: input.public,
        server_address: input.server_address,
        landings: vec![HandoffLandingInput {
            address: input.landing_address,
            port: input.landing_port,
        }],
    })?;
    let GeneratedMultiHandoffConfigs {
        line,
        landings,
        client,
        client_uuid,
    } = generated;
    let [landing] = landings
        .try_into()
        .expect("single-landing generation produces exactly one landing");
    Ok(GeneratedHandoffConfigs {
        line,
        landing,
        client,
        client_uuid,
    })
}

/// Generates a multi-landing Handoff deployment: one public line node whose
/// accepted sessions are transferred to one of several firewall-restricted
/// landing nodes, one configuration per landing node, and the matching Xray
/// client configuration.
///
/// The line node carries one VLESS UUID per landing and routes each UUID's
/// own group to that landing's handoff outbound (`landing-1`, `landing-2`,
/// ...). Every landing pair gets independent key material: its own Handoff
/// pre-shared key and static X25519 pair, generated fresh per landing. A
/// single landing keeps the unnumbered `landing` tag, `landing-users` group,
/// and `default-user` email of [`generate_handoff_configs`]. The Xray client
/// references the first UUID only; assigning further UUIDs to clients is an
/// operator choice.
///
/// # Errors
///
/// Returns an error when the landing list is empty, when entropy is
/// unavailable, or when any public or Handoff setting violates strict
/// configuration invariants. Every emitted server configuration is validated
/// before it is returned.
pub fn generate_multi_handoff_configs(
    input: GenerateMultiHandoffConfigInput,
) -> Result<GeneratedMultiHandoffConfigs, GenerateConfigError> {
    if input.landings.is_empty() {
        return Err(ConfigError::new("landings", "must contain at least one landing node").into());
    }
    let multi = input.landings.len() > 1;
    let (private_key, public_key) = generate_x25519_key_pair()?.into_parts();

    let mut uuids = Vec::with_capacity(input.landings.len());
    let mut client_short_ids = Vec::with_capacity(input.landings.len());
    let mut handoff_outbounds = Vec::with_capacity(input.landings.len());
    let mut landing_material = Vec::with_capacity(input.landings.len());
    for (index, landing) in input.landings.iter().enumerate() {
        let pre_shared_key = generate_node_key()?;
        let (landing_private_key, landing_public_key) = generate_x25519_key_pair()?.into_parts();
        handoff_outbounds.push(OutboundConfig::Handoff {
            tag: handoff_tag(index, multi),
            settings: HandoffSettings {
                address: landing.address.clone(),
                port: landing.port,
                pre_shared_key: pre_shared_key.clone(),
                landing_public_key,
                connect_timeout_ms: 10_000,
                first_byte_timeout_ms: 15_000,
                warm_tcp: true,
            },
        });
        landing_material.push((landing.port, pre_shared_key, landing_private_key));
        uuids.push(generate_uuid()?.to_string());
        client_short_ids.push(generate_client_short_ids()?);
    }

    let clients = uuids
        .iter()
        .enumerate()
        .map(|(index, uuid)| VlessClient {
            id: uuid.clone(),
            short_ids: client_short_ids[index].clone(),
            email: Some(handoff_email(index, multi)),
            flow: "xtls-rprx-vision".to_owned(),
        })
        .collect();
    let users = uuids
        .iter()
        .enumerate()
        .map(|(index, uuid)| UserPolicy {
            name: handoff_user_group(index, multi),
            user_ids: vec![uuid.clone()],
            default_outbound: handoff_tag(index, multi),
            rules: Vec::new(),
        })
        .collect();
    let mut outbounds = handoff_outbounds;
    outbounds.push(OutboundConfig::Direct {
        tag: "direct".to_owned(),
    });
    outbounds.push(OutboundConfig::Blackhole {
        tag: "block".to_owned(),
        settings: BlackholeSettings::default(),
    });
    let line = Config {
        log: LogConfig::default(),
        assets: AssetsConfig::default(),
        dns: DnsConfig::default(),
        network: NetworkConfig::default(),
        inbounds: vec![public_inbound_with_clients(
            &input.public,
            clients,
            private_key,
        )],
        outbounds,
        routing: RoutingConfig {
            domain_strategy: DnsStrategy::IpIfNonMatch,
            global_rules: Vec::new(),
            users,
        },
        advanced: AdvancedConfig::default(),
        runtime: RuntimeConfig::default(),
    };
    validate_config(&line)?;

    let mut landings = Vec::with_capacity(landing_material.len());
    for (port, pre_shared_key, landing_private_key) in landing_material {
        let landing = handoff_landing_config(port, pre_shared_key, landing_private_key);
        validate_config(&landing)?;
        landings.push(landing);
    }

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
                    "id": uuids[0].clone(),
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
                    "shortId": client_short_ids[0][0].clone(),
                    "spiderX": "/",
                },
            },
        }],
    });
    Ok(GeneratedMultiHandoffConfigs {
        line: GeneratedConfig {
            config: line,
            reality_public_key: public_key,
        },
        landings,
        client,
        client_uuid: uuids[0].clone(),
    })
}

/// Single-landing deployments keep the historical unnumbered names; numbered
/// names appear only from the second landing onward.
fn handoff_tag(index: usize, multi: bool) -> String {
    if multi {
        format!("landing-{}", index + 1)
    } else {
        "landing".to_owned()
    }
}

fn handoff_user_group(index: usize, multi: bool) -> String {
    if multi {
        format!("landing-{}-users", index + 1)
    } else {
        "landing-users".to_owned()
    }
}

fn handoff_email(index: usize, multi: bool) -> String {
    if multi {
        format!("default-user-{}", index + 1)
    } else {
        "default-user".to_owned()
    }
}

fn handoff_landing_config(
    port: u16,
    pre_shared_key: SecretString,
    landing_private_key: SecretString,
) -> Config {
    Config {
        log: LogConfig::default(),
        assets: AssetsConfig::default(),
        dns: DnsConfig::default(),
        network: NetworkConfig::default(),
        inbounds: vec![InboundConfig::Handoff(HandoffInboundConfig {
            tag: "internal-handoff".to_owned(),
            listen: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED).into(),
            port,
            settings: HandoffInboundSettings {
                pre_shared_key,
                private_key: landing_private_key,
                max_time_difference_seconds: 30,
                max_nonce_entries: 65_536,
                nonce_retention_seconds: 120,
                pre_auth_idle_timeout_ms: 60_000,
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
        advanced: AdvancedConfig::default(),
        runtime: RuntimeConfig::default(),
    }
}

fn public_inbound(
    input: &GenerateConfigInput,
    uuid: String,
    short_ids: Vec<String>,
    private_key: SecretString,
) -> InboundConfig {
    public_inbound_with_clients(
        input,
        vec![VlessClient {
            id: uuid,
            short_ids,
            email: Some("default-user".to_owned()),
            flow: "xtls-rprx-vision".to_owned(),
        }],
        private_key,
    )
}

fn public_inbound_with_clients(
    input: &GenerateConfigInput,
    clients: Vec<VlessClient>,
    private_key: SecretString,
) -> InboundConfig {
    InboundConfig::Vless(VlessInboundConfig {
        tag: "public-reality".to_owned(),
        listen: input.listen.into(),
        port: input.port,
        settings: VlessInboundSettings {
            clients,
            decryption: "none".to_owned(),
        },
        stream_settings: StreamSettings {
            network: Network::Tcp,
            security: "reality".to_owned(),
            reality_settings: RealityConfig {
                target: input.target.clone(),
                server_names: vec![input.server_name.clone()],
                private_key,
                max_time_diff_ms: 60_000,
                cover_optimization: CoverOptimizationConfig::default(),
            },
        },
    })
}

/// Generates two independent short IDs for one UUID. The spare value supports
/// staged client rotation while preserving exclusive UUID ownership.
fn generate_client_short_ids() -> Result<Vec<String>, KeyGenerationError> {
    let first = generate_short_id()?;
    let mut second = generate_short_id()?;
    while second.eq_ignore_ascii_case(&first) {
        second = generate_short_id()?;
    }
    Ok(vec![first, second])
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, net::IpAddr, str::FromStr};

    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::{
        GenerateConfigInput, GenerateHandoffConfigInput, GenerateLandingConfigInput,
        GenerateLineConfigInput, GenerateMultiHandoffConfigInput, HandoffLandingInput,
        generate_handoff_configs, generate_landing_config, generate_line_config,
        generate_minimal_config, generate_multi_handoff_configs,
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
        assert!(json.contains("\"dial\""));
        assert!(json.contains("\"mode\": \"auto\""));
        assert!(json.contains("\"ipv4\": \"0.0.0.0\""));
        assert!(json.contains("\"ipv6\": \"::\""));
        assert!(!json.contains("addressFamily"));
        assert_eq!(generated.reality_public_key().len(), 43);
        let public = generated.config().inbounds[0]
            .as_vless()
            .expect("generated inbound must be VLESS");
        assert_eq!(public.settings.clients[0].short_ids.len(), 2);
        assert_ne!(
            public.settings.clients[0].short_ids[0],
            public.settings.clients[0].short_ids[1]
        );

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
        assert_eq!(public.settings.clients[0].short_ids.len(), 2);
        let client_reality = &client["outbounds"][0]["streamSettings"]["realitySettings"];
        assert_eq!(
            client_reality["publicKey"].as_str(),
            Some(generated.line().reality_public_key())
        );
        assert_eq!(
            client_reality["shortId"].as_str(),
            Some(public.settings.clients[0].short_ids[0].as_str())
        );
        assert_eq!(client_reality["serverName"], "cover.example.com");
    }

    #[test]
    fn multi_handoff_templates_validate_with_independent_key_material() {
        let generated = generate_multi_handoff_configs(GenerateMultiHandoffConfigInput {
            public: GenerateConfigInput {
                listen: IpAddr::from_str("0.0.0.0").expect("address must parse"),
                port: 443,
                target: "cover.example.com:443".to_owned(),
                server_name: "cover.example.com".to_owned(),
            },
            server_address: "line.example.com".to_owned(),
            landings: vec![
                HandoffLandingInput {
                    address: "10.0.0.2".to_owned(),
                    port: 7_443,
                },
                HandoffLandingInput {
                    address: "10.0.0.3".to_owned(),
                    port: 8_443,
                },
            ],
        })
        .expect("multi-landing generation must succeed");
        let line = generated.line().config();
        assert_loadable_and_valid(line, "multi-handoff-line");
        assert_eq!(generated.landings().len(), 2);
        for (index, landing) in generated.landings().iter().enumerate() {
            assert_loadable_and_valid(landing, &format!("multi-handoff-landing-{}", index + 1));
        }

        // One UUID per landing, each routed by its own first-class group to
        // that landing's numbered handoff outbound.
        let InboundConfig::Vless(public) = &line.inbounds[0] else {
            panic!("line must keep the public VLESS inbound");
        };
        assert_eq!(public.settings.clients.len(), 2);
        let short_ids = public
            .settings
            .clients
            .iter()
            .flat_map(|client| {
                client
                    .short_ids
                    .iter()
                    .map(|value| value.to_ascii_lowercase())
            })
            .collect::<HashSet<_>>();
        assert_eq!(short_ids.len(), 4, "each UUID must own two unique IDs");
        assert!(
            public
                .settings
                .clients
                .iter()
                .all(|client| client.short_ids.len() == 2)
        );
        let mut handoff_settings = Vec::new();
        for index in 0..2 {
            let tag = format!("landing-{}", index + 1);
            let OutboundConfig::Handoff {
                tag: outbound_tag,
                settings,
            } = &line.outbounds[index]
            else {
                panic!("line outbound {index} must be the handoff transfer");
            };
            assert_eq!(outbound_tag, &tag);
            let group = &line.routing.users[index];
            assert_eq!(group.name, format!("landing-{}-users", index + 1));
            assert_eq!(group.default_outbound, tag);
            assert_eq!(
                group.user_ids,
                vec![public.settings.clients[index].id.clone()]
            );
            handoff_settings.push(settings);
        }

        // Each landing pair shares exactly its own Handoff PSK, and every
        // other piece of key material is independent across ALL emitted files.
        let reality = &public.stream_settings.reality_settings;
        let mut landing_inbounds = Vec::new();
        for landing in generated.landings() {
            let InboundConfig::Handoff(inbound) = &landing.inbounds[0] else {
                panic!("landing must expose the handoff inbound");
            };
            landing_inbounds.push(inbound);
        }
        for (settings, inbound) in handoff_settings.iter().zip(&landing_inbounds) {
            assert_eq!(
                settings.pre_shared_key, inbound.settings.pre_shared_key,
                "the pair PSK must match on both sides"
            );
        }
        let first = handoff_settings[0];
        let second = handoff_settings[1];
        assert_ne!(first.pre_shared_key, second.pre_shared_key);
        assert_ne!(
            landing_inbounds[0].settings.private_key,
            landing_inbounds[1].settings.private_key
        );
        assert_ne!(
            first.pre_shared_key, landing_inbounds[1].settings.pre_shared_key,
            "landing pairs must not share key material across files"
        );
        for settings in [&first, &second] {
            assert_ne!(settings.pre_shared_key, reality.private_key);
        }
        for inbound in &landing_inbounds {
            assert_ne!(inbound.settings.private_key, reality.private_key);
        }
        for (settings, inbound) in handoff_settings.iter().zip(&landing_inbounds) {
            let landing_secret: [u8; 32] = BASE64_URL_SAFE_NO_PAD
                .decode(inbound.settings.private_key.expose())
                .expect("landing private key must decode")
                .try_into()
                .expect("landing private key must be 32 bytes");
            let landing_public = PublicKey::from(&StaticSecret::from(landing_secret));
            assert_eq!(
                settings.landing_public_key,
                BASE64_URL_SAFE_NO_PAD.encode(landing_public.as_bytes()),
                "the line must pin each landing's static public key"
            );
        }

        // The client references the first landing's UUID only.
        assert_eq!(generated.client_uuid(), public.settings.clients[0].id);
        let vnext = &generated.client()["outbounds"][0]["settings"]["vnext"][0];
        assert_eq!(
            vnext["users"][0]["id"].as_str(),
            Some(generated.client_uuid())
        );
    }

    #[test]
    fn multi_handoff_requires_at_least_one_landing() {
        let error = generate_multi_handoff_configs(GenerateMultiHandoffConfigInput {
            public: GenerateConfigInput {
                listen: IpAddr::from_str("0.0.0.0").expect("address must parse"),
                port: 443,
                target: "cover.example.com:443".to_owned(),
                server_name: "cover.example.com".to_owned(),
            },
            server_address: "line.example.com".to_owned(),
            landings: Vec::new(),
        })
        .expect_err("an empty landing list must fail");
        assert!(error.to_string().contains("at least one landing"));
    }
}
