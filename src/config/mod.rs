//! Strict JSON configuration loading and validation.

mod generate;
mod io;
mod model;
mod schema;
mod validate;

pub use generate::{
    GenerateConfigError, GenerateConfigInput, GenerateHandoffConfigInput,
    GenerateLandingConfigInput, GenerateLineConfigInput, GenerateMultiHandoffConfigInput,
    GeneratedConfig, GeneratedHandoffConfigs, GeneratedMultiHandoffConfigs, HandoffLandingInput,
    generate_handoff_configs, generate_landing_config, generate_line_config,
    generate_minimal_config, generate_multi_handoff_configs,
};
pub use io::{
    ConfigLoadError, ConfigLoadReport, MAX_CONFIG_BYTES, format_config, load_config,
    load_config_with_report,
};
pub use model::{
    AdvancedConfig, AssetsConfig, BlackholeSettings, Config, DialConfig, DialMode,
    DirectBarrierConfig, DnsCacheConfig, DnsConfig, DnsStrategy, FileLogConfig, GlobalRule,
    HandoffInboundConfig, HandoffInboundSettings, HandoffSettings, InboundConfig, ListenConfig,
    ListenMode, LogConfig, LogLevel, LogOutput, Network, NetworkConfig, NxrInboundConfig,
    NxrInboundSettings, NxrSettings, Objective, OutboundConfig, PolicyConfig, PortMatcher,
    RealityConfig, RelayPolicy, ResourceGovernorConfig, ResourceMode, RouteRule, RoutingConfig,
    RuntimeConfig, RuntimeProfile, SecretString, Socks5Settings, StreamSettings, TuningConfig,
    TuningMode, UserPolicy, VlessClient, VlessInboundConfig, VlessInboundSettings,
};
pub use schema::{config_schema, format_config_schema};
pub use validate::{ConfigError, validate_config};

#[cfg(test)]
pub(crate) fn test_config_json() -> &'static str {
    r#"{
  "log": { "level": "info", "output": "stderr" },
  "assets": {
    "geoip": "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat",
    "geosite": "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat",
    "cacheDirectory": "/var/lib/rust-reality/assets",
    "reloadIntervalSeconds": 300
  },
  "dns": {
    "servers": ["system"],
    "timeoutMs": 5000
  },
  "network": {
    "dial": {
      "mode": "auto",
      "fallbackDelayMs": 250,
      "routeRefreshSeconds": 30,
      "hardFailurePenaltySeconds": 30,
      "latencyMemorySeconds": 300
    }
  },
  "inbounds": [{
    "protocol": "vless",
    "tag": "public-reality",
    "listen": { "mode": "auto", "ipv4": "0.0.0.0", "ipv6": "::" },
    "port": 443,
    "settings": {
      "clients": [{
        "id": "11111111-1111-4111-8111-111111111111",
        "shortIds": ["0123456789abcdef", "1023456789abcdef"],
        "email": "test-user",
        "flow": "xtls-rprx-vision"
      }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "target": "www.example.com:443",
        "serverNames": ["www.example.com"],
        "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE"
      }
    }
  }],
  "outbounds": [
    { "protocol": "direct", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block", "settings": {} }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "globalRules": [{
      "name": "block-private",
      "outbound": "block",
      "ip": ["geoip:private"]
    }],
    "users": [{
      "name": "direct-users",
      "userIds": ["11111111-1111-4111-8111-111111111111"],
      "defaultOutbound": "direct",
      "rules": []
    }]
  },
  "policy": {}
}"#
}
