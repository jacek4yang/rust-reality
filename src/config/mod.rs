//! Strict JSON configuration loading and validation.

mod generate;
mod io;
mod model;
mod schema;
mod validate;

pub use generate::{
    GenerateConfigError, GenerateConfigInput, GenerateLandingConfigInput, GenerateLineConfigInput,
    GeneratedConfig, generate_landing_config, generate_line_config, generate_minimal_config,
};
pub use io::{ConfigLoadError, MAX_CONFIG_BYTES, format_config, load_config};
pub use model::{
    AssetsConfig, BlackholeSettings, Config, DirectBarrierConfig, DnsConfig, DnsStrategy,
    FileLogConfig, GlobalRule, InboundConfig, LogConfig, LogLevel, LogOutput, Network,
    NxrInboundConfig, NxrInboundSettings, NxrSettings, OutboundConfig, PolicyConfig, PortMatcher,
    RealityConfig, RelayPolicy, ResourceGovernorConfig, ResourceMode, RouteRule, RoutingConfig,
    RuntimeConfig, SecretString, Socks5Settings, StreamSettings, UserPolicy, VlessClient,
    VlessInboundConfig, VlessInboundSettings,
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
  "inbounds": [{
    "protocol": "vless",
    "tag": "public-reality",
    "listen": "0.0.0.0",
    "port": 443,
    "settings": {
      "clients": [{
        "id": "11111111-1111-4111-8111-111111111111",
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
        "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE",
        "shortIds": ["0123456789abcdef"]
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
