//! Strict JSON configuration loading, validation, and atomic publication.

mod io;
mod model;
mod snapshot;
mod validate;

pub use io::{ConfigLoadError, MAX_CONFIG_BYTES, format_config, load_config};
pub use model::{
    AssetsConfig, BlackholeSettings, Config, DirectBarrierConfig, DnsConfig, DnsStrategy,
    FileLogConfig, GlobalRule, InboundConfig, LogConfig, LogLevel, LogOutput, Network,
    NxrPoolConfig, NxrSettings, OutboundConfig, PolicyConfig, PortMatcher, RealityConfig,
    RelayPolicy, ResourceGovernorConfig, RouteRule, RoutingConfig, SecretString, Socks5Settings,
    StreamSettings, UserPolicy, VlessClient, VlessInboundSettings,
};
pub use snapshot::{ConfigSnapshot, ConfigStore, ConfigUpdateError};
pub use validate::{ConfigError, validate_config};

#[cfg(test)]
pub(crate) fn test_config_json() -> &'static str {
    r#"{
  "log": { "level": "info", "output": "stderr" },
  "assets": {
    "geoip": "geoip.dat",
    "geosite": "geosite.dat",
    "reloadIntervalSeconds": 300
  },
  "dns": {
    "strategy": "IPIfNonMatch",
    "servers": ["system"],
    "timeoutMs": 5000
  },
  "inbounds": [{
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
        "privateKey": "test-private-key",
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
