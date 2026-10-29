//! The client role: local SOCKS5 / HTTP CONNECT inbound and REALITY LINEs.
//!
//! A client node terminates no public REALITY identity. It listens locally,
//! authenticates outbound to an entry, and relays application bytes through
//! VLESS + REALITY + Vision. Multiple LINEs may be grouped; selection races
//! authentication only and never migrates a committed session (ADR 0032).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{dns::DnsConfig, listener::ListenerConfig, log::LogConfig, runtime::RuntimeConfig};

/// A local client node.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClientConfig {
    /// Always `client`.
    pub role: ClientRole,
    /// Local SOCKS5 and/or HTTP CONNECT endpoints. Loopback-only; `protocol` defaults to socks5.
    pub listeners: Vec<ListenerConfig>,
    /// Authenticated LINEs to an entry. One or more; groups reference them by `tag`.
    pub lines: Vec<LineConfig>,
    /// Named LINE groups for selection. Absent means one implicit `default` group of all lines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_groups: Option<Vec<LineGroupConfig>>,
    /// Pre-commit selection timing. Absent uses sticky primary + 275 ms hedge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection: Option<LineSelectionConfig>,
    /// Name resolution for LINE addresses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfig>,
    /// Logging destination and retention.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<LogConfig>,
    /// Resource posture and expert limit overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<RuntimeConfig>,
}

/// The role tag of a client node.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientRole {
    /// The only accepted value.
    Client,
}

/// One REALITY-authenticated LINE to an entry.
#[derive(Clone, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LineConfig {
    /// Label for diagnostics and `lineGroups`. Required when `lineGroups` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// Entry host or IP without a scheme or port.
    pub address: String,
    /// Entry TCP port.
    pub port: u16,
    /// Authorized user UUID (canonical hyphenated form).
    pub id: String,
    /// Entry REALITY public key (URL-safe unpadded base64, 32 bytes).
    pub public_key: String,
    /// Short ID assigned to this user (even-length hex, 2..=16 characters).
    pub short_id: String,
    /// Server-accepted SNI / serverName.
    pub server_name: String,
    /// Browser ClientHello profile. Omission selects Chrome 156.0.8078.74.
    #[serde(default)]
    pub fingerprint: crate::protocol::reality::BrowserFingerprint,
    /// When true, UDP/443 is permitted under XUDP (stock `xtls-rprx-vision-udp443` policy).
    /// Wire Addons still carry `xtls-rprx-vision`. Default false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_udp_443: bool,
}

impl std::fmt::Debug for LineConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LineConfig")
            .field("tag", &self.tag)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

/// A named set of LINE tags used for sticky + hedge selection.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LineGroupConfig {
    /// Group name; listeners may set `lineGroup` to this value.
    pub name: String,
    /// LINE `tag` values, sticky-primary first. At least one; at most eight.
    pub lines: Vec<String>,
}

/// Timing for pre-commit LINE selection.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LineSelectionConfig {
    /// Milliseconds before starting the alternate while the primary is pending.
    /// Absent means 275.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hedge_ms: Option<u64>,
    /// Overall authentication budget in milliseconds. Absent means 15000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_minimal_single_line_client() {
        let json = r#"{
  "role": "client",
  "listeners": [{"port": 10808, "ipv4": "127.0.0.1"}],
  "lines": [{
    "address": "127.0.0.1",
    "port": 8443,
    "id": "11111111-1111-4111-8111-111111111111",
    "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "shortId": "0102030405060708",
    "serverName": "www.example.com"
  }]
}"#;
        let parsed: ClientConfig = serde_json::from_str(json).expect("parse");
        assert_eq!(parsed.role, ClientRole::Client);
        assert_eq!(parsed.listeners.len(), 1);
        assert_eq!(parsed.lines.len(), 1);
        assert_eq!(parsed.lines[0].port, 8443);
        assert_eq!(
            parsed.lines[0].fingerprint,
            crate::protocol::reality::BrowserFingerprint::Chrome
        );
        for name in ["chrome", "firefox"] {
            let explicit = json.replace(
                "\"port\": 8443,",
                &format!("\"port\": 8443, \"fingerprint\": \"{name}\","),
            );
            let config: ClientConfig = serde_json::from_str(&explicit).unwrap();
            assert_eq!(
                serde_json::to_value(&config).unwrap()["lines"][0]["fingerprint"],
                name
            );
        }
        for name in ["safari", "random", "hellofirefox_120", "Chrome", ""] {
            let explicit = json.replace(
                "\"port\": 8443,",
                &format!("\"port\": 8443, \"fingerprint\": \"{name}\","),
            );
            assert!(serde_json::from_str::<ClientConfig>(&explicit).is_err());
        }
    }

    #[test]
    fn parses_multi_line_group() {
        let json = r#"{
  "role": "client",
  "listeners": [{"port": 10808, "ipv4": "127.0.0.1", "lineGroup": "edge"}],
  "lines": [
    {"tag": "a", "address": "10.0.0.1", "port": 443,
     "id": "11111111-1111-4111-8111-111111111111",
     "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
     "shortId": "0102030405060708", "serverName": "www.example.com"},
    {"tag": "b", "address": "10.0.0.2", "port": 443,
     "id": "11111111-1111-4111-8111-111111111111",
     "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
     "shortId": "0102030405060708", "serverName": "www.example.com"}
  ],
  "lineGroups": [{"name": "edge", "lines": ["a", "b"]}],
  "selection": {"hedgeMs": 200, "timeoutMs": 10000}
}"#;
        let parsed: ClientConfig = serde_json::from_str(json).expect("parse");
        assert_eq!(parsed.lines.len(), 2);
        assert_eq!(parsed.line_groups.as_ref().unwrap()[0].name, "edge");
        assert_eq!(parsed.selection.as_ref().unwrap().hedge_ms, Some(200));
    }

    #[test]
    fn client_debug_omits_line_credentials_without_changing_serialization() {
        let mut first: ClientConfig = serde_json::from_value(serde_json::json!({
            "role": "client",
            "listeners": [{"port": 10808}],
            "lines": [{
                "tag": "line-a", "address": "private-entry.test", "port": 443,
                "id": "11111111-1111-4111-8111-111111111111",
                "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "shortId": "0102030405060708", "serverName": "private-cover.test"
            }]
        }))
        .unwrap();
        let mut second = first.clone();
        second.lines[0].id = "22222222-2222-4222-8222-222222222222".to_owned();
        second.lines[0].short_id = "1122334455667788".to_owned();
        second.lines[0].public_key = "another-public-key".to_owned();
        second.lines[0].address = "another-entry.test".to_owned();
        second.lines[0].server_name = "another-cover.test".to_owned();
        let diagnostic = format!("{first:?}");
        assert_eq!(diagnostic, format!("{second:?}"));
        assert!(!diagnostic.contains(&first.lines[0].id));
        assert!(!diagnostic.contains(&first.lines[0].short_id));
        assert!(!diagnostic.contains("private-"));
        assert!(diagnostic.contains("line-a"));
        assert!(diagnostic.contains("Chrome"));
        let serialized = serde_json::to_value(&first).unwrap();
        assert_eq!(serialized["lines"][0]["id"], first.lines[0].id);
        assert_eq!(serialized["lines"][0]["shortId"], first.lines[0].short_id);
        first.lines[0].fingerprint = crate::protocol::reality::BrowserFingerprint::Firefox;
        assert_ne!(diagnostic, format!("{first:?}"));
        assert!(format!("{first:?}").contains("Firefox"));
    }
}
