//! The entry role: a public node that terminates VLESS + REALITY + Vision.
//!
//! An entry node is what clients dial. It owns the REALITY identity, the user
//! list, and the routing decision. Whether it serves traffic itself or forwards
//! to a landing node is not a separate role — it is the outbound its routing
//! selects, which is why a standalone node and a line node have the same shape
//! and differ by a few lines.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    assets::AssetsConfig, dns::DnsConfig, listener::ListenerConfig, log::LogConfig,
    network::NetworkConfig, outbound::OutboundConfig, reality::RealityConfig,
    routing::RoutingConfig, runtime::RuntimeConfig, user::UserConfig,
};

/// A public entry node.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EntryConfig {
    /// Always `entry`.
    pub role: EntryRole,
    /// Public listening endpoints. Several endpoints share one REALITY
    /// identity.
    pub listeners: Vec<ListenerConfig>,
    /// REALITY identity and cover target.
    pub reality: RealityConfig,
    /// Authorized client identities.
    pub users: Vec<UserConfig>,
    /// Declared outbound transports, keyed by name.
    ///
    /// Absent means only the built-in `direct` and `block` outbounds exist,
    /// which is everything a standalone node needs.
    ///
    /// Declared above `routing` despite being optional, because that is the
    /// order it reads in: these names are what `routing` refers to, so the
    /// canonical form defines them before it uses them.
    #[serde(
        default,
        deserialize_with = "super::named::optional_unique_map",
        skip_serializing_if = "Option::is_none"
    )]
    pub outbounds: Option<BTreeMap<String, OutboundConfig>>,
    /// Where traffic goes.
    pub routing: RoutingConfig,
    /// GeoIP and GeoSite data. Consulted only when a routing rule names a
    /// `geoip:` or `geosite:` condition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assets: Option<AssetsConfig>,
    /// Name resolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfig>,
    /// Outbound address-family policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkConfig>,
    /// Logging destination and retention.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<LogConfig>,
    /// Resource posture and expert limit overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<RuntimeConfig>,
}

/// The role tag of an entry node.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryRole {
    /// The only accepted value.
    Entry,
}

impl EntryConfig {
    /// The declared outbounds, applying the empty default.
    pub fn outbounds(&self) -> impl Iterator<Item = (&String, &OutboundConfig)> {
        self.outbounds.iter().flat_map(BTreeMap::iter)
    }

    /// Returns whether `name` is a declared outbound.
    #[must_use]
    pub fn has_outbound(&self, name: &str) -> bool {
        self.outbounds
            .as_ref()
            .is_some_and(|outbounds| outbounds.contains_key(name))
    }

    /// Whether any routing rule names a `geoip:` or `geosite:` condition, and
    /// therefore whether geo assets are needed at all.
    #[must_use]
    pub fn needs_geo_assets(&self) -> bool {
        let rules = self.routing.rules().iter().chain(
            self.routing
                .policies()
                .flat_map(|(_, policy)| policy.rules()),
        );
        rules
            .flat_map(|rule| rule.domain().iter().chain(rule.ip()))
            .any(|matcher| matcher.starts_with("geoip:") || matcher.starts_with("geosite:"))
    }
}

#[cfg(test)]
mod tests {
    use super::EntryConfig;

    const MINIMAL: &str = r#"{
      "role": "entry",
      "listeners": [{ "port": 443 }],
      "reality": {
        "cover": "www.example.com:443",
        "privateKey": "k"
      },
      "users": [{ "id": "11111111-1111-4111-8111-111111111111", "shortIds": ["ab"] }],
      "routing": { "default": "direct" }
    }"#;

    fn parse(json: &str) -> EntryConfig {
        serde_json::from_str(json).expect("entry must decode")
    }

    #[test]
    fn a_standalone_node_declares_no_outbounds_and_needs_no_assets() {
        let entry = parse(MINIMAL);

        assert_eq!(entry.listeners.len(), 1);
        assert_eq!(entry.users.len(), 1);
        assert_eq!(entry.routing.default, "direct");
        assert_eq!(entry.outbounds().count(), 0);
        assert!(!entry.has_outbound("direct"), "built-ins are not declared");
        assert!(!entry.needs_geo_assets());
        assert!(entry.assets.is_none());
    }

    #[test]
    fn a_line_node_is_a_standalone_node_with_an_outbound_and_a_default() {
        let entry = parse(
            r#"{
              "role": "entry",
              "listeners": [{ "port": 443 }],
              "reality": { "cover": "www.example.com:443", "privateKey": "k" },
              "users": [{ "id": "u", "shortIds": ["ab"] }],
              "outbounds": {
                "landing-1": { "type": "handoff", "address": "10.0.0.2", "port": 7443,
                               "psk": "k2", "landingPublicKey": "p" }
              },
              "routing": { "default": "landing-1" }
            }"#,
        );

        assert!(entry.has_outbound("landing-1"));
        assert_eq!(entry.routing.default, "landing-1");
        assert_eq!(entry.outbounds().count(), 1);
    }

    #[test]
    fn geo_conditions_are_detected_in_global_rules_and_in_policies() {
        let plain = parse(
            r#"{"role":"entry","listeners":[{"port":443}],
                "reality":{"cover":"a:443","privateKey":"k"},
                "users":[{"id":"u","shortIds":["ab"]}],
                "routing":{"default":"direct",
                           "rules":[{"ip":["10.0.0.0/8"],"outbound":"block"}]}}"#,
        );
        assert!(!plain.needs_geo_assets(), "CIDR rules need no geo data");

        let global = parse(
            r#"{"role":"entry","listeners":[{"port":443}],
                "reality":{"cover":"a:443","privateKey":"k"},
                "users":[{"id":"u","shortIds":["ab"]}],
                "routing":{"default":"direct",
                           "rules":[{"ip":["geoip:private"],"outbound":"block"}]}}"#,
        );
        assert!(global.needs_geo_assets());

        let in_policy = parse(
            r#"{"role":"entry","listeners":[{"port":443}],
                "reality":{"cover":"a:443","privateKey":"k"},
                "users":[{"id":"u","shortIds":["ab"]}],
                "routing":{"default":"direct",
                           "policies":{"split":{"default":"direct",
                             "rules":[{"domain":["geosite:cn"],"outbound":"direct"}]}}}}"#,
        );
        assert!(
            in_policy.needs_geo_assets(),
            "a policy rule counts just as much as a global rule"
        );
    }

    #[test]
    fn the_removed_top_level_sections_are_rejected() {
        for section in [
            r#""inbounds":[]"#,
            r#""advanced":{}"#,
            r#""landing":{"protocol":"nxr","psk":"k"}"#,
            r#""egress":"direct""#,
        ] {
            let json = format!(
                r#"{{"role":"entry","listeners":[{{"port":443}}],
                     "reality":{{"cover":"a:443","privateKey":"k"}},
                     "users":[{{"id":"u","shortIds":["ab"]}}],
                     "routing":{{"default":"direct"}},{section}}}"#
            );
            assert!(
                serde_json::from_str::<EntryConfig>(&json).is_err(),
                "an entry node has no {section}"
            );
        }
    }

    #[test]
    fn every_load_bearing_section_is_required() {
        // Each case is the minimal node with exactly one section removed.
        for (missing, json) in [
            (
                "listeners",
                r#"{"role":"entry","reality":{"cover":"a:443","privateKey":"k"},
                    "users":[{"id":"u","shortIds":["ab"]}],"routing":{"default":"direct"}}"#,
            ),
            (
                "reality",
                r#"{"role":"entry","listeners":[{"port":443}],
                    "users":[{"id":"u","shortIds":["ab"]}],"routing":{"default":"direct"}}"#,
            ),
            (
                "users",
                r#"{"role":"entry","listeners":[{"port":443}],
                    "reality":{"cover":"a:443","privateKey":"k"},"routing":{"default":"direct"}}"#,
            ),
            (
                "routing",
                r#"{"role":"entry","listeners":[{"port":443}],
                    "reality":{"cover":"a:443","privateKey":"k"},
                    "users":[{"id":"u","shortIds":["ab"]}]}"#,
            ),
            (
                "role",
                r#"{"listeners":[{"port":443}],
                    "reality":{"cover":"a:443","privateKey":"k"},
                    "users":[{"id":"u","shortIds":["ab"]}],"routing":{"default":"direct"}}"#,
            ),
        ] {
            assert!(
                serde_json::from_str::<EntryConfig>(json).is_err(),
                "a node without {missing} must not parse"
            );
        }
    }
}
