//! The operator-facing configuration model.
//!
//! One node, one role. `role` is the first thing in the file and it decides
//! which sections exist: an `entry` node has a REALITY identity, users, and
//! routing; a `landing` node has an internal protocol and one egress. Neither
//! shape can express the other, so a configuration that mixes them fails on
//! the offending field rather than starting a server that is half of each.
//!
//! Every field with a default is an `Option`. Nothing here applies a default
//! during deserialization, because the difference between "the operator wrote
//! the default" and "the operator wrote nothing" is real information: it is
//! what lets `explain` report provenance exactly and `format` reproduce a file
//! without inventing content. Accessors named after their field apply the
//! documented default; [`crate::config::semantics`] turns a parsed node into a
//! validated one.
//!
//! Module layout follows the configuration sections, so a change to DNS
//! handling is a change to one small file.

pub mod assets;
pub mod dns;
pub mod entry;
pub mod landing;
pub mod listener;
pub mod log;
mod named;
pub mod network;
pub mod outbound;
pub mod reality;
pub mod routing;
pub mod runtime;
pub mod user;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use entry::{EntryConfig, EntryRole};
pub use landing::{LandingConfig, LandingProtocol, LandingRole, LandingTiming};
pub use listener::{ListenFamily, ListenerConfig};
pub use outbound::{BUILTIN_BLOCK, BUILTIN_DIRECT, OutboundConfig, is_builtin_outbound};
pub use routing::{DomainStrategy, RoutePolicy, RouteRule, RoutingConfig};
pub use user::UserConfig;

/// One node's configuration.
///
/// This enum is never derived through serde's tagged-enum support. Internal
/// tagging buffers the whole document before dispatching, which costs the
/// source spans the diagnostics depend on and degrades the field paths
/// `serde_path_to_error` reports. [`crate::config::parse`] reads `role` in a
/// cheap first pass and then deserializes the document directly into the
/// matching type, so every field keeps an exact path and an exact span.
#[derive(Clone, Debug, Eq, PartialEq, JsonSchema, Serialize)]
#[serde(untagged)]
pub enum NodeConfig {
    /// A public node that terminates VLESS + REALITY + Vision.
    Entry(Box<EntryConfig>),
    /// A firewall-restricted node that terminates an internal transfer.
    Landing(Box<LandingConfig>),
}

impl NodeConfig {
    /// The role this node performs.
    #[must_use]
    pub const fn role(&self) -> Role {
        match self {
            Self::Entry(_) => Role::Entry,
            Self::Landing(_) => Role::Landing,
        }
    }

    /// The entry configuration, when this node is an entry node.
    #[must_use]
    pub fn as_entry(&self) -> Option<&EntryConfig> {
        match self {
            Self::Entry(entry) => Some(entry),
            Self::Landing(_) => None,
        }
    }

    /// The landing configuration, when this node is a landing node.
    #[must_use]
    pub fn as_landing(&self) -> Option<&LandingConfig> {
        match self {
            Self::Landing(landing) => Some(landing),
            Self::Entry(_) => None,
        }
    }

    /// The listening endpoints, whichever role this is.
    #[must_use]
    pub fn listeners(&self) -> &[ListenerConfig] {
        match self {
            Self::Entry(entry) => &entry.listeners,
            Self::Landing(landing) => &landing.listeners,
        }
    }

    /// The resource posture, applying the defaults for an omitted section.
    #[must_use]
    pub fn runtime(&self) -> runtime::RuntimeConfig {
        let configured = match self {
            Self::Entry(entry) => entry.runtime.as_ref(),
            Self::Landing(landing) => landing.runtime.as_ref(),
        };
        configured.cloned().unwrap_or_default()
    }

    /// The logging settings, applying the defaults for an omitted section.
    #[must_use]
    pub fn log(&self) -> log::LogConfig {
        let configured = match self {
            Self::Entry(entry) => entry.log.as_ref(),
            Self::Landing(landing) => landing.log.as_ref(),
        };
        configured.cloned().unwrap_or_default()
    }

    /// The outbound dial policy, applying the defaults for an omitted section.
    #[must_use]
    pub fn network(&self) -> network::NetworkConfig {
        let configured = match self {
            Self::Entry(entry) => entry.network.as_ref(),
            Self::Landing(landing) => landing.network.as_ref(),
        };
        configured.copied().unwrap_or_default()
    }

    /// Name resolution, applying the defaults for an omitted section.
    #[must_use]
    pub fn dns(&self) -> dns::DnsConfig {
        let configured = match self {
            Self::Entry(entry) => entry.dns.as_ref(),
            Self::Landing(landing) => landing.dns.as_ref(),
        };
        configured.cloned().unwrap_or_default()
    }
}

/// Which role a node performs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// A public node that terminates VLESS + REALITY + Vision.
    Entry,
    /// A firewall-restricted node that terminates an internal transfer.
    Landing,
}

impl Role {
    /// The stable name used in configuration, logs, and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Entry => "entry",
            Self::Landing => "landing",
        }
    }

    /// Every role name, for diagnostics that list the alternatives.
    pub const ALL: [&'static str; 2] = ["entry", "landing"];
}

/// Renders the JSON Schema of the current configuration.
///
/// One schema per role, because the roles are different shapes and a single
/// permissive union would describe a configuration this binary does not
/// accept. Editors and CI consume this; the running binary remains the final
/// authority through `rust-reality check`.
///
/// # Errors
///
/// Returns an error if the schema fails to serialise.
pub fn schema_json() -> Result<String, serde_json::Error> {
    let schema = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "rust-reality configuration",
        "oneOf": [
            schemars::schema_for!(EntryConfig),
            schemars::schema_for!(LandingConfig),
        ],
    });
    let mut output = serde_json::to_string_pretty(&schema)?;
    output.push('\n');
    Ok(output)
}

/// Test fixtures for the current schema.
///
/// One place to build a valid node, so a schema change breaks in one file
/// rather than in every module that happens to need a configuration.
#[cfg(test)]
pub(crate) mod fixture {
    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};

    /// A distinct, well-formed 32-byte key, so fixtures never collide.
    pub(crate) fn key(seed: u8) -> String {
        BASE64_URL_SAFE_NO_PAD.encode([seed; 32])
    }

    /// A canonical version-4 UUID that differs per `seed`.
    pub(crate) fn uuid(seed: u8) -> String {
        format!("{seed:02x}{seed:02x}{seed:02x}{seed:02x}-1111-4111-8111-111111111111")
    }

    /// A minimal standalone entry node.
    pub(crate) fn entry_json() -> String {
        entry_with("")
    }

    /// A minimal entry node with extra top-level sections spliced in.
    ///
    /// `extra` must start with a comma, so a caller reads as JSON.
    pub(crate) fn entry_with(extra: &str) -> String {
        format!(
            r#"{{
  "role": "entry",
  "listeners": [{{ "port": 443 }}],
  "reality": {{ "cover": "www.example.com:443", "privateKey": "{}" }},
  "users": [{{ "id": "{}", "shortIds": ["0123456789abcdef"] }}],
  "routing": {{ "default": "direct" }}{extra}
}}"#,
            key(1),
            uuid(0x11)
        )
    }

    /// An entry node carrying only the identity: role, REALITY, and users.
    ///
    /// The caller supplies `listeners`, `routing`, and anything else. This is
    /// what a test that needs its own listener or routing block wants:
    /// splicing a second one into [`entry_with`] would be a duplicate key.
    pub(crate) fn entry_without_routing(sections: &str) -> String {
        format!(
            r#"{{
  "role": "entry",
  "reality": {{ "cover": "www.example.com:443", "privateKey": "{}" }},
  "users": [{{ "id": "{}", "shortIds": ["0123456789abcdef"] }}],
  {sections}
}}"#,
            key(1),
            uuid(0x11)
        )
    }

    /// A minimal entry node fronting a specific cover endpoint.
    ///
    /// The cover is usually a loopback listener a test just bound, so the
    /// server names are stated explicitly rather than defaulting to a host
    /// that is an address.
    pub(crate) fn entry_with_cover(cover: &str) -> String {
        format!(
            r#"{{
  "role": "entry",
  "listeners": [{{ "port": 443 }}],
  "reality": {{
    "cover": "{cover}",
    "serverNames": ["www.example.com"],
    "privateKey": "{}"
  }},
  "users": [{{ "id": "{}", "shortIds": ["0123456789abcdef"] }}],
  "routing": {{ "default": "direct" }}
}}"#,
            key(1),
            uuid(0x11)
        )
    }

    /// A minimal Handoff landing node.
    pub(crate) fn landing_json() -> String {
        landing_with("")
    }

    /// A minimal Handoff landing node with extra sections spliced in.
    pub(crate) fn landing_with(extra: &str) -> String {
        format!(
            r#"{{
  "role": "landing",
  "listeners": [{{ "port": 7443 }}],
  "landing": {{ "protocol": "handoff", "psk": "{}", "privateKey": "{}" }}{extra}
}}"#,
            key(2),
            key(3)
        )
    }

    /// Parses one fixture without semantic validation.
    ///
    /// For tests that deliberately need a value validation rejects — an
    /// `http://` asset source pointing at a local test server, for instance.
    /// A test that wants a *valid* node uses [`validated`].
    pub(crate) fn parsed(json: &str) -> crate::config::NodeConfig {
        crate::config::parse::parse_bytes(std::path::Path::new("fixture.json"), json.as_bytes())
            .unwrap_or_else(|error| panic!("fixture must parse: {error}"))
    }

    /// Parses and validates one fixture, panicking on anything invalid.
    pub(crate) fn validated(json: &str) -> crate::config::ValidatedConfig {
        crate::config::load_bytes(std::path::Path::new("fixture.json"), json.as_bytes())
            .unwrap_or_else(|error| panic!("fixture must load: {error}"))
    }

    /// Parses and validates the minimal entry fixture.
    pub(crate) fn entry() -> crate::config::ValidatedConfig {
        validated(&entry_json())
    }
}

#[cfg(test)]
mod tests {
    use super::{NodeConfig, Role};
    use crate::config::node::entry::EntryConfig;

    #[test]
    fn the_schema_describes_both_roles_and_no_removed_section() {
        let schema = super::schema_json().expect("the schema must serialise");

        for present in ["reality", "listeners", "routing", "landing", "outbounds"] {
            assert!(
                schema.contains(present),
                "the schema must describe {present}"
            );
        }
        for removed in ["inbounds", "advanced", "streamSettings", "vnext"] {
            assert!(
                !schema.contains(removed),
                "{removed} no longer exists and must not appear in the schema"
            );
        }
    }

    #[test]
    fn role_names_are_stable_and_exhaustively_listed() {
        assert_eq!(Role::Entry.as_str(), "entry");
        assert_eq!(Role::Landing.as_str(), "landing");
        assert_eq!(Role::ALL, ["entry", "landing"]);
    }

    #[test]
    fn a_node_exposes_only_the_sections_its_role_owns() {
        let entry: EntryConfig = serde_json::from_str(
            r#"{"role":"entry","listeners":[{"port":443}],
                "reality":{"cover":"a:443","privateKey":"k"},
                "users":[{"id":"u","shortIds":["ab"]}],
                "routing":{"default":"direct"}}"#,
        )
        .expect("entry must decode");
        let node = NodeConfig::Entry(Box::new(entry));

        assert_eq!(node.role(), Role::Entry);
        assert!(node.as_entry().is_some());
        assert!(node.as_landing().is_none());
        assert_eq!(node.listeners().len(), 1);
    }
}
