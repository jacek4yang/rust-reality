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

#[cfg(test)]
mod tests {
    use super::{NodeConfig, Role};
    use crate::config::node::entry::EntryConfig;

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
