//! Listening endpoints.
//!
//! Both node roles listen, so this shape is shared. What differs is the
//! security expectation around it: an entry listener faces the public internet
//! on a normal HTTPS port, while a landing listener must be restricted at the
//! firewall to the line node's address.

use std::net::{Ipv4Addr, Ipv6Addr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One listening endpoint.
///
/// Several listeners may share one identity, which is why this is an array
/// rather than a single object: adding a second port must not require
/// restating the REALITY block.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ListenerConfig {
    /// TCP port to bind.
    pub port: u16,
    /// Which address families to bind, and whether both are required.
    ///
    /// Absent means [`ListenFamily::Auto`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<ListenFamily>,
    /// IPv4 address to bind, when IPv4 is bound at all.
    ///
    /// Absent means every IPv4 address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<Ipv4Addr>,
    /// IPv6 address to bind, when IPv6 is bound at all.
    ///
    /// Absent means every IPv6 address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<Ipv6Addr>,
}

impl ListenerConfig {
    /// The address family policy, applying the `auto` default.
    #[must_use]
    pub fn family(&self) -> ListenFamily {
        self.ip.unwrap_or_default()
    }

    /// The IPv4 bind address, applying the "every address" default.
    #[must_use]
    pub fn ipv4_address(&self) -> Ipv4Addr {
        self.ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    /// The IPv6 bind address, applying the "every address" default.
    #[must_use]
    pub fn ipv6_address(&self) -> Ipv6Addr {
        self.ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED)
    }
}

/// Which address families a listener binds, and whether both are required.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ListenFamily {
    /// Try both families and start when at least one bound.
    #[default]
    Auto,
    /// Require both family sockets; fail startup if either cannot bind.
    DualStack,
    /// Bind IPv4 only.
    Ipv4Only,
    /// Bind IPv6 only.
    Ipv6Only,
}

impl ListenFamily {
    /// The stable name used in configuration, logs, and reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::DualStack => "dualStack",
            Self::Ipv4Only => "ipv4Only",
            Self::Ipv6Only => "ipv6Only",
        }
    }

    /// Whether this policy binds IPv4.
    #[must_use]
    pub const fn binds_ipv4(self) -> bool {
        !matches!(self, Self::Ipv6Only)
    }

    /// Whether this policy binds IPv6.
    #[must_use]
    pub const fn binds_ipv6(self) -> bool {
        !matches!(self, Self::Ipv4Only)
    }

    /// Whether startup requires every family this policy binds.
    #[must_use]
    pub const fn requires_every_family(self) -> bool {
        matches!(self, Self::DualStack)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::{ListenFamily, ListenerConfig};

    fn parse(json: &str) -> ListenerConfig {
        serde_json::from_str(json).expect("listener must decode")
    }

    #[test]
    fn a_bare_port_takes_every_default() {
        let listener = parse(r#"{"port":443}"#);

        assert_eq!(listener.port, 443);
        assert_eq!(listener.family(), ListenFamily::Auto);
        assert_eq!(listener.ipv4_address(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(listener.ipv6_address(), Ipv6Addr::UNSPECIFIED);
        assert!(listener.ip.is_none(), "an omitted family stays absent");
    }

    #[test]
    fn presence_is_preserved_even_when_the_value_equals_the_default() {
        let listener = parse(r#"{"port":443,"ip":"auto"}"#);

        assert_eq!(listener.family(), ListenFamily::Auto);
        assert_eq!(
            listener.ip,
            Some(ListenFamily::Auto),
            "an explicit value must stay visible to the formatter"
        );
    }

    #[test]
    fn unknown_fields_and_unknown_families_are_rejected() {
        assert!(serde_json::from_str::<ListenerConfig>(r#"{"port":443,"mode":"auto"}"#).is_err());
        assert!(serde_json::from_str::<ListenerConfig>(r#"{"port":443,"ip":"ipv4"}"#).is_err());
        assert!(serde_json::from_str::<ListenerConfig>(r#"{"ip":"auto"}"#).is_err());
    }

    #[test]
    fn family_policies_select_the_documented_sockets() {
        assert!(ListenFamily::Auto.binds_ipv4() && ListenFamily::Auto.binds_ipv6());
        assert!(!ListenFamily::Auto.requires_every_family());
        assert!(ListenFamily::DualStack.requires_every_family());
        assert!(ListenFamily::Ipv4Only.binds_ipv4() && !ListenFamily::Ipv4Only.binds_ipv6());
        assert!(!ListenFamily::Ipv6Only.binds_ipv4() && ListenFamily::Ipv6Only.binds_ipv6());
    }
}
