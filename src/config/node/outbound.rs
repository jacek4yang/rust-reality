//! Declared outbound transports.
//!
//! Outbounds are a name-keyed object rather than an array of objects carrying
//! their own `tag`: the name is the identity, order carries no meaning, and a
//! duplicate name becomes impossible to write instead of something validation
//! has to catch.
//!
//! Two outbounds are built in and are never declared here:
//!
//! - `direct` dials the requested destination;
//! - `block` completes and discards the connection.
//!
//! Declaring an outbound under either name is an error, because the name would
//! then mean two things.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::config::secret::SecretString;

/// The built-in outbound that dials the requested destination.
pub const BUILTIN_DIRECT: &str = "direct";

/// The built-in outbound that completes and discards the connection.
pub const BUILTIN_BLOCK: &str = "block";

/// Every outbound name that exists without being declared.
pub const BUILTIN_OUTBOUNDS: [&str; 2] = [BUILTIN_DIRECT, BUILTIN_BLOCK];

/// Returns whether `name` is a built-in outbound.
#[must_use]
pub fn is_builtin_outbound(name: &str) -> bool {
    BUILTIN_OUTBOUNDS.contains(&name)
}

/// One declared outbound transport.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "camelCase")]
pub enum OutboundConfig {
    /// Connect through a SOCKS5 server.
    Socks5(Socks5Config),
    /// Connect one flow through one authenticated NXR connection.
    Nxr(NxrOutboundConfig),
    /// Transfer one authenticated session to a Handoff landing node.
    Handoff(HandoffOutboundConfig),
}

impl OutboundConfig {
    /// The stable type name used in configuration and diagnostics.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Socks5(_) => "socks5",
            Self::Nxr(_) => "nxr",
            Self::Handoff(_) => "handoff",
        }
    }

    /// The endpoint host this outbound dials.
    #[must_use]
    pub fn address(&self) -> &str {
        match self {
            Self::Socks5(settings) => &settings.address,
            Self::Nxr(settings) => &settings.address,
            Self::Handoff(settings) => &settings.address,
        }
    }

    /// The endpoint port this outbound dials.
    #[must_use]
    pub const fn port(&self) -> u16 {
        match self {
            Self::Socks5(settings) => settings.port,
            Self::Nxr(settings) => settings.port,
            Self::Handoff(settings) => settings.port,
        }
    }

    /// Whether this outbound pre-establishes TCP connections to its endpoint.
    #[must_use]
    pub fn warm_tcp(&self) -> bool {
        let configured = match self {
            Self::Socks5(settings) => settings.warm_tcp,
            Self::Nxr(settings) => settings.warm_tcp,
            Self::Handoff(settings) => settings.warm_tcp,
        };
        configured.unwrap_or(true)
    }
}

/// A SOCKS5 upstream.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Socks5Config {
    /// SOCKS5 server host.
    pub address: String,
    /// SOCKS5 server port.
    pub port: u16,
    /// Username, required if and only if `password` is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<SecretString>,
    /// Password, required if and only if `username` is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretString>,
    /// Pre-establish TCP connections to this server. Negotiation and
    /// authentication always stay session-owned and happen after checkout.
    /// Absent means enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warm_tcp: Option<bool>,
}

/// An NXR landing node.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NxrOutboundConfig {
    /// Landing node host.
    pub address: String,
    /// Firewall-restricted NXR port on the landing node.
    pub port: u16,
    /// Shared 32-byte key, URL-safe unpadded base64, from
    /// `rust-reality generate psk`. Must match the landing node's `psk` and be
    /// independent of every other key in the deployment.
    pub psk: SecretString,
    /// Pre-establish TCP connections to this landing. Absent means enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warm_tcp: Option<bool>,
}

/// A Handoff landing node.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HandoffOutboundConfig {
    /// Landing node host.
    pub address: String,
    /// Firewall-restricted Handoff port on the landing node.
    pub port: u16,
    /// Shared 32-byte key, URL-safe unpadded base64, from
    /// `rust-reality generate psk`. Must match the landing node's `psk` and be
    /// independent of every other key in the deployment.
    pub psk: SecretString,
    /// The landing node's static X25519 public key, URL-safe unpadded base64.
    /// Public material, not a secret: it is the public half of the landing's
    /// `privateKey`.
    pub landing_public_key: String,
    /// Deadline for dialing the landing and writing the sealed transfer.
    /// Absent means 10000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,
    /// Deadline for the landing's first downlink byte after the transfer
    /// write, which is how this node detects a silent rejection.
    ///
    /// A successful transfer produces immediate downlink; every rejection
    /// closes silently. This must exceed the landing's authentication and
    /// connect deadlines together, because the first sealed record appears
    /// only after the transfer is read, authenticated, and the destination
    /// dialed — a shorter deadline resets viable sessions whose landing is
    /// merely slow. Absent means 15000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_byte_timeout_ms: Option<u64>,
    /// Pre-establish TCP connections to this landing. Absent means enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warm_tcp: Option<bool>,
}

/// The default Handoff dial-and-write deadline, in milliseconds.
pub const DEFAULT_HANDOFF_CONNECT_TIMEOUT_MS: u64 = 10_000;

/// The default Handoff first-downlink-byte deadline, in milliseconds.
pub const DEFAULT_HANDOFF_FIRST_BYTE_TIMEOUT_MS: u64 = 15_000;

impl HandoffOutboundConfig {
    /// The dial-and-write deadline, applying the default.
    #[must_use]
    pub fn connect_timeout_ms(&self) -> u64 {
        self.connect_timeout_ms
            .unwrap_or(DEFAULT_HANDOFF_CONNECT_TIMEOUT_MS)
    }

    /// The first-downlink-byte deadline, applying the default.
    #[must_use]
    pub fn first_byte_timeout_ms(&self) -> u64 {
        self.first_byte_timeout_ms
            .unwrap_or(DEFAULT_HANDOFF_FIRST_BYTE_TIMEOUT_MS)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BUILTIN_BLOCK, BUILTIN_DIRECT, DEFAULT_HANDOFF_CONNECT_TIMEOUT_MS,
        DEFAULT_HANDOFF_FIRST_BYTE_TIMEOUT_MS, OutboundConfig, is_builtin_outbound,
    };

    fn parse(json: &str) -> OutboundConfig {
        serde_json::from_str(json).expect("outbound must decode")
    }

    #[test]
    fn a_handoff_outbound_defaults_its_deadlines_and_warm_tcp() {
        let outbound = parse(
            r#"{"type":"handoff","address":"10.0.0.2","port":7443,
                "psk":"k","landingPublicKey":"p"}"#,
        );

        assert_eq!(outbound.type_name(), "handoff");
        assert_eq!(outbound.address(), "10.0.0.2");
        assert_eq!(outbound.port(), 7443);
        assert!(outbound.warm_tcp());
        let OutboundConfig::Handoff(settings) = &outbound else {
            panic!("must be a handoff outbound");
        };
        assert_eq!(
            settings.connect_timeout_ms(),
            DEFAULT_HANDOFF_CONNECT_TIMEOUT_MS
        );
        assert_eq!(
            settings.first_byte_timeout_ms(),
            DEFAULT_HANDOFF_FIRST_BYTE_TIMEOUT_MS
        );
    }

    #[test]
    fn warm_tcp_can_be_turned_off_explicitly() {
        let outbound =
            parse(r#"{"type":"nxr","address":"10.0.0.2","port":7443,"psk":"k","warmTcp":false}"#);

        assert!(!outbound.warm_tcp());
    }

    #[test]
    fn built_in_names_are_recognised_without_declaration() {
        assert!(is_builtin_outbound(BUILTIN_DIRECT));
        assert!(is_builtin_outbound(BUILTIN_BLOCK));
        assert!(!is_builtin_outbound("landing-1"));
    }

    #[test]
    fn built_in_types_cannot_be_declared() {
        assert!(
            serde_json::from_str::<OutboundConfig>(r#"{"type":"direct"}"#).is_err(),
            "direct is built in and has no declared form"
        );
        assert!(serde_json::from_str::<OutboundConfig>(r#"{"type":"blackhole"}"#).is_err());
        assert!(serde_json::from_str::<OutboundConfig>(r#"{"type":"block"}"#).is_err());
    }

    #[test]
    fn the_removed_protocol_tag_and_settings_wrapper_are_rejected() {
        assert!(
            serde_json::from_str::<OutboundConfig>(
                r#"{"protocol":"socks5","settings":{"address":"a","port":1}}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<OutboundConfig>(
                r#"{"type":"socks5","address":"a","port":1,"tag":"x"}"#
            )
            .is_err(),
            "the object key is the name; a tag field would be a second identity"
        );
    }
}
