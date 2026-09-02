//! The landing role: a firewall-restricted node that terminates an internal
//! transfer and dials the destination.
//!
//! A landing has no REALITY identity, no users, and no routing rules. It
//! authenticates one internal protocol and sends everything it accepts to one
//! egress. Its listening port must be restricted at the firewall to the entry
//! node's address; nothing in this file can enforce that, and the deployment
//! documentation says so at every step.
//!
//! The timing fields are declared once per protocol variant rather than shared
//! through `#[serde(flatten)]`, because serde does not honour
//! `deny_unknown_fields` on a container that flattens. Strictness is not
//! negotiable here, so the four declarations are repeated and the resolved
//! values are produced by one shared type.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    dns::DnsConfig, listener::ListenerConfig, log::LogConfig, network::NetworkConfig,
    outbound::OutboundConfig, runtime::RuntimeConfig,
};
use crate::config::secret::SecretString;

/// A landing node.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LandingConfig {
    /// Always `landing`.
    pub role: LandingRole,
    /// Firewall-restricted listening endpoints.
    pub listeners: Vec<ListenerConfig>,
    /// The internal protocol this node terminates, and its credentials.
    pub landing: LandingProtocol,
    /// How this node reaches transferred destinations.
    ///
    /// Names a built-in outbound or a key of `outbounds`. Absent means
    /// `direct`. A landing may not name a `handoff` outbound: landings do not
    /// chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<String>,
    /// Declared outbound transports, keyed by name.
    #[serde(
        default,
        deserialize_with = "super::named::optional_unique_map",
        skip_serializing_if = "Option::is_none"
    )]
    pub outbounds: Option<BTreeMap<String, OutboundConfig>>,
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

/// The role tag of a landing node.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LandingRole {
    /// The only accepted value.
    Landing,
}

impl LandingConfig {
    /// The egress outbound name, applying the `direct` default.
    #[must_use]
    pub fn egress(&self) -> &str {
        self.egress
            .as_deref()
            .unwrap_or(super::outbound::BUILTIN_DIRECT)
    }
}

/// The internal protocol a landing terminates.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, tag = "protocol", rename_all = "camelCase")]
pub enum LandingProtocol {
    /// Sealed session transfer from a Handoff entry node.
    Handoff(HandoffLandingConfig),
    /// Authenticated per-flow connection from an NXR entry node.
    Nxr(NxrLandingConfig),
}

impl LandingProtocol {
    /// The stable protocol name used in configuration and diagnostics.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Handoff(_) => "handoff",
            Self::Nxr(_) => "nxr",
        }
    }

    /// The resolved timing policy, whichever protocol this is.
    #[must_use]
    pub fn timing(&self) -> LandingTiming {
        match self {
            Self::Handoff(settings) => settings.timing(),
            Self::Nxr(settings) => settings.timing(),
        }
    }

    /// The active pre-shared key.
    #[must_use]
    pub const fn psk(&self) -> &SecretString {
        match self {
            Self::Handoff(settings) => &settings.psk,
            Self::Nxr(settings) => &settings.psk,
        }
    }
}

/// A Handoff landing's credentials, rotation state, and timing.
///
/// The pre-shared key and the static X25519 key are independent of each other,
/// of any NXR key, and of any REALITY key. Reusing material across those
/// boundaries is a configuration error that validation rejects within one file;
/// keeping it independent across nodes is the operator's obligation.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HandoffLandingConfig {
    /// Shared 32-byte key, URL-safe unpadded base64. Must match the entry
    /// node's Handoff outbound `psk`.
    pub psk: SecretString,
    /// This landing's static X25519 private key, URL-safe unpadded base64. The
    /// entry node holds the matching public half as `landingPublicKey`.
    pub private_key: SecretString,
    /// Retired pre-shared keys still accepted during a rotation window.
    ///
    /// At most two, each distinct from `psk`. Senders always seal with the
    /// active key; drop a retired key as soon as every sender has moved. While
    /// one is accepted the rotation window is reported at startup and on every
    /// reload, because the forward-secrecy bound of the retired material has
    /// not yet taken hold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_psks: Option<Vec<SecretString>>,
    /// Retired static private keys still accepted during a rotation window.
    /// The same limit and the same drop-promptly rule apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_private_keys: Option<Vec<SecretString>>,
    /// Largest accepted absolute wall-clock difference, in seconds. Absent
    /// means 30.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_time_difference_seconds: Option<u64>,
    /// How long an accepted socket may stay completely silent before it starts
    /// the sealed transfer, in milliseconds. Absent means 60000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_auth_idle_timeout_ms: Option<u64>,
    /// Deadline for reading the sealed transfer once its first byte has
    /// arrived, in milliseconds. Absent means 3000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication_timeout_ms: Option<u64>,
    /// Deadline for connecting to the transferred destination, in
    /// milliseconds. Absent means 10000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,
}

impl HandoffLandingConfig {
    /// The resolved timing policy.
    #[must_use]
    pub fn timing(&self) -> LandingTiming {
        LandingTiming::resolve(
            self.max_time_difference_seconds,
            self.pre_auth_idle_timeout_ms,
            self.authentication_timeout_ms,
            self.connect_timeout_ms,
        )
    }

    /// The retired pre-shared keys, applying the empty default.
    #[must_use]
    pub fn previous_psks(&self) -> &[SecretString] {
        self.previous_psks.as_deref().unwrap_or_default()
    }

    /// The retired static private keys, applying the empty default.
    #[must_use]
    pub fn previous_private_keys(&self) -> &[SecretString] {
        self.previous_private_keys.as_deref().unwrap_or_default()
    }

    /// Whether a key rotation window is currently open.
    #[must_use]
    pub fn rotation_window_is_open(&self) -> bool {
        !self.previous_psks().is_empty() || !self.previous_private_keys().is_empty()
    }
}

/// An NXR landing's credentials and timing.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NxrLandingConfig {
    /// Shared 32-byte key, URL-safe unpadded base64. Must match the entry
    /// node's NXR outbound `psk`.
    pub psk: SecretString,
    /// Largest accepted absolute wall-clock difference, in seconds. Absent
    /// means 30.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_time_difference_seconds: Option<u64>,
    /// How long an accepted socket may stay completely silent before it starts
    /// the authenticated request, in milliseconds. Absent means 60000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_auth_idle_timeout_ms: Option<u64>,
    /// Deadline for reading the authenticated request once its first byte has
    /// arrived, in milliseconds. Absent means 3000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication_timeout_ms: Option<u64>,
    /// Deadline for connecting to the authenticated destination, in
    /// milliseconds. Absent means 10000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,
}

impl NxrLandingConfig {
    /// The resolved timing policy.
    #[must_use]
    pub fn timing(&self) -> LandingTiming {
        LandingTiming::resolve(
            self.max_time_difference_seconds,
            self.pre_auth_idle_timeout_ms,
            self.authentication_timeout_ms,
            self.connect_timeout_ms,
        )
    }
}

/// Resolved landing timing policy.
///
/// The replay nonce capacity and its retention window are absent on purpose:
/// they follow from the accepted clock skew and the memory the process may use,
/// so they are derived rather than configured.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LandingTiming {
    /// Largest accepted absolute wall-clock difference, in seconds.
    pub max_time_difference_seconds: u64,
    /// How long an accepted socket may stay completely silent, in
    /// milliseconds.
    pub pre_auth_idle_timeout_ms: u64,
    /// Deadline for reading the authenticated exchange, in milliseconds.
    pub authentication_timeout_ms: u64,
    /// Deadline for connecting to the destination, in milliseconds.
    pub connect_timeout_ms: u64,
}

/// The default accepted wall-clock difference, in seconds.
pub const DEFAULT_MAX_TIME_DIFFERENCE_SECONDS: u64 = 30;

/// The default silent-socket window, in milliseconds.
pub const DEFAULT_PRE_AUTH_IDLE_TIMEOUT_MS: u64 = 60_000;

/// The default authentication-read deadline, in milliseconds.
pub const DEFAULT_AUTHENTICATION_TIMEOUT_MS: u64 = 3_000;

/// The default destination-connect deadline, in milliseconds.
pub const DEFAULT_LANDING_CONNECT_TIMEOUT_MS: u64 = 10_000;

impl LandingTiming {
    fn resolve(
        max_time_difference_seconds: Option<u64>,
        pre_auth_idle_timeout_ms: Option<u64>,
        authentication_timeout_ms: Option<u64>,
        connect_timeout_ms: Option<u64>,
    ) -> Self {
        Self {
            max_time_difference_seconds: max_time_difference_seconds
                .unwrap_or(DEFAULT_MAX_TIME_DIFFERENCE_SECONDS),
            pre_auth_idle_timeout_ms: pre_auth_idle_timeout_ms
                .unwrap_or(DEFAULT_PRE_AUTH_IDLE_TIMEOUT_MS),
            authentication_timeout_ms: authentication_timeout_ms
                .unwrap_or(DEFAULT_AUTHENTICATION_TIMEOUT_MS),
            connect_timeout_ms: connect_timeout_ms.unwrap_or(DEFAULT_LANDING_CONNECT_TIMEOUT_MS),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_AUTHENTICATION_TIMEOUT_MS, DEFAULT_MAX_TIME_DIFFERENCE_SECONDS,
        DEFAULT_PRE_AUTH_IDLE_TIMEOUT_MS, LandingConfig, LandingProtocol,
    };

    const MINIMAL_HANDOFF: &str = r#"{
      "role": "landing",
      "listeners": [{ "port": 7443 }],
      "landing": { "protocol": "handoff", "psk": "k", "privateKey": "p" }
    }"#;

    fn parse(json: &str) -> LandingConfig {
        serde_json::from_str(json).expect("landing must decode")
    }

    #[test]
    fn a_minimal_handoff_landing_needs_only_a_port_and_two_keys() {
        let landing = parse(MINIMAL_HANDOFF);

        assert_eq!(landing.listeners.len(), 1);
        assert_eq!(landing.listeners[0].port, 7443);
        assert_eq!(landing.landing.name(), "handoff");
        assert_eq!(landing.egress(), "direct");
        let timing = landing.landing.timing();
        assert_eq!(
            timing.max_time_difference_seconds,
            DEFAULT_MAX_TIME_DIFFERENCE_SECONDS
        );
        assert_eq!(
            timing.pre_auth_idle_timeout_ms,
            DEFAULT_PRE_AUTH_IDLE_TIMEOUT_MS
        );
        let LandingProtocol::Handoff(settings) = &landing.landing else {
            panic!("must be a handoff landing");
        };
        assert!(!settings.rotation_window_is_open());
        assert!(settings.previous_psks().is_empty());
    }

    #[test]
    fn an_nxr_landing_needs_only_one_key() {
        let landing = parse(
            r#"{"role":"landing","listeners":[{"port":7443}],
                "landing":{"protocol":"nxr","psk":"k"}}"#,
        );

        assert_eq!(landing.landing.name(), "nxr");
        assert_eq!(landing.landing.psk().expose(), "k");
        assert_eq!(
            landing.landing.timing().authentication_timeout_ms,
            DEFAULT_AUTHENTICATION_TIMEOUT_MS
        );
    }

    #[test]
    fn timing_fields_sit_beside_the_credentials() {
        let landing = parse(
            r#"{"role":"landing","listeners":[{"port":7443}],
                "landing":{"protocol":"nxr","psk":"k","authenticationTimeoutMs":9000}}"#,
        );

        assert_eq!(landing.landing.timing().authentication_timeout_ms, 9000);
    }

    #[test]
    fn a_rotation_window_is_visible_once_a_retired_key_is_listed() {
        let landing = parse(
            r#"{"role":"landing","listeners":[{"port":7443}],
                "landing":{"protocol":"handoff","psk":"k","privateKey":"p",
                           "previousPsks":["old"]}}"#,
        );

        let LandingProtocol::Handoff(settings) = &landing.landing else {
            panic!("must be a handoff landing");
        };
        assert!(settings.rotation_window_is_open());
        assert_eq!(settings.previous_psks().len(), 1);
    }

    #[test]
    fn an_nxr_landing_cannot_carry_a_handoff_private_key() {
        assert!(
            serde_json::from_str::<LandingConfig>(
                r#"{"role":"landing","listeners":[{"port":7443}],
                    "landing":{"protocol":"nxr","psk":"k","privateKey":"p"}}"#
            )
            .is_err(),
            "the protocol variant decides which credentials exist"
        );
    }

    #[test]
    fn a_landing_cannot_carry_entry_sections() {
        for section in [
            r#""reality":{"cover":"a:443","privateKey":"k"}"#,
            r#""users":[]"#,
            r#""routing":{"default":"direct"}"#,
            r#""assets":{}"#,
        ] {
            let json = format!(
                r#"{{"role":"landing","listeners":[{{"port":7443}}],
                     "landing":{{"protocol":"nxr","psk":"k"}},{section}}}"#
            );
            assert!(
                serde_json::from_str::<LandingConfig>(&json).is_err(),
                "a landing has no {section}"
            );
        }
    }

    #[test]
    fn the_role_tag_must_say_landing() {
        assert!(
            serde_json::from_str::<LandingConfig>(
                r#"{"role":"entry","listeners":[{"port":7443}],
                    "landing":{"protocol":"nxr","psk":"k"}}"#
            )
            .is_err()
        );
    }
}
