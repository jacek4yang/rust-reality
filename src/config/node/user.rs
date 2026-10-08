//! Client identities.
//!
//! A user owns its credentials and its routing policy in one place. The
//! previous model declared the UUID once under the inbound and again under
//! `routing.users[].userIds`, which forced validation to prove that every
//! identity was assigned to exactly one group. Here that is structural: a
//! user has at most one policy because it has one `policy` field.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One authorized client identity.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UserConfig {
    /// Canonical UUID, from `rust-reality generate uuid`.
    pub id: String,
    /// REALITY short IDs owned exclusively by this identity, from
    /// `rust-reality generate short-id`.
    ///
    /// A client picks one per connection. Several values allow staged
    /// client-side rotation without sharing an authentication identity with
    /// another user.
    pub short_ids: Vec<String>,
    /// Non-secret operator label, for logs and for the operator's own records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Routing policy this user follows, naming a key of `routing.policies`.
    ///
    /// Absent means the top-level `routing` default and rules apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// Whether this identity may authenticate. Absent means `true`.
    ///
    /// A disabled user keeps its identity, short IDs, and policy, and keeps
    /// them reserved, but its short IDs are left out of the REALITY
    /// authentication index, so a new connection presenting them is treated
    /// exactly like an unknown short ID. Sessions established under an
    /// earlier generation are unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

impl UserConfig {
    /// Whether this identity may authenticate, applying the default.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::UserConfig;

    #[test]
    fn a_user_needs_only_an_identity_and_short_ids() {
        let user: UserConfig = serde_json::from_str(
            r#"{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}"#,
        )
        .expect("user must decode");

        assert_eq!(user.id, "11111111-1111-4111-8111-111111111111");
        assert_eq!(user.short_ids, ["ab"]);
        assert!(user.label.is_none());
        assert!(user.policy.is_none());
        assert!(user.enabled.is_none());
        assert!(
            user.enabled(),
            "an identity is enabled unless stated otherwise"
        );
    }

    #[test]
    fn an_explicitly_disabled_user_decodes_and_reports_disabled() {
        let user: UserConfig = serde_json::from_str(
            r#"{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"],"enabled":false}"#,
        )
        .expect("user must decode");

        assert_eq!(user.enabled, Some(false));
        assert!(!user.enabled());
    }

    #[test]
    fn the_removed_flow_ceremony_field_is_rejected() {
        assert!(
            serde_json::from_str::<UserConfig>(
                r#"{"id":"u","shortIds":["ab"],"flow":"xtls-rprx-vision"}"#
            )
            .is_err(),
            "flow carried no information and no longer exists"
        );
    }

    #[test]
    fn required_fields_are_required() {
        assert!(serde_json::from_str::<UserConfig>(r#"{"shortIds":["ab"]}"#).is_err());
        assert!(serde_json::from_str::<UserConfig>(r#"{"id":"u"}"#).is_err());
    }
}
