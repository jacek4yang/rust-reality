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
