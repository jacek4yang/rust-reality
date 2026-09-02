//! Destination routing.
//!
//! One mechanism, used two ways. `routing` holds the rules that apply to every
//! user; `routing.policies` holds named overrides that a user opts into
//! through its own `policy` field. A user therefore has exactly one rule list
//! and one default, and which one it is can be read off the user object.
//!
//! Rules are an array because first-match order is the semantics. Policies are
//! a name-keyed object because the name is the identity.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Global routing and the policies users may opt into.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RoutingConfig {
    /// Outbound selected when no rule matches.
    ///
    /// Required. Where traffic goes by default is the single most consequential
    /// line in the file, so it is never inferred and never invisible.
    pub default: String,
    /// How names are resolved while rules are evaluated.
    ///
    /// Absent means [`DomainStrategy::ResolveIfNoMatch`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<DomainStrategy>,
    /// Ordered first-match rules applied to every user.
    ///
    /// Absent means no rules: everything takes `default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<RouteRule>>,
    /// Named policies a user may select through its `policy` field.
    ///
    /// A policy replaces both the global rules and the global default for the
    /// users that select it.
    #[serde(
        default,
        deserialize_with = "super::named::optional_unique_map",
        skip_serializing_if = "Option::is_none"
    )]
    pub policies: Option<BTreeMap<String, RoutePolicy>>,
}

impl RoutingConfig {
    /// The name-resolution strategy, applying the default.
    #[must_use]
    pub fn strategy(&self) -> DomainStrategy {
        self.strategy.unwrap_or_default()
    }

    /// The global rules, applying the empty default.
    #[must_use]
    pub fn rules(&self) -> &[RouteRule] {
        self.rules.as_deref().unwrap_or_default()
    }

    /// The named policies, applying the empty default.
    pub fn policies(&self) -> impl Iterator<Item = (&String, &RoutePolicy)> {
        self.policies.iter().flat_map(BTreeMap::iter)
    }

    /// Returns whether `name` is a declared policy.
    #[must_use]
    pub fn has_policy(&self, name: &str) -> bool {
        self.policies
            .as_ref()
            .is_some_and(|policies| policies.contains_key(name))
    }
}

/// One named routing policy.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RoutePolicy {
    /// Outbound selected when none of this policy's rules match.
    pub default: String,
    /// Ordered first-match rules for the users that select this policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<RouteRule>>,
}

impl RoutePolicy {
    /// This policy's rules, applying the empty default.
    #[must_use]
    pub fn rules(&self) -> &[RouteRule] {
        self.rules.as_deref().unwrap_or_default()
    }
}

/// One first-match routing rule.
///
/// Conditions are combined with AND across kinds and OR within a kind: a rule
/// with two domains and one port matches a connection whose destination
/// matches either domain *and* that port. A rule with no condition at all is
/// rejected, because it would shadow every rule after it.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RouteRule {
    /// Operator label, reported by `rust-reality explain --route`.
    ///
    /// Absent means the rule is reported by its position.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Domain and GeoSite conditions, such as `example.com`,
    /// `domain:example.com`, `full:www.example.com`, `regexp:…`, or
    /// `geosite:cn`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<Vec<String>>,
    /// IP, CIDR, and GeoIP conditions, such as `10.0.0.0/8` or `geoip:private`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<Vec<String>>,
    /// Destination port conditions: a single port or an inclusive `from-to`
    /// range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<Vec<String>>,
    /// Outbound selected when this rule matches.
    pub outbound: String,
}

impl RouteRule {
    /// The domain conditions, applying the empty default.
    #[must_use]
    pub fn domain(&self) -> &[String] {
        self.domain.as_deref().unwrap_or_default()
    }

    /// The IP conditions, applying the empty default.
    #[must_use]
    pub fn ip(&self) -> &[String] {
        self.ip.as_deref().unwrap_or_default()
    }

    /// The port conditions, applying the empty default.
    #[must_use]
    pub fn port(&self) -> &[String] {
        self.port.as_deref().unwrap_or_default()
    }

    /// Whether this rule states any condition at all.
    #[must_use]
    pub fn has_condition(&self) -> bool {
        !self.domain().is_empty() || !self.ip().is_empty() || !self.port().is_empty()
    }
}

/// How destination names are resolved while routing rules are evaluated.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DomainStrategy {
    /// Never resolve for routing. Domains reach the selected outbound intact,
    /// so IP conditions match only destinations that were already addresses.
    AsIs,
    /// Resolve only when the domain conditions produced no match, then retry
    /// the IP conditions. The default.
    #[default]
    ResolveIfNoMatch,
    /// Resolve before evaluating any rule that depends on an address.
    ResolveOnDemand,
}

impl DomainStrategy {
    /// The stable name used in configuration, logs, and reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AsIs => "asIs",
            Self::ResolveIfNoMatch => "resolveIfNoMatch",
            Self::ResolveOnDemand => "resolveOnDemand",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DomainStrategy, RouteRule, RoutingConfig};

    fn parse(json: &str) -> RoutingConfig {
        serde_json::from_str(json).expect("routing must decode")
    }

    #[test]
    fn a_default_alone_is_a_complete_routing_block() {
        let routing = parse(r#"{"default":"direct"}"#);

        assert_eq!(routing.default, "direct");
        assert_eq!(routing.strategy(), DomainStrategy::ResolveIfNoMatch);
        assert!(routing.rules().is_empty());
        assert_eq!(routing.policies().count(), 0);
    }

    #[test]
    fn the_default_outbound_is_required() {
        assert!(
            serde_json::from_str::<RoutingConfig>(r#"{"rules":[]}"#).is_err(),
            "where traffic goes by default must never be invisible"
        );
    }

    #[test]
    fn policies_are_keyed_by_name_and_carry_their_own_default() {
        let routing = parse(
            r#"{"default":"direct","policies":{
                 "split":{"default":"landing-1",
                          "rules":[{"domain":["geosite:cn"],"outbound":"direct"}]}}}"#,
        );

        assert!(routing.has_policy("split"));
        assert!(!routing.has_policy("missing"));
        let (name, policy) = routing.policies().next().expect("one policy");
        assert_eq!(name, "split");
        assert_eq!(policy.default, "landing-1");
        assert_eq!(policy.rules().len(), 1);
        assert_eq!(policy.rules()[0].outbound, "direct");
    }

    #[test]
    fn a_rule_without_a_condition_is_detectable() {
        let bare = RouteRule {
            outbound: "block".to_owned(),
            ..RouteRule::default()
        };
        assert!(
            !bare.has_condition(),
            "semantic validation rejects a rule that would shadow everything after it"
        );

        let rule: RouteRule =
            serde_json::from_str(r#"{"ip":["geoip:private"],"outbound":"block"}"#)
                .expect("rule must decode");
        assert!(rule.has_condition());
        assert_eq!(rule.ip(), ["geoip:private"]);
        assert!(rule.domain().is_empty());
        assert!(rule.name.is_none());
    }

    #[test]
    fn the_removed_rule_conditions_are_rejected() {
        assert!(
            serde_json::from_str::<RouteRule>(r#"{"network":["tcp"],"outbound":"direct"}"#)
                .is_err(),
            "every flow is TCP, so a network condition could only ever match all or nothing"
        );
        assert!(
            serde_json::from_str::<RouteRule>(r#"{"inboundTag":["x"],"outbound":"direct"}"#)
                .is_err(),
            "a node has one identity, so there is no inbound to discriminate on"
        );
    }

    #[test]
    fn strategy_values_use_the_current_vocabulary() {
        assert_eq!(
            parse(r#"{"default":"direct","strategy":"asIs"}"#).strategy(),
            DomainStrategy::AsIs
        );
        assert_eq!(
            parse(r#"{"default":"direct","strategy":"resolveOnDemand"}"#).strategy(),
            DomainStrategy::ResolveOnDemand
        );
        assert!(
            serde_json::from_str::<RoutingConfig>(
                r#"{"default":"direct","strategy":"IPIfNonMatch"}"#
            )
            .is_err(),
            "the Xray-inherited spellings are not the current vocabulary"
        );
        assert_eq!(
            DomainStrategy::ResolveIfNoMatch.as_str(),
            "resolveIfNoMatch"
        );
    }
}
