//! Pinning the relay policy a fallback measurement runs under.
//!
//! `benchmark-fallback-ab.sh` compares two builds on the REALITY *fallback* relay
//! path, so the relay's own knobs — splice, the pipe pool, the buffer size — must
//! be identical on both sides or the comparison measures configuration rather than
//! code.
//!
//! ## Why the schema is probed rather than assumed
//!
//! The two binaries under test can be from different generations, and the relay
//! policy moved between them: it lives at `.advanced.limits.relay` in the current
//! schema and at `.policy.relay` in the older one. The script therefore asked each
//! *generated config* which shape it had, rather than deciding from the A/B role —
//! as its comment put it, "A/B role does not imply a configuration generation: a
//! patch release compares two binaries from the same generation".
//!
//! A config with neither path is a hard error. Silently skipping the patch would
//! run one side on defaults and report the difference as a code change.

use crate::{
    bench::suites::render_compact,
    perf::json_in::{self, Value},
};

/// Where a generated config keeps its relay policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaySchema {
    /// The current schema: `advanced.limits.relay`.
    AdvancedLimits,
    /// The older schema: `policy.relay`.
    Policy,
}

impl RelaySchema {
    /// The dotted path this schema keeps the relay policy at.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::AdvancedLimits => ".advanced.limits.relay",
            Self::Policy => ".policy.relay",
        }
    }
}

/// The relay knobs a fallback run pins on both sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayPolicy {
    /// Whether the relay may use `splice`.
    pub splice: bool,
    /// Whether the relay pools pipes.
    pub pipe_pool: bool,
    /// Relay buffer size in KiB; recorded in bytes.
    pub buffer_kib: u32,
}

impl Default for RelayPolicy {
    fn default() -> Self {
        Self {
            splice: true,
            pipe_pool: true,
            buffer_kib: 32,
        }
    }
}

/// Detects which relay schema a generated config uses.
///
/// # Errors
///
/// Returns the script's message when the config carries neither shape.
pub fn detect(config: &Value) -> Result<RelaySchema, String> {
    let is_object = |value: Option<&Value>| matches!(value, Some(Value::Object(_)));
    if is_object(
        config
            .field("", "advanced")
            .ok()
            .and_then(|advanced| advanced.field("advanced", "limits").ok())
            .and_then(|limits| limits.field("advanced.limits", "relay").ok()),
    ) {
        return Ok(RelaySchema::AdvancedLimits);
    }
    if is_object(
        config
            .field("", "policy")
            .ok()
            .and_then(|policy| policy.field("policy", "relay").ok()),
    ) {
        return Ok(RelaySchema::Policy);
    }
    Err("generated configuration has no canonical relay policy".to_owned())
}

/// Pins `policy` into a generated config, whichever schema it uses.
///
/// # Errors
///
/// Returns a message when the config is not an object or carries no relay policy.
pub fn apply(config_json: &str, policy: RelayPolicy) -> Result<String, String> {
    let value = json_in::parse(config_json)
        .map_err(|error| format!("the generated server config is invalid JSON: {error}"))?;
    let schema = detect(&value)?;
    let Value::Object(mut members) = value else {
        return Err("the generated server config is not an object".to_owned());
    };

    let relay = {
        let outer = match schema {
            RelaySchema::AdvancedLimits => {
                let Some(Value::Object(advanced)) = members.get_mut("advanced") else {
                    return Err("the config has no advanced object".to_owned());
                };
                let Some(Value::Object(limits)) = advanced.get_mut("limits") else {
                    return Err("the config has no advanced.limits object".to_owned());
                };
                limits
            }
            RelaySchema::Policy => {
                let Some(Value::Object(policy_object)) = members.get_mut("policy") else {
                    return Err("the config has no policy object".to_owned());
                };
                policy_object
            }
        };
        let Some(Value::Object(relay)) = outer.get_mut("relay") else {
            return Err("the config has no relay object".to_owned());
        };
        relay
    };
    relay.insert("splice".to_owned(), Value::Bool(policy.splice));
    relay.insert("pipePool".to_owned(), Value::Bool(policy.pipe_pool));
    relay.insert(
        "bufferBytes".to_owned(),
        Value::Number((u64::from(policy.buffer_kib) * 1024).to_string()),
    );
    Ok(render_compact(&Value::Object(members)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The script's own `SELF_TEST` cases, verbatim.
    #[test]
    fn the_script_self_test_schema_selection_is_reproduced() {
        let current = json_in::parse(r#"{"advanced":{"limits":{"relay":{}}}}"#).unwrap();
        assert_eq!(detect(&current).unwrap(), RelaySchema::AdvancedLimits);
        assert!(detect(&current).unwrap().path().starts_with(".advanced"));

        let legacy = json_in::parse(r#"{"policy":{"relay":{}}}"#).unwrap();
        assert_eq!(detect(&legacy).unwrap(), RelaySchema::Policy);
        assert!(detect(&legacy).unwrap().path().starts_with(".policy"));

        let missing = json_in::parse("{}").unwrap();
        assert_eq!(
            detect(&missing).unwrap_err(),
            "generated configuration has no canonical relay policy"
        );
    }

    /// A relay key that is present but not an object is not a relay policy.
    #[test]
    fn a_non_object_relay_is_not_accepted_as_a_policy() {
        let wrong = json_in::parse(r#"{"advanced":{"limits":{"relay":true}}}"#).unwrap();
        assert!(detect(&wrong).is_err());
        let wrong = json_in::parse(r#"{"policy":{"relay":[]}}"#).unwrap();
        assert!(detect(&wrong).is_err());
    }

    #[test]
    fn the_policy_is_pinned_into_whichever_schema_the_config_uses() {
        let policy = RelayPolicy {
            splice: false,
            pipe_pool: true,
            buffer_kib: 64,
        };
        let current = apply(
            r#"{"advanced":{"limits":{"relay":{"existing":1}}},"log":{}}"#,
            policy,
        )
        .unwrap();
        assert!(current.contains(r#""splice":false"#));
        assert!(current.contains(r#""pipePool":true"#));
        assert!(current.contains(r#""bufferBytes":65536"#));
        assert!(current.contains(r#""existing":1"#), "other keys survive");

        let legacy = apply(r#"{"policy":{"relay":{}},"log":{}}"#, policy).unwrap();
        assert!(legacy.contains(r#""bufferBytes":65536"#));
        assert!(legacy.contains(r#""policy""#));
        assert!(!legacy.contains("advanced"));
    }

    /// Skipping the patch would run one side on defaults and report the
    /// difference as a code change, so a config with neither shape is fatal.
    #[test]
    fn a_config_without_a_relay_policy_is_refused() {
        let error = apply(r#"{"log":{}}"#, RelayPolicy::default()).unwrap_err();
        assert!(error.contains("no canonical relay policy"), "{error}");
        assert!(apply("not json", RelayPolicy::default()).is_err());
    }

    #[test]
    fn the_default_policy_matches_the_script_defaults() {
        let policy = RelayPolicy::default();
        assert!(policy.splice);
        assert!(policy.pipe_pool);
        assert_eq!(policy.buffer_kib, 32);
        let pinned = apply(r#"{"advanced":{"limits":{"relay":{}}}}"#, policy).unwrap();
        assert!(pinned.contains(r#""bufferBytes":32768"#));
    }
}
