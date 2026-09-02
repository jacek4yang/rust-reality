//! Pinning the relay policy a fallback measurement runs under.
//!
//! `benchmark-fallback-ab.sh` compares two builds on the REALITY *fallback*
//! relay path, so the relay's knobs must be identical on both sides or the
//! comparison measures configuration rather than code.
//!
//! ## What can still be pinned, and what cannot
//!
//! Two of the three knobs survive as operator policy: `splice` and `pipePool`
//! are escape hatches for a kernel that reports a capability and then
//! misbehaves, so they are pinnable in `runtime.limits`.
//!
//! The buffer size is not. It is derived from the machine, and the objective
//! moves it one tier per step among 16, 32, and 64 KiB — which is exactly the
//! three sizes the old `bufferBytes` field could usefully hold. So a run that
//! wants a specific tier states the objective that selects it, and a size
//! outside those three is refused rather than silently rounded, because a
//! fallback A/B that thought it pinned 48 KiB and got 32 would report the
//! difference as a code change.

use crate::{
    bench::suites::render_compact,
    perf::json_in::{self, Value},
};

/// The relay knobs a fallback run pins on both sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayPolicy {
    /// Whether the relay may use `splice`.
    pub splice: bool,
    /// Whether the relay pools pipes.
    pub pipe_pool: bool,
    /// Relay buffer tier in KiB. One of 16, 32, or 64.
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

impl RelayPolicy {
    /// Rejects a combination the server would refuse at startup.
    ///
    /// Pooling exists to reuse splice pipes, so pooling without splice is not a
    /// weaker configuration but a contradictory one. Catching it here means an
    /// A/B run fails with this sentence rather than with a server that never
    /// binds.
    ///
    /// # Errors
    ///
    /// Returns a message when the pool is enabled without splice.
    pub const fn check(self) -> Result<(), &'static str> {
        if self.pipe_pool && !self.splice {
            return Err("pipePool cannot be enabled while splice is disabled: \
                        the pool holds splice pipes");
        }
        Ok(())
    }

    /// The `runtime.objective` that selects this buffer tier.
    ///
    /// # Errors
    ///
    /// Returns a message when the size is not one of the three tiers.
    pub const fn objective(self) -> Result<&'static str, &'static str> {
        match self.buffer_kib {
            16 => Ok("latency"),
            32 => Ok("balanced"),
            64 => Ok("throughput"),
            _ => Err("relay buffer must be 16, 32, or 64 KiB: the derivation \
                      selects one of three tiers and rounding would make an A/B \
                      report a configuration difference as a code change"),
        }
    }
}

/// Pins `policy` into a generated config.
///
/// # Errors
///
/// Returns a message when the config is not an object, the knobs contradict
/// each other, or the buffer tier is not one the derivation can select.
pub fn apply(config_json: &str, policy: RelayPolicy) -> Result<String, String> {
    policy.check().map_err(str::to_owned)?;
    let objective = policy.objective().map_err(str::to_owned)?;
    let value = json_in::parse(config_json)
        .map_err(|error| format!("the generated server config is invalid JSON: {error}"))?;
    let Value::Object(mut members) = value else {
        return Err("the generated server config is not an object".to_owned());
    };

    let runtime = members
        .entry("runtime".to_owned())
        .or_insert_with(|| Value::Object(std::collections::BTreeMap::new()));
    let Value::Object(runtime) = runtime else {
        return Err("the config's runtime is not an object".to_owned());
    };
    runtime.insert("objective".to_owned(), Value::Str(objective.to_owned()));
    let limits = runtime
        .entry("limits".to_owned())
        .or_insert_with(|| Value::Object(std::collections::BTreeMap::new()));
    let Value::Object(limits) = limits else {
        return Err("the config's runtime.limits is not an object".to_owned());
    };
    limits.insert("splice".to_owned(), Value::Bool(policy.splice));
    limits.insert("pipePool".to_owned(), Value::Bool(policy.pipe_pool));
    Ok(render_compact(&Value::Object(members)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"{"role":"entry",
        "listeners":[{"port":8443,"ip":"ipv4Only","ipv4":"127.0.0.1"}],
        "reality":{"cover":"dl.google.com:443",
                   "privateKey":"ERERERERERERERERERERERERERERERERERERERERERE"},
        "users":[{"id":"11111111-1111-4111-8111-111111111111",
                  "shortIds":["0123456789abcdef"]}],
        "routing":{"default":"direct"},"log":{"level":"warn"}}"#;

    #[test]
    fn each_buffer_tier_maps_onto_the_objective_that_selects_it() {
        for (kib, objective) in [(16, "latency"), (32, "balanced"), (64, "throughput")] {
            let policy = RelayPolicy {
                buffer_kib: kib,
                ..RelayPolicy::default()
            };

            assert_eq!(policy.objective(), Ok(objective));
        }
    }

    /// Rounding would let a fallback A/B believe it had pinned a size it did
    /// not get, and report the resulting difference as a code change.
    #[test]
    fn a_size_outside_the_three_tiers_is_refused_rather_than_rounded() {
        let policy = RelayPolicy {
            buffer_kib: 48,
            ..RelayPolicy::default()
        };

        let error = apply(BASE, policy).unwrap_err();

        assert!(error.contains("16, 32, or 64"), "{error}");
    }

    #[test]
    fn the_policy_is_pinned_and_the_result_still_validates() {
        let policy = RelayPolicy {
            splice: false,
            pipe_pool: false,
            buffer_kib: 64,
        };

        let pinned = apply(BASE, policy).unwrap();

        assert!(pinned.contains(r#""splice":false"#));
        assert!(pinned.contains(r#""pipePool":false"#));
        assert!(pinned.contains(r#""objective":"throughput""#));
        rust_reality::config::load_bytes(std::path::Path::new("relay.json"), pinned.as_bytes())
            .unwrap_or_else(|error| panic!("a pinned relay config must validate:\n{error}"));
    }

    /// An existing `runtime` block is merged into, not replaced: the profile a
    /// suite already chose has to survive.
    #[test]
    fn an_existing_runtime_block_survives() {
        let with_profile = BASE.replace(
            r#""log":{"level":"warn"}"#,
            r#""runtime":{"profile":"dedicated"},"log":{"level":"warn"}"#,
        );

        let pinned = apply(&with_profile, RelayPolicy::default()).unwrap();

        assert!(pinned.contains(r#""profile":"dedicated""#));
        assert!(pinned.contains(r#""splice":true"#));
    }

    #[test]
    fn the_default_policy_matches_the_script_defaults() {
        let policy = RelayPolicy::default();

        assert!(policy.splice);
        assert!(policy.pipe_pool);
        assert_eq!(policy.buffer_kib, 32);
        assert_eq!(policy.objective(), Ok("balanced"));
    }

    /// The server refuses this combination, so the harness refuses it first.
    #[test]
    fn pooling_without_splice_is_refused_before_the_server_sees_it() {
        let policy = RelayPolicy {
            splice: false,
            pipe_pool: true,
            buffer_kib: 32,
        };

        let error = apply(BASE, policy).unwrap_err();

        assert!(error.contains("pipePool cannot be enabled"), "{error}");
    }

    #[test]
    fn malformed_input_is_refused() {
        assert!(apply("not json", RelayPolicy::default()).is_err());
        assert!(apply("[]", RelayPolicy::default()).is_err());
    }
}
