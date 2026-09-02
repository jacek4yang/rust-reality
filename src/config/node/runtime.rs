//! Resource posture and the expert limit overrides.
//!
//! The previous model had two channels for the same numbers: `advanced.limits`,
//! which inferred operator intent by comparing a value to its default, and
//! `advanced.overrides`, which existed because that inference could not express
//! "pin one field" or "pin to the default value". There is now one channel.
//! A limit is present or it is absent; present means pinned, whatever its
//! value, and absent means derived from the detected machine.

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Process-level resource posture.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeConfig {
    /// Who owns this machine. Absent means [`RuntimeProfile::Auto`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<RuntimeProfile>,
    /// How the numeric policy is produced and maintained. Absent means
    /// [`TuningMode::Startup`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tuning: Option<TuningMode>,
    /// The shape of the derived numbers. Absent means [`Objective::Balanced`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objective: Option<Objective>,
    /// Where the adaptive controller publishes its snapshot.
    ///
    /// Consulted only with `tuning: "adaptive"`. The controller rewrites this
    /// JSON file atomically at startup and on every ceiling or pressure
    /// transition; read it with any JSON tool. Process lifetime, so a change
    /// requires a restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_file: Option<PathBuf>,
    /// Expert overrides. Every field is optional and a present field is pinned
    /// to its stated value; absent fields derive from the detected machine.
    /// An ordinary deployment states none of these.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<LimitOverrides>,
}

impl RuntimeConfig {
    /// The machine-tenancy declaration, applying the default.
    #[must_use]
    pub fn profile(&self) -> RuntimeProfile {
        self.profile.unwrap_or_default()
    }

    /// The tuning mode, applying the default.
    #[must_use]
    pub fn tuning(&self) -> TuningMode {
        self.tuning.unwrap_or_default()
    }

    /// The derivation objective, applying the default.
    #[must_use]
    pub fn objective(&self) -> Objective {
        self.objective.unwrap_or_default()
    }

    /// The expert overrides, applying the empty default.
    #[must_use]
    pub fn limits(&self) -> LimitOverrides {
        self.limits.unwrap_or_default()
    }
}

/// Machine-tenancy declaration.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeProfile {
    /// Detect single tenancy from the cgroup v2 boundaries. Never assumes a
    /// dedicated machine on bare metal, where the boundary is unobservable.
    #[default]
    Auto,
    /// This machine is shared. Budget against inherited limits.
    Shared,
    /// This process owns the machine or cgroup. Budget against the whole of it
    /// and supervise memory pressure.
    Dedicated,
}

impl RuntimeProfile {
    /// The stable name used in configuration, logs, and reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Shared => "shared",
            Self::Dedicated => "dedicated",
        }
    }
}

/// How the numeric policy is produced and maintained.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TuningMode {
    /// Derive once at startup from the detected machine, then hold static for
    /// the process lifetime. The default.
    #[default]
    Startup,
    /// Startup derivation plus a controller that moves soft ceilings within
    /// the startup-derived hard bounds.
    Adaptive,
}

impl TuningMode {
    /// The stable name used in configuration, logs, and reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Adaptive => "adaptive",
        }
    }
}

/// The shape of the derived policy numbers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Objective {
    /// Prefer lower latency: tighter concurrency ceilings.
    Latency,
    /// Balanced derivation. The default.
    #[default]
    Balanced,
    /// Prefer throughput: wider ceilings, within the machine-derived caps.
    Throughput,
}

impl Objective {
    /// The stable name used in configuration, logs, and reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Latency => "latency",
            Self::Balanced => "balanced",
            Self::Throughput => "throughput",
        }
    }
}

/// Operator pins that survive machine-aware derivation.
///
/// This is deliberately much smaller than the numbers the runtime actually
/// uses. Buffer sizes, pool capacities, admission sub-limits, replay retention,
/// and warm-connection sizing are derived: they follow from CPU count, memory
/// boundary, and descriptor budget, and an operator has no better information
/// about them than the process does. What remains is either capacity planning
/// the operator owns, or a kernel-behaviour escape hatch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LimitOverrides {
    /// Ceiling on simultaneously accepted connections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,
    /// Ceiling on simultaneous pre-authentication handshakes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_handshakes: Option<u32>,
    /// Deadline for reading a complete ClientHello, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_hello_timeout_ms: Option<u64>,
    /// Deadline for a complete authenticated handshake, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake_timeout_ms: Option<u64>,
    /// Deadline for a cover or outbound connection, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,
    /// Largest lifetime of one cover fallback, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_timeout_ms: Option<u64>,
    /// Permit non-blocking `splice` on plaintext TCP boundaries.
    ///
    /// Absent follows the detected platform capability. State it only to work
    /// around a kernel that misbehaves, which is the one case where an
    /// operator knows something the process cannot detect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub splice: Option<bool>,
    /// Reuse splice pipes process-wide instead of creating and destroying them
    /// per relay. Absent follows the detected platform capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipe_pool: Option<bool>,
}

impl LimitOverrides {
    /// The configuration path of every field this value pins, in a stable
    /// order, for reports and diagnostics.
    #[must_use]
    pub fn pinned_paths(&self) -> Vec<&'static str> {
        let mut paths = Vec::new();
        let mut push = |present: bool, path: &'static str| {
            if present {
                paths.push(path);
            }
        };
        push(
            self.max_connections.is_some(),
            "runtime.limits.maxConnections",
        );
        push(
            self.max_handshakes.is_some(),
            "runtime.limits.maxHandshakes",
        );
        push(
            self.client_hello_timeout_ms.is_some(),
            "runtime.limits.clientHelloTimeoutMs",
        );
        push(
            self.handshake_timeout_ms.is_some(),
            "runtime.limits.handshakeTimeoutMs",
        );
        push(
            self.connect_timeout_ms.is_some(),
            "runtime.limits.connectTimeoutMs",
        );
        push(
            self.fallback_timeout_ms.is_some(),
            "runtime.limits.fallbackTimeoutMs",
        );
        push(self.splice.is_some(), "runtime.limits.splice");
        push(self.pipe_pool.is_some(), "runtime.limits.pipePool");
        paths
    }

    /// Whether the operator pinned nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pinned_paths().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{LimitOverrides, Objective, RuntimeConfig, RuntimeProfile, TuningMode};

    #[test]
    fn an_empty_runtime_block_takes_every_default() {
        let runtime: RuntimeConfig = serde_json::from_str("{}").expect("runtime must decode");

        assert_eq!(runtime.profile(), RuntimeProfile::Auto);
        assert_eq!(runtime.tuning(), TuningMode::Startup);
        assert_eq!(runtime.objective(), Objective::Balanced);
        assert!(runtime.limits().is_empty());
        assert!(runtime.status_file.is_none());
    }

    #[test]
    fn a_pin_is_honoured_even_when_it_equals_the_derived_default() {
        let runtime: RuntimeConfig =
            serde_json::from_str(r#"{"limits":{"splice":true}}"#).expect("runtime must decode");

        assert_eq!(runtime.limits().splice, Some(true));
        assert!(!runtime.limits().is_empty());
        assert_eq!(runtime.limits().pinned_paths(), ["runtime.limits.splice"]);
    }

    #[test]
    fn pinned_paths_are_reported_in_a_stable_order() {
        let limits = LimitOverrides {
            pipe_pool: Some(false),
            max_connections: Some(1),
            connect_timeout_ms: Some(2),
            ..LimitOverrides::default()
        };

        assert_eq!(
            limits.pinned_paths(),
            [
                "runtime.limits.maxConnections",
                "runtime.limits.connectTimeoutMs",
                "runtime.limits.pipePool",
            ]
        );
    }

    #[test]
    fn the_removed_tuning_mode_and_channels_are_rejected() {
        assert!(
            serde_json::from_str::<RuntimeConfig>(r#"{"tuning":"fixed"}"#).is_err(),
            "fixed existed only to read the deleted legacy limit channel"
        );
        assert!(serde_json::from_str::<RuntimeConfig>(r#"{"overrides":{}}"#).is_err());
        assert!(
            serde_json::from_str::<super::LimitOverrides>(r#"{"maxReplayEntries":1024}"#).is_err(),
            "replay sizing is derived, not configured"
        );
        assert!(
            serde_json::from_str::<super::LimitOverrides>(r#"{"bufferBytes":32768}"#).is_err(),
            "relay buffer sizing is derived, not configured"
        );
    }
}
