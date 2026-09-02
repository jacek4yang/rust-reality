//! Merging the derivation with what the operator pinned, and recording which
//! won.
//!
//! Provenance is not decoration. Because `runtime.limits` is presence-tracked,
//! a pinned value that happens to equal the derived one is still a pin, and
//! `explain` must be able to say so — an operator who wrote a number down is
//! telling this process not to move it, and a report that hid that would be
//! reporting the wrong thing.

use crate::{
    config::node::runtime::{LimitOverrides, Objective},
    runtime::{
        machine::MachineReport,
        policy::{EffectivePolicy, ResourceMode},
    },
};

use super::{
    derive::{PlannedPolicy, StartupPlan, multipliers},
    inputs::{MachineCapabilities, SafetyLimits},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldSource {
    /// Derived at startup from the detected machine.
    ///
    /// Startup derivation, not the adaptive controller. The controller moves
    /// only selected soft admission and direct-dial ceilings while the process
    /// runs; it never retunes a startup-derived field such as the relay buffer
    /// size.
    Derived,
    /// Pinned by presence in `runtime.limits`.
    ///
    /// Honoured whatever the value, including one that equals what derivation
    /// or the default would have produced. Presence is the whole signal, which
    /// is why there is one override channel rather than two.
    Pinned,
    /// The built-in default: no operator value, and a field the derivation
    /// does not produce. Every timeout lands here unless it is pinned, because
    /// timeouts are protocol security parameters rather than machine budgets.
    Default,
}

impl FieldSource {
    /// The stable report name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Derived => "startup-derived",
            Self::Pinned => "operator-pinned",
            Self::Default => "default",
        }
    }

    /// Whether the operator pinned this field.
    #[must_use]
    pub const fn is_operator_pinned(self) -> bool {
        matches!(self, Self::Pinned)
    }
}

/// One effective policy value with its provenance, for `runtime explain`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FieldResolution {
    /// Stable dotted field path, e.g. `resourceGovernor.maxConnections`.
    pub field: &'static str,
    /// The effective value (booleans report 0/1).
    pub value: u64,
    /// Where the value came from.
    pub source: FieldSource,
    /// The objective multiplier applied, for derived scalable fields.
    pub multiplier: Option<f64>,
    /// The safety floor the derivation applies last, when one exists.
    pub floor: Option<u64>,
    /// The hard cap the derivation never exceeds, when one exists.
    pub cap: Option<u64>,
}

/// The effective policy for one serve startup, with per-field provenance.
#[derive(Clone, Debug)]
pub struct PolicyResolution {
    /// The effective policy: derived fields merged under operator pins.
    pub policy: EffectivePolicy,
    /// Per-field value and source, in a stable order.
    pub fields: Vec<FieldResolution>,
    /// The startup derivation (`startup`/`adaptive` modes only). Its
    /// [`PlannedPolicy::hard_bounds`] are the balanced derivation the later
    /// adaptive controller may never exceed.
    pub plan: Option<PlannedPolicy>,
}

/// Resolves the effective policy for the serve path and `rust-reality explain`.
///
/// Derivation always runs: there is one policy channel, and an absent limit
/// means "let the machine decide" rather than "use a fixed number". Each field
/// is then either pinned by presence in `runtime.limits` or taken from the
/// derivation. Derivation is passive — no storage or network benchmark runs at
/// startup, so readiness is never delayed. Fields the design does not derive
/// (every timeout) report `default` when unpinned, and the unpinned
/// `splice`/`pipePool` booleans follow the detected platform capability.
#[must_use]
pub fn resolve_policy(
    overrides: &LimitOverrides,
    objective: Objective,
    machine: &MachineReport,
    mode: ResourceMode,
    listener_count: usize,
) -> PolicyResolution {
    let plan = StartupPlan::derive(
        &MachineCapabilities::from_report(machine),
        &SafetyLimits::default(),
        mode,
        objective,
        listener_count,
        overrides,
    );
    let derived = plan.policy().clone();
    let defaults = EffectivePolicy::default();
    let multipliers = multipliers(objective);
    let mut effective = derived.clone();
    let mut fields = Vec::with_capacity(26);

    /// A field the derivation produces: pinned, or derived.
    macro_rules! resolve_field {
        ($section:ident, $name:ident, $path:literal, $pin:expr, $multiplier:expr, $floor:expr, $cap:expr) => {{
            let (value, source) = match $pin {
                Some(pinned) => (pinned, FieldSource::Pinned),
                None => (derived.$section.$name, FieldSource::Derived),
            };
            effective.$section.$name = value;
            fields.push(FieldResolution {
                field: $path,
                value: value as u64,
                source,
                multiplier: if source == FieldSource::Derived {
                    $multiplier
                } else {
                    None
                },
                floor: $floor,
                cap: $cap,
            });
        }};
    }

    /// A field the derivation never produces (every timeout): pinned, or the
    /// built-in default.
    macro_rules! resolve_carried {
        ($section:ident, $name:ident, $path:literal, $pin:expr) => {{
            let (value, source) = match $pin {
                Some(pinned) => (pinned, FieldSource::Pinned),
                None => (defaults.$section.$name, FieldSource::Default),
            };
            effective.$section.$name = value;
            fields.push(FieldResolution {
                field: $path,
                value: value as u64,
                source,
                multiplier: None,
                floor: None,
                cap: None,
            });
        }};
    }

    let ratio = |(numerator, denominator): (u64, u64)| numerator as f64 / denominator as f64;
    let bounds = SafetyLimits::default();

    resolve_field!(
        governor,
        max_connections,
        "governor.maxConnections",
        overrides.max_connections,
        Some(ratio(multipliers.connections)),
        Some(64),
        Some(bounds.max_connections)
    );
    resolve_field!(
        governor,
        max_handshakes,
        "governor.maxHandshakes",
        overrides.max_handshakes,
        Some(1.0),
        Some(1),
        None
    );
    resolve_field!(
        governor,
        max_pre_auth_idle_connections,
        "governor.maxPreAuthIdleConnections",
        None,
        Some(1.0),
        Some(1),
        None
    );
    resolve_field!(
        governor,
        max_fallbacks,
        "governor.maxFallbacks",
        None,
        Some(ratio(multipliers.fallbacks)),
        Some(1),
        None
    );
    resolve_field!(
        governor,
        max_crypto_operations,
        "governor.maxCryptoOperations",
        None,
        Some(1.0),
        Some(1),
        None
    );
    resolve_field!(
        governor,
        max_replay_entries,
        "governor.maxReplayEntries",
        None,
        Some(1.0),
        Some(1_024),
        Some(1_000_000)
    );
    resolve_field!(
        governor,
        max_dns_lookups,
        "governor.maxDnsLookups",
        None,
        Some(1.0),
        Some(16),
        None
    );
    resolve_carried!(
        governor,
        replay_retention_ms,
        "governor.replayRetentionMs",
        None
    );
    resolve_carried!(
        governor,
        client_hello_timeout_ms,
        "governor.clientHelloTimeoutMs",
        overrides.client_hello_timeout_ms
    );
    resolve_carried!(
        governor,
        handshake_timeout_ms,
        "governor.handshakeTimeoutMs",
        overrides.handshake_timeout_ms
    );
    resolve_carried!(
        governor,
        connect_timeout_ms,
        "governor.connectTimeoutMs",
        overrides.connect_timeout_ms
    );
    resolve_carried!(
        governor,
        fallback_timeout_ms,
        "governor.fallbackTimeoutMs",
        overrides.fallback_timeout_ms
    );
    resolve_field!(
        direct_barrier,
        max_concurrent,
        "directBarrier.maxConcurrent",
        None,
        Some(ratio(multipliers.direct_concurrent)),
        Some(64),
        None
    );
    resolve_field!(
        direct_barrier,
        max_per_second,
        "directBarrier.maxPerSecond",
        None,
        Some(ratio(multipliers.direct_per_second)),
        Some(64),
        None
    );
    resolve_field!(
        relay,
        buffer_bytes,
        "relay.bufferBytes",
        None,
        None,
        None,
        None
    );
    resolve_field!(
        relay,
        max_pooled_buffers,
        "relay.maxPooledBuffers",
        None,
        Some(ratio(multipliers.pooled_buffers)),
        Some(2),
        Some(bounds.max_pooled_buffers)
    );
    resolve_field!(
        relay,
        max_splice_relays,
        "relay.maxSpliceRelays",
        None,
        Some(ratio(multipliers.splice_relays)),
        Some(1),
        Some(bounds.max_splice_relays)
    );
    resolve_field!(
        relay,
        max_relay_memory_bytes,
        "relay.maxRelayMemoryBytes",
        None,
        None,
        None,
        None
    );
    resolve_field!(
        relay,
        splice,
        "relay.splice",
        overrides.splice,
        None,
        None,
        None
    );
    resolve_field!(
        relay,
        pipe_pool,
        "relay.pipePool",
        overrides.pipe_pool,
        None,
        None,
        None
    );
    resolve_field!(
        relay,
        max_pooled_pipes,
        "relay.maxPooledPipes",
        None,
        Some(ratio(multipliers.splice_relays)),
        None,
        None
    );
    resolve_field!(
        warm_connections,
        min_ready,
        "warmConnections.minReady",
        None,
        None,
        None,
        None
    );
    resolve_field!(
        warm_connections,
        max_ready,
        "warmConnections.maxReady",
        None,
        None,
        None,
        None
    );
    resolve_field!(
        warm_connections,
        max_connecting,
        "warmConnections.maxConnecting",
        None,
        None,
        None,
        None
    );
    resolve_field!(
        warm_connections,
        refill_batch,
        "warmConnections.refillBatch",
        None,
        None,
        None,
        None
    );

    // A pipe pool without splice would reserve pipes nothing can use.
    if !effective.relay.splice {
        effective.relay.pipe_pool = false;
    }

    PolicyResolution {
        policy: effective,
        fields,
        plan: Some(plan),
    }
}
