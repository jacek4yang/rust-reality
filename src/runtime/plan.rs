//! Startup resource-policy derivation shared by the CLI autotuner and
//! server startup.
//!
//! Everything here is pure: the same capabilities, limits, mode, objective,
//! probe inputs, and overrides always produce the same plan, and nothing
//! touches the host. `config autotune` feeds measured benchmark and loopback
//! probes; serve startup passes [`Probes::default`], which selects the
//! conservative fallback tiers. Both callers share the exact formulas the
//! v1.5 autotuner shipped, so a plan derived without probes never invents
//! numbers the autotuner would not.
//!
//! The tuning objective scales selected derivation outputs after the
//! balanced derivation, before the caps; the safety floors apply last, so
//! `latency` can never under-provision and `throughput` can never exceed the
//! machine-derived ceilings (design §1.2). [`PlannedPolicy::hard_bounds`] is
//! always the balanced derivation — the ceiling set the adaptive controller
//! (a later slice) may never exceed.

use serde::Serialize;

use crate::{
    config::{
        DirectBarrierConfig, Objective, PolicyConfig, RelayPolicy, ResourceGovernorConfig,
        ResourceMode, TuningConfig, TuningMode,
    },
    runtime::machine::MachineReport,
};

const MEBIBYTE: u64 = 1024 * 1024;
/// Default userspace buffer size, selected when no network probe measured
/// the loopback stack. Matches the middle probe tier and the `RelayPolicy`
/// default.
const DEFAULT_BUFFER_BYTES: usize = 32 * 1024;

/// Machine inputs the policy derivation budgets against.
///
/// A superset of the autotune report's machine view, built directly from a
/// [`MachineReport`] so the CLI autotuner and serve startup share one view
/// of the host, including the cgroup-aware [`MachineReport::effective_cpus`]
/// math.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachineCapabilities {
    /// Logical CPUs visible through process affinity.
    pub logical_cpus: usize,
    /// CPU count after applying a finite cgroup quota.
    pub effective_cpus: usize,
    /// Inherited soft descriptor limit.
    pub fd_soft_limit: u64,
    /// Inherited hard descriptor limit.
    pub fd_hard_limit: u64,
    /// Memory source selected by host detection.
    pub memory_source: &'static str,
    /// Effective memory ceiling, or zero when unavailable.
    pub memory_total_bytes: u64,
    /// Current cgroup memory usage when available.
    pub memory_current_bytes: Option<u64>,
    /// Finite cgroup CPU quota when available.
    pub cpu_quota_microseconds: Option<u64>,
    /// Cgroup CPU quota period when available.
    pub cpu_period_microseconds: Option<u64>,
}

impl MachineCapabilities {
    /// Builds the derivation view from one detected machine report.
    #[must_use]
    pub fn from_report(report: &MachineReport) -> Self {
        Self {
            logical_cpus: report.available_cpus,
            effective_cpus: report.effective_cpus(),
            fd_soft_limit: report.fd_soft_limit,
            fd_hard_limit: report.fd_hard_limit,
            memory_source: report.memory_source,
            memory_total_bytes: report.memory_total,
            memory_current_bytes: report.memory_current,
            cpu_quota_microseconds: report.cpu_quota_us,
            cpu_period_microseconds: report.cpu_period_us,
        }
    }
}

/// Hard safety bounds applied to every derived policy.
///
/// Pure data plus pure functions: the caps cannot be exceeded no matter how
/// abundant the machine looks, and the divisors keep headroom for the rest
/// of the host (`standard`) or for the runtime's own machinery inside the
/// cgroup (`dedicated`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SafetyLimits {
    /// Descriptor total the derivation never plans beyond.
    pub max_planned_fds: u64,
    /// Connection ceiling the derivation never plans beyond.
    pub max_connections: u64,
    /// Splice-relay ceiling the derivation never plans beyond.
    pub max_splice_relays: u64,
    /// Pooled-buffer ceiling the derivation never plans beyond.
    pub max_pooled_buffers: u64,
    /// Planning charge per connection above the measured ~47 KiB
    /// idle-session footprint. The margin covers allocator variation and
    /// per-session kernel state without pretending that every byte is
    /// process RSS.
    pub planned_connection_bytes: u64,
    /// Memory reserved for one pooled pipe pair.
    pub pipe_pair_memory_bytes: u64,
}

impl Default for SafetyLimits {
    fn default() -> Self {
        Self {
            max_planned_fds: 1_048_576,
            max_connections: 262_144,
            max_splice_relays: 8_192,
            max_pooled_buffers: 65_536,
            planned_connection_bytes: 64 * 1024,
            pipe_pair_memory_bytes: 2 * 256 * 1024,
        }
    }
}

impl SafetyLimits {
    /// Returns the descriptor headroom divisor for the resource mode: the
    /// selected limit is divided by this to reserve descriptors for
    /// everything the plan does not account for.
    #[must_use]
    pub const fn headroom_divisor(&self, mode: ResourceMode) -> u64 {
        match mode {
            ResourceMode::Standard => 16,
            ResourceMode::Dedicated => 10,
        }
    }

    /// Returns the memory available to relay pools: one eighth of the
    /// effective total, bounded so tiny and huge machines both stay sane. An
    /// unknown total falls back to a fixed conservative budget.
    #[must_use]
    pub fn relay_memory_budget(&self, memory_total_bytes: u64) -> u64 {
        if memory_total_bytes == 0 {
            256 * MEBIBYTE
        } else {
            (memory_total_bytes / 8).clamp(16 * MEBIBYTE, 2 * 1024 * MEBIBYTE)
        }
    }

    /// Returns the connections the memory budget alone can sustain, leaving
    /// the rest for relay pools, crypto/asset state, the allocator, kernel
    /// socket/pipe memory, and other processes in the same budget. An
    /// unknown total disables the memory dimension.
    #[must_use]
    pub fn connection_memory_limit(&self, memory_total_bytes: u64, mode: ResourceMode) -> u64 {
        if memory_total_bytes == 0 {
            return self.max_connections;
        }
        let budget = match mode {
            ResourceMode::Standard => memory_total_bytes.saturating_mul(3) / 8,
            ResourceMode::Dedicated => memory_total_bytes / 2,
        };
        (budget / self.planned_connection_bytes).max(64)
    }
}

/// TCP loopback measurements of the local network stack.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkProbe {
    /// Echo round trips in the latency sample.
    pub round_trips: usize,
    /// Median one-byte TCP round-trip latency.
    pub p50_round_trip_microseconds: f64,
    /// 95th percentile one-byte TCP round-trip latency.
    pub p95_round_trip_microseconds: f64,
    /// Client-to-server loopback throughput.
    pub upload_mebibytes_per_second: f64,
    /// Server-to-client loopback throughput.
    pub download_mebibytes_per_second: f64,
    /// Bytes transferred in each throughput direction.
    pub bytes_per_direction: u64,
}

/// Optional measurements the derivation consumes when available.
///
/// Every input is optional so serve startup can derive without running
/// benchmarks: an absent protocol measurement contributes zero measured
/// setup capacity, and an absent network probe selects the default 32 KiB
/// buffer tier.
#[derive(Clone, Copy, Debug, Default)]
pub struct Probes<'a> {
    /// Slowest measured protocol hot path, in operations per second.
    pub protocol_ops_per_sec: Option<u64>,
    /// Loopback network measurements.
    pub network: Option<&'a NetworkProbe>,
}

/// The entry point both the CLI autotuner and serve startup call.
pub struct StartupPlan;

impl StartupPlan {
    /// Derives the resource policy from machine capabilities, safety limits,
    /// the resource mode, the tuning objective, and whatever probes the
    /// caller measured.
    ///
    /// `overrides` contributes the timeout fields verbatim: timeouts are
    /// protocol security parameters and are never machine-derived. The
    /// balanced derivation runs first; the objective then scales the
    /// selected outputs documented in design §1.2, the caps bound the scaled
    /// values, and the safety floors apply last, so a tiny or unobservable
    /// machine still gets a usable plan. [`PlannedPolicy::hard_bounds`]
    /// carries the balanced derivation regardless of the objective.
    #[must_use]
    pub fn derive(
        capabilities: &MachineCapabilities,
        limits: &SafetyLimits,
        mode: ResourceMode,
        objective: Objective,
        listener_count: usize,
        probes: Probes<'_>,
        overrides: &PolicyConfig,
    ) -> PlannedPolicy {
        let cpus = u64::try_from(capabilities.effective_cpus)
            .unwrap_or(u64::MAX)
            .max(1);
        let selected_limit = match mode {
            ResourceMode::Standard => capabilities.fd_soft_limit,
            ResourceMode::Dedicated => capabilities.fd_hard_limit,
        }
        .min(limits.max_planned_fds);
        let headroom = (selected_limit / limits.headroom_divisor(mode)).max(64);
        let listeners = u64::try_from(listener_count).unwrap_or(u64::MAX);
        let fixed = listeners.saturating_mul(2).saturating_add(3 + 1 + 16 + 32);
        let dynamic_fds = selected_limit
            .saturating_sub(headroom)
            .saturating_sub(fixed)
            .max(64);

        let relay_budget = limits.relay_memory_budget(capabilities.memory_total_bytes);
        let desired_splice = cpus.saturating_mul(256).clamp(1, limits.max_splice_relays);
        let memory_splice = (relay_budget / 2 / (2 * limits.pipe_pair_memory_bytes)).max(1);
        let max_splice_relays = desired_splice
            .min(dynamic_fds / 12)
            .min(memory_splice)
            .max(1);
        let max_pooled_pipes = max_splice_relays.saturating_mul(2);
        let accelerator_fds = max_splice_relays
            .saturating_mul(4)
            .saturating_add(max_pooled_pipes.saturating_mul(2));
        let fd_connection_limit = dynamic_fds
            .saturating_sub(accelerator_fds)
            .saturating_div(2);
        let memory_connection_limit =
            limits.connection_memory_limit(capabilities.memory_total_bytes, mode);
        let max_connections = fd_connection_limit
            .min(memory_connection_limit)
            .clamp(64, limits.max_connections);

        let buffer_bytes = selected_buffer_bytes(probes.network);
        let pipe_memory = max_pooled_pipes.saturating_mul(limits.pipe_pair_memory_bytes);
        let buffer_memory = relay_budget
            .saturating_sub(pipe_memory)
            .max(2 * buffer_bytes as u64);
        let max_pooled_buffers = (buffer_memory / buffer_bytes as u64)
            .clamp(2, limits.max_pooled_buffers)
            .min(max_connections.saturating_mul(2));
        let relay_memory =
            pipe_memory.saturating_add(max_pooled_buffers.saturating_mul(buffer_bytes as u64));

        let measured_setup_capacity = probes
            .protocol_ops_per_sec
            .map_or(0, |operations| operations / 1_000);
        let max_handshakes = cpus
            .saturating_mul(128)
            .max(measured_setup_capacity)
            .min(max_connections)
            .max(1);
        let max_crypto_operations = cpus.saturating_mul(32).min(max_handshakes).max(1);
        let max_fallbacks = max_connections.min(cpus.saturating_mul(128).max(64));
        let max_dns_lookups = max_connections.min(cpus.saturating_mul(32).max(16));
        let max_replay_entries = max_connections.saturating_mul(4).clamp(1_024, 1_000_000);
        let max_direct_concurrent = max_connections.min(cpus.saturating_mul(512).max(64));
        let max_direct_per_second = cpus
            .saturating_mul(2_048)
            .max(measured_setup_capacity.saturating_mul(4))
            .clamp(64, u64::from(u32::MAX));

        let policy = PolicyConfig {
            resource_governor: ResourceGovernorConfig {
                max_connections: to_u32(max_connections),
                max_handshakes: to_u32(max_handshakes),
                max_fallbacks: to_u32(max_fallbacks),
                max_crypto_operations: to_u32(max_crypto_operations),
                max_replay_entries: to_u32(max_replay_entries),
                max_dns_lookups: to_u32(max_dns_lookups),
                replay_retention_ms: overrides.resource_governor.replay_retention_ms,
                client_hello_timeout_ms: overrides.resource_governor.client_hello_timeout_ms,
                handshake_timeout_ms: overrides.resource_governor.handshake_timeout_ms,
                connect_timeout_ms: overrides.resource_governor.connect_timeout_ms,
                fallback_timeout_ms: overrides.resource_governor.fallback_timeout_ms,
            },
            direct_barrier: DirectBarrierConfig {
                max_concurrent: to_u32(max_direct_concurrent),
                max_per_second: to_u32(max_direct_per_second),
            },
            relay: RelayPolicy {
                buffer_bytes,
                max_pooled_buffers: usize::try_from(max_pooled_buffers).unwrap_or(65_536),
                max_splice_relays: to_u32(max_splice_relays.min(max_connections)),
                max_relay_memory_bytes: relay_memory,
                splice: cfg!(target_os = "linux"),
                pipe_pool: cfg!(target_os = "linux"),
                max_pooled_pipes: if cfg!(target_os = "linux") {
                    to_u32(max_pooled_pipes)
                } else {
                    0
                },
            },
        };
        PlannedPolicy {
            policy: scale_for_objective(&policy, objective, limits, capabilities),
            hard_bounds: policy,
        }
    }
}

/// The derived policy and the hard bounds it may move within.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedPolicy {
    policy: PolicyConfig,
    hard_bounds: PolicyConfig,
}

impl PlannedPolicy {
    /// Returns the derived effective policy.
    #[must_use]
    pub const fn policy(&self) -> &PolicyConfig {
        &self.policy
    }

    /// Returns the balanced-mode derivation: the ceiling set the adaptive
    /// controller may never exceed, independent of the configured objective.
    #[must_use]
    pub const fn hard_bounds(&self) -> &PolicyConfig {
        &self.hard_bounds
    }

    /// Consumes the plan and returns the effective policy.
    #[must_use]
    pub fn into_policy(self) -> PolicyConfig {
        self.policy
    }
}

/// Per-field objective multipliers (design §1.2), as numerator/denominator
/// pairs so the scaling stays exact integer math. Fields absent here are
/// objective-invariant.
#[derive(Clone, Copy, Debug)]
struct ObjectiveMultipliers {
    connections: (u64, u64),
    fallbacks: (u64, u64),
    direct_concurrent: (u64, u64),
    direct_per_second: (u64, u64),
    pooled_buffers: (u64, u64),
    splice_relays: (u64, u64),
    relay_memory: (u64, u64),
    /// Buffer-tier shift: -1 one tier down, 0 the probe tier, +1 one tier up.
    buffer_tier_shift: i8,
}

/// Returns the multiplier set for one objective.
///
/// `maxHandshakes`, `maxCryptoOperations`, and `maxDnsLookups` are
/// objective-invariant (×1); `maxReplayEntries` follows the scaled
/// `maxConnections`; `bufferBytes` moves one probe tier per step instead of
/// scaling.
fn multipliers(objective: Objective) -> ObjectiveMultipliers {
    match objective {
        Objective::Latency => ObjectiveMultipliers {
            connections: (1, 2),
            fallbacks: (1, 2),
            direct_concurrent: (1, 2),
            direct_per_second: (1, 2),
            pooled_buffers: (1, 2),
            splice_relays: (1, 1),
            relay_memory: (3, 4),
            buffer_tier_shift: -1,
        },
        Objective::Balanced => ObjectiveMultipliers {
            connections: (1, 1),
            fallbacks: (1, 1),
            direct_concurrent: (1, 1),
            direct_per_second: (1, 1),
            pooled_buffers: (1, 1),
            splice_relays: (1, 1),
            relay_memory: (1, 1),
            buffer_tier_shift: 0,
        },
        Objective::Throughput => ObjectiveMultipliers {
            connections: (3, 2),
            fallbacks: (1, 1),
            direct_concurrent: (3, 2),
            direct_per_second: (2, 1),
            pooled_buffers: (2, 1),
            splice_relays: (2, 1),
            relay_memory: (3, 2),
            buffer_tier_shift: 1,
        },
    }
}

/// Scales `value` by an exact fraction.
fn scale(value: u64, (numerator, denominator): (u64, u64)) -> u64 {
    value.saturating_mul(numerator) / denominator
}

/// Applies the objective to the balanced derivation.
///
/// The multipliers scale the balanced outputs; the caps bound the result and
/// the safety floors apply last, exactly as the unscaled derivation applies
/// them. Fields the design marks objective-invariant are only re-clamped
/// against the scaled `maxConnections`/`maxHandshakes` parents so the
/// validator's child-≤-parent invariants keep holding, and the relay memory
/// budget always covers the scaled pools so the derived policy validates.
fn scale_for_objective(
    balanced: &PolicyConfig,
    objective: Objective,
    limits: &SafetyLimits,
    capabilities: &MachineCapabilities,
) -> PolicyConfig {
    if objective == Objective::Balanced {
        return balanced.clone();
    }
    let multipliers = multipliers(objective);
    let governor = &balanced.resource_governor;
    let max_connections = scale(u64::from(governor.max_connections), multipliers.connections)
        .clamp(64, limits.max_connections);
    let max_handshakes = u64::from(governor.max_handshakes)
        .min(max_connections)
        .max(1);
    let max_crypto_operations = u64::from(governor.max_crypto_operations)
        .min(max_handshakes)
        .max(1);
    let max_fallbacks = scale(u64::from(governor.max_fallbacks), multipliers.fallbacks)
        .min(max_connections)
        .max(1);
    let max_dns_lookups = u64::from(governor.max_dns_lookups)
        .min(max_connections)
        .max(1);
    let max_replay_entries = max_connections.saturating_mul(4).clamp(1_024, 1_000_000);
    let max_direct_concurrent = scale(
        u64::from(balanced.direct_barrier.max_concurrent),
        multipliers.direct_concurrent,
    )
    .min(max_connections)
    .max(1);
    let max_direct_per_second = scale(
        u64::from(balanced.direct_barrier.max_per_second),
        multipliers.direct_per_second,
    )
    .clamp(64, u64::from(u32::MAX));

    let buffer_bytes =
        shift_buffer_tier(balanced.relay.buffer_bytes, multipliers.buffer_tier_shift);
    let max_splice_relays = scale(
        u64::from(balanced.relay.max_splice_relays),
        multipliers.splice_relays,
    )
    .clamp(1, limits.max_splice_relays)
    .min(max_connections);
    // A zero balanced pipe count is the non-Linux derivation: the pool stays
    // disabled and reserves no memory whatever the objective.
    let max_pooled_pipes = if balanced.relay.max_pooled_pipes == 0 {
        0
    } else {
        max_splice_relays.saturating_mul(2)
    };
    let mut max_pooled_buffers = scale(
        balanced.relay.max_pooled_buffers as u64,
        multipliers.pooled_buffers,
    )
    .clamp(2, limits.max_pooled_buffers)
    .min(max_connections.saturating_mul(2));
    let buffer_bytes_u64 = buffer_bytes as u64;
    let pipe_memory = max_pooled_pipes.saturating_mul(limits.pipe_pair_memory_bytes);
    let required_memory =
        pipe_memory.saturating_add(max_pooled_buffers.saturating_mul(buffer_bytes_u64));
    let mut relay_memory = scale(
        balanced.relay.max_relay_memory_bytes,
        multipliers.relay_memory,
    )
    .max(required_memory);
    if capabilities.memory_total_bytes > 0 {
        let memory_cap = capabilities.memory_total_bytes / 4;
        if relay_memory > memory_cap {
            // The memory ceiling wins over the scaled budget: refit the
            // buffer pool into what remains after the pipe reservation. The
            // floors still apply last, so a machine too small to cover even
            // them keeps its minimal pools instead of failing validation.
            relay_memory = memory_cap.max(pipe_memory.saturating_add(2 * buffer_bytes_u64));
            max_pooled_buffers = (relay_memory.saturating_sub(pipe_memory) / buffer_bytes_u64)
                .clamp(2, limits.max_pooled_buffers)
                .min(max_connections.saturating_mul(2));
            relay_memory = relay_memory.max(
                pipe_memory.saturating_add(max_pooled_buffers.saturating_mul(buffer_bytes_u64)),
            );
        }
    }

    PolicyConfig {
        resource_governor: ResourceGovernorConfig {
            max_connections: to_u32(max_connections),
            max_handshakes: to_u32(max_handshakes),
            max_fallbacks: to_u32(max_fallbacks),
            max_crypto_operations: to_u32(max_crypto_operations),
            max_replay_entries: to_u32(max_replay_entries),
            max_dns_lookups: to_u32(max_dns_lookups),
            ..governor.clone()
        },
        direct_barrier: DirectBarrierConfig {
            max_concurrent: to_u32(max_direct_concurrent),
            max_per_second: to_u32(max_direct_per_second),
        },
        relay: RelayPolicy {
            buffer_bytes,
            max_pooled_buffers: usize::try_from(max_pooled_buffers).unwrap_or(65_536),
            max_splice_relays: to_u32(max_splice_relays),
            max_relay_memory_bytes: relay_memory,
            splice: balanced.relay.splice,
            pipe_pool: balanced.relay.pipe_pool,
            max_pooled_pipes: to_u32(max_pooled_pipes),
        },
    }
}

/// Moves one buffer tier per objective step, bounded by the slowest and
/// fastest tiers the loopback probe can select.
fn shift_buffer_tier(buffer_bytes: usize, shift: i8) -> usize {
    const TIERS: [usize; 3] = [16 * 1024, 32 * 1024, 64 * 1024];
    let index = TIERS
        .iter()
        .position(|tier| *tier >= buffer_bytes)
        .unwrap_or(TIERS.len() - 1);
    let shifted = (index as i8 + shift).clamp(0, (TIERS.len() - 1) as i8);
    TIERS[shifted as usize]
}

/// Selects the userspace buffer size from the loopback throughput tier, or
/// the default tier when no probe measured the stack.
fn selected_buffer_bytes(network: Option<&NetworkProbe>) -> usize {
    let Some(network) = network else {
        return DEFAULT_BUFFER_BYTES;
    };
    let slower_direction = network
        .upload_mebibytes_per_second
        .min(network.download_mebibytes_per_second);
    if slower_direction >= 1_024.0 {
        64 * 1024
    } else if slower_direction >= 256.0 {
        32 * 1024
    } else {
        16 * 1024
    }
}

fn to_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Where one effective policy value came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldSource {
    /// Derived at startup from the detected machine (`startup`/`adaptive`).
    Derived,
    /// Pinned by an explicit `advanced.limits` value; always wins.
    Override,
    /// The built-in default (`fixed` mode with no explicit value).
    Default,
}

impl FieldSource {
    /// Returns the stable report name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Derived => "derived",
            Self::Override => "override",
            Self::Default => "default",
        }
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
    pub policy: PolicyConfig,
    /// Per-field value and source, in a stable order.
    pub fields: Vec<FieldResolution>,
    /// The startup derivation (`startup`/`adaptive` modes only). Its
    /// [`PlannedPolicy::hard_bounds`] are the balanced derivation the later
    /// adaptive controller may never exceed.
    pub plan: Option<PlannedPolicy>,
}

/// Resolves the effective policy for the serve path and `runtime explain`.
///
/// `fixed` mode returns `limits` verbatim (v1.5 behavior). The derived modes
/// (`startup`, and `adaptive` until the controller lands) run
/// [`StartupPlan::derive`] against the detected machine and merge field by
/// field: a field whose configured value differs from the built-in default
/// is operator-pinned and always wins — the same presence rule the `policy`
/// alias merge applies — and every other field takes the derived value.
/// Derivation is passive: no storage or network benchmark runs at startup,
/// so readiness is never delayed; fields the design does not derive always
/// carry the configured value (all timeouts), and the unpinned `splice`/
/// `pipePool` booleans follow the derived platform capability.
#[must_use]
pub fn resolve_policy(
    limits: &PolicyConfig,
    tuning: &TuningConfig,
    machine: &MachineReport,
    mode: ResourceMode,
    listener_count: usize,
) -> PolicyResolution {
    let derive = tuning.mode() != TuningMode::Fixed;
    let plan = derive.then(|| {
        StartupPlan::derive(
            &MachineCapabilities::from_report(machine),
            &SafetyLimits::default(),
            mode,
            tuning.objective,
            listener_count,
            Probes::default(),
            limits,
        )
    });
    let derived = plan.as_ref().map_or(limits, PlannedPolicy::policy);
    let defaults = PolicyConfig::default();
    let multipliers = multipliers(tuning.objective);
    let mut effective = limits.clone();
    let mut fields = Vec::with_capacity(20);
    macro_rules! resolve_field {
        ($section:ident, $name:ident, $path:literal, $multiplier:expr, $floor:expr, $cap:expr) => {{
            let default = defaults.$section.$name;
            let (value, source) = if limits.$section.$name != default {
                (limits.$section.$name, FieldSource::Override)
            } else if derive {
                (derived.$section.$name, FieldSource::Derived)
            } else {
                (default, FieldSource::Default)
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
    /// Fields the derivation never produces (all timeouts): the configured
    /// value always wins, so an unpinned field reports `default`, never
    /// `derived`.
    macro_rules! resolve_carried {
        ($section:ident, $name:ident, $path:literal) => {{
            let default = defaults.$section.$name;
            let (value, source) = if limits.$section.$name != default {
                (limits.$section.$name, FieldSource::Override)
            } else {
                (default, FieldSource::Default)
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
    let limits_ref = SafetyLimits::default();
    resolve_field!(
        resource_governor,
        max_connections,
        "resourceGovernor.maxConnections",
        Some(ratio(multipliers.connections)),
        Some(64),
        Some(limits_ref.max_connections)
    );
    resolve_field!(
        resource_governor,
        max_handshakes,
        "resourceGovernor.maxHandshakes",
        Some(1.0),
        Some(1),
        None
    );
    resolve_field!(
        resource_governor,
        max_fallbacks,
        "resourceGovernor.maxFallbacks",
        Some(ratio(multipliers.fallbacks)),
        Some(1),
        None
    );
    resolve_field!(
        resource_governor,
        max_crypto_operations,
        "resourceGovernor.maxCryptoOperations",
        Some(1.0),
        Some(1),
        None
    );
    resolve_field!(
        resource_governor,
        max_replay_entries,
        "resourceGovernor.maxReplayEntries",
        Some(ratio(multipliers.connections)),
        Some(1_024),
        Some(1_000_000)
    );
    resolve_field!(
        resource_governor,
        max_dns_lookups,
        "resourceGovernor.maxDnsLookups",
        Some(1.0),
        Some(1),
        None
    );
    resolve_carried!(
        resource_governor,
        replay_retention_ms,
        "resourceGovernor.replayRetentionMs"
    );
    resolve_carried!(
        resource_governor,
        client_hello_timeout_ms,
        "resourceGovernor.clientHelloTimeoutMs"
    );
    resolve_carried!(
        resource_governor,
        handshake_timeout_ms,
        "resourceGovernor.handshakeTimeoutMs"
    );
    resolve_carried!(
        resource_governor,
        connect_timeout_ms,
        "resourceGovernor.connectTimeoutMs"
    );
    resolve_carried!(
        resource_governor,
        fallback_timeout_ms,
        "resourceGovernor.fallbackTimeoutMs"
    );
    resolve_field!(
        direct_barrier,
        max_concurrent,
        "directBarrier.maxConcurrent",
        Some(ratio(multipliers.direct_concurrent)),
        Some(1),
        None
    );
    resolve_field!(
        direct_barrier,
        max_per_second,
        "directBarrier.maxPerSecond",
        Some(ratio(multipliers.direct_per_second)),
        Some(64),
        Some(u64::from(u32::MAX))
    );
    resolve_field!(
        relay,
        buffer_bytes,
        "relay.bufferBytes",
        Some(match multipliers.buffer_tier_shift {
            -1 => 0.5,
            1 => 2.0,
            _ => 1.0,
        }),
        Some(16 * 1024),
        Some(64 * 1024)
    );
    resolve_field!(
        relay,
        max_pooled_buffers,
        "relay.maxPooledBuffers",
        Some(ratio(multipliers.pooled_buffers)),
        Some(2),
        Some(limits_ref.max_pooled_buffers)
    );
    resolve_field!(
        relay,
        max_splice_relays,
        "relay.maxSpliceRelays",
        Some(ratio(multipliers.splice_relays)),
        Some(1),
        Some(limits_ref.max_splice_relays)
    );
    resolve_field!(
        relay,
        max_relay_memory_bytes,
        "relay.maxRelayMemoryBytes",
        Some(ratio(multipliers.relay_memory)),
        None,
        (machine.memory_total > 0).then_some(machine.memory_total / 4)
    );
    resolve_field!(relay, splice, "relay.splice", None, None, None);
    resolve_field!(relay, pipe_pool, "relay.pipePool", None, None, None);
    resolve_field!(
        relay,
        max_pooled_pipes,
        "relay.maxPooledPipes",
        Some(ratio(multipliers.splice_relays)),
        None,
        None
    );
    PolicyResolution {
        policy: effective,
        fields,
        plan,
    }
}

/// Tokio runtime sizing decided at bootstrap, before the runtime exists.
///
/// The runtime is built once and tokio cannot resize either pool afterwards,
/// so these are cold settings (design §4.4). `None` keeps the tokio default:
/// the shared/standard posture changes nothing about how v1.5 built the
/// runtime, while the dedicated posture sizes both pools from the
/// cgroup-aware CPU view (design §4.2).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeTopology {
    /// Explicit worker-thread count, or `None` for the tokio default
    /// (`available_parallelism`).
    pub worker_threads: Option<usize>,
    /// Explicit blocking-pool size, or `None` for the tokio default (512).
    pub max_blocking_threads: Option<usize>,
}

impl RuntimeTopology {
    /// Tokio's built-in blocking-pool size, for reporting the effective
    /// topology when the default is kept.
    pub const TOKIO_DEFAULT_MAX_BLOCKING_THREADS: usize = 512;

    /// Computes the bootstrap topology for one resolved resource mode.
    ///
    /// Dedicated: `worker_threads = effective_cpus().clamp(1, 64)` — at
    /// 1 vCPU the multi-thread runtime stays (never `current_thread`) so the
    /// blocking-pool and `enable_all` semantics stay uniform — and
    /// `max_blocking_threads = (32 + 8 × cpus).clamp(64, 512)`, the pool DNS
    /// and probe work sit on. Standard/shared keeps the tokio defaults.
    #[must_use]
    pub fn for_mode(mode: ResourceMode, effective_cpus: usize) -> Self {
        match mode {
            ResourceMode::Dedicated => Self {
                worker_threads: Some(effective_cpus.clamp(1, 64)),
                max_blocking_threads: Some(
                    32_usize
                        .saturating_add(effective_cpus.saturating_mul(8))
                        .clamp(64, Self::TOKIO_DEFAULT_MAX_BLOCKING_THREADS),
                ),
            },
            ResourceMode::Standard => Self::default(),
        }
    }

    /// Returns the effective blocking-pool size, resolving the tokio default.
    #[must_use]
    pub fn effective_max_blocking_threads(&self) -> usize {
        self.max_blocking_threads
            .unwrap_or(Self::TOKIO_DEFAULT_MAX_BLOCKING_THREADS)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FieldSource, MachineCapabilities, Probes, RuntimeTopology, SafetyLimits, StartupPlan,
        resolve_policy,
    };
    use crate::config::{Objective, PolicyConfig, ResourceMode, TuningConfig, TuningMode};

    fn capabilities(
        effective_cpus: usize,
        fd_soft_limit: u64,
        fd_hard_limit: u64,
        memory_total_bytes: u64,
    ) -> MachineCapabilities {
        MachineCapabilities {
            logical_cpus: effective_cpus,
            effective_cpus,
            fd_soft_limit,
            fd_hard_limit,
            memory_source: "test",
            memory_total_bytes,
            memory_current_bytes: None,
            cpu_quota_microseconds: None,
            cpu_period_microseconds: None,
        }
    }

    fn derive(
        capabilities: &MachineCapabilities,
        mode: ResourceMode,
        listener_count: usize,
        probes: Probes<'_>,
    ) -> PolicyConfig {
        StartupPlan::derive(
            capabilities,
            &SafetyLimits::default(),
            mode,
            Objective::Balanced,
            listener_count,
            probes,
            &PolicyConfig::default(),
        )
        .into_policy()
    }

    #[test]
    fn the_golden_shared_machine_vector_matches_the_v15_autotuner() {
        // The derive_policy fixture from the v1.5 autotuner: 4 effective
        // CPUs, 4 GiB, 64k/1M descriptors, standard mode, one listener, no
        // measured setup capacity, fast loopback.
        let capabilities = capabilities(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
        let network = super::NetworkProbe {
            round_trips: 128,
            p50_round_trip_microseconds: 10.0,
            p95_round_trip_microseconds: 20.0,
            upload_mebibytes_per_second: 2_000.0,
            download_mebibytes_per_second: 2_000.0,
            bytes_per_direction: 1024 * 1024,
        };
        let policy = derive(
            &capabilities,
            ResourceMode::Standard,
            1,
            Probes {
                protocol_ops_per_sec: None,
                network: Some(&network),
            },
        );
        assert_eq!(policy.relay.buffer_bytes, 64 * 1024);
        assert_eq!(policy.resource_governor.max_connections, 24_576);
        assert!(policy.relay.max_splice_relays <= policy.resource_governor.max_connections);
    }

    #[test]
    fn the_hard_bounds_always_carry_the_balanced_derivation() {
        let capabilities = capabilities(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
        for objective in [
            Objective::Latency,
            Objective::Balanced,
            Objective::Throughput,
        ] {
            let plan = StartupPlan::derive(
                &capabilities,
                &SafetyLimits::default(),
                ResourceMode::Standard,
                objective,
                1,
                Probes::default(),
                &PolicyConfig::default(),
            );
            let balanced = StartupPlan::derive(
                &capabilities,
                &SafetyLimits::default(),
                ResourceMode::Standard,
                Objective::Balanced,
                1,
                Probes::default(),
                &PolicyConfig::default(),
            );
            assert_eq!(
                plan.hard_bounds(),
                balanced.policy(),
                "hard bounds are the balanced derivation for {objective:?}"
            );
        }
    }

    #[test]
    fn absent_probes_select_the_conservative_tiers() {
        let capabilities = capabilities(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
        let policy = derive(&capabilities, ResourceMode::Standard, 1, Probes::default());
        assert_eq!(
            policy.relay.buffer_bytes,
            32 * 1024,
            "no network probe selects the default tier"
        );
        assert_eq!(
            policy.resource_governor.max_connections, 24_576,
            "an absent protocol probe still derives the fd/memory-bounded plan"
        );
    }

    #[test]
    fn measured_setup_capacity_raises_the_handshake_pool() {
        let capabilities = capabilities(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
        let probes = Probes {
            protocol_ops_per_sec: Some(2_000_000),
            network: None,
        };
        let policy = derive(&capabilities, ResourceMode::Standard, 1, probes);
        assert_eq!(
            policy.resource_governor.max_handshakes, 2_000,
            "the measured capacity wins over cpus x 128"
        );
        assert_eq!(policy.direct_barrier.max_per_second, 8_192);
    }

    #[test]
    fn the_conservative_machine_hits_the_floors_and_caps() {
        // 1 CPU, 1 024 descriptors, no memory reading: the golden tiny-machine
        // vector from the v1.5 autotuner formulas.
        let report = crate::runtime::machine::MachineReport::conservative();
        let capabilities = MachineCapabilities::from_report(&report);
        let policy = derive(&capabilities, ResourceMode::Standard, 1, Probes::default());
        assert_eq!(policy.resource_governor.max_connections, 153);
        assert_eq!(policy.resource_governor.max_handshakes, 128);
        assert_eq!(policy.resource_governor.max_crypto_operations, 32);
        assert_eq!(policy.resource_governor.max_fallbacks, 128);
        assert_eq!(policy.resource_governor.max_dns_lookups, 32);
        assert_eq!(policy.resource_governor.max_replay_entries, 1_024);
        assert_eq!(policy.relay.buffer_bytes, 32 * 1024);
        assert_eq!(policy.relay.max_splice_relays, 75);
        assert_eq!(policy.relay.max_pooled_pipes, 150);
        assert_eq!(policy.relay.max_pooled_buffers, 306);
        assert_eq!(policy.relay.max_relay_memory_bytes, 88_670_208);
    }

    #[test]
    fn the_dedicated_mode_budgets_against_the_hard_limit() {
        let capabilities = capabilities(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
        let standard = derive(&capabilities, ResourceMode::Standard, 1, Probes::default());
        let dedicated = derive(&capabilities, ResourceMode::Dedicated, 1, Probes::default());
        assert!(
            dedicated.resource_governor.max_connections
                > standard.resource_governor.max_connections,
            "the hard limit and the /10 headroom must widen the plan"
        );
    }

    #[test]
    fn an_unknown_memory_total_disables_the_memory_dimension() {
        let capabilities = capabilities(8, 1_048_576, 1_048_576, 0);
        let policy = derive(&capabilities, ResourceMode::Dedicated, 1, Probes::default());
        assert_eq!(
            policy.resource_governor.max_connections, 262_144,
            "the fd dimension alone still produces a plan, bounded by the cap"
        );
        assert_eq!(
            policy.relay.max_relay_memory_bytes,
            256 * 1024 * 1024,
            "the fixed fallback relay budget applies when memory is unknown"
        );
    }

    #[test]
    fn the_caps_bound_an_abundant_machine() {
        let capabilities = capabilities(64, 1_048_576, 1_048_576, 64 * 1024 * 1024 * 1024);
        let limits = SafetyLimits::default();
        let policy = derive(&capabilities, ResourceMode::Dedicated, 1, Probes::default());
        assert!(u64::from(policy.resource_governor.max_connections) <= limits.max_connections);
        assert!(u64::from(policy.relay.max_splice_relays) <= limits.max_splice_relays);
        assert!(policy.relay.max_pooled_buffers <= limits.max_pooled_buffers as usize);
    }

    #[test]
    fn overrides_carry_the_timeouts_verbatim() {
        let capabilities = capabilities(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
        let mut overrides = PolicyConfig::default();
        overrides.resource_governor.handshake_timeout_ms = 42_000;
        overrides.resource_governor.replay_retention_ms = 7_000;
        let policy = StartupPlan::derive(
            &capabilities,
            &SafetyLimits::default(),
            ResourceMode::Standard,
            Objective::Balanced,
            1,
            Probes::default(),
            &overrides,
        )
        .into_policy();
        assert_eq!(policy.resource_governor.handshake_timeout_ms, 42_000);
        assert_eq!(policy.resource_governor.replay_retention_ms, 7_000);
    }

    #[test]
    fn the_relay_memory_budget_is_bounded_on_both_ends() {
        let limits = SafetyLimits::default();
        assert_eq!(limits.relay_memory_budget(0), 256 * 1024 * 1024);
        assert_eq!(limits.relay_memory_budget(1024 * 1024), 16 * 1024 * 1024);
        assert_eq!(
            limits.relay_memory_budget(1024 * 1024 * 1024 * 1024),
            2 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn the_connection_memory_model_preserves_mode_headroom() {
        let limits = SafetyLimits::default();
        let gibibyte = 1024 * 1024 * 1024;
        assert_eq!(
            limits.connection_memory_limit(gibibyte, ResourceMode::Standard),
            6_144
        );
        assert_eq!(
            limits.connection_memory_limit(gibibyte, ResourceMode::Dedicated),
            8_192
        );
        assert_eq!(
            limits.connection_memory_limit(0, ResourceMode::Standard),
            limits.max_connections
        );
    }

    #[test]
    fn the_buffer_tier_tracks_the_slower_loopback_direction() {
        let probe = |upload, download| super::NetworkProbe {
            round_trips: 128,
            p50_round_trip_microseconds: 10.0,
            p95_round_trip_microseconds: 20.0,
            upload_mebibytes_per_second: upload,
            download_mebibytes_per_second: download,
            bytes_per_direction: 1024 * 1024,
        };
        assert_eq!(
            super::selected_buffer_bytes(Some(&probe(2_000.0, 2_000.0))),
            64 * 1024
        );
        assert_eq!(
            super::selected_buffer_bytes(Some(&probe(2_000.0, 300.0))),
            32 * 1024
        );
        assert_eq!(
            super::selected_buffer_bytes(Some(&probe(100.0, 2_000.0))),
            16 * 1024
        );
        assert_eq!(super::selected_buffer_bytes(None), 32 * 1024);
    }

    fn derive_with_objective(
        capabilities: &MachineCapabilities,
        mode: ResourceMode,
        objective: Objective,
    ) -> PolicyConfig {
        StartupPlan::derive(
            capabilities,
            &SafetyLimits::default(),
            mode,
            objective,
            1,
            Probes::default(),
            &PolicyConfig::default(),
        )
        .into_policy()
    }

    /// The validator's numeric invariants, mirrored so every derived and
    /// scaled policy proves it would pass `validate_config`.
    fn assert_policy_invariants(policy: &PolicyConfig) {
        let governor = &policy.resource_governor;
        assert!(governor.max_connections >= 64);
        assert!(governor.max_handshakes >= 1);
        assert!(governor.max_handshakes <= governor.max_connections);
        assert!(governor.max_crypto_operations >= 1);
        assert!(governor.max_crypto_operations <= governor.max_handshakes);
        assert!(governor.max_fallbacks >= 1);
        assert!(governor.max_fallbacks <= governor.max_connections);
        assert!(governor.max_dns_lookups >= 1);
        assert!(governor.max_dns_lookups <= governor.max_connections);
        assert!(governor.max_replay_entries >= 1_024);
        assert!(policy.direct_barrier.max_concurrent >= 1);
        assert!(policy.direct_barrier.max_concurrent <= governor.max_connections);
        assert!(policy.direct_barrier.max_per_second >= 64);
        assert!((2..=65_536).contains(&policy.relay.max_pooled_buffers));
        let splice_term = if !policy.relay.splice {
            0
        } else if policy.relay.pipe_pool {
            assert!(policy.relay.max_splice_relays >= 1);
            assert!(policy.relay.max_splice_relays <= governor.max_connections);
            u64::from(policy.relay.max_pooled_pipes) * 2 * 256 * 1024
        } else {
            u64::from(policy.relay.max_splice_relays) * 4 * 256 * 1024
        };
        let buffered = policy.relay.max_pooled_buffers as u64 * policy.relay.buffer_bytes as u64;
        assert!(
            buffered + splice_term <= policy.relay.max_relay_memory_bytes,
            "the relay memory budget must cover the pools: {policy:?}"
        );
    }

    #[test]
    fn every_objective_on_every_machine_shape_keeps_the_validator_invariants() {
        let machines = [
            capabilities(1, 1_024, 1_024, 0),
            capabilities(1, 1_024, 1_024, 64 * 1024 * 1024),
            capabilities(2, 65_535, 65_535, 2 * 1024 * 1024 * 1024),
            capabilities(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024),
            capabilities(16, 1_048_576, 1_048_576, 64 * 1024 * 1024 * 1024),
            capabilities(64, 1_048_576, 1_048_576, 64 * 1024 * 1024 * 1024),
        ];
        for capabilities in &machines {
            for mode in [ResourceMode::Standard, ResourceMode::Dedicated] {
                for objective in [
                    Objective::Latency,
                    Objective::Balanced,
                    Objective::Throughput,
                ] {
                    let policy = derive_with_objective(capabilities, mode, objective);
                    assert_policy_invariants(&policy);
                }
            }
        }
    }

    #[test]
    fn the_objective_scales_the_documented_fields_monotonically() {
        let capabilities = capabilities(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
        let latency =
            derive_with_objective(&capabilities, ResourceMode::Standard, Objective::Latency);
        let balanced =
            derive_with_objective(&capabilities, ResourceMode::Standard, Objective::Balanced);
        let throughput =
            derive_with_objective(&capabilities, ResourceMode::Standard, Objective::Throughput);

        // The documented multipliers on the golden machine.
        assert_eq!(balanced.resource_governor.max_connections, 24_576);
        assert_eq!(latency.resource_governor.max_connections, 12_288);
        assert_eq!(throughput.resource_governor.max_connections, 36_864);
        assert_eq!(latency.relay.buffer_bytes, 16 * 1024, "one tier down");
        assert_eq!(balanced.relay.buffer_bytes, 32 * 1024, "the probe tier");
        assert_eq!(throughput.relay.buffer_bytes, 64 * 1024, "one tier up");
        assert_eq!(
            throughput.direct_barrier.max_per_second,
            balanced.direct_barrier.max_per_second * 2
        );

        // Objective-invariant fields never move; replay entries follow the
        // scaled connection ceiling.
        for policy in [&latency, &balanced, &throughput] {
            assert_eq!(policy.resource_governor.max_handshakes, 512);
            assert_eq!(policy.resource_governor.max_crypto_operations, 128);
            assert_eq!(policy.resource_governor.max_dns_lookups, 128);
            assert_eq!(
                policy.resource_governor.max_replay_entries,
                policy.resource_governor.max_connections * 4
            );
        }

        // Monotonicity across the scaled fields.
        for (lo, mid, hi) in [
            (
                latency.resource_governor.max_connections,
                balanced.resource_governor.max_connections,
                throughput.resource_governor.max_connections,
            ),
            (
                latency.resource_governor.max_fallbacks,
                balanced.resource_governor.max_fallbacks,
                throughput.resource_governor.max_fallbacks,
            ),
            (
                latency.direct_barrier.max_concurrent,
                balanced.direct_barrier.max_concurrent,
                throughput.direct_barrier.max_concurrent,
            ),
            (
                latency.relay.max_splice_relays,
                balanced.relay.max_splice_relays,
                throughput.relay.max_splice_relays,
            ),
        ] {
            assert!(lo <= mid && mid <= hi, "{lo} <= {mid} <= {hi}");
        }
        assert!(latency.relay.max_relay_memory_bytes <= balanced.relay.max_relay_memory_bytes);
        assert!(balanced.relay.max_relay_memory_bytes <= throughput.relay.max_relay_memory_bytes);
    }

    #[test]
    fn the_conservative_machine_keeps_its_floors_under_every_objective() {
        let capabilities = capabilities(1, 1_024, 1_024, 0);
        for objective in [
            Objective::Latency,
            Objective::Balanced,
            Objective::Throughput,
        ] {
            let policy = derive_with_objective(&capabilities, ResourceMode::Standard, objective);
            assert_policy_invariants(&policy);
            assert!(
                policy.resource_governor.max_connections >= 64,
                "the connection floor survives {objective:?}"
            );
        }
        let latency =
            derive_with_objective(&capabilities, ResourceMode::Standard, Objective::Latency);
        assert_eq!(latency.resource_governor.max_connections, 76);
        assert_eq!(
            latency.resource_governor.max_handshakes, 76,
            "the child limit re-clamps to the scaled parent"
        );
        assert_eq!(
            latency.resource_governor.max_replay_entries, 1_024,
            "the replay floor applies last"
        );
    }

    #[test]
    fn throughput_never_exceeds_the_hard_caps() {
        let capabilities = capabilities(64, 1_048_576, 1_048_576, 64 * 1024 * 1024 * 1024);
        let limits = SafetyLimits::default();
        let policy = derive_with_objective(
            &capabilities,
            ResourceMode::Dedicated,
            Objective::Throughput,
        );
        assert!(u64::from(policy.resource_governor.max_connections) <= limits.max_connections);
        assert!(u64::from(policy.relay.max_splice_relays) <= limits.max_splice_relays);
        assert!(policy.relay.max_pooled_buffers <= limits.max_pooled_buffers as usize);
        assert!(
            policy.relay.max_relay_memory_bytes <= capabilities.memory_total_bytes / 4,
            "the memory ceiling bounds the scaled relay budget"
        );
    }

    fn report(
        available_cpus: usize,
        fd_soft_limit: u64,
        fd_hard_limit: u64,
        memory_total: u64,
    ) -> crate::runtime::machine::MachineReport {
        crate::runtime::machine::MachineReport {
            fd_soft_limit,
            fd_hard_limit,
            memlock_soft_limit: 0,
            memlock_hard_limit: 0,
            available_cpus,
            cpu_quota_us: None,
            cpu_period_us: None,
            cpuset_effective: None,
            memory_source: "test",
            memory_current: None,
            memory_high: None,
            memory_max: None,
            memory_total,
        }
    }

    #[test]
    fn fixed_mode_returns_the_limits_verbatim() {
        let machine = report(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
        let mut limits = PolicyConfig::default();
        limits.resource_governor.max_connections = 100_000;
        let tuning = TuningConfig {
            mode: Some(TuningMode::Fixed),
            objective: Objective::Throughput,
        };
        let resolution = resolve_policy(&limits, &tuning, &machine, ResourceMode::Standard, 1);
        assert_eq!(resolution.policy, limits, "fixed never derives");
        assert!(resolution.plan.is_none());
        assert!(
            resolution
                .fields
                .iter()
                .all(|field| field.source != FieldSource::Derived)
        );
        let pinned = resolution
            .fields
            .iter()
            .find(|field| field.field == "resourceGovernor.maxConnections")
            .expect("the field is reported");
        assert_eq!(pinned.value, 100_000);
        assert_eq!(pinned.source, FieldSource::Override);
    }

    #[test]
    fn startup_mode_derives_unpinned_fields_and_records_provenance() {
        let machine = report(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
        let limits = PolicyConfig::default();
        let tuning = TuningConfig::default();
        let resolution = resolve_policy(&limits, &tuning, &machine, ResourceMode::Standard, 1);
        let expected = StartupPlan::derive(
            &MachineCapabilities::from_report(&machine),
            &SafetyLimits::default(),
            ResourceMode::Standard,
            Objective::Balanced,
            1,
            Probes::default(),
            &limits,
        )
        .into_policy();
        // The booleans follow the derived platform capability; everything
        // else matches the derivation exactly when nothing is pinned.
        assert_eq!(resolution.policy, expected);
        for field in &resolution.fields {
            if field.field.contains("TimeoutMs")
                || field.field == "resourceGovernor.replayRetentionMs"
            {
                assert_eq!(
                    field.source,
                    FieldSource::Default,
                    "timeouts are never derived: {}",
                    field.field
                );
            } else {
                assert_eq!(
                    field.source,
                    FieldSource::Derived,
                    "an unpinned startup field derives: {}",
                    field.field
                );
            }
        }
        assert_eq!(resolution.policy.resource_governor.max_connections, 24_576);
        assert!(resolution.plan.is_some());
    }

    #[test]
    fn operator_pins_win_over_the_derivation_field_by_field() {
        let machine = report(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
        let mut limits = PolicyConfig::default();
        limits.resource_governor.max_connections = 100_000;
        limits.relay.buffer_bytes = 8 * 1024;
        let resolution = resolve_policy(
            &limits,
            &TuningConfig::default(),
            &machine,
            ResourceMode::Standard,
            1,
        );
        assert_eq!(resolution.policy.resource_governor.max_connections, 100_000);
        assert_eq!(resolution.policy.relay.buffer_bytes, 8 * 1024);
        assert_eq!(
            resolution.policy.resource_governor.max_handshakes, 512,
            "unpinned fields still derive"
        );
        let source_of = |name: &str| {
            resolution
                .fields
                .iter()
                .find(|field| field.field == name)
                .expect("the field is reported")
                .source
        };
        assert_eq!(
            source_of("resourceGovernor.maxConnections"),
            FieldSource::Override
        );
        assert_eq!(source_of("relay.bufferBytes"), FieldSource::Override);
        assert_eq!(
            source_of("resourceGovernor.maxHandshakes"),
            FieldSource::Derived
        );
        assert_eq!(
            source_of("resourceGovernor.handshakeTimeoutMs"),
            FieldSource::Default,
            "timeouts are carried from the configuration, never derived"
        );
    }

    #[test]
    fn the_conservative_machine_resolves_to_the_documented_floors() {
        let machine = crate::runtime::machine::MachineReport::conservative();
        let resolution = resolve_policy(
            &PolicyConfig::default(),
            &TuningConfig::default(),
            &machine,
            ResourceMode::Standard,
            1,
        );
        assert_eq!(resolution.policy.resource_governor.max_connections, 153);
        assert_eq!(resolution.policy.relay.buffer_bytes, 32 * 1024);
    }

    #[test]
    fn the_dedicated_profile_derives_a_wider_policy() {
        let machine = report(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
        let tuning = TuningConfig::default();
        let shared = resolve_policy(
            &PolicyConfig::default(),
            &tuning,
            &machine,
            ResourceMode::Standard,
            1,
        );
        let dedicated = resolve_policy(
            &PolicyConfig::default(),
            &tuning,
            &machine,
            ResourceMode::Dedicated,
            1,
        );
        assert!(
            dedicated.policy.resource_governor.max_connections
                > shared.policy.resource_governor.max_connections
        );
    }

    #[test]
    fn the_bootstrap_topology_matches_the_documented_sizing() {
        for (cpus, workers, blocking) in [
            (1, 1, 64),
            (4, 4, 64),
            (16, 16, 160),
            (60, 60, 512),
            (64, 64, 512),
            (128, 64, 512),
        ] {
            let topology = RuntimeTopology::for_mode(ResourceMode::Dedicated, cpus);
            assert_eq!(
                topology.worker_threads,
                Some(workers),
                "worker threads at {cpus} cpus"
            );
            assert_eq!(
                topology.max_blocking_threads,
                Some(blocking),
                "blocking threads at {cpus} cpus"
            );
        }
        let shared = RuntimeTopology::for_mode(ResourceMode::Standard, 4);
        assert_eq!(
            shared.worker_threads, None,
            "shared keeps the tokio default"
        );
        assert_eq!(shared.max_blocking_threads, None);
        assert_eq!(
            shared.effective_max_blocking_threads(),
            RuntimeTopology::TOKIO_DEFAULT_MAX_BLOCKING_THREADS
        );
    }

    #[test]
    fn the_buffer_tier_shift_is_bounded() {
        assert_eq!(super::shift_buffer_tier(16 * 1024, -1), 16 * 1024);
        assert_eq!(super::shift_buffer_tier(32 * 1024, -1), 16 * 1024);
        assert_eq!(super::shift_buffer_tier(32 * 1024, 1), 64 * 1024);
        assert_eq!(super::shift_buffer_tier(64 * 1024, 1), 64 * 1024);
        assert_eq!(super::shift_buffer_tier(64 * 1024, -1), 32 * 1024);
    }
}
