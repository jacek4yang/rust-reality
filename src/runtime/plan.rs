//! Startup resource-policy derivation shared by the CLI autotuner and
//! (from the startup-derivation slice) server startup.
//!
//! Everything here is pure: the same capabilities, limits, mode, probe
//! inputs, and overrides always produce the same plan, and nothing touches
//! the host. `config autotune` feeds measured benchmark and loopback probes;
//! serve startup passes [`Probes::default`], which selects the conservative
//! fallback tiers. Both callers share the exact formulas the v1.5 autotuner
//! shipped, so a plan derived without probes never invents numbers the
//! autotuner would not.
//!
//! Deferred to later v1.6 slices (design §1.2, §3.5): the objective
//! multipliers and the per-field [`PolicyConfig`] provenance record. Until
//! they land, [`PlannedPolicy::hard_bounds`] — the balanced-mode derivation
//! the adaptive controller may never exceed — equals the derived policy.

use serde::Serialize;

use crate::{
    config::{
        DirectBarrierConfig, PolicyConfig, RelayPolicy, ResourceGovernorConfig, ResourceMode,
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
    /// the resource mode, and whatever probes the caller measured.
    ///
    /// `overrides` contributes the timeout fields verbatim: timeouts are
    /// protocol security parameters and are never machine-derived. Every
    /// numeric field is bounded by `limits`, and safety floors apply last,
    /// so a tiny or unobservable machine still gets a usable plan.
    #[must_use]
    pub fn derive(
        capabilities: &MachineCapabilities,
        limits: &SafetyLimits,
        mode: ResourceMode,
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
            hard_bounds: policy.clone(),
            policy,
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
    /// controller may never exceed. Until objective scaling lands it equals
    /// [`PlannedPolicy::policy`].
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

#[cfg(test)]
mod tests {
    use super::{MachineCapabilities, Probes, SafetyLimits, StartupPlan};
    use crate::config::{PolicyConfig, ResourceMode};

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
    fn the_hard_bounds_equal_the_policy_until_objectives_land() {
        let capabilities = capabilities(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
        let plan = StartupPlan::derive(
            &capabilities,
            &SafetyLimits::default(),
            ResourceMode::Standard,
            1,
            Probes::default(),
            &PolicyConfig::default(),
        );
        assert_eq!(plan.hard_bounds(), plan.policy());
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
}
