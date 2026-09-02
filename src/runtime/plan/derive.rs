//! The balanced derivation, and the objective that scales it.
//!
//! Order is the contract here: derive balanced, scale by objective, cap, then
//! floor. Reversing any two would let `throughput` exceed a machine-derived
//! ceiling or `latency` fall below a usable floor. The balanced derivation is
//! kept alongside the scaled one as [`PlannedPolicy::hard_bounds`], because
//! the adaptive controller needs a ceiling that does not move when an operator
//! changes objective.

use crate::{
    config::node::runtime::{LimitOverrides, Objective},
    runtime::policy::{
        DirectBarrierPolicy, EffectivePolicy, RelayPolicy, ResourceGovernorPolicy, ResourceMode,
        WarmConnectionPolicy,
    },
};

use super::inputs::{MachineCapabilities, SafetyLimits};

/// Userspace relay buffer size before the objective shift.
///
/// The middle of the three tiers [`shift_buffer_tier`] can select, and the
/// `RelayPolicy` default.
const DEFAULT_BUFFER_BYTES: usize = 32 * 1024;

/// The startup derivation: machine in, effective policy out.
pub struct StartupPlan;

impl StartupPlan {
    /// Derives the resource policy from machine capabilities, safety limits,
    /// the resource mode, and the tuning objective.
    ///
    /// `overrides` contributes the timeout fields: timeouts are protocol
    /// security parameters and are never machine-derived, so a pinned value
    /// is carried and an absent one takes its documented default. The
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
        overrides: &LimitOverrides,
    ) -> PlannedPolicy {
        let timeouts = ResourceGovernorPolicy::default();
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

        let buffer_bytes = DEFAULT_BUFFER_BYTES;
        let pipe_memory = max_pooled_pipes.saturating_mul(limits.pipe_pair_memory_bytes);
        let buffer_memory = relay_budget
            .saturating_sub(pipe_memory)
            .max(2 * buffer_bytes as u64);
        let max_pooled_buffers = (buffer_memory / buffer_bytes as u64)
            .clamp(2, limits.max_pooled_buffers)
            .min(max_connections.saturating_mul(2));
        let relay_memory =
            pipe_memory.saturating_add(max_pooled_buffers.saturating_mul(buffer_bytes as u64));

        let max_handshakes = cpus.saturating_mul(128).min(max_connections).max(1);
        let max_crypto_operations = cpus.saturating_mul(32).min(max_handshakes).max(1);
        let max_fallbacks = max_connections.min(cpus.saturating_mul(128).max(64));
        let max_dns_lookups = max_connections.min(cpus.saturating_mul(32).max(16));
        let max_replay_entries = max_connections.saturating_mul(4).clamp(1_024, 1_000_000);
        let max_direct_concurrent = max_connections.min(cpus.saturating_mul(512).max(64));
        let max_direct_per_second = cpus.saturating_mul(2_048).clamp(64, u64::from(u32::MAX));

        // Warm-connection sizing follows the machine for the same reason the
        // admission ceilings do. At eight effective CPUs this reproduces the
        // values the previous fixed defaults used, so an ordinary host keeps
        // the behaviour it had while a small or large one now scales.
        let warm_max_ready = cpus.saturating_mul(32).clamp(1, 4_096).min(max_connections);
        let warm_max_connecting = cpus.saturating_mul(8).clamp(1, 1_024).min(warm_max_ready);
        let warm_defaults = WarmConnectionPolicy::default();

        let policy = EffectivePolicy {
            governor: ResourceGovernorPolicy {
                max_connections: to_u32(max_connections),
                max_handshakes: to_u32(max_handshakes),
                max_pre_auth_idle_connections: to_u32(max_handshakes.min(max_connections)),
                max_fallbacks: to_u32(max_fallbacks),
                max_crypto_operations: to_u32(max_crypto_operations),
                max_replay_entries: to_u32(max_replay_entries),
                max_dns_lookups: to_u32(max_dns_lookups),
                replay_retention_ms: timeouts.replay_retention_ms,
                client_hello_timeout_ms: overrides
                    .client_hello_timeout_ms
                    .unwrap_or(timeouts.client_hello_timeout_ms),
                handshake_timeout_ms: overrides
                    .handshake_timeout_ms
                    .unwrap_or(timeouts.handshake_timeout_ms),
                connect_timeout_ms: overrides
                    .connect_timeout_ms
                    .unwrap_or(timeouts.connect_timeout_ms),
                fallback_timeout_ms: overrides
                    .fallback_timeout_ms
                    .unwrap_or(timeouts.fallback_timeout_ms),
            },
            direct_barrier: DirectBarrierPolicy {
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
            warm_connections: WarmConnectionPolicy {
                min_ready: warm_defaults.min_ready.min(to_u32(warm_max_ready)),
                max_ready: to_u32(warm_max_ready),
                max_connecting: to_u32(warm_max_connecting),
                refill_batch: warm_defaults.refill_batch.min(to_u32(warm_max_connecting)),
                ..warm_defaults
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
    policy: EffectivePolicy,
    hard_bounds: EffectivePolicy,
}

impl PlannedPolicy {
    /// Returns the derived effective policy.
    #[must_use]
    pub const fn policy(&self) -> &EffectivePolicy {
        &self.policy
    }

    /// Returns the balanced-mode derivation: the ceiling set the adaptive
    /// controller may never exceed, independent of the configured objective.
    #[must_use]
    pub const fn hard_bounds(&self) -> &EffectivePolicy {
        &self.hard_bounds
    }

    /// Consumes the plan and returns the effective policy.
    #[must_use]
    pub fn into_policy(self) -> EffectivePolicy {
        self.policy
    }
}

/// Per-field objective multipliers (design §1.2), as numerator/denominator
/// pairs so the scaling stays exact integer math. Fields absent here are
/// objective-invariant.
#[derive(Clone, Copy, Debug)]
pub(super) struct ObjectiveMultipliers {
    pub(super) connections: (u64, u64),
    pub(super) fallbacks: (u64, u64),
    pub(super) direct_concurrent: (u64, u64),
    pub(super) direct_per_second: (u64, u64),
    pub(super) pooled_buffers: (u64, u64),
    pub(super) splice_relays: (u64, u64),
    pub(super) relay_memory: (u64, u64),
    /// Buffer-tier shift: -1 one tier down, 0 the probe tier, +1 one tier up.
    pub(super) buffer_tier_shift: i8,
}

/// Returns the multiplier set for one objective.
///
/// `maxHandshakes`, `maxCryptoOperations`, and `maxDnsLookups` are
/// objective-invariant (×1); `maxReplayEntries` follows the scaled
/// `maxConnections`; `bufferBytes` moves one probe tier per step instead of
/// scaling.
pub(super) fn multipliers(objective: Objective) -> ObjectiveMultipliers {
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
    balanced: &EffectivePolicy,
    objective: Objective,
    limits: &SafetyLimits,
    capabilities: &MachineCapabilities,
) -> EffectivePolicy {
    if objective == Objective::Balanced {
        return balanced.clone();
    }
    let multipliers = multipliers(objective);
    let governor = &balanced.governor;
    let max_connections = scale(u64::from(governor.max_connections), multipliers.connections)
        .clamp(64, limits.max_connections);
    let max_handshakes = u64::from(governor.max_handshakes)
        .min(max_connections)
        .max(1);
    let max_pre_auth_idle_connections = u64::from(governor.max_pre_auth_idle_connections)
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

    EffectivePolicy {
        governor: ResourceGovernorPolicy {
            max_connections: to_u32(max_connections),
            max_handshakes: to_u32(max_handshakes),
            max_pre_auth_idle_connections: to_u32(max_pre_auth_idle_connections),
            max_fallbacks: to_u32(max_fallbacks),
            max_crypto_operations: to_u32(max_crypto_operations),
            max_replay_entries: to_u32(max_replay_entries),
            max_dns_lookups: to_u32(max_dns_lookups),
            ..governor.clone()
        },
        direct_barrier: DirectBarrierPolicy {
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
        warm_connections: balanced.warm_connections,
    }
}

/// Moves one buffer tier per objective step, bounded by the slowest and
/// fastest tiers the relay is willing to run.
fn shift_buffer_tier(buffer_bytes: usize, shift: i8) -> usize {
    const TIERS: [usize; 3] = [16 * 1024, 32 * 1024, 64 * 1024];
    let index = TIERS
        .iter()
        .position(|tier| *tier >= buffer_bytes)
        .unwrap_or(TIERS.len() - 1);
    let shifted = (index as i8 + shift).clamp(0, (TIERS.len() - 1) as i8);
    TIERS[shifted as usize]
}

fn to_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::shift_buffer_tier;

    #[test]
    fn the_objective_shift_cannot_leave_the_three_tiers() {
        // The relay runs at one of exactly three buffer sizes, and the pool
        // arithmetic above is sized against them. The objective moves between
        // them and saturates at both ends rather than inventing a fourth.
        assert_eq!(shift_buffer_tier(32 * 1024, 0), 32 * 1024);
        assert_eq!(shift_buffer_tier(32 * 1024, 1), 64 * 1024);
        assert_eq!(shift_buffer_tier(32 * 1024, -1), 16 * 1024);
        assert_eq!(shift_buffer_tier(64 * 1024, -1), 32 * 1024);
        assert_eq!(
            shift_buffer_tier(64 * 1024, 1),
            64 * 1024,
            "the fastest tier is the ceiling"
        );
        assert_eq!(
            shift_buffer_tier(16 * 1024, -1),
            16 * 1024,
            "the slowest tier is the floor"
        );
    }
}
