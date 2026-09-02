//! What the derivation is allowed to look at, and what it may never exceed.
//!
//! Two inputs, and the split between them is the point. [`MachineCapabilities`]
//! is measurement — what this host actually offers. [`SafetyLimits`] is
//! judgement — the absolute ceilings and reserves this project is willing to
//! plan within, whatever a host claims. A machine that reports a million
//! descriptors does not get a million-connection policy.

use crate::runtime::{machine::MachineReport, policy::ResourceMode};

const MEBIBYTE: u64 = 1024 * 1024;

/// Machine inputs the policy derivation budgets against.
///
/// Built directly from a [`MachineReport`], so `explain` and serve startup
/// budget against one view of the host — including the cgroup-aware
/// [`MachineReport::effective_cpus`] math, which is what makes a container
/// with a CPU quota plan against its quota rather than its host.
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
            pipe_pair_memory_bytes: 2 * 512 * 1024,
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
