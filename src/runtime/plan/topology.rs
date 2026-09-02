//! How many threads the Tokio runtime gets.
//!
//! Decided at bootstrap, before the runtime exists, because tokio cannot
//! resize either pool afterwards. Kept apart from the resource policy because
//! it answers a different question: the policy bounds what this process
//! admits, this bounds what it schedules.

use crate::runtime::policy::ResourceMode;

/// Tokio runtime sizing decided at bootstrap, before the runtime exists.
///
/// The runtime is built once and tokio cannot resize either pool afterwards,
/// so these are cold settings (design §4.4). `None` keeps the tokio default,
/// which is what a shared or standard posture uses: a process sharing the
/// host has no business sizing its own thread pools. The dedicated posture
/// sizes both from the cgroup-aware CPU view (design §4.2).
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
