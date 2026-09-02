//! What this process decided it may consume, decided once before the first
//! listener binds.
//!
//! Two questions are answered here and never again: how many descriptors this
//! process may hold, and whether it owns the machine well enough to raise its
//! own soft limit and watch memory. Both answers are cold — a reload reuses
//! them rather than re-deriving — because every admission ceiling, pool, and
//! barrier was constructed against them. The monitors that keep the answers
//! honest at runtime live in [`super::monitor`].

use crate::{
    config::{NodeConfig, node::runtime::RuntimeProfile},
    runtime::{
        FdBudgetError, FdBudgetPlan, FdHeadroomPolicy, FixedFdReserve,
        machine::{self, MachineReport, MemoryPlan, MemorySampler},
        policy::{EffectivePolicy, ResourceMode, resolve_resource_mode},
    },
    transport::FdBudget,
};

/// Computes the configured worst-case simultaneous descriptor demand.
///
/// Every term is a configured bound, and the sum is deliberately pessimistic:
/// it assumes every connection simultaneously holds an inbound socket and two
/// racing outbound candidates, that every splice relay is armed at once, and
/// that the pipe pool retains its full keep count of drained pipes afterwards.
/// The winning candidate retains the same unit as the established outbound.
/// The number is used only to decide whether to warn about clamping; it never
/// raises the admission budget.
pub(super) fn theoretical_fd_peak(node: &NodeConfig, policy: &EffectivePolicy) -> u64 {
    let connections = u64::from(policy.governor.max_connections);
    let splice = u64::from(policy.relay.max_splice_relays)
        .saturating_mul(u64::from(crate::transport::UNITS_SPLICE_RELAY));
    // A pooled pipe holds its two descriptors past the relay that created it,
    // so the pool's retention is steady-state demand the peak must include.
    let pool_retention = if policy.relay.splice && policy.relay.pipe_pool {
        u64::from(policy.relay.max_pooled_pipes)
            .saturating_mul(u64::from(crate::transport::UNITS_SPLICE_DIRECTION))
    } else {
        0
    };
    // Every eligible transport pool retains at most maxReady established descriptors.
    // A speculative Happy Eyeballs dial can transiently hold two candidates,
    // so account maxConnecting twice. Checked-out sockets replace a normal
    // per-connection cover dial and are already covered by the connection term.
    let pool_count = u64::try_from(maximum_warm_pool_count(node)).unwrap_or(u64::MAX);
    let warm = &policy.warm_connections;
    let warm_transport = pool_count.saturating_mul(
        u64::from(warm.max_ready).saturating_add(u64::from(warm.max_connecting).saturating_mul(2)),
    );
    connections
        .saturating_mul(3)
        .saturating_add(splice)
        .saturating_add(pool_retention)
        .saturating_add(warm_transport)
}

/// The largest number of warm TCP pools one generation can create.
///
/// An entry node keeps at most one cover pool; every declared outbound that
/// pre-establishes connections keeps one more.
pub(super) fn maximum_warm_pool_count(node: &NodeConfig) -> usize {
    let cover = usize::from(node.as_entry().is_some());
    let declared = match node {
        NodeConfig::Entry(entry) => entry.outbounds.as_ref(),
        NodeConfig::Landing(landing) => landing.outbounds.as_ref(),
    };
    let outbound = declared
        .into_iter()
        .flatten()
        .filter(|(_, outbound)| outbound.warm_tcp())
        .count();
    cover.saturating_add(outbound)
}

/// Everything the startup resource derivation decided, before any listener
/// is bound.
pub(super) struct ResourceStartup {
    pub(super) plan: FdBudgetPlan,
    pub(super) budget: FdBudget,
    pub(super) resource_mode: ResourceMode,
    pub(super) machine: MachineReport,
    pub(super) fd_effective_soft_limit: u64,
    pub(super) fd_soft_raise_attempted: bool,
    pub(super) fd_soft_limit_raised: bool,
    pub(super) memory: Option<MemoryWatch>,
}

/// The bounded memory signal the pressure monitor samples.
#[derive(Clone)]
pub(super) struct MemoryWatch {
    pub(super) sampler: MemorySampler,
    pub(super) plan: MemoryPlan,
}

/// Derives the process descriptor budget before any listener is bound.
///
/// In standard resource mode this is exactly the historical derivation from
/// the inherited soft limit. In dedicated mode the process first raises its
/// own soft `RLIMIT_NOFILE` to the hard limit — a process-local, privilege-
/// free adjustment — and plans against the relaxed dedicated headroom. A
/// failed raise is logged through the machine report and the derivation
/// continues with the effective soft limit. The effective mode and the
/// machine view come from the caller: the bootstrap resolves both before the
/// Tokio runtime exists so the runtime topology and the policy derivation
/// share one detection.
pub(super) fn derive_fd_budget(
    node: &NodeConfig,
    policy: &EffectivePolicy,
    resource_mode: ResourceMode,
    mut machine: MachineReport,
) -> Result<ResourceStartup, FdBudgetError> {
    let listeners = node
        .listeners()
        .iter()
        .map(|listener| listener.bind_addresses().len())
        .try_fold(0_u64, |total, count| {
            u64::try_from(count)
                .ok()
                .and_then(|count| total.checked_add(count))
                .ok_or(())
        })
        .unwrap_or(u64::MAX);
    let reserve = FixedFdReserve::new(listeners);
    let dedicated = resource_mode == ResourceMode::Dedicated;
    if !dedicated {
        let limit = read_descriptor_limit();
        machine.fd_soft_limit = limit.0;
        machine.fd_hard_limit = limit.1;
    }

    #[cfg(target_os = "linux")]
    let (raise_attempted, raised, effective_soft, effective_hard) = {
        let mut attempted = false;
        let mut raised = false;
        let mut soft = machine.fd_soft_limit;
        let mut hard = machine.fd_hard_limit;
        if dedicated && let Some(target) = machine::soft_limit_raise_target(soft, hard) {
            attempted = true;
            if let Ok(limit) = rr_linux::raise_descriptor_soft_limit(target) {
                raised = limit.soft > soft;
                soft = limit.soft;
                hard = limit.hard;
            }
            // A failed raise is not fatal: the report records it and the plan
            // below derives from the effective soft limit, whatever it is.
        }
        (attempted, raised, soft, hard)
    };
    #[cfg(not(target_os = "linux"))]
    let (raise_attempted, raised, effective_soft, effective_hard) =
        (false, false, machine.fd_soft_limit, machine.fd_hard_limit);

    let headroom_policy = if dedicated {
        FdHeadroomPolicy::Dedicated
    } else {
        FdHeadroomPolicy::Standard
    };
    let plan = FdBudgetPlan::derive(
        effective_soft,
        effective_hard,
        reserve,
        theoretical_fd_peak(node, policy),
        headroom_policy,
    )?;
    let budget = FdBudget::new(plan.effective_budget());
    let memory = if dedicated {
        MemoryPlan::derive(machine.memory_total).map(|plan| MemoryWatch {
            sampler: machine.memory_sampler(),
            plan,
        })
    } else {
        None
    };
    Ok(ResourceStartup {
        plan,
        budget,
        resource_mode,
        fd_effective_soft_limit: effective_soft,
        fd_soft_raise_attempted: raise_attempted,
        fd_soft_limit_raised: raised,
        machine,
        memory,
    })
}

/// Resolves the effective startup resource mode and the machine view it was
/// resolved against.
///
/// The machine is always measured. Every profile now derives its numeric
/// policy from the measured view, `auto` additionally needs the cgroup
/// tenancy boundary to choose a mode, and a dedicated outcome budgets against
/// it — so there is no profile left that can decide anything without looking.
/// [`MachineReport::conservative`] survives as the *detection* fallback inside
/// the report, not as a branch here.
pub(super) fn resolve_startup_resource_mode(
    profile: RuntimeProfile,
) -> (ResourceMode, MachineReport) {
    let machine = MachineReport::detect();
    (resolve_resource_mode(profile, &machine), machine)
}

/// Reads the process descriptor limit, falling back to a conservative default.
///
/// A platform that cannot report a limit is treated as if it had the
/// conservative POSIX minimum rather than as if it had no limit, because
/// assuming abundance is exactly how the incident happened.
fn read_descriptor_limit() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        let limit = rr_linux::descriptor_limit();
        (limit.soft, limit.hard)
    }
    #[cfg(not(target_os = "linux"))]
    {
        (1_024, 1_024)
    }
}

#[cfg(test)]
mod tests {
    use super::{resolve_startup_resource_mode, theoretical_fd_peak};
    use crate::{
        config::node::runtime::RuntimeProfile,
        runtime::{machine::MachineReport, policy::ResourceMode},
        server::production::fixture::entry_config,
    };

    #[test]
    fn the_theoretical_peak_includes_pipe_pool_retention() {
        let node = entry_config(8443).into_node();
        let mut policy = crate::runtime::policy::EffectivePolicy::default();
        policy.relay.splice = true;
        policy.relay.pipe_pool = true;
        policy.relay.max_splice_relays = 4;
        policy.relay.max_pooled_pipes = 8;
        let connections = u64::from(policy.governor.max_connections) * 3;
        let warm = u64::from(policy.warm_connections.max_ready)
            + u64::from(policy.warm_connections.max_connecting) * 2;

        assert_eq!(
            theoretical_fd_peak(&node, &policy),
            connections + 4 * 4 + 8 * 2 + warm,
            "active flows, warm cover candidates, armed splice relays, and retained pipes are demand"
        );

        policy.relay.pipe_pool = false;
        assert_eq!(
            theoretical_fd_peak(&node, &policy),
            connections + 4 * 4 + warm,
            "a disabled pool retains nothing"
        );

        policy.relay.pipe_pool = true;
        policy.relay.splice = false;
        assert_eq!(
            theoretical_fd_peak(&node, &policy),
            connections + 4 * 4 + warm,
            "without splice there is no pool to retain pipes"
        );
    }

    #[test]
    fn startup_resource_mode_resolution_follows_the_profile() {
        // Derivation always runs now, so the measured view is always needed
        // and every profile plans against the real machine.
        let (mode, _) = resolve_startup_resource_mode(RuntimeProfile::Shared);
        assert_eq!(mode, ResourceMode::Standard);

        let (mode, _) = resolve_startup_resource_mode(RuntimeProfile::Dedicated);
        assert_eq!(mode, ResourceMode::Dedicated);

        // Auto agrees with the detected tenancy boundary, whatever the test
        // machine looks like.
        let (mode, machine) = resolve_startup_resource_mode(RuntimeProfile::Auto);
        let expected = if machine.tenancy_boundary_observable() {
            ResourceMode::Dedicated
        } else {
            ResourceMode::Standard
        };
        assert_eq!(mode, expected);

        #[cfg(target_os = "linux")]
        {
            let (_, machine) = resolve_startup_resource_mode(RuntimeProfile::Shared);
            assert_ne!(
                machine,
                MachineReport::conservative(),
                "derivation never plans against the conservative fallback on a readable host"
            );
        }
    }
}
