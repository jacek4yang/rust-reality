//! The derivation's regression fence.
//!
//! These vectors exist so a change to any divisor, clamp, floor, or cap has
//! to be a deliberate edit to a number written down here, not a silent drift
//! in what a deployed node admits.

use super::{
    FieldSource, MachineCapabilities, RuntimeTopology, SafetyLimits, StartupPlan, resolve_policy,
};
use crate::{
    config::node::runtime::{LimitOverrides, Objective},
    runtime::policy::{EffectivePolicy, ResourceGovernorPolicy, ResourceMode},
};

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
) -> EffectivePolicy {
    StartupPlan::derive(
        capabilities,
        &SafetyLimits::default(),
        mode,
        Objective::Balanced,
        listener_count,
        &LimitOverrides::default(),
    )
    .into_policy()
}

#[test]
fn the_golden_shared_machine_vector_is_stable() {
    // Four effective CPUs, 4 GiB, 64k/1M descriptors, standard mode, one
    // listener. This vector is the regression fence on the arithmetic:
    // any change to a divisor, clamp, or floor moves one of these three.
    let capabilities = capabilities(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);

    let policy = derive(&capabilities, ResourceMode::Standard, 1);

    assert_eq!(policy.relay.buffer_bytes, 32 * 1024);
    assert_eq!(policy.governor.max_connections, 24_576);
    assert!(policy.relay.max_splice_relays <= policy.governor.max_connections);
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
            &LimitOverrides::default(),
        );
        let balanced = StartupPlan::derive(
            &capabilities,
            &SafetyLimits::default(),
            ResourceMode::Standard,
            Objective::Balanced,
            1,
            &LimitOverrides::default(),
        );
        assert_eq!(
            plan.hard_bounds(),
            balanced.policy(),
            "hard bounds are the balanced derivation for {objective:?}"
        );
    }
}

#[test]
fn the_conservative_machine_hits_the_floors_and_caps() {
    // 1 CPU, 1 024 descriptors, no readable memory: the golden
    // tiny-machine vector, where every floor and cap binds at once.
    let report = crate::runtime::machine::MachineReport::conservative();
    let capabilities = MachineCapabilities::from_report(&report);
    let policy = derive(&capabilities, ResourceMode::Standard, 1);
    assert_eq!(policy.governor.max_connections, 197);
    assert_eq!(policy.governor.max_handshakes, 128);
    assert_eq!(policy.governor.max_crypto_operations, 32);
    assert_eq!(policy.governor.max_fallbacks, 128);
    assert_eq!(policy.governor.max_dns_lookups, 32);
    assert_eq!(policy.governor.max_replay_entries, 1_024);
    assert_eq!(policy.relay.buffer_bytes, 32 * 1024);
    assert_eq!(policy.relay.max_splice_relays, 64);
    assert_eq!(policy.relay.max_pooled_pipes, 128);
    assert_eq!(policy.relay.max_pooled_buffers, 394);
    assert_eq!(policy.relay.max_relay_memory_bytes, 147_128_320);
}

#[test]
fn the_dedicated_mode_budgets_against_the_hard_limit() {
    let capabilities = capabilities(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
    let standard = derive(&capabilities, ResourceMode::Standard, 1);
    let dedicated = derive(&capabilities, ResourceMode::Dedicated, 1);
    assert!(
        dedicated.governor.max_connections > standard.governor.max_connections,
        "the hard limit and the /10 headroom must widen the plan"
    );
}

#[test]
fn an_unknown_memory_total_disables_the_memory_dimension() {
    let capabilities = capabilities(8, 1_048_576, 1_048_576, 0);
    let policy = derive(&capabilities, ResourceMode::Dedicated, 1);
    assert_eq!(
        policy.governor.max_connections, 262_144,
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
    let policy = derive(&capabilities, ResourceMode::Dedicated, 1);
    assert!(u64::from(policy.governor.max_connections) <= limits.max_connections);
    assert!(u64::from(policy.relay.max_splice_relays) <= limits.max_splice_relays);
    assert!(policy.relay.max_pooled_buffers <= limits.max_pooled_buffers as usize);
}

#[test]
fn a_pinned_timeout_is_carried_verbatim_through_derivation() {
    let capabilities = capabilities(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
    let overrides = LimitOverrides {
        handshake_timeout_ms: Some(42_000),
        ..LimitOverrides::default()
    };
    let policy = StartupPlan::derive(
        &capabilities,
        &SafetyLimits::default(),
        ResourceMode::Standard,
        Objective::Balanced,
        1,
        &overrides,
    )
    .into_policy();
    assert_eq!(policy.governor.handshake_timeout_ms, 42_000);
    assert_eq!(
        policy.governor.replay_retention_ms,
        ResourceGovernorPolicy::default().replay_retention_ms,
        "replay retention is derived, so it keeps its default"
    );
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

fn derive_with_objective(
    capabilities: &MachineCapabilities,
    mode: ResourceMode,
    objective: Objective,
) -> EffectivePolicy {
    StartupPlan::derive(
        capabilities,
        &SafetyLimits::default(),
        mode,
        objective,
        1,
        &LimitOverrides::default(),
    )
    .into_policy()
}

/// The validator's numeric invariants, mirrored so every derived and
/// scaled policy proves it would pass `validate_config`.
fn assert_policy_invariants(policy: &EffectivePolicy) {
    let governor = &policy.governor;
    assert!(governor.max_connections >= 64);
    assert!(governor.max_handshakes >= 1);
    assert!(governor.max_handshakes <= governor.max_connections);
    assert!(governor.max_pre_auth_idle_connections >= 1);
    assert!(governor.max_pre_auth_idle_connections <= governor.max_connections);
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
        u64::from(policy.relay.max_pooled_pipes) * SafetyLimits::default().pipe_pair_memory_bytes
    } else {
        u64::from(policy.relay.max_splice_relays)
            * 2
            * SafetyLimits::default().pipe_pair_memory_bytes
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
    let latency = derive_with_objective(&capabilities, ResourceMode::Standard, Objective::Latency);
    let balanced =
        derive_with_objective(&capabilities, ResourceMode::Standard, Objective::Balanced);
    let throughput =
        derive_with_objective(&capabilities, ResourceMode::Standard, Objective::Throughput);

    // The documented multipliers on the golden machine.
    assert_eq!(balanced.governor.max_connections, 24_576);
    assert_eq!(latency.governor.max_connections, 12_288);
    assert_eq!(throughput.governor.max_connections, 36_864);
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
        assert_eq!(policy.governor.max_handshakes, 512);
        assert_eq!(policy.governor.max_crypto_operations, 128);
        assert_eq!(policy.governor.max_dns_lookups, 128);
        assert_eq!(
            policy.governor.max_replay_entries,
            policy.governor.max_connections * 4
        );
    }

    // Monotonicity across the scaled fields.
    for (lo, mid, hi) in [
        (
            latency.governor.max_connections,
            balanced.governor.max_connections,
            throughput.governor.max_connections,
        ),
        (
            latency.governor.max_fallbacks,
            balanced.governor.max_fallbacks,
            throughput.governor.max_fallbacks,
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
            policy.governor.max_connections >= 64,
            "the connection floor survives {objective:?}"
        );
    }
    let latency = derive_with_objective(&capabilities, ResourceMode::Standard, Objective::Latency);
    assert_eq!(latency.governor.max_connections, 98);
    assert_eq!(
        latency.governor.max_handshakes, 98,
        "the child limit re-clamps to the scaled parent"
    );
    assert_eq!(
        latency.governor.max_replay_entries, 1_024,
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
    assert!(u64::from(policy.governor.max_connections) <= limits.max_connections);
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
fn derivation_always_runs_and_records_its_provenance() {
    let machine = report(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
    let resolution = resolve_policy(
        &LimitOverrides::default(),
        Objective::Balanced,
        &machine,
        ResourceMode::Standard,
        1,
    );
    let expected = StartupPlan::derive(
        &MachineCapabilities::from_report(&machine),
        &SafetyLimits::default(),
        ResourceMode::Standard,
        Objective::Balanced,
        1,
        &LimitOverrides::default(),
    )
    .into_policy();

    assert_eq!(resolution.policy, expected);
    assert!(
        resolution.plan.is_some(),
        "there is one policy channel, so an absent limit always derives"
    );
    for field in &resolution.fields {
        let expected_source =
            if field.field.ends_with("TimeoutMs") || field.field.ends_with("RetentionMs") {
                FieldSource::Default
            } else {
                FieldSource::Derived
            };
        assert_eq!(
            field.source, expected_source,
            "{} reported the wrong provenance",
            field.field
        );
        assert!(!field.source.is_operator_pinned());
    }
}

#[test]
fn a_pin_wins_over_the_derivation_and_reports_itself() {
    let machine = report(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
    let overrides = LimitOverrides {
        max_connections: Some(100_000),
        ..LimitOverrides::default()
    };
    let resolution = resolve_policy(
        &overrides,
        Objective::Balanced,
        &machine,
        ResourceMode::Standard,
        1,
    );

    assert_eq!(resolution.policy.governor.max_connections, 100_000);
    let pinned = resolution
        .fields
        .iter()
        .find(|field| field.field == "governor.maxConnections")
        .expect("the field is reported");
    assert_eq!(pinned.source, FieldSource::Pinned);
    assert!(pinned.source.is_operator_pinned());
    assert_eq!(pinned.multiplier, None, "a pin is not scaled");
}

#[test]
fn a_pin_does_not_disturb_its_siblings() {
    let machine = report(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
    let derived = resolve_policy(
        &LimitOverrides::default(),
        Objective::Balanced,
        &machine,
        ResourceMode::Standard,
        1,
    );
    let pinned = resolve_policy(
        &LimitOverrides {
            max_connections: Some(100_000),
            ..LimitOverrides::default()
        },
        Objective::Balanced,
        &machine,
        ResourceMode::Standard,
        1,
    );

    assert_ne!(
        derived.policy.governor.max_connections,
        pinned.policy.governor.max_connections
    );
    assert_eq!(
        derived.policy.governor.max_handshakes, pinned.policy.governor.max_handshakes,
        "pinning one field must not move another"
    );
    assert_eq!(derived.policy.relay, pinned.policy.relay);
}

#[test]
fn a_pin_equal_to_the_derived_value_is_still_a_pin() {
    // This is the case the previous two-channel model could not express,
    // and the reason presence rather than inequality is the signal.
    let machine = report(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
    let derived = resolve_policy(
        &LimitOverrides::default(),
        Objective::Balanced,
        &machine,
        ResourceMode::Standard,
        1,
    );
    let same = derived.policy.governor.max_connections;
    let resolution = resolve_policy(
        &LimitOverrides {
            max_connections: Some(same),
            ..LimitOverrides::default()
        },
        Objective::Balanced,
        &machine,
        ResourceMode::Standard,
        1,
    );

    assert_eq!(resolution.policy.governor.max_connections, same);
    let field = resolution
        .fields
        .iter()
        .find(|field| field.field == "governor.maxConnections")
        .expect("the field is reported");
    assert_eq!(field.source, FieldSource::Pinned);
}

#[test]
fn pinned_timeouts_replace_the_default_they_would_otherwise_report() {
    let machine = report(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
    let resolution = resolve_policy(
        &LimitOverrides {
            handshake_timeout_ms: Some(15_000),
            ..LimitOverrides::default()
        },
        Objective::Balanced,
        &machine,
        ResourceMode::Standard,
        1,
    );

    assert_eq!(resolution.policy.governor.handshake_timeout_ms, 15_000);
    let pinned = resolution
        .fields
        .iter()
        .find(|field| field.field == "governor.handshakeTimeoutMs")
        .expect("the field is reported");
    assert_eq!(pinned.source, FieldSource::Pinned);
    let unpinned = resolution
        .fields
        .iter()
        .find(|field| field.field == "governor.connectTimeoutMs")
        .expect("the field is reported");
    assert_eq!(
        unpinned.source,
        FieldSource::Default,
        "a timeout the derivation does not produce reports its default"
    );
}

#[test]
fn disabling_splice_also_disables_the_pipe_pool_it_would_fill() {
    let machine = report(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
    let resolution = resolve_policy(
        &LimitOverrides {
            splice: Some(false),
            ..LimitOverrides::default()
        },
        Objective::Balanced,
        &machine,
        ResourceMode::Standard,
        1,
    );

    assert!(!resolution.policy.relay.splice);
    assert!(
        !resolution.policy.relay.pipe_pool,
        "a pipe pool with no splice would reserve pipes nothing can use"
    );
}

#[test]
fn the_conservative_machine_resolves_to_the_documented_floors() {
    let machine = crate::runtime::machine::MachineReport::conservative();
    let resolution = resolve_policy(
        &LimitOverrides::default(),
        Objective::Balanced,
        &machine,
        ResourceMode::Standard,
        1,
    );
    assert_eq!(resolution.policy.governor.max_connections, 197);
    assert_eq!(resolution.policy.relay.buffer_bytes, 32 * 1024);
}

#[test]
fn the_dedicated_profile_derives_a_wider_policy() {
    let machine = report(4, 65_536, 1_048_576, 4 * 1024 * 1024 * 1024);
    let shared = resolve_policy(
        &LimitOverrides::default(),
        Objective::Balanced,
        &machine,
        ResourceMode::Standard,
        1,
    );
    let dedicated = resolve_policy(
        &LimitOverrides::default(),
        Objective::Balanced,
        &machine,
        ResourceMode::Dedicated,
        1,
    );
    assert!(dedicated.policy.governor.max_connections > shared.policy.governor.max_connections);
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
