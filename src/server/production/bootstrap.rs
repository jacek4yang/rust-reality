//! Startup: from a validated configuration to a bound-ready server.
//!
//! This runs once, before any listener exists, and it is where every
//! process-lifetime decision is made — the machine view, the resource mode,
//! the effective policy, the admission authorities, the descriptor budget,
//! the shared resolver, and the replay caches. Everything downstream borrows
//! those; nothing rebuilds them.
//!
//! It is also where the startup report is written. An operator who reads
//! nothing else should still learn from the journal what this process decided
//! about the machine it landed on.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, atomic::AtomicU64},
    time::Duration,
};

use arc_swap::ArcSwap;

use crate::{
    config::{
        NodeConfig, ValidatedConfig, node::landing::LandingProtocol, node::listener::ListenFamily,
    },
    logging::LogEvent,
    network::{DialTuning, NetworkEnvironment},
    protocol::{handoff::HandoffReplayCache, reality::ReplayCache},
    runtime::{
        DirectBarrier, PressureGauge, ResourceGovernor,
        machine::MachineReport,
        plan,
        policy::{RelayPolicy, ResourceMode, resolve_resource_mode},
    },
    transport::tcp_relay::{TcpRelay, TcpRelayConfig},
};

use super::{
    error::{ProductionServerError, RuntimeUpdateError},
    event::{backend_statuses, emit},
    resources::{derive_fd_budget, maximum_warm_pool_count, resolve_startup_resource_mode},
    snapshot::{RuntimeSnapshot, canonical_listener_address},
    store::{ListenerReplays, ProcessAuthorities, RuntimeStore},
};
use crate::server::{
    dns::DnsResolver, handoff::HandoffLandingConfigError, nxr::NxrReplayCache,
    warm_pool::WarmPoolAuthority,
};

/// One listener's tag and the concrete addresses its declaration expands to.
#[derive(Clone, Debug)]
pub(super) struct ListenerPlan {
    pub(super) tag: String,
    pub(super) mode: ListenFamily,
    pub(super) addresses: Vec<SocketAddr>,
}

/// Translates validated operator policy into the concrete Transport mechanism.
///
/// `max_relay_memory_bytes` remains a Configuration validation ceiling rather
/// than leaking into Transport, which consumes only the pool/backend values.
const fn compile_tcp_relay_config(policy: &RelayPolicy) -> TcpRelayConfig {
    TcpRelayConfig {
        buffer_bytes: policy.buffer_bytes,
        max_pooled_buffers: policy.max_pooled_buffers,
        max_splice_relays: policy.max_splice_relays,
        splice: policy.splice,
        pipe_pool: policy.pipe_pool,
        max_pooled_pipes: policy.max_pooled_pipes,
    }
}

/// Builds every process-lifetime authority and publishes generation zero.
///
/// A caller-supplied machine report is used verbatim — the serve bootstrap
/// detects the machine before it builds the Tokio runtime, so the runtime
/// topology and the policy derivation share one detection instead of
/// disagreeing about the host they landed on.
///
/// # Errors
///
/// Returns a validation, logger, asset, routing, REALITY, descriptor-budget,
/// or DNS error. Nothing here binds a socket; the first bind happens in
/// [`super::supervisor`].
pub(super) fn build(
    config: ValidatedConfig,
    machine: Option<MachineReport>,
) -> Result<(Vec<ListenerPlan>, Arc<RuntimeStore>), ProductionServerError> {
    // Resolve the machine view and the resource mode before anything is
    // built: the policy derivation and the descriptor budget share this
    // one detection.
    let node = config.into_node();
    let runtime = node.runtime();
    let (resource_mode, machine) = match machine {
        Some(machine) => (resolve_resource_mode(runtime.profile(), &machine), machine),
        None => resolve_startup_resource_mode(runtime.profile()),
    };
    // The effective policy is derived here and stays a value of its own.
    // It is never written back into the configuration: the operator's
    // input and what this process decided are different things, and every
    // pool, barrier, and reload comparison below reads the policy.
    let policy = plan::resolve_policy(
        &runtime.limits(),
        runtime.objective(),
        &machine,
        resource_mode,
        node.listeners().len(),
    )
    .policy;
    let topology = plan::RuntimeTopology::for_mode(resource_mode, machine.effective_cpus());
    let pressure = PressureGauge::new();
    // Process-lifetime authorities: reload generations swap routing and
    // protocol snapshots only — admission ceilings and the direct-dial
    // barrier must never multiply while old sessions hold old permits.
    let authorities = ProcessAuthorities {
        governor: ResourceGovernor::with_pressure(&policy.governor, pressure.clone()),
        direct_barrier: DirectBarrier::with_pressure(&policy.direct_barrier, pressure.clone()),
        warm_pools: WarmPoolAuthority::new(
            &policy.warm_connections,
            maximum_warm_pool_count(&node),
            pressure.clone(),
        ),
        network_environment: NetworkEnvironment::from_config(&DialTuning::for_policy(
            node.network().ip(),
        )),
    };
    // Process-lifetime shared resolver: the configured DNS backend and the
    // admission governor apply to every connector-side lookup. First-wins
    // keeps reload generations on the one installed resolver.
    let _ = crate::server::dns::install_shared(
        DnsResolver::from_config(&node.dns(), authorities.governor.clone())
            .map_err(ProductionServerError::Dns)?,
    );
    let replay = ReplayCache::new(authorities.governor.clone(), &policy.governor);
    let listener_replays = ListenerReplays {
        nxr: compile_nxr_replays(&node)?,
        handoff: compile_handoff_replays(&node)?,
    };
    let startup = derive_fd_budget(&node, &policy, resource_mode, machine)
        .map_err(ProductionServerError::DescriptorBudget)?;
    let tcp_relay = TcpRelay::new(
        compile_tcp_relay_config(&policy.relay),
        startup.budget.clone(),
    )
    .map_err(RuntimeUpdateError::Relay)?;
    let initial = RuntimeSnapshot::compile(
        node,
        &policy,
        0,
        replay.clone(),
        &listener_replays,
        tcp_relay.clone(),
        &pressure,
        &authorities,
    )?;
    let listeners = initial
        .node
        .listeners()
        .iter()
        .map(|listener| ListenerPlan {
            tag: initial.node.role().as_str().to_owned(),
            mode: listener.family(),
            addresses: listener.bind_addresses(),
        })
        .collect();
    emit(&initial.logger, &LogEvent::ServerStarting);
    let network = authorities.network_environment.startup_snapshot();
    emit(
        &initial.logger,
        &LogEvent::OutboundNetworkInitialized {
            mode: network.mode.as_str(),
            primary_family: network.initial_primary.as_str(),
            ipv4_available: network.ipv4_available,
            ipv6_available: network.ipv6_available,
        },
    );
    if startup.resource_mode == ResourceMode::Dedicated {
        emit(
            &initial.logger,
            &LogEvent::MachineReport {
                resource_mode: startup.resource_mode.as_str(),
                fd_soft_limit: startup.machine.fd_soft_limit,
                fd_hard_limit: startup.machine.fd_hard_limit,
                fd_effective_soft_limit: startup.fd_effective_soft_limit,
                fd_soft_raise_attempted: startup.fd_soft_raise_attempted,
                fd_soft_limit_raised: startup.fd_soft_limit_raised,
                memlock_soft_limit: startup.machine.memlock_soft_limit,
                memlock_hard_limit: startup.machine.memlock_hard_limit,
                available_cpus: startup.machine.available_cpus,
                cpu_quota_us: startup.machine.cpu_quota_us,
                cpu_period_us: startup.machine.cpu_period_us,
                cpuset_effective: startup.machine.cpuset_effective.clone(),
                memory_source: startup.machine.memory_source,
                memory_current: startup.machine.memory_current,
                memory_high: startup.machine.memory_high,
                memory_max: startup.machine.memory_max,
                memory_total: startup.machine.memory_total,
            },
        );
    }
    emit(
        &initial.logger,
        &LogEvent::RuntimePlanReport {
            resource_mode: resource_mode.as_str(),
            tuning_mode: initial.node.runtime().tuning().as_str(),
            objective: initial.node.runtime().objective().as_str(),
            worker_threads: topology
                .worker_threads
                .unwrap_or(startup.machine.available_cpus),
            max_blocking_threads: topology.effective_max_blocking_threads(),
            policy_derived: true,
        },
    );
    emit(
        &initial.logger,
        &LogEvent::DescriptorBudgetReport {
            fd_soft_limit: startup.plan.soft_limit(),
            fd_hard_limit: startup.plan.hard_limit(),
            fd_fixed_reserve: startup.plan.fixed_reserve().total(),
            fd_safety_headroom: startup.plan.safety_headroom(),
            fd_effective_budget: startup.plan.effective_budget(),
            fd_clamped: startup.plan.is_clamped(),
            fd_recommended_soft_limit: startup.plan.recommended_soft_limit(),
        },
    );
    emit(
        &initial.logger,
        &LogEvent::RelayBackendReport {
            backends: backend_statuses(tcp_relay.report()),
        },
    );
    emit(
        &initial.logger,
        &LogEvent::ConfigurationPublished {
            generation: initial.generation,
        },
    );
    Ok((
        listeners,
        Arc::new(RuntimeStore {
            current: ArcSwap::from(Arc::new(initial)),
            policy,
            replay,
            listener_replays,
            tcp_relay,
            fd_budget: startup.budget,
            authorities,
            pressure,
            memory: startup.memory,
            generation: AtomicU64::new(0),
            update: Mutex::new(()),
        }),
    ))
}

/// Builds the Handoff replay cache for every address a landing binds.
///
/// The capacity and retention are derived from the accepted clock skew rather
/// than configured: the cache exists to bound memory while covering the window
/// in which a replayed transfer could still be accepted.
pub(super) fn compile_handoff_replays(
    node: &NodeConfig,
) -> Result<HashMap<SocketAddr, HandoffReplayCache>, RuntimeUpdateError> {
    let mut replays = HashMap::new();
    let Some(landing) = node.as_landing() else {
        return Ok(replays);
    };
    let LandingProtocol::Handoff(settings) = &landing.landing else {
        return Ok(replays);
    };
    let address = canonical_listener_address(node);
    let replay = HandoffReplayCache::new(
        usize::try_from(crate::server::nxr::REPLAY_NONCE_CAPACITY)
            .map_err(|_| HandoffLandingConfigError::Capacity)
            .map_err(RuntimeUpdateError::Handoff)?,
        Duration::from_secs(crate::server::nxr::replay_retention_seconds(
            settings.timing().max_time_difference_seconds,
        )),
    )
    .map_err(HandoffLandingConfigError::Replay)
    .map_err(RuntimeUpdateError::Handoff)?;
    replays.insert(address, replay);
    Ok(replays)
}

/// Builds the NXR replay cache for every address a landing binds.
pub(super) fn compile_nxr_replays(
    node: &NodeConfig,
) -> Result<HashMap<SocketAddr, NxrReplayCache>, RuntimeUpdateError> {
    let mut replays = HashMap::new();
    let Some(landing) = node.as_landing() else {
        return Ok(replays);
    };
    let LandingProtocol::Nxr(settings) = &landing.landing else {
        return Ok(replays);
    };
    replays.insert(
        canonical_listener_address(node),
        NxrReplayCache::from_landing(settings)?,
    );
    Ok(replays)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use crate::{
        config::node::fixture,
        protocol::vless::VISION_FLOW,
        runtime::{machine::MachineReport, policy::ResourceGovernorPolicy},
        server::production::{ProductionServer, fixture::entry_config},
    };

    #[test]
    fn an_entry_node_compiles_into_a_reality_vision_server() {
        let config = entry_config(8443);
        // Vision is the only flow this server speaks; the configuration no
        // longer states it, because there was never another value to choose.
        assert_eq!(VISION_FLOW, "xtls-rprx-vision");

        ProductionServer::from_config(config).expect("server must compile");
    }

    #[test]
    fn a_wildcard_listener_compiles_two_independent_family_sockets() {
        let config = fixture::validated(&fixture::entry_without_routing(
            r#""listeners": [{ "port": 8443 }],
  "routing": { "default": "direct" }"#,
        ));
        let server = ProductionServer::from_config(config).expect("dual-stack server must compile");
        assert_eq!(
            server.listeners[0].addresses,
            [
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 8443),
                SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 8443),
            ],
            "the old single-IpAddr topology silently omitted IPv6 ingress"
        );
    }

    #[test]
    fn startup_tuning_derives_the_policy_from_the_machine() {
        let config = entry_config(8443);
        assert_eq!(
            config.node().runtime().tuning(),
            crate::config::node::runtime::TuningMode::Startup,
            "an omitted tuning mode derives at startup"
        );
        let server = ProductionServer::from_loaded(config, None, MachineReport::conservative())
            .expect("server must compile");
        let effective = &server.runtime.policy;
        // The golden conservative-machine derivation from runtime::plan.
        assert_eq!(effective.governor.max_connections, 197);
        assert_eq!(effective.governor.max_handshakes, 128);
        assert_eq!(effective.relay.buffer_bytes, 32 * 1024);
        assert_eq!(effective.relay.max_splice_relays, 64);
        assert_eq!(
            effective.governor.handshake_timeout_ms,
            ResourceGovernorPolicy::default().handshake_timeout_ms,
            "timeouts are carried from the configuration, never derived"
        );
        assert_ne!(
            effective.governor.max_connections,
            ResourceGovernorPolicy::default().max_connections,
            "the default tuning mode no longer applies the built-in numbers"
        );
    }

    #[test]
    fn an_operator_pin_wins_over_the_startup_derivation() {
        let config = fixture::validated(&fixture::entry_without_routing(
            r#""listeners": [{ "port": 8443, "ip": "ipv4Only", "ipv4": "127.0.0.1" }],
  "routing": { "default": "direct" },
  "runtime": { "limits": { "maxConnections": 1000 } }"#,
        ));
        let server = ProductionServer::from_loaded(config, None, MachineReport::conservative())
            .expect("server must compile");
        let effective = &server.runtime.policy;
        assert_eq!(effective.governor.max_connections, 1_000);
        assert_eq!(
            effective.governor.max_handshakes, 128,
            "unpinned fields still derive"
        );
    }
}
