use std::{
    collections::HashMap,
    error::Error,
    fmt,
    future::Future,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::io::Write as _;
use tokio::{
    sync::{mpsc, watch},
    task::{JoinError, JoinSet},
    time::{self, Instant, Sleep},
};

use crate::{
    assets::{AssetLoadError, AssetSnapshot},
    config::{LoadError, NodeConfig, ValidatedConfig, load, node::landing::LandingProtocol},
    logging::{AdmissionResource, BackendStatus, LogEvent, LogWriteError, Logger, RejectionReason},
    network::{AddressFamily, NetworkEnvironment},
    protocol::{handoff::HandoffReplayCache, reality::ReplayCache},
    runtime::{
        AdmissionDenied, AdmissionKind, AdmissionPermit, DirectBarrier, FdBudgetError,
        FdBudgetPlan, FdHeadroomPolicy, FixedFdReserve, PressureGauge, ResourceGovernor,
        ResourcePressure, adaptive,
        connection::ConnectionTasks,
        machine::{self, MachineReport, MemoryPlan, MemorySampler},
        plan,
        policy::{EffectivePolicy, RelayPolicy, ResourceMode, resolve_resource_mode},
    },
    transport::{
        BackendDeclineReason, BackendReport, FdBudget, FdPermit, RelayBackend,
        UNITS_INBOUND_SOCKET,
        tcp::{AcceptBackoff, AcceptErrorClass, EmergencyDescriptor, TcpAcceptor},
        tcp_relay::{TcpRelay, TcpRelayConfig, TcpRelayConfigError, is_liveness_timeout_abort},
    },
};

use super::{
    dns::{DnsResolver, DnsResolverConfigError},
    handoff::{HandoffLandingConfigError, HandoffLandingError, HandoffLandingHandler},
    nxr::{NxrLandingConfigError, NxrLandingError, NxrLandingHandler, NxrReplayCache},
    pre_auth::PreAuthGeneration,
    reality::{
        RealityAcceptError, RealityAcceptOutcome, RealityAcceptor, RealityAcceptorConfigError,
    },
    routing::RoutingCompileError,
    vision::{VisionHandler, VisionSessionError},
    warm_pool::WarmPoolAuthority,
};
use crate::config::node::listener::{ListenFamily, ListenerConfig};
use crate::config::node::runtime::{RuntimeProfile, TuningMode};
use crate::network::DialTuning;

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// How often the memory pressure monitor samples its bounded signal.
///
/// One sample per second is cheap (one small file read), fast enough to
/// refuse new work well before a cgroup OOM kill, and slow enough that it
/// can never show up in a profile of the data path.
const MEMORY_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// Fully compiled production server using only REALITY-protected Vision inbounds.
///
/// New connections acquire one lock-free immutable runtime snapshot. A successful
/// reload swaps configuration, assets, routing, outbounds, users, REALITY state,
/// resource limits, and logging as one generation. Existing connections retain
/// their previous generation. Listener addresses and replay-cache policy are cold
/// settings because replacing either without a process restart can create a bind
/// outage or weaken replay retention.
pub struct ProductionServer {
    listeners: Vec<ListenerPlan>,
    runtime: Arc<RuntimeStore>,
    config_path: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct ListenerPlan {
    tag: String,
    mode: ListenFamily,
    addresses: Vec<SocketAddr>,
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

/// Computes the configured worst-case simultaneous descriptor demand.
///
/// Every term is a configured bound, and the sum is deliberately pessimistic:
/// it assumes every connection simultaneously holds an inbound socket and two
/// racing outbound candidates, that every splice relay is armed at once, and
/// that the pipe pool retains its full keep count of drained pipes afterwards.
/// The winning candidate retains the same unit as the established outbound.
/// The number is used only to decide whether to warn about clamping; it never
/// raises the admission budget.
fn theoretical_fd_peak(node: &NodeConfig, policy: &EffectivePolicy) -> u64 {
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
fn maximum_warm_pool_count(node: &NodeConfig) -> usize {
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
struct ResourceStartup {
    plan: FdBudgetPlan,
    budget: FdBudget,
    resource_mode: ResourceMode,
    machine: MachineReport,
    fd_effective_soft_limit: u64,
    fd_soft_raise_attempted: bool,
    fd_soft_limit_raised: bool,
    memory: Option<MemoryWatch>,
}

/// The bounded memory signal the pressure monitor samples.
#[derive(Clone)]
struct MemoryWatch {
    sampler: MemorySampler,
    plan: MemoryPlan,
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
fn derive_fd_budget(
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
/// The profile maps onto the mode ([`RuntimeConfig::resolve_resource_mode`]).
/// The detected machine view is gathered only when the resolution, the
/// dedicated-mode derivation, or the startup policy derivation can need it:
/// the `shared` profile resolves to standard without looking at the machine,
/// while `auto` needs the cgroup tenancy boundary to decide, every dedicated
/// outcome budgets against the measured view, and `derivation_active` (a
/// `startup`/`adaptive` tuning mode) derives the numeric policy from the
/// measured view.
fn resolve_startup_resource_mode(profile: RuntimeProfile) -> (ResourceMode, MachineReport) {
    // Derivation always runs, so the measured view is always needed.
    let detect = true;
    let _ = profile == RuntimeProfile::Shared;
    let machine = if detect {
        MachineReport::detect()
    } else {
        MachineReport::conservative()
    };
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

impl ProductionServer {
    /// Compiles one programmatically supplied production configuration.
    ///
    /// This constructor supports deterministic tests and embedded service managers.
    /// Use [`Self::from_path`] when SIGHUP configuration reload is required.
    ///
    /// # Errors
    ///
    /// Returns a validation, logger, asset, routing, REALITY, or listener error.
    pub fn from_config(config: ValidatedConfig) -> Result<Self, ProductionServerError> {
        Self::compile(config, None, None)
    }

    /// Loads and compiles a production configuration while retaining its path for
    /// SIGHUP reload.
    ///
    /// # Errors
    ///
    /// Returns a load, validation, logger, asset, routing, REALITY, or listener error.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ProductionServerError> {
        let path = path.as_ref().to_path_buf();
        let config = load(&path).map_err(RuntimeUpdateError::Load)?;
        Self::compile(config, Some(path), None)
    }

    /// Compiles one already-loaded configuration against a caller-detected
    /// machine view.
    ///
    /// The serve bootstrap uses this constructor: it detects the machine
    /// before building the Tokio runtime so the runtime topology and the
    /// startup policy derivation share one detection, then hands the report
    /// over instead of letting the server detect again.
    ///
    /// # Errors
    ///
    /// Returns a validation, logger, asset, routing, REALITY, or listener error.
    pub fn from_loaded(
        config: ValidatedConfig,
        config_path: Option<PathBuf>,
        machine: MachineReport,
    ) -> Result<Self, ProductionServerError> {
        Self::compile(config, config_path, Some(machine))
    }

    fn compile(
        config: ValidatedConfig,
        config_path: Option<PathBuf>,
        machine: Option<MachineReport>,
    ) -> Result<Self, ProductionServerError> {
        // Resolve the machine view and the resource mode before anything is
        // built: the policy derivation and the descriptor budget share this
        // one detection. A caller-supplied report is used verbatim; otherwise
        // detection happens here, skipped only when nothing can consume the
        // view (a shared posture with fixed tuning).
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
        let _ = super::dns::install_shared(
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
        Ok(Self {
            listeners,
            runtime: Arc::new(RuntimeStore {
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
            config_path,
        })
    }

    /// Returns the live resource-pressure gauge.
    ///
    /// In standard resource mode the gauge never leaves `Normal`. In
    /// dedicated mode the pressure monitor publishes the combined
    /// descriptor/memory state. Supervisors and tests can observe it; the
    /// listener and admission governor already consult it on their own.
    #[must_use]
    pub fn pressure_gauge(&self) -> PressureGauge {
        self.runtime.pressure.clone()
    }

    /// Binds every configured listener before serving any connection and runs
    /// until SIGINT or SIGTERM. On Unix, SIGHUP requests one complete atomic
    /// configuration reload. Assets are also revalidated on their configured
    /// interval while the last good generation remains live on every failure.
    ///
    /// # Errors
    ///
    /// Returns a bind, accept, signal, or task-supervision error.
    pub async fn run(self) -> Result<(), ProductionServerError> {
        let (reload_sender, reload_receiver) = mpsc::channel(1);
        #[cfg(unix)]
        let reload_task: Option<tokio::task::JoinHandle<()>> = {
            let signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .map_err(ProductionServerError::Signal)?;
            Some(tokio::spawn(forward_reload_signals(signal, reload_sender)))
        };
        #[cfg(not(unix))]
        let reload_task: Option<tokio::task::JoinHandle<()>> = {
            let _sender = reload_sender;
            None
        };

        let result = self
            .run_internal(shutdown_signal(), reload_receiver, true)
            .await;
        if let Some(task) = reload_task {
            task.abort();
        }
        result
    }

    /// Runs until an injected shutdown future completes, without installing
    /// process signals or scheduled asset/configuration reloads. The normal
    /// low-cost process-wide route refresh remains active.
    ///
    /// # Errors
    ///
    /// Returns a bind, accept, or task-supervision error.
    pub async fn run_until<F>(self, shutdown: F) -> Result<(), ProductionServerError>
    where
        F: Future<Output = Result<(), io::Error>> + Send,
    {
        let (reload_sender, reload_receiver) = mpsc::channel(1);
        let result = self.run_internal(shutdown, reload_receiver, false).await;
        drop(reload_sender);
        result
    }

    async fn run_internal<F>(
        self,
        shutdown: F,
        mut reload_receiver: mpsc::Receiver<()>,
        managed_updates: bool,
    ) -> Result<(), ProductionServerError>
    where
        F: Future<Output = Result<(), io::Error>> + Send,
    {
        let initial = self.runtime.load();
        let listener_capacity = self
            .listeners
            .iter()
            .map(|listener| listener.addresses.len())
            .sum();
        let mut bound = Vec::with_capacity(listener_capacity);
        for listener in &self.listeners {
            let mut active_families = Vec::with_capacity(listener.addresses.len());
            let mut unavailable_families = Vec::with_capacity(listener.addresses.len());
            let mut last_degradable = None;
            for address in &listener.addresses {
                match TcpAcceptor::bind(*address).await {
                    Ok(acceptor) => {
                        active_families.push(AddressFamily::of(address.ip()).as_str());
                        bound.push((acceptor, *address));
                    }
                    Err(source)
                        if listener.mode == ListenFamily::Auto
                            && is_degradable_listener_bind_error(*address, &source) =>
                    {
                        let family = AddressFamily::of(address.ip()).as_str();
                        unavailable_families.push(family);
                        emit(
                            &initial.logger,
                            &LogEvent::ListenerFamilyUnavailable {
                                tag: listener.tag.clone(),
                                family,
                                address: *address,
                                errno: source.raw_os_error(),
                            },
                        );
                        last_degradable = Some((*address, source));
                    }
                    Err(source) => {
                        return Err(ProductionServerError::Bind {
                            address: *address,
                            source,
                        });
                    }
                }
            }
            if active_families.is_empty() {
                let (address, source) = last_degradable
                    .expect("an empty auto listener must have a degradable bind error");
                return Err(ProductionServerError::Bind { address, source });
            }
            emit(
                &initial.logger,
                &LogEvent::ListenerTopologyActive {
                    tag: listener.tag.clone(),
                    active_families,
                    unavailable_families,
                },
            );
        }

        // Listener binding is complete, so this immutable generation may begin
        // speculative cover and fixed-peer dialing without delaying availability.
        initial.activate_warm_pools();
        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let mut listener_tasks = JoinSet::new();
        for (acceptor, address) in bound {
            let local_address = acceptor
                .local_addr()
                .map_err(ProductionServerError::ListenerAddress)?;
            let state = initial
                .connections
                .get(&address)
                .ok_or(ProductionServerError::ListenerStopped)?;
            emit(
                &initial.logger,
                &LogEvent::ListenerStarted {
                    tag: state.tag.to_string(),
                    address: local_address,
                },
            );
            listener_tasks.spawn(run_listener(
                acceptor,
                address,
                Arc::clone(&self.runtime),
                shutdown_receiver.clone(),
            ));
        }
        let monitor_task = self.runtime.memory.clone().map(|watch| {
            tokio::spawn(run_resource_monitor(
                Arc::clone(&self.runtime),
                watch,
                shutdown_receiver.clone(),
            ))
        });
        // The adaptive controller exists only under the `adaptive` tuning
        // mode; under `fixed` and `startup` nothing adjusts the ceilings and
        // behavior is byte-identical to v1.5.
        let adaptive_task = adaptive_controller(
            &initial.node,
            &self.runtime.policy,
            &self.runtime.authorities,
            &self.runtime.pressure,
        )
        .map(|controller| {
            tokio::spawn(run_adaptive_controller(
                Arc::clone(&self.runtime),
                controller,
                shutdown_receiver.clone(),
            ))
        });
        let network_refresh_task = tokio::spawn(run_network_refresh(
            self.runtime.authorities.network_environment.clone(),
            Duration::from_secs(
                DialTuning::for_policy(initial.node.network().ip()).route_refresh_seconds,
            ),
            shutdown_receiver.clone(),
        ));
        drop(initial);

        tokio::pin!(shutdown);
        let refresh_deadline = Instant::now() + self.runtime.reload_interval();
        let mut refresh = Box::pin(time::sleep_until(refresh_deadline));
        let mut update_tasks = JoinSet::new();
        let result = loop {
            tokio::select! {
                signal = &mut shutdown => {
                    break signal.map_err(ProductionServerError::Signal);
                }
                completed = listener_tasks.join_next() => {
                    break match completed {
                        Some(Ok(Ok(()))) => Err(ProductionServerError::ListenerStopped),
                        Some(Ok(Err(source))) => Err(ProductionServerError::Accept(source)),
                        Some(Err(source)) => Err(ProductionServerError::Task(source)),
                        None => Err(ProductionServerError::ListenerStopped),
                    };
                }
                requested = reload_receiver.recv(), if managed_updates && !reload_receiver.is_closed() => {
                    if requested.is_some() && update_tasks.is_empty() {
                        if let Some(path) = self.config_path.clone() {
                            let runtime = Arc::clone(&self.runtime);
                            update_tasks.spawn_blocking(move || {
                                ("configuration", runtime.reload_path(&path))
                            });
                        } else {
                            emit_rejected(&self.runtime, "configuration", None);
                        }
                    }
                    reset_refresh(&mut refresh, self.runtime.reload_interval());
                }
                () = &mut refresh, if managed_updates => {
                    if update_tasks.is_empty() {
                        let runtime = Arc::clone(&self.runtime);
                        update_tasks.spawn_blocking(move || ("assets", runtime.refresh()));
                    }
                    reset_refresh(&mut refresh, self.runtime.reload_interval());
                }
                completed = update_tasks.join_next(), if !update_tasks.is_empty() => {
                    match completed {
                        Some(Ok((_, Ok(_)))) => {
                            self.runtime.load().activate_warm_pools();
                        }
                        Some(Ok((field, Err(error)))) => {
                            emit_rejected(&self.runtime, field, Some(&error));
                        }
                        Some(Err(_)) | None => emit_rejected(&self.runtime, "configuration", None),
                    }
                    reset_refresh(&mut refresh, self.runtime.reload_interval());
                }
            }
        };

        self.runtime.load().deactivate_warm_pools();
        update_tasks.abort_all();
        if let Some(task) = monitor_task {
            task.abort();
        }
        if let Some(task) = adaptive_task {
            task.abort();
        }
        network_refresh_task.abort();
        let _ignored = shutdown_sender.send(true);
        while let Some(completed) = listener_tasks.join_next().await {
            match completed {
                Ok(Ok(())) => {}
                Ok(Err(source)) if result.is_ok() => {
                    return Err(ProductionServerError::Accept(source));
                }
                Err(source) if result.is_ok() => {
                    return Err(ProductionServerError::Task(source));
                }
                Ok(Err(_)) | Err(_) => {}
            }
        }
        result
    }
}

/// Process-lifetime bounded replay caches for internal landing listeners,
/// retained across immutable runtime generations.
struct ListenerReplays {
    nxr: HashMap<SocketAddr, NxrReplayCache>,
    handoff: HashMap<SocketAddr, HandoffReplayCache>,
}

struct RuntimeStore {
    current: ArcSwap<RuntimeSnapshot>,
    policy: EffectivePolicy,
    replay: ReplayCache,
    listener_replays: ListenerReplays,
    tcp_relay: TcpRelay,
    fd_budget: FdBudget,
    authorities: ProcessAuthorities,
    pressure: PressureGauge,
    memory: Option<MemoryWatch>,
    generation: AtomicU64,
    update: Mutex<()>,
}

/// Admission authorities built once at startup and shared by every generation.
///
/// Reload swaps routing and protocol snapshots only — these ceilings and
/// rate gates must never multiply while old sessions hold old permits.
struct ProcessAuthorities {
    governor: ResourceGovernor,
    direct_barrier: DirectBarrier,
    warm_pools: WarmPoolAuthority,
    network_environment: NetworkEnvironment,
}

impl RuntimeStore {
    fn load(&self) -> Arc<RuntimeSnapshot> {
        self.current.load_full()
    }

    fn reload_interval(&self) -> Duration {
        let node = self.load();
        let interval = node
            .node
            .as_entry()
            .and_then(|entry| entry.assets.as_ref())
            .map_or(
                crate::config::node::assets::DEFAULT_RELOAD_INTERVAL_SECONDS,
                crate::config::node::assets::AssetsConfig::reload_interval_seconds,
            );
        Duration::from_secs(interval)
    }

    fn reload_path(&self, path: &Path) -> Result<u64, RuntimeUpdateError> {
        let config = load(path)?;
        self.publish(config.into_node())
    }

    fn refresh(&self) -> Result<u64, RuntimeUpdateError> {
        let node = self.load().node.clone();
        self.publish(node)
    }

    fn publish(&self, config: NodeConfig) -> Result<u64, RuntimeUpdateError> {
        let _guard = self
            .update
            .lock()
            .map_err(|_| RuntimeUpdateError::Unavailable)?;
        let current = self.load();
        let config = ensure_hot_compatible(&current, config)?;
        let generation = self
            .generation
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or(RuntimeUpdateError::GenerationExhausted)?;
        let candidate = RuntimeSnapshot::compile(
            config,
            &self.policy,
            generation,
            self.replay.clone(),
            &self.listener_replays,
            self.tcp_relay.clone(),
            &self.pressure,
            &self.authorities,
        )?;
        self.current.store(Arc::new(candidate));
        self.generation.store(generation, Ordering::Release);
        // Publish first so an accept racing this update can only observe a
        // live old generation or the new one, never a retired handler. The old
        // snapshot remains locally owned here while its unused speculative
        // sockets are reclaimed immediately afterwards; checked-out sessions
        // retain their independent stream and permits.
        current.deactivate_warm_pools();
        let published = self.load();
        emit(
            &published.logger,
            &LogEvent::ConfigurationPublished {
                generation: published.generation,
            },
        );
        Ok(generation)
    }
}

struct RuntimeSnapshot {
    generation: u64,
    node: NodeConfig,
    connections: HashMap<SocketAddr, Arc<ConnectionRuntime>>,
    logger: Logger,
    pre_auth_generation: PreAuthGeneration,
    outbounds: super::outbound::OutboundRegistry,
}

impl RuntimeSnapshot {
    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter per process-lifetime authority the snapshot binds"
    )]
    fn compile(
        config: NodeConfig,
        policy: &EffectivePolicy,
        generation: u64,
        replay: ReplayCache,
        listener_replays: &ListenerReplays,
        tcp_relay: TcpRelay,
        pressure: &PressureGauge,
        authorities: &ProcessAuthorities,
    ) -> Result<Self, RuntimeUpdateError> {
        let logger = Logger::new(&config.log())?;
        let pre_auth_generation = PreAuthGeneration::default();
        let network = config.network();

        // One node, one role, so one handler shared by every bound address.
        // The role also decides what has to be built at all: only an entry
        // node compiles routing, and only routing can need geo assets.
        let (handler, outbounds) = match &config {
            NodeConfig::Entry(entry) => {
                let assets = Arc::new(AssetSnapshot::load_generation(entry, generation)?);
                let vision = VisionHandler::from_config_with_pressure(
                    entry,
                    policy,
                    assets,
                    tcp_relay.clone(),
                    pressure,
                    authorities.direct_barrier.clone(),
                    authorities.governor.clone(),
                    authorities.network_environment.clone(),
                    generation,
                    authorities.warm_pools.clone(),
                )?;
                let outbounds = vision.outbounds().clone();
                let reality = RealityAcceptor::from_inbound_with_warm_pool(
                    entry,
                    authorities.governor.clone(),
                    &policy.governor,
                    replay.clone(),
                    tcp_relay.clone(),
                    &network,
                    authorities.network_environment.clone(),
                    generation,
                    authorities.warm_pools.clone(),
                    &policy.warm_connections,
                )?;
                (
                    ConnectionHandler::Public {
                        reality: Box::new(reality),
                        vision,
                    },
                    outbounds,
                )
            }
            NodeConfig::Landing(landing) => {
                let outbounds = super::outbound::OutboundRegistry::with_warm_pools(
                    &landing.outbounds.clone().unwrap_or_default(),
                    authorities.direct_barrier.clone(),
                    Duration::from_millis(policy.governor.connect_timeout_ms),
                    tcp_relay.fd_budget().clone(),
                    &network,
                    authorities.network_environment.clone(),
                    generation,
                    authorities.warm_pools.clone(),
                    &policy.warm_connections,
                );
                let address = canonical_listener_address(&config);
                let io_timeout = Duration::from_millis(policy.governor.fallback_timeout_ms);
                let handler = match &landing.landing {
                    LandingProtocol::Nxr(settings) => {
                        let replay = listener_replays
                            .nxr
                            .get(&address)
                            .cloned()
                            .ok_or(RuntimeUpdateError::MissingNxrReplay(address))?;
                        ConnectionHandler::Nxr(NxrLandingHandler::from_landing_with_replay(
                            settings,
                            replay,
                            tcp_relay.clone(),
                            io_timeout,
                            &network,
                            authorities.network_environment.clone(),
                            authorities.governor.clone(),
                            pressure.clone(),
                            pre_auth_generation.clone(),
                        )?)
                    }
                    LandingProtocol::Handoff(settings) => {
                        let replay = listener_replays
                            .handoff
                            .get(&address)
                            .cloned()
                            .ok_or(RuntimeUpdateError::MissingHandoffReplay(address))?;
                        if settings.rotation_window_is_open() {
                            // One warning per generation, startup and reload
                            // alike: an open rotation window voids the
                            // forward-secrecy bound until the retired keys drop.
                            emit(
                                &logger,
                                &LogEvent::HandoffRotationWindowOpen {
                                    tag: "landing".to_owned(),
                                    previous_pre_shared_keys: settings.previous_psks().len(),
                                    previous_private_keys: settings.previous_private_keys().len(),
                                },
                            );
                        }
                        ConnectionHandler::Handoff(HandoffLandingHandler::from_landing_with_replay(
                            settings,
                            Some(landing.egress())
                                .filter(|egress| *egress != crate::config::node::BUILTIN_DIRECT),
                            replay,
                            tcp_relay.clone(),
                            io_timeout,
                            &outbounds,
                            &network,
                            authorities.network_environment.clone(),
                            authorities.governor.clone(),
                            pressure.clone(),
                            pre_auth_generation.clone(),
                        )?)
                    }
                };
                (handler, outbounds)
            }
        };

        let runtime = Arc::new(ConnectionRuntime {
            tag: Arc::from(config.role().as_str()),
            governor: authorities.governor.clone(),
            handler,
        });
        let mut connections = HashMap::new();
        let bound: Vec<SocketAddr> = config
            .listeners()
            .iter()
            .flat_map(ListenerConfig::bind_addresses)
            .collect();
        connections
            .try_reserve(bound.len())
            .map_err(|_| RuntimeUpdateError::Unavailable)?;
        for address in bound {
            if connections.insert(address, Arc::clone(&runtime)).is_some() {
                return Err(RuntimeUpdateError::DuplicateListener(address));
            }
        }

        Ok(Self {
            generation,
            node: config,
            connections,
            logger,
            pre_auth_generation,
            outbounds,
        })
    }

    fn activate_warm_pools(&self) {
        self.outbounds.activate_warm_pools();
        for connection in self.connections.values() {
            if let ConnectionHandler::Public { reality, .. } = &connection.handler {
                reality.activate_cover_pool();
            }
        }
    }

    fn deactivate_warm_pools(&self) {
        self.pre_auth_generation.deactivate();
        let outbound_snapshots = self.outbounds.warm_pool_snapshots();
        self.outbounds.deactivate_warm_pools();
        for snapshot in outbound_snapshots {
            let pool = snapshot.pool;
            emit(
                &self.logger,
                &LogEvent::TransportPoolSummary {
                    transport: snapshot.transport,
                    generation: pool.generation,
                    pool_ready: pool.ready,
                    pool_connecting: pool.connecting,
                    pool_in_use: pool.in_use,
                    pool_checkout_total: pool.checkout_total,
                    pool_checkout_hit: pool.checkout_hit,
                    pool_checkout_miss: pool.checkout_miss,
                    pool_cold_fallback: pool.cold_fallback,
                    pool_connect_failure: pool.connect_failure,
                    pool_stale_discard: pool.stale_discard,
                    pool_refill: pool.refill,
                    pool_target_ready: pool.target_ready,
                    pool_growth: pool.growth,
                    pool_shrink: pool.shrink,
                    arrival_rate_ewma: format!("{:.3}", pool.arrival_rate_per_second),
                    connect_latency_ewma_ms: format!("{:.3}", pool.connect_latency_ms),
                    recent_burst: format!("{:.3}", pool.recent_burst),
                },
            );
        }
        for connection in self.connections.values() {
            if let ConnectionHandler::Public { reality, .. } = &connection.handler {
                let snapshot = reality.cover_pool_snapshot();
                let profile_snapshot = reality.cover_profile_snapshot();
                let _deactivated = reality.deactivate_cover_pool();
                if let Some(snapshot) = snapshot {
                    emit(
                        &self.logger,
                        &LogEvent::CoverPoolSummary {
                            generation: snapshot.generation,
                            pool_ready: snapshot.ready,
                            pool_connecting: snapshot.connecting,
                            pool_in_use: snapshot.in_use,
                            pool_checkout_total: snapshot.checkout_total,
                            pool_checkout_hit: snapshot.checkout_hit,
                            pool_checkout_miss: snapshot.checkout_miss,
                            pool_cold_fallback: snapshot.cold_fallback,
                            pool_connect_failure: snapshot.connect_failure,
                            pool_stale_discard: snapshot.stale_discard,
                            pool_refill: snapshot.refill,
                            pool_target_ready: snapshot.target_ready,
                            pool_growth: snapshot.growth,
                            pool_shrink: snapshot.shrink,
                            arrival_rate_ewma: format!("{:.3}", snapshot.arrival_rate_per_second),
                            connect_latency_ewma_ms: format!("{:.3}", snapshot.connect_latency_ms),
                            recent_burst: format!("{:.3}", snapshot.recent_burst),
                        },
                    );
                }
                if let Some(snapshot) = profile_snapshot {
                    emit(
                        &self.logger,
                        &LogEvent::CoverProfileSummary {
                            generation: snapshot.generation,
                            cover_profile_state: snapshot.state.as_str(),
                            cover_profile_hit: snapshot.hit,
                            cover_profile_miss: snapshot.miss,
                            cover_profile_stale: snapshot.stale,
                            cover_profile_unstable: snapshot.unstable,
                            cover_profile_refresh: snapshot.refresh,
                            cover_profile_refresh_failure: snapshot.refresh_failure,
                            cover_profile_disagreement: snapshot.disagreement,
                            cover_profile_disabled: snapshot.disabled,
                            cover_profile_collecting: snapshot.collecting,
                            cover_profile_validated: snapshot.validated,
                        },
                    );
                }
            }
        }
    }
}

struct ConnectionRuntime {
    tag: Arc<str>,
    governor: ResourceGovernor,
    handler: ConnectionHandler,
}

enum ConnectionHandler {
    Public {
        reality: Box<RealityAcceptor>,
        vision: VisionHandler,
    },
    Nxr(NxrLandingHandler),
    Handoff(HandoffLandingHandler),
}

/// Rejects a reload that would change something only a restart can change.
///
/// The cold set is structural: which sockets exist, how this process dials,
/// which resolver it installed, and the resource posture the pools were sized
/// against. Everything else — users, routing, outbounds, log level, assets —
/// is hot, and a new generation simply replaces the old one.
///
/// The effective policy is *not* recompared here. It is derived once at
/// startup and stored in the store; a reload reuses it rather than deriving
/// again, so there is nothing for the two to disagree about. That is a direct
/// consequence of the policy no longer living inside the configuration: when
/// the two were the same value, a reload had to re-derive and re-compare to
/// tell an operator edit apart from a machine-view drift.
fn ensure_hot_compatible(
    current: &RuntimeSnapshot,
    candidate: NodeConfig,
) -> Result<NodeConfig, RuntimeUpdateError> {
    if listener_topology(&candidate) != listener_topology(&current.node) {
        return Err(RuntimeUpdateError::ListenerTopologyChanged);
    }
    if candidate.network() != current.node.network() {
        return Err(RuntimeUpdateError::NetworkDialPolicyChanged);
    }
    // The shared DNS resolver is a process-lifetime first-wins install, so a
    // reload can never swap it; reject DNS drift instead of silently keeping
    // the old resolver.
    if candidate.dns() != current.node.dns() {
        return Err(RuntimeUpdateError::DnsPolicyChanged);
    }
    // The runtime posture is cold: the descriptor budget, the memory monitor,
    // and every admission ceiling were sized against it before the first
    // listener bound. The resource mode compares resolved values against one
    // freshly detected machine view, so identical configurations never
    // disagree.
    let machine = MachineReport::detect();
    let current_runtime = current.node.runtime();
    let candidate_runtime = candidate.runtime();
    let posture_matches = resolve_resource_mode(current_runtime.profile(), &machine)
        == resolve_resource_mode(candidate_runtime.profile(), &machine)
        && current_runtime.profile() == candidate_runtime.profile()
        && current_runtime.tuning() == candidate_runtime.tuning()
        && current_runtime.objective() == candidate_runtime.objective()
        && current_runtime.status_file == candidate_runtime.status_file
        && current_runtime.limits() == candidate_runtime.limits();
    if !posture_matches {
        return Err(RuntimeUpdateError::ResourceModeChanged);
    }
    Ok(candidate)
}

/// What a bound socket speaks, for the reload topology comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ListenerRole {
    /// Public VLESS + REALITY + Vision.
    Entry,
    /// Internal NXR.
    Nxr,
    /// Internal Handoff.
    Handoff,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ListenerTopology {
    protocol: ListenerRole,
    mode: ListenFamily,
}

fn listener_topology(node: &NodeConfig) -> HashMap<SocketAddr, ListenerTopology> {
    let protocol = match node {
        NodeConfig::Entry(_) => ListenerRole::Entry,
        NodeConfig::Landing(landing) => match landing.landing {
            LandingProtocol::Nxr(_) => ListenerRole::Nxr,
            LandingProtocol::Handoff(_) => ListenerRole::Handoff,
        },
    };
    node.listeners()
        .iter()
        .flat_map(|listener| {
            let topology = ListenerTopology {
                protocol,
                mode: listener.family(),
            };
            listener
                .bind_addresses()
                .into_iter()
                .map(move |address| (address, topology))
        })
        .collect()
}

fn listener_addresses(node: &NodeConfig) -> Vec<SocketAddr> {
    node.listeners()
        .iter()
        .flat_map(ListenerConfig::bind_addresses)
        .collect()
}

fn canonical_listener_address(node: &NodeConfig) -> SocketAddr {
    listener_addresses(node)[0]
}

fn is_degradable_listener_bind_error(address: SocketAddr, error: &io::Error) -> bool {
    match error.raw_os_error() {
        // The kernel cannot create a socket for this protocol family.
        Some(93 | 97) => true,
        // An unspecified family wildcard may be unavailable on this host.
        // The same errno for a concrete address is invalid configuration.
        Some(99) => address.ip().is_unspecified(),
        _ => false,
    }
}

/// Builds the Handoff replay cache for every address a landing binds.
///
/// The capacity and retention are derived from the accepted clock skew rather
/// than configured: the cache exists to bound memory while covering the window
/// in which a replayed transfer could still be accepted.
fn compile_handoff_replays(
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
        usize::try_from(super::nxr::REPLAY_NONCE_CAPACITY)
            .map_err(|_| HandoffLandingConfigError::Capacity)
            .map_err(RuntimeUpdateError::Handoff)?,
        Duration::from_secs(super::nxr::replay_retention_seconds(
            settings.timing().max_time_difference_seconds,
        )),
    )
    .map_err(HandoffLandingConfigError::Replay)
    .map_err(RuntimeUpdateError::Handoff)?;
    replays.insert(address, replay);
    Ok(replays)
}

/// Builds the NXR replay cache for every address a landing binds.
fn compile_nxr_replays(
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

/// Runs one listener until shutdown, surviving every recoverable accept error.
///
/// # The invariant this function exists to hold
///
/// The listener task must not return `Err` for any condition the process can
/// recover from. The previous implementation propagated every accept error with
/// `?`, so `accept4(...) = -1 EMFILE` terminated the server. Here only
/// [`AcceptErrorClass::Fatal`] leaves the loop, and it does so with the raw
/// errno attached so the operator can identify it.
///
/// # Ordering
///
/// The descriptor permit is acquired *before* `accept`, never after. Acquiring
/// after would mean the kernel had already created a descriptor the process had
/// not reserved, which is precisely the accounting gap that produced the
/// incident.
async fn run_listener(
    acceptor: TcpAcceptor,
    address: SocketAddr,
    runtime: Arc<RuntimeStore>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let mut connections = ConnectionTasks::new();
    let fd_budget = runtime.fd_budget.clone();
    let mut backoff = AcceptBackoff::new();
    // Starting without the reserve is a degraded but serviceable state:
    // admission still bounds descriptors, and the reserve only covers pressure
    // that originates outside this process's accounting.
    let mut reserve = EmergencyDescriptor::open().ok();
    let mut last_pressure = fd_budget.pressure();
    loop {
        // At critical resource pressure, pause before touching the listener.
        // The wait is a `Notify` wakeup, never a poll loop, it costs one
        // atomic load in any other state, and it stays cancellable so
        // shutdown is prompt. Established connections are unaffected: their
        // tasks are already running.
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            () = runtime.pressure.wait_while_critical() => {}
        }

        // Acquire the inbound descriptor permit before touching the listener.
        // When capacity is exhausted this waits on a `Notify` rather than
        // spinning, and it remains cancellable so shutdown is still prompt.
        let fd_permit = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            permit = fd_budget.acquire(UNITS_INBOUND_SOCKET) => permit,
            completed = connections.join_next(), if !connections.is_empty() => {
                consume_connection_result(completed);
                continue;
            }
        };

        let pressure = fd_budget.pressure();
        if pressure != last_pressure {
            last_pressure = pressure;
            let snapshot = runtime.load();
            emit(
                &snapshot.logger,
                &LogEvent::DescriptorPressureChanged {
                    fd_pressure_state: pressure.as_str(),
                    fd_units_in_use: fd_budget.in_use(),
                    fd_effective_budget: fd_budget.capacity(),
                },
            );
        }

        tokio::select! {
            changed = shutdown.changed() => {
                drop(fd_permit);
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = acceptor.accept_only() => {
                match accepted {
                    Ok((stream, peer)) => {
                        backoff.reset();
                        if runtime.pressure.state() == ResourcePressure::Critical {
                            // The connection raced the critical transition
                            // while the listener was parked in `accept`. Fail
                            // it fast through the ordinary decline path; the
                            // next loop iteration parks on the pressure gate.
                            drop(stream);
                            drop(fd_permit);
                            let snapshot = runtime.load();
                            emit(
                                &snapshot.logger,
                                &LogEvent::ConnectionRejected {
                                    peer,
                                    reason: RejectionReason::ResourceLimit,
                                },
                            );
                            continue;
                        }
                        admit_accepted_connection(
                            &runtime,
                            &mut connections,
                            address,
                            stream,
                            peer,
                            fd_permit,
                        );
                    }
                    Err(error) => {
                        // Release the reservation immediately: no descriptor was
                        // created, so holding it would shrink capacity on every
                        // failed accept until the listener starved itself.
                        drop(fd_permit);
                        let class = AcceptErrorClass::classify(&error);
                        if class.is_fatal() {
                            return Err(io::Error::new(
                                error.kind(),
                                format!(
                                    "listener {address} cannot accept: {class} \
                                     (errno {errno:?}): {error}",
                                    class = class.as_str(),
                                    errno = error.raw_os_error(),
                                ),
                            ));
                        }
                        if class == AcceptErrorClass::DescriptorPressure
                            && let Some(reserve) = reserve.as_mut()
                        {
                            recover_from_descriptor_pressure(&acceptor, reserve).await;
                        }
                        let delay = if class.needs_backoff() {
                            backoff.next_delay()
                        } else {
                            Duration::ZERO
                        };
                        if class != AcceptErrorClass::WouldBlock {
                            let snapshot = runtime.load();
                            emit(
                                &snapshot.logger,
                                &LogEvent::AcceptErrorRecovered {
                                    address,
                                    accept_error_class: class.as_str(),
                                    errno: error.raw_os_error(),
                                    accept_backoff_ms: backoff.current_ms(),
                                },
                            );
                        }
                        if !delay.is_zero() {
                            tokio::select! {
                                changed = shutdown.changed() => {
                                    if changed.is_err() || *shutdown.borrow() {
                                        break;
                                    }
                                }
                                () = time::sleep(delay) => {}
                            }
                        }
                    }
                }
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                drop(fd_permit);
                consume_connection_result(completed);
            }
        }
    }
    drain_connections(&mut connections).await;
    Ok(())
}

/// Samples the bounded memory signal and publishes the combined pressure state.
///
/// This is the only place the pressure gauge is written outside tests. It
/// runs on a fixed interval — never in a read, write or record loop — folds
/// the descriptor dimension in from the budget's own hysteresis watermarks,
/// and logs transitions only, so a sustained condition costs two log lines
/// rather than one per second.
async fn run_resource_monitor(
    runtime: Arc<RuntimeStore>,
    watch: MemoryWatch,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut memory_state = ResourcePressure::Normal;
    let mut last_usage: Option<u64> = None;
    let mut last_source = watch.sampler.configured_source();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            () = time::sleep(MEMORY_SAMPLE_INTERVAL) => {}
        }
        if *shutdown.borrow() {
            break;
        }
        let fd_state = ResourcePressure::from(runtime.fd_budget.pressure());
        if let Some(reading) = watch.sampler.sample() {
            // An unreadable sample keeps the previous state: a monitoring gap
            // must never itself raise or clear an alarm. A sampler that falls
            // back to a different source reports the source actually used,
            // so a fallback can never masquerade as the configured source.
            if reading.source != last_source {
                let snapshot = runtime.load();
                emit(
                    &snapshot.logger,
                    &LogEvent::MemorySamplerChanged {
                        from: last_source.as_str(),
                        to: reading.source.as_str(),
                    },
                );
                last_source = reading.source;
            }
            last_usage = Some(reading.bytes);
            memory_state = watch.plan.classify(memory_state, reading.bytes);
        }
        let effective = fd_state.max(memory_state);
        if runtime.pressure.set(effective) {
            let snapshot = runtime.load();
            emit(
                &snapshot.logger,
                &LogEvent::ResourcePressureChanged {
                    pressure_state: effective.as_str(),
                    fd_pressure_state: runtime.fd_budget.pressure().as_str(),
                    memory_bytes_in_use: last_usage,
                    memory_pressure_enter: watch.plan.pressure_enter(),
                    memory_critical_enter: watch.plan.critical_enter(),
                },
            );
        }
    }
}

/// Builds the adaptive soft-ceiling controller when the tuning mode selects one.
///
/// The controller exists only under `adaptive`: under `startup` no controller
/// is built and nothing ever adjusts a ceiling or the dial rate. Its bounds
/// come from the effective startup policy, so every hard bound is exactly the
/// value the pools were constructed with.
fn adaptive_controller(
    node: &NodeConfig,
    policy: &EffectivePolicy,
    authorities: &ProcessAuthorities,
    pressure: &PressureGauge,
) -> Option<adaptive::AdaptiveController> {
    let runtime = node.runtime();
    (runtime.tuning() == TuningMode::Adaptive).then(|| {
        adaptive::AdaptiveController::new(
            authorities.governor.clone(),
            authorities.direct_barrier.clone(),
            pressure.clone(),
            policy,
            runtime.status_file.clone(),
        )
    })
}

/// Runs the adaptive controller until shutdown.
///
/// One tick every five seconds, driven by the same cancellable
/// sleep-or-shutdown pattern as the resource monitor; the loop holds no
/// lock across an await, so shutdown is never delayed. Observability is
/// transition-based: exactly one structured event per knob change, and the
/// status file (when `runtime.statusFile` is set) is rewritten at startup
/// and whenever a ceiling or the pressure state changed — never per tick.
async fn run_adaptive_controller(
    runtime: Arc<RuntimeStore>,
    mut controller: adaptive::AdaptiveController,
    mut shutdown: watch::Receiver<bool>,
) {
    // Publish the initial snapshot so `runtime report` works before the
    // first transition.
    write_adaptive_status(&runtime, &controller);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            () = time::sleep(adaptive::TICK_INTERVAL) => {}
        }
        if *shutdown.borrow() {
            break;
        }
        let now = adaptive::unix_millis();
        let outcome = controller.tick(now);
        if outcome.changes.is_empty() && !outcome.pressure_changed {
            continue;
        }
        let snapshot = runtime.load();
        for change in &outcome.changes {
            emit(
                &snapshot.logger,
                &LogEvent::AdaptiveCeilingChanged {
                    knob: change.knob.name(),
                    reason: change.reason.as_str(),
                    from: change.from,
                    to: change.to,
                    floor: change.floor,
                    ceiling: change.ceiling,
                },
            );
        }
        drop(snapshot);
        write_adaptive_status(&runtime, &controller);
    }
}

/// Rewrites the status file, logging a bounded warning on failure.
fn write_adaptive_status(runtime: &Arc<RuntimeStore>, controller: &adaptive::AdaptiveController) {
    if let Err(error) = controller.write_status(adaptive::unix_millis()) {
        let snapshot = runtime.load();
        emit(
            &snapshot.logger,
            &LogEvent::AdaptiveStatusWriteFailed {
                path: controller
                    .status_file()
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
                error: error.to_string(),
            },
        );
    }
}

async fn run_network_refresh(
    environment: NetworkEnvironment,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            () = time::sleep(interval) => environment.refresh_routes(),
        }
    }
}

/// Configures and admits one accepted stream.
///
/// A socket-configuration failure closes exactly that stream and releases
/// exactly its permit. It never reaches the listener loop as an error.
fn admit_accepted_connection(
    runtime: &Arc<RuntimeStore>,
    connections: &mut ConnectionTasks,
    address: SocketAddr,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    fd_permit: FdPermit,
) {
    let snapshot = runtime.load();
    let Some(state) = snapshot.connections.get(&address).cloned() else {
        // A reload cannot remove a listener, so this is unreachable in practice;
        // dropping the stream is still the correct conservative response.
        drop(stream);
        drop(fd_permit);
        return;
    };
    let logger = snapshot.logger.clone();
    drop(snapshot);

    if let Err(error) = TcpAcceptor::configure_accepted(&stream) {
        let _unused = error;
        drop(stream);
        drop(fd_permit);
        emit(
            &logger,
            &LogEvent::ConnectionRejected {
                peer,
                reason: RejectionReason::SocketConfiguration,
            },
        );
        return;
    }

    let permit = match state.governor.try_acquire(AdmissionKind::Connection) {
        Ok(permit) => permit,
        Err(error) => {
            drop(stream);
            drop(fd_permit);
            emit_admission(&logger, error);
            emit(
                &logger,
                &LogEvent::ConnectionRejected {
                    peer,
                    reason: RejectionReason::ResourceLimit,
                },
            );
            return;
        }
    };
    emit_debug(&logger, || LogEvent::ConnectionAccepted { peer });
    connections.spawn(peer, async move {
        // Both permits move into the task and are released when it ends, on
        // every path including cancellation and abort.
        let _fd_permit = fd_permit;
        run_connection(state, stream, peer, permit, &logger).await
    });
}

/// Drains one backlog entry using the emergency reserve descriptor.
///
/// This runs only when `accept` reported `EMFILE`/`ENFILE` despite strict
/// admission, which means descriptors were consumed outside this process's
/// accounting. Releasing the reserve makes exactly one accept possible; the
/// accepted socket is closed immediately, so the peer observes a reset rather
/// than an indefinite hang and the backlog advances by one.
async fn recover_from_descriptor_pressure(
    acceptor: &TcpAcceptor,
    reserve: &mut EmergencyDescriptor,
) {
    if !reserve.release() {
        return;
    }
    // A single non-blocking attempt. Waiting here would stall the listener for
    // an arbitrary time while holding no reservation.
    if let Ok(Ok((stream, _peer))) =
        time::timeout(Duration::from_millis(1), acceptor.accept_only()).await
    {
        drop(stream);
    }
    // Reacquiring can fail while the process is still at its limit. That is a
    // recoverable state: the next pressure event simply finds no reserve, and
    // admission continues to bound everything this process does account for.
    let _unused = reserve.reacquire();
}

async fn run_connection(
    state: Arc<ConnectionRuntime>,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    connection_permit: AdmissionPermit,
    logger: &Logger,
) -> io::Result<()> {
    let started = std::time::Instant::now();
    let mut completion = None;
    let result = async {
        match &state.handler {
            ConnectionHandler::Public { reality, vision } => {
                match reality.accept(stream, peer).await? {
                    RealityAcceptOutcome::Established(mut established) => {
                        if logger.debug_enabled()
                            && let Some(evidence) = established.take_cover_flight_evidence()
                        {
                            let digest = Sha256::digest(&evidence.retained_prefix);
                            let mut retained_prefix_sha256 = String::with_capacity(64);
                            for byte in digest {
                                let _ = write!(&mut retained_prefix_sha256, "{byte:02x}");
                            }
                            emit(
                                logger,
                                &LogEvent::CoverFlightSelected {
                                    emit_ccs: evidence.emit_ccs,
                                    layout: evidence.layout,
                                    wire_lens: evidence.wire_lens,
                                    nst_wire_len: evidence.nst_wire_len,
                                    retained_prefix_bytes: evidence.retained_prefix.len(),
                                    retained_prefix_sha256,
                                },
                            );
                        }
                        let stats = vision.handle(*established).await?;
                        completion = Some(stats);
                    }
                    RealityAcceptOutcome::Fallback(_) => {}
                }
            }
            ConnectionHandler::Nxr(handler) => {
                handler.handle(stream).await?;
            }
            ConnectionHandler::Handoff(handler) => {
                handler.handle(stream).await?;
            }
        }
        Ok::<(), ConnectionRunError>(())
    }
    .await;
    drop(connection_permit);
    match result {
        Ok(()) => {
            if let Some(stats) = completion {
                emit_debug(logger, || LogEvent::ConnectionCompleted {
                    duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    uplink_bytes: stats.uplink_bytes(),
                    downlink_bytes: stats.downlink_bytes(),
                    uplink_direct: stats.uplink_direct(),
                    downlink_direct: stats.downlink_direct(),
                    relay_backend: stats.relay_backend().map(RelayBackend::as_str),
                    uplink_direct_at_bytes: stats.uplink_direct_at_bytes(),
                    downlink_direct_at_bytes: stats.downlink_direct_at_bytes(),
                    uplink_backend: stats.uplink_backend().map(RelayBackend::as_str),
                    downlink_backend: stats.downlink_backend().map(RelayBackend::as_str),
                    uplink_handoff_delay_us: stats.uplink_handoff_delay_us(),
                    downlink_handoff_delay_us: stats.downlink_handoff_delay_us(),
                    handoff_server_sequence: stats.handoff_server_sequence(),
                    pipe_capacity_downgraded: stats.pipe_capacity_downgraded(),
                });
            }
            emit_debug(logger, || LogEvent::ConnectionClosed { peer });
            Ok(())
        }
        Err(error) if error.is_quiet_pre_auth_retirement() => {
            // READY-socket lifetime rotation closes a zero-byte transport by
            // design. It granted no authority and started no authentication,
            // so reporting it as a warn-level authentication rejection would
            // turn ordinary idle maintenance into unbounded log I/O.
            emit_debug(logger, || LogEvent::ConnectionClosed { peer });
            Ok(())
        }
        Err(error) => {
            emit_connection_failure(logger, peer, &error);
            Err(io::Error::other(error))
        }
    }
}

fn emit_connection_failure(logger: &Logger, peer: SocketAddr, error: &ConnectionRunError) {
    // A direct-barrier denial is a resource-limit event, not an ordinary
    // outbound failure: report the bounded resource next to the rejection so
    // operators can tell the two apart.
    if let Some(denied) = error.admission_denial() {
        emit_admission(logger, denied);
    }
    emit(
        logger,
        &LogEvent::ConnectionRejected {
            peer,
            reason: error.rejection_reason(),
        },
    );
}

async fn drain_connections(connections: &mut ConnectionTasks) {
    let drain = async {
        while !connections.is_empty() {
            consume_connection_result(connections.join_next().await);
        }
    };
    if time::timeout(GRACEFUL_SHUTDOWN_TIMEOUT, drain)
        .await
        .is_err()
    {
        connections.abort_all();
        while !connections.is_empty() {
            consume_connection_result(connections.join_next().await);
        }
    }
}

fn consume_connection_result(
    completed: Option<Result<crate::runtime::connection::ConnectionTaskResult, JoinError>>,
) {
    if let Some(Ok(result)) = completed {
        let (_, connection_result) = result.into_parts();
        let _ignored = connection_result;
    }
}

fn reset_refresh(refresh: &mut std::pin::Pin<Box<Sleep>>, interval: Duration) {
    refresh.as_mut().reset(Instant::now() + interval);
}

fn emit(logger: &Logger, event: &LogEvent) {
    let _ignored = logger.emit(event);
}

/// Emits one debug-only event, constructing it only when debug evidence can
/// actually reach the configured sink.
///
/// Per-connection callers stay at zero cost when debug is disabled: no stats
/// accessors run and no event is allocated, whereas the warn-level rejections
/// stay eager because they are operator signal.
fn emit_debug(logger: &Logger, event: impl FnOnce() -> LogEvent) {
    if logger.debug_enabled() {
        emit(logger, &event());
    }
}

fn emit_rejected(runtime: &RuntimeStore, field: &'static str, error: Option<&RuntimeUpdateError>) {
    emit(
        &runtime.load().logger,
        &LogEvent::ConfigurationRejected {
            field: field.to_owned(),
        },
    );
    // The structured event stays a closed shape (a stable path, never
    // configuration content); the full compiler-style diagnostic goes to
    // stderr instead, where systemd captures it into the journal and an
    // interactive operator sees it directly.
    if let Some(error) = error {
        let _ignored = writeln!(
            io::stderr().lock(),
            "configuration {field} reload rejected:\n{error}"
        );
    }
}

fn emit_admission(logger: &Logger, error: AdmissionDenied) {
    let resource = match error {
        AdmissionDenied::Limit(AdmissionKind::Connection)
        | AdmissionDenied::Pressure(AdmissionKind::Connection) => AdmissionResource::Connections,
        AdmissionDenied::Limit(AdmissionKind::PreAuthIdle)
        | AdmissionDenied::Pressure(AdmissionKind::PreAuthIdle) => {
            AdmissionResource::PreAuthIdleConnections
        }
        AdmissionDenied::Limit(AdmissionKind::Handshake)
        | AdmissionDenied::Pressure(AdmissionKind::Handshake) => AdmissionResource::Handshakes,
        AdmissionDenied::Limit(AdmissionKind::Fallback)
        | AdmissionDenied::Pressure(AdmissionKind::Fallback) => AdmissionResource::Fallbacks,
        AdmissionDenied::Limit(AdmissionKind::CryptoOperation)
        | AdmissionDenied::Pressure(AdmissionKind::CryptoOperation) => {
            AdmissionResource::CryptoOperations
        }
        AdmissionDenied::Limit(AdmissionKind::ReplayEntry)
        | AdmissionDenied::Pressure(AdmissionKind::ReplayEntry) => AdmissionResource::ReplayEntries,
        AdmissionDenied::Limit(AdmissionKind::DnsLookup)
        | AdmissionDenied::Pressure(AdmissionKind::DnsLookup) => AdmissionResource::Handshakes,
        AdmissionDenied::DirectConcurrency
        | AdmissionDenied::DirectRate
        | AdmissionDenied::DirectPressure => AdmissionResource::DirectConnections,
        AdmissionDenied::Unavailable => AdmissionResource::Connections,
    };
    emit(logger, &LogEvent::AdmissionLimited { resource });
}

#[cfg(unix)]
async fn forward_reload_signals(mut signal: tokio::signal::unix::Signal, sender: mpsc::Sender<()>) {
    while signal.recv().await.is_some() {
        match sender.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(())) => {}
            Err(mpsc::error::TrySendError::Closed(())) => break,
        }
    }
}

async fn shutdown_signal() -> Result<(), io::Error> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

#[derive(Debug)]
enum ConnectionRunError {
    Reality(RealityAcceptError),
    Vision(VisionSessionError),
    Nxr(NxrLandingError),
    Handoff(HandoffLandingError),
}

impl ConnectionRunError {
    const fn is_quiet_pre_auth_retirement(&self) -> bool {
        matches!(
            self,
            Self::Nxr(
                NxrLandingError::PreAuthPeerClosed | NxrLandingError::PreAuthGenerationRetired,
            ) | Self::Handoff(
                HandoffLandingError::PreAuthPeerClosed
                    | HandoffLandingError::PreAuthGenerationRetired,
            )
        )
    }

    fn rejection_reason(&self) -> RejectionReason {
        match self {
            Self::Reality(RealityAcceptError::Admission(_)) => RejectionReason::ResourceLimit,
            Self::Nxr(NxrLandingError::Admission(_) | NxrLandingError::Reclaimed)
            | Self::Handoff(HandoffLandingError::Admission(_) | HandoffLandingError::Reclaimed) => {
                RejectionReason::ResourceLimit
            }
            Self::Reality(RealityAcceptError::HandshakeWriteTimeout)
            | Self::Vision(VisionSessionError::Timeout)
            | Self::Nxr(NxrLandingError::Timeout)
            | Self::Handoff(HandoffLandingError::Timeout) => RejectionReason::Timeout,
            Self::Reality(RealityAcceptError::Fallback(_)) => RejectionReason::Outbound,
            Self::Reality(_) => RejectionReason::Authentication,
            Self::Vision(VisionSessionError::Outbound(
                crate::server::outbound::OutboundConnectError::Admission(_)
                | crate::server::outbound::OutboundConnectError::DescriptorBudget,
            ))
            | Self::Vision(VisionSessionError::HandoffLine(
                crate::server::handoff::HandoffLineError::DescriptorBudget,
            ))
            | Self::Nxr(NxrLandingError::DescriptorBudget)
            | Self::Handoff(HandoffLandingError::DescriptorBudget) => {
                RejectionReason::ResourceLimit
            }
            Self::Vision(VisionSessionError::Route(_) | VisionSessionError::Outbound(_)) => {
                RejectionReason::Outbound
            }
            Self::Vision(VisionSessionError::HandoffLine(_))
            | Self::Nxr(NxrLandingError::Destination(_) | NxrLandingError::Relay(_))
            | Self::Handoff(
                HandoffLandingError::Destination(_)
                | HandoffLandingError::Egress(_)
                | HandoffLandingError::Session(_),
            ) => RejectionReason::Outbound,
            Self::Nxr(_) | Self::Handoff(_) => RejectionReason::Authentication,
            Self::Vision(VisionSessionError::Relay(error)) if is_liveness_timeout_abort(error) => {
                // A mid-transfer liveness kill is rewrapped as
                // `ConnectionAborted` so a truncated transfer can never pass
                // for a clean idle close, but the cause is the liveness
                // policy: classify it as a timeout, not a protocol rejection.
                RejectionReason::Timeout
            }
            Self::Vision(_) => RejectionReason::Protocol,
        }
    }

    /// Returns the admission denial carried by an outbound barrier rejection.
    const fn admission_denial(&self) -> Option<AdmissionDenied> {
        match self {
            Self::Vision(VisionSessionError::Outbound(
                crate::server::outbound::OutboundConnectError::Admission(denied),
            )) => Some(*denied),
            Self::Nxr(NxrLandingError::Admission(denied))
            | Self::Handoff(HandoffLandingError::Admission(denied)) => Some(*denied),
            _ => None,
        }
    }
}

impl From<RealityAcceptError> for ConnectionRunError {
    fn from(source: RealityAcceptError) -> Self {
        Self::Reality(source)
    }
}

impl From<VisionSessionError> for ConnectionRunError {
    fn from(source: VisionSessionError) -> Self {
        Self::Vision(source)
    }
}

impl From<NxrLandingError> for ConnectionRunError {
    fn from(source: NxrLandingError) -> Self {
        Self::Nxr(source)
    }
}

impl From<HandoffLandingError> for ConnectionRunError {
    fn from(source: HandoffLandingError) -> Self {
        Self::Handoff(source)
    }
}

impl fmt::Display for ConnectionRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reality(source) => source.fmt(formatter),
            Self::Vision(source) => source.fmt(formatter),
            Self::Nxr(source) => source.fmt(formatter),
            Self::Handoff(source) => source.fmt(formatter),
        }
    }
}

impl Error for ConnectionRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Reality(source) => Some(source),
            Self::Vision(source) => Some(source),
            Self::Nxr(source) => Some(source),
            Self::Handoff(source) => Some(source),
        }
    }
}

/// One last-good runtime update failed before publication.
#[derive(Debug)]
pub enum RuntimeUpdateError {
    Load(LoadError),
    Log(LogWriteError),
    Assets(AssetLoadError),
    Routing(RoutingCompileError),
    Reality(RealityAcceptorConfigError),
    Nxr(NxrLandingConfigError),
    Handoff(HandoffLandingConfigError),
    DuplicateListener(SocketAddr),
    MissingNxrReplay(SocketAddr),
    MissingHandoffReplay(SocketAddr),
    ListenerTopologyChanged,
    NetworkDialPolicyChanged,
    DnsPolicyChanged,
    ResourceModeChanged,
    ReplayPolicyChanged,
    DirectBarrierPolicyChanged,
    WarmConnectionPolicyChanged,
    NxrReplayPolicyChanged,
    HandoffReplayPolicyChanged,
    Relay(TcpRelayConfigError),
    RelayPolicyChanged,
    GenerationExhausted,
    Unavailable,
}

impl fmt::Display for RuntimeUpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Load(source) => source.fmt(formatter),
            Self::Log(source) => source.fmt(formatter),
            Self::Assets(source) => source.fmt(formatter),
            Self::Routing(source) => source.fmt(formatter),
            Self::Reality(source) => source.fmt(formatter),
            Self::Nxr(source) => source.fmt(formatter),
            Self::Handoff(source) => source.fmt(formatter),
            Self::DuplicateListener(address) => write!(formatter, "duplicate listener {address}"),
            Self::MissingNxrReplay(address) => {
                write!(
                    formatter,
                    "NXR replay cache is missing for listener {address}"
                )
            }
            Self::MissingHandoffReplay(address) => {
                write!(
                    formatter,
                    "Handoff replay cache is missing for listener {address}"
                )
            }
            Self::ListenerTopologyChanged => {
                formatter.write_str("listener addresses require a process restart")
            }
            Self::NetworkDialPolicyChanged => {
                formatter.write_str("network dial policy requires a process restart")
            }
            Self::DnsPolicyChanged => {
                formatter.write_str("DNS resolver policy requires a process restart")
            }
            Self::ResourceModeChanged => formatter.write_str(
                "runtime profile, tuning, or resource-mode changes require a process restart",
            ),
            Self::ReplayPolicyChanged => {
                formatter.write_str("resource governor policy requires a process restart")
            }
            Self::DirectBarrierPolicyChanged => {
                formatter.write_str("direct barrier policy requires a process restart")
            }
            Self::WarmConnectionPolicyChanged => {
                formatter.write_str("warm connection policy requires a process restart")
            }
            Self::NxrReplayPolicyChanged => {
                formatter.write_str("NXR replay policy requires a process restart")
            }
            Self::HandoffReplayPolicyChanged => {
                formatter.write_str("Handoff replay policy requires a process restart")
            }
            Self::Relay(source) => source.fmt(formatter),
            Self::RelayPolicyChanged => {
                formatter.write_str("TCP relay policy requires a process restart")
            }
            Self::GenerationExhausted => formatter.write_str("runtime generation exhausted"),
            Self::Unavailable => formatter.write_str("runtime update is unavailable"),
        }
    }
}

impl Error for RuntimeUpdateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Load(source) => Some(source),
            Self::Log(source) => Some(source),
            Self::Assets(source) => Some(source),
            Self::Routing(source) => Some(source),
            Self::Reality(source) => Some(source),
            Self::Nxr(source) => Some(source),
            Self::Handoff(source) => Some(source),
            Self::Relay(source) => Some(source),
            Self::DuplicateListener(_)
            | Self::MissingNxrReplay(_)
            | Self::MissingHandoffReplay(_)
            | Self::ListenerTopologyChanged
            | Self::NetworkDialPolicyChanged
            | Self::DnsPolicyChanged
            | Self::ResourceModeChanged
            | Self::ReplayPolicyChanged
            | Self::DirectBarrierPolicyChanged
            | Self::WarmConnectionPolicyChanged
            | Self::NxrReplayPolicyChanged
            | Self::HandoffReplayPolicyChanged
            | Self::RelayPolicyChanged
            | Self::GenerationExhausted
            | Self::Unavailable => None,
        }
    }
}

impl From<LoadError> for RuntimeUpdateError {
    fn from(source: LoadError) -> Self {
        Self::Load(source)
    }
}

impl From<LogWriteError> for RuntimeUpdateError {
    fn from(source: LogWriteError) -> Self {
        Self::Log(source)
    }
}

impl From<AssetLoadError> for RuntimeUpdateError {
    fn from(source: AssetLoadError) -> Self {
        Self::Assets(source)
    }
}

impl From<RoutingCompileError> for RuntimeUpdateError {
    fn from(source: RoutingCompileError) -> Self {
        Self::Routing(source)
    }
}

impl From<RealityAcceptorConfigError> for RuntimeUpdateError {
    fn from(source: RealityAcceptorConfigError) -> Self {
        Self::Reality(source)
    }
}

impl From<NxrLandingConfigError> for RuntimeUpdateError {
    fn from(source: NxrLandingConfigError) -> Self {
        Self::Nxr(source)
    }
}

impl From<HandoffLandingConfigError> for RuntimeUpdateError {
    fn from(source: HandoffLandingConfigError) -> Self {
        Self::Handoff(source)
    }
}

impl From<TcpRelayConfigError> for RuntimeUpdateError {
    fn from(source: TcpRelayConfigError) -> Self {
        Self::Relay(source)
    }
}

/// Production server construction or lifecycle failed.
#[derive(Debug)]
pub enum ProductionServerError {
    /// The process descriptor limit cannot support a usable admission budget.
    ///
    /// This is returned before any listener is bound, so an impossible limit is
    /// a startup failure with a concrete recommendation rather than an
    /// `accept4` failure under load.
    DescriptorBudget(FdBudgetError),
    /// The configured DNS resolver could not be constructed at startup.
    Dns(DnsResolverConfigError),
    Runtime(RuntimeUpdateError),
    Bind {
        address: SocketAddr,
        source: io::Error,
    },
    ListenerAddress(io::Error),
    Accept(io::Error),
    Signal(io::Error),
    Task(JoinError),
    ListenerStopped,
}

impl fmt::Display for ProductionServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(source) => source.fmt(formatter),
            Self::DescriptorBudget(source) => source.fmt(formatter),
            Self::Dns(source) => source.fmt(formatter),
            Self::Bind { address, .. } => write!(formatter, "failed to bind listener {address}"),
            Self::ListenerAddress(_) => formatter.write_str("failed to read listener address"),
            Self::Accept(_) => formatter.write_str("listener accept failed"),
            Self::Signal(_) => formatter.write_str("failed to install process signal"),
            Self::Task(_) => formatter.write_str("listener task failed"),
            Self::ListenerStopped => formatter.write_str("listener stopped unexpectedly"),
        }
    }
}

impl Error for ProductionServerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Runtime(source) => Some(source),
            Self::Bind { source, .. }
            | Self::ListenerAddress(source)
            | Self::Accept(source)
            | Self::Signal(source) => Some(source),
            Self::Task(source) => Some(source),
            Self::DescriptorBudget(source) => Some(source),
            Self::Dns(source) => Some(source),
            Self::ListenerStopped => None,
        }
    }
}

impl From<RuntimeUpdateError> for ProductionServerError {
    fn from(source: RuntimeUpdateError) -> Self {
        Self::Runtime(source)
    }
}

/// Renders one stable capability line per backend for the startup report.
///
/// Static declines are emitted here exactly once. Nothing in this function can
/// produce a high-cardinality or connection-specific value.
fn backend_statuses(report: &BackendReport) -> Vec<BackendStatus> {
    report
        .entries()
        .into_iter()
        .map(|(backend, capability)| BackendStatus {
            backend: backend.as_str(),
            available: capability.available,
            decline_reason: capability.decline_reason.map(BackendDeclineReason::as_str),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::oneshot,
        time,
    };

    use super::{
        ConnectionRunError, ProductionServer, RuntimeUpdateError,
        is_degradable_listener_bind_error, theoretical_fd_peak,
    };
    use crate::{
        config::{
            ValidatedConfig,
            node::{
                fixture,
                listener::ListenFamily,
                log::{LogConfig, LogLevel, LogOutput},
                outbound::{NxrOutboundConfig, OutboundConfig},
                runtime::RuntimeProfile,
            },
        },
        protocol::vless::{Address, Destination, VISION_FLOW},
        runtime::policy::{DirectBarrierPolicy, ResourceMode},
        server::{
            handoff::HandoffLandingError,
            nxr::NxrLandingError,
            outbound::{OutboundConnectOutcome, OutboundRegistry},
        },
    };

    #[test]
    fn zero_byte_warm_retirement_is_quiet_for_both_landing_protocols() {
        assert!(
            ConnectionRunError::Handoff(HandoffLandingError::PreAuthPeerClosed)
                .is_quiet_pre_auth_retirement()
        );
        assert!(
            ConnectionRunError::Nxr(NxrLandingError::PreAuthPeerClosed)
                .is_quiet_pre_auth_retirement()
        );
        assert!(
            ConnectionRunError::Handoff(HandoffLandingError::PreAuthGenerationRetired)
                .is_quiet_pre_auth_retirement()
        );
        assert!(
            !ConnectionRunError::Nxr(NxrLandingError::Read(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer stalled after byte one",
            )))
            .is_quiet_pre_auth_retirement(),
            "EOF after authentication starts must remain a rejection"
        );
    }

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

    fn simulate_listener_startup(
        mode: ListenFamily,
        outcomes: &[(SocketAddr, Option<i32>)],
    ) -> Result<Vec<SocketAddr>, SocketAddr> {
        let mut active = Vec::new();
        for (address, errno) in outcomes {
            let Some(errno) = errno else {
                active.push(*address);
                continue;
            };
            let error = io::Error::from_raw_os_error(*errno);
            if mode != ListenFamily::Auto || !is_degradable_listener_bind_error(*address, &error) {
                return Err(*address);
            }
        }
        if active.is_empty() {
            Err(outcomes[0].0)
        } else {
            Ok(active)
        }
    }

    #[test]
    fn auto_listener_starts_on_simulated_single_family_hosts() {
        let ipv4 = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 443);
        let ipv6 = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 443);
        assert_eq!(
            simulate_listener_startup(ListenFamily::Auto, &[(ipv4, None), (ipv6, Some(97))]),
            Ok(vec![ipv4])
        );
        assert_eq!(
            simulate_listener_startup(ListenFamily::Auto, &[(ipv4, Some(97)), (ipv6, None)]),
            Ok(vec![ipv6])
        );
    }

    #[test]
    fn dual_stack_requires_both_families_and_auto_never_swallows_real_bind_errors() {
        let ipv4 = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 443);
        let ipv6 = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 443);
        assert_eq!(
            simulate_listener_startup(ListenFamily::DualStack, &[(ipv4, None), (ipv6, Some(97))]),
            Err(ipv6)
        );
        for errno in [13, 22, 98] {
            assert_eq!(
                simulate_listener_startup(ListenFamily::Auto, &[(ipv4, None), (ipv6, Some(errno))]),
                Err(ipv6),
                "errno {errno} must remain fatal"
            );
        }
        let concrete = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443);
        assert_eq!(
            simulate_listener_startup(ListenFamily::Auto, &[(ipv4, None), (concrete, Some(99))]),
            Err(concrete),
            "EADDRNOTAVAIL on a configured address is invalid configuration"
        );
    }

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

    #[tokio::test(flavor = "current_thread")]
    async fn binds_all_listeners_and_stops_on_injected_shutdown() {
        let config = entry_config(unused_loopback_port());
        let server = ProductionServer::from_config(config.clone()).expect("server must compile");

        server
            .run_until(async { Ok(()) })
            .await
            .expect("injected shutdown must stop every listener");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_landing_node_serves_an_authenticated_nxr_session() {
        // Entry and landing are separate nodes now, so this drives a landing
        // the way a line node would: one authenticated NXR connection from an
        // outbound registry to a landing server.
        let landing_port = unused_loopback_port();
        let key_bytes = [0x5a; 32];
        let encoded_key = BASE64_URL_SAFE_NO_PAD.encode(key_bytes);
        let config = fixture::validated(&format!(
            r#"{{
  "role": "landing",
  "listeners": [{{ "port": {landing_port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "landing": {{ "protocol": "nxr", "psk": "{encoded_key}",
                "authenticationTimeoutMs": 1000, "connectTimeoutMs": 1000 }}
}}"#
        ));
        let server = ProductionServer::from_config(config).expect("landing must compile");
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("target must bind");
        let destination = Destination::new(
            Address::Ipv4(Ipv4Addr::LOCALHOST),
            target
                .local_addr()
                .expect("target address must exist")
                .port(),
        );
        let registry = OutboundRegistry::new(
            &std::collections::BTreeMap::from([(
                "landing".to_owned(),
                OutboundConfig::Nxr(NxrOutboundConfig {
                    address: Ipv4Addr::LOCALHOST.to_string(),
                    port: landing_port,
                    psk: crate::config::SecretString::new(encoded_key),
                    warm_tcp: Some(false),
                }),
            )]),
            &DirectBarrierPolicy::default(),
            Duration::from_secs(1),
            crate::transport::FdBudget::new(4_096),
        );
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let server_task = tokio::spawn(server.run_until(async move {
            let _ = shutdown_receiver.await;
            Ok(())
        }));

        // Bounded, so a real failure surfaces as an error instead of a hang.
        let mut last_error = None;
        let mut connected = None;
        for _ in 0..200 {
            match registry.connect("landing", &destination).await {
                Ok(OutboundConnectOutcome::Connected(connection)) => {
                    connected = Some(connection);
                    break;
                }
                Ok(other) => panic!("the NXR outbound must connect, got {other:?}"),
                Err(error) => {
                    last_error = Some(error);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
        let connected =
            connected.unwrap_or_else(|| panic!("the landing never accepted: {last_error:?}"));
        let (mut accepted, _) = target.accept().await.expect("landing must dial the target");

        let (mut stream, _permit) = connected.into_parts();
        stream
            .write_all(b"ping")
            .await
            .expect("uplink must reach the target");
        let mut received = [0_u8; 4];
        accepted
            .read_exact(&mut received)
            .await
            .expect("the target must observe the uplink");
        assert_eq!(&received, b"ping");

        // Close the session before asking the server to stop: graceful
        // shutdown waits for live relays, and an open one would hold it for
        // the full thirty-second window.
        drop(stream);
        drop(accepted);
        let _ = shutdown_sender.send(());
        let _ = server_task.await;
    }

    #[test]
    fn atomically_publishes_hot_runtime_generation() {
        let config = entry_config(8443);
        let server = ProductionServer::from_config(config.clone()).expect("server must compile");
        let previous = server.runtime.load();
        let replacement = with_extra_rule(8443, "hot").into_node();

        assert_eq!(
            server
                .runtime
                .publish(replacement)
                .expect("compatible snapshot must publish"),
            1
        );
        let current = server.runtime.load();
        assert_eq!(previous.generation, 0);
        assert_eq!(current.generation, 1);
        assert!(!Arc::ptr_eq(&previous, &current));
    }

    /// Resolves the outbound table a snapshot's listener actually compiled.
    ///
    /// Reaching through the handler rather than the config is the point: this is
    /// the table a live connection would consult, so a crossing between
    /// generations would be visible here and nowhere else.
    fn outbounds_of(state: &super::ConnectionRuntime) -> &super::super::outbound::OutboundRegistry {
        match &state.handler {
            super::ConnectionHandler::Public { vision, .. } => vision.outbounds(),
            super::ConnectionHandler::Nxr(_) | super::ConnectionHandler::Handoff(_) => {
                panic!("the generated listener must be a public VLESS listener")
            }
        }
    }

    /// Returns the single listener runtime of a snapshot.
    fn only_listener(snapshot: &super::RuntimeSnapshot) -> Arc<super::ConnectionRuntime> {
        let mut listeners = snapshot.connections.values();
        let state = listeners
            .next()
            .expect("the generated config declares one listener")
            .clone();
        assert!(
            listeners.next().is_none(),
            "this test assumes a single listener"
        );
        state
    }

    /// A hot-reloadable variant of the same node: one extra routing rule,
    /// which changes nothing structural.
    fn with_extra_rule(port: u16, label: &str) -> ValidatedConfig {
        fixture::validated(&fixture::entry_without_routing(&format!(
            r#""listeners": [{{ "port": {port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct",
    "rules": [{{ "name": "{label}", "ip": ["10.0.0.0/8"], "outbound": "block" }}] }}"#
        )))
    }

    #[test]
    fn a_rejected_publication_must_not_advance_the_generation_counter() {
        let config = entry_config(unused_loopback_port());
        let server = ProductionServer::from_config(config.clone()).expect("server must compile");
        let before = server
            .runtime
            .generation
            .load(std::sync::atomic::Ordering::Acquire);

        let incompatible = cold_variant(config.node().listeners()[0].port);
        assert!(matches!(
            server.runtime.publish(incompatible),
            Err(RuntimeUpdateError::NetworkDialPolicyChanged)
        ));

        assert_eq!(
            server
                .runtime
                .generation
                .load(std::sync::atomic::Ordering::Acquire),
            before,
            "a rejected candidate must leave the generation counter untouched, or the \
             next accepted publication silently skips a generation number"
        );
        assert_eq!(
            server.runtime.load().generation,
            before,
            "the live snapshot must still report the last good generation"
        );
    }

    #[test]
    fn generations_increment_by_exactly_one_and_never_repeat() {
        let config = entry_config(unused_loopback_port());
        let server = ProductionServer::from_config(config.clone()).expect("server must compile");
        let mut seen = vec![server.runtime.load().generation];

        for round in 1..=4u64 {
            let accepted =
                with_extra_outbound(config.node().listeners()[0].port, &format!("probe-{round}"));
            let published = server
                .runtime
                .publish(accepted)
                .expect("an added outbound is a hot-compatible change");
            assert_eq!(
                published, round,
                "each accepted publication must advance the generation by exactly one"
            );

            let rejected = cold_variant(config.node().listeners()[0].port);
            assert!(server.runtime.publish(rejected).is_err());

            seen.push(published);
        }

        let mut unique = seen.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            seen.len(),
            "a generation number must never be reused: {seen:?}"
        );
        assert_eq!(seen, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn outbound_tables_are_replaced_wholesale_across_a_publication() {
        let config = entry_config(unused_loopback_port());
        let server = ProductionServer::from_config(config.clone()).expect("server must compile");
        let before = only_listener(&server.runtime.load());
        assert!(outbounds_of(&before).contains("direct"));
        assert!(
            !outbounds_of(&before).contains("crossed"),
            "the first generation cannot know a tag introduced later"
        );

        server
            .runtime
            .publish(with_extra_outbound(
                config.node().listeners()[0].port,
                "crossed",
            ))
            .expect("an added outbound is hot-compatible");

        let after = only_listener(&server.runtime.load());
        assert!(
            outbounds_of(&after).contains("crossed"),
            "the published generation must expose its own outbound table"
        );
        assert!(
            outbounds_of(&after).contains("direct"),
            "the published table must be complete, not a partial overlay"
        );
        assert!(
            !Arc::ptr_eq(&before, &after),
            "a publication must install a freshly compiled listener runtime"
        );
    }

    #[test]
    fn an_in_flight_connection_keeps_its_own_generation_outbound_table() {
        let config = entry_config(unused_loopback_port());
        let server = ProductionServer::from_config(config.clone()).expect("server must compile");

        // A live connection holds exactly this: an Arc taken at accept time.
        let in_flight = only_listener(&server.runtime.load());

        server
            .runtime
            .publish(with_extra_outbound(
                config.node().listeners()[0].port,
                "next-generation",
            ))
            .expect("an added outbound is hot-compatible");

        assert!(
            !outbounds_of(&in_flight).contains("next-generation"),
            "a connection that started before the reload must never observe the new \
             generation's outbound table"
        );
        assert!(
            outbounds_of(&in_flight).contains("direct"),
            "the retired generation must stay usable until its sessions finish"
        );
        assert!(
            outbounds_of(&only_listener(&server.runtime.load())).contains("next-generation"),
            "newly accepted connections must observe the published generation"
        );
    }

    #[test]
    fn retiring_a_generation_deactivates_only_its_own_pre_auth_pool() {
        let config = entry_config(unused_loopback_port());
        let server = ProductionServer::from_config(config.clone()).expect("server must compile");
        let retired = server.runtime.load();

        server
            .runtime
            .publish(with_extra_outbound(
                config.node().listeners()[0].port,
                "pool-probe",
            ))
            .expect("an added outbound is hot-compatible");

        let published = server.runtime.load();
        assert!(
            !Arc::ptr_eq(&retired, &published),
            "the retired and published generations must be distinct objects"
        );
        assert!(
            !retired.pre_auth_generation.is_active(),
            "publish must retire the old generation's pre-auth pool"
        );
        assert!(
            published.pre_auth_generation.is_active(),
            "retiring the old generation must not deactivate the published one, or a \
             reload would strand every subsequent pre-auth connection"
        );
    }

    #[test]
    fn rejected_hot_update_keeps_last_good_runtime() {
        let config = entry_config(8443);
        let server = ProductionServer::from_config(config.clone()).expect("server must compile");
        let previous = server.runtime.load();
        let replacement = entry_config(9443).into_node();

        assert!(matches!(
            server.runtime.publish(replacement),
            Err(RuntimeUpdateError::ListenerTopologyChanged)
        ));
        assert!(Arc::ptr_eq(&previous, &server.runtime.load()));
    }

    #[test]
    fn listener_topology_and_dial_policy_changes_require_restart() {
        let config = entry_config(8443);
        let server = ProductionServer::from_config(config.clone()).expect("server must compile");

        // A family change expands to different sockets, so the topology moves.
        let listener_change = fixture::validated(&fixture::entry_without_routing(
            r#""listeners": [{ "port": 8443 }],
  "routing": { "default": "direct" }"#,
        ))
        .into_node();
        assert!(matches!(
            server.runtime.publish(listener_change),
            Err(RuntimeUpdateError::ListenerTopologyChanged)
        ));

        assert!(matches!(
            server.runtime.publish(cold_variant(8443)),
            Err(RuntimeUpdateError::NetworkDialPolicyChanged)
        ));

        let dns_change = fixture::validated(&fixture::entry_without_routing(
            r#""listeners": [{ "port": 8443, "ip": "ipv4Only", "ipv4": "127.0.0.1" }],
  "routing": { "default": "direct" },
  "dns": { "timeoutMs": 6000 }"#,
        ))
        .into_node();
        assert!(matches!(
            server.runtime.publish(dns_change),
            Err(RuntimeUpdateError::DnsPolicyChanged)
        ));
    }

    const ROTATION_PSK_A: [u8; 32] = [0x5a; 32];
    const ROTATION_PSK_B: [u8; 32] = [0x5b; 32];
    const ROTATION_SECRET_A: [u8; 32] = [0x77; 32];
    const ROTATION_SECRET_B: [u8; 32] = [0x78; 32];

    /// A Handoff landing node with an explicit rotation window.
    ///
    /// This is a landing node on its own: entry and landing are separate
    /// roles, so a rotation test configures the node that holds the keys.
    fn rotation_config(
        port: u16,
        active_psk: [u8; 32],
        active_secret: [u8; 32],
        previous_psks: &[[u8; 32]],
        previous_secrets: &[[u8; 32]],
    ) -> ValidatedConfig {
        let encode = |bytes: &[u8; 32]| BASE64_URL_SAFE_NO_PAD.encode(bytes);
        let list = |keys: &[[u8; 32]]| {
            if keys.is_empty() {
                String::new()
            } else {
                let values: Vec<String> = keys
                    .iter()
                    .map(|key| format!("\"{}\"", encode(key)))
                    .collect();
                format!("[{}]", values.join(","))
            }
        };
        let previous_psk_field = if previous_psks.is_empty() {
            String::new()
        } else {
            format!(r#","previousPsks":{}"#, list(previous_psks))
        };
        let previous_secret_field = if previous_secrets.is_empty() {
            String::new()
        } else {
            format!(r#","previousPrivateKeys":{}"#, list(previous_secrets))
        };
        fixture::validated(&format!(
            r#"{{
  "role": "landing",
  "listeners": [{{ "port": {port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "landing": {{ "protocol": "handoff",
                "psk": "{}",
                "privateKey": "{}",
                "authenticationTimeoutMs": 1000,
                "connectTimeoutMs": 1000{previous_psk_field}{previous_secret_field} }}
}}"#,
            encode(&active_psk),
            encode(&active_secret)
        ))
    }

    /// Rotates only the landing's key material, keeping the listener topology
    /// — and therefore hot reload compatibility — intact.
    fn rotated_config(
        base: &ValidatedConfig,
        active_psk: [u8; 32],
        active_secret: [u8; 32],
        previous_psks: &[[u8; 32]],
        previous_secrets: &[[u8; 32]],
    ) -> crate::config::NodeConfig {
        rotation_config(
            base.node().listeners()[0].port,
            active_psk,
            active_secret,
            previous_psks,
            previous_secrets,
        )
        .into_node()
    }

    fn handoff_handler(
        server: &ProductionServer,
        address: &SocketAddr,
    ) -> crate::server::handoff::HandoffLandingHandler {
        let snapshot = server.runtime.load();
        let super::ConnectionHandler::Handoff(handler) = &snapshot
            .connections
            .get(address)
            .expect("the handoff listener must exist")
            .handler
        else {
            panic!("the listener must be a handoff landing");
        };
        handler.clone()
    }

    /// Seals a fresh transfer (fresh nonce) toward the discard port: when the
    /// landing authenticates it, the dial fails — proving every
    /// authentication step passed without standing up a destination.
    fn rotation_message(psk: [u8; 32], landing_secret: [u8; 32]) -> Vec<u8> {
        use crate::protocol::{
            handoff::{ContinuationState, HandoffPsk, seal_transfer},
            reality::tls13::{CipherSuite, TrafficKeys},
        };
        let landing_public =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(landing_secret));
        let state = ContinuationState::new(
            CipherSuite::ChaCha20Poly1305Sha256,
            TrafficKeys::from_raw_parts(&[0x11; 32], [0x21; 12]).expect("client keys"),
            1,
            TrafficKeys::from_raw_parts(&[0x12; 32], [0x22; 12]).expect("server keys"),
            0,
            [0x33; 16],
            Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 9),
            Vec::new(),
            Vec::new(),
        )
        .expect("test state must be valid");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock must be valid")
            .as_secs();
        let mut message = Vec::new();
        seal_transfer(
            &state,
            &HandoffPsk::new(psk),
            &landing_public,
            [0x44; 32],
            now,
            &mut message,
        )
        .expect("test state must seal");
        message
    }

    async fn deliver(
        handler: &crate::server::handoff::HandoffLandingHandler,
        message: &[u8],
    ) -> crate::server::handoff::HandoffLandingError {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("peer listener must bind");
        let address = listener.local_addr().expect("peer address must exist");
        let mut peer = tokio::net::TcpStream::connect(address)
            .await
            .expect("peer must connect");
        let (stream, _) = listener.accept().await.expect("listener must accept");
        peer.write_all(message).await.expect("message must write");
        let result = handler.handle(stream).await;
        drop(peer);
        result.expect_err("a transfer toward the discard port never relays")
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handoff_reload_rotates_keys_without_dropping_in_window_transfers() {
        use crate::protocol::handoff::HandoffError;
        use crate::server::handoff::HandoffLandingError;

        let port = unused_loopback_port();
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let base = rotation_config(port, ROTATION_PSK_A, ROTATION_SECRET_A, &[], &[]);
        let server =
            ProductionServer::from_config(base.clone()).expect("generation 0 must compile");

        // Generation 0: only the original pair is accepted.
        let handler = handoff_handler(&server, &address);
        assert!(
            matches!(
                deliver(
                    &handler,
                    &rotation_message(ROTATION_PSK_A, ROTATION_SECRET_A)
                )
                .await,
                HandoffLandingError::Destination(_)
            ),
            "the active pair must authenticate before rotation"
        );
        assert!(
            matches!(
                deliver(
                    &handler,
                    &rotation_message(ROTATION_PSK_B, ROTATION_SECRET_B)
                )
                .await,
                HandoffLandingError::Protocol(HandoffError::Authentication)
            ),
            "the next pair must fail before the window opens"
        );

        // Reload: the new pair becomes active, the retired pair stays
        // accepted inside the bounded window. The listener address and the
        // replay cache carry over untouched.
        server
            .runtime
            .publish(rotated_config(
                &base,
                ROTATION_PSK_B,
                ROTATION_SECRET_B,
                &[ROTATION_PSK_A],
                &[ROTATION_SECRET_A],
            ))
            .expect("a key rotation must be hot-compatible");
        let handler = handoff_handler(&server, &address);
        assert!(
            matches!(
                deliver(
                    &handler,
                    &rotation_message(ROTATION_PSK_B, ROTATION_SECRET_B)
                )
                .await,
                HandoffLandingError::Destination(_)
            ),
            "senders already on the new pair must land"
        );
        let old_pair_message = rotation_message(ROTATION_PSK_A, ROTATION_SECRET_A);
        assert!(
            matches!(
                deliver(&handler, &old_pair_message).await,
                HandoffLandingError::Destination(_)
            ),
            "senders still on the retired pair must land during the window"
        );
        assert!(
            matches!(
                deliver(&handler, &old_pair_message).await,
                HandoffLandingError::Protocol(HandoffError::Replay)
            ),
            "the retained replay cache must reject a redelivery across the reload"
        );

        // Reload again: the retired keys are dropped and the window closes.
        server
            .runtime
            .publish(rotated_config(
                &base,
                ROTATION_PSK_B,
                ROTATION_SECRET_B,
                &[],
                &[],
            ))
            .expect("dropping retired keys must be hot-compatible");
        let handler = handoff_handler(&server, &address);
        assert!(
            matches!(
                deliver(
                    &handler,
                    &rotation_message(ROTATION_PSK_A, ROTATION_SECRET_A)
                )
                .await,
                HandoffLandingError::Protocol(HandoffError::Authentication)
            ),
            "the retired pair must fail closed once dropped"
        );
        assert!(
            matches!(
                deliver(
                    &handler,
                    &rotation_message(ROTATION_PSK_B, ROTATION_SECRET_B)
                )
                .await,
                HandoffLandingError::Destination(_)
            ),
            "the active pair must keep landing after the window closes"
        );
    }

    #[test]
    fn a_pinned_limit_change_requires_restart() {
        // Admission ceilings, the direct-dial barrier, and the warm pools are
        // sized once, before the first listener binds. Everything they derive
        // from is therefore cold — and since one channel now carries every
        // pin, one comparison covers all of them.
        let pinned = |port: u16, connections: u32| {
            fixture::validated(&fixture::entry_without_routing(&format!(
                r#""listeners": [{{ "port": {port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct" }},
  "runtime": {{ "limits": {{ "maxConnections": {connections} }} }}"#
            )))
        };
        let server =
            ProductionServer::from_config(pinned(8443, 4_096)).expect("server must compile");
        let previous = server.runtime.load();

        assert!(matches!(
            server.runtime.publish(pinned(8443, 8_192).into_node()),
            Err(RuntimeUpdateError::ResourceModeChanged)
        ));
        assert!(Arc::ptr_eq(&previous, &server.runtime.load()));
    }

    #[test]
    fn profile_change_requires_restart() {
        let posture = |port: u16, profile: &str| {
            fixture::validated(&fixture::entry_without_routing(&format!(
                r#""listeners": [{{ "port": {port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct" }},
  "runtime": {{ "profile": "{profile}" }}"#
            )))
        };
        let server =
            ProductionServer::from_config(posture(8443, "shared")).expect("server must compile");
        let previous = server.runtime.load();

        assert!(matches!(
            server
                .runtime
                .publish(posture(8443, "dedicated").into_node()),
            Err(RuntimeUpdateError::ResourceModeChanged)
        ));
        assert!(Arc::ptr_eq(&previous, &server.runtime.load()));
    }

    #[test]
    fn tuning_mode_drift_requires_restart() {
        let tuned = |port: u16, tuning: Option<&str>| {
            let section = tuning.map_or(String::new(), |mode| {
                format!(r#","runtime": {{ "tuning": "{mode}", "statusFile": "/run/rr.json" }}"#)
            });
            fixture::validated(&fixture::entry_without_routing(&format!(
                r#""listeners": [{{ "port": {port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct" }}{section}"#
            )))
        };
        let server = ProductionServer::from_config(tuned(8443, Some("adaptive")))
            .expect("server must compile");
        let previous = server.runtime.load();

        // An omitted tuning mode resolves to `startup`, which builds no
        // controller: the two produce different runtimes, so a reload rejects.
        assert!(matches!(
            server.runtime.publish(tuned(8443, None).into_node()),
            Err(RuntimeUpdateError::ResourceModeChanged)
        ));
        assert!(Arc::ptr_eq(&previous, &server.runtime.load()));
    }

    #[test]
    fn the_adaptive_controller_is_built_only_in_adaptive_mode() {
        for (mode, expect_controller) in [("startup", false), ("adaptive", true)] {
            // A status file is meaningful only under `adaptive`, and
            // validation says so, so the fixture states one only there.
            let status = if mode == "adaptive" {
                r#", "statusFile": "/run/rust-reality/status.json""#
            } else {
                ""
            };
            let config = fixture::validated(&fixture::entry_without_routing(&format!(
                r#""listeners": [{{ "port": 8443, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct" }},
  "runtime": {{ "tuning": "{mode}"{status} }}"#
            )));
            let server = ProductionServer::from_config(config).expect("server must compile");
            let snapshot = server.runtime.load();
            let controller = super::adaptive_controller(
                &snapshot.node,
                &server.runtime.policy,
                &server.runtime.authorities,
                &server.runtime.pressure,
            );
            assert_eq!(
                controller.is_some(),
                expect_controller,
                "mode {mode} must select the controller only when adaptive"
            );
        }
    }

    #[test]
    fn status_file_drift_requires_restart() {
        let with_status = |path: &str| {
            fixture::validated(&fixture::entry_without_routing(&format!(
                r#""listeners": [{{ "port": 8443, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct" }},
  "runtime": {{ "tuning": "adaptive", "statusFile": "{path}" }}"#
            )))
        };
        let server = ProductionServer::from_config(with_status("/tmp/rust-reality-a.json"))
            .expect("server must compile");
        let previous = server.runtime.load();
        let replacement = with_status("/tmp/rust-reality-b.json").into_node();

        assert!(matches!(
            server.runtime.publish(replacement),
            Err(RuntimeUpdateError::ResourceModeChanged)
        ));
        assert!(Arc::ptr_eq(&previous, &server.runtime.load()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn adaptive_mode_publishes_a_status_file_and_shuts_down_cleanly() {
        let port = unused_loopback_port();
        let directory = std::env::temp_dir().join(format!(
            "rust-reality-adaptive-server-{}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("test clock must be valid")
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).expect("temporary directory must be created");
        let status_path = directory.join("status.json");
        let config = fixture::validated(&fixture::entry_without_routing(&format!(
            r#""listeners": [{{ "port": {port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct" }},
  "runtime": {{ "tuning": "adaptive", "statusFile": "{}" }}"#,
            status_path.display()
        )));
        let server = ProductionServer::from_config(config).expect("server must compile");
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let server_task = tokio::spawn(server.run_until(async move {
            shutdown_receiver
                .await
                .map_err(|_| io::Error::other("test shutdown sender dropped"))
        }));

        time::timeout(Duration::from_secs(5), async {
            while !status_path.exists() {
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the controller must publish its initial status snapshot");
        let status =
            crate::runtime::adaptive::read_status(&status_path).expect("the snapshot must parse");
        assert_eq!(status.schema_version, 1);
        assert_eq!(status.pressure, "normal");
        assert_eq!(status.knobs.len(), 8);
        assert!(
            status
                .knobs
                .iter()
                .all(|knob| knob.value == knob.ceiling && knob.last_change.is_none()),
            "before any tick every knob sits at its startup-derived ceiling"
        );

        shutdown_sender.send(()).expect("shutdown must send");
        time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("the controller task must not hang shutdown")
            .expect("server task must not panic")
            .expect("server must stop cleanly");
        std::fs::remove_dir_all(&directory).expect("temporary directory must be removed");
    }

    #[test]
    fn startup_tuning_derives_the_policy_from_the_machine() {
        let config = entry_config(8443);
        assert_eq!(
            config.node().runtime().tuning(),
            crate::config::node::runtime::TuningMode::Startup,
            "an omitted tuning mode derives at startup"
        );
        let server = ProductionServer::from_loaded(
            config,
            None,
            crate::runtime::machine::MachineReport::conservative(),
        )
        .expect("server must compile");
        let effective = &server.runtime.policy;
        // The golden conservative-machine derivation from runtime::plan.
        assert_eq!(effective.governor.max_connections, 197);
        assert_eq!(effective.governor.max_handshakes, 128);
        assert_eq!(effective.relay.buffer_bytes, 32 * 1024);
        assert_eq!(effective.relay.max_splice_relays, 64);
        assert_eq!(
            effective.governor.handshake_timeout_ms,
            crate::runtime::policy::ResourceGovernorPolicy::default().handshake_timeout_ms,
            "timeouts are carried from the configuration, never derived"
        );
        assert_ne!(
            effective.governor.max_connections,
            crate::runtime::policy::ResourceGovernorPolicy::default().max_connections,
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
        let server = ProductionServer::from_loaded(
            config,
            None,
            crate::runtime::machine::MachineReport::conservative(),
        )
        .expect("server must compile");
        let effective = &server.runtime.policy;
        assert_eq!(effective.governor.max_connections, 1_000);
        assert_eq!(
            effective.governor.max_handshakes, 128,
            "unpinned fields still derive"
        );
    }

    #[test]
    fn an_unchanged_startup_tuned_config_reloads_cleanly() {
        let config = entry_config(8443);
        let server = ProductionServer::from_config(config.clone()).expect("server must compile");
        assert!(server.runtime.policy.governor.max_connections > 0);
        server
            .runtime
            .publish(entry_config(8443).into_node())
            .expect("the same startup-tuned configuration must reload");
    }

    #[test]
    fn startup_resource_mode_resolution_follows_the_profile() {
        use crate::runtime::machine::MachineReport;

        // Derivation always runs now, so the measured view is always needed
        // and every profile plans against the real machine.
        let (mode, _) = super::resolve_startup_resource_mode(RuntimeProfile::Shared);
        assert_eq!(mode, ResourceMode::Standard);

        let (mode, _) = super::resolve_startup_resource_mode(RuntimeProfile::Dedicated);
        assert_eq!(mode, ResourceMode::Dedicated);

        // Auto agrees with the detected tenancy boundary, whatever the test
        // machine looks like.
        let (mode, machine) = super::resolve_startup_resource_mode(RuntimeProfile::Auto);
        let expected = if machine.tenancy_boundary_observable() {
            ResourceMode::Dedicated
        } else {
            ResourceMode::Standard
        };
        assert_eq!(mode, expected);

        #[cfg(target_os = "linux")]
        {
            let (_, machine) = super::resolve_startup_resource_mode(RuntimeProfile::Shared);
            assert_ne!(
                machine,
                MachineReport::conservative(),
                "derivation never plans against the conservative fallback on a readable host"
            );
        }
    }

    /// The same node with one declared outbound added: a hot change.
    fn with_extra_outbound(port: u16, name: &str) -> crate::config::NodeConfig {
        fixture::validated(&fixture::entry_without_routing(&format!(
            r#""listeners": [{{ "port": {port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "outbounds": {{ "{name}": {{ "type": "socks5", "address": "10.0.0.9", "port": 1080,
                              "warmTcp": false }} }},
  "routing": {{ "default": "direct" }}"#
        )))
        .into_node()
    }

    /// The same node with a different dial policy: a cold change a reload
    /// must refuse, because the process-wide dial policy is fixed at startup.
    fn cold_variant(port: u16) -> crate::config::NodeConfig {
        fixture::validated(&fixture::entry_without_routing(&format!(
            r#""listeners": [{{ "port": {port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct" }},
  "network": {{ "ip": "preferIpv6" }}"#
        )))
        .into_node()
    }

    /// A valid entry node bound to one loopback port.
    ///
    /// This replaces the whole-config generator the binary no longer has: a
    /// test that needs a server needs a *configuration*, and composing one is
    /// exactly what an operator does.
    fn entry_config(port: u16) -> ValidatedConfig {
        fixture::validated(&fixture::entry_without_routing(&format!(
            r#""listeners": [{{ "port": {port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct" }}"#
        )))
    }

    fn unused_loopback_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .map(|address| address.port())
            .unwrap_or_else(|error: io::Error| panic!("reserve loopback port: {error}"))
    }

    /// A node whose admission ceilings are pinned as low as validation allows,
    /// so a test can exhaust them in a few connections.
    ///
    /// Only the two ceilings an operator can pin are stated; the rest derive,
    /// which is the point of the reload test that uses this.
    fn tiny_ceiling_config() -> ValidatedConfig {
        fixture::validated(&fixture::entry_without_routing(&format!(
            r#""listeners": [{{ "port": {}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct" }},
  "runtime": {{ "limits": {{ "maxConnections": 2, "maxHandshakes": 2 }} }}"#,
            unused_loopback_port()
        )))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reload_cannot_multiply_the_connection_ceiling() {
        let server = ProductionServer::from_config(tiny_ceiling_config()).expect("must compile");
        let governor = server.runtime.authorities.governor.clone();
        let permit_a = governor
            .try_acquire(crate::runtime::AdmissionKind::Connection)
            .expect("first connection must be admitted");
        let permit_b = governor
            .try_acquire(crate::runtime::AdmissionKind::Connection)
            .expect("second connection must be admitted");
        assert!(
            governor
                .try_acquire(crate::runtime::AdmissionKind::Connection)
                .is_err(),
            "the ceiling must hold before any reload"
        );

        for generation in 1..=10 {
            server
                .runtime
                .refresh()
                .unwrap_or_else(|error| panic!("reload {generation} must succeed: {error}"));
        }

        assert!(
            server
                .runtime
                .authorities
                .governor
                .try_acquire(crate::runtime::AdmissionKind::Connection)
                .is_err(),
            "ten reloads must not multiply the connection ceiling"
        );
        drop(permit_a);
        assert!(
            server
                .runtime
                .authorities
                .governor
                .try_acquire(crate::runtime::AdmissionKind::Connection)
                .is_ok(),
            "releasing an old-generation permit must free capacity after reloads"
        );
        drop(permit_b);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reload_cannot_reset_the_direct_dial_rate_gate() {
        let server = ProductionServer::from_config(tiny_ceiling_config()).expect("must compile");
        // The barrier is derived, so its width is whatever the machine
        // supports; exhaust exactly that many permits rather than assuming one.
        let width = server.runtime.policy.direct_barrier.max_concurrent;
        let mut held: Vec<_> = (0..width.saturating_sub(1))
            .map(|_| {
                server
                    .runtime
                    .authorities
                    .direct_barrier
                    .try_acquire()
                    .expect("every derived direct permit must be acquirable")
            })
            .collect();
        let permit = server
            .runtime
            .authorities
            .direct_barrier
            .try_acquire()
            .expect("the last direct concurrency permit must be acquirable");
        assert!(
            server
                .runtime
                .authorities
                .direct_barrier
                .try_acquire()
                .is_err()
        );

        for _ in 0..10 {
            server.runtime.refresh().expect("reload must succeed");
        }

        assert!(
            server
                .runtime
                .authorities
                .direct_barrier
                .try_acquire()
                .is_err(),
            "ten reloads must not reset direct concurrency"
        );
        drop(permit);
        assert!(
            server
                .runtime
                .authorities
                .direct_barrier
                .try_acquire()
                .is_ok(),
            "releasing the permit must free the rate gate after reloads"
        );
        held.clear();
    }

    #[test]
    fn disabled_debug_skips_event_construction() {
        use std::sync::atomic::{AtomicU64, Ordering};

        use crate::logging::{LogEvent, Logger};

        let constructed = AtomicU64::new(0);
        let attempt = |logger: &Logger| {
            super::emit_debug(logger, || {
                constructed.fetch_add(1, Ordering::Relaxed);
                LogEvent::ConnectionAccepted {
                    peer: SocketAddr::from((Ipv4Addr::LOCALHOST, 40_001)),
                }
            });
        };

        let info_logger = Logger::new(&LogConfig {
            level: Some(LogLevel::Info),
            output: Some(LogOutput::Stderr),
            file: None,
        })
        .expect("stderr logger must initialize");
        attempt(&info_logger);
        assert_eq!(
            constructed.load(Ordering::Relaxed),
            0,
            "a disabled level must not even construct the event"
        );

        let none_logger = Logger::new(&LogConfig {
            level: Some(LogLevel::Debug),
            output: Some(LogOutput::None),
            file: None,
        })
        .expect("none logger must initialize");
        attempt(&none_logger);
        assert_eq!(
            constructed.load(Ordering::Relaxed),
            0,
            "a none sink must report debug as disabled and skip construction"
        );

        let debug_logger = Logger::new(&LogConfig {
            level: Some(LogLevel::Debug),
            output: Some(LogOutput::Stderr),
            file: None,
        })
        .expect("stderr logger must initialize");
        attempt(&debug_logger);
        assert_eq!(
            constructed.load(Ordering::Relaxed),
            1,
            "an enabled debug level must construct exactly one event"
        );
    }

    #[test]
    fn a_denied_direct_dial_is_reported_as_a_resource_limit() {
        use std::{fs, net::SocketAddr, sync::atomic::AtomicU64};

        use crate::{
            logging::{Logger, RejectionReason},
            runtime::AdmissionDenied,
            server::{
                outbound::OutboundConnectError, production::ConnectionRunError,
                vision::VisionSessionError,
            },
        };

        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "rust-reality-barrier-log-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&directory).expect("unique log directory must be created");
        let path = directory.join("events.log");
        let logger = Logger::new(&LogConfig {
            level: Some(LogLevel::Debug),
            output: Some(LogOutput::File),
            file: Some(crate::config::node::log::FileLogConfig {
                path: path.clone(),
                max_bytes: Some(64 * 1024),
                max_files: Some(1),
                max_total_bytes: Some(64 * 1024),
            }),
        })
        .expect("file logger must initialize");

        let error = ConnectionRunError::Vision(VisionSessionError::Outbound(
            OutboundConnectError::Admission(AdmissionDenied::DirectConcurrency),
        ));
        assert_eq!(
            error.rejection_reason(),
            RejectionReason::ResourceLimit,
            "a barrier denial must not look like an ordinary outbound failure"
        );
        assert_eq!(
            error.admission_denial(),
            Some(AdmissionDenied::DirectConcurrency),
            "the denial category must flow to the admission event"
        );

        super::emit_connection_failure(
            &logger,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 40_000)),
            &error,
        );
        let contents = fs::read_to_string(&path).expect("the log file must be readable");
        assert!(
            contents.contains("\"event\":\"admission_limited\""),
            "expected an admission_limited event, got {contents}"
        );
        assert!(
            contents.contains("\"resource\":\"direct_connections\""),
            "expected the direct_connections resource, got {contents}"
        );
        assert!(
            contents.contains("\"event\":\"connection_rejected\""),
            "expected a connection_rejected event, got {contents}"
        );
        assert!(
            contents.contains("\"reason\":\"resource_limit\""),
            "expected the resource_limit reason, got {contents}"
        );
        fs::remove_dir_all(&directory).expect("log directory must be removed");
    }

    #[test]
    fn a_mid_transfer_liveness_abort_is_reported_as_a_timeout() {
        use crate::{
            logging::RejectionReason,
            server::{production::ConnectionRunError, vision::VisionSessionError},
        };

        // A healthy transfer whose peer direction stalls past the liveness
        // deadline aborts both sockets with RST and surfaces as
        // ConnectionAborted carrying the original TimedOut (the exact shape
        // classify_abort produces). That is a liveness-policy kill: the
        // rejection log must say timeout, not protocol.
        let abort = io::Error::new(
            io::ErrorKind::ConnectionAborted,
            io::Error::new(io::ErrorKind::TimedOut, "raw relay idle timeout"),
        );
        let error = ConnectionRunError::Vision(VisionSessionError::Relay(abort));
        assert_eq!(
            error.rejection_reason(),
            RejectionReason::Timeout,
            "a liveness timeout that truncated a live transfer is still a timeout"
        );

        let error = ConnectionRunError::Vision(VisionSessionError::Relay(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "peer abort",
        )));
        assert_eq!(
            error.rejection_reason(),
            RejectionReason::Protocol,
            "a plain relay abort without a timeout payload stays a protocol rejection"
        );
    }
}
