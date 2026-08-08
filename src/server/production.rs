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
use tokio::{
    sync::{mpsc, watch},
    task::{JoinError, JoinSet},
    time::{self, Instant, Sleep},
};

use crate::{
    assets::{AssetLoadError, AssetSnapshot},
    config::{
        Config, ConfigError, ConfigLoadError, InboundConfig, ResourceMode, load_config,
        validate_config,
    },
    logging::{AdmissionResource, BackendStatus, LogEvent, LogWriteError, Logger, RejectionReason},
    protocol::{handoff::HandoffReplayCache, reality::ReplayCache},
    runtime::{
        AdmissionDenied, AdmissionKind, AdmissionPermit, DirectBarrier, FdBudget, FdBudgetError,
        FdBudgetPlan, FdHeadroomPolicy, FdPermit, FixedFdReserve, PressureGauge, ResourceGovernor,
        ResourcePressure, UNITS_INBOUND_SOCKET,
        connection::ConnectionTasks,
        machine::{self, MachineReport, MemoryPlan, MemorySampler},
    },
    transport::{
        BackendDeclineReason, BackendReport, RelayBackend,
        tcp::{AcceptBackoff, AcceptErrorClass, EmergencyDescriptor, TcpAcceptor},
        tcp_relay::{TcpRelay, TcpRelayConfigError, is_liveness_timeout_abort},
    },
};

use super::{
    handoff::{HandoffLandingConfigError, HandoffLandingError, HandoffLandingHandler},
    nxr::{NxrLandingConfigError, NxrLandingError, NxrLandingHandler, NxrReplayCache},
    reality::{
        RealityAcceptError, RealityAcceptOutcome, RealityAcceptor, RealityAcceptorConfigError,
    },
    routing::RoutingCompileError,
    vision::{VisionHandler, VisionSessionError},
};

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
    addresses: Vec<SocketAddr>,
    runtime: Arc<RuntimeStore>,
    config_path: Option<PathBuf>,
}

/// Computes the configured worst-case simultaneous descriptor demand.
///
/// Every term is a configured bound, and the sum is deliberately pessimistic:
/// it assumes every connection simultaneously holds an inbound socket, an
/// outbound socket, that every splice relay is armed at once, and that the
/// pipe pool retains its full keep count of drained pipes afterwards. The
/// number is used only to decide whether to warn about clamping; it never
/// raises the admission budget.
fn theoretical_fd_peak(config: &Config) -> u64 {
    let connections = u64::from(config.policy.resource_governor.max_connections);
    let splice = u64::from(config.policy.relay.max_splice_relays)
        .saturating_mul(u64::from(crate::runtime::UNITS_SPLICE_RELAY));
    // A pooled pipe holds its two descriptors past the relay that created it,
    // so the pool's retention is steady-state demand the peak must include.
    let pool_retention = if config.policy.relay.splice && config.policy.relay.pipe_pool {
        u64::from(config.policy.relay.max_pooled_pipes)
            .saturating_mul(u64::from(crate::runtime::UNITS_SPLICE_DIRECTION))
    } else {
        0
    };
    connections
        .saturating_mul(2)
        .saturating_add(splice)
        .saturating_add(pool_retention)
}

/// Everything the startup resource derivation decided, before any listener
/// is bound.
struct ResourceStartup {
    plan: FdBudgetPlan,
    budget: FdBudget,
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
/// continues with the effective soft limit.
fn derive_fd_budget(config: &Config) -> Result<ResourceStartup, FdBudgetError> {
    let listeners = u64::try_from(config.inbounds.len()).unwrap_or(u64::MAX);
    let reserve = FixedFdReserve::new(listeners);
    let dedicated = config.runtime.resource_mode == ResourceMode::Dedicated;
    let mut machine = if dedicated {
        MachineReport::detect()
    } else {
        MachineReport::conservative()
    };
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
        theoretical_fd_peak(config),
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
        fd_effective_soft_limit: effective_soft,
        fd_soft_raise_attempted: raise_attempted,
        fd_soft_limit_raised: raised,
        machine,
        memory,
    })
}

/// Reads the process descriptor limit, falling back to a conservative default.
///
/// A platform that cannot report a limit is treated as if it had the
/// conservative POSIX minimum rather than as if it had no limit, because
/// assuming abundance is exactly how the incident happened.
fn read_descriptor_limit() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        match rr_linux::descriptor_limit() {
            Ok(limit) => (limit.soft, limit.hard),
            Err(_) => (1_024, 1_024),
        }
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
    pub fn from_config(config: &Config) -> Result<Self, ProductionServerError> {
        validate_config(config).map_err(RuntimeUpdateError::Invalid)?;
        Self::compile(config.clone(), None)
    }

    /// Loads and compiles a production configuration while retaining its path for
    /// SIGHUP reload.
    ///
    /// # Errors
    ///
    /// Returns a load, validation, logger, asset, routing, REALITY, or listener error.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ProductionServerError> {
        let path = path.as_ref().to_path_buf();
        let config = load_config(&path).map_err(RuntimeUpdateError::Load)?;
        Self::compile(config, Some(path))
    }

    fn compile(
        config: Config,
        config_path: Option<PathBuf>,
    ) -> Result<Self, ProductionServerError> {
        let pressure = PressureGauge::new();
        // Process-lifetime authorities: reload generations swap routing and
        // protocol snapshots only — admission ceilings and the direct-dial
        // barrier must never multiply while old sessions hold old permits.
        let authorities = ProcessAuthorities {
            governor: ResourceGovernor::with_pressure(
                &config.policy.resource_governor,
                pressure.clone(),
            ),
            direct_barrier: DirectBarrier::with_pressure(
                &config.policy.direct_barrier,
                pressure.clone(),
            ),
        };
        let replay = ReplayCache::new(
            authorities.governor.clone(),
            &config.policy.resource_governor,
        );
        let listener_replays = ListenerReplays {
            nxr: compile_nxr_replays(&config)?,
            handoff: compile_handoff_replays(&config)?,
        };
        let startup = derive_fd_budget(&config).map_err(ProductionServerError::DescriptorBudget)?;
        let tcp_relay = TcpRelay::new(&config.policy.relay, startup.budget.clone())
            .map_err(RuntimeUpdateError::Relay)?;
        let initial = RuntimeSnapshot::compile(
            config,
            0,
            replay.clone(),
            &listener_replays,
            tcp_relay.clone(),
            &pressure,
            &authorities,
        )?;
        let mut addresses: Vec<_> = initial.connections.keys().copied().collect();
        addresses.sort_unstable();
        emit(&initial.logger, &LogEvent::ServerStarting);
        if initial.config.runtime.resource_mode == ResourceMode::Dedicated {
            emit(
                &initial.logger,
                &LogEvent::MachineReport {
                    resource_mode: initial.config.runtime.resource_mode.as_str(),
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
            addresses,
            runtime: Arc::new(RuntimeStore {
                current: ArcSwap::from(Arc::new(initial)),
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
    /// process signals or scheduled network refreshes.
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
        let mut bound = Vec::with_capacity(self.addresses.len());
        for address in &self.addresses {
            let acceptor = TcpAcceptor::bind(*address).await.map_err(|source| {
                ProductionServerError::Bind {
                    address: *address,
                    source,
                }
            })?;
            bound.push((acceptor, *address));
        }

        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let mut listener_tasks = JoinSet::new();
        let initial = self.runtime.load();
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
        drop(initial);

        let monitor_task = self.runtime.memory.clone().map(|watch| {
            tokio::spawn(run_resource_monitor(
                Arc::clone(&self.runtime),
                watch,
                shutdown_receiver.clone(),
            ))
        });

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
                            emit_rejected(&self.runtime, "configuration");
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
                        Some(Ok((_, Ok(_)))) => {}
                        Some(Ok((field, Err(_)))) => emit_rejected(&self.runtime, field),
                        Some(Err(_)) | None => emit_rejected(&self.runtime, "configuration"),
                    }
                    reset_refresh(&mut refresh, self.runtime.reload_interval());
                }
            }
        };

        update_tasks.abort_all();
        if let Some(task) = monitor_task {
            task.abort();
        }
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
/// buckets must never multiply while old sessions hold old permits.
struct ProcessAuthorities {
    governor: ResourceGovernor,
    direct_barrier: DirectBarrier,
}

impl RuntimeStore {
    fn load(&self) -> Arc<RuntimeSnapshot> {
        self.current.load_full()
    }

    fn reload_interval(&self) -> Duration {
        Duration::from_secs(self.load().config.assets.reload_interval_seconds)
    }

    fn reload_path(&self, path: &Path) -> Result<u64, RuntimeUpdateError> {
        let config = load_config(path)?;
        self.publish(config)
    }

    fn refresh(&self) -> Result<u64, RuntimeUpdateError> {
        let config = self.load().config.clone();
        self.publish(config)
    }

    fn publish(&self, config: Config) -> Result<u64, RuntimeUpdateError> {
        validate_config(&config)?;
        let _guard = self
            .update
            .lock()
            .map_err(|_| RuntimeUpdateError::Unavailable)?;
        let current = self.load();
        ensure_hot_compatible(&current, &config)?;
        let generation = self
            .generation
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or(RuntimeUpdateError::GenerationExhausted)?;
        let candidate = RuntimeSnapshot::compile(
            config,
            generation,
            self.replay.clone(),
            &self.listener_replays,
            self.tcp_relay.clone(),
            &self.pressure,
            &self.authorities,
        )?;
        self.current.store(Arc::new(candidate));
        self.generation.store(generation, Ordering::Release);
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
    config: Config,
    connections: HashMap<SocketAddr, Arc<ConnectionRuntime>>,
    logger: Logger,
}

impl RuntimeSnapshot {
    fn compile(
        config: Config,
        generation: u64,
        replay: ReplayCache,
        listener_replays: &ListenerReplays,
        tcp_relay: TcpRelay,
        pressure: &PressureGauge,
        authorities: &ProcessAuthorities,
    ) -> Result<Self, RuntimeUpdateError> {
        let logger = Logger::new(&config.log)?;
        let assets = Arc::new(AssetSnapshot::load_generation(&config, generation)?);
        let vision = VisionHandler::from_config_with_pressure(
            &config,
            assets,
            tcp_relay.clone(),
            pressure,
            authorities.direct_barrier.clone(),
            authorities.governor.clone(),
        )?;
        let mut connections = HashMap::new();
        connections
            .try_reserve(config.inbounds.len())
            .map_err(|_| RuntimeUpdateError::Unavailable)?;
        for inbound in &config.inbounds {
            let address = SocketAddr::new(inbound.listen(), inbound.port());
            let handler = match inbound {
                InboundConfig::Vless(inbound) => ConnectionHandler::Public {
                    reality: Box::new(RealityAcceptor::from_inbound_with_replay(
                        inbound,
                        authorities.governor.clone(),
                        &config.policy.resource_governor,
                        replay.clone(),
                        tcp_relay.clone(),
                    )?),
                    vision: vision.clone(),
                },
                InboundConfig::Nxr(inbound) => {
                    let replay = listener_replays
                        .nxr
                        .get(&address)
                        .cloned()
                        .ok_or(RuntimeUpdateError::MissingNxrReplay(address))?;
                    ConnectionHandler::Nxr(NxrLandingHandler::from_inbound_with_replay(
                        inbound,
                        replay,
                        tcp_relay.clone(),
                        Duration::from_millis(config.policy.resource_governor.fallback_timeout_ms),
                    )?)
                }
                InboundConfig::Handoff(inbound) => {
                    let replay = listener_replays
                        .handoff
                        .get(&address)
                        .cloned()
                        .ok_or(RuntimeUpdateError::MissingHandoffReplay(address))?;
                    ConnectionHandler::Handoff(HandoffLandingHandler::from_inbound_with_replay(
                        inbound,
                        replay,
                        tcp_relay.clone(),
                        Duration::from_millis(config.policy.resource_governor.fallback_timeout_ms),
                        vision.outbounds(),
                    )?)
                }
            };
            if connections
                .insert(
                    address,
                    Arc::new(ConnectionRuntime {
                        tag: Arc::from(inbound.tag()),
                        governor: authorities.governor.clone(),
                        handler,
                    }),
                )
                .is_some()
            {
                return Err(RuntimeUpdateError::DuplicateListener(address));
            }
        }
        Ok(Self {
            generation,
            config,
            connections,
            logger,
        })
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

fn ensure_hot_compatible(
    current: &RuntimeSnapshot,
    candidate: &Config,
) -> Result<(), RuntimeUpdateError> {
    if listener_topology(candidate) != listener_topology(&current.config) {
        return Err(RuntimeUpdateError::ListenerTopologyChanged);
    }
    if candidate.runtime != current.config.runtime {
        return Err(RuntimeUpdateError::ResourceModeChanged);
    }
    if candidate.policy.resource_governor != current.config.policy.resource_governor {
        return Err(RuntimeUpdateError::ReplayPolicyChanged);
    }
    if candidate.policy.direct_barrier != current.config.policy.direct_barrier {
        return Err(RuntimeUpdateError::DirectBarrierPolicyChanged);
    }
    if nxr_replay_policy(candidate) != nxr_replay_policy(&current.config) {
        return Err(RuntimeUpdateError::NxrReplayPolicyChanged);
    }
    if handoff_replay_policy(candidate) != handoff_replay_policy(&current.config) {
        return Err(RuntimeUpdateError::HandoffReplayPolicyChanged);
    }
    if candidate.policy.relay != current.config.policy.relay {
        return Err(RuntimeUpdateError::RelayPolicyChanged);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ListenerProtocol {
    Vless,
    Nxr,
    Handoff,
}

fn listener_topology(config: &Config) -> HashMap<SocketAddr, ListenerProtocol> {
    config
        .inbounds
        .iter()
        .map(|inbound| {
            let protocol = match inbound {
                InboundConfig::Vless(_) => ListenerProtocol::Vless,
                InboundConfig::Nxr(_) => ListenerProtocol::Nxr,
                InboundConfig::Handoff(_) => ListenerProtocol::Handoff,
            };
            (SocketAddr::new(inbound.listen(), inbound.port()), protocol)
        })
        .collect()
}

fn nxr_replay_policy(config: &Config) -> HashMap<SocketAddr, (u32, u64)> {
    config
        .inbounds
        .iter()
        .filter_map(|inbound| match inbound {
            InboundConfig::Vless(_) | InboundConfig::Handoff(_) => None,
            InboundConfig::Nxr(inbound) => Some((
                SocketAddr::new(inbound.listen, inbound.port),
                (
                    inbound.settings.max_nonce_entries,
                    inbound.settings.nonce_retention_seconds,
                ),
            )),
        })
        .collect()
}

fn handoff_replay_policy(config: &Config) -> HashMap<SocketAddr, (u32, u64)> {
    config
        .inbounds
        .iter()
        .filter_map(|inbound| match inbound {
            InboundConfig::Vless(_) | InboundConfig::Nxr(_) => None,
            InboundConfig::Handoff(inbound) => Some((
                SocketAddr::new(inbound.listen, inbound.port),
                (
                    inbound.settings.max_nonce_entries,
                    inbound.settings.nonce_retention_seconds,
                ),
            )),
        })
        .collect()
}

fn compile_handoff_replays(
    config: &Config,
) -> Result<HashMap<SocketAddr, HandoffReplayCache>, RuntimeUpdateError> {
    let mut replays = HashMap::new();
    for inbound in &config.inbounds {
        if let InboundConfig::Handoff(inbound) = inbound {
            let address = SocketAddr::new(inbound.listen, inbound.port);
            let replay = HandoffReplayCache::new(
                usize::try_from(inbound.settings.max_nonce_entries)
                    .map_err(|_| HandoffLandingConfigError::Capacity)
                    .map_err(RuntimeUpdateError::Handoff)?,
                Duration::from_secs(inbound.settings.nonce_retention_seconds),
            )
            .map_err(HandoffLandingConfigError::Replay)
            .map_err(RuntimeUpdateError::Handoff)?;
            if replays.insert(address, replay).is_some() {
                return Err(RuntimeUpdateError::DuplicateListener(address));
            }
        }
    }
    Ok(replays)
}

fn compile_nxr_replays(
    config: &Config,
) -> Result<HashMap<SocketAddr, NxrReplayCache>, RuntimeUpdateError> {
    let mut replays = HashMap::new();
    for inbound in &config.inbounds {
        if let InboundConfig::Nxr(inbound) = inbound {
            let address = SocketAddr::new(inbound.listen, inbound.port);
            let replay = NxrReplayCache::from_inbound(inbound)?;
            if replays.insert(address, replay).is_some() {
                return Err(RuntimeUpdateError::DuplicateListener(address));
            }
        }
    }
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
    emit(&logger, &LogEvent::ConnectionAccepted { peer });
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
                    RealityAcceptOutcome::Established(established) => {
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
                emit(
                    logger,
                    &LogEvent::ConnectionCompleted {
                        duration_ms: u64::try_from(started.elapsed().as_millis())
                            .unwrap_or(u64::MAX),
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
                        pipe_capacity_downgraded: stats.pipe_capacity_downgraded(),
                    },
                );
            }
            emit(logger, &LogEvent::ConnectionClosed { peer });
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

fn emit_rejected(runtime: &RuntimeStore, field: &'static str) {
    emit(
        &runtime.load().logger,
        &LogEvent::ConfigurationRejected {
            field: field.to_owned(),
        },
    );
}

fn emit_admission(logger: &Logger, error: AdmissionDenied) {
    let resource = match error {
        AdmissionDenied::Limit(AdmissionKind::Connection)
        | AdmissionDenied::Pressure(AdmissionKind::Connection) => AdmissionResource::Connections,
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
    fn rejection_reason(&self) -> RejectionReason {
        match self {
            Self::Reality(RealityAcceptError::Admission(_)) => RejectionReason::ResourceLimit,
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
    Load(ConfigLoadError),
    Invalid(ConfigError),
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
    ResourceModeChanged,
    ReplayPolicyChanged,
    DirectBarrierPolicyChanged,
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
            Self::Invalid(source) => source.fmt(formatter),
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
            Self::ResourceModeChanged => {
                formatter.write_str("the runtime resource mode requires a process restart")
            }
            Self::ReplayPolicyChanged => {
                formatter.write_str("resource governor policy requires a process restart")
            }
            Self::DirectBarrierPolicyChanged => {
                formatter.write_str("direct barrier policy requires a process restart")
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
            Self::Invalid(source) => Some(source),
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
            | Self::ResourceModeChanged
            | Self::ReplayPolicyChanged
            | Self::DirectBarrierPolicyChanged
            | Self::NxrReplayPolicyChanged
            | Self::HandoffReplayPolicyChanged
            | Self::RelayPolicyChanged
            | Self::GenerationExhausted
            | Self::Unavailable => None,
        }
    }
}

impl From<ConfigLoadError> for RuntimeUpdateError {
    fn from(source: ConfigLoadError) -> Self {
        Self::Load(source)
    }
}

impl From<ConfigError> for RuntimeUpdateError {
    fn from(source: ConfigError) -> Self {
        Self::Invalid(source)
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
        net::{IpAddr, Ipv4Addr},
        str::FromStr,
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

    use super::{ProductionServer, RuntimeUpdateError, theoretical_fd_peak};
    use crate::{
        config::{
            DirectBarrierConfig, GenerateConfigInput, InboundConfig, NxrInboundConfig,
            NxrInboundSettings, NxrSettings, OutboundConfig, SecretString, generate_minimal_config,
        },
        protocol::vless::{Address, Destination, VISION_FLOW},
        server::outbound::{OutboundConnectOutcome, OutboundRegistry},
    };

    #[test]
    fn compiles_generated_reality_vision_server_without_plain_inbound() {
        let generated = generated_config(8443);

        ProductionServer::from_config(generated.config()).expect("server must compile");
        assert_eq!(
            generated.config().inbounds[0]
                .as_vless()
                .expect("generated listener must be VLESS")
                .settings
                .clients[0]
                .flow,
            VISION_FLOW
        );
    }

    #[test]
    fn the_theoretical_peak_includes_pipe_pool_retention() {
        let generated = generated_config(8443);
        let mut config = generated.config().clone();
        config.policy.relay.splice = true;
        config.policy.relay.pipe_pool = true;
        config.policy.relay.max_splice_relays = 4;
        config.policy.relay.max_pooled_pipes = 8;
        let connections = u64::from(config.policy.resource_governor.max_connections) * 2;

        assert_eq!(
            theoretical_fd_peak(&config),
            connections + 4 * 4 + 8 * 2,
            "armed splice relays and the pipes the pool retains are both demand"
        );

        config.policy.relay.pipe_pool = false;
        assert_eq!(
            theoretical_fd_peak(&config),
            connections + 4 * 4,
            "a disabled pool retains nothing"
        );

        config.policy.relay.pipe_pool = true;
        config.policy.relay.splice = false;
        assert_eq!(
            theoretical_fd_peak(&config),
            connections + 4 * 4,
            "without splice there is no pool to retain pipes"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn binds_all_listeners_and_stops_on_injected_shutdown() {
        let generated = generated_config(unused_loopback_port());
        let server =
            ProductionServer::from_config(generated.config()).expect("server must compile");

        server
            .run_until(async { Ok(()) })
            .await
            .expect("injected shutdown must stop every listener");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn serves_internal_nxr_alongside_public_reality_vision() {
        let public_port = unused_loopback_port();
        let mut landing_port = unused_loopback_port();
        while landing_port == public_port {
            landing_port = unused_loopback_port();
        }
        let key_bytes = [0x5a; 32];
        let encoded_key = BASE64_URL_SAFE_NO_PAD.encode(key_bytes);
        let generated = generated_config(public_port);
        let mut config = generated.config().clone();
        config.inbounds.push(InboundConfig::Nxr(NxrInboundConfig {
            tag: "landing-internal".to_owned(),
            listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: landing_port,
            settings: NxrInboundSettings {
                pre_shared_key: SecretString::new(encoded_key.clone()),
                max_time_difference_seconds: 30,
                max_nonce_entries: 4_096,
                nonce_retention_seconds: 120,
                authentication_timeout_ms: 1_000,
                connect_timeout_ms: 1_000,
            },
        }));
        let server = ProductionServer::from_config(&config).expect("combined server must compile");
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
            &[OutboundConfig::Nxr {
                tag: "landing".to_owned(),
                settings: NxrSettings {
                    address: Ipv4Addr::LOCALHOST.to_string(),
                    port: landing_port,
                    pre_shared_key: SecretString::new(encoded_key),
                },
            }],
            &DirectBarrierConfig::default(),
            Duration::from_secs(1),
            crate::runtime::FdBudget::new(4_096),
        );
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let server_task = tokio::spawn(server.run_until(async move {
            shutdown_receiver
                .await
                .map_err(|_| io::Error::other("test shutdown sender dropped"))
        }));
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await?;
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).await?;
            assert_eq!(payload, b"ping");
            stream.write_all(b"pong").await?;
            stream.shutdown().await
        });

        let connection = time::timeout(Duration::from_secs(2), async {
            loop {
                match registry.connect("landing", &destination).await {
                    Ok(OutboundConnectOutcome::Connected(connection)) => break connection,
                    Ok(OutboundConnectOutcome::Blackholed) | Err(_) => {
                        time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        })
        .await
        .expect("NXR listener must become ready");
        let (mut stream, _permit) = connection.into_parts();
        stream.write_all(b"ping").await.expect("payload must write");
        stream.shutdown().await.expect("uplink must half-close");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("response must read");
        assert_eq!(response, b"pong");

        shutdown_sender.send(()).expect("shutdown must send");
        target_task
            .await
            .expect("target task must join")
            .expect("target exchange must succeed");
        server_task
            .await
            .expect("server task must join")
            .expect("server must stop cleanly");
    }

    #[test]
    fn atomically_publishes_hot_runtime_generation() {
        let generated = generated_config(8443);
        let server =
            ProductionServer::from_config(generated.config()).expect("server must compile");
        let previous = server.runtime.load();
        let mut replacement = generated.config().clone();
        replacement.log.level = crate::config::LogLevel::Debug;

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

    #[test]
    fn rejected_hot_update_keeps_last_good_runtime() {
        let generated = generated_config(8443);
        let server =
            ProductionServer::from_config(generated.config()).expect("server must compile");
        let previous = server.runtime.load();
        let mut replacement = generated.config().clone();
        replacement.inbounds[0]
            .as_vless_mut()
            .expect("generated listener must be VLESS")
            .port = 9443;

        assert!(matches!(
            server.runtime.publish(replacement),
            Err(RuntimeUpdateError::ListenerTopologyChanged)
        ));
        assert!(Arc::ptr_eq(&previous, &server.runtime.load()));
    }

    #[test]
    fn replay_policy_change_requires_restart() {
        let generated = generated_config(8443);
        let server =
            ProductionServer::from_config(generated.config()).expect("server must compile");
        let previous = server.runtime.load();
        let mut replacement = generated.config().clone();
        replacement.policy.resource_governor.max_replay_entries += 1;

        assert!(matches!(
            server.runtime.publish(replacement),
            Err(RuntimeUpdateError::ReplayPolicyChanged)
        ));
        assert!(Arc::ptr_eq(&previous, &server.runtime.load()));
    }

    #[test]
    fn resource_mode_change_requires_restart() {
        let generated = generated_config(8443);
        let server =
            ProductionServer::from_config(generated.config()).expect("server must compile");
        let previous = server.runtime.load();
        let mut replacement = generated.config().clone();
        replacement.runtime.resource_mode = crate::config::ResourceMode::Dedicated;

        assert!(matches!(
            server.runtime.publish(replacement),
            Err(RuntimeUpdateError::ResourceModeChanged)
        ));
        assert!(Arc::ptr_eq(&previous, &server.runtime.load()));
    }

    fn generated_config(port: u16) -> crate::config::GeneratedConfig {
        generate_minimal_config(GenerateConfigInput {
            listen: IpAddr::from_str("127.0.0.1").expect("address must parse"),
            port,
            target: "www.example.com:443".to_owned(),
            server_name: "www.example.com".to_owned(),
        })
        .expect("configuration must generate")
    }

    fn unused_loopback_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .map(|address| address.port())
            .unwrap_or_else(|error: io::Error| panic!("reserve loopback port: {error}"))
    }

    fn tiny_ceiling_config() -> crate::config::Config {
        let generated = generated_config(unused_loopback_port());
        let mut config = generated.config().clone();
        config.policy.resource_governor.max_connections = 2;
        config.policy.resource_governor.max_handshakes = 2;
        config.policy.resource_governor.max_fallbacks = 2;
        config.policy.resource_governor.max_crypto_operations = 2;
        config.policy.resource_governor.max_dns_lookups = 2;
        config.policy.relay.max_splice_relays = 2;
        config.policy.direct_barrier = DirectBarrierConfig {
            max_concurrent: 1,
            max_per_second: 1_000,
        };
        config
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reload_cannot_multiply_the_connection_ceiling() {
        let server = ProductionServer::from_config(&tiny_ceiling_config()).expect("must compile");
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
    async fn reload_cannot_reset_the_direct_dial_bucket() {
        let server = ProductionServer::from_config(&tiny_ceiling_config()).expect("must compile");
        let permit = server
            .runtime
            .authorities
            .direct_barrier
            .try_acquire()
            .expect("the single direct concurrency permit must be acquirable");
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
            "releasing the permit must free the bucket after reloads"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn direct_barrier_policy_is_a_cold_restart_setting() {
        let config = tiny_ceiling_config();
        let server = ProductionServer::from_config(&config).expect("must compile");
        let mut candidate = server.runtime.load().config.clone();
        candidate.policy.direct_barrier.max_concurrent = 2;

        let error = server
            .runtime
            .publish(candidate)
            .expect_err("changing the direct barrier policy must require a restart");
        assert!(
            matches!(error, RuntimeUpdateError::DirectBarrierPolicyChanged),
            "expected DirectBarrierPolicyChanged, got {error}"
        );
    }

    #[test]
    fn a_denied_direct_dial_is_reported_as_a_resource_limit() {
        use std::{fs, net::SocketAddr, sync::atomic::AtomicU64};

        use crate::{
            config::{FileLogConfig, LogConfig, LogLevel, LogOutput},
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
            level: LogLevel::Debug,
            output: LogOutput::File,
            file: Some(FileLogConfig {
                path: path.clone(),
                max_bytes: 64 * 1024,
                max_files: 1,
                max_total_bytes: 64 * 1024,
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
