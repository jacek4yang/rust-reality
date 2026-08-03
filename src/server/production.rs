use std::{
    collections::{HashMap, HashSet},
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
    config::{Config, ConfigError, ConfigLoadError, load_config, validate_config},
    logging::{AdmissionResource, LogEvent, LogWriteError, Logger, RejectionReason},
    protocol::reality::ReplayCache,
    runtime::{
        AdmissionDenied, AdmissionKind, AdmissionPermit, ResourceGovernor,
        connection::ConnectionTasks,
    },
    transport::tcp::TcpAcceptor,
};

use super::{
    reality::{
        RealityAcceptError, RealityAcceptOutcome, RealityAcceptor, RealityAcceptorConfigError,
    },
    routing::RoutingCompileError,
    vision::{VisionHandler, VisionSessionError},
};

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

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
        let replay_governor = ResourceGovernor::new(&config.policy.resource_governor);
        let replay = ReplayCache::new(replay_governor, &config.policy.resource_governor);
        let initial = RuntimeSnapshot::compile(config, 0, replay.clone())?;
        let mut addresses: Vec<_> = initial.connections.keys().copied().collect();
        addresses.sort_unstable();
        emit(&initial.logger, &LogEvent::ServerStarting);
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
                generation: AtomicU64::new(0),
                update: Mutex::new(()),
            }),
            config_path,
        })
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

struct RuntimeStore {
    current: ArcSwap<RuntimeSnapshot>,
    replay: ReplayCache,
    generation: AtomicU64,
    update: Mutex<()>,
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
        let candidate = RuntimeSnapshot::compile(config, generation, self.replay.clone())?;
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
    ) -> Result<Self, RuntimeUpdateError> {
        let logger = Logger::new(&config.log)?;
        let assets = Arc::new(AssetSnapshot::load_generation(&config, generation)?);
        let vision = VisionHandler::from_config(&config, assets)?;
        let governor = ResourceGovernor::new(&config.policy.resource_governor);
        let mut connections = HashMap::new();
        connections
            .try_reserve(config.inbounds.len())
            .map_err(|_| RuntimeUpdateError::Unavailable)?;
        for inbound in &config.inbounds {
            let address = SocketAddr::new(inbound.listen, inbound.port);
            let reality = RealityAcceptor::from_inbound_with_replay(
                inbound,
                governor.clone(),
                &config.policy.resource_governor,
                replay.clone(),
            )?;
            if connections
                .insert(
                    address,
                    Arc::new(ConnectionRuntime {
                        tag: Arc::from(inbound.tag.as_str()),
                        governor: governor.clone(),
                        reality,
                        vision: vision.clone(),
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
    reality: RealityAcceptor,
    vision: VisionHandler,
}

fn ensure_hot_compatible(
    current: &RuntimeSnapshot,
    candidate: &Config,
) -> Result<(), RuntimeUpdateError> {
    let addresses: HashSet<_> = candidate
        .inbounds
        .iter()
        .map(|inbound| SocketAddr::new(inbound.listen, inbound.port))
        .collect();
    if addresses.len() != current.connections.len()
        || !current
            .connections
            .keys()
            .all(|address| addresses.contains(address))
    {
        return Err(RuntimeUpdateError::ListenerTopologyChanged);
    }
    if candidate.policy.resource_governor != current.config.policy.resource_governor {
        return Err(RuntimeUpdateError::ReplayPolicyChanged);
    }
    Ok(())
}

async fn run_listener(
    acceptor: TcpAcceptor,
    address: SocketAddr,
    runtime: Arc<RuntimeStore>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let mut connections = ConnectionTasks::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = acceptor.accept() => {
                let (stream, peer) = accepted?;
                let snapshot = runtime.load();
                let Some(state) = snapshot.connections.get(&address).cloned() else {
                    return Err(io::Error::other("active runtime is missing listener state"));
                };
                let logger = snapshot.logger.clone();
                drop(snapshot);
                let permit = match state.governor.try_acquire(AdmissionKind::Connection) {
                    Ok(permit) => permit,
                    Err(error) => {
                        emit_admission(&logger, error);
                        emit(
                            &logger,
                            &LogEvent::ConnectionRejected {
                                peer,
                                reason: RejectionReason::ResourceLimit,
                            },
                        );
                        continue;
                    }
                };
                emit(&logger, &LogEvent::ConnectionAccepted { peer });
                connections.spawn(peer, async move {
                    run_connection(state, stream, peer, permit, &logger).await
                });
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                consume_connection_result(completed);
            }
        }
    }
    drain_connections(&mut connections).await;
    Ok(())
}

async fn run_connection(
    state: Arc<ConnectionRuntime>,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    connection_permit: AdmissionPermit,
    logger: &Logger,
) -> io::Result<()> {
    let result = async {
        match state.reality.accept(stream, peer).await? {
            RealityAcceptOutcome::Established(established) => {
                state.vision.handle(established).await?;
            }
            RealityAcceptOutcome::Fallback(_) => {}
        }
        Ok::<(), ConnectionRunError>(())
    }
    .await;
    drop(connection_permit);
    match result {
        Ok(()) => {
            emit(logger, &LogEvent::ConnectionClosed { peer });
            Ok(())
        }
        Err(error) => {
            emit(
                logger,
                &LogEvent::ConnectionRejected {
                    peer,
                    reason: error.rejection_reason(),
                },
            );
            Err(io::Error::other(error))
        }
    }
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
        AdmissionDenied::Limit(AdmissionKind::Connection) => AdmissionResource::Connections,
        AdmissionDenied::Limit(AdmissionKind::Handshake) => AdmissionResource::Handshakes,
        AdmissionDenied::Limit(AdmissionKind::Fallback) => AdmissionResource::Fallbacks,
        AdmissionDenied::Limit(AdmissionKind::CryptoOperation) => {
            AdmissionResource::CryptoOperations
        }
        AdmissionDenied::Limit(AdmissionKind::ReplayEntry) => AdmissionResource::ReplayEntries,
        AdmissionDenied::DirectConcurrency | AdmissionDenied::DirectRate => {
            AdmissionResource::DirectConnections
        }
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
}

impl ConnectionRunError {
    const fn rejection_reason(&self) -> RejectionReason {
        match self {
            Self::Reality(RealityAcceptError::Admission(_)) => RejectionReason::ResourceLimit,
            Self::Reality(RealityAcceptError::HandshakeWriteTimeout)
            | Self::Vision(VisionSessionError::Timeout) => RejectionReason::Timeout,
            Self::Reality(RealityAcceptError::Fallback(_)) => RejectionReason::Outbound,
            Self::Reality(_) => RejectionReason::Authentication,
            Self::Vision(VisionSessionError::Route(_) | VisionSessionError::Outbound(_)) => {
                RejectionReason::Outbound
            }
            Self::Vision(_) => RejectionReason::Protocol,
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

impl fmt::Display for ConnectionRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reality(source) => source.fmt(formatter),
            Self::Vision(source) => source.fmt(formatter),
        }
    }
}

impl Error for ConnectionRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Reality(source) => Some(source),
            Self::Vision(source) => Some(source),
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
    DuplicateListener(SocketAddr),
    ListenerTopologyChanged,
    ReplayPolicyChanged,
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
            Self::DuplicateListener(address) => write!(formatter, "duplicate listener {address}"),
            Self::ListenerTopologyChanged => {
                formatter.write_str("listener addresses require a process restart")
            }
            Self::ReplayPolicyChanged => {
                formatter.write_str("resource governor policy requires a process restart")
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
            Self::DuplicateListener(_)
            | Self::ListenerTopologyChanged
            | Self::ReplayPolicyChanged
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

/// Production server construction or lifecycle failed.
#[derive(Debug)]
pub enum ProductionServerError {
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
            Self::ListenerStopped => None,
        }
    }
}

impl From<RuntimeUpdateError> for ProductionServerError {
    fn from(source: RuntimeUpdateError) -> Self {
        Self::Runtime(source)
    }
}

#[cfg(test)]
mod tests {
    use std::{io, net::IpAddr, str::FromStr, sync::Arc};

    use super::{ProductionServer, RuntimeUpdateError};
    use crate::{
        config::{GenerateConfigInput, generate_minimal_config},
        protocol::vless::VISION_FLOW,
    };

    #[test]
    fn compiles_generated_reality_vision_server_without_plain_inbound() {
        let generated = generated_config(8443);

        ProductionServer::from_config(generated.config()).expect("server must compile");
        assert_eq!(
            generated.config().inbounds[0].settings.clients[0].flow,
            VISION_FLOW
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
        replacement.inbounds[0].port = 9443;

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
}
