use std::{
    collections::HashSet, error::Error, fmt, future::Future, io, net::SocketAddr, sync::Arc,
    time::Duration,
};

use tokio::{
    sync::watch,
    task::{JoinError, JoinSet},
    time,
};

use crate::{
    assets::{AssetLoadError, AssetSnapshot},
    config::Config,
    logging::{AdmissionResource, LogEvent, LogWriteError, Logger, RejectionReason},
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
pub struct ProductionServer {
    listeners: Vec<Arc<ListenerRuntime>>,
    logger: Logger,
}

impl ProductionServer {
    /// Compiles validated configuration, remote geo assets, routing, outbounds,
    /// REALITY authentication, replay state, and resource limits.
    ///
    /// # Errors
    ///
    /// Returns a logger, asset, routing, REALITY, or duplicate-listener error.
    pub fn from_config(config: &Config) -> Result<Self, ProductionServerError> {
        let logger = Logger::new(&config.log).map_err(ProductionServerError::Log)?;
        emit(&logger, &LogEvent::ServerStarting);
        let assets = Arc::new(AssetSnapshot::load(config).map_err(ProductionServerError::Assets)?);
        let generation = assets.generation();
        let vision =
            VisionHandler::from_config(config, assets).map_err(ProductionServerError::Routing)?;
        let governor = ResourceGovernor::new(&config.policy.resource_governor);
        let mut addresses = HashSet::new();
        let mut listeners = Vec::with_capacity(config.inbounds.len());
        for inbound in &config.inbounds {
            let address = SocketAddr::new(inbound.listen, inbound.port);
            if !addresses.insert(address) {
                return Err(ProductionServerError::DuplicateListener(address));
            }
            let reality = RealityAcceptor::from_inbound(
                inbound,
                governor.clone(),
                &config.policy.resource_governor,
            )
            .map_err(ProductionServerError::Reality)?;
            listeners.push(Arc::new(ListenerRuntime {
                tag: Arc::from(inbound.tag.as_str()),
                address,
                governor: governor.clone(),
                reality,
                vision: vision.clone(),
            }));
        }
        emit(&logger, &LogEvent::ConfigurationPublished { generation });
        Ok(Self { listeners, logger })
    }

    /// Binds every configured listener before serving any connection and runs
    /// until SIGINT or SIGTERM.
    ///
    /// # Errors
    ///
    /// Returns a bind, accept, signal, or task-supervision error.
    pub async fn run(self) -> Result<(), ProductionServerError> {
        self.run_until(shutdown_signal()).await
    }

    /// Runs until an injected shutdown future completes. This is public to make
    /// service managers and deterministic integration tests independent of signals.
    ///
    /// # Errors
    ///
    /// Returns a bind, accept, or task-supervision error.
    pub async fn run_until<F>(self, shutdown: F) -> Result<(), ProductionServerError>
    where
        F: Future<Output = Result<(), io::Error>> + Send,
    {
        let mut bound = Vec::with_capacity(self.listeners.len());
        for listener in &self.listeners {
            let acceptor = TcpAcceptor::bind(listener.address)
                .await
                .map_err(|source| ProductionServerError::Bind {
                    address: listener.address,
                    source,
                })?;
            bound.push((acceptor, Arc::clone(listener)));
        }

        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let mut listener_tasks = JoinSet::new();
        for (acceptor, state) in bound {
            let address = acceptor
                .local_addr()
                .map_err(ProductionServerError::ListenerAddress)?;
            emit(
                &self.logger,
                &LogEvent::ListenerStarted {
                    tag: state.tag.to_string(),
                    address,
                },
            );
            listener_tasks.spawn(run_listener(
                acceptor,
                state,
                self.logger.clone(),
                shutdown_receiver.clone(),
            ));
        }

        tokio::pin!(shutdown);
        let result = tokio::select! {
            signal = &mut shutdown => signal.map_err(ProductionServerError::Signal),
            completed = listener_tasks.join_next() => match completed {
                Some(Ok(Ok(()))) => Err(ProductionServerError::ListenerStopped),
                Some(Ok(Err(source))) => Err(ProductionServerError::Accept(source)),
                Some(Err(source)) => Err(ProductionServerError::Task(source)),
                None => Err(ProductionServerError::ListenerStopped),
            },
        };
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

struct ListenerRuntime {
    tag: Arc<str>,
    address: SocketAddr,
    governor: ResourceGovernor,
    reality: RealityAcceptor,
    vision: VisionHandler,
}

async fn run_listener(
    acceptor: TcpAcceptor,
    state: Arc<ListenerRuntime>,
    logger: Logger,
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
                let state = Arc::clone(&state);
                let connection_logger = logger.clone();
                connections.spawn(peer, async move {
                    run_connection(state, stream, peer, permit, &connection_logger).await
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
    state: Arc<ListenerRuntime>,
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

fn emit(logger: &Logger, event: &LogEvent) {
    let _ignored = logger.emit(event);
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

/// Production server construction or lifecycle failed.
#[derive(Debug)]
pub enum ProductionServerError {
    Log(LogWriteError),
    Assets(AssetLoadError),
    Routing(RoutingCompileError),
    Reality(RealityAcceptorConfigError),
    DuplicateListener(SocketAddr),
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
            Self::Log(source) => source.fmt(formatter),
            Self::Assets(source) => source.fmt(formatter),
            Self::Routing(source) => source.fmt(formatter),
            Self::Reality(source) => source.fmt(formatter),
            Self::DuplicateListener(address) => write!(formatter, "duplicate listener {address}"),
            Self::Bind { address, .. } => write!(formatter, "failed to bind listener {address}"),
            Self::ListenerAddress(_) => formatter.write_str("failed to read listener address"),
            Self::Accept(_) => formatter.write_str("listener accept failed"),
            Self::Signal(_) => formatter.write_str("failed to install shutdown signal"),
            Self::Task(_) => formatter.write_str("listener task failed"),
            Self::ListenerStopped => formatter.write_str("listener stopped unexpectedly"),
        }
    }
}

impl Error for ProductionServerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Log(source) => Some(source),
            Self::Assets(source) => Some(source),
            Self::Routing(source) => Some(source),
            Self::Reality(source) => Some(source),
            Self::Bind { source, .. }
            | Self::ListenerAddress(source)
            | Self::Accept(source)
            | Self::Signal(source) => Some(source),
            Self::Task(source) => Some(source),
            Self::DuplicateListener(_) | Self::ListenerStopped => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{io, net::IpAddr, str::FromStr};

    use super::{ProductionServer, ProductionServerError};
    use crate::{
        config::{GenerateConfigInput, generate_minimal_config},
        protocol::vless::VISION_FLOW,
    };

    #[test]
    fn compiles_generated_reality_vision_server_without_plain_inbound() {
        let generated = generate_minimal_config(GenerateConfigInput {
            listen: IpAddr::from_str("127.0.0.1").expect("address must parse"),
            port: 8443,
            target: "www.example.com:443".to_owned(),
            server_name: "www.example.com".to_owned(),
        })
        .expect("configuration must generate");

        ProductionServer::from_config(generated.config()).expect("server must compile");
        assert_eq!(
            generated.config().inbounds[0].settings.clients[0].flow,
            VISION_FLOW
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn binds_all_listeners_and_stops_on_injected_shutdown() {
        let generated = generate_minimal_config(GenerateConfigInput {
            listen: IpAddr::from_str("127.0.0.1").expect("address must parse"),
            port: unused_loopback_port(),
            target: "www.example.com:443".to_owned(),
            server_name: "www.example.com".to_owned(),
        })
        .expect("configuration must generate");
        let server =
            ProductionServer::from_config(generated.config()).expect("server must compile");

        server
            .run_until(async { Ok(()) })
            .await
            .expect("injected shutdown must stop every listener");
    }

    #[test]
    fn rejects_duplicate_socket_bindings_before_runtime() {
        let generated = generate_minimal_config(GenerateConfigInput {
            listen: IpAddr::from_str("127.0.0.1").expect("address must parse"),
            port: 8443,
            target: "www.example.com:443".to_owned(),
            server_name: "www.example.com".to_owned(),
        })
        .expect("configuration must generate");
        let mut config = generated.config().clone();
        let mut duplicate = config.inbounds[0].clone();
        duplicate.tag = "duplicate".to_owned();
        config.inbounds.push(duplicate);

        assert!(matches!(
            ProductionServer::from_config(&config),
            Err(ProductionServerError::DuplicateListener(_))
        ));
    }

    fn unused_loopback_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .map(|address| address.port())
            .unwrap_or_else(|error: io::Error| panic!("reserve loopback port: {error}"))
    }
}
