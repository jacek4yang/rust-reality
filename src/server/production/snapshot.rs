//! One immutable generation: everything a connection accepted right now will
//! use for its whole life.
//!
//! A snapshot is compiled, published, and never mutated. A connection takes
//! one `Arc` at accept time and keeps it, so a reload landing mid-session
//! cannot cross a live flow onto a new routing table or a new outbound. The
//! process-lifetime authorities are *borrowed* into each generation rather
//! than rebuilt, which is what stops ten reloads from multiplying an
//! admission ceiling.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use crate::{
    assets::AssetSnapshot,
    config::{NodeConfig, node::landing::LandingProtocol, node::listener::ListenerConfig},
    logging::{LogEvent, Logger},
    protocol::reality::ReplayCache,
    runtime::{PressureGauge, policy::EffectivePolicy},
    transport::tcp_relay::TcpRelay,
};

use crate::runtime::ResourceGovernor;
use crate::server::{
    handoff::HandoffLandingHandler, nxr::NxrLandingHandler, outbound::OutboundRegistry,
    pre_auth::PreAuthGeneration, reality::RealityAcceptor, vision::VisionHandler,
};

use super::{
    error::RuntimeUpdateError,
    event::emit,
    store::{ListenerReplays, ProcessAuthorities},
};

/// What produced a generation. Reported by the control interface; never
/// consulted by a connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GenerationOrigin {
    /// Generation zero, compiled from the startup configuration.
    Startup,
    /// A configuration file reload (`SIGHUP` or `config.reload`).
    Configuration,
    /// A scheduled asset refresh of the live configuration.
    Assets,
    /// A control-interface mutation.
    Control,
}

impl GenerationOrigin {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Configuration => "configuration",
            Self::Assets => "assets",
            Self::Control => "control",
        }
    }
}

/// How a generation relates to the configuration file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Provenance {
    pub(super) origin: GenerationOrigin,
    /// Whether this generation carries control changes the configuration
    /// file does not. A file reload replaces them.
    pub(super) control_changes: bool,
}

impl Provenance {
    pub(super) const STARTUP: Self = Self {
        origin: GenerationOrigin::Startup,
        control_changes: false,
    };
}

pub(super) struct RuntimeSnapshot {
    pub(super) generation: u64,
    pub(super) provenance: Provenance,
    pub(super) node: NodeConfig,
    pub(super) connections: HashMap<SocketAddr, Arc<ConnectionRuntime>>,
    pub(super) logger: Logger,
    pub(super) pre_auth_generation: PreAuthGeneration,
    pub(super) outbounds: OutboundRegistry,
    /// The entry's loaded geo assets, kept so an identity-only generation can
    /// reuse them instead of loading them again. `None` on a landing.
    pub(super) assets: Option<Arc<AssetSnapshot>>,
    /// Every configured user's control handle, derived on the first control
    /// read of this generation and reused by every later one.
    pub(super) handle_index: std::sync::OnceLock<Option<Arc<crate::control::HandleIndex>>>,
}

impl RuntimeSnapshot {
    #[allow(
        clippy::too_many_arguments,
        reason = "one parameter per process-lifetime authority the snapshot binds"
    )]
    pub(super) fn compile(
        config: NodeConfig,
        policy: &EffectivePolicy,
        generation: u64,
        provenance: Provenance,
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
        let mut loaded_assets = None;
        let (handler, outbounds) = match &config {
            NodeConfig::Entry(entry) => {
                let assets = Arc::new(AssetSnapshot::load_generation(entry, generation)?);
                loaded_assets = Some(Arc::clone(&assets));
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
                let outbounds = OutboundRegistry::with_warm_pools(
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
                let io_timeout = crate::io_activity::WRITE_STALL_TIMEOUT;
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
        let connections = bind_connections(&config, &runtime)?;

        Ok(Self {
            generation,
            provenance,
            node: config,
            connections,
            logger,
            pre_auth_generation,
            outbounds,
            assets: loaded_assets,
            handle_index: std::sync::OnceLock::new(),
        })
    }

    /// Compiles a generation whose configuration differs from `previous` only
    /// in the entry's `users`.
    ///
    /// Who may authenticate and which routing policy applies are recompiled
    /// from the new users: the REALITY authenticator and short-ID index, the
    /// UUID-grouped routing table, and the VLESS user map are all built fresh,
    /// exactly as a full compile builds them. What does not depend on users is
    /// shared with `previous` instead of rebuilt: the loaded geo assets (so no
    /// asset is read or fetched), the outbound registry and its line-to-landing
    /// pools, the cover fallback and its pool, the cover profiles, the
    /// certificate identity, and the logger. Sharing is sound because none of
    /// these hold per-user state, and the process-lifetime replay cache and
    /// admission authorities were already shared by every generation.
    ///
    /// The new generation therefore takes over `previous`'s pools; the caller
    /// must retire only `previous`'s pre-auth generation, not its pools.
    pub(super) fn compile_identity(
        previous: &Self,
        config: NodeConfig,
        generation: u64,
        provenance: Provenance,
    ) -> Result<Self, RuntimeUpdateError> {
        let (NodeConfig::Entry(entry), Some(assets)) = (&config, previous.assets.as_ref()) else {
            return Err(RuntimeUpdateError::Unavailable);
        };
        let Some(previous_runtime) = previous.connections.values().next() else {
            return Err(RuntimeUpdateError::Unavailable);
        };
        let ConnectionHandler::Public { reality, vision } = &previous_runtime.handler else {
            return Err(RuntimeUpdateError::Unavailable);
        };
        let assets_matcher: Arc<dyn crate::assets::AssetMatcher> = Arc::clone(assets) as _;
        let vision = vision.with_users(entry, assets_matcher)?;
        let reality = reality.with_users(entry)?;
        let runtime = Arc::new(ConnectionRuntime {
            tag: Arc::clone(&previous_runtime.tag),
            governor: previous_runtime.governor.clone(),
            handler: ConnectionHandler::Public {
                reality: Box::new(reality),
                vision,
            },
        });
        let connections = bind_connections(&config, &runtime)?;
        Ok(Self {
            generation,
            provenance,
            node: config,
            connections,
            logger: previous.logger.clone(),
            pre_auth_generation: PreAuthGeneration::default(),
            outbounds: previous.outbounds.clone(),
            assets: Some(Arc::clone(assets)),
            handle_index: std::sync::OnceLock::new(),
        })
    }

    pub(super) fn activate_warm_pools(&self) {
        self.outbounds.activate_warm_pools();
        for connection in self.connections.values() {
            if let ConnectionHandler::Public { reality, .. } = &connection.handler {
                reality.activate_cover_pool();
            }
        }
    }

    pub(super) fn deactivate_warm_pools(&self) {
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

pub(super) struct ConnectionRuntime {
    pub(super) tag: Arc<str>,
    pub(super) governor: ResourceGovernor,
    pub(super) handler: ConnectionHandler,
}

pub(super) enum ConnectionHandler {
    Public {
        reality: Box<RealityAcceptor>,
        vision: VisionHandler,
    },
    Nxr(NxrLandingHandler),
    Handoff(HandoffLandingHandler),
}

/// Maps every bound address of `config` to the one shared connection runtime.
fn bind_connections(
    config: &NodeConfig,
    runtime: &Arc<ConnectionRuntime>,
) -> Result<HashMap<SocketAddr, Arc<ConnectionRuntime>>, RuntimeUpdateError> {
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
        if connections.insert(address, Arc::clone(runtime)).is_some() {
            return Err(RuntimeUpdateError::DuplicateListener(address));
        }
    }
    Ok(connections)
}

pub(super) fn listener_addresses(node: &NodeConfig) -> Vec<SocketAddr> {
    node.listeners()
        .iter()
        .flat_map(ListenerConfig::bind_addresses)
        .collect()
}

pub(super) fn canonical_listener_address(node: &NodeConfig) -> SocketAddr {
    listener_addresses(node)[0]
}
