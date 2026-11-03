use std::{
    collections::BTreeMap,
    collections::HashMap,
    error::Error,
    fmt, io,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{self, Instant},
};
use zeroize::Zeroizing;

use crate::{
    config::node::outbound::{BUILTIN_BLOCK, BUILTIN_DIRECT},
    network::NetworkEnvironment,
    protocol::{
        nxr::{NxrKey, NxrProtocolError, encode_request},
        nxr_udp::{NxrUdpSessionKey, encode_udp_open, open_authenticated_prefix},
        vless::{Address, Destination},
    },
    runtime::{AdmissionDenied, DirectBarrier},
    transport::{FdBudget, FdPermit},
};
use rr_session::AttemptTransport;

use super::{
    connector::{AccountedTcpStream, DestinationConnectError, DestinationConnector},
    counted_write::write_all_counted_before,
    handoff::HandoffLine,
    warm_pool::{AdaptiveTcpPool, WarmPoolAuthority, WarmPoolSnapshot, WarmUsePermit},
};
use crate::config::node::network::NetworkConfig;
use crate::config::node::outbound::{NxrOutboundConfig, OutboundConfig, Socks5Config};
use crate::runtime::policy::{DirectBarrierPolicy, WarmConnectionPolicy};

const SOCKS_VERSION: u8 = 5;
const SOCKS_AUTH_VERSION: u8 = 1;
const SOCKS_CONNECT: u8 = 1;
const SOCKS_NO_AUTH: u8 = 0;
const SOCKS_USERNAME_PASSWORD: u8 = 2;
const SOCKS_NO_ACCEPTABLE_METHODS: u8 = 0xff;
/// Benchmarked crossover for immutable outbound tags: sorted lookup is faster
/// at one and four entries; hashing wins by sixteen entries.
const SORTED_OUTBOUND_LIMIT: usize = 4;

enum OutboundIndex {
    Sorted(Box<[(Box<str>, CompiledOutbound)]>),
    Hashed(HashMap<Box<str>, CompiledOutbound>),
}

/// How many outbounds exist without being declared: `direct` and `block`.
#[cfg(test)]
const BUILTIN_OUTBOUND_COUNT: usize = crate::config::node::outbound::BUILTIN_OUTBOUNDS.len();

impl OutboundIndex {
    fn from_config(
        outbounds: &BTreeMap<String, OutboundConfig>,
        connector: &DestinationConnector,
        fd_budget: &FdBudget,
        warm: Option<&WarmBuildContext<'_>>,
    ) -> Self {
        // `direct` and `block` are always available and are never declared, so
        // they are compiled in rather than read from the map.
        let mut entries = vec![
            (Box::<str>::from(BUILTIN_DIRECT), CompiledOutbound::Direct),
            (Box::<str>::from(BUILTIN_BLOCK), CompiledOutbound::Block),
        ];
        entries.extend(outbounds.iter().map(|(name, outbound)| {
            (
                Box::<str>::from(name.as_str()),
                CompiledOutbound::from_config(outbound, connector, fd_budget, warm),
            )
        }));
        if entries.len() <= SORTED_OUTBOUND_LIMIT {
            entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            Self::Sorted(entries.into_boxed_slice())
        } else {
            Self::Hashed(entries.into_iter().collect())
        }
    }

    fn get(&self, tag: &str) -> Option<&CompiledOutbound> {
        match self {
            Self::Sorted(entries) => entries
                .binary_search_by(|(candidate, _)| candidate.as_ref().cmp(tag))
                .ok()
                .map(|index| &entries[index].1),
            Self::Hashed(entries) => entries.get(tag),
        }
    }

    fn contains(&self, tag: &str) -> bool {
        self.get(tag).is_some()
    }

    fn tags(&self) -> Vec<&str> {
        match self {
            Self::Sorted(entries) => entries.iter().map(|(tag, _)| tag.as_ref()).collect(),
            Self::Hashed(entries) => {
                let mut tags = entries.keys().map(Box::as_ref).collect::<Vec<_>>();
                tags.sort_unstable();
                tags
            }
        }
    }

    fn values(&self) -> Box<dyn Iterator<Item = &CompiledOutbound> + '_> {
        match self {
            Self::Sorted(entries) => Box::new(entries.iter().map(|(_, outbound)| outbound)),
            Self::Hashed(entries) => Box::new(entries.values()),
        }
    }
}

struct WarmBuildContext<'a> {
    generation: u64,
    authority: WarmPoolAuthority,
    policy: &'a WarmConnectionPolicy,
}

/// Immutable outbound transports indexed by validated routing tags.
#[derive(Clone)]
pub struct OutboundRegistry {
    outbounds: Arc<OutboundIndex>,
    direct_barrier: DirectBarrier,
    connect_timeout: Duration,
    fd_budget: FdBudget,
    connector: DestinationConnector,
}

impl OutboundRegistry {
    /// Compiles validated outbound configuration into secret-safe runtime state.
    #[must_use]
    pub fn new(
        outbounds: &BTreeMap<String, OutboundConfig>,
        direct_barrier: &DirectBarrierPolicy,
        connect_timeout: Duration,
        fd_budget: FdBudget,
    ) -> Self {
        Self::build(
            outbounds,
            DirectBarrier::new(direct_barrier),
            connect_timeout,
            fd_budget,
            NetworkConfig::default(),
            NetworkEnvironment::detect(),
            None,
        )
    }

    /// Compiles outbound configuration onto one shared direct-dial authority.
    ///
    /// The barrier is process-lifetime: reload generations reuse the same
    /// concurrency and rate permits instead of silently multiplying them.
    #[must_use]
    pub fn with_barrier(
        outbounds: &BTreeMap<String, OutboundConfig>,
        direct_barrier: DirectBarrier,
        connect_timeout: Duration,
        fd_budget: FdBudget,
    ) -> Self {
        Self::build(
            outbounds,
            direct_barrier,
            connect_timeout,
            fd_budget,
            NetworkConfig::default(),
            NetworkEnvironment::detect(),
            None,
        )
    }

    /// Compiles outbounds over one process-lifetime adaptive network state.
    #[must_use]
    pub fn with_barrier_and_network(
        outbounds: &BTreeMap<String, OutboundConfig>,
        direct_barrier: DirectBarrier,
        connect_timeout: Duration,
        fd_budget: FdBudget,
        network: &NetworkConfig,
        environment: NetworkEnvironment,
    ) -> Self {
        Self::build(
            outbounds,
            direct_barrier,
            connect_timeout,
            fd_budget,
            *network,
            environment,
            None,
        )
    }

    /// Compiles generation-owned adaptive pools for eligible fixed peers.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "one argument per process/generation authority"
    )]
    pub(crate) fn with_warm_pools(
        outbounds: &BTreeMap<String, OutboundConfig>,
        direct_barrier: DirectBarrier,
        connect_timeout: Duration,
        fd_budget: FdBudget,
        network: &NetworkConfig,
        environment: NetworkEnvironment,
        generation: u64,
        authority: WarmPoolAuthority,
        policy: &WarmConnectionPolicy,
    ) -> Self {
        let warm = WarmBuildContext {
            generation,
            authority,
            policy,
        };
        Self::build(
            outbounds,
            direct_barrier,
            connect_timeout,
            fd_budget,
            *network,
            environment,
            Some(&warm),
        )
    }

    fn build(
        outbounds: &BTreeMap<String, OutboundConfig>,
        direct_barrier: DirectBarrier,
        connect_timeout: Duration,
        fd_budget: FdBudget,
        network: NetworkConfig,
        environment: NetworkEnvironment,
        warm: Option<&WarmBuildContext<'_>>,
    ) -> Self {
        let connector =
            DestinationConnector::with_environment(connect_timeout, network, environment);
        Self {
            outbounds: Arc::new(OutboundIndex::from_config(
                outbounds, &connector, &fd_budget, warm,
            )),
            direct_barrier,
            connect_timeout,
            fd_budget,
            connector,
        }
    }

    /// Connects the selected transport without ever logging credentials or keys.
    ///
    /// # Errors
    ///
    /// Returns an unknown-tag, admission, connection, SOCKS5, or NXR authentication error.
    pub async fn connect(
        &self,
        tag: &str,
        destination: &Destination,
    ) -> Result<OutboundConnectOutcome, OutboundConnectError> {
        self.connect_resolved(tag, destination, &[]).await
    }

    /// Connects a selected outbound while allowing direct TCP to reuse the exact
    /// bounded DNS snapshot considered by GeoIP routing. Proxy and NXR outbounds
    /// continue forwarding the authenticated domain to the remote hop.
    pub async fn connect_resolved(
        &self,
        tag: &str,
        destination: &Destination,
        resolved_ips: &[std::net::IpAddr],
    ) -> Result<OutboundConnectOutcome, OutboundConnectError> {
        let outbound = self
            .outbounds
            .get(tag)
            .ok_or_else(|| OutboundConnectError::UnknownTag(tag.to_owned()))?;
        self.connect_compiled(outbound, destination, resolved_ips)
            .await
    }

    /// Classifies a routed outbound tag for XUDP eligibility.
    pub(crate) fn xudp_route_class(&self, tag: &str) -> crate::server::xudp::XudpRouteClass {
        use crate::server::xudp::XudpRouteClass;
        match self.outbounds.get(tag) {
            Some(CompiledOutbound::Direct) => XudpRouteClass::Direct,
            Some(CompiledOutbound::Nxr(_)) => XudpRouteClass::Nxr,
            Some(CompiledOutbound::Handoff(_)) => XudpRouteClass::Handoff,
            Some(CompiledOutbound::Block) => XudpRouteClass::Block,
            Some(CompiledOutbound::Socks5(_)) | None => XudpRouteClass::Unsupported,
        }
    }

    /// Opens one NXR UDP association carrier toward `destination` (ADR 0060).
    ///
    /// Fail-closed: unknown tags, non-NXR outbounds, and Handoff/Direct tags
    /// return errors — never remapped to Direct UDP sockets.
    pub(crate) async fn connect_nxr_udp(
        &self,
        tag: &str,
        destination: &Destination,
        user_id: [u8; 16],
    ) -> Result<(OutboundConnection, NxrUdpSessionKey), OutboundConnectError> {
        let outbound = self
            .outbounds
            .get(tag)
            .ok_or_else(|| OutboundConnectError::UnknownTag(tag.to_owned()))?;
        match outbound {
            CompiledOutbound::Nxr(Some(settings)) => {
                let (prepared, session) = dial_nxr_udp_carrier(
                    settings,
                    destination,
                    user_id,
                    self.connect_timeout,
                    &self.connector,
                    &self.fd_budget,
                )
                .await?;
                let (connection, warm_permit) = prepared.into_parts();
                let (stream, fd_permit) = connection.into_parts();
                Ok((
                    OutboundConnection {
                        stream,
                        fd_permit,
                        warm_permit,
                    },
                    session,
                ))
            }
            CompiledOutbound::Nxr(None) => Err(OutboundConnectError::NxrOutboundConfig),
            CompiledOutbound::Handoff(_) => Err(OutboundConnectError::HandoffUnsupported),
            CompiledOutbound::Direct | CompiledOutbound::Block | CompiledOutbound::Socks5(_) => {
                Err(OutboundConnectError::UnknownTag(tag.to_owned()))
            }
        }
    }

    /// Resolves one Vision route exactly once, returning a session handoff or
    /// the completed ordinary outbound decision.
    pub(crate) async fn connect_session_resolved(
        &self,
        tag: &str,
        destination: &Destination,
        resolved_ips: &[std::net::IpAddr],
    ) -> Result<SessionOutboundOutcome, OutboundConnectError> {
        let outbound = self
            .outbounds
            .get(tag)
            .ok_or_else(|| OutboundConnectError::UnknownTag(tag.to_owned()))?;
        if let CompiledOutbound::Handoff(line) = outbound {
            return line
                .clone()
                .map(SessionOutboundOutcome::Handoff)
                .ok_or(OutboundConnectError::HandoffUnsupported);
        }
        self.connect_compiled(outbound, destination, resolved_ips)
            .await
            .map(SessionOutboundOutcome::Connected)
    }

    async fn connect_compiled(
        &self,
        outbound: &CompiledOutbound,
        destination: &Destination,
        resolved_ips: &[std::net::IpAddr],
    ) -> Result<OutboundConnectOutcome, OutboundConnectError> {
        match outbound {
            CompiledOutbound::Direct => {
                let permit = self
                    .direct_barrier
                    .try_acquire()
                    .map_err(OutboundConnectError::Admission)?;
                let connected = self
                    .connector
                    .connect_resolved_accounted(destination, resolved_ips, &self.fd_budget)
                    .await
                    .map_err(map_direct_error)?;
                let (stream, fd_permit) = connected.into_parts();
                // The barrier permit bounds the dial phase only: every error
                // return above drops it implicitly, and a resolved connect
                // releases it here before the session starts. The descriptor
                // permit is different — it rides the socket for its entire
                // lifetime so the unit is never freed before the close.
                drop(permit);
                Ok(OutboundConnectOutcome::Connected(OutboundConnection {
                    stream,
                    fd_permit,
                    warm_permit: None,
                }))
            }
            CompiledOutbound::Block => Ok(OutboundConnectOutcome::Blocked),
            CompiledOutbound::Socks5(settings) => {
                let connected = connect_socks5(
                    settings,
                    destination,
                    self.connect_timeout,
                    &self.connector,
                    &self.fd_budget,
                )
                .await?;
                let (connection, warm_permit) = connected.into_parts();
                let (stream, fd_permit) = connection.into_parts();
                Ok(OutboundConnectOutcome::Connected(OutboundConnection {
                    stream,
                    fd_permit,
                    warm_permit,
                }))
            }
            CompiledOutbound::Nxr(Some(settings)) => {
                let connected = connect_nxr(
                    settings,
                    destination,
                    self.connect_timeout,
                    &self.connector,
                    &self.fd_budget,
                )
                .await?;
                let (connection, warm_permit) = connected.into_parts();
                let (stream, fd_permit) = connection.into_parts();
                Ok(OutboundConnectOutcome::Connected(OutboundConnection {
                    stream,
                    fd_permit,
                    warm_permit,
                }))
            }
            CompiledOutbound::Nxr(None) => Err(OutboundConnectError::NxrOutboundConfig),
            // The Vision session pipeline intercepts a handoff route at the
            // session boundary via `handoff_line`; a handoff outbound never
            // serves a plain destination dial.
            CompiledOutbound::Handoff(_) => Err(OutboundConnectError::HandoffUnsupported),
        }
    }

    /// Returns whether a validated tag is present in this immutable snapshot.
    #[must_use]
    pub fn contains(&self, tag: &str) -> bool {
        self.outbounds.contains(tag)
    }

    pub(crate) fn activate_warm_pools(&self) {
        for outbound in self.outbounds.values() {
            outbound.activate_warm_pool();
        }
    }

    pub(crate) fn deactivate_warm_pools(&self) {
        for outbound in self.outbounds.values() {
            outbound.deactivate_warm_pool();
        }
    }

    pub(crate) fn warm_pool_snapshots(&self) -> Vec<OutboundWarmPoolSnapshot> {
        self.outbounds
            .values()
            .filter_map(CompiledOutbound::warm_pool_snapshot)
            .collect()
    }

    /// Visits each warm outbound pool without allocating an intermediate vector.
    ///
    /// Callers that need only aggregates (telemetry) use this path so sampling
    /// stays allocation-free on the observer hot path. Order is unspecified.
    pub(crate) fn visit_warm_pool_snapshots(
        &self,
        mut visitor: impl FnMut(OutboundWarmPoolSnapshot),
    ) {
        let mut visit = |outbound: &CompiledOutbound| {
            if let Some(snapshot) = outbound.warm_pool_snapshot() {
                visitor(snapshot);
            }
        };
        match self.outbounds.as_ref() {
            OutboundIndex::Sorted(entries) => {
                for (_, outbound) in entries {
                    visit(outbound);
                }
            }
            OutboundIndex::Hashed(entries) => {
                for outbound in entries.values() {
                    visit(outbound);
                }
            }
        }
    }
}

impl fmt::Debug for OutboundRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundRegistry")
            .field("tags", &self.outbounds.tags())
            .field("connect_timeout", &self.connect_timeout)
            .finish_non_exhaustive()
    }
}

enum CompiledOutbound {
    Direct,
    Block,
    Socks5(CompiledSocks5),
    Nxr(Option<CompiledNxr>),
    Handoff(Option<HandoffLine>),
}

impl CompiledOutbound {
    fn from_config(
        outbound: &OutboundConfig,
        connector: &DestinationConnector,
        fd_budget: &FdBudget,
        warm: Option<&WarmBuildContext<'_>>,
    ) -> Self {
        match outbound {
            OutboundConfig::Socks5(settings) => {
                Self::Socks5(CompiledSocks5::new(settings, connector, fd_budget, warm))
            }
            OutboundConfig::Nxr(settings) => {
                Self::Nxr(CompiledNxr::new(settings, connector, fd_budget, warm))
            }
            OutboundConfig::Handoff(settings) => {
                Self::Handoff(HandoffLine::from_settings_with_warm_pool(
                    settings,
                    connector.clone(),
                    fd_budget,
                    warm.map(|context| {
                        (
                            context.generation,
                            context.authority.clone(),
                            context.policy,
                        )
                    }),
                ))
            }
        }
    }

    fn warm_pool(&self) -> Option<&AdaptiveTcpPool> {
        match self {
            Self::Socks5(settings) => settings.pool.as_ref(),
            Self::Nxr(Some(settings)) => settings.pool.as_ref(),
            Self::Handoff(Some(line)) => line.warm_pool(),
            Self::Direct | Self::Block | Self::Nxr(None) | Self::Handoff(None) => None,
        }
    }

    fn activate_warm_pool(&self) {
        if let Some(pool) = self.warm_pool() {
            let _activated = pool.activate();
        }
    }

    fn deactivate_warm_pool(&self) {
        if let Some(pool) = self.warm_pool() {
            let _deactivated = pool.deactivate();
        }
    }

    fn warm_pool_snapshot(&self) -> Option<OutboundWarmPoolSnapshot> {
        let transport = match self {
            Self::Socks5(_) => WarmOutboundKind::Socks5,
            Self::Nxr(Some(_)) => WarmOutboundKind::Nxr,
            Self::Handoff(Some(_)) => WarmOutboundKind::Handoff,
            Self::Direct | Self::Block | Self::Nxr(None) | Self::Handoff(None) => {
                return None;
            }
        };
        self.warm_pool().map(|pool| OutboundWarmPoolSnapshot {
            transport,
            pool: pool.snapshot(),
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) enum WarmOutboundKind {
    Handoff,
    Nxr,
    Socks5,
}

impl WarmOutboundKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Handoff => "handoff",
            Self::Nxr => "nxr",
            Self::Socks5 => "socks5",
        }
    }
}

pub(crate) struct OutboundWarmPoolSnapshot {
    pub(crate) transport: WarmOutboundKind,
    pub(crate) pool: WarmPoolSnapshot,
}

struct CompiledSocks5 {
    address: Arc<str>,
    port: u16,
    credentials: Option<Socks5Credentials>,
    pool: Option<AdaptiveTcpPool>,
}

impl CompiledSocks5 {
    fn new(
        settings: &Socks5Config,
        connector: &DestinationConnector,
        fd_budget: &FdBudget,
        warm: Option<&WarmBuildContext<'_>>,
    ) -> Self {
        let credentials = settings
            .username
            .as_ref()
            .zip(settings.password.as_ref())
            .map(|(username, password)| Socks5Credentials {
                username: Zeroizing::new(username.expose().to_owned()),
                password: Zeroizing::new(password.expose().to_owned()),
            });
        Self {
            address: Arc::from(settings.address.as_str()),
            port: settings.port,
            credentials,
            pool: settings
                .warm_tcp
                .unwrap_or(true)
                .then_some(warm)
                .flatten()
                .map(|warm| {
                    AdaptiveTcpPool::new(
                        Arc::from(format!("{}:{}", settings.address, settings.port)),
                        warm.generation,
                        connector.clone(),
                        fd_budget.clone(),
                        warm.authority.clone(),
                        warm.policy,
                    )
                }),
        }
    }
}

struct Socks5Credentials {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

struct CompiledNxr {
    address: Arc<str>,
    port: u16,
    key: NxrKey,
    pool: Option<AdaptiveTcpPool>,
}

impl CompiledNxr {
    fn new(
        settings: &NxrOutboundConfig,
        connector: &DestinationConnector,
        fd_budget: &FdBudget,
        warm: Option<&WarmBuildContext<'_>>,
    ) -> Option<Self> {
        let decoded = Zeroizing::new(BASE64_URL_SAFE_NO_PAD.decode(settings.psk.expose()).ok()?);
        let key: [u8; 32] = decoded.as_slice().try_into().ok()?;
        Some(Self {
            address: Arc::from(settings.address.as_str()),
            port: settings.port,
            key: NxrKey::new(key),
            pool: settings
                .warm_tcp
                .unwrap_or(true)
                .then_some(warm)
                .flatten()
                .map(|warm| {
                    AdaptiveTcpPool::new(
                        Arc::from(format!("{}:{}", settings.address, settings.port)),
                        warm.generation,
                        connector.clone(),
                        fd_budget.clone(),
                        warm.authority.clone(),
                        warm.policy,
                    )
                }),
        })
    }
}

/// A connected outbound stream retaining its lifetime descriptor permit.
pub struct OutboundConnection {
    stream: TcpStream,
    fd_permit: FdPermit,
    warm_permit: Option<WarmUsePermit>,
}

impl OutboundConnection {
    /// Separates the stream and its lifetime permit for a session relay.
    #[must_use]
    pub fn into_parts(self) -> (TcpStream, OutboundPermit) {
        (
            self.stream,
            OutboundPermit {
                _fd: self.fd_permit,
                _warm: self.warm_permit,
            },
        )
    }
}

impl fmt::Debug for OutboundConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundConnection")
            .field("stream", &"[CONNECTED]")
            .finish()
    }
}

/// Permit retained until a connected outbound session ends.
pub struct OutboundPermit {
    _fd: FdPermit,
    _warm: Option<WarmUsePermit>,
}

/// The selected route either connected or intentionally discarded the session.
#[derive(Debug)]
pub enum OutboundConnectOutcome {
    Connected(OutboundConnection),
    Blocked,
}

/// A Vision route either transfers the authenticated session or completes an
/// ordinary outbound decision.
pub(crate) enum SessionOutboundOutcome {
    Handoff(HandoffLine),
    Connected(OutboundConnectOutcome),
}

/// Outbound selection or connection failed.
#[derive(Debug)]
pub enum OutboundConnectError {
    UnknownTag(String),
    Admission(AdmissionDenied),
    DescriptorBudget,
    Direct(DestinationConnectError),
    SocksConnect(io::Error),
    SocksTimeout,
    SocksProtocol(Socks5ProtocolError),
    NxrOutboundConfig,
    NxrConnect(io::Error),
    NxrTimeout,
    NxrClock,
    NxrRandom,
    NxrProtocol(NxrProtocolError),
    HandoffUnsupported,
}

impl fmt::Display for OutboundConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTag(_) => formatter.write_str("routing selected an unknown outbound tag"),
            Self::Admission(source) => source.fmt(formatter),
            Self::DescriptorBudget => {
                formatter.write_str("descriptor budget denied the outbound connection")
            }
            Self::Direct(source) => source.fmt(formatter),
            Self::SocksConnect(_) => formatter.write_str("failed to connect to SOCKS5 outbound"),
            Self::SocksTimeout => formatter.write_str("SOCKS5 outbound handshake timed out"),
            Self::SocksProtocol(source) => source.fmt(formatter),
            Self::NxrOutboundConfig => formatter.write_str("NXR outbound settings are invalid"),
            Self::NxrConnect(_) => formatter.write_str("failed to connect to NXR landing node"),
            Self::NxrTimeout => formatter.write_str("NXR outbound authentication timed out"),
            Self::NxrClock => formatter.write_str("system clock is before the Unix epoch"),
            Self::NxrRandom => formatter.write_str("NXR nonce generation failed"),
            Self::NxrProtocol(source) => source.fmt(formatter),
            Self::HandoffUnsupported => {
                formatter.write_str("handoff outbounds transfer sessions and cannot dial directly")
            }
        }
    }
}

impl Error for OutboundConnectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Admission(source) => Some(source),
            Self::Direct(source) => Some(source),
            Self::SocksConnect(source) => Some(source),
            Self::SocksProtocol(source) => Some(source),
            Self::NxrConnect(source) => Some(source),
            Self::NxrProtocol(source) => Some(source),
            Self::UnknownTag(_)
            | Self::DescriptorBudget
            | Self::SocksTimeout
            | Self::NxrOutboundConfig
            | Self::NxrTimeout
            | Self::NxrClock
            | Self::NxrRandom
            | Self::HandoffUnsupported => None,
        }
    }
}

fn map_direct_error(error: DestinationConnectError) -> OutboundConnectError {
    if matches!(error, DestinationConnectError::DescriptorBudget) {
        OutboundConnectError::DescriptorBudget
    } else {
        OutboundConnectError::Direct(error)
    }
}

fn map_socks_connect_error(error: DestinationConnectError) -> OutboundConnectError {
    match error {
        DestinationConnectError::DescriptorBudget => OutboundConnectError::DescriptorBudget,
        DestinationConnectError::TimedOut { .. } => OutboundConnectError::SocksTimeout,
        error => OutboundConnectError::SocksConnect(error.into_io()),
    }
}

fn map_nxr_connect_error(error: DestinationConnectError) -> OutboundConnectError {
    match error {
        DestinationConnectError::DescriptorBudget => OutboundConnectError::DescriptorBudget,
        DestinationConnectError::TimedOut { .. } => OutboundConnectError::NxrTimeout,
        error => OutboundConnectError::NxrConnect(error.into_io()),
    }
}

/// A SOCKS5 server returned invalid negotiation data or a failure reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Socks5ProtocolError {
    CredentialsTooLong,
    DomainTooLong,
    UnexpectedMethod { expected: u8, received: u8 },
    AuthenticationFailed(u8),
    ConnectFailed(u8),
    InvalidReply,
}

impl fmt::Display for Socks5ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CredentialsTooLong => formatter.write_str("SOCKS5 credentials exceed 255 bytes"),
            Self::DomainTooLong => formatter.write_str("SOCKS5 domain exceeds 255 bytes"),
            Self::UnexpectedMethod { .. } => {
                formatter.write_str("SOCKS5 server selected an unexpected authentication method")
            }
            Self::AuthenticationFailed(_) => {
                formatter.write_str("SOCKS5 username/password authentication failed")
            }
            Self::ConnectFailed(_) => formatter.write_str("SOCKS5 CONNECT request was rejected"),
            Self::InvalidReply => formatter.write_str("SOCKS5 server returned an invalid reply"),
        }
    }
}

impl Error for Socks5ProtocolError {}

async fn connect_nxr(
    settings: &CompiledNxr,
    destination: &Destination,
    timeout: Duration,
    connector: &DestinationConnector,
    fd_budget: &FdBudget,
) -> Result<PreparedConnection, OutboundConnectError> {
    if let Some(pool) = &settings.pool {
        if let Some(checkout) = pool.checkout() {
            let deadline = Instant::now()
                .checked_add(timeout)
                .ok_or(OutboundConnectError::NxrTimeout)?;
            let (connection, warm_permit) = checkout.into_parts();
            let (mut stream, fd_permit) = connection.into_parts();
            let request = fresh_nxr_request(settings, destination)?;
            match write_all_counted_before(&mut stream, &request, deadline).await {
                Ok(committed) => {
                    // The warm socket carried its own fresh request to
                    // completion, so it now owns this session.
                    committed.commit_transport_ownership();
                    return Ok(PreparedConnection {
                        connection: AccountedTcpStream::from_parts(stream, fd_permit),
                        warm_permit: Some(warm_permit),
                    });
                }
                Err(error) => {
                    // The error type proves no byte was authenticated, and the
                    // warm transport is the speculative attempt, so an alternate
                    // attempt remains.
                    debug_assert!(AttemptTransport::Warm.permits_alternate_attempt());
                    let _discarded = error.progress().bytes_discarded();
                    pool.record_stale_checkout();
                    // The immediate cold fallback below is the sole alternate
                    // attempt and constructs a fresh timestamp, nonce and HMAC.
                }
            }
        }
        pool.record_cold_fallback();
    }

    // Speculative transport failure cannot consume the required connection's
    // timeout budget. Retry count remains bounded, but every permitted attempt
    // receives the same normal per-attempt deadline as an ordinary cold dial.
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(OutboundConnectError::NxrTimeout)?;
    let connected = time::timeout_at(
        deadline,
        connector.connect_host_accounted(settings.address.as_ref(), settings.port, fd_budget),
    )
    .await
    .map_err(|_| OutboundConnectError::NxrTimeout)?
    .map_err(map_nxr_connect_error)?;
    let (mut stream, fd_permit) = connected.into_parts();
    let request = fresh_nxr_request(settings, destination)?;
    write_all_counted_before(&mut stream, &request, deadline)
        .await
        .map_err(|error| {
            let source = error.into_source();
            if source.kind() == io::ErrorKind::TimedOut {
                OutboundConnectError::NxrTimeout
            } else {
                OutboundConnectError::NxrConnect(source)
            }
        })?;
    Ok(PreparedConnection {
        connection: AccountedTcpStream::from_parts(stream, fd_permit),
        warm_permit: None,
    })
}

fn fresh_nxr_request(
    settings: &CompiledNxr,
    destination: &Destination,
) -> Result<Vec<u8>, OutboundConnectError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OutboundConnectError::NxrClock)?
        .as_secs();
    let mut nonce = [0_u8; 16];
    crate::crypto::entropy::fill(&mut nonce).map_err(|_| OutboundConnectError::NxrRandom)?;
    let mut request = Vec::new();
    encode_request(destination, timestamp, nonce, &settings.key, &mut request)
        .map_err(OutboundConnectError::NxrProtocol)?;
    Ok(request)
}

/// Builds one UDP-mode NXR open (ADR 0060 Option A).
fn fresh_nxr_udp_request(
    settings: &CompiledNxr,
    destination: &Destination,
    user_id: [u8; 16],
) -> Result<Vec<u8>, OutboundConnectError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OutboundConnectError::NxrClock)?
        .as_secs();
    let mut nonce = [0_u8; 16];
    crate::crypto::entropy::fill(&mut nonce).map_err(|_| OutboundConnectError::NxrRandom)?;
    let mut request = Vec::new();
    encode_udp_open(
        destination,
        user_id,
        timestamp,
        nonce,
        &settings.key,
        &mut request,
    )
    .map_err(|error| OutboundConnectError::NxrProtocol(NxrProtocolError::from(error)))?;
    Ok(request)
}

/// Dials an NXR landing and writes one authenticated UDP-mode open.
///
/// Returns the TCP carrier plus the session MAC key derived from the open
/// transcript (ADR 0060 Option A). Warm-pool sockets are TCP-open shaped and
/// must not be reused for UDP associations.
async fn dial_nxr_udp_carrier(
    settings: &CompiledNxr,
    destination: &Destination,
    user_id: [u8; 16],
    timeout: Duration,
    connector: &DestinationConnector,
    fd_budget: &FdBudget,
) -> Result<(PreparedConnection, NxrUdpSessionKey), OutboundConnectError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(OutboundConnectError::NxrTimeout)?;
    let connected = time::timeout_at(
        deadline,
        connector.connect_host_accounted(settings.address.as_ref(), settings.port, fd_budget),
    )
    .await
    .map_err(|_| OutboundConnectError::NxrTimeout)?
    .map_err(map_nxr_connect_error)?;
    let (mut stream, fd_permit) = connected.into_parts();
    let request = fresh_nxr_udp_request(settings, destination, user_id)?;
    let prefix = open_authenticated_prefix(&request).ok_or_else(|| {
        OutboundConnectError::NxrProtocol(NxrProtocolError::from(
            crate::protocol::nxr_udp::NxrUdpError::Length,
        ))
    })?;
    let session = NxrUdpSessionKey::derive(&settings.key, prefix);
    write_all_counted_before(&mut stream, &request, deadline)
        .await
        .map_err(|error| {
            let source = error.into_source();
            if source.kind() == io::ErrorKind::TimedOut {
                OutboundConnectError::NxrTimeout
            } else {
                OutboundConnectError::NxrConnect(source)
            }
        })?;
    Ok((
        PreparedConnection {
            connection: AccountedTcpStream::from_parts(stream, fd_permit),
            warm_permit: None,
        },
        session,
    ))
}

async fn connect_socks5(
    settings: &CompiledSocks5,
    destination: &Destination,
    timeout: Duration,
    connector: &DestinationConnector,
    fd_budget: &FdBudget,
) -> Result<PreparedConnection, OutboundConnectError> {
    if let Some(pool) = &settings.pool {
        for _attempt in 0..2 {
            let Some(checkout) = pool.checkout() else {
                break;
            };
            let deadline = Instant::now()
                .checked_add(timeout)
                .ok_or(OutboundConnectError::SocksTimeout)?;
            let (connection, warm_permit) = checkout.into_parts();
            let (mut stream, fd_permit) = connection.into_parts();
            match negotiate_socks5_retryable(&mut stream, settings, destination, deadline).await {
                Ok(()) => {
                    return Ok(PreparedConnection {
                        connection: AccountedTcpStream::from_parts(stream, fd_permit),
                        warm_permit: Some(warm_permit),
                    });
                }
                Err((error, true)) => {
                    pool.record_stale_checkout();
                    let _unused = error;
                }
                Err((error, false)) => return Err(error),
            }
        }
        pool.record_cold_fallback();
    }

    // A third-party SOCKS server may deliberately expire or stall an idle
    // preconnected socket. Preserve the normal cold path by giving it a fresh
    // deadline after the bounded READY-socket attempts.
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(OutboundConnectError::SocksTimeout)?;
    let connected = time::timeout_at(
        deadline,
        connector.connect_host_accounted(settings.address.as_ref(), settings.port, fd_budget),
    )
    .await
    .map_err(|_| OutboundConnectError::SocksTimeout)?
    .map_err(map_socks_connect_error)?;
    let (mut stream, fd_permit) = connected.into_parts();

    negotiate_socks5(&mut stream, settings, destination, deadline).await?;
    Ok(PreparedConnection {
        connection: AccountedTcpStream::from_parts(stream, fd_permit),
        warm_permit: None,
    })
}

struct PreparedConnection {
    connection: AccountedTcpStream,
    warm_permit: Option<WarmUsePermit>,
}

impl PreparedConnection {
    fn into_parts(self) -> (AccountedTcpStream, Option<WarmUsePermit>) {
        (self.connection, self.warm_permit)
    }
}

async fn negotiate_socks5(
    stream: &mut TcpStream,
    settings: &CompiledSocks5,
    destination: &Destination,
    deadline: Instant,
) -> Result<(), OutboundConnectError> {
    negotiate_socks5_retryable(stream, settings, destination, deadline)
        .await
        .map_err(|(error, _retryable)| error)
}

/// Returns whether an error occurred before SOCKS CONNECT began and is
/// therefore safe to repeat on one fresh transport. Protocol rejection is
/// never retryable.
async fn negotiate_socks5_retryable(
    stream: &mut TcpStream,
    settings: &CompiledSocks5,
    destination: &Destination,
    deadline: Instant,
) -> Result<(), (OutboundConnectError, bool)> {
    let method = if settings.credentials.is_some() {
        SOCKS_USERNAME_PASSWORD
    } else {
        SOCKS_NO_AUTH
    };
    write_before(stream, &[SOCKS_VERSION, 1, method], deadline)
        .await
        .map_err(|error| (error, true))?;
    let mut method_reply = [0_u8; 2];
    read_before(stream, &mut method_reply, deadline)
        .await
        .map_err(|error| (error, true))?;
    if method_reply[0] != SOCKS_VERSION || method_reply[1] != method {
        return Err((
            OutboundConnectError::SocksProtocol(Socks5ProtocolError::UnexpectedMethod {
                expected: method,
                received: method_reply[1],
            }),
            false,
        ));
    }
    if method_reply[1] == SOCKS_NO_ACCEPTABLE_METHODS {
        return Err((
            OutboundConnectError::SocksProtocol(Socks5ProtocolError::UnexpectedMethod {
                expected: method,
                received: method_reply[1],
            }),
            false,
        ));
    }

    if let Some(credentials) = &settings.credentials {
        authenticate_socks5(stream, credentials, deadline)
            .await
            .map_err(|error| {
                let retryable = matches!(
                    error,
                    OutboundConnectError::SocksConnect(_) | OutboundConnectError::SocksTimeout
                );
                (error, retryable)
            })?;
    }
    // Beginning CONNECT is the side-effect cutoff for arbitrary third-party
    // SOCKS servers. Every failure from here is final for this logical flow.
    write_connect_request(stream, destination, deadline)
        .await
        .map_err(|error| (error, false))?;
    read_connect_reply(stream, deadline)
        .await
        .map_err(|error| (error, false))
}

async fn authenticate_socks5(
    stream: &mut TcpStream,
    credentials: &Socks5Credentials,
    deadline: Instant,
) -> Result<(), OutboundConnectError> {
    let username = credentials.username.as_bytes();
    let password = credentials.password.as_bytes();
    let username_length = u8::try_from(username.len()).map_err(|_| {
        OutboundConnectError::SocksProtocol(Socks5ProtocolError::CredentialsTooLong)
    })?;
    let password_length = u8::try_from(password.len()).map_err(|_| {
        OutboundConnectError::SocksProtocol(Socks5ProtocolError::CredentialsTooLong)
    })?;
    let mut request = Zeroizing::new(Vec::new());
    request
        .try_reserve(3 + username.len() + password.len())
        .map_err(|_| {
            OutboundConnectError::SocksProtocol(Socks5ProtocolError::CredentialsTooLong)
        })?;
    request.extend_from_slice(&[SOCKS_AUTH_VERSION, username_length]);
    request.extend_from_slice(username);
    request.push(password_length);
    request.extend_from_slice(password);
    write_before(stream, &request, deadline).await?;

    let mut reply = [0_u8; 2];
    read_before(stream, &mut reply, deadline).await?;
    if reply[0] != SOCKS_AUTH_VERSION || reply[1] != 0 {
        return Err(OutboundConnectError::SocksProtocol(
            Socks5ProtocolError::AuthenticationFailed(reply[1]),
        ));
    }
    Ok(())
}

async fn write_connect_request(
    stream: &mut TcpStream,
    destination: &Destination,
    deadline: Instant,
) -> Result<(), OutboundConnectError> {
    let mut request = Vec::with_capacity(4 + 1 + 255 + 2);
    request.extend_from_slice(&[SOCKS_VERSION, SOCKS_CONNECT, 0]);
    match destination.address() {
        Address::Ipv4(address) => {
            request.push(1);
            request.extend_from_slice(&address.octets());
        }
        Address::Domain(domain) => {
            let length = u8::try_from(domain.len()).map_err(|_| {
                OutboundConnectError::SocksProtocol(Socks5ProtocolError::DomainTooLong)
            })?;
            request.extend_from_slice(&[3, length]);
            request.extend_from_slice(domain.as_bytes());
        }
        Address::Ipv6(address) => {
            request.push(4);
            request.extend_from_slice(&address.octets());
        }
    }
    request.extend_from_slice(&destination.port().to_be_bytes());
    write_before(stream, &request, deadline).await
}

async fn read_connect_reply(
    stream: &mut TcpStream,
    deadline: Instant,
) -> Result<(), OutboundConnectError> {
    let mut header = [0_u8; 4];
    read_before(stream, &mut header, deadline).await?;
    if header[0] != SOCKS_VERSION || header[2] != 0 {
        return Err(OutboundConnectError::SocksProtocol(
            Socks5ProtocolError::InvalidReply,
        ));
    }
    if header[1] != 0 {
        return Err(OutboundConnectError::SocksProtocol(
            Socks5ProtocolError::ConnectFailed(header[1]),
        ));
    }
    match header[3] {
        1 => consume_reply_address(stream, 4, deadline).await?,
        3 => {
            let mut length = [0_u8; 1];
            read_before(stream, &mut length, deadline).await?;
            consume_reply_address(stream, usize::from(length[0]), deadline).await?;
        }
        4 => consume_reply_address(stream, 16, deadline).await?,
        _ => {
            return Err(OutboundConnectError::SocksProtocol(
                Socks5ProtocolError::InvalidReply,
            ));
        }
    }
    let mut port = [0_u8; 2];
    read_before(stream, &mut port, deadline).await
}

async fn consume_reply_address(
    stream: &mut TcpStream,
    length: usize,
    deadline: Instant,
) -> Result<(), OutboundConnectError> {
    let mut address = [0_u8; 255];
    read_before(stream, &mut address[..length], deadline).await
}

async fn write_before(
    stream: &mut TcpStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), OutboundConnectError> {
    time::timeout_at(deadline, stream.write_all(bytes))
        .await
        .map_err(|_| OutboundConnectError::SocksTimeout)?
        .map_err(OutboundConnectError::SocksConnect)
}

async fn read_before(
    stream: &mut TcpStream,
    bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), OutboundConnectError> {
    time::timeout_at(deadline, stream.read_exact(bytes))
        .await
        .map_err(|_| OutboundConnectError::SocksTimeout)?
        .map(|_| ())
        .map_err(OutboundConnectError::SocksConnect)
}

#[cfg(test)]
mod tests;
