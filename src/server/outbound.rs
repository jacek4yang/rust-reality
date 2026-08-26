use std::{
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
    config::{
        DirectBarrierConfig, NetworkConfig, NxrSettings, OutboundConfig, Socks5Settings,
        WarmConnectionPolicy,
    },
    network::NetworkEnvironment,
    protocol::{
        nxr::{NxrKey, NxrProtocolError, encode_request},
        vless::{Address, Destination},
    },
    runtime::{AdmissionDenied, DirectBarrier, FdBudget, FdPermit},
};
use rr_session::WriteProgress;

use super::{
    connector::{AccountedTcpStream, DestinationConnectError, DestinationConnector},
    counted_write::write_all_counted_before,
    handoff::HandoffLine,
    warm_pool::{AdaptiveTcpPool, WarmPoolAuthority, WarmPoolSnapshot, WarmUsePermit},
};

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

impl OutboundIndex {
    fn from_config(
        outbounds: &[OutboundConfig],
        connector: &DestinationConnector,
        fd_budget: &FdBudget,
        warm: Option<&WarmBuildContext<'_>>,
    ) -> Self {
        let mut entries = outbounds
            .iter()
            .map(|outbound| {
                (
                    Box::<str>::from(outbound.tag()),
                    CompiledOutbound::from_config(outbound, connector, fd_budget, warm),
                )
            })
            .collect::<Vec<_>>();
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
        outbounds: &[OutboundConfig],
        direct_barrier: &DirectBarrierConfig,
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
        outbounds: &[OutboundConfig],
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
        outbounds: &[OutboundConfig],
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
            network.clone(),
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
        outbounds: &[OutboundConfig],
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
            network.clone(),
            environment,
            Some(&warm),
        )
    }

    fn build(
        outbounds: &[OutboundConfig],
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
            CompiledOutbound::Blackhole { delay } => {
                if !delay.is_zero() {
                    time::sleep(*delay).await;
                }
                Ok(OutboundConnectOutcome::Blackholed)
            }
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
            CompiledOutbound::Nxr(None) => Err(OutboundConnectError::NxrSettings),
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
    Blackhole { delay: Duration },
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
            OutboundConfig::Direct { .. } => Self::Direct,
            OutboundConfig::Blackhole { settings, .. } => Self::Blackhole {
                delay: Duration::from_millis(settings.response_delay_ms),
            },
            OutboundConfig::Socks5 { settings, .. } => {
                Self::Socks5(CompiledSocks5::new(settings, connector, fd_budget, warm))
            }
            OutboundConfig::Nxr { settings, .. } => {
                Self::Nxr(CompiledNxr::new(settings, connector, fd_budget, warm))
            }
            OutboundConfig::Handoff { settings, .. } => {
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
            Self::Direct | Self::Blackhole { .. } | Self::Nxr(None) | Self::Handoff(None) => None,
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
            Self::Socks5(_) => "socks5",
            Self::Nxr(Some(_)) => "nxr",
            Self::Handoff(Some(_)) => "handoff",
            Self::Direct | Self::Blackhole { .. } | Self::Nxr(None) | Self::Handoff(None) => {
                return None;
            }
        };
        self.warm_pool().map(|pool| OutboundWarmPoolSnapshot {
            transport,
            pool: pool.snapshot(),
        })
    }
}

pub(crate) struct OutboundWarmPoolSnapshot {
    pub(crate) transport: &'static str,
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
        settings: &Socks5Settings,
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
            pool: settings.warm_tcp.then_some(warm).flatten().map(|warm| {
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
        settings: &NxrSettings,
        connector: &DestinationConnector,
        fd_budget: &FdBudget,
        warm: Option<&WarmBuildContext<'_>>,
    ) -> Option<Self> {
        let decoded = Zeroizing::new(
            BASE64_URL_SAFE_NO_PAD
                .decode(settings.pre_shared_key.expose())
                .ok()?,
        );
        let key: [u8; 32] = decoded.as_slice().try_into().ok()?;
        Some(Self {
            address: Arc::from(settings.address.as_str()),
            port: settings.port,
            key: NxrKey::new(key),
            pool: settings.warm_tcp.then_some(warm).flatten().map(|warm| {
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
    Blackholed,
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
    NxrSettings,
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
            Self::NxrSettings => formatter.write_str("NXR outbound settings are invalid"),
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
            | Self::NxrSettings
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
                Ok(WriteProgress::CompleteWrite) => {
                    return Ok(PreparedConnection {
                        connection: AccountedTcpStream::from_parts(stream, fd_permit),
                        warm_permit: Some(warm_permit),
                    });
                }
                Ok(WriteProgress::NoBytesWritten | WriteProgress::PartialWrite { .. }) => {
                    unreachable!("counted write reports incomplete progress only as an error")
                }
                Err(error) => {
                    match error.progress() {
                        WriteProgress::NoBytesWritten | WriteProgress::PartialWrite { .. } => {}
                        WriteProgress::CompleteWrite => {
                            unreachable!("a complete write cannot be a retryable error")
                        }
                    }
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
    getrandom::fill(&mut nonce).map_err(|_| OutboundConnectError::NxrRandom)?;
    let mut request = Vec::new();
    encode_request(destination, timestamp, nonce, &settings.key, &mut request)
        .map_err(OutboundConnectError::NxrProtocol)?;
    Ok(request)
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
mod tests {
    use std::{
        io,
        net::{Ipv4Addr, Ipv6Addr},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::mpsc,
    };

    use super::{
        OutboundConnectError, OutboundConnectOutcome, OutboundIndex, OutboundRegistry,
        SOCKS_CONNECT, SOCKS_NO_AUTH, SOCKS_USERNAME_PASSWORD, SOCKS_VERSION,
        SORTED_OUTBOUND_LIMIT, Socks5ProtocolError,
    };
    use crate::{
        config::{
            DirectBarrierConfig, NetworkConfig, NxrSettings, OutboundConfig, SecretString,
            Socks5Settings, WarmConnectionPolicy,
        },
        network::NetworkEnvironment,
        protocol::{
            nxr::{
                NxrKey, REQUEST_HEADER_LEN, decode_authenticated_request, request_len_from_header,
            },
            vless::{Address, Destination},
        },
        runtime::{AdmissionDenied, DirectBarrier, FdBudget, PressureGauge, ResourcePressure},
        server::warm_pool::WarmPoolAuthority,
    };

    #[test]
    fn outbound_index_uses_the_measured_cardinality_boundary() {
        let configs = (0..=SORTED_OUTBOUND_LIMIT)
            .map(|index| OutboundConfig::Direct {
                tag: format!("direct-{index}"),
            })
            .collect::<Vec<_>>();
        let connector = super::DestinationConnector::new(Duration::from_secs(1));
        let fd_budget = FdBudget::new(4_096);
        let small = OutboundIndex::from_config(
            &configs[..SORTED_OUTBOUND_LIMIT],
            &connector,
            &fd_budget,
            None,
        );
        assert!(matches!(small, OutboundIndex::Sorted(_)));
        assert!(small.contains("direct-2"));
        assert!(!small.contains("missing"));

        let large = OutboundIndex::from_config(&configs, &connector, &fd_budget, None);
        assert!(matches!(large, OutboundIndex::Hashed(_)));
        assert!(large.contains("direct-4"));
    }

    fn direct_registry(barrier: &DirectBarrier, connect_timeout: Duration) -> OutboundRegistry {
        OutboundRegistry::with_barrier(
            &[OutboundConfig::Direct {
                tag: "direct".to_owned(),
            }],
            barrier.clone(),
            connect_timeout,
            crate::runtime::FdBudget::new(4_096),
        )
    }

    fn warm_policy() -> WarmConnectionPolicy {
        WarmConnectionPolicy {
            min_ready: 1,
            max_ready: 4,
            max_connecting: 1,
            refill_batch: 1,
            idle_timeout_ms: 30_000,
            max_lifetime_ms: 60_000,
            shrink_delay_ms: 30_000,
        }
    }

    async fn wait_for_one_ready(registry: &OutboundRegistry) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if registry
                    .warm_pool_snapshots()
                    .first()
                    .is_some_and(|snapshot| snapshot.pool.ready == 1)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("warm pool must become ready");
    }

    async fn serve_one_no_auth_socks_connect(listener: &TcpListener) -> io::Result<()> {
        for _ in 0..4 {
            let (mut stream, _) = listener.accept().await?;
            let mut greeting = [0_u8; 3];
            match tokio::time::timeout(Duration::from_millis(100), stream.read_exact(&mut greeting))
                .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => return Err(error),
                Err(_) => continue,
            }
            if greeting != [SOCKS_VERSION, 1, SOCKS_NO_AUTH] {
                return Err(io::Error::other("unexpected SOCKS greeting"));
            }
            stream.write_all(&[SOCKS_VERSION, SOCKS_NO_AUTH]).await?;
            let mut request = [0_u8; 10];
            stream.read_exact(&mut request).await?;
            if request[..4] != [SOCKS_VERSION, SOCKS_CONNECT, 0, 1] {
                return Err(io::Error::other("unexpected SOCKS CONNECT request"));
            }
            stream
                .write_all(&[SOCKS_VERSION, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await?;
            return Ok(());
        }
        Err(io::Error::other(
            "SOCKS protocol did not begin on a bounded candidate",
        ))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn warm_nxr_sends_no_protocol_bytes_before_checkout_and_uses_fresh_nonce() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("NXR landing must bind");
        let address = listener.local_addr().expect("NXR landing address");
        let key_bytes = [0x62; 32];
        let key = NxrKey::new(key_bytes);
        let (accepted_tx, mut accepted_rx) = mpsc::channel(2);
        let server = tokio::spawn(async move {
            let mut nonces = Vec::new();
            for expected_payload in [b"one".as_slice(), b"two".as_slice()] {
                let (mut stream, _) = listener.accept().await?;
                let mut probe = [0_u8; 1];
                assert!(
                    matches!(stream.try_read(&mut probe), Err(ref error) if error.kind() == io::ErrorKind::WouldBlock)
                );
                accepted_tx.send(()).await.map_err(io::Error::other)?;
                let mut header = [0_u8; REQUEST_HEADER_LEN];
                stream.read_exact(&mut header).await?;
                let total = request_len_from_header(&header).map_err(io::Error::other)?;
                let mut request = vec![0_u8; total];
                request[..REQUEST_HEADER_LEN].copy_from_slice(&header);
                stream
                    .read_exact(&mut request[REQUEST_HEADER_LEN..])
                    .await?;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(io::Error::other)?
                    .as_secs();
                let authenticated = decode_authenticated_request(&request, &key, now, 30)
                    .map_err(io::Error::other)?;
                nonces.push(*authenticated.nonce());
                let mut payload = vec![0_u8; expected_payload.len()];
                stream.read_exact(&mut payload).await?;
                assert_eq!(payload, expected_payload);
            }
            Ok::<_, io::Error>(nonces)
        });

        let policy = warm_policy();
        let pressure = PressureGauge::new();
        let fd_budget = FdBudget::new(4_096);
        let registry = OutboundRegistry::with_warm_pools(
            &[OutboundConfig::Nxr {
                tag: "nxr".to_owned(),
                settings: NxrSettings {
                    address: address.ip().to_string(),
                    port: address.port(),
                    pre_shared_key: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(key_bytes)),
                    warm_tcp: true,
                },
            }],
            DirectBarrier::new(&DirectBarrierConfig::default()),
            Duration::from_secs(2),
            fd_budget,
            &NetworkConfig::default(),
            NetworkEnvironment::detect(),
            7,
            WarmPoolAuthority::new(&policy, 1, pressure),
            &policy,
        );
        registry.activate_warm_pools();
        let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);
        for payload in [b"one".as_slice(), b"two".as_slice()] {
            accepted_rx
                .recv()
                .await
                .expect("warm dial must reach landing");
            wait_for_one_ready(&registry).await;
            let OutboundConnectOutcome::Connected(connection) = registry
                .connect("nxr", &destination)
                .await
                .expect("warm NXR checkout must connect")
            else {
                panic!("NXR cannot blackhole");
            };
            let (mut stream, permit) = connection.into_parts();
            stream.write_all(payload).await.expect("raw payload");
            drop(stream);
            drop(permit);
        }
        registry.deactivate_warm_pools();
        let nonces = server
            .await
            .expect("server must join")
            .expect("server result");
        assert_ne!(nonces[0], nonces[1], "every warm flow needs a fresh nonce");
        let snapshot = registry.warm_pool_snapshots().remove(0).pool;
        assert_eq!(snapshot.checkout_hit, 2);
        assert_eq!(snapshot.cold_fallback, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stale_warm_nxr_socket_is_discarded_before_cold_fallback() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("NXR landing must bind");
        let address = listener.local_addr().expect("NXR landing address");
        let key_bytes = [0x63; 32];
        let policy = warm_policy();
        let registry = OutboundRegistry::with_warm_pools(
            &[OutboundConfig::Nxr {
                tag: "nxr".to_owned(),
                settings: NxrSettings {
                    address: address.ip().to_string(),
                    port: address.port(),
                    pre_shared_key: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(key_bytes)),
                    warm_tcp: true,
                },
            }],
            DirectBarrier::new(&DirectBarrierConfig::default()),
            Duration::from_secs(2),
            FdBudget::new(4_096),
            &NetworkConfig::default(),
            NetworkEnvironment::detect(),
            8,
            WarmPoolAuthority::new(&policy, 1, PressureGauge::new()),
            &policy,
        );
        registry.activate_warm_pools();
        let (mut stale_peer, _) = listener.accept().await.expect("warm peer must connect");
        wait_for_one_ready(&registry).await;
        stale_peer
            .shutdown()
            .await
            .expect("peer FIN must be observable");
        drop(stale_peer);
        tokio::time::sleep(Duration::from_millis(10)).await;

        let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);
        let OutboundConnectOutcome::Connected(connection) = registry
            .connect("nxr", &destination)
            .await
            .expect("cold fallback must submit a fresh authenticated request")
        else {
            panic!("NXR cannot blackhole");
        };
        drop(connection);
        let snapshot = registry.warm_pool_snapshots().remove(0).pool;
        assert_eq!(snapshot.checkout_hit, 0);
        assert_eq!(snapshot.checkout_miss, 1);
        assert_eq!(snapshot.cold_fallback, 1);
        assert_eq!(snapshot.stale_discard, 1);
        registry.deactivate_warm_pools();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn warm_socks5_stays_protocol_unprivileged_until_checkout() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("SOCKS server must bind");
        let address = listener.local_addr().expect("SOCKS address");
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut probe = [0_u8; 1];
            assert!(
                matches!(stream.try_read(&mut probe), Err(ref error) if error.kind() == io::ErrorKind::WouldBlock)
            );
            accepted_tx
                .send(())
                .map_err(|()| io::Error::other("receiver closed"))?;
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await?;
            assert_eq!(greeting, [SOCKS_VERSION, 1, SOCKS_NO_AUTH]);
            stream.write_all(&[SOCKS_VERSION, SOCKS_NO_AUTH]).await?;
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await?;
            assert_eq!(request, [SOCKS_VERSION, SOCKS_CONNECT, 0, 3]);
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await?;
            let mut domain = vec![0_u8; usize::from(length[0])];
            stream.read_exact(&mut domain).await?;
            assert_eq!(domain, b"example.com");
            let mut port = [0_u8; 2];
            stream.read_exact(&mut port).await?;
            assert_eq!(u16::from_be_bytes(port), 443);
            stream
                .write_all(&[SOCKS_VERSION, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await?;
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await?;
            assert_eq!(&payload, b"data");
            Ok::<_, io::Error>(())
        });

        let policy = warm_policy();
        let pressure = PressureGauge::new();
        let registry = OutboundRegistry::with_warm_pools(
            &[OutboundConfig::Socks5 {
                tag: "socks".to_owned(),
                settings: Socks5Settings {
                    address: address.ip().to_string(),
                    port: address.port(),
                    username: None,
                    password: None,
                    warm_tcp: true,
                },
            }],
            DirectBarrier::new(&DirectBarrierConfig::default()),
            Duration::from_secs(2),
            FdBudget::new(4_096),
            &NetworkConfig::default(),
            NetworkEnvironment::detect(),
            9,
            WarmPoolAuthority::new(&policy, 1, pressure),
            &policy,
        );
        registry.activate_warm_pools();
        accepted_rx.await.expect("warm TCP must reach SOCKS server");
        wait_for_one_ready(&registry).await;
        let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);
        let OutboundConnectOutcome::Connected(connection) = registry
            .connect("socks", &destination)
            .await
            .expect("warm SOCKS checkout must negotiate")
        else {
            panic!("SOCKS cannot blackhole");
        };
        let (mut stream, permit) = connection.into_parts();
        stream.write_all(b"data").await.expect("relay payload");
        drop(stream);
        drop(permit);
        registry.deactivate_warm_pools();
        server
            .await
            .expect("server must join")
            .expect("server result");
        let snapshot = registry.warm_pool_snapshots().remove(0).pool;
        assert_eq!(snapshot.checkout_hit, 1);
        assert_eq!(snapshot.cold_fallback, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn socks5_upstream_close_while_ready_discards_then_cold_falls_back() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("SOCKS server must bind");
        let address = listener.local_addr().expect("SOCKS address");
        let policy = warm_policy();
        let registry = OutboundRegistry::with_warm_pools(
            &[OutboundConfig::Socks5 {
                tag: "socks".to_owned(),
                settings: Socks5Settings {
                    address: address.ip().to_string(),
                    port: address.port(),
                    username: None,
                    password: None,
                    warm_tcp: true,
                },
            }],
            DirectBarrier::new(&DirectBarrierConfig::default()),
            Duration::from_secs(2),
            FdBudget::new(4_096),
            &NetworkConfig::default(),
            NetworkEnvironment::detect(),
            11,
            WarmPoolAuthority::new(&policy, 1, PressureGauge::new()),
            &policy,
        );
        registry.activate_warm_pools();
        let (mut stale_peer, _) = listener.accept().await.expect("warm peer must connect");
        wait_for_one_ready(&registry).await;
        stale_peer
            .shutdown()
            .await
            .expect("peer FIN must be observable");
        drop(stale_peer);
        tokio::time::sleep(Duration::from_millis(10)).await;
        let server = tokio::spawn(async move { serve_one_no_auth_socks_connect(&listener).await });

        let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 443);
        let OutboundConnectOutcome::Connected(connection) = registry
            .connect("socks", &destination)
            .await
            .expect("cold SOCKS fallback must negotiate")
        else {
            panic!("SOCKS cannot blackhole");
        };
        drop(connection);
        let snapshot = registry.warm_pool_snapshots().remove(0).pool;
        assert_eq!(snapshot.checkout_hit, 0);
        assert_eq!(snapshot.checkout_miss, 1);
        assert_eq!(snapshot.cold_fallback, 1);
        assert_eq!(snapshot.stale_discard, 1);
        registry.deactivate_warm_pools();
        server
            .await
            .expect("SOCKS server must join")
            .expect("SOCKS server result");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn socks5_upstream_close_immediately_after_checkout_recovers_before_connect() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("SOCKS server must bind");
        let address = listener.local_addr().expect("SOCKS address");
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut checked_out, _) = listener.accept().await?;
            accepted_tx
                .send(())
                .map_err(|()| io::Error::other("receiver closed"))?;
            let mut greeting = [0_u8; 3];
            checked_out.read_exact(&mut greeting).await?;
            assert_eq!(greeting, [SOCKS_VERSION, 1, SOCKS_NO_AUTH]);
            drop(checked_out);
            serve_one_no_auth_socks_connect(&listener).await
        });
        let policy = warm_policy();
        let registry = OutboundRegistry::with_warm_pools(
            &[OutboundConfig::Socks5 {
                tag: "socks".to_owned(),
                settings: Socks5Settings {
                    address: address.ip().to_string(),
                    port: address.port(),
                    username: None,
                    password: None,
                    warm_tcp: true,
                },
            }],
            DirectBarrier::new(&DirectBarrierConfig::default()),
            Duration::from_secs(2),
            FdBudget::new(4_096),
            &NetworkConfig::default(),
            NetworkEnvironment::detect(),
            12,
            WarmPoolAuthority::new(&policy, 1, PressureGauge::new()),
            &policy,
        );
        registry.activate_warm_pools();
        accepted_rx.await.expect("warm TCP must reach SOCKS server");
        wait_for_one_ready(&registry).await;

        let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 443);
        let OutboundConnectOutcome::Connected(connection) = registry
            .connect("socks", &destination)
            .await
            .expect("bounded pre-CONNECT retry must recover")
        else {
            panic!("SOCKS cannot blackhole");
        };
        drop(connection);
        let snapshot = registry.warm_pool_snapshots().remove(0).pool;
        assert!(snapshot.checkout_hit >= 1);
        assert_eq!(snapshot.stale_discard, 1);
        assert!(snapshot.checkout_total <= 2);
        assert!(snapshot.cold_fallback <= 1);
        registry.deactivate_warm_pools();
        server
            .await
            .expect("SOCKS server must join")
            .expect("SOCKS server result");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stalled_warm_socks_attempt_does_not_consume_retry_deadline() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("SOCKS server must bind");
        let address = listener.local_addr().expect("SOCKS address");
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stalled, _) = listener.accept().await?;
            accepted_tx
                .send(())
                .map_err(|()| io::Error::other("receiver closed"))?;
            let mut greeting = [0_u8; 3];
            stalled.read_exact(&mut greeting).await?;
            assert_eq!(greeting, [SOCKS_VERSION, 1, SOCKS_NO_AUTH]);

            // Keep the checked-out socket open without replying until its
            // per-attempt deadline fires. Refill may establish the one bounded
            // alternate in the listener backlog meanwhile.
            serve_one_no_auth_socks_connect(&listener).await?;
            drop(stalled);
            Ok::<_, io::Error>(())
        });
        let policy = warm_policy();
        let registry = OutboundRegistry::with_warm_pools(
            &[OutboundConfig::Socks5 {
                tag: "socks".to_owned(),
                settings: Socks5Settings {
                    address: address.ip().to_string(),
                    port: address.port(),
                    username: None,
                    password: None,
                    warm_tcp: true,
                },
            }],
            DirectBarrier::new(&DirectBarrierConfig::default()),
            Duration::from_millis(25),
            FdBudget::new(4_096),
            &NetworkConfig::default(),
            NetworkEnvironment::detect(),
            13,
            WarmPoolAuthority::new(&policy, 1, PressureGauge::new()),
            &policy,
        );
        registry.activate_warm_pools();
        accepted_rx.await.expect("warm TCP must reach SOCKS server");
        wait_for_one_ready(&registry).await;

        let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 443);
        let OutboundConnectOutcome::Connected(connection) = registry
            .connect("socks", &destination)
            .await
            .expect("bounded alternate must receive a fresh deadline")
        else {
            panic!("SOCKS cannot blackhole");
        };
        drop(connection);
        let snapshot = registry.warm_pool_snapshots().remove(0).pool;
        assert_eq!(snapshot.stale_discard, 1);
        assert!(snapshot.checkout_total <= 2);
        registry.deactivate_warm_pools();
        server
            .await
            .expect("SOCKS server must join")
            .expect("SOCKS server result");
    }

    #[tokio::test]
    async fn socks5_connect_encodes_ipv4_ipv6_and_domain_destinations() {
        let destinations = [
            (
                Destination::new(Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)), 443),
                vec![SOCKS_VERSION, SOCKS_CONNECT, 0, 1, 192, 0, 2, 1, 1, 187],
            ),
            (
                Destination::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 53),
                [
                    vec![SOCKS_VERSION, SOCKS_CONNECT, 0, 4],
                    vec![0; 15],
                    vec![1, 0, 53],
                ]
                .concat(),
            ),
            (
                Destination::new(Address::Domain("example.com".to_owned()), 80),
                [
                    vec![SOCKS_VERSION, SOCKS_CONNECT, 0, 3, 11],
                    b"example.com".to_vec(),
                    vec![0, 80],
                ]
                .concat(),
            ),
        ];
        for (destination, expected) in destinations {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("test listener must bind");
            let address = listener.local_addr().expect("test listener address");
            let writer = tokio::net::TcpStream::connect(address);
            let reader = listener.accept();
            let (writer, reader) = tokio::join!(writer, reader);
            let mut writer = writer.expect("writer must connect");
            let (mut reader, _) = reader.expect("reader must accept");
            super::write_connect_request(
                &mut writer,
                &destination,
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
            .expect("SOCKS CONNECT must encode");
            let mut actual = vec![0_u8; expected.len()];
            reader.read_exact(&mut actual).await.expect("encoded bytes");
            assert_eq!(actual, expected);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn warm_socks5_credentials_are_isolated_between_outbound_pools() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("SOCKS server must bind");
        let address = listener.local_addr().expect("SOCKS address");
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut streams = Vec::new();
            for _ in 0..2 {
                streams.push(listener.accept().await?.0);
            }
            accepted_tx
                .send(())
                .map_err(|()| io::Error::other("receiver closed"))?;
            let mut credentials = Vec::new();
            for mut stream in streams {
                let mut greeting = [0_u8; 3];
                stream.read_exact(&mut greeting).await?;
                assert_eq!(greeting, [SOCKS_VERSION, 1, SOCKS_USERNAME_PASSWORD]);
                stream
                    .write_all(&[SOCKS_VERSION, SOCKS_USERNAME_PASSWORD])
                    .await?;

                let mut auth_header = [0_u8; 2];
                stream.read_exact(&mut auth_header).await?;
                assert_eq!(auth_header[0], 1);
                let mut username = vec![0_u8; usize::from(auth_header[1])];
                stream.read_exact(&mut username).await?;
                let mut password_length = [0_u8; 1];
                stream.read_exact(&mut password_length).await?;
                let mut password = vec![0_u8; usize::from(password_length[0])];
                stream.read_exact(&mut password).await?;
                credentials.push((username, password));
                stream.write_all(&[1, 0]).await?;

                let mut connect = [0_u8; 4];
                stream.read_exact(&mut connect).await?;
                assert_eq!(connect, [SOCKS_VERSION, SOCKS_CONNECT, 0, 1]);
                let mut destination = [0_u8; 6];
                stream.read_exact(&mut destination).await?;
                stream
                    .write_all(&[SOCKS_VERSION, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                    .await?;
            }
            credentials.sort();
            Ok::<_, io::Error>(credentials)
        });

        let policy = warm_policy();
        let registry = OutboundRegistry::with_warm_pools(
            &[
                OutboundConfig::Socks5 {
                    tag: "socks-a".to_owned(),
                    settings: Socks5Settings {
                        address: address.ip().to_string(),
                        port: address.port(),
                        username: Some(SecretString::new("alice".to_owned())),
                        password: Some(SecretString::new("alpha".to_owned())),
                        warm_tcp: true,
                    },
                },
                OutboundConfig::Socks5 {
                    tag: "socks-b".to_owned(),
                    settings: Socks5Settings {
                        address: address.ip().to_string(),
                        port: address.port(),
                        username: Some(SecretString::new("bob".to_owned())),
                        password: Some(SecretString::new("bravo".to_owned())),
                        warm_tcp: true,
                    },
                },
            ],
            DirectBarrier::new(&DirectBarrierConfig::default()),
            Duration::from_secs(2),
            FdBudget::new(4_096),
            &NetworkConfig::default(),
            NetworkEnvironment::detect(),
            10,
            WarmPoolAuthority::new(&policy, 2, PressureGauge::new()),
            &policy,
        );
        registry.activate_warm_pools();
        accepted_rx.await.expect("both warm sockets must connect");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if registry
                    .warm_pool_snapshots()
                    .iter()
                    .all(|snapshot| snapshot.pool.ready == 1)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both pools must become ready");

        let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 443);
        for tag in ["socks-a", "socks-b"] {
            let OutboundConnectOutcome::Connected(connection) = registry
                .connect(tag, &destination)
                .await
                .expect("isolated warm SOCKS connection")
            else {
                panic!("SOCKS cannot blackhole");
            };
            drop(connection);
        }
        registry.deactivate_warm_pools();
        let credentials = server
            .await
            .expect("server must join")
            .expect("server result");
        assert_eq!(
            credentials,
            vec![
                (b"alice".to_vec(), b"alpha".to_vec()),
                (b"bob".to_vec(), b"bravo".to_vec())
            ]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn outbound_descriptor_unit_is_exact_and_released_with_the_connection() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("target listener must bind");
        let address = listener.local_addr().expect("target address must exist");
        let budget = crate::runtime::FdBudget::new(4_096);
        let registry = OutboundRegistry::new(
            &[OutboundConfig::Direct {
                tag: "direct".to_owned(),
            }],
            &DirectBarrierConfig::default(),
            Duration::from_secs(1),
            budget.clone(),
        );
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), address.port());
        let baseline = budget.in_use();

        let outcome = registry
            .connect("direct", &destination)
            .await
            .expect("connect must succeed");
        let OutboundConnectOutcome::Connected(connection) = outcome else {
            panic!("a direct route must connect");
        };
        let in_flight = budget.in_use() - baseline;
        assert_eq!(
            in_flight,
            u64::from(crate::runtime::UNITS_OUTBOUND_SOCKET),
            "one outbound connection accounts exactly one descriptor"
        );
        let (_stream, permit) = connection.into_parts();
        drop(permit);
        assert_eq!(
            budget.in_use(),
            baseline,
            "dropping the connection permit returns the unit"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn outbound_connect_declines_when_the_descriptor_budget_is_exhausted() {
        let budget = crate::runtime::FdBudget::new(4_096);
        let _reservation = budget
            .try_acquire(4_096)
            .expect("the whole budget must be acquirable for the test");
        let registry = OutboundRegistry::new(
            &[OutboundConfig::Direct {
                tag: "direct".to_owned(),
            }],
            &DirectBarrierConfig::default(),
            Duration::from_secs(1),
            budget,
        );
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 9);
        let error = registry
            .connect("direct", &destination)
            .await
            .expect_err("an exhausted budget must deny the outbound connect");
        assert!(
            matches!(error, super::OutboundConnectError::DescriptorBudget),
            "expected DescriptorBudget, got {error}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn negotiates_authenticated_socks5_domain_connect() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("SOCKS listener must bind");
        let address = listener.local_addr().expect("SOCKS address must exist");
        let registry = OutboundRegistry::new(
            &[OutboundConfig::Socks5 {
                tag: "socks".to_owned(),
                settings: Socks5Settings {
                    address: address.ip().to_string(),
                    port: address.port(),
                    username: Some(SecretString::new("user")),
                    password: Some(SecretString::new("pass")),
                    warm_tcp: false,
                },
            }],
            &DirectBarrierConfig::default(),
            Duration::from_secs(1),
            crate::runtime::FdBudget::new(4_096),
        );
        let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

        let proxy = async {
            let (mut stream, _) = listener.accept().await?;
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await?;
            assert_eq!(greeting, [5, 1, 2]);
            stream.write_all(&[5, 2]).await?;
            let mut auth = [0_u8; 11];
            stream.read_exact(&mut auth).await?;
            assert_eq!(
                auth,
                [1, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's']
            );
            stream.write_all(&[1, 0]).await?;
            let mut connect = [0_u8; 18];
            stream.read_exact(&mut connect).await?;
            assert_eq!(&connect[..5], &[5, 1, 0, 3, 11]);
            assert_eq!(&connect[5..16], b"example.com");
            assert_eq!(&connect[16..], &443_u16.to_be_bytes());
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x12, 0x34])
                .await?;
            Ok::<_, std::io::Error>(())
        };
        let connect = registry.connect("socks", &destination);
        let (proxy_result, connect_result) = tokio::join!(proxy, connect);

        proxy_result.expect("SOCKS exchange must succeed");
        assert!(matches!(
            connect_result.expect("SOCKS connection must succeed"),
            OutboundConnectOutcome::Connected(_)
        ));
    }

    fn socks5_registry(
        address: std::net::SocketAddr,
        credentials: Option<(&str, &str)>,
        connect_timeout: Duration,
    ) -> OutboundRegistry {
        let (username, password) = match credentials {
            Some((username, password)) => (
                Some(SecretString::new(username)),
                Some(SecretString::new(password)),
            ),
            None => (None, None),
        };
        OutboundRegistry::new(
            &[OutboundConfig::Socks5 {
                tag: "socks".to_owned(),
                settings: Socks5Settings {
                    address: address.ip().to_string(),
                    port: address.port(),
                    username,
                    password,
                    warm_tcp: false,
                },
            }],
            &DirectBarrierConfig::default(),
            connect_timeout,
            crate::runtime::FdBudget::new(4_096),
        )
    }

    fn socks_protocol_error(error: OutboundConnectError) -> Socks5ProtocolError {
        match error {
            OutboundConnectError::SocksProtocol(error) => error,
            other => panic!("expected a SOCKS protocol error, got {other}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn socks5_method_rejection_maps_to_unexpected_method() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("SOCKS listener must bind");
        let address = listener.local_addr().expect("SOCKS address must exist");
        let registry = socks5_registry(address, None, Duration::from_secs(1));
        let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

        let proxy = async {
            let (mut stream, _) = listener.accept().await?;
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await?;
            assert_eq!(greeting, [5, 1, 0]);
            // 0xFF: no acceptable authentication methods.
            stream.write_all(&[5, 0xff]).await?;
            Ok::<_, std::io::Error>(())
        };
        let connect = registry.connect("socks", &destination);
        let (proxy_result, connect_result) = tokio::join!(proxy, connect);

        proxy_result.expect("SOCKS exchange must succeed");
        assert_eq!(
            socks_protocol_error(
                connect_result.expect_err("a method rejection must fail the connect")
            ),
            Socks5ProtocolError::UnexpectedMethod {
                expected: 0,
                received: 0xff,
            }
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn socks5_username_password_failure_maps_to_authentication_failed() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("SOCKS listener must bind");
        let address = listener.local_addr().expect("SOCKS address must exist");
        let registry = socks5_registry(address, Some(("user", "pass")), Duration::from_secs(1));
        let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

        let proxy = async {
            let (mut stream, _) = listener.accept().await?;
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await?;
            assert_eq!(greeting, [5, 1, 2]);
            stream.write_all(&[5, 2]).await?;
            let mut auth = [0_u8; 11];
            stream.read_exact(&mut auth).await?;
            assert_eq!(
                auth,
                [1, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's']
            );
            // Status 1: the credentials were rejected.
            stream.write_all(&[1, 1]).await?;
            Ok::<_, std::io::Error>(())
        };
        let connect = registry.connect("socks", &destination);
        let (proxy_result, connect_result) = tokio::join!(proxy, connect);

        proxy_result.expect("SOCKS exchange must succeed");
        assert_eq!(
            socks_protocol_error(
                connect_result.expect_err("a rejected login must fail the connect")
            ),
            Socks5ProtocolError::AuthenticationFailed(1)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn socks5_connect_failure_codes_map_to_connect_failed() {
        for code in [5_u8, 4_u8] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("SOCKS listener must bind");
            let address = listener.local_addr().expect("SOCKS address must exist");
            let registry = socks5_registry(address, None, Duration::from_secs(1));
            let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

            let proxy = async {
                let (mut stream, _) = listener.accept().await?;
                let mut greeting = [0_u8; 3];
                stream.read_exact(&mut greeting).await?;
                stream.write_all(&[5, 0]).await?;
                let mut connect = [0_u8; 18];
                stream.read_exact(&mut connect).await?;
                // Failure codes: 0x05 connection refused, 0x04 host unreachable.
                stream
                    .write_all(&[5, code, 0, 1, 127, 0, 0, 1, 0x12, 0x34])
                    .await?;
                Ok::<_, std::io::Error>(())
            };
            let connect = registry.connect("socks", &destination);
            let (proxy_result, connect_result) = tokio::join!(proxy, connect);

            proxy_result.expect("SOCKS exchange must succeed");
            assert_eq!(
                socks_protocol_error(
                    connect_result.expect_err("a failure reply code must fail the connect")
                ),
                Socks5ProtocolError::ConnectFailed(code),
                "reply code {code:#04x} must map to ConnectFailed"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn socks5_malformed_connect_replies_map_to_invalid_reply() {
        let garbage_headers: [[u8; 10]; 3] = [
            // Wrong SOCKS version in the reply header.
            [4, 0, 0, 1, 127, 0, 0, 1, 0x12, 0x34],
            // Non-zero reserved byte in the reply header.
            [5, 0, 1, 1, 127, 0, 0, 1, 0x12, 0x34],
            // Unknown address type in the reply header.
            [5, 0, 0, 9, 127, 0, 0, 1, 0x12, 0x34],
        ];
        for garbage in garbage_headers {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("SOCKS listener must bind");
            let address = listener.local_addr().expect("SOCKS address must exist");
            let registry = socks5_registry(address, None, Duration::from_secs(1));
            let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

            let proxy = async {
                let (mut stream, _) = listener.accept().await?;
                let mut greeting = [0_u8; 3];
                stream.read_exact(&mut greeting).await?;
                stream.write_all(&[5, 0]).await?;
                let mut connect = [0_u8; 18];
                stream.read_exact(&mut connect).await?;
                stream.write_all(&garbage).await?;
                Ok::<_, std::io::Error>(())
            };
            let connect = registry.connect("socks", &destination);
            let (proxy_result, connect_result) = tokio::join!(proxy, connect);

            proxy_result.expect("SOCKS exchange must succeed");
            assert_eq!(
                socks_protocol_error(
                    connect_result.expect_err("a malformed reply must fail the connect")
                ),
                Socks5ProtocolError::InvalidReply,
                "garbage reply {garbage:02x?} must map to InvalidReply"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn socks5_garbage_method_reply_maps_to_unexpected_method() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("SOCKS listener must bind");
        let address = listener.local_addr().expect("SOCKS address must exist");
        let registry = socks5_registry(address, None, Duration::from_secs(1));
        let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

        let proxy = async {
            let (mut stream, _) = listener.accept().await?;
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await?;
            // Not a SOCKS5 method selection reply at all.
            stream.write_all(b"NO").await?;
            Ok::<_, std::io::Error>(())
        };
        let connect = registry.connect("socks", &destination);
        let (proxy_result, connect_result) = tokio::join!(proxy, connect);

        proxy_result.expect("SOCKS exchange must succeed");
        assert_eq!(
            socks_protocol_error(
                connect_result.expect_err("a garbage method reply must fail the connect")
            ),
            Socks5ProtocolError::UnexpectedMethod {
                expected: 0,
                received: b'O',
            }
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn socks5_truncated_reply_fails_instead_of_hanging() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("SOCKS listener must bind");
        let address = listener.local_addr().expect("SOCKS address must exist");
        let registry = socks5_registry(address, None, Duration::from_secs(1));
        let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

        let proxy = async {
            let (mut stream, _) = listener.accept().await?;
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await?;
            stream.write_all(&[5, 0]).await?;
            let mut connect = [0_u8; 18];
            stream.read_exact(&mut connect).await?;
            // Half a reply header, then an abrupt close: the client must see an
            // I/O failure, not a panic or a hang.
            stream.write_all(&[5, 0]).await?;
            Ok::<_, std::io::Error>(())
        };
        let connect = registry.connect("socks", &destination);
        let (proxy_result, connect_result) = tokio::join!(proxy, connect);

        proxy_result.expect("SOCKS exchange must succeed");
        assert!(
            matches!(
                connect_result.expect_err("a truncated reply must fail the connect"),
                OutboundConnectError::SocksConnect(_)
            ),
            "a truncated reply must surface as a SOCKS connect I/O error"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn socks5_silent_server_fails_within_the_connect_timeout() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("SOCKS listener must bind");
        let address = listener.local_addr().expect("SOCKS address must exist");
        let registry = socks5_registry(address, None, Duration::from_millis(100));
        let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

        let proxy = async {
            let (mut stream, _) = listener.accept().await?;
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await?;
            // Never answer: the client deadline must bound the wait.
            let mut byte = [0_u8; 1];
            let _ = stream.read(&mut byte).await;
            Ok::<_, std::io::Error>(())
        };
        let connect = registry.connect("socks", &destination);
        let (proxy_result, connect_result) =
            tokio::time::timeout(Duration::from_secs(2), async move {
                tokio::join!(proxy, connect)
            })
            .await
            .expect("a silent server must be bounded by the connect timeout");

        proxy_result.expect("SOCKS exchange must succeed");
        assert!(
            matches!(
                connect_result.expect_err("a silent server must fail the connect"),
                OutboundConnectError::SocksTimeout
            ),
            "a silent server must hit the SOCKS timeout"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blackhole_never_opens_a_destination_stream() {
        let registry = OutboundRegistry::new(
            &[OutboundConfig::Blackhole {
                tag: "blocked".to_owned(),
                settings: crate::config::BlackholeSettings {
                    response_delay_ms: 0,
                },
            }],
            &DirectBarrierConfig::default(),
            Duration::from_secs(1),
            crate::runtime::FdBudget::new(4_096),
        );
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 9);

        assert!(matches!(
            registry
                .connect("blocked", &destination)
                .await
                .expect("blackhole route must complete"),
            OutboundConnectOutcome::Blackholed
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn nxr_writes_one_authentication_request_then_raw_payload() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("NXR listener must bind");
        let address = listener.local_addr().expect("NXR address must exist");
        let key_bytes = [0x5a; 32];
        let registry = OutboundRegistry::new(
            &[OutboundConfig::Nxr {
                tag: "landing".to_owned(),
                settings: NxrSettings {
                    address: address.ip().to_string(),
                    port: address.port(),
                    pre_shared_key: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(key_bytes)),
                    warm_tcp: false,
                },
            }],
            &DirectBarrierConfig::default(),
            Duration::from_secs(1),
            crate::runtime::FdBudget::new(4_096),
        );
        let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

        let landing = async {
            let (mut stream, _) = listener.accept().await?;
            let mut header = [0_u8; REQUEST_HEADER_LEN];
            stream.read_exact(&mut header).await?;
            let total = request_len_from_header(&header).expect("header must be bounded");
            let mut request = Vec::with_capacity(total);
            request.extend_from_slice(&header);
            request.resize(total, 0);
            stream
                .read_exact(&mut request[REQUEST_HEADER_LEN..])
                .await?;
            let timestamp = u64::from_be_bytes(
                header[10..18]
                    .try_into()
                    .expect("timestamp field must be fixed"),
            );
            let authenticated =
                decode_authenticated_request(&request, &NxrKey::new(key_bytes), timestamp, 0)
                    .expect("NXR request must authenticate");
            assert_eq!(authenticated.destination(), &destination);
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await?;
            assert_eq!(&payload, b"ping");
            Ok::<_, std::io::Error>(())
        };
        let line = async {
            let outcome = registry
                .connect("landing", &destination)
                .await
                .expect("NXR outbound must connect");
            let OutboundConnectOutcome::Connected(connection) = outcome else {
                panic!("NXR route must connect");
            };
            let (mut stream, _permit) = connection.into_parts();
            stream.write_all(b"ping").await
        };
        let (landing_result, line_result) = tokio::join!(landing, line);

        landing_result.expect("landing exchange must succeed");
        line_result.expect("raw payload write must succeed");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_dial_limit_denies_a_second_in_flight_dial() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("target listener must bind");
        let address = listener.local_addr().expect("target address must exist");
        let barrier = DirectBarrier::new(&DirectBarrierConfig {
            max_concurrent: 1,
            max_per_second: 1_000,
        });
        // A permit held by another task is exactly the state of one dial in
        // flight; the second dial must be refused until it resolves.
        let in_flight = barrier
            .try_acquire()
            .expect("the first dial permit must be available");
        let registry = direct_registry(&barrier, Duration::from_secs(1));
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), address.port());

        let error = registry
            .connect("direct", &destination)
            .await
            .expect_err("a dial at the concurrency ceiling must be denied");
        assert!(
            matches!(
                error,
                OutboundConnectError::Admission(AdmissionDenied::DirectConcurrency)
            ),
            "expected DirectConcurrency, got {error}"
        );

        drop(in_flight);
        assert!(
            matches!(
                registry
                    .connect("direct", &destination)
                    .await
                    .expect("the dial must proceed once the in-flight dial resolves"),
                OutboundConnectOutcome::Connected(_)
            ),
            "a direct route must connect once capacity is free"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_completed_dial_releases_its_permit_while_the_session_stays_open() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("target listener must bind");
        let address = listener.local_addr().expect("target address must exist");
        let barrier = DirectBarrier::new(&DirectBarrierConfig {
            max_concurrent: 1,
            max_per_second: 1_000,
        });
        let registry = direct_registry(&barrier, Duration::from_secs(1));
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), address.port());

        let first = registry
            .connect("direct", &destination)
            .await
            .expect("the first dial must connect");
        let OutboundConnectOutcome::Connected(first) = first else {
            panic!("a direct route must connect");
        };

        // The dial resolved, so the concurrency permit is already free even
        // though the established session above is still open.
        let probe = barrier
            .try_acquire()
            .expect("a completed dial must not hold its barrier permit");
        drop(probe);
        assert!(
            matches!(
                registry
                    .connect("direct", &destination)
                    .await
                    .expect("a second dial must fit under the barrier"),
                OutboundConnectOutcome::Connected(_)
            ),
            "an open session must not consume the dial concurrency limit"
        );

        // Drain the backlog so both sessions are fully accepted before close.
        let _accepted = listener.accept().await.expect("first peer must accept");
        let _accepted = listener.accept().await.expect("second peer must accept");
        drop(first);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_established_session_relays_while_the_concurrency_limit_is_exhausted() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("target listener must bind");
        let address = listener.local_addr().expect("target address must exist");
        let barrier = DirectBarrier::new(&DirectBarrierConfig {
            max_concurrent: 1,
            max_per_second: 1_000,
        });
        let registry = direct_registry(&barrier, Duration::from_secs(1));
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), address.port());

        let outcome = registry
            .connect("direct", &destination)
            .await
            .expect("the session dial must connect");
        let OutboundConnectOutcome::Connected(connection) = outcome else {
            panic!("a direct route must connect");
        };
        let (mut stream, session_permit) = connection.into_parts();
        // Exhaust the concurrency limit again, standing in for another dial in
        // flight: the established session must be unaffected either way.
        let _in_flight = barrier
            .try_acquire()
            .expect("the established session must not hold the concurrency permit");

        let echo = async {
            let (mut peer, _) = listener.accept().await?;
            let mut payload = [0_u8; 4];
            peer.read_exact(&mut payload).await?;
            peer.write_all(&payload).await
        };
        let exchange = async {
            stream.write_all(b"ping").await?;
            let mut echoed = [0_u8; 4];
            stream.read_exact(&mut echoed).await?;
            assert_eq!(&echoed, b"ping");
            Ok::<_, std::io::Error>(())
        };
        let (echo_result, exchange_result) = tokio::join!(echo, exchange);
        echo_result.expect("echo peer must succeed");
        exchange_result.expect("the established session must still relay bytes");
        drop(session_permit);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_failed_dial_releases_its_permit() {
        // Reserve a port and drop the listener so connects are refused fast.
        let refused_port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("probe listener must bind")
            .local_addr()
            .expect("probe address must exist")
            .port();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("target listener must bind");
        let good_port = listener
            .local_addr()
            .expect("target address must exist")
            .port();
        let barrier = DirectBarrier::new(&DirectBarrierConfig {
            max_concurrent: 1,
            max_per_second: 1_000,
        });
        let registry = direct_registry(&barrier, Duration::from_secs(1));

        let refused = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), refused_port);
        let error = registry
            .connect("direct", &refused)
            .await
            .expect_err("a refused destination must fail the dial");
        assert!(
            matches!(error, OutboundConnectError::Direct(_)),
            "expected a direct connect error, got {error}"
        );

        let good = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), good_port);
        assert!(
            matches!(
                registry
                    .connect("direct", &good)
                    .await
                    .expect("the failed dial must have released its permit"),
                OutboundConnectOutcome::Connected(_)
            ),
            "a good dial must succeed after a failure under a barrier of one"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_rate_limit_applies_to_new_dials_after_a_permit_is_released() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("target listener must bind");
        let address = listener.local_addr().expect("target address must exist");
        let barrier = DirectBarrier::new(&DirectBarrierConfig {
            max_concurrent: 8,
            max_per_second: 1,
        });
        let registry = direct_registry(&barrier, Duration::from_secs(1));
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), address.port());

        assert!(
            matches!(
                registry
                    .connect("direct", &destination)
                    .await
                    .expect("the first dial must connect"),
                OutboundConnectOutcome::Connected(_)
            ),
            "a direct route must connect"
        );
        // The first dial's concurrency permit is already released, so only the
        // rate gate can refuse an immediate second dial.
        let error = registry
            .connect("direct", &destination)
            .await
            .expect_err("the rate limit must deny an immediate second dial");
        assert!(
            matches!(
                error,
                OutboundConnectError::Admission(AdmissionDenied::DirectRate)
            ),
            "expected DirectRate, got {error}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn critical_pressure_blocks_new_dials_but_not_established_relays() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("target listener must bind");
        let address = listener.local_addr().expect("target address must exist");
        let gauge = crate::runtime::PressureGauge::new();
        let barrier = DirectBarrier::with_pressure(
            &DirectBarrierConfig {
                max_concurrent: 4,
                max_per_second: 1_000,
            },
            gauge.clone(),
        );
        let registry = direct_registry(&barrier, Duration::from_secs(1));
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), address.port());

        let outcome = registry
            .connect("direct", &destination)
            .await
            .expect("the session dial must connect under normal pressure");
        let OutboundConnectOutcome::Connected(connection) = outcome else {
            panic!("a direct route must connect");
        };
        let (mut stream, session_permit) = connection.into_parts();

        gauge.set(ResourcePressure::Critical);
        let error = registry
            .connect("direct", &destination)
            .await
            .expect_err("critical pressure must pause new dials");
        assert!(
            matches!(
                error,
                OutboundConnectError::Admission(AdmissionDenied::DirectPressure)
            ),
            "expected DirectPressure, got {error}"
        );

        let echo = async {
            let (mut peer, _) = listener.accept().await?;
            let mut payload = [0_u8; 4];
            peer.read_exact(&mut payload).await?;
            peer.write_all(&payload).await
        };
        let exchange = async {
            stream.write_all(b"ping").await?;
            let mut echoed = [0_u8; 4];
            stream.read_exact(&mut echoed).await?;
            assert_eq!(&echoed, b"ping");
            Ok::<_, std::io::Error>(())
        };
        let (echo_result, exchange_result) = tokio::join!(echo, exchange);
        echo_result.expect("echo peer must succeed");
        exchange_result.expect("critical pressure must not interrupt an established relay");
        drop(session_permit);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn socks5_dials_never_consume_direct_barrier_permits() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("SOCKS listener must bind");
        let address = listener.local_addr().expect("SOCKS address must exist");
        let barrier = DirectBarrier::new(&DirectBarrierConfig {
            max_concurrent: 1,
            max_per_second: 1,
        });
        // Fill the barrier completely: the one concurrency permit and the one
        // rate token. A SOCKS5 dial must not touch either.
        let _in_flight = barrier
            .try_acquire()
            .expect("the barrier must be fillable for the test");
        let registry = OutboundRegistry::with_barrier(
            &[OutboundConfig::Socks5 {
                tag: "socks".to_owned(),
                settings: Socks5Settings {
                    address: address.ip().to_string(),
                    port: address.port(),
                    username: None,
                    password: None,
                    warm_tcp: false,
                },
            }],
            barrier,
            Duration::from_secs(1),
            crate::runtime::FdBudget::new(4_096),
        );
        let destination = Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 443);

        let proxy = async {
            let (mut stream, _) = listener.accept().await?;
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await?;
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await?;
            let mut connect = [0_u8; 10];
            stream.read_exact(&mut connect).await?;
            assert_eq!(&connect[..8], &[5, 1, 0, 1, 127, 0, 0, 1]);
            assert_eq!(&connect[8..], &443_u16.to_be_bytes());
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x12, 0x34])
                .await?;
            Ok::<_, std::io::Error>(())
        };
        let connect = registry.connect("socks", &destination);
        let (proxy_result, connect_result) = tokio::join!(proxy, connect);

        proxy_result.expect("SOCKS exchange must succeed");
        assert!(
            matches!(
                connect_result.expect("a full barrier must not block a SOCKS5 dial"),
                OutboundConnectOutcome::Connected(_)
            ),
            "a SOCKS5 route must connect"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn nxr_dials_never_consume_direct_barrier_permits() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("NXR listener must bind");
        let address = listener.local_addr().expect("NXR address must exist");
        let key_bytes = [0x5a; 32];
        let barrier = DirectBarrier::new(&DirectBarrierConfig {
            max_concurrent: 1,
            max_per_second: 1,
        });
        // Fill the barrier completely: the one concurrency permit and the one
        // rate token. An NXR dial must not touch either.
        let _in_flight = barrier
            .try_acquire()
            .expect("the barrier must be fillable for the test");
        let registry = OutboundRegistry::with_barrier(
            &[OutboundConfig::Nxr {
                tag: "landing".to_owned(),
                settings: NxrSettings {
                    address: address.ip().to_string(),
                    port: address.port(),
                    pre_shared_key: SecretString::new(BASE64_URL_SAFE_NO_PAD.encode(key_bytes)),
                    warm_tcp: false,
                },
            }],
            barrier,
            Duration::from_secs(1),
            crate::runtime::FdBudget::new(4_096),
        );
        let destination = Destination::new(Address::Domain("example.com".to_owned()), 443);

        let landing = async {
            let (mut stream, _) = listener.accept().await?;
            let mut header = [0_u8; REQUEST_HEADER_LEN];
            stream.read_exact(&mut header).await?;
            let total = request_len_from_header(&header).expect("header must be bounded");
            let mut request = Vec::with_capacity(total);
            request.extend_from_slice(&header);
            request.resize(total, 0);
            stream
                .read_exact(&mut request[REQUEST_HEADER_LEN..])
                .await?;
            let timestamp = u64::from_be_bytes(
                header[10..18]
                    .try_into()
                    .expect("timestamp field must be fixed"),
            );
            let authenticated =
                decode_authenticated_request(&request, &NxrKey::new(key_bytes), timestamp, 0)
                    .expect("NXR request must authenticate");
            assert_eq!(authenticated.destination(), &destination);
            Ok::<_, std::io::Error>(())
        };
        let connect = registry.connect("landing", &destination);
        let (landing_result, connect_result) = tokio::join!(landing, connect);

        landing_result.expect("landing exchange must succeed");
        assert!(
            matches!(
                connect_result.expect("a full barrier must not block an NXR dial"),
                OutboundConnectOutcome::Connected(_)
            ),
            "an NXR route must connect"
        );
    }
}
