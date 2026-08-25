use std::{error::Error, fmt, io, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{self, Instant},
};

use crate::{
    config::{NetworkConfig, ResourceGovernorConfig, WarmConnectionPolicy},
    network::NetworkEnvironment,
    protocol::reality::{
        ClientHello,
        tls13::{
            TargetServerFlightRead, TargetServerHelloRead, TargetServerHelloReadError,
            read_target_server_flight as read_server_flight,
            read_target_server_hello as read_server_hello,
        },
    },
    runtime::{AdmissionDenied, AdmissionKind, AdmissionPermit, ResourceGovernor},
    transport::{RelayContext, TcpRelay, relay::RelayStats},
};

use super::warm_pool::{AdaptiveTcpPool, WarmPoolAuthority, WarmPoolSnapshot, WarmUsePermit};

const MAX_WARM_CHECKOUT_ATTEMPTS: usize = 2;

/// Completed fallback byte counts, including the already-consumed wire prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FallbackStats {
    forwarded_prefix: u64,
    returned_prefix: u64,
    relay: RelayStats,
}

impl FallbackStats {
    /// Returns the exact number of pre-read bytes forwarded before live relay.
    #[must_use]
    pub const fn forwarded_prefix_bytes(self) -> u64 {
        self.forwarded_prefix
    }

    /// Returns target bytes replayed before live target-to-client relay.
    #[must_use]
    pub const fn returned_prefix_bytes(self) -> u64 {
        self.returned_prefix
    }

    /// Returns the subsequent bidirectional relay counts.
    #[must_use]
    pub const fn relay(self) -> RelayStats {
        self.relay
    }
}

/// A bounded cover-target fallback failure.
#[derive(Debug)]
pub enum FallbackError {
    /// Global fallback admission rejected the session without queuing.
    Admission(AdmissionDenied),
    /// Cover target connection exceeded its configured deadline.
    ConnectTimeout,
    /// The entire fallback session exceeded its configured lifetime.
    SessionTimeout,
    /// Target connection, exact prefix forwarding, or relay failed.
    Io(io::Error),
    /// The descriptor budget denied the cover connection before `connect(2)`.
    DescriptorBudget,
}

impl fmt::Display for FallbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(_) => formatter.write_str("REALITY fallback admission denied"),
            Self::ConnectTimeout => formatter.write_str("REALITY cover connection timed out"),
            Self::SessionTimeout => formatter.write_str("REALITY fallback session timed out"),
            Self::Io(_) => formatter.write_str("REALITY fallback I/O failed"),
            Self::DescriptorBudget => {
                formatter.write_str("descriptor budget denied the fallback connection")
            }
        }
    }
}

impl Error for FallbackError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Admission(source) => Some(source),
            Self::Io(source) => Some(source),
            Self::ConnectTimeout | Self::SessionTimeout | Self::DescriptorBudget => None,
        }
    }
}

/// Connects failed REALITY handshakes to their cover target under hard bounds.
#[derive(Clone)]
pub struct RealityFallback {
    target: Arc<str>,
    governor: ResourceGovernor,
    relay: TcpRelay,
    connect_timeout: Duration,
    session_timeout: Duration,
    connector: super::connector::DestinationConnector,
    warm_pool: Option<AdaptiveTcpPool>,
}

/// One admitted cover connection whose byte ownership can transition to fallback.
pub struct CoverConnection {
    stream: TcpStream,
    governor: ResourceGovernor,
    relay: TcpRelay,
    permit: Option<AdmissionPermit>,
    fd_permit: Option<crate::runtime::FdPermit>,
    deadline: Instant,
    forwarded_prefix: u64,
    warm_use: Option<WarmUsePermit>,
}

impl RealityFallback {
    /// Creates immutable fallback state from a validated listener snapshot.
    #[must_use]
    pub fn new(
        target: impl Into<Arc<str>>,
        governor: ResourceGovernor,
        config: &ResourceGovernorConfig,
        relay: TcpRelay,
    ) -> Self {
        Self::with_environment(
            target,
            governor,
            config,
            relay,
            &NetworkConfig::default(),
            NetworkEnvironment::detect(),
        )
    }

    /// Creates fallback state over the shared process network environment.
    #[must_use]
    pub fn with_environment(
        target: impl Into<Arc<str>>,
        governor: ResourceGovernor,
        config: &ResourceGovernorConfig,
        relay: TcpRelay,
        network: &NetworkConfig,
        environment: NetworkEnvironment,
    ) -> Self {
        Self::build(
            target.into(),
            governor,
            config,
            relay,
            network,
            environment,
            None,
        )
    }

    /// Creates fallback state with an authenticated-only raw cover TCP pool.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "extends the existing immutable fallback constructor with one pool generation"
    )]
    pub(crate) fn with_warm_pool(
        target: impl Into<Arc<str>>,
        governor: ResourceGovernor,
        config: &ResourceGovernorConfig,
        relay: TcpRelay,
        network: &NetworkConfig,
        environment: NetworkEnvironment,
        generation: u64,
        authority: WarmPoolAuthority,
        policy: &WarmConnectionPolicy,
    ) -> Self {
        Self::build(
            target.into(),
            governor,
            config,
            relay,
            network,
            environment,
            Some((generation, authority, policy)),
        )
    }

    fn build(
        target: Arc<str>,
        governor: ResourceGovernor,
        config: &ResourceGovernorConfig,
        relay: TcpRelay,
        network: &NetworkConfig,
        environment: NetworkEnvironment,
        warm: Option<(u64, WarmPoolAuthority, &WarmConnectionPolicy)>,
    ) -> Self {
        let connector = super::connector::DestinationConnector::with_environment(
            Duration::from_millis(config.connect_timeout_ms),
            network.clone(),
            environment,
        );
        let warm_pool = warm.map(|(generation, authority, policy)| {
            AdaptiveTcpPool::new(
                Arc::clone(&target),
                generation,
                connector.clone(),
                relay.fd_budget().clone(),
                authority,
                policy,
            )
        });
        Self {
            target,
            governor,
            relay,
            connect_timeout: Duration::from_millis(config.connect_timeout_ms),
            session_timeout: Duration::from_millis(config.fallback_timeout_ms),
            connector,
            warm_pool,
        }
    }

    /// Starts speculative cover dialing without delaying listener startup.
    pub(crate) fn activate(&self) {
        if let Some(pool) = &self.warm_pool {
            let _started = pool.activate();
        }
    }

    /// Stops refill and closes every idle socket in this immutable generation.
    pub(crate) fn deactivate(&self) -> bool {
        if let Some(pool) = &self.warm_pool {
            return pool.deactivate();
        }
        false
    }

    /// Returns fixed-cardinality pool metrics when warm cover TCP is enabled.
    pub(crate) fn warm_pool_snapshot(&self) -> Option<WarmPoolSnapshot> {
        self.warm_pool.as_ref().map(AdaptiveTcpPool::snapshot)
    }

    /// Forwards every consumed byte before relaying any new client input.
    ///
    /// The caller must pass the exact owned prefix from `read_client_hello`; this
    /// method never reparses, normalizes, or reconstructs attacker-controlled bytes.
    /// Admission is non-waiting and both connection setup and total lifetime are
    /// bounded. The permit is released on timeout, cancellation, and every error.
    ///
    /// After the exact prefixes are written, the remaining raw pair is relayed by
    /// the unified owned relay, so a fallback session can use kernel backends
    /// under the same descriptor accounting as every other raw boundary.
    ///
    /// # Errors
    ///
    /// Returns an admission, deadline, connection, prefix-write, or relay error.
    pub async fn relay(
        &self,
        inbound: TcpStream,
        consumed_prefix: &[u8],
    ) -> Result<FallbackStats, FallbackError> {
        self.connect(consumed_prefix)
            .await?
            .relay(inbound, &[])
            .await
    }

    /// Opens one admitted target connection and writes the exact client prefix.
    ///
    /// The returned connection may first inspect the target ServerHello. Any bytes
    /// consumed during that inspection remain caller-owned and can be supplied to
    /// [`CoverConnection::relay`] if authentication or compatibility later fails.
    ///
    /// # Errors
    ///
    /// Returns an admission, connection deadline, prefix write, or session error.
    pub async fn connect(&self, consumed_prefix: &[u8]) -> Result<CoverConnection, FallbackError> {
        let permit = self
            .governor
            .try_acquire(AdmissionKind::Fallback)
            .map_err(FallbackError::Admission)?;
        self.connect_with_permit(consumed_prefix, Some(permit), false)
            .await
    }

    /// Opens a short-lived target mirror without consuming fallback capacity.
    ///
    /// The caller must already hold handshake admission. If the connection later
    /// transitions to byte relay, [`CoverConnection::relay`] acquires fallback
    /// admission immediately before that longer-lived phase.
    ///
    /// # Errors
    ///
    /// Returns a connection deadline, prefix write, or session error.
    pub async fn mirror(&self, consumed_prefix: &[u8]) -> Result<CoverConnection, FallbackError> {
        self.connect_with_permit(consumed_prefix, None, true).await
    }

    /// Opens one cold, independently accounted connection for a controlled
    /// background profile probe. It never consumes a warm socket, so real
    /// authenticated handshakes retain priority over speculative collection.
    pub(crate) async fn profile_probe(
        &self,
        controlled_prefix: &[u8],
    ) -> Result<CoverConnection, FallbackError> {
        self.connect_with_permit(controlled_prefix, None, false)
            .await
    }

    async fn connect_with_permit(
        &self,
        consumed_prefix: &[u8],
        permit: Option<AdmissionPermit>,
        allow_warm: bool,
    ) -> Result<CoverConnection, FallbackError> {
        let now = Instant::now();
        let deadline = now
            .checked_add(self.session_timeout)
            .ok_or(FallbackError::SessionTimeout)?;
        let connect_deadline = now
            .checked_add(self.connect_timeout)
            .map_or(deadline, |candidate| candidate.min(deadline));
        if allow_warm && let Some(pool) = &self.warm_pool {
            for _ in 0..MAX_WARM_CHECKOUT_ATTEMPTS {
                let Some(checkout) = pool.checkout() else {
                    break;
                };
                let (connected, warm_use) = checkout.into_parts();
                let (mut stream, fd_permit) = connected.into_parts();
                match time::timeout_at(connect_deadline, stream.write_all(consumed_prefix)).await {
                    Ok(Ok(())) => {
                        return Ok(CoverConnection {
                            stream,
                            governor: self.governor.clone(),
                            relay: self.relay.clone(),
                            permit,
                            fd_permit: Some(fd_permit),
                            deadline,
                            forwarded_prefix: prefix_len(consumed_prefix),
                            warm_use: Some(warm_use),
                        });
                    }
                    Ok(Err(_)) | Err(_) => {
                        pool.record_stale_checkout();
                    }
                }
            }
            pool.record_cold_fallback();
        }

        let connected = time::timeout_at(
            connect_deadline,
            self.connector
                .connect_target_accounted(self.target.as_ref(), self.relay.fd_budget()),
        )
        .await
        .map_err(|_| FallbackError::ConnectTimeout)?
        .map_err(|error| match error {
            super::connector::DestinationConnectError::DescriptorBudget => {
                FallbackError::DescriptorBudget
            }
            super::connector::DestinationConnectError::TimedOut { .. } => {
                FallbackError::ConnectTimeout
            }
            error => FallbackError::Io(error.into_io()),
        })?;
        let (mut stream, fd_permit) = connected.into_parts();
        time::timeout_at(deadline, stream.write_all(consumed_prefix))
            .await
            .map_err(|_| FallbackError::SessionTimeout)?
            .map_err(FallbackError::Io)?;
        let forwarded_prefix =
            u64::try_from(consumed_prefix.len()).map_or(u64::MAX, |length| length);
        Ok(CoverConnection {
            stream,
            governor: self.governor.clone(),
            relay: self.relay.clone(),
            permit,
            fd_permit: Some(fd_permit),
            deadline,
            forwarded_prefix,
            warm_use: None,
        })
    }
}

impl CoverConnection {
    /// Reads the target ServerHello and bounded encrypted-handshake record shape.
    ///
    /// The shorter of `timeout` and the remaining fallback lifetime is used.
    /// Every consumed target byte remains owned by the returned value or error
    /// so a rejected shape can still transition to exact fallback.
    ///
    /// # Errors
    ///
    /// Returns a byte-owning target read error suitable for exact fallback.
    pub(crate) async fn read_server_flight(
        &mut self,
        client: &ClientHello,
        timeout: Duration,
    ) -> Result<TargetServerFlightRead, TargetServerHelloReadError> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        read_server_flight(&mut self.stream, client, timeout.min(remaining)).await
    }

    /// Completes a bounded already-started cover prefix without changing its
    /// byte order. Used only by the controlled collector when the production
    /// coalesced-flight parser intentionally stopped after one ciphertext byte.
    pub(crate) async fn complete_prefix(
        &mut self,
        prefix: &mut Vec<u8>,
        required_len: usize,
        timeout: Duration,
    ) -> Result<(), FallbackError> {
        if prefix.len() >= required_len {
            return Ok(());
        }
        let missing = required_len.saturating_sub(prefix.len());
        prefix
            .try_reserve_exact(missing)
            .map_err(|_| FallbackError::Io(io::Error::other("cover profile prefix bound")))?;
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        let read_timeout = timeout.min(remaining);
        let mut tail = vec![0_u8; missing];
        time::timeout(read_timeout, self.stream.read_exact(&mut tail))
            .await
            .map_err(|_| FallbackError::SessionTimeout)?
            .map_err(FallbackError::Io)?;
        prefix.extend_from_slice(&tail);
        Ok(())
    }

    /// Reads the compatible target ServerHello without consuming its next record.
    ///
    /// The shorter of `timeout` and the remaining fallback lifetime is used.
    ///
    /// # Errors
    ///
    /// Returns a byte-owning target read error suitable for exact fallback.
    pub async fn read_server_hello(
        &mut self,
        client: &ClientHello,
        timeout: Duration,
    ) -> Result<TargetServerHelloRead, TargetServerHelloReadError> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        read_server_hello(&mut self.stream, client, timeout.min(remaining)).await
    }

    /// Replays a previously consumed target prefix, then relays the same connection.
    ///
    /// This consumes the transaction so the fallback permit and socket cannot be
    /// accidentally reused after ownership passes to the unified raw relay. The
    /// owned client and cover sockets are handed to [`TcpRelay::relay_owned`], so
    /// the remaining raw pair can run on the best available backend instead of a
    /// borrowed userspace copy.
    ///
    /// # Errors
    ///
    /// Returns an I/O or absolute session-lifetime error.
    pub async fn relay(
        mut self,
        inbound: TcpStream,
        consumed_target_prefix: &[u8],
    ) -> Result<FallbackStats, FallbackError> {
        let _permit = match self.permit.take() {
            Some(permit) => permit,
            None => self
                .governor
                .try_acquire(AdmissionKind::Fallback)
                .map_err(FallbackError::Admission)?,
        };
        // Declared before the relay future so it drops last: the cover
        // descriptor is closed before its budget unit is released.
        let _fd_permit = self.fd_permit.take();
        let _warm_use = self.warm_use.take();
        let operation = async {
            let mut inbound = inbound;
            inbound
                .write_all(consumed_target_prefix)
                .await
                .map_err(FallbackError::Io)?;
            let outcome = self
                .relay
                // No idle liveness here: the absolute session deadline below
                // already bounds the whole relay, subsuming an idle window.
                .relay_owned(inbound, self.stream, RelayContext::owned())
                .await
                .map_err(FallbackError::Io)?;
            let returned_prefix =
                u64::try_from(consumed_target_prefix.len()).map_or(u64::MAX, |length| length);
            Ok(FallbackStats {
                forwarded_prefix: self.forwarded_prefix,
                returned_prefix,
                relay: RelayStats::new(
                    outcome.inbound_to_outbound(),
                    outcome.outbound_to_inbound(),
                ),
            })
        };

        time::timeout_at(self.deadline, operation)
            .await
            .map_err(|_| FallbackError::SessionTimeout)?
    }
}

fn prefix_len(prefix: &[u8]) -> u64 {
    u64::try_from(prefix.len()).unwrap_or(u64::MAX)
}

impl fmt::Debug for CoverConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoverConnection")
            .field("deadline", &self.deadline)
            .field("forwarded_prefix", &self.forwarded_prefix)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for RealityFallback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealityFallback")
            .field("target", &"[CONFIGURED]")
            .field("connect_timeout", &self.connect_timeout)
            .field("session_timeout", &self.session_timeout)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::{io, net::Ipv4Addr, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::timeout,
    };

    use super::{FallbackError, RealityFallback};
    use crate::{
        config::{NetworkConfig, RelayPolicy, ResourceGovernorConfig, WarmConnectionPolicy},
        network::NetworkEnvironment,
        protocol::reality::{ClientHello, SESSION_ID_LEN, X25519_GROUP, client_hello_fixtures},
        runtime::{FdBudget, PressureGauge, ResourceGovernor, ResourcePressure},
        server::warm_pool::WarmPoolAuthority,
        transport::TcpRelay,
    };

    const PREFIX: &[u8] = b"exact-fragmented-client-hello-prefix";
    const SUFFIX: &[u8] = b"bytes-read-after-fallback-connect";
    const RESPONSE: &[u8] = b"cover-response";

    fn test_fallback(target: String, config: &ResourceGovernorConfig) -> RealityFallback {
        let relay = TcpRelay::new(&RelayPolicy::default(), FdBudget::new(4_096))
            .expect("test relay must build");
        RealityFallback::new(target, ResourceGovernor::new(config), config, relay)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_mirror_consumes_preestablished_socket_byte_exactly() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("cover listener must bind");
        let target = listener
            .local_addr()
            .expect("cover address must exist")
            .to_string();
        let resource = ResourceGovernorConfig::default();
        let warm = WarmConnectionPolicy {
            min_ready: 1,
            max_ready: 2,
            max_connecting: 1,
            refill_batch: 1,
            idle_timeout_ms: 1_000,
            max_lifetime_ms: 2_000,
            shrink_delay_ms: 1_000,
        };
        let relay = TcpRelay::new(&RelayPolicy::default(), FdBudget::new(64))
            .expect("test relay must build");
        let pressure = PressureGauge::new();
        let fallback = RealityFallback::with_warm_pool(
            target,
            ResourceGovernor::new(&resource),
            &resource,
            relay,
            &NetworkConfig::default(),
            NetworkEnvironment::detect(),
            31,
            WarmPoolAuthority::new(&warm, 1, pressure),
            &warm,
        );
        fallback.activate();
        let (mut cover, _) = timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("pool warmup must remain bounded")
            .expect("cover must accept the pre-established TCP socket");
        timeout(Duration::from_secs(1), async {
            while fallback
                .warm_pool_snapshot()
                .is_none_or(|snapshot| snapshot.ready != 1)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pre-established socket must become ready");

        let mirror = fallback
            .mirror(PREFIX)
            .await
            .expect("authenticated mirror must check out the warm socket");
        let mut observed = vec![0_u8; PREFIX.len()];
        cover
            .read_exact(&mut observed)
            .await
            .expect("exact ClientHello prefix must reach the cover");
        assert_eq!(observed, PREFIX);
        let snapshot = fallback
            .warm_pool_snapshot()
            .expect("warm pool must be configured");
        assert_eq!(snapshot.generation, 31);
        assert_eq!(snapshot.checkout_total, 1);
        assert_eq!(snapshot.checkout_hit, 1);
        assert_eq!(snapshot.checkout_miss, 0);
        assert_eq!(snapshot.in_use, 1);
        assert_eq!(snapshot.cold_fallback, 0);

        drop(mirror);
        fallback.deactivate();
        assert_eq!(
            fallback
                .warm_pool_snapshot()
                .expect("warm pool must be configured")
                .in_use,
            0
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resource_pressure_discards_speculative_socket_before_cold_fallback() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("cover listener must bind");
        let target = listener
            .local_addr()
            .expect("cover address must exist")
            .to_string();
        let resource = ResourceGovernorConfig::default();
        let warm = WarmConnectionPolicy {
            min_ready: 1,
            max_ready: 1,
            max_connecting: 1,
            refill_batch: 1,
            idle_timeout_ms: 1_000,
            max_lifetime_ms: 2_000,
            shrink_delay_ms: 1_000,
        };
        let relay = TcpRelay::new(&RelayPolicy::default(), FdBudget::new(64))
            .expect("test relay must build");
        let pressure = PressureGauge::new();
        let fallback = RealityFallback::with_warm_pool(
            target,
            ResourceGovernor::new(&resource),
            &resource,
            relay,
            &NetworkConfig::default(),
            NetworkEnvironment::detect(),
            32,
            WarmPoolAuthority::new(&warm, 1, pressure.clone()),
            &warm,
        );
        fallback.activate();
        let (stale, _) = timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("pool warmup must remain bounded")
            .expect("cover must accept the pre-established socket");
        timeout(Duration::from_secs(1), async {
            while fallback
                .warm_pool_snapshot()
                .is_none_or(|snapshot| snapshot.ready != 1)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pre-established socket must become ready");
        pressure.set(ResourcePressure::Pressure);
        timeout(Duration::from_secs(1), async {
            while fallback
                .warm_pool_snapshot()
                .is_some_and(|snapshot| snapshot.ready != 0)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pressure must promptly yield speculative descriptor capacity");

        let (mirror, cold_cover, observed) = timeout(Duration::from_secs(2), async {
            let mirror = fallback
                .mirror(PREFIX)
                .await
                .expect("cold fallback must recover the cover transaction");
            let (mut cover, _) = listener.accept().await?;
            let mut observed = vec![0_u8; PREFIX.len()];
            cover.read_exact(&mut observed).await?;
            Ok::<_, io::Error>((mirror, cover, observed))
        })
        .await
        .expect("pressure fallback must remain bounded")
        .expect("cold cover must receive the prefix");
        assert_eq!(observed, PREFIX);
        let snapshot = fallback
            .warm_pool_snapshot()
            .expect("warm pool must be configured");
        assert_eq!(snapshot.stale_discard, 0);
        assert!(snapshot.checkout_miss >= 1);
        assert_eq!(snapshot.cold_fallback, 1);

        drop((mirror, cold_cover, stale));
        fallback.deactivate();
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("pair listener must bind");
        let client = TcpStream::connect(listener.local_addr().expect("pair address must exist"))
            .await
            .expect("pair client must connect");
        let (server, _) = listener.accept().await.expect("pair must accept");
        (client, server)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn forwards_consumed_prefix_byte_exactly_before_live_bytes() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("cover listener must bind");
        let target = listener
            .local_addr()
            .expect("cover listener address must exist")
            .to_string();
        let config = ResourceGovernorConfig::default();
        let fallback = test_fallback(target, &config);
        let (mut client, inbound) = tcp_pair().await;

        let exchange = async {
            let fallback_io = fallback.relay(inbound, PREFIX);
            let client_io = async {
                client.write_all(SUFFIX).await?;
                client.shutdown().await?;
                let mut response = Vec::new();
                client.read_to_end(&mut response).await?;
                Ok::<_, io::Error>(response)
            };
            let cover_io = async {
                let (mut cover, _) = listener.accept().await?;
                let mut request = Vec::new();
                cover.read_to_end(&mut request).await?;
                cover.write_all(RESPONSE).await?;
                cover.shutdown().await?;
                Ok::<_, io::Error>(request)
            };
            tokio::join!(fallback_io, client_io, cover_io)
        };
        let (fallback_result, client_result, cover_result) =
            timeout(Duration::from_secs(2), exchange)
                .await
                .expect("fallback exchange must finish");

        let stats = fallback_result.expect("fallback must succeed");
        let response = client_result.expect("client I/O must succeed");
        let request = cover_result.expect("cover I/O must succeed");
        let mut expected = PREFIX.to_vec();
        expected.extend_from_slice(SUFFIX);
        assert_eq!(request, expected);
        assert_eq!(response, RESPONSE);
        assert_eq!(stats.forwarded_prefix_bytes(), PREFIX.len() as u64);
        assert_eq!(stats.returned_prefix_bytes(), 0);
        assert_eq!(
            stats.relay().inbound_to_outbound_bytes(),
            SUFFIX.len() as u64
        );
        assert_eq!(
            stats.relay().outbound_to_inbound_bytes(),
            RESPONSE.len() as u64
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn coalesced_flight_prefix_rejoins_its_unread_body_byte_exactly() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("cover listener must bind");
        let target = listener
            .local_addr()
            .expect("cover listener address must exist")
            .to_string();
        let config = ResourceGovernorConfig::default();
        let fallback = test_fallback(target, &config);
        let client_hello = client_hello();
        let mut target_flight = target_server_hello_record();
        target_flight.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        target_flight.extend_from_slice(&opaque_record(23, 600, 0xa5));
        let minimum_inspected_prefix_len = target_server_hello_record().len() + 6 + 6;
        let (mut client, inbound) = tcp_pair().await;

        let exchange = async {
            let fallback_io = async {
                let mut connection = fallback
                    .connect(PREFIX)
                    .await
                    .expect("cover connection must open");
                let flight = connection
                    .read_server_flight(&client_hello, Duration::from_secs(1))
                    .await
                    .expect("coalesced cover flight must be classified");
                let (_, _, inspected_prefix) = flight.into_parts();
                assert!(target_flight.starts_with(&inspected_prefix));
                assert!(inspected_prefix.len() >= minimum_inspected_prefix_len);
                connection.relay(inbound, &inspected_prefix).await
            };
            let client_io = async {
                client.write_all(SUFFIX).await?;
                client.shutdown().await?;
                let mut response = Vec::new();
                client.read_to_end(&mut response).await?;
                Ok::<_, io::Error>(response)
            };
            let cover_io = async {
                let (mut cover, _) = listener.accept().await?;
                let mut prefix = vec![0_u8; PREFIX.len()];
                cover.read_exact(&mut prefix).await?;
                cover.write_all(&target_flight).await?;
                cover.write_all(RESPONSE).await?;
                let mut suffix = Vec::new();
                cover.read_to_end(&mut suffix).await?;
                cover.shutdown().await?;
                Ok::<_, io::Error>((prefix, suffix))
            };
            tokio::join!(fallback_io, client_io, cover_io)
        };
        let (fallback_result, client_result, cover_result) =
            timeout(Duration::from_secs(2), exchange)
                .await
                .expect("coalesced fallback exchange must finish");

        let stats = fallback_result.expect("same cover connection must relay");
        let response = client_result.expect("client I/O must succeed");
        let (prefix, suffix) = cover_result.expect("cover I/O must succeed");
        let mut expected_response = target_flight.clone();
        expected_response.extend_from_slice(RESPONSE);
        assert_eq!(prefix, PREFIX);
        assert_eq!(suffix, SUFFIX);
        assert_eq!(response, expected_response);
        assert!(
            stats.returned_prefix_bytes()
                >= u64::try_from(minimum_inspected_prefix_len)
                    .expect("test prefix length must fit u64")
        );
        assert!(
            stats.returned_prefix_bytes()
                <= u64::try_from(target_flight.len()).expect("test flight length must fit u64")
        );
        assert_eq!(
            stats
                .returned_prefix_bytes()
                .checked_add(stats.relay().outbound_to_inbound_bytes())
                .expect("test byte count must not overflow"),
            u64::try_from(target_flight.len() + RESPONSE.len())
                .expect("test response length must fit u64")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn partial_positional_record_rejoins_after_shape_timeout() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("cover listener must bind");
        let target = listener
            .local_addr()
            .expect("cover listener address must exist")
            .to_string();
        let config = ResourceGovernorConfig::default();
        let fallback = test_fallback(target, &config);
        let client_hello = client_hello();
        let mut initial = target_server_hello_record();
        initial.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        initial.extend_from_slice(&opaque_record(23, 32, 0x11));
        let second = opaque_record(23, 64, 0x22);
        initial.extend_from_slice(&second[..8]);
        let mut remainder = second[8..].to_vec();
        remainder.extend_from_slice(&opaque_record(23, 48, 0x33));
        remainder.extend_from_slice(&opaque_record(23, 40, 0x44));
        let (mut client, inbound) = tcp_pair().await;

        let exchange = async {
            let fallback_io = async {
                let mut connection = fallback
                    .connect(PREFIX)
                    .await
                    .expect("cover connection must open");
                let error = connection
                    .read_server_flight(&client_hello, Duration::from_millis(10))
                    .await
                    .expect_err("partial positional record must time out");
                let (_, inspected_prefix) = error.into_parts();
                assert_eq!(inspected_prefix, initial);
                connection.relay(inbound, &inspected_prefix).await
            };
            let client_io = async {
                client.write_all(SUFFIX).await?;
                client.shutdown().await?;
                let mut response = Vec::new();
                client.read_to_end(&mut response).await?;
                Ok::<_, io::Error>(response)
            };
            let cover_io = async {
                let (mut cover, _) = listener.accept().await?;
                let mut prefix = vec![0_u8; PREFIX.len()];
                cover.read_exact(&mut prefix).await?;
                cover.write_all(&initial).await?;
                tokio::time::sleep(Duration::from_millis(30)).await;
                cover.write_all(&remainder).await?;
                cover.write_all(RESPONSE).await?;
                let mut suffix = Vec::new();
                cover.read_to_end(&mut suffix).await?;
                cover.shutdown().await?;
                Ok::<_, io::Error>((prefix, suffix))
            };
            tokio::join!(fallback_io, client_io, cover_io)
        };
        let (fallback_result, client_result, cover_result) =
            timeout(Duration::from_secs(2), exchange)
                .await
                .expect("partial positional fallback exchange must finish");

        let stats = fallback_result.expect("same cover connection must relay");
        let response = client_result.expect("client I/O must succeed");
        let (prefix, suffix) = cover_result.expect("cover I/O must succeed");
        let mut expected_response = initial.clone();
        expected_response.extend_from_slice(&remainder);
        expected_response.extend_from_slice(RESPONSE);
        assert_eq!(prefix, PREFIX);
        assert_eq!(suffix, SUFFIX);
        assert_eq!(response, expected_response);
        assert_eq!(stats.returned_prefix_bytes(), initial.len() as u64);
        assert_eq!(
            stats.relay().outbound_to_inbound_bytes(),
            (remainder.len() + RESPONSE.len()) as u64
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn inspected_target_response_can_rejoin_same_fallback_connection() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("cover listener must bind");
        let target = listener
            .local_addr()
            .expect("cover listener address must exist")
            .to_string();
        let config = ResourceGovernorConfig::default();
        let fallback = test_fallback(target, &config);
        let client_hello = client_hello();
        let target_record = target_server_hello_record();
        let (mut client, inbound) = tcp_pair().await;

        let exchange = async {
            let fallback_io = async {
                let mut connection = fallback
                    .connect(PREFIX)
                    .await
                    .expect("cover connection must open");
                let target_hello = connection
                    .read_server_hello(&client_hello, Duration::from_secs(1))
                    .await
                    .expect("target ServerHello must be compatible");
                connection.relay(inbound, target_hello.wire_record()).await
            };
            let client_io = async {
                client.write_all(SUFFIX).await?;
                client.shutdown().await?;
                let mut response = Vec::new();
                client.read_to_end(&mut response).await?;
                Ok::<_, io::Error>(response)
            };
            let cover_io = async {
                let (mut cover, _) = listener.accept().await?;
                let mut prefix = vec![0_u8; PREFIX.len()];
                cover.read_exact(&mut prefix).await?;
                cover.write_all(&target_record).await?;
                let mut suffix = Vec::new();
                cover.read_to_end(&mut suffix).await?;
                cover.write_all(RESPONSE).await?;
                cover.shutdown().await?;
                Ok::<_, io::Error>((prefix, suffix))
            };
            tokio::join!(fallback_io, client_io, cover_io)
        };
        let (fallback_result, client_result, cover_result) =
            timeout(Duration::from_secs(2), exchange)
                .await
                .expect("inspected fallback exchange must finish");

        let stats = fallback_result.expect("same cover connection must relay");
        let response = client_result.expect("client I/O must succeed");
        let (prefix, suffix) = cover_result.expect("cover I/O must succeed");
        let mut expected_response = target_record.clone();
        expected_response.extend_from_slice(RESPONSE);
        assert_eq!(prefix, PREFIX);
        assert_eq!(suffix, SUFFIX);
        assert_eq!(response, expected_response);
        assert_eq!(stats.forwarded_prefix_bytes(), PREFIX.len() as u64);
        assert_eq!(stats.returned_prefix_bytes(), target_record.len() as u64);
        assert_eq!(
            stats.relay().inbound_to_outbound_bytes(),
            SUFFIX.len() as u64
        );
        assert_eq!(
            stats.relay().outbound_to_inbound_bytes(),
            RESPONSE.len() as u64
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn timeout_releases_fallback_admission_permit() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("cover listener must bind");
        let mut config = ResourceGovernorConfig {
            max_fallbacks: 1,
            fallback_timeout_ms: 10,
            ..ResourceGovernorConfig::default()
        };
        config.connect_timeout_ms = 100;
        let fallback = test_fallback(
            listener
                .local_addr()
                .expect("cover listener address must exist")
                .to_string(),
            &config,
        );

        for _ in 0..2 {
            let (_client, inbound) = tcp_pair().await;
            assert!(matches!(
                fallback.relay(inbound, &[]).await,
                Err(FallbackError::SessionTimeout)
            ));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refused_cover_target_fails_closed_and_releases_capacity() {
        // Reserve a port and drop the listener so cover connects are refused.
        let refused_target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("probe listener must bind")
            .local_addr()
            .expect("probe address must exist")
            .to_string();
        let config = ResourceGovernorConfig::default();
        let fallback = test_fallback(refused_target, &config);

        // Two attempts: the second proves the refused first attempt released
        // its fallback admission permit instead of leaking capacity.
        for _ in 0..2 {
            let (_client, inbound) = tcp_pair().await;
            let error = fallback
                .relay(inbound, PREFIX)
                .await
                .expect_err("a refused cover target must fail the fallback");
            match error {
                FallbackError::Io(error) => assert_eq!(
                    error.kind(),
                    io::ErrorKind::ConnectionRefused,
                    "a refused cover target must surface the connect refusal"
                ),
                other => panic!("expected a fallback I/O error, got {other}"),
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn target_mirror_acquires_fallback_capacity_only_when_relaying() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("cover listener must bind");
        let config = ResourceGovernorConfig {
            max_fallbacks: 0,
            ..ResourceGovernorConfig::default()
        };
        let fallback = test_fallback(
            listener
                .local_addr()
                .expect("cover listener address must exist")
                .to_string(),
            &config,
        );

        let connection = fallback
            .mirror(PREFIX)
            .await
            .expect("short target mirror must not consume fallback capacity");
        let (mut cover, _) = listener.accept().await.expect("mirror must connect");
        let mut received = vec![0_u8; PREFIX.len()];
        cover
            .read_exact(&mut received)
            .await
            .expect("mirror prefix must arrive");
        assert_eq!(received, PREFIX);

        let (_client, inbound) = tcp_pair().await;
        assert!(matches!(
            connection.relay(inbound, &[]).await,
            Err(FallbackError::Admission(_))
        ));
    }

    fn client_hello() -> ClientHello {
        ClientHello::parse_message(&client_hello_fixtures::client_hello_with_key_share(
            [0x44; 32],
            &[0x11; SESSION_ID_LEN],
            "www.example.com",
            &[b"h2"],
            X25519_GROUP,
            &[0x22; 32],
        ))
        .expect("test ClientHello must parse")
    }

    fn target_server_hello_record() -> Vec<u8> {
        let mut extensions = Vec::new();
        push_extension(&mut extensions, 0x002b, &0x0304_u16.to_be_bytes());
        let mut key_share = Vec::new();
        key_share.extend_from_slice(&X25519_GROUP.to_be_bytes());
        key_share.extend_from_slice(&32_u16.to_be_bytes());
        key_share.extend_from_slice(&[0x55; 32]);
        push_extension(&mut extensions, 0x0033, &key_share);

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303_u16.to_be_bytes());
        body.extend_from_slice(&[0x33; 32]);
        body.push(u8::try_from(SESSION_ID_LEN).expect("test session ID must fit"));
        body.extend_from_slice(&[0x11; SESSION_ID_LEN]);
        body.extend_from_slice(&0x1301_u16.to_be_bytes());
        body.push(0);
        body.extend_from_slice(
            &u16::try_from(extensions.len())
                .expect("test extensions must fit")
                .to_be_bytes(),
        );
        body.extend_from_slice(&extensions);

        let mut message = vec![2];
        let message_len = u32::try_from(body.len()).expect("test ServerHello body must fit");
        message.extend_from_slice(&message_len.to_be_bytes()[1..]);
        message.extend_from_slice(&body);

        let mut record = vec![22, 3, 3];
        record.extend_from_slice(
            &u16::try_from(message.len())
                .expect("test record must fit")
                .to_be_bytes(),
        );
        record.extend_from_slice(&message);
        record
    }

    fn opaque_record(content_type: u8, body_len: usize, fill: u8) -> Vec<u8> {
        let mut record = vec![content_type, 3, 3];
        record.extend_from_slice(
            &u16::try_from(body_len)
                .expect("test record body must fit")
                .to_be_bytes(),
        );
        record.resize(5 + body_len, fill);
        record
    }

    fn push_extension(output: &mut Vec<u8>, extension_type: u16, value: &[u8]) {
        output.extend_from_slice(&extension_type.to_be_bytes());
        output.extend_from_slice(
            &u16::try_from(value.len())
                .expect("test extension must fit")
                .to_be_bytes(),
        );
        output.extend_from_slice(value);
    }
}
