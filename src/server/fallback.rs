use std::{error::Error, fmt, io, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{self, Instant},
};

use crate::{
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
use crate::config::node::network::NetworkConfig;
use crate::runtime::policy::{ResourceGovernorPolicy, WarmConnectionPolicy};

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
    fd_permit: Option<crate::transport::FdPermit>,
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
        config: &ResourceGovernorPolicy,
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
        config: &ResourceGovernorPolicy,
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
        config: &ResourceGovernorPolicy,
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
        config: &ResourceGovernorPolicy,
        relay: TcpRelay,
        network: &NetworkConfig,
        environment: NetworkEnvironment,
        warm: Option<(u64, WarmPoolAuthority, &WarmConnectionPolicy)>,
    ) -> Self {
        let connector = super::connector::DestinationConnector::with_environment(
            Duration::from_millis(config.connect_timeout_ms),
            *network,
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
        let forwarded_prefix = u64::try_from(consumed_prefix.len()).unwrap_or(u64::MAX);
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
            let returned_prefix = u64::try_from(consumed_target_prefix.len()).unwrap_or(u64::MAX);
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
mod tests;
