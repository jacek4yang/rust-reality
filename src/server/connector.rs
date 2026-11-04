//! Outbound TCP dialing for proxied destinations.
//!
//! [`DestinationConnector`] turns a VLESS [`Destination`] into a connected
//! [`TcpStream`]: numeric literals are dialed directly, hostnames are resolved
//! asynchronously, candidate addresses are ordered by the
//! [`ConnectionPlanner`] for the current [`NetworkEnvironment`], and each
//! socket is charged against the outbound [`FdBudget`] so the returned
//! [`AccountedTcpStream`] releases its permit on drop. Failures are reported
//! as [`DestinationConnectError`] so callers can classify them.

use std::{
    error::Error,
    fmt, io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use tokio::{
    net::TcpStream,
    task::JoinSet,
    time::{self, Instant},
};

use crate::{config::node::network::NetworkConfig, network::DialTuning};
use crate::{
    network::{AddressFamily, ConnectionPlanner, NetworkEnvironment},
    protocol::vless::{Address, Destination},
    transport::{FdBudget, FdPermit, UNITS_OUTBOUND_SOCKET},
};

const MAX_PRE_RESOLVED_IPS: usize = 64;

/// Returns a socket address when `host` is a numeric IP literal, so callers
/// can dial it directly without entering the blocking system resolver.
/// Real hostnames return `None` and keep asynchronous resolution.
pub(crate) fn literal_socket_addr(host: &str, port: u16) -> Option<SocketAddr> {
    host.parse::<IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, port))
}

/// Splits a `host:port` target, tolerating bracketed IPv6 literals. Bare IPv6
/// literals without a port are not valid targets and return `None`.
fn split_target(target: &str) -> Option<(&str, u16)> {
    let (host, port) = target.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let host = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty() {
        return None;
    }
    Some((host, port))
}

/// Connects to a combined `host:port` target, skipping the blocking resolver
/// when the target is a numeric socket address literal.
#[cfg(test)]
pub(crate) async fn connect_target(target: &str) -> io::Result<TcpStream> {
    DestinationConnector::new(Duration::from_secs(86_400))
        .connect_target(target)
        .await
        .map_err(DestinationConnectError::into_io)
}

/// Establishes outbound TCP connections for authorized VLESS requests.
#[derive(Clone, Debug)]
pub struct DestinationConnector {
    connect_timeout: Duration,
    planner: ConnectionPlanner,
}

impl DestinationConnector {
    pub fn new(connect_timeout: Duration) -> Self {
        Self::with_environment(
            connect_timeout,
            NetworkConfig::default(),
            NetworkEnvironment::detect(),
        )
    }

    /// Creates a connector using one process-lifetime environment snapshot.
    #[must_use]
    pub fn with_environment(
        connect_timeout: Duration,
        config: NetworkConfig,
        environment: NetworkEnvironment,
    ) -> Self {
        Self {
            connect_timeout,
            planner: ConnectionPlanner::new(DialTuning::for_policy(config.ip()), environment),
        }
    }

    pub const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Reuses the same policy and process-lifetime health state with a
    /// call-site-specific overall deadline.
    #[must_use]
    pub fn with_timeout(&self, connect_timeout: Duration) -> Self {
        Self {
            connect_timeout,
            planner: self.planner.clone(),
        }
    }

    pub async fn connect(
        &self,
        destination: &Destination,
    ) -> Result<TcpStream, DestinationConnectError> {
        self.connect_resolved(destination, &[]).await
    }

    /// Connects a domain to the exact bounded address snapshot already used by
    /// routing. Empty snapshots retain normal system resolution behavior.
    pub async fn connect_resolved(
        &self,
        destination: &Destination,
        resolved_ips: &[IpAddr],
    ) -> Result<TcpStream, DestinationConnectError> {
        let deadline = self.deadline()?;
        let addresses = self
            .destination_addresses(destination, resolved_ips, deadline)
            .await?;
        let (stream, _) = self.race(addresses, deadline, None).await?;
        crate::transport::TcpAcceptor::configure_stream(&stream)
            .map_err(DestinationConnectError::Io)?;
        Ok(stream)
    }

    /// Connects while reserving one descriptor per live candidate. The
    /// winning permit is returned with the socket; cancelled and failed
    /// candidates release theirs through RAII before this method returns.
    pub async fn connect_resolved_accounted(
        &self,
        destination: &Destination,
        resolved_ips: &[IpAddr],
        fd_budget: &FdBudget,
    ) -> Result<AccountedTcpStream, DestinationConnectError> {
        let deadline = self.deadline()?;
        let addresses = self
            .destination_addresses(destination, resolved_ips, deadline)
            .await?;
        self.connect_addresses_accounted(addresses, deadline, fd_budget)
            .await
    }

    /// Connects to a locally resolved endpoint under the shared policy.
    pub async fn connect_host(
        &self,
        host: &str,
        port: u16,
    ) -> Result<TcpStream, DestinationConnectError> {
        let deadline = self.deadline()?;
        let addresses = self.host_addresses(host, port, deadline).await?;
        let (stream, _) = self.race(addresses, deadline, None).await?;
        crate::transport::TcpAcceptor::configure_stream(&stream)
            .map_err(DestinationConnectError::Io)?;
        Ok(stream)
    }

    /// Connects to a locally resolved endpoint with strict candidate FD
    /// accounting.
    pub async fn connect_host_accounted(
        &self,
        host: &str,
        port: u16,
        fd_budget: &FdBudget,
    ) -> Result<AccountedTcpStream, DestinationConnectError> {
        let deadline = self.deadline()?;
        let addresses = self.host_addresses(host, port, deadline).await?;
        self.connect_addresses_accounted(addresses, deadline, fd_budget)
            .await
    }

    /// Connects to a combined `host:port` endpoint under one deadline.
    pub async fn connect_target(&self, target: &str) -> Result<TcpStream, DestinationConnectError> {
        let deadline = self.deadline()?;
        let addresses = self.target_addresses(target, deadline).await?;
        let (stream, _) = self.race(addresses, deadline, None).await?;
        crate::transport::TcpAcceptor::configure_stream(&stream)
            .map_err(DestinationConnectError::Io)?;
        Ok(stream)
    }

    /// Connects to a combined `host:port` endpoint with strict candidate FD
    /// accounting.
    pub async fn connect_target_accounted(
        &self,
        target: &str,
        fd_budget: &FdBudget,
    ) -> Result<AccountedTcpStream, DestinationConnectError> {
        let deadline = self.deadline()?;
        let addresses = self.target_addresses(target, deadline).await?;
        self.connect_addresses_accounted(addresses, deadline, fd_budget)
            .await
    }

    fn deadline(&self) -> Result<Instant, DestinationConnectError> {
        Instant::now()
            .checked_add(self.connect_timeout)
            .ok_or(DestinationConnectError::TimedOut {
                timeout: self.connect_timeout,
            })
    }

    async fn destination_addresses(
        &self,
        destination: &Destination,
        resolved_ips: &[IpAddr],
        deadline: Instant,
    ) -> Result<Vec<SocketAddr>, DestinationConnectError> {
        if resolved_ips.len() > MAX_PRE_RESOLVED_IPS {
            return Err(DestinationConnectError::TooManyResolvedAddresses);
        }
        match destination.address() {
            Address::Ipv4(address) => Ok(vec![SocketAddr::new(
                IpAddr::V4(*address),
                destination.port(),
            )]),
            Address::Ipv6(address) => Ok(vec![SocketAddr::new(
                IpAddr::V6(*address),
                destination.port(),
            )]),
            Address::Domain(_) if !resolved_ips.is_empty() => Ok(resolved_ips
                .iter()
                .copied()
                .map(|ip| SocketAddr::new(ip, destination.port()))
                .collect()),
            Address::Domain(domain) => {
                if let Some(address) = literal_socket_addr(domain, destination.port()) {
                    return Ok(vec![address]);
                }
                // Client-requested destinations resolve as dynamic values:
                // cached only when the upstream answer carries a real TTL.
                let ips = super::dns::shared()
                    .resolve(
                        domain,
                        super::dns::IpFamily::Any,
                        deadline.saturating_duration_since(Instant::now()),
                    )
                    .await
                    .map_err(|error| self.map_dns_error(error))?;
                Self::collect_ips(&ips, destination.port())
            }
        }
    }

    async fn host_addresses(
        &self,
        host: &str,
        port: u16,
        deadline: Instant,
    ) -> Result<Vec<SocketAddr>, DestinationConnectError> {
        if let Some(address) = literal_socket_addr(host, port) {
            return Ok(vec![address]);
        }
        // `connect_host` dials only operator-configured fixed peers, so this
        // resolution is cached as a static value in every resolver mode.
        let ips = super::dns::shared()
            .resolve_static(
                host,
                super::dns::IpFamily::Any,
                deadline.saturating_duration_since(Instant::now()),
            )
            .await
            .map_err(|error| self.map_dns_error(error))?;
        Self::collect_ips(&ips, port)
    }

    async fn target_addresses(
        &self,
        target: &str,
        deadline: Instant,
    ) -> Result<Vec<SocketAddr>, DestinationConnectError> {
        if let Ok(address) = target.parse::<SocketAddr>() {
            return Ok(vec![address]);
        }
        let Some((host, port)) = split_target(target) else {
            return Err(DestinationConnectError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("target {target:?} is not a host:port endpoint"),
            )));
        };
        if let Some(address) = literal_socket_addr(host, port) {
            return Ok(vec![address]);
        }
        // `connect_target` dials only operator-configured targets (the REALITY
        // cover destination), so this resolution is cached as a static value.
        let ips = super::dns::shared()
            .resolve_static(
                host,
                super::dns::IpFamily::Any,
                deadline.saturating_duration_since(Instant::now()),
            )
            .await
            .map_err(|error| self.map_dns_error(error))?;
        Self::collect_ips(&ips, port)
    }

    fn map_dns_error(&self, error: super::dns::DnsError) -> DestinationConnectError {
        match error {
            super::dns::DnsError::Timeout => DestinationConnectError::TimedOut {
                timeout: self.connect_timeout,
            },
            super::dns::DnsError::TooManyAddresses => {
                DestinationConnectError::TooManyResolvedAddresses
            }
            super::dns::DnsError::Allocation => DestinationConnectError::Allocation,
            other => DestinationConnectError::Io(io::Error::other(other)),
        }
    }

    fn collect_ips(ips: &[IpAddr], port: u16) -> Result<Vec<SocketAddr>, DestinationConnectError> {
        let mut addresses = Vec::new();
        addresses
            .try_reserve_exact(ips.len().min(MAX_PRE_RESOLVED_IPS))
            .map_err(|_| DestinationConnectError::Allocation)?;
        for ip in ips {
            let address = SocketAddr::new(*ip, port);
            if addresses.contains(&address) {
                continue;
            }
            if addresses.len() == MAX_PRE_RESOLVED_IPS {
                return Err(DestinationConnectError::TooManyResolvedAddresses);
            }
            addresses.push(address);
        }
        Ok(addresses)
    }

    async fn connect_addresses_accounted(
        &self,
        addresses: Vec<SocketAddr>,
        deadline: Instant,
        fd_budget: &FdBudget,
    ) -> Result<AccountedTcpStream, DestinationConnectError> {
        let (stream, permit) = self
            .race(addresses, deadline, Some(fd_budget.clone()))
            .await?;
        crate::transport::TcpAcceptor::configure_stream(&stream)
            .map_err(DestinationConnectError::Io)?;
        Ok(AccountedTcpStream {
            stream,
            fd_permit: permit.ok_or(DestinationConnectError::DescriptorBudget)?,
        })
    }

    async fn race(
        &self,
        addresses: Vec<SocketAddr>,
        deadline: Instant,
        fd_budget: Option<FdBudget>,
    ) -> Result<(TcpStream, Option<FdPermit>), DestinationConnectError> {
        race_with(
            self.planner.clone(),
            addresses,
            deadline,
            self.connect_timeout,
            fd_budget,
            TcpStream::connect,
        )
        .await
    }
}

/// A connected socket retaining its lifetime descriptor reservation.
pub struct AccountedTcpStream {
    stream: TcpStream,
    fd_permit: FdPermit,
}

impl AccountedTcpStream {
    /// Reassembles an already connected socket and its lifetime reservation.
    #[must_use]
    pub(crate) fn from_parts(stream: TcpStream, fd_permit: FdPermit) -> Self {
        Self { stream, fd_permit }
    }

    /// Separates the socket and its lifetime permit.
    #[must_use]
    pub fn into_parts(self) -> (TcpStream, FdPermit) {
        (self.stream, self.fd_permit)
    }

    /// Performs a local, non-waiting idle-socket health check.
    ///
    /// EOF, a reset, and unsolicited bytes all make a preconnected protocol
    /// socket unusable; one nonblocking `recv` reports each of those states and
    /// `WouldBlock` is the healthy result. This deliberately sends no ping and
    /// therefore adds no network RTT at checkout.
    pub(crate) fn idle_healthy(&self) -> bool {
        let mut byte = [0_u8; 1];
        match self.stream.try_read(&mut byte) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => true,
            Ok(_) | Err(_) => false,
        }
    }
}

struct AttemptResult<T> {
    address: SocketAddr,
    started: Instant,
    outcome: io::Result<T>,
    permit: Option<FdPermit>,
}

async fn race_with<T, C, F>(
    planner: ConnectionPlanner,
    addresses: Vec<SocketAddr>,
    deadline: Instant,
    timeout: Duration,
    fd_budget: Option<FdBudget>,
    connector: C,
) -> Result<(T, Option<FdPermit>), DestinationConnectError>
where
    T: Send + 'static,
    C: Fn(SocketAddr) -> F + Clone + Send + Sync + 'static,
    F: std::future::Future<Output = io::Result<T>> + Send + 'static,
{
    let addresses = planner.plan(&addresses);
    if addresses.is_empty() {
        return Err(DestinationConnectError::NoAddressesForPolicy);
    }
    if addresses.len() == 1 {
        let address = addresses[0];
        let permit = match fd_budget.as_ref() {
            Some(budget) => Some(
                budget
                    .try_acquire(UNITS_OUTBOUND_SOCKET)
                    .ok_or(DestinationConnectError::DescriptorBudget)?,
            ),
            None => None,
        };
        let started = Instant::now();
        let outcome = time::timeout_at(deadline, connector(address)).await;
        return match outcome {
            Ok(Ok(value)) => {
                planner.record_success(AddressFamily::of(address.ip()), started.elapsed());
                Ok((value, permit))
            }
            Ok(Err(error)) => {
                planner.environment().record_connect_error(
                    AddressFamily::of(address.ip()),
                    &error,
                    planner.hard_failure_penalty(),
                );
                Err(DestinationConnectError::Io(error))
            }
            Err(_) => Err(DestinationConnectError::TimedOut { timeout }),
        };
    }
    let first_family = AddressFamily::of(addresses[0].ip());
    if addresses
        .iter()
        .all(|address| AddressFamily::of(address.ip()) == first_family)
    {
        let mut recycled = None;
        let mut last_error = None;
        for address in addresses {
            let permit = match fd_budget.as_ref() {
                Some(budget) => Some(
                    recycled
                        .take()
                        .or_else(|| budget.try_acquire(UNITS_OUTBOUND_SOCKET))
                        .ok_or(DestinationConnectError::DescriptorBudget)?,
                ),
                None => None,
            };
            let started = Instant::now();
            match time::timeout_at(deadline, connector.clone()(address)).await {
                Ok(Ok(value)) => {
                    planner.record_success(first_family, started.elapsed());
                    return Ok((value, permit));
                }
                Ok(Err(error)) => {
                    planner.environment().record_connect_error(
                        first_family,
                        &error,
                        planner.hard_failure_penalty(),
                    );
                    last_error = Some(error);
                    recycled = permit;
                }
                Err(_) => return Err(DestinationConnectError::TimedOut { timeout }),
            }
        }
        return Err(DestinationConnectError::Io(
            last_error.expect("a non-empty single-family plan must attempt an address"),
        ));
    }

    let mut tasks = JoinSet::new();
    let mut active = Vec::with_capacity(2);
    let mut recycled = Vec::with_capacity(2);
    let mut next = 0;
    let mut launch_at = Instant::now();
    let mut fd_blocked = false;
    let mut last_error = None;

    loop {
        while next < addresses.len()
            && tasks.len() < 2
            && Instant::now() >= launch_at
            && !fd_blocked
        {
            let permit = match attempt_permit(fd_budget.as_ref(), &mut recycled) {
                Some(permit) => permit,
                None if tasks.is_empty() => {
                    return Err(DestinationConnectError::DescriptorBudget);
                }
                None => {
                    fd_blocked = true;
                    break;
                }
            };
            let address = addresses[next];
            next += 1;
            active.push(address);
            let connect = connector.clone();
            tasks.spawn(async move {
                let started = Instant::now();
                let outcome = connect(address).await;
                AttemptResult {
                    address,
                    started,
                    outcome,
                    permit,
                }
            });
            launch_at = Instant::now() + planner.fallback_delay();
        }

        if tasks.is_empty() {
            return Err(last_error.map_or(
                DestinationConnectError::NoAddressesForPolicy,
                DestinationConnectError::Io,
            ));
        }

        tokio::select! {
            () = time::sleep_until(deadline) => {
                abort_and_drain(&mut tasks).await;
                return Err(DestinationConnectError::TimedOut { timeout });
            }
            completed = tasks.join_next() => {
                let Some(completed) = completed else {
                    continue;
                };
                let result = match completed {
                    Ok(result) => result,
                    Err(error) => {
                        abort_and_drain(&mut tasks).await;
                        return Err(DestinationConnectError::Io(io::Error::other(
                            format!("connection attempt task failed: {error}"),
                        )));
                    }
                };
                if let Some(index) = active.iter().position(|address| *address == result.address) {
                    active.swap_remove(index);
                }
                match result.outcome {
                    Ok(value) => {
                        let winning_family = AddressFamily::of(result.address.ip());
                        planner.record_success(winning_family, result.started.elapsed());
                        for address in &active {
                            let family = AddressFamily::of(address.ip());
                            if family != winning_family {
                                planner.environment().record_alternate_success(
                                    winning_family,
                                    family,
                                );
                            }
                        }
                        abort_and_drain(&mut tasks).await;
                        return Ok((value, result.permit));
                    }
                    Err(error) => {
                        planner.environment().record_connect_error(
                            AddressFamily::of(result.address.ip()),
                            &error,
                            planner.hard_failure_penalty(),
                        );
                        last_error = Some(error);
                        if let Some(permit) = result.permit {
                            recycled.push(permit);
                        }
                        fd_blocked = false;
                        launch_at = Instant::now();
                    }
                }
            }
            () = time::sleep_until(launch_at),
                if next < addresses.len() && tasks.len() < 2 && !fd_blocked => {}
        }
    }
}

fn attempt_permit(
    fd_budget: Option<&FdBudget>,
    recycled: &mut Vec<FdPermit>,
) -> Option<Option<FdPermit>> {
    let Some(fd_budget) = fd_budget else {
        return Some(None);
    };
    recycled
        .pop()
        .or_else(|| fd_budget.try_acquire(UNITS_OUTBOUND_SOCKET))
        .map(Some)
}

async fn abort_and_drain<T: 'static>(tasks: &mut JoinSet<T>) {
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

/// An error produced while connecting to a VLESS destination.
#[derive(Debug)]
pub enum DestinationConnectError {
    /// The connection attempt exceeded its configured deadline.
    TimedOut { timeout: Duration },

    /// Address resolution or TCP connection establishment failed.
    Io(io::Error),

    /// The descriptor budget could not reserve a candidate socket.
    DescriptorBudget,

    /// Allocation of a bounded address snapshot failed.
    Allocation,

    /// Resolution returned no address enabled by the configured policy.
    NoAddressesForPolicy,

    /// A caller supplied more addresses than the bounded connector accepts.
    TooManyResolvedAddresses,
}

impl fmt::Display for DestinationConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimedOut { timeout } => write!(
                formatter,
                "destination connection timed out after {timeout:?}"
            ),
            Self::Io(error) => write!(formatter, "failed to connect to destination: {error}"),
            Self::DescriptorBudget => {
                formatter.write_str("descriptor budget denied a connection candidate")
            }
            Self::Allocation => formatter.write_str("resolved address allocation failed"),
            Self::NoAddressesForPolicy => {
                formatter.write_str("no resolved address is enabled by network.dial.mode")
            }
            Self::TooManyResolvedAddresses => {
                formatter.write_str("pre-resolved destination address count exceeds 64")
            }
        }
    }
}

impl Error for DestinationConnectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TimedOut { .. }
            | Self::DescriptorBudget
            | Self::Allocation
            | Self::NoAddressesForPolicy => None,
            Self::Io(error) => Some(error),
            Self::TooManyResolvedAddresses => None,
        }
    }
}

impl From<io::Error> for DestinationConnectError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl DestinationConnectError {
    pub(crate) fn into_io(self) -> io::Error {
        match self {
            Self::Io(error) => error,
            Self::TimedOut { .. } => io::Error::new(io::ErrorKind::TimedOut, self),
            Self::DescriptorBudget => io::Error::other(self),
            Self::Allocation => io::Error::new(io::ErrorKind::OutOfMemory, self),
            Self::NoAddressesForPolicy | Self::TooManyResolvedAddresses => {
                io::Error::new(io::ErrorKind::InvalidInput, self)
            }
        }
    }
}

#[cfg(test)]
mod tests;
