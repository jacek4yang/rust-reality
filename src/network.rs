//! Centralized IP-family policy, environment detection, and connection plans.
//!
//! This state is consulted only during listener construction, DNS ordering,
//! and TCP setup. Established relay reads and writes never touch it.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use crate::config::{AddressFamilyPolicy, NetworkConfig};

const ROUTE_IPV4: u8 = 1;
const ROUTE_IPV6: u8 = 2;

/// One Internet address family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressFamily {
    /// IPv4.
    Ipv4,
    /// IPv6.
    Ipv6,
}

impl AddressFamily {
    /// Classifies one IP address.
    #[must_use]
    pub const fn of(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }
}

/// Expiring route and passive connection-health state shared by all dialers.
///
/// The structure has exactly two fixed family records and uses atomics only;
/// it cannot grow with destinations and never introduces a global mutex.
#[derive(Clone, Debug)]
pub struct NetworkEnvironment {
    inner: Arc<EnvironmentInner>,
}

#[derive(Debug)]
struct EnvironmentInner {
    ipv4: FamilyHealth,
    ipv6: FamilyHealth,
    routes: AtomicU8,
    routes_expire_at_ms: AtomicU64,
    refreshing_routes: AtomicBool,
}

#[derive(Debug)]
struct FamilyHealth {
    penalty_until_ms: AtomicU64,
    last_success_ms: AtomicU64,
    latency_micros: AtomicU64,
}

impl FamilyHealth {
    const fn new() -> Self {
        Self {
            penalty_until_ms: AtomicU64::new(0),
            last_success_ms: AtomicU64::new(0),
            latency_micros: AtomicU64::new(0),
        }
    }
}

impl Default for NetworkEnvironment {
    fn default() -> Self {
        Self::detect()
    }
}

impl NetworkEnvironment {
    /// Creates process-lifetime state. The first dual-family plan detects route
    /// and usable source-address availability without sending a public probe;
    /// single-family operation never pays for detection. UDP `connect`
    /// performs only local route and source selection until bytes are written.
    #[must_use]
    pub fn detect() -> Self {
        Self {
            inner: Arc::new(EnvironmentInner {
                ipv4: FamilyHealth::new(),
                ipv6: FamilyHealth::new(),
                routes: AtomicU8::new(0),
                routes_expire_at_ms: AtomicU64::new(0),
                refreshing_routes: AtomicBool::new(false),
            }),
        }
    }

    fn health(&self, family: AddressFamily) -> &FamilyHealth {
        match family {
            AddressFamily::Ipv4 => &self.inner.ipv4,
            AddressFamily::Ipv6 => &self.inner.ipv6,
        }
    }

    fn refresh_routes_if_expired(&self, now_ms: u64, lifetime: Duration) {
        if self.inner.routes_expire_at_ms.load(Ordering::Acquire) > now_ms {
            return;
        }
        if self
            .inner
            .refreshing_routes
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        self.inner.routes.store(detect_routes(), Ordering::Release);
        self.inner.routes_expire_at_ms.store(
            now_ms.saturating_add(duration_millis(lifetime)),
            Ordering::Release,
        );
        self.inner.refreshing_routes.store(false, Ordering::Release);
    }

    fn route_available(&self, family: AddressFamily) -> bool {
        let bit = match family {
            AddressFamily::Ipv4 => ROUTE_IPV4,
            AddressFamily::Ipv6 => ROUTE_IPV6,
        };
        self.inner.routes.load(Ordering::Acquire) & bit != 0
    }

    fn is_penalized(&self, family: AddressFamily, now_ms: u64) -> bool {
        self.health(family).penalty_until_ms.load(Ordering::Acquire) > now_ms
    }

    fn recent_latency(&self, family: AddressFamily, now_ms: u64, memory: Duration) -> Option<u64> {
        let health = self.health(family);
        let last = health.last_success_ms.load(Ordering::Acquire);
        if last == 0 || now_ms.saturating_sub(last) > duration_millis(memory) {
            return None;
        }
        let latency = health.latency_micros.load(Ordering::Acquire);
        (latency != 0).then_some(latency)
    }

    /// Records a successful family connection and a bounded EWMA of setup
    /// latency. A success immediately clears an older reachability penalty.
    fn record_success(&self, family: AddressFamily, latency: Duration, memory: Duration) {
        self.record_success_at(family, latency, monotonic_millis(), memory);
    }

    fn record_success_at(
        &self,
        family: AddressFamily,
        latency: Duration,
        now_ms: u64,
        memory: Duration,
    ) {
        let health = self.health(family);
        let sample = u64::try_from(latency.as_micros())
            .unwrap_or(u64::MAX)
            .max(1);
        let last_success = health.last_success_ms.load(Ordering::Acquire);
        let previous = if last_success != 0
            && now_ms.saturating_sub(last_success) <= duration_millis(memory)
        {
            health.latency_micros.load(Ordering::Acquire)
        } else {
            0
        };
        let next = if previous == 0 {
            sample
        } else {
            previous.saturating_mul(7).saturating_add(sample) / 8
        };
        health.latency_micros.store(next.max(1), Ordering::Release);
        health
            .last_success_ms
            .store(now_ms.max(1), Ordering::Release);
        health.penalty_until_ms.store(0, Ordering::Release);
    }

    /// Penalizes only errors that signal family-level route or source-address
    /// failure. Endpoint-local failures such as connection refusal do not
    /// contaminate global family health.
    pub fn record_failure(&self, family: AddressFamily, error: &io::Error, penalty: Duration) {
        if is_family_reachability_error(error) {
            self.record_failure_at(family, monotonic_millis(), penalty);
        }
    }

    /// Deprioritizes a family whose attempt remained pending while the
    /// alternate family connected, or until the overall deadline elapsed.
    pub fn record_timeout(&self, family: AddressFamily, penalty: Duration) {
        self.record_failure_at(family, monotonic_millis(), penalty);
    }

    fn record_failure_at(&self, family: AddressFamily, now_ms: u64, penalty: Duration) {
        let until = now_ms.saturating_add(duration_millis(penalty));
        self.health(family)
            .penalty_until_ms
            .fetch_max(until, Ordering::AcqRel);
    }

    #[cfg(test)]
    pub(crate) fn with_routes(ipv4: bool, ipv6: bool) -> Self {
        let routes = (u8::from(ipv4) * ROUTE_IPV4) | (u8::from(ipv6) * ROUTE_IPV6);
        Self {
            inner: Arc::new(EnvironmentInner {
                ipv4: FamilyHealth::new(),
                ipv6: FamilyHealth::new(),
                routes: AtomicU8::new(routes),
                routes_expire_at_ms: AtomicU64::new(u64::MAX),
                refreshing_routes: AtomicBool::new(false),
            }),
        }
    }
}

/// Immutable policy compiler for listener endpoints and connection ordering.
#[derive(Clone, Debug)]
pub struct ConnectionPlanner {
    config: NetworkConfig,
    environment: NetworkEnvironment,
}

impl ConnectionPlanner {
    /// Compiles a planner over process-lifetime environment state.
    #[must_use]
    pub const fn new(config: NetworkConfig, environment: NetworkEnvironment) -> Self {
        Self {
            config,
            environment,
        }
    }

    /// Returns the configured fallback delay.
    #[must_use]
    pub const fn fallback_delay(&self) -> Duration {
        Duration::from_millis(self.config.fallback_delay_ms)
    }

    /// Returns the shared environment.
    #[must_use]
    pub const fn environment(&self) -> &NetworkEnvironment {
        &self.environment
    }

    /// Returns the configured family-health penalty.
    #[must_use]
    pub const fn family_penalty(&self) -> Duration {
        Duration::from_secs(self.config.family_penalty_seconds)
    }

    /// Records one successful attempt using this policy's latency lifetime.
    pub fn record_success(&self, family: AddressFamily, latency: Duration) {
        self.environment.record_success(
            family,
            latency,
            Duration::from_secs(self.config.health_memory_seconds),
        );
    }

    /// Expands one logical inbound deterministically. An unspecified address
    /// means every family enabled by policy; dual-family modes return two
    /// independent sockets rather than relying on IPv4-mapped connections.
    #[must_use]
    pub fn listener_addresses(
        address: IpAddr,
        port: u16,
        policy: AddressFamilyPolicy,
    ) -> Vec<SocketAddr> {
        if !address.is_unspecified() {
            return vec![SocketAddr::new(address, port)];
        }
        let mut addresses = Vec::with_capacity(2);
        if policy.allows_ipv4() {
            addresses.push(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port));
        }
        if policy.allows_ipv6() {
            addresses.push(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port));
        }
        addresses
    }

    /// Filters, de-duplicates, and interleaves a bounded DNS snapshot according
    /// to policy, route usability, recent success latency, and active penalties.
    #[must_use]
    pub fn plan(&self, addresses: &[SocketAddr]) -> Vec<SocketAddr> {
        self.plan_at(addresses, monotonic_millis())
    }

    fn plan_at(&self, addresses: &[SocketAddr], now_ms: u64) -> Vec<SocketAddr> {
        let allows_v4 = self.config.address_family.allows_ipv4();
        let allows_v6 = self.config.address_family.allows_ipv6();
        let has_v4 = allows_v4 && addresses.iter().any(SocketAddr::is_ipv4);
        let has_v6 = allows_v6 && addresses.iter().any(SocketAddr::is_ipv6);
        let first = match (has_v4, has_v6) {
            (true, true) => {
                self.environment.refresh_routes_if_expired(
                    now_ms,
                    Duration::from_secs(self.config.route_refresh_seconds),
                );
                self.preferred_family_at(now_ms)
            }
            (true, false) => AddressFamily::Ipv4,
            (false, true) | (false, false) => AddressFamily::Ipv6,
        };
        let second = match first {
            AddressFamily::Ipv4 => AddressFamily::Ipv6,
            AddressFamily::Ipv6 => AddressFamily::Ipv4,
        };
        let mut ordered = Vec::with_capacity(addresses.len());
        let mut first_index = 0;
        let mut second_index = 0;
        loop {
            let first_address = next_unique_family(
                addresses,
                &mut first_index,
                first,
                allows_v4,
                allows_v6,
                &ordered,
            );
            if let Some(address) = first_address {
                ordered.push(address);
            }
            let second_address = next_unique_family(
                addresses,
                &mut second_index,
                second,
                allows_v4,
                allows_v6,
                &ordered,
            );
            if let Some(address) = second_address {
                ordered.push(address);
            }
            if first_address.is_none() && second_address.is_none() {
                break;
            }
        }
        ordered
    }

    fn preferred_family_at(&self, now_ms: u64) -> AddressFamily {
        let v4_healthy = !self.environment.is_penalized(AddressFamily::Ipv4, now_ms);
        let v6_healthy = !self.environment.is_penalized(AddressFamily::Ipv6, now_ms);
        if v4_healthy != v6_healthy {
            return if v4_healthy {
                AddressFamily::Ipv4
            } else {
                AddressFamily::Ipv6
            };
        }
        let v4_route = self.environment.route_available(AddressFamily::Ipv4);
        let v6_route = self.environment.route_available(AddressFamily::Ipv6);
        if v4_route != v6_route {
            return if v4_route {
                AddressFamily::Ipv4
            } else {
                AddressFamily::Ipv6
            };
        }
        match self.config.address_family {
            AddressFamilyPolicy::Ipv4Only | AddressFamilyPolicy::PreferIpv4 => AddressFamily::Ipv4,
            AddressFamilyPolicy::Ipv6Only | AddressFamilyPolicy::PreferIpv6 => AddressFamily::Ipv6,
            AddressFamilyPolicy::Auto => {
                let memory = Duration::from_secs(self.config.health_memory_seconds);
                match (
                    self.environment
                        .recent_latency(AddressFamily::Ipv4, now_ms, memory),
                    self.environment
                        .recent_latency(AddressFamily::Ipv6, now_ms, memory),
                ) {
                    (Some(v4), Some(v6)) if v4 < v6 => AddressFamily::Ipv4,
                    (Some(_), Some(_)) => AddressFamily::Ipv6,
                    (Some(_), None) => AddressFamily::Ipv4,
                    (None, Some(_)) | (None, None) => AddressFamily::Ipv6,
                }
            }
        }
    }
}

fn next_unique_family(
    addresses: &[SocketAddr],
    index: &mut usize,
    family: AddressFamily,
    allows_v4: bool,
    allows_v6: bool,
    ordered: &[SocketAddr],
) -> Option<SocketAddr> {
    while let Some(address) = addresses.get(*index).copied() {
        *index += 1;
        let address_family = AddressFamily::of(address.ip());
        let allowed = match address_family {
            AddressFamily::Ipv4 => allows_v4,
            AddressFamily::Ipv6 => allows_v6,
        };
        if allowed && address_family == family && !ordered.contains(&address) {
            return Some(address);
        }
    }
    None
}

fn detect_routes() -> u8 {
    let mut routes = 0;
    if route_and_source_available(
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 9),
    ) {
        routes |= ROUTE_IPV4;
    }
    if route_and_source_available(
        SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
        SocketAddr::new(
            Ipv6Addr::from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).into(),
            9,
        ),
    ) {
        routes |= ROUTE_IPV6;
    }
    routes
}

fn route_and_source_available(bind: SocketAddr, target: SocketAddr) -> bool {
    UdpSocket::bind(bind)
        .and_then(|socket| {
            socket.connect(target)?;
            socket.local_addr()
        })
        .is_ok_and(|local| !local.ip().is_unspecified())
}

fn is_family_reachability_error(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(99 | 101 | 113))
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn monotonic_millis() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    duration_millis(EPOCH.get_or_init(Instant::now).elapsed()).saturating_add(1)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{AddressFamily, ConnectionPlanner, NetworkEnvironment};
    use crate::config::{AddressFamilyPolicy, NetworkConfig};

    fn planner(policy: AddressFamilyPolicy, ipv4: bool, ipv6: bool) -> ConnectionPlanner {
        ConnectionPlanner::new(
            NetworkConfig {
                address_family: policy,
                ..NetworkConfig::default()
            },
            NetworkEnvironment::with_routes(ipv4, ipv6),
        )
    }

    fn mixed() -> [SocketAddr; 4] {
        [
            SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 443),
            SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443),
            SocketAddr::new(Ipv4Addr::new(192, 0, 2, 2).into(), 443),
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 443),
        ]
    }

    #[test]
    fn every_policy_filters_and_orders_mixed_results() {
        for (policy, first_v4) in [
            (AddressFamilyPolicy::Auto, false),
            (AddressFamilyPolicy::PreferIpv4, true),
            (AddressFamilyPolicy::PreferIpv6, false),
            (AddressFamilyPolicy::Ipv4Only, true),
            (AddressFamilyPolicy::Ipv6Only, false),
        ] {
            let plan = planner(policy, true, true).plan_at(&mixed(), 1);
            assert_eq!(plan[0].is_ipv4(), first_v4, "policy {policy:?}");
            if policy == AddressFamilyPolicy::Ipv4Only {
                assert!(plan.iter().all(SocketAddr::is_ipv4));
            } else if policy == AddressFamilyPolicy::Ipv6Only {
                assert!(plan.iter().all(SocketAddr::is_ipv6));
            } else {
                assert_ne!(plan[0].is_ipv4(), plan[1].is_ipv4());
            }
        }

        let duplicated = [mixed()[0], mixed()[0], mixed()[1], mixed()[1]];
        let plan = planner(AddressFamilyPolicy::Auto, true, true).plan_at(&duplicated, 1);
        assert_eq!(plan, [mixed()[1], mixed()[0]]);
    }

    #[test]
    fn auto_penalty_expires_and_latency_memory_recovers() {
        let environment = NetworkEnvironment::with_routes(true, true);
        let planner = ConnectionPlanner::new(
            NetworkConfig {
                health_memory_seconds: 1,
                family_penalty_seconds: 1,
                ..NetworkConfig::default()
            },
            environment.clone(),
        );
        environment.record_success_at(
            AddressFamily::Ipv4,
            std::time::Duration::from_millis(5),
            10,
            std::time::Duration::from_secs(1),
        );
        environment.record_success_at(
            AddressFamily::Ipv6,
            std::time::Duration::from_millis(20),
            10,
            std::time::Duration::from_secs(1),
        );
        assert!(planner.plan_at(&mixed(), 20)[0].is_ipv4());
        environment.record_failure_at(AddressFamily::Ipv4, 20, std::time::Duration::from_secs(1));
        assert!(planner.plan_at(&mixed(), 21)[0].is_ipv6());
        assert!(planner.plan_at(&mixed(), 2_000)[0].is_ipv6());
        environment.record_success_at(
            AddressFamily::Ipv4,
            std::time::Duration::from_millis(50),
            2_010,
            std::time::Duration::from_secs(1),
        );
        assert_eq!(
            environment.recent_latency(
                AddressFamily::Ipv4,
                2_010,
                std::time::Duration::from_secs(1)
            ),
            Some(50_000),
            "an expired EWMA must not revive when the family recovers"
        );
    }

    #[test]
    fn wildcard_listener_expansion_is_deterministic() {
        for policy in [
            AddressFamilyPolicy::Auto,
            AddressFamilyPolicy::PreferIpv4,
            AddressFamilyPolicy::PreferIpv6,
        ] {
            let dual = ConnectionPlanner::listener_addresses(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                443,
                policy,
            );
            assert_eq!(dual.len(), 2, "policy {policy:?}");
            assert!(dual[0].is_ipv4());
            assert!(dual[1].is_ipv6());
        }
        assert_eq!(
            ConnectionPlanner::listener_addresses(
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                443,
                AddressFamilyPolicy::Ipv4Only,
            ),
            [SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 443)]
        );
        assert_eq!(
            ConnectionPlanner::listener_addresses(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                443,
                AddressFamilyPolicy::Ipv6Only,
            ),
            [SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 443)]
        );
    }
}
