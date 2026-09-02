//! Process-wide IP-family detection, bounded health, and connection plans.
//!
//! Startup performs one local kernel route/source-address observation. Runtime
//! refresh and connection setup update a fixed two-family state machine; the
//! established relay path never consults this module.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs as _, UdpSocket},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use crate::config::node::network::DialPolicy;

/// Dial timing, derived rather than configured.
///
/// These four numbers used to be operator-facing fields. None of them is a
/// decision an operator has information to make better than the process does:
/// the first is the happy-eyeballs delay, and the rest are how long an
/// observation about the local network stays trusted. They are constants here
/// so the configuration carries only the family preference, which *is* an
/// operator decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DialTuning {
    /// Which families to dial, and which to prefer.
    pub mode: DialPolicy,
    /// Delay before the first alternate-family attempt.
    pub fallback_delay_ms: u64,
    /// Lifetime of the cached route and local-address observation.
    pub route_refresh_seconds: u64,
    /// How long a family-level reachability error deprioritises that family.
    pub hard_failure_penalty_seconds: u64,
    /// Lifetime of learned family latency before it expires.
    pub latency_memory_seconds: u64,
}

impl DialTuning {
    /// The derived timing for one family preference.
    #[must_use]
    pub const fn for_policy(mode: DialPolicy) -> Self {
        Self {
            mode,
            fallback_delay_ms: 250,
            route_refresh_seconds: 30,
            hard_failure_penalty_seconds: 30,
            latency_memory_seconds: 300,
        }
    }
}

impl Default for DialTuning {
    fn default() -> Self {
        Self::for_policy(DialPolicy::Auto)
    }
}

const ROUTE_IPV4: u8 = 1;
const ROUTE_IPV6: u8 = 2;
const PRIMARY_IPV4: u8 = 4;
const PRIMARY_IPV6: u8 = 6;
const HARD_FAILURE_THRESHOLD: u8 = 2;
const WEAK_LOSS_THRESHOLD: u8 = 3;
const RECOVERY_SUCCESS_THRESHOLD: u8 = 2;

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

    /// Returns the alternate family.
    #[must_use]
    pub const fn alternate(self) -> Self {
        match self {
            Self::Ipv4 => Self::Ipv6,
            Self::Ipv6 => Self::Ipv4,
        }
    }

    /// Returns the stable log/config name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::Ipv4 => PRIMARY_IPV4,
            Self::Ipv6 => PRIMARY_IPV6,
        }
    }

    const fn route_bit(self) -> u8 {
        match self {
            Self::Ipv4 => ROUTE_IPV4,
            Self::Ipv6 => ROUTE_IPV6,
        }
    }

    const fn from_code(code: u8) -> Self {
        if code == PRIMARY_IPV4 {
            Self::Ipv4
        } else {
            Self::Ipv6
        }
    }
}

/// Immutable network decision made once during process startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartupNetworkSnapshot {
    /// Configured outbound dialing mode.
    pub mode: DialPolicy,
    /// Whether local route/source selection found usable IPv4.
    pub ipv4_available: bool,
    /// Whether local route/source selection found usable IPv6.
    pub ipv6_available: bool,
    /// Stable initial process-wide primary family.
    pub initial_primary: AddressFamily,
}

/// Classification of a failed connection attempt for family health.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureEvidence {
    /// Family-level route, device, address, or protocol failure.
    StrongFamily,
    /// The family reached the endpoint, which refused or reset the connection.
    ReachableEndpoint,
    /// Destination-local or ambiguous failure; global health is unchanged.
    DestinationOnly,
}

/// Fixed, process-wide route and passive family-health state.
#[derive(Clone, Debug)]
pub struct NetworkEnvironment {
    inner: Arc<EnvironmentInner>,
}

#[derive(Debug)]
struct EnvironmentInner {
    startup: StartupNetworkSnapshot,
    routes: AtomicU8,
    primary: AtomicU8,
    ipv4: FamilyHealth,
    ipv6: FamilyHealth,
}

#[derive(Debug)]
struct FamilyHealth {
    penalty_until_ms: AtomicU64,
    next_recovery_probe_ms: AtomicU64,
    last_success_ms: AtomicU64,
    latency_micros: AtomicU64,
    consecutive_hard_failures: AtomicU8,
    consecutive_weak_losses: AtomicU8,
    recovery_successes: AtomicU8,
}

impl FamilyHealth {
    const fn new() -> Self {
        Self {
            penalty_until_ms: AtomicU64::new(0),
            next_recovery_probe_ms: AtomicU64::new(0),
            last_success_ms: AtomicU64::new(0),
            latency_micros: AtomicU64::new(0),
            consecutive_hard_failures: AtomicU8::new(0),
            consecutive_weak_losses: AtomicU8::new(0),
            recovery_successes: AtomicU8::new(0),
        }
    }
}

impl Default for NetworkEnvironment {
    fn default() -> Self {
        Self::from_config(&DialTuning::default())
    }
}

impl NetworkEnvironment {
    /// Detects the startup route/source snapshot without sending network data.
    #[must_use]
    pub fn from_config(config: &DialTuning) -> Self {
        let routes = detect_routes();
        let primary = initial_primary(config.mode, routes, system_preferred_family());
        Self::from_snapshot(StartupNetworkSnapshot {
            mode: config.mode,
            ipv4_available: routes & ROUTE_IPV4 != 0,
            ipv6_available: routes & ROUTE_IPV6 != 0,
            initial_primary: primary,
        })
    }

    /// Creates an environment using default outbound dialing settings.
    #[must_use]
    pub fn detect() -> Self {
        Self::default()
    }

    fn from_snapshot(snapshot: StartupNetworkSnapshot) -> Self {
        let routes = (u8::from(snapshot.ipv4_available) * ROUTE_IPV4)
            | (u8::from(snapshot.ipv6_available) * ROUTE_IPV6);
        Self {
            inner: Arc::new(EnvironmentInner {
                startup: snapshot,
                routes: AtomicU8::new(routes),
                primary: AtomicU8::new(snapshot.initial_primary.code()),
                ipv4: FamilyHealth::new(),
                ipv6: FamilyHealth::new(),
            }),
        }
    }

    /// Returns the immutable startup decision.
    #[must_use]
    pub fn startup_snapshot(&self) -> StartupNetworkSnapshot {
        self.inner.startup
    }

    /// Returns the current stable process-wide primary family.
    #[must_use]
    pub fn primary(&self) -> AddressFamily {
        AddressFamily::from_code(self.inner.primary.load(Ordering::Acquire))
    }

    /// Performs one low-cost route/source refresh and updates availability.
    pub fn refresh_routes(&self) {
        self.update_routes(detect_routes());
    }

    fn update_routes(&self, routes: u8) {
        let previous_routes = self.inner.routes.swap(routes, Ordering::AcqRel);
        let primary = self.primary();
        let alternate = primary.alternate();
        if !self.route_available(primary)
            && self.route_available(alternate)
            && mode_allows(self.inner.startup.mode, alternate)
        {
            self.inner
                .primary
                .store(alternate.code(), Ordering::Release);
            self.health(alternate)
                .recovery_successes
                .store(0, Ordering::Release);
        }
        let preferred = self.preferred_recovery_family();
        if previous_routes & preferred.route_bit() == 0
            && routes & preferred.route_bit() != 0
            && self.primary() != preferred
        {
            self.health(preferred)
                .next_recovery_probe_ms
                .store(monotonic_millis(), Ordering::Release);
        }
    }

    fn health(&self, family: AddressFamily) -> &FamilyHealth {
        match family {
            AddressFamily::Ipv4 => &self.inner.ipv4,
            AddressFamily::Ipv6 => &self.inner.ipv6,
        }
    }

    fn route_available(&self, family: AddressFamily) -> bool {
        self.inner.routes.load(Ordering::Acquire) & family.route_bit() != 0
    }

    fn is_penalized(&self, family: AddressFamily, now_ms: u64) -> bool {
        self.health(family).penalty_until_ms.load(Ordering::Acquire) > now_ms
    }

    /// Returns a recent bounded EWMA sample for diagnostics and adaptive delay.
    #[must_use]
    pub fn recent_latency(&self, family: AddressFamily, memory: Duration) -> Option<Duration> {
        self.recent_latency_at(family, monotonic_millis(), memory)
            .map(Duration::from_micros)
    }

    fn recent_latency_at(
        &self,
        family: AddressFamily,
        now_ms: u64,
        memory: Duration,
    ) -> Option<u64> {
        let health = self.health(family);
        let last = health.last_success_ms.load(Ordering::Acquire);
        if last == 0 || now_ms.saturating_sub(last) > duration_millis(memory) {
            return None;
        }
        let latency = health.latency_micros.load(Ordering::Acquire);
        (latency != 0).then_some(latency)
    }

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
        let last = health.last_success_ms.load(Ordering::Acquire);
        let previous = if last != 0 && now_ms.saturating_sub(last) <= duration_millis(memory) {
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
        health.consecutive_hard_failures.store(0, Ordering::Release);
        health.consecutive_weak_losses.store(0, Ordering::Release);
        health.penalty_until_ms.store(0, Ordering::Release);

        if family == self.primary() {
            health.recovery_successes.store(0, Ordering::Release);
            return;
        }
        let recoveries = saturating_increment(&health.recovery_successes);
        if recoveries >= RECOVERY_SUCCESS_THRESHOLD
            && self.preferred_recovery_family() == family
            && self.route_available(family)
        {
            self.inner.primary.store(family.code(), Ordering::Release);
            health.recovery_successes.store(0, Ordering::Release);
            health.next_recovery_probe_ms.store(0, Ordering::Release);
        } else {
            // Confirm recovery on the next connection rather than waiting for
            // the normal probe interval after the first successful trial.
            health
                .next_recovery_probe_ms
                .store(now_ms, Ordering::Release);
        }
    }

    fn preferred_recovery_family(&self) -> AddressFamily {
        match self.inner.startup.mode.prefers_ipv4() {
            Some(true) => AddressFamily::Ipv4,
            Some(false) => AddressFamily::Ipv6,
            None => self.inner.startup.initial_primary,
        }
    }

    /// Records one connection error without treating destination-local failures
    /// or a single ambiguous route failure as a global family outage.
    pub fn record_connect_error(
        &self,
        family: AddressFamily,
        error: &io::Error,
        penalty: Duration,
    ) {
        match classify_connect_error(error) {
            FailureEvidence::ReachableEndpoint => {
                let health = self.health(family);
                health.consecutive_hard_failures.store(0, Ordering::Release);
                health.penalty_until_ms.store(0, Ordering::Release);
            }
            FailureEvidence::DestinationOnly => {}
            FailureEvidence::StrongFamily => {
                let failures = saturating_increment(&self.health(family).consecutive_hard_failures);
                if failures >= HARD_FAILURE_THRESHOLD {
                    self.penalize_and_fail_over(family, penalty);
                }
            }
        }
    }

    fn penalize_and_fail_over(&self, family: AddressFamily, penalty: Duration) {
        let now_ms = monotonic_millis();
        self.health(family).penalty_until_ms.fetch_max(
            now_ms.saturating_add(duration_millis(penalty)),
            Ordering::AcqRel,
        );
        self.health(family).next_recovery_probe_ms.fetch_max(
            now_ms.saturating_add(duration_millis(penalty)),
            Ordering::AcqRel,
        );
        let alternate = family.alternate();
        if self.primary() == family
            && mode_allows(self.inner.startup.mode, alternate)
            && self.route_available(alternate)
        {
            self.inner
                .primary
                .store(alternate.code(), Ordering::Release);
        }
    }

    /// Records weak same-destination evidence when an alternate family wins
    /// while another-family attempt remains pending. No hard penalty is set.
    pub fn record_alternate_success(&self, winner: AddressFamily, pending_loser: AddressFamily) {
        if winner == pending_loser || self.primary() != pending_loser {
            return;
        }
        let losses = saturating_increment(&self.health(pending_loser).consecutive_weak_losses);
        if losses >= WEAK_LOSS_THRESHOLD
            && self.route_available(winner)
            && mode_allows(self.inner.startup.mode, winner)
        {
            self.inner.primary.store(winner.code(), Ordering::Release);
            self.health(pending_loser)
                .consecutive_weak_losses
                .store(0, Ordering::Release);
        }
    }

    #[cfg(test)]
    pub(crate) fn with_routes_and_primary(
        mode: DialPolicy,
        ipv4: bool,
        ipv6: bool,
        primary: AddressFamily,
    ) -> Self {
        Self::from_snapshot(StartupNetworkSnapshot {
            mode,
            ipv4_available: ipv4,
            ipv6_available: ipv6,
            initial_primary: primary,
        })
    }

    fn claim_recovery_probe(
        &self,
        family: AddressFamily,
        now_ms: u64,
        retry_interval: Duration,
    ) -> bool {
        if family == self.primary()
            || family != self.preferred_recovery_family()
            || !self.route_available(family)
            || self.is_penalized(family, now_ms)
        {
            return false;
        }
        let health = self.health(family);
        let due = health.next_recovery_probe_ms.load(Ordering::Acquire);
        if due == 0 || now_ms < due {
            return false;
        }
        health
            .next_recovery_probe_ms
            .compare_exchange(
                due,
                now_ms.saturating_add(duration_millis(retry_interval)),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

/// Immutable planner over shared process-lifetime state.
#[derive(Clone, Debug)]
pub struct ConnectionPlanner {
    config: DialTuning,
    environment: NetworkEnvironment,
}

impl ConnectionPlanner {
    /// Compiles one planner.
    #[must_use]
    pub const fn new(config: DialTuning, environment: NetworkEnvironment) -> Self {
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

    /// Returns the configured hard-family penalty.
    #[must_use]
    pub const fn hard_failure_penalty(&self) -> Duration {
        Duration::from_secs(self.config.hard_failure_penalty_seconds)
    }

    /// Records successful setup latency without switching on one sample.
    pub fn record_success(&self, family: AddressFamily, latency: Duration) {
        self.environment.record_success(
            family,
            latency,
            Duration::from_secs(self.config.latency_memory_seconds),
        );
    }

    /// Filters, de-duplicates, and interleaves a bounded DNS snapshot using the
    /// current stable process-wide primary family.
    #[must_use]
    pub fn plan(&self, addresses: &[SocketAddr]) -> Vec<SocketAddr> {
        self.plan_at(addresses, monotonic_millis())
    }

    fn plan_at(&self, addresses: &[SocketAddr], now_ms: u64) -> Vec<SocketAddr> {
        let allows_v4 = self.config.mode.allows_ipv4();
        let allows_v6 = self.config.mode.allows_ipv6();
        let has_v4 = allows_v4 && addresses.iter().any(SocketAddr::is_ipv4);
        let has_v6 = allows_v6 && addresses.iter().any(SocketAddr::is_ipv6);
        let first = match (has_v4, has_v6) {
            (true, true) => self.preferred_family_at(now_ms),
            (true, false) => AddressFamily::Ipv4,
            (false, true) | (false, false) => AddressFamily::Ipv6,
        };
        let second = first.alternate();
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
        let primary = self.environment.primary();
        let alternate = primary.alternate();
        if self
            .environment
            .claim_recovery_probe(alternate, now_ms, self.hard_failure_penalty())
        {
            return alternate;
        }
        let primary_healthy = !self.environment.is_penalized(primary, now_ms);
        let alternate_healthy = !self.environment.is_penalized(alternate, now_ms);
        if (!primary_healthy && alternate_healthy)
            || (!self.environment.route_available(primary)
                && self.environment.route_available(alternate))
        {
            alternate
        } else {
            primary
        }
    }
}

/// Classifies one socket error for global family-health purposes.
#[must_use]
pub fn classify_connect_error(error: &io::Error) -> FailureEvidence {
    match error.raw_os_error() {
        // Linux: EAFNOSUPPORT, EPROTONOSUPPORT, ENETUNREACH,
        // EHOSTUNREACH, EADDRNOTAVAIL, ENODEV.
        Some(97 | 93 | 101 | 113 | 99 | 19) => FailureEvidence::StrongFamily,
        // ECONNREFUSED and ECONNRESET prove packets reached the peer path.
        Some(111 | 104) => FailureEvidence::ReachableEndpoint,
        _ => FailureEvidence::DestinationOnly,
    }
}

fn mode_allows(mode: DialPolicy, family: AddressFamily) -> bool {
    match family {
        AddressFamily::Ipv4 => mode.allows_ipv4(),
        AddressFamily::Ipv6 => mode.allows_ipv6(),
    }
}

fn initial_primary(
    mode: DialPolicy,
    routes: u8,
    system_preference: AddressFamily,
) -> AddressFamily {
    let v4 = routes & ROUTE_IPV4 != 0;
    let v6 = routes & ROUTE_IPV6 != 0;
    match mode {
        DialPolicy::Ipv4Only => AddressFamily::Ipv4,
        DialPolicy::Ipv6Only => AddressFamily::Ipv6,
        DialPolicy::PreferIpv4 if v4 || !v6 => AddressFamily::Ipv4,
        DialPolicy::PreferIpv4 => AddressFamily::Ipv6,
        DialPolicy::PreferIpv6 if v6 || !v4 => AddressFamily::Ipv6,
        DialPolicy::PreferIpv6 => AddressFamily::Ipv4,
        DialPolicy::Auto => match (v4, v6) {
            (true, false) => AddressFamily::Ipv4,
            (false, true) => AddressFamily::Ipv6,
            (true, true) | (false, false) => system_preference,
        },
    }
}

fn system_preferred_family() -> AddressFamily {
    ("localhost", 0)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addresses| addresses.next())
        .map(|address| AddressFamily::of(address.ip()))
        // RFC 6724's default policy prefers IPv6 when the system resolver gives
        // no usable evidence. Actual route availability still overrides it.
        .unwrap_or(AddressFamily::Ipv6)
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

fn saturating_increment(value: &AtomicU8) -> u8 {
    let mut current = value.load(Ordering::Acquire);
    loop {
        let next = current.saturating_add(1);
        match value.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return next,
            Err(observed) => current = observed,
        }
    }
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
    use std::{
        io,
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        time::Duration,
    };

    use super::DialTuning;
    use super::{
        AddressFamily, ConnectionPlanner, FailureEvidence, NetworkEnvironment,
        classify_connect_error, initial_primary,
    };
    use crate::config::node::network::DialPolicy;

    fn planner(mode: DialPolicy, primary: AddressFamily) -> ConnectionPlanner {
        ConnectionPlanner::new(
            DialTuning {
                mode,
                ..DialTuning::default()
            },
            NetworkEnvironment::with_routes_and_primary(mode, true, true, primary),
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
    fn every_dial_mode_filters_and_orders_mixed_results() {
        for (mode, primary) in [
            (DialPolicy::Auto, AddressFamily::Ipv6),
            (DialPolicy::PreferIpv4, AddressFamily::Ipv4),
            (DialPolicy::PreferIpv6, AddressFamily::Ipv6),
            (DialPolicy::Ipv4Only, AddressFamily::Ipv4),
            (DialPolicy::Ipv6Only, AddressFamily::Ipv6),
        ] {
            let plan = planner(mode, primary).plan(&mixed());
            assert_eq!(plan[0].is_ipv4(), primary == AddressFamily::Ipv4);
            if mode == DialPolicy::Ipv4Only {
                assert!(plan.iter().all(SocketAddr::is_ipv4));
            } else if mode == DialPolicy::Ipv6Only {
                assert!(plan.iter().all(SocketAddr::is_ipv6));
            } else {
                assert_ne!(plan[0].is_ipv4(), plan[1].is_ipv4());
            }
        }
    }

    #[test]
    fn startup_decision_uses_capability_then_stable_system_preference() {
        assert_eq!(
            initial_primary(DialPolicy::Auto, super::ROUTE_IPV4, AddressFamily::Ipv6),
            AddressFamily::Ipv4
        );
        assert_eq!(
            initial_primary(DialPolicy::Auto, super::ROUTE_IPV6, AddressFamily::Ipv4),
            AddressFamily::Ipv6
        );
        assert_eq!(
            initial_primary(
                DialPolicy::Auto,
                super::ROUTE_IPV4 | super::ROUTE_IPV6,
                AddressFamily::Ipv4
            ),
            AddressFamily::Ipv4
        );
        assert_eq!(
            initial_primary(
                DialPolicy::PreferIpv6,
                super::ROUTE_IPV4,
                AddressFamily::Ipv6
            ),
            AddressFamily::Ipv4
        );
    }

    #[test]
    fn route_refresh_changes_primary_only_when_current_route_disappears() {
        let environment = NetworkEnvironment::with_routes_and_primary(
            DialPolicy::Auto,
            true,
            true,
            AddressFamily::Ipv6,
        );
        environment.update_routes(super::ROUTE_IPV4);
        assert_eq!(environment.primary(), AddressFamily::Ipv4);
        environment.update_routes(super::ROUTE_IPV4 | super::ROUTE_IPV6);
        assert_eq!(environment.primary(), AddressFamily::Ipv4);
    }

    #[test]
    fn strong_failures_need_hysteresis_and_endpoint_failures_clear_them() {
        let environment = NetworkEnvironment::with_routes_and_primary(
            DialPolicy::Auto,
            true,
            true,
            AddressFamily::Ipv6,
        );
        let unreachable = io::Error::from_raw_os_error(101);
        environment.record_connect_error(
            AddressFamily::Ipv6,
            &unreachable,
            Duration::from_secs(30),
        );
        assert_eq!(environment.primary(), AddressFamily::Ipv6);
        let refused = io::Error::from_raw_os_error(111);
        environment.record_connect_error(AddressFamily::Ipv6, &refused, Duration::from_secs(30));
        environment.record_connect_error(
            AddressFamily::Ipv6,
            &unreachable,
            Duration::from_secs(30),
        );
        assert_eq!(environment.primary(), AddressFamily::Ipv6);
        environment.record_connect_error(
            AddressFamily::Ipv6,
            &unreachable,
            Duration::from_secs(30),
        );
        assert_eq!(environment.primary(), AddressFamily::Ipv4);
    }

    #[test]
    fn refusal_reset_and_timeout_do_not_poison_family_health() {
        assert_eq!(
            classify_connect_error(&io::Error::from_raw_os_error(111)),
            FailureEvidence::ReachableEndpoint
        );
        assert_eq!(
            classify_connect_error(&io::Error::from_raw_os_error(104)),
            FailureEvidence::ReachableEndpoint
        );
        assert_eq!(
            classify_connect_error(&io::Error::new(io::ErrorKind::TimedOut, "destination")),
            FailureEvidence::DestinationOnly
        );
        assert_eq!(
            classify_connect_error(&io::Error::from_raw_os_error(97)),
            FailureEvidence::StrongFamily
        );
    }

    #[test]
    fn weak_loser_evidence_switches_only_after_repeated_alternate_wins() {
        let environment = NetworkEnvironment::with_routes_and_primary(
            DialPolicy::Auto,
            true,
            true,
            AddressFamily::Ipv6,
        );
        for _ in 0..2 {
            environment.record_alternate_success(AddressFamily::Ipv4, AddressFamily::Ipv6);
            assert_eq!(environment.primary(), AddressFamily::Ipv6);
        }
        environment.record_alternate_success(AddressFamily::Ipv4, AddressFamily::Ipv6);
        assert_eq!(environment.primary(), AddressFamily::Ipv4);
    }

    #[test]
    fn successful_recovery_restores_configured_preference_with_hysteresis() {
        let environment = NetworkEnvironment::with_routes_and_primary(
            DialPolicy::PreferIpv6,
            true,
            true,
            AddressFamily::Ipv6,
        );
        environment.update_routes(super::ROUTE_IPV4);
        assert_eq!(environment.primary(), AddressFamily::Ipv4);
        environment.update_routes(super::ROUTE_IPV4 | super::ROUTE_IPV6);
        environment.record_success(
            AddressFamily::Ipv6,
            Duration::from_millis(5),
            Duration::from_secs(300),
        );
        assert_eq!(environment.primary(), AddressFamily::Ipv4);
        environment.record_success(
            AddressFamily::Ipv6,
            Duration::from_millis(5),
            Duration::from_secs(300),
        );
        assert_eq!(environment.primary(), AddressFamily::Ipv6);
    }

    #[test]
    fn expired_penalty_allows_bounded_recovery_attempts() {
        let environment = NetworkEnvironment::with_routes_and_primary(
            DialPolicy::PreferIpv6,
            true,
            true,
            AddressFamily::Ipv6,
        );
        let planner = ConnectionPlanner::new(DialTuning::default(), environment.clone());
        let unreachable = io::Error::from_raw_os_error(101);
        for _ in 0..2 {
            environment.record_connect_error(AddressFamily::Ipv6, &unreachable, Duration::ZERO);
        }
        assert_eq!(environment.primary(), AddressFamily::Ipv4);

        let first_recovery = planner.plan(&mixed());
        assert!(first_recovery[0].is_ipv6());
        planner.record_success(AddressFamily::Ipv6, Duration::from_millis(5));
        assert_eq!(environment.primary(), AddressFamily::Ipv4);

        let confirmation = planner.plan(&mixed());
        assert!(confirmation[0].is_ipv6());
        planner.record_success(AddressFamily::Ipv6, Duration::from_millis(5));
        assert_eq!(environment.primary(), AddressFamily::Ipv6);
    }
}
