//! Shared DNS resolution front-end for every connector-side lookup path.
//!
//! One [`DnsResolver`] serves fallback cover targets, fixed SOCKS5/NXR/Handoff
//! peers, and per-session destinations. It provides a TTL-bounded positive
//! cache, a bounded negative cache, singleflight coalescing of concurrent
//! identical lookups, one absolute timeout, and upstream concurrency governed
//! by the same `DnsLookup` admission pool as the routing path.
//!
//! Two backends exist. The system backend (getaddrinfo) exposes no TTLs, so
//! per release policy it never populates the dynamic caches (the optional
//! `dns.cache.systemReuseMs` recent-completion window is the bounded
//! exception); it still gains coalescing, governance, and the absolute
//! timeout. The DNS protocol backend (hickory, plain UDP with TCP fallback
//! against the configured servers) observes real TTLs and caches only
//! TTL-backed answers. Static configured peers are the explicit exception in
//! every mode: the operator owns their staleness through
//! `dns.cache.staticTtlSeconds`.
//!
//! Cache identity is the (query class, normalized name) pair: a static entry
//! and a dynamic entry for the same name are independent slots with
//! independent lifetimes, so the static TTL can never extend a dynamic
//! answer and a dynamic answer can never satisfy a static lookup. One global
//! table keeps the configured entry bound exact; both entries count against
//! it.
//!
//! Cancellation and accounting: every upstream query is a detached flight
//! task holding one `DnsLookup` permit. Dropping a waiter never disturbs the
//! flight; dropping a hickory query cancels it and releases the permit at
//! once; a system getaddrinfo call cannot be cancelled, so its permit is held
//! inside the blocking task until the call actually returns — the same
//! documented trade-off as `routing::resolve_domain_with`.

use std::{
    collections::HashMap,
    error::Error,
    fmt,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, OnceLock, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use hickory_resolver::{
    Resolver, TokioResolver,
    config::{ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts},
    net::{DnsError as HickoryDnsError, NetError, runtime::TokioRuntimeProvider},
    proto::{op::ResponseCode, rr::RData},
};
use tokio::{
    sync::broadcast,
    time::{self, Instant},
};

use crate::config::node::dns::{DnsCacheConfig, DnsConfig};
use crate::runtime::policy::ResourceGovernorPolicy;
use crate::runtime::{AdmissionKind, AdmissionPermit, ResourceGovernor};

/// Longest DNS name accepted by the resolver (RFC 1035 presentation form).
const MAX_NAME_LENGTH: usize = 253;

/// Hard bound on addresses kept from one upstream answer, matching the
/// connector's pre-resolved snapshot bound.
const MAX_RESOLVED_IPS: usize = 64;

/// Address family restriction applied when reading a resolution.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum IpFamily {
    /// Every resolved address family.
    #[default]
    Any,
    /// Only IPv4 addresses.
    Ipv4,
    /// Only IPv6 addresses.
    Ipv6,
}

impl IpFamily {
    const fn admits(self, ip: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Ipv4 => ip.is_ipv4(),
            Self::Ipv6 => ip.is_ipv6(),
        }
    }
}

/// Static configured peer or per-session dynamic destination.
///
/// The class is part of the cache identity: a static entry and a dynamic
/// entry for the same normalized name are independent slots with independent
/// lifetimes, so the operator-owned `static_ttl` can never extend a dynamic
/// answer and a dynamic answer can never satisfy a static lookup.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum QueryClass {
    /// Client-requested destination: cached only with a TTL-backed answer.
    Dynamic,
    /// Operator-configured fixed peer: cached for `static_ttl` in every mode.
    Static,
}

/// Cache identity: the query class plus the normalized lookup name. Two
/// classes resolving one name share nothing — neither cached entries nor
/// in-flight flights — which keeps the split obviously correct at the cost
/// of at most one duplicate upstream query per name.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct CacheKey {
    class: QueryClass,
    name: Box<str>,
}

/// A DNS resolution failure. Clonable so one coalesced flight can share its
/// outcome with every waiter.
#[derive(Clone, Debug)]
pub enum DnsError {
    /// The name is empty, too long, or otherwise not a valid DNS name.
    InvalidName,
    /// The upstream answer carried more addresses than the bounded snapshot.
    TooManyAddresses,
    /// Resolution succeeded but no address satisfies the requested family.
    NoAddresses,
    /// The upstream resolver authoritatively reported no records.
    NotFound {
        /// The response code was NXDOMAIN rather than NODATA.
        nxdomain: bool,
    },
    /// The absolute resolution timeout elapsed.
    Timeout,
    /// The DNS admission pool is exhausted.
    Limit,
    /// A bounded resolution allocation failed.
    Allocation,
    /// The upstream resolution failed (SERVFAIL, REFUSED, transport, ...).
    Failed(Arc<str>),
}

impl fmt::Display for DnsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName => formatter.write_str("invalid DNS name"),
            Self::TooManyAddresses => {
                formatter.write_str("upstream answer exceeds the resolved address bound")
            }
            Self::NoAddresses => {
                formatter.write_str("no resolved address matches the requested family")
            }
            Self::NotFound { nxdomain: true } => formatter.write_str("NXDOMAIN"),
            Self::NotFound { nxdomain: false } => {
                formatter.write_str("name exists without address records")
            }
            Self::Timeout => formatter.write_str("DNS resolution timed out"),
            Self::Limit => formatter.write_str("DNS admission limit reached"),
            Self::Allocation => formatter.write_str("resolved address allocation failed"),
            Self::Failed(message) => write!(formatter, "DNS resolution failed: {message}"),
        }
    }
}

impl Error for DnsError {}

/// One answer from an upstream backend.
struct UpstreamAnswer {
    ips: Vec<IpAddr>,
    /// Real TTL observed from the DNS protocol; `None` for the TTL-less
    /// system resolver, which must never feed the dynamic cache.
    ttl: Option<Duration>,
}

/// One upstream failure, before conversion into a shareable [`DnsError`].
#[derive(Debug)]
enum UpstreamError {
    NotFound {
        nxdomain: bool,
        negative_ttl: Option<Duration>,
    },
    TooManyAddresses,
    Allocation,
    Failed(Arc<str>),
}

/// The resolver engine behind the front-end.
trait DnsBackend: Send + Sync {
    /// Resolves `name` to addresses. The returned future must be safe to
    /// drop at any point: dropping cancels the work or, for the uncancellable
    /// system call, abandons the wait while the permit outlives the call.
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        permit: AdmissionPermit,
    ) -> Pin<Box<dyn Future<Output = Result<UpstreamAnswer, UpstreamError>> + Send + 'a>>;
}

/// getaddrinfo on a blocking thread, governed exactly like the routing path:
/// the permit is held inside the blocking task, so an abandoned wait can
/// never abandon the accounting.
struct SystemBackend;

impl DnsBackend for SystemBackend {
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        permit: AdmissionPermit,
    ) -> Pin<Box<dyn Future<Output = Result<UpstreamAnswer, UpstreamError>> + Send + 'a>> {
        Box::pin(async move {
            let (sender, receiver) = tokio::sync::oneshot::channel();
            let name = name.to_owned();
            tokio::task::spawn_blocking(move || {
                let result = system_lookup(&name);
                drop(permit);
                let _ignored = sender.send(result);
            });
            receiver
                .await
                .map_err(|_| UpstreamError::Failed(Arc::from("system resolver task failed")))?
        })
    }
}

fn system_lookup(name: &str) -> Result<UpstreamAnswer, UpstreamError> {
    use std::net::ToSocketAddrs;
    let addresses = (name, 0_u16)
        .to_socket_addrs()
        .map_err(|error| UpstreamError::Failed(Arc::from(error.to_string())))?;
    let mut ips = Vec::new();
    ips.try_reserve_exact(MAX_RESOLVED_IPS)
        .map_err(|_| UpstreamError::Allocation)?;
    for ip in addresses.map(|address| address.ip()) {
        push_unique(&mut ips, ip)?;
    }
    if ips.is_empty() {
        return Err(UpstreamError::NotFound {
            nxdomain: false,
            negative_ttl: None,
        });
    }
    Ok(UpstreamAnswer { ips, ttl: None })
}

/// Real DNS over plain UDP with TCP fallback, observing upstream TTLs.
struct HickoryBackend {
    resolver: TokioResolver,
}

impl HickoryBackend {
    fn build(servers: Vec<NameServerConfig>, timeout: Duration) -> Result<Self, NetError> {
        let mut options = ResolverOpts::default();
        // One absolute timeout lives at the flight level; hickory gets the
        // same per-attempt bound so its internal retry never outlives it.
        options.timeout = timeout;
        options.attempts = 1;
        // The front-end owns caching; the internal cache stays disabled so
        // every upstream query is visible to governance and metrics.
        options.cache_size = 0;
        options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        let resolver = Resolver::builder_with_config(
            ResolverConfig::from_parts(None, Vec::new(), servers),
            TokioRuntimeProvider::new(),
        )
        .with_options(options)
        .build()?;
        Ok(Self { resolver })
    }
}

impl DnsBackend for HickoryBackend {
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        permit: AdmissionPermit,
    ) -> Pin<Box<dyn Future<Output = Result<UpstreamAnswer, UpstreamError>> + Send + 'a>> {
        Box::pin(async move {
            // Always query the absolute name: no search-domain expansion.
            let fqdn = format!("{name}.");
            let result = self.resolver.lookup_ip(fqdn).await;
            drop(permit);
            let lookup = result.map_err(classify_net_error)?;
            let mut ips = Vec::new();
            ips.try_reserve_exact(MAX_RESOLVED_IPS)
                .map_err(|_| UpstreamError::Allocation)?;
            let mut min_ttl = u32::MAX;
            for record in lookup.as_lookup().answers() {
                let ip = match &record.data {
                    RData::A(address) => IpAddr::V4(address.0),
                    RData::AAAA(address) => IpAddr::V6(address.0),
                    _ => continue,
                };
                min_ttl = min_ttl.min(record.ttl);
                push_unique(&mut ips, ip)?;
            }
            if ips.is_empty() {
                return Err(UpstreamError::NotFound {
                    nxdomain: false,
                    negative_ttl: None,
                });
            }
            Ok(UpstreamAnswer {
                ips,
                ttl: Some(Duration::from_secs(u64::from(min_ttl))),
            })
        })
    }
}

fn classify_net_error(error: NetError) -> UpstreamError {
    // Keep timeout / NXDOMAIN / NODATA semantics explicit. Truncation,
    // foreign-class answers, and transport-level connection closure stay
    // distinct Failed messages so a Hickory 0.26.x NetError reshape cannot
    // silently collapse them into an opaque Display string.
    if error.is_connection_closed() {
        return UpstreamError::Failed(Arc::from(
            "upstream DNS connection closed before a usable answer",
        ));
    }
    match error {
        NetError::Timeout => UpstreamError::Failed(Arc::from("upstream DNS query timed out")),
        NetError::Dns(HickoryDnsError::NoRecordsFound(no_records)) => UpstreamError::NotFound {
            nxdomain: no_records.response_code == ResponseCode::NXDomain,
            negative_ttl: no_records
                .negative_ttl
                .map(|ttl| Duration::from_secs(u64::from(ttl))),
        },
        NetError::Truncated => UpstreamError::Failed(Arc::from(
            "upstream DNS response was truncated without a usable TCP fallback",
        )),
        NetError::ForeignClassRecord { .. } => UpstreamError::Failed(Arc::from(
            "upstream DNS response contained a foreign-class record",
        )),
        other => UpstreamError::Failed(Arc::from(other.to_string())),
    }
}

fn push_unique(ips: &mut Vec<IpAddr>, ip: IpAddr) -> Result<(), UpstreamError> {
    if ips.contains(&ip) {
        return Ok(());
    }
    if ips.len() == MAX_RESOLVED_IPS {
        return Err(UpstreamError::TooManyAddresses);
    }
    ips.push(ip);
    Ok(())
}

/// The shared outcome of one coalesced flight.
type FlightResult = Result<Arc<[IpAddr]>, DnsError>;

enum Slot {
    Positive {
        ips: Arc<[IpAddr]>,
        expires: Instant,
    },
    Negative {
        nxdomain: bool,
        expires: Instant,
    },
    InFlight(broadcast::Sender<FlightResult>),
}

impl Slot {
    const fn expires_at(&self) -> Option<Instant> {
        match self {
            Self::Positive { expires, .. } | Self::Negative { expires, .. } => Some(*expires),
            Self::InFlight(_) => None,
        }
    }

    fn is_expired(&self, now: Instant) -> bool {
        self.expires_at().is_some_and(|expires| expires <= now)
    }
}

#[derive(Default)]
struct DnsMetrics {
    requests: AtomicU64,
    cache_hits: AtomicU64,
    negative_hits: AtomicU64,
    coalesced: AtomicU64,
    upstream_queries: AtomicU64,
    upstream_failures: AtomicU64,
    timeouts: AtomicU64,
    admission_denied: AtomicU64,
    evictions: AtomicU64,
    expirations: AtomicU64,
}

impl DnsMetrics {
    fn bump(&self, counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// A point-in-time copy of the resolver counters. Counters are
/// process-observability grade: no names, no per-query logs, no cardinality.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DnsMetricsSnapshot {
    /// Resolution requests received, including cache hits.
    pub requests: u64,
    /// Requests served from the positive cache.
    pub cache_hits: u64,
    /// Requests served from the negative cache.
    pub negative_hits: u64,
    /// Requests coalesced onto an already running flight.
    pub coalesced: u64,
    /// Upstream queries actually sent (one per flight).
    pub upstream_queries: u64,
    /// Upstream queries that failed without a usable answer.
    pub upstream_failures: u64,
    /// Resolutions that hit the absolute timeout.
    pub timeouts: u64,
    /// Resolutions denied by the DNS admission pool.
    pub admission_denied: u64,
    /// Live entries evicted under cache pressure.
    pub evictions: u64,
    /// Expired entries removed.
    pub expirations: u64,
}

struct CacheBounds {
    max_entries: usize,
    min_ttl: Duration,
    max_ttl: Duration,
    negative_ttl: Duration,
    static_ttl: Duration,
}

impl CacheBounds {
    fn new(config: &DnsCacheConfig) -> Self {
        Self {
            max_entries: usize::try_from(config.max_entries()).unwrap_or(usize::MAX),
            min_ttl: Duration::from_secs(u64::from(config.min_ttl_seconds())),
            max_ttl: Duration::from_secs(u64::from(config.max_ttl_seconds())),
            negative_ttl: Duration::from_secs(u64::from(config.negative_ttl_seconds())),
            static_ttl: Duration::from_secs(u64::from(config.static_ttl_seconds())),
        }
    }
}

struct ResolverInner {
    backend: Box<dyn DnsBackend>,
    governor: ResourceGovernor,
    timeout: Duration,
    bounds: CacheBounds,
    /// Optional recent-completion reuse window for TTL-less system-backend
    /// positive answers (`dns.cache.systemReuseMs`). `Some` only for the
    /// system backend; this is not authoritative TTL caching.
    system_reuse: Option<Duration>,
    /// One global table keeps the entry bound global and exact; a name's
    /// static and dynamic entries both count against `max_entries`.
    slots: std::sync::Mutex<HashMap<CacheKey, Slot>>,
    metrics: DnsMetrics,
}

/// The shared, clonable resolution front-end.
#[derive(Clone)]
pub struct DnsResolver {
    inner: Arc<ResolverInner>,
}

impl DnsResolver {
    /// Builds a resolver on the operating system resolver (getaddrinfo).
    ///
    /// Dynamic answers carry no TTL and are never cached, unless the optional
    /// `dns.cache.systemReuseMs` recent-completion window is configured —
    /// that window reuses positive answers briefly and is not authoritative
    /// TTL caching. Coalescing, governance, the absolute timeout, and the
    /// static-peer cache apply either way.
    #[must_use]
    pub fn system(governor: ResourceGovernor, timeout: Duration, cache: &DnsCacheConfig) -> Self {
        let system_reuse = Duration::from_millis(cache.system_reuse_ms());
        Self::with_backend(
            Box::new(SystemBackend),
            governor,
            timeout,
            cache,
            (!system_reuse.is_zero()).then_some(system_reuse),
        )
    }

    fn with_backend(
        backend: Box<dyn DnsBackend>,
        governor: ResourceGovernor,
        timeout: Duration,
        cache: &DnsCacheConfig,
        system_reuse: Option<Duration>,
    ) -> Self {
        Self {
            inner: Arc::new(ResolverInner {
                backend,
                governor,
                timeout,
                bounds: CacheBounds::new(cache),
                system_reuse,
                slots: std::sync::Mutex::new(HashMap::new()),
                metrics: DnsMetrics::default(),
            }),
        }
    }

    /// Builds a resolver from validated configuration. `["system"]` selects
    /// the system backend; any other server list selects the DNS protocol
    /// backend. Hostname servers are resolved once through the system
    /// resolver here (bootstrap), so the configured resolvers themselves
    /// never depend on the cache they feed.
    ///
    /// # Errors
    ///
    /// Returns a server-specification, bootstrap-resolution, or backend
    /// construction error.
    pub fn from_config(
        config: &DnsConfig,
        governor: ResourceGovernor,
    ) -> Result<Self, DnsResolverConfigError> {
        let timeout = Duration::from_millis(config.timeout_ms());
        let cache = config.cache.unwrap_or_default();
        let configured = config.servers();
        let mut servers = Vec::new();
        for (index, server) in configured.iter().enumerate() {
            match parse_server_spec(server)
                .map_err(|reason| DnsResolverConfigError::InvalidServer { index, reason })?
            {
                DnsServerSpec::System => {
                    if configured.len() > 1 {
                        return Err(DnsResolverConfigError::MixedSystem);
                    }
                    return Ok(Self::system(governor, timeout, &cache));
                }
                DnsServerSpec::Address(address) => servers.push(name_server_config(address)),
                DnsServerSpec::Host { host, port } => {
                    let bootstrapped = bootstrap_host(&host).map_err(|reason| {
                        DnsResolverConfigError::Bootstrap {
                            host: host.clone(),
                            reason,
                        }
                    })?;
                    for ip in bootstrapped {
                        servers.push(name_server_config(SocketAddr::new(ip, port)));
                    }
                }
            }
        }
        if servers.is_empty() {
            return Err(DnsResolverConfigError::NoServers);
        }
        let backend = HickoryBackend::build(servers, timeout)
            .map_err(|error| DnsResolverConfigError::Backend(error.to_string()))?;
        // Real upstream TTLs govern; the system recent-completion window
        // does not apply to the DNS protocol backend.
        Ok(Self::with_backend(
            Box::new(backend),
            governor,
            timeout,
            &cache,
            None,
        ))
    }

    /// Resolves a client-requested destination name.
    ///
    /// Dynamic answers are cached only with a TTL-backed upstream answer;
    /// `budget` bounds this resolution together with the configured absolute
    /// timeout, whichever is tighter.
    ///
    /// # Errors
    ///
    /// Returns [`DnsError`] for invalid names, authoritative negatives,
    /// timeouts, admission denial, and upstream failures.
    pub async fn resolve(
        &self,
        name: &str,
        family: IpFamily,
        budget: Duration,
    ) -> Result<Arc<[IpAddr]>, DnsError> {
        self.resolve_class(name, family, budget, QueryClass::Dynamic)
            .await
    }

    /// Resolves a static configured peer (cover target, fixed outbound
    /// endpoint). Static answers are cached for `dns.cache.staticTtlSeconds`
    /// in every resolver mode; the operator owns that staleness.
    ///
    /// # Errors
    ///
    /// Returns [`DnsError`] for invalid names, negatives, timeouts, admission
    /// denial, and upstream failures.
    pub async fn resolve_static(
        &self,
        name: &str,
        family: IpFamily,
        budget: Duration,
    ) -> Result<Arc<[IpAddr]>, DnsError> {
        self.resolve_class(name, family, budget, QueryClass::Static)
            .await
    }

    async fn resolve_class(
        &self,
        name: &str,
        family: IpFamily,
        budget: Duration,
        class: QueryClass,
    ) -> Result<Arc<[IpAddr]>, DnsError> {
        self.inner.metrics.bump(&self.inner.metrics.requests);
        let key = CacheKey {
            class,
            name: normalize_name(name)?,
        };
        if let Ok(ip) = key.name.parse::<IpAddr>() {
            return filter_family(&Arc::from([ip]), family);
        }
        let effective = budget.min(self.inner.timeout);
        if effective.is_zero() {
            self.inner.metrics.bump(&self.inner.metrics.timeouts);
            return Err(DnsError::Timeout);
        }
        loop {
            let mut receiver = {
                let mut slots = self.locked_slots();
                let now = Instant::now();
                match slots.get(&key) {
                    Some(Slot::Positive { ips, expires }) if *expires > now => {
                        self.inner.metrics.bump(&self.inner.metrics.cache_hits);
                        return filter_family(ips, family);
                    }
                    Some(Slot::Negative { nxdomain, expires }) if *expires > now => {
                        self.inner.metrics.bump(&self.inner.metrics.negative_hits);
                        return Err(DnsError::NotFound {
                            nxdomain: *nxdomain,
                        });
                    }
                    Some(Slot::InFlight(sender)) => {
                        self.inner.metrics.bump(&self.inner.metrics.coalesced);
                        sender.subscribe()
                    }
                    Some(_) => {
                        // Expired entry: drop it and retry as a fresh lookup.
                        slots.remove(&key);
                        self.inner.metrics.bump(&self.inner.metrics.expirations);
                        continue;
                    }
                    None => {
                        let permit = self
                            .inner
                            .governor
                            .try_acquire(AdmissionKind::DnsLookup)
                            .map_err(|_| {
                                self.inner
                                    .metrics
                                    .bump(&self.inner.metrics.admission_denied);
                                DnsError::Limit
                            })?;
                        // The entry bound applies before an in-flight slot is
                        // claimed as well; only a table of purely in-flight
                        // entries may transiently exceed it, bounded by the
                        // governor's DNS permit count.
                        if slots.len() >= self.inner.bounds.max_entries {
                            evict_pressure(&self.inner, &mut slots, now);
                        }
                        let (sender, _) = broadcast::channel(1);
                        slots.insert(key.clone(), Slot::InFlight(sender.clone()));
                        Self::spawn_flight(
                            Arc::clone(&self.inner),
                            key.clone(),
                            sender.clone(),
                            permit,
                            class,
                            effective,
                        );
                        sender.subscribe()
                    }
                }
            };
            match time::timeout(effective, receiver.recv()).await {
                Ok(Ok(outcome)) => return outcome.and_then(|ips| filter_family(&ips, family)),
                // The leader task vanished without publishing (shutdown or
                // panic): loop once more to lead or join a fresh flight.
                Ok(Err(_)) => continue,
                Err(_) => {
                    self.inner.metrics.bump(&self.inner.metrics.timeouts);
                    return Err(DnsError::Timeout);
                }
            }
        }
    }

    fn locked_slots(&self) -> std::sync::MutexGuard<'_, HashMap<CacheKey, Slot>> {
        self.inner
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn spawn_flight(
        inner: Arc<ResolverInner>,
        key: CacheKey,
        sender: broadcast::Sender<FlightResult>,
        permit: AdmissionPermit,
        class: QueryClass,
        timeout: Duration,
    ) {
        tokio::spawn(async move {
            inner.metrics.bump(&inner.metrics.upstream_queries);
            let result = time::timeout(timeout, inner.backend.lookup(&key.name, permit)).await;
            let now = Instant::now();
            let (slot, outcome): (Option<Slot>, FlightResult) = match result {
                Err(_) => {
                    inner.metrics.bump(&inner.metrics.timeouts);
                    (None, Err(DnsError::Timeout))
                }
                Ok(Err(UpstreamError::NotFound {
                    nxdomain,
                    negative_ttl,
                })) => {
                    // Negative caching is strictly TTL-backed: an SOA TTL
                    // clamped to the configured ceiling, and never for static
                    // peers (an operator fixing a peer's DNS must not wait).
                    let ttl = (class == QueryClass::Dynamic)
                        .then_some(negative_ttl)
                        .flatten()
                        .map(|ttl| ttl.min(inner.bounds.negative_ttl))
                        .filter(|ttl| !ttl.is_zero());
                    let slot = ttl.map(|ttl| Slot::Negative {
                        nxdomain,
                        expires: now + ttl,
                    });
                    (slot, Err(DnsError::NotFound { nxdomain }))
                }
                Ok(Err(UpstreamError::TooManyAddresses)) => (None, Err(DnsError::TooManyAddresses)),
                Ok(Err(UpstreamError::Allocation)) => (None, Err(DnsError::Allocation)),
                Ok(Err(UpstreamError::Failed(message))) => {
                    inner.metrics.bump(&inner.metrics.upstream_failures);
                    (None, Err(DnsError::Failed(message)))
                }
                Ok(Ok(answer)) => {
                    let ips: Arc<[IpAddr]> = answer.ips.into();
                    let ttl = match class {
                        QueryClass::Static => Some(inner.bounds.static_ttl),
                        // Dynamic answers enter the cache only with a real
                        // upstream TTL, clamped to the configured bounds.
                        // TTL-less answers come from the system backend; the
                        // optional recent-completion window reuses them for
                        // a short bounded time — recent-completion reuse,
                        // not authoritative TTL caching.
                        QueryClass::Dynamic => answer
                            .ttl
                            .map(|ttl| ttl.clamp(inner.bounds.min_ttl, inner.bounds.max_ttl))
                            .or(inner.system_reuse),
                    }
                    .filter(|ttl| !ttl.is_zero());
                    let slot = ttl.map(|ttl| Slot::Positive {
                        ips: Arc::clone(&ips),
                        expires: now + ttl,
                    });
                    (slot, Ok(ips))
                }
            };
            match slot {
                Some(slot) => insert_bounded(&inner, key, slot, now),
                None => {
                    inner
                        .slots
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .remove(&key);
                }
            }
            let _ignored = sender.send(outcome);
        });
    }

    /// Returns the current counter snapshot.
    #[must_use]
    pub fn metrics(&self) -> DnsMetricsSnapshot {
        let metrics = &self.inner.metrics;
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        DnsMetricsSnapshot {
            requests: load(&metrics.requests),
            cache_hits: load(&metrics.cache_hits),
            negative_hits: load(&metrics.negative_hits),
            coalesced: load(&metrics.coalesced),
            upstream_queries: load(&metrics.upstream_queries),
            upstream_failures: load(&metrics.upstream_failures),
            timeouts: load(&metrics.timeouts),
            admission_denied: load(&metrics.admission_denied),
            evictions: load(&metrics.evictions),
            expirations: load(&metrics.expirations),
        }
    }

    /// Returns the number of cached and in-flight entries.
    #[must_use]
    pub fn cache_len(&self) -> usize {
        self.locked_slots().len()
    }
}

fn normalize_name(name: &str) -> Result<Box<str>, DnsError> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > MAX_NAME_LENGTH {
        return Err(DnsError::InvalidName);
    }
    Ok(trimmed.to_ascii_lowercase().into_boxed_str())
}

fn filter_family(ips: &Arc<[IpAddr]>, family: IpFamily) -> Result<Arc<[IpAddr]>, DnsError> {
    if family == IpFamily::Any {
        return Ok(Arc::clone(ips));
    }
    let filtered: Vec<IpAddr> = ips
        .iter()
        .copied()
        .filter(|ip| family.admits(*ip))
        .collect();
    if filtered.is_empty() {
        return Err(DnsError::NoAddresses);
    }
    Ok(Arc::from(filtered))
}

fn insert_bounded(inner: &ResolverInner, key: CacheKey, slot: Slot, now: Instant) {
    let mut slots = inner.slots.lock().unwrap_or_else(PoisonError::into_inner);
    // Replacing our own in-flight entry never grows the table.
    if slots.len() >= inner.bounds.max_entries && !slots.contains_key(&key) {
        evict_pressure(inner, &mut slots, now);
    }
    slots.insert(key, slot);
}

/// Makes room for a new entry: expired entries first, then the
/// earliest-expiring cached entry. In-flight entries are never evicted;
/// their waiters would otherwise lose the flight.
fn evict_pressure(inner: &ResolverInner, slots: &mut HashMap<CacheKey, Slot>, now: Instant) {
    let before = slots.len();
    slots.retain(|_, slot| !slot.is_expired(now));
    inner
        .metrics
        .expirations
        .fetch_add((before - slots.len()) as u64, Ordering::Relaxed);
    if slots.len() >= inner.bounds.max_entries {
        let victim = slots
            .iter()
            .filter_map(|(key, slot)| Some((key.clone(), slot.expires_at()?)))
            .min_by_key(|(_, expires)| *expires)
            .map(|(key, _)| key);
        if let Some(victim) = victim {
            slots.remove(&victim);
            inner.metrics.bump(&inner.metrics.evictions);
        }
    }
}

/// One parsed `dns.servers` entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsServerSpec {
    /// The operating system resolver.
    System,
    /// An upstream DNS server socket address.
    Address(SocketAddr),
    /// An upstream DNS server hostname, resolved once through the system
    /// resolver at startup.
    Host {
        /// The configured hostname.
        host: String,
        /// The configured or default (53) DNS port.
        port: u16,
    },
}

/// Parses one `dns.servers` entry without performing any network I/O.
///
/// Accepted forms: `system`, an IP literal (port 53), a socket address
/// (`1.1.1.1:53`, `[2606:4700:4700::1111]:853`), or a hostname with an
/// optional `:port`.
///
/// # Errors
///
/// Returns [`DnsServerSpecError`] describing the syntax violation.
pub fn parse_server_spec(spec: &str) -> Result<DnsServerSpec, DnsServerSpecError> {
    let spec = spec.trim();
    if spec == "system" {
        return Ok(DnsServerSpec::System);
    }
    if let Ok(ip) = spec.parse::<IpAddr>() {
        return Ok(DnsServerSpec::Address(SocketAddr::new(ip, 53)));
    }
    if let Ok(address) = spec.parse::<SocketAddr>() {
        return Ok(DnsServerSpec::Address(address));
    }
    let (host, port) = match spec.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            let port = port
                .parse::<u16>()
                .map_err(|_| DnsServerSpecError::new(spec, "port must be a number"))?;
            if port == 0 {
                return Err(DnsServerSpecError::new(
                    spec,
                    "port must be greater than zero",
                ));
            }
            (host, port)
        }
        _ => (spec, 53),
    };
    validate_dns_hostname(host).map_err(|reason| DnsServerSpecError::new(spec, reason))?;
    Ok(DnsServerSpec::Host {
        host: host.to_owned(),
        port,
    })
}

fn validate_dns_hostname(host: &str) -> Result<(), &'static str> {
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.len() > MAX_NAME_LENGTH {
        return Err("hostname must be between 1 and 253 characters");
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("hostname labels must be between 1 and 63 characters");
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("hostname labels must be alphanumeric or hyphens");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("hostname labels must not start or end with a hyphen");
        }
    }
    Ok(())
}

/// A `dns.servers` entry violates the accepted syntax.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsServerSpecError {
    spec: String,
    reason: &'static str,
}

impl DnsServerSpecError {
    fn new(spec: &str, reason: &'static str) -> Self {
        Self {
            spec: spec.to_owned(),
            reason,
        }
    }
}

impl fmt::Display for DnsServerSpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid DNS server {:?}: {}",
            self.spec, self.reason
        )
    }
}

impl Error for DnsServerSpecError {}

/// A DNS resolver could not be built from validated configuration.
#[derive(Clone, Debug)]
pub enum DnsResolverConfigError {
    /// One server entry failed to parse.
    InvalidServer {
        /// Index into `dns.servers`.
        index: usize,
        /// The syntax violation.
        reason: DnsServerSpecError,
    },
    /// `system` was mixed with upstream DNS servers.
    MixedSystem,
    /// The server list resolved to no upstream DNS server.
    NoServers,
    /// A hostname server could not be resolved through the system resolver.
    Bootstrap {
        /// The configured hostname.
        host: String,
        /// The system resolution failure.
        reason: String,
    },
    /// The DNS protocol backend failed to initialize.
    Backend(String),
}

impl fmt::Display for DnsResolverConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidServer { index, reason } => {
                write!(formatter, "dns.servers[{index}]: {reason}")
            }
            Self::MixedSystem => {
                formatter.write_str("dns.servers must not mix system with upstream servers")
            }
            Self::NoServers => formatter.write_str("dns.servers resolved to no upstream server"),
            Self::Bootstrap { host, reason } => write!(
                formatter,
                "dns.servers hostname {host:?} failed bootstrap resolution: {reason}"
            ),
            Self::Backend(reason) => write!(formatter, "DNS resolver backend failed: {reason}"),
        }
    }
}

impl Error for DnsResolverConfigError {}

/// Resolves a configured DNS server hostname through the system resolver,
/// once, at startup. This blocking call is the bootstrap exception: the
/// configured resolvers must never depend on the cache they feed.
fn bootstrap_host(host: &str) -> Result<Vec<IpAddr>, String> {
    use std::net::ToSocketAddrs;
    let addresses = (host, 0_u16)
        .to_socket_addrs()
        .map_err(|error| error.to_string())?;
    let mut ips = Vec::new();
    for ip in addresses.map(|address| address.ip()) {
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    if ips.is_empty() {
        return Err("system resolver returned no addresses".to_owned());
    }
    Ok(ips)
}

fn name_server_config(address: SocketAddr) -> NameServerConfig {
    let mut udp = ConnectionConfig::udp();
    udp.port = address.port();
    let mut tcp = ConnectionConfig::tcp();
    tcp.port = address.port();
    NameServerConfig::new(address.ip(), true, vec![udp, tcp])
}

/// The process-lifetime shared resolver, installed once at startup.
static SHARED: OnceLock<DnsResolver> = OnceLock::new();

/// Installs the process-lifetime shared resolver built from validated
/// configuration. The first installation wins; like the other process
/// authorities (admission ceilings, dial barrier), later attempts are
/// rejected so a reload never silently multiplies pools or swaps a cache
/// that in-flight lookups rely on.
///
/// # Errors
///
/// Returns the resolver that could not be installed.
pub fn install_shared(resolver: DnsResolver) -> Result<(), DnsResolver> {
    SHARED.set(resolver)
}

/// Returns the installed shared resolver, or a lazily built default: system
/// backend, default cache bounds, and a default `DnsLookup` pool. The default
/// keeps every connector path governed and coalesced even when no production
/// server installed a configured resolver (tests, embedding).
#[must_use]
pub fn shared() -> DnsResolver {
    SHARED
        .get_or_init(|| {
            DnsResolver::system(
                ResourceGovernor::new(&ResourceGovernorPolicy::default()),
                Duration::from_millis(crate::config::node::dns::DnsConfig::default().timeout_ms()),
                &DnsCacheConfig::default(),
            )
        })
        .clone()
}

#[cfg(test)]
mod tests;
