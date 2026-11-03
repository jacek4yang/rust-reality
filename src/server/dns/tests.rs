use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::time;

use std::io;

use hickory_resolver::{
    net::NetError,
    proto::rr::{DNSClass, Name, RecordType},
};

use super::{
    DnsBackend, DnsCacheConfig, DnsError, DnsResolver, DnsServerSpec, IpFamily, UpstreamAnswer,
    UpstreamError, classify_net_error, parse_server_spec,
};
use crate::runtime::ResourceGovernor;
use crate::runtime::policy::ResourceGovernorPolicy;

#[test]
fn classify_net_error_preserves_timeout_and_protocol_failures() {
    match classify_net_error(NetError::Timeout) {
        UpstreamError::Failed(message) => {
            assert_eq!(&*message, "upstream DNS query timed out");
        }
        other => panic!("unexpected classification: {other:?}"),
    }

    match classify_net_error(NetError::Truncated) {
        UpstreamError::Failed(message) => assert!(
            message.contains("truncated"),
            "truncated must stay explicit: {message}"
        ),
        other => panic!("unexpected classification: {other:?}"),
    }

    let foreign = NetError::ForeignClassRecord {
        record_name: Name::from_ascii("example.test.").expect("name"),
        record_class: DNSClass::CH,
        record_type: RecordType::TXT,
    };
    match classify_net_error(foreign) {
        UpstreamError::Failed(message) => assert!(
            message.contains("foreign-class"),
            "foreign-class must stay explicit: {message}"
        ),
        other => panic!("unexpected classification: {other:?}"),
    }

    let closed = NetError::from(io::Error::from(io::ErrorKind::ConnectionReset));
    assert!(closed.is_connection_closed());
    match classify_net_error(closed) {
        UpstreamError::Failed(message) => assert!(
            message.contains("connection closed"),
            "connection closed must stay explicit: {message}"
        ),
        other => panic!("unexpected classification: {other:?}"),
    }
}

/// A scripted backend: counts calls, optionally delays, and replays one
/// programmable outcome per call.
struct MockBackend {
    calls: AtomicUsize,
    delay: time::Duration,
    outcome: std::sync::Mutex<MockOutcome>,
}

#[derive(Clone)]
enum MockOutcome {
    Answer {
        ips: Vec<IpAddr>,
        ttl: Option<Duration>,
    },
    NotFound {
        nxdomain: bool,
        negative_ttl: Option<Duration>,
    },
    Failed,
}

impl MockBackend {
    fn answering(ips: Vec<IpAddr>, ttl: Option<Duration>) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            delay: Duration::ZERO,
            outcome: std::sync::Mutex::new(MockOutcome::Answer { ips, ttl }),
        }
    }

    fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    fn set_outcome(&self, outcome: MockOutcome) {
        *self.outcome.lock().expect("mock outcome lock") = outcome;
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
}

impl DnsBackend for MockBackend {
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        permit: crate::runtime::AdmissionPermit,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<UpstreamAnswer, UpstreamError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let _name = name;
            self.calls.fetch_add(1, Ordering::AcqRel);
            // Like the real backends, the permit is held until the
            // upstream work (including its delay) actually ends.
            if !self.delay.is_zero() {
                time::sleep(self.delay).await;
            }
            drop(permit);
            match self.outcome.lock().expect("mock outcome lock").clone() {
                MockOutcome::Answer { ips, ttl } => Ok(UpstreamAnswer { ips, ttl }),
                MockOutcome::NotFound {
                    nxdomain,
                    negative_ttl,
                } => Err(UpstreamError::NotFound {
                    nxdomain,
                    negative_ttl,
                }),
                MockOutcome::Failed => Err(UpstreamError::Failed(Arc::from("mock failure"))),
            }
        })
    }
}

struct Harness {
    resolver: DnsResolver,
    backend: Arc<MockBackend>,
}

fn build(
    backend: MockBackend,
    cache: &DnsCacheConfig,
    timeout: Duration,
    max_dns_lookups: u32,
) -> Harness {
    build_inner(backend, cache, timeout, max_dns_lookups, None)
}

/// A harness behaving like the system backend: TTL-less answers, with the
/// recent-completion window taken from the cache config.
fn build_system(
    backend: MockBackend,
    cache: &DnsCacheConfig,
    timeout: Duration,
    max_dns_lookups: u32,
) -> Harness {
    let reuse = Duration::from_millis(cache.system_reuse_ms());
    build_inner(
        backend,
        cache,
        timeout,
        max_dns_lookups,
        (!reuse.is_zero()).then_some(reuse),
    )
}

fn build_inner(
    backend: MockBackend,
    cache: &DnsCacheConfig,
    timeout: Duration,
    max_dns_lookups: u32,
    system_reuse: Option<Duration>,
) -> Harness {
    let backend = Arc::new(backend);
    let resolver = DnsResolver::with_backend(
        Box::new(ArcBackend(Arc::clone(&backend))),
        ResourceGovernor::new(&ResourceGovernorPolicy {
            max_dns_lookups,
            ..ResourceGovernorPolicy::default()
        }),
        timeout,
        cache,
        system_reuse,
    );
    Harness { resolver, backend }
}

/// Arc indirection so tests keep a handle to the scripted backend.
struct ArcBackend(Arc<MockBackend>);

impl DnsBackend for ArcBackend {
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        permit: crate::runtime::AdmissionPermit,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<UpstreamAnswer, UpstreamError>> + Send + 'a>,
    > {
        self.0.lookup(name, permit)
    }
}

fn cache_config() -> DnsCacheConfig {
    DnsCacheConfig {
        min_ttl_seconds: Some(0),
        ..DnsCacheConfig::default()
    }
}

fn v4(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
}

fn v6(last: u8) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, u16::from(last)))
}

#[test]
fn parses_server_spec_forms() {
    use std::net::SocketAddr;
    assert_eq!(parse_server_spec("system"), Ok(DnsServerSpec::System));
    assert_eq!(
        parse_server_spec("1.1.1.1"),
        Ok(DnsServerSpec::Address(SocketAddr::from(([1, 1, 1, 1], 53))))
    );
    assert_eq!(
        parse_server_spec("1.1.1.1:5353"),
        Ok(DnsServerSpec::Address(SocketAddr::from((
            [1, 1, 1, 1],
            5353
        ))))
    );
    assert_eq!(
        parse_server_spec("[2606:4700:4700::1111]:853"),
        Ok(DnsServerSpec::Address(SocketAddr::new(
            "2606:4700:4700::1111".parse().expect("v6 literal"),
            853
        )))
    );
    assert_eq!(
        parse_server_spec("dns.example.com"),
        Ok(DnsServerSpec::Host {
            host: "dns.example.com".to_owned(),
            port: 53
        })
    );
    assert_eq!(
        parse_server_spec("dns.example.com:853"),
        Ok(DnsServerSpec::Host {
            host: "dns.example.com".to_owned(),
            port: 853
        })
    );
    assert!(parse_server_spec("").is_err());
    assert!(parse_server_spec("example.com:0").is_err());
    assert!(parse_server_spec("example.com:nope").is_err());
    assert!(parse_server_spec("-bad.example.com").is_err());
    assert!(parse_server_spec("bad_underscore.example").is_err());
}

#[tokio::test]
async fn coalesces_concurrent_identical_lookups() {
    let harness = build(
        MockBackend::answering(vec![v4(1)], None).with_delay(Duration::from_millis(50)),
        &cache_config(),
        Duration::from_secs(5),
        64,
    );
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..32 {
        let resolver = harness.resolver.clone();
        tasks.spawn(async move {
            resolver
                .resolve("coalesce.test", IpFamily::Any, Duration::from_secs(5))
                .await
        });
    }
    let mut successes = 0;
    while let Some(outcome) = tasks.join_next().await {
        let addresses = outcome
            .expect("task must not panic")
            .expect("resolution must succeed");
        assert_eq!(addresses.as_ref(), &[v4(1)]);
        successes += 1;
    }
    assert_eq!(successes, 32);
    assert_eq!(harness.backend.calls(), 1);
    let metrics = harness.resolver.metrics();
    assert_eq!(metrics.upstream_queries, 1);
    assert_eq!(metrics.coalesced, 31);
}

#[tokio::test]
async fn dynamic_answers_are_cached_only_with_a_ttl() {
    // TTL-backed answer: second resolution is a cache hit.
    let harness = build(
        MockBackend::answering(vec![v4(1)], Some(Duration::from_secs(30))),
        &cache_config(),
        Duration::from_secs(5),
        64,
    );
    for _ in 0..3 {
        harness
            .resolver
            .resolve("cached.test", IpFamily::Any, Duration::from_secs(5))
            .await
            .expect("resolution must succeed");
    }
    assert_eq!(harness.backend.calls(), 1);
    assert_eq!(harness.resolver.metrics().cache_hits, 2);

    // TTL-less answer (system resolver semantics): never cached.
    let harness = build(
        MockBackend::answering(vec![v4(1)], None),
        &cache_config(),
        Duration::from_secs(5),
        64,
    );
    for _ in 0..3 {
        harness
            .resolver
            .resolve("uncached.test", IpFamily::Any, Duration::from_secs(5))
            .await
            .expect("resolution must succeed");
    }
    assert_eq!(harness.backend.calls(), 3);
    assert_eq!(harness.resolver.metrics().cache_hits, 0);
    assert_eq!(harness.resolver.cache_len(), 0);
}

#[tokio::test]
async fn positive_entries_expire_at_their_ttl() {
    let harness = build(
        MockBackend::answering(vec![v4(1)], Some(Duration::from_millis(60))),
        &cache_config(),
        Duration::from_secs(5),
        64,
    );
    harness
        .resolver
        .resolve("expiry.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("resolution must succeed");
    time::sleep(Duration::from_millis(30)).await;
    harness
        .resolver
        .resolve("expiry.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("warm resolution must succeed");
    assert_eq!(harness.backend.calls(), 1);
    time::sleep(Duration::from_millis(60)).await;
    harness
        .resolver
        .resolve("expiry.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("post-expiry resolution must succeed");
    assert_eq!(harness.backend.calls(), 2);
}

#[tokio::test]
async fn upstream_ttls_are_clamped_to_the_configured_floor() {
    let cache = DnsCacheConfig {
        min_ttl_seconds: Some(2),
        ..cache_config()
    };
    let harness = build(
        MockBackend::answering(vec![v4(1)], Some(Duration::from_millis(10))),
        &cache,
        Duration::from_secs(5),
        64,
    );
    harness
        .resolver
        .resolve("floor.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("resolution must succeed");
    time::sleep(Duration::from_millis(500)).await;
    harness
        .resolver
        .resolve("floor.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("clamped entry must still be warm");
    assert_eq!(
        harness.backend.calls(),
        1,
        "a 10ms upstream TTL clamped to a 2s floor must still hit"
    );
}

#[tokio::test]
async fn negative_answers_cache_only_with_an_soa_ttl() {
    let backend = MockBackend::answering(vec![], None);
    backend.set_outcome(MockOutcome::NotFound {
        nxdomain: true,
        negative_ttl: Some(Duration::from_millis(80)),
    });
    let harness = build(backend, &cache_config(), Duration::from_secs(5), 64);
    for _ in 0..2 {
        let error = harness
            .resolver
            .resolve("absent.test", IpFamily::Any, Duration::from_secs(5))
            .await
            .expect_err("NXDOMAIN must fail");
        assert!(matches!(error, DnsError::NotFound { nxdomain: true }));
    }
    assert_eq!(harness.backend.calls(), 1);
    assert_eq!(harness.resolver.metrics().negative_hits, 1);
    time::sleep(Duration::from_millis(120)).await;
    let error = harness
        .resolver
        .resolve("absent.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect_err("expired negative entry must re-resolve upstream");
    assert!(matches!(error, DnsError::NotFound { nxdomain: true }));
    assert_eq!(harness.backend.calls(), 2);

    // No SOA TTL: the negative answer is never cached.
    let backend = MockBackend::answering(vec![], None);
    backend.set_outcome(MockOutcome::NotFound {
        nxdomain: false,
        negative_ttl: None,
    });
    let harness = build(backend, &cache_config(), Duration::from_secs(5), 64);
    for _ in 0..2 {
        harness
            .resolver
            .resolve("nodata.test", IpFamily::Any, Duration::from_secs(5))
            .await
            .expect_err("NODATA must fail");
    }
    assert_eq!(harness.backend.calls(), 2);
}

#[tokio::test]
async fn static_peers_cache_without_a_ttl_in_every_mode() {
    let harness = build(
        MockBackend::answering(vec![v4(7)], None),
        &cache_config(),
        Duration::from_secs(5),
        64,
    );
    for _ in 0..3 {
        let addresses = harness
            .resolver
            .resolve_static("peer.test", IpFamily::Any, Duration::from_secs(5))
            .await
            .expect("static resolution must succeed");
        assert_eq!(addresses.as_ref(), &[v4(7)]);
    }
    assert_eq!(harness.backend.calls(), 1);
    assert_eq!(harness.resolver.metrics().cache_hits, 2);
}

#[tokio::test]
async fn static_negatives_are_never_cached() {
    let backend = MockBackend::answering(vec![], None);
    backend.set_outcome(MockOutcome::NotFound {
        nxdomain: true,
        negative_ttl: Some(Duration::from_secs(300)),
    });
    let harness = build(backend, &cache_config(), Duration::from_secs(5), 64);
    for _ in 0..2 {
        harness
            .resolver
            .resolve_static("gone-peer.test", IpFamily::Any, Duration::from_secs(5))
            .await
            .expect_err("static NXDOMAIN must fail");
    }
    assert_eq!(
        harness.backend.calls(),
        2,
        "an operator fixing a static peer must not wait out a negative cache"
    );
}

#[tokio::test]
async fn a_cancelled_waiter_never_disturbs_the_flight() {
    let harness = build(
        MockBackend::answering(vec![v4(1)], Some(Duration::from_secs(30)))
            .with_delay(Duration::from_millis(60)),
        &cache_config(),
        Duration::from_secs(5),
        64,
    );
    let cancelled = {
        let resolver = harness.resolver.clone();
        tokio::spawn(async move {
            resolver
                .resolve("cancel.test", IpFamily::Any, Duration::from_secs(5))
                .await
        })
    };
    time::sleep(Duration::from_millis(10)).await;
    cancelled.abort();
    time::sleep(Duration::from_millis(120)).await;
    let addresses = harness
        .resolver
        .resolve("cancel.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("the completed flight must have populated the cache");
    assert_eq!(addresses.as_ref(), &[v4(1)]);
    assert_eq!(harness.backend.calls(), 1);
    assert_eq!(harness.resolver.metrics().cache_hits, 1);
}

#[tokio::test]
async fn admission_denial_is_reported_without_a_flight() {
    let harness = build(
        MockBackend::answering(vec![v4(1)], None).with_delay(Duration::from_millis(200)),
        &cache_config(),
        Duration::from_secs(5),
        1,
    );
    let first = {
        let resolver = harness.resolver.clone();
        tokio::spawn(async move {
            resolver
                .resolve("first.test", IpFamily::Any, Duration::from_secs(5))
                .await
        })
    };
    time::sleep(Duration::from_millis(20)).await;
    let error = harness
        .resolver
        .resolve("second.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect_err("the single permit is held by the first flight");
    assert!(matches!(error, DnsError::Limit));
    assert_eq!(harness.resolver.metrics().admission_denied, 1);
    first
        .await
        .expect("first flight must finish")
        .expect("first resolution must succeed");
}

#[tokio::test]
async fn timeouts_release_the_slot_and_recovery_works() {
    let backend = MockBackend::answering(vec![v4(1)], None).with_delay(Duration::from_secs(30));
    let harness = build(backend, &cache_config(), Duration::from_millis(40), 64);
    let error = harness
        .resolver
        .resolve("slow.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect_err("the slow backend must hit the absolute timeout");
    assert!(matches!(error, DnsError::Timeout));
    // The flight task's own timeout fires concurrently with the waiter's;
    // give it a moment to publish and clear the slot.
    time::sleep(Duration::from_millis(60)).await;
    assert_eq!(
        harness.resolver.cache_len(),
        0,
        "a timed-out flight leaves no slot"
    );

    // The resolver recovers once the backend answers promptly again.
    harness.backend.set_outcome(MockOutcome::Answer {
        ips: vec![v4(2)],
        ttl: Some(Duration::from_secs(30)),
    });
    // Shrink the emulated upstream latency below the timeout.
    // (The old 30s flight is still sleeping in the background; it will be
    // dropped when the test runtime shuts down.)
    let backend = MockBackend::answering(vec![v4(2)], Some(Duration::from_secs(30)));
    let harness = build(backend, &cache_config(), Duration::from_millis(400), 64);
    let addresses = harness
        .resolver
        .resolve("slow.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("a recovered backend must resolve");
    assert_eq!(addresses.as_ref(), &[v4(2)]);
}

#[tokio::test]
async fn cache_pressure_evicts_the_earliest_expiring_entry() {
    let cache = DnsCacheConfig {
        max_entries: Some(2),
        ..cache_config()
    };
    let harness = build(
        MockBackend::answering(vec![v4(1)], Some(Duration::from_secs(10))),
        &cache,
        Duration::from_secs(5),
        64,
    );
    harness
        .resolver
        .resolve("a.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("a.test resolves");
    // b.test gets the shortest remaining TTL: it is the eviction victim.
    harness.backend.set_outcome(MockOutcome::Answer {
        ips: vec![v4(2)],
        ttl: Some(Duration::from_secs(5)),
    });
    harness
        .resolver
        .resolve("b.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("b.test resolves");
    harness.backend.set_outcome(MockOutcome::Answer {
        ips: vec![v4(3)],
        ttl: Some(Duration::from_secs(10)),
    });
    harness
        .resolver
        .resolve("c.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("c.test resolves");
    assert!(
        harness.resolver.cache_len() <= 2,
        "the cache must stay bounded"
    );
    assert_eq!(harness.resolver.metrics().evictions, 1);
    // a.test survived; b.test was evicted and must re-resolve upstream.
    harness
        .resolver
        .resolve("a.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("a.test must still be cached");
    let calls_before = harness.backend.calls();
    harness
        .resolver
        .resolve("b.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("b.test re-resolves after eviction");
    assert_eq!(harness.backend.calls(), calls_before + 1);
}

#[tokio::test]
async fn static_and_dynamic_entries_for_one_name_are_independent() {
    // Dynamic first: the static lookup must not be satisfied by the
    // dynamic entry, and afterwards each class is served by its own
    // entry.
    let harness = build(
        MockBackend::answering(vec![v4(1)], Some(Duration::from_secs(30))),
        &cache_config(),
        Duration::from_secs(5),
        64,
    );
    harness
        .resolver
        .resolve("shared.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("dynamic resolution");
    harness
        .resolver
        .resolve_static("shared.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("static resolution goes upstream despite the dynamic entry");
    assert_eq!(harness.backend.calls(), 2);
    assert_eq!(harness.resolver.cache_len(), 2);
    for _ in 0..2 {
        harness
            .resolver
            .resolve("shared.test", IpFamily::Any, Duration::from_secs(5))
            .await
            .expect("warm dynamic resolution");
        harness
            .resolver
            .resolve_static("shared.test", IpFamily::Any, Duration::from_secs(5))
            .await
            .expect("warm static resolution");
    }
    assert_eq!(harness.backend.calls(), 2, "each class hits its own entry");
    assert_eq!(harness.resolver.metrics().cache_hits, 4);

    // Static first: the dynamic lookup must not be satisfied by the
    // static entry.
    let harness = build(
        MockBackend::answering(vec![v4(1)], Some(Duration::from_secs(30))),
        &cache_config(),
        Duration::from_secs(5),
        64,
    );
    harness
        .resolver
        .resolve_static("shared.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("static resolution");
    harness
        .resolver
        .resolve("shared.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("dynamic resolution goes upstream despite the static entry");
    assert_eq!(harness.backend.calls(), 2);
}

#[tokio::test]
async fn a_static_ttl_never_extends_a_dynamic_entry() {
    // A TTL-less dynamic answer is uncached, and the static entry for the
    // same name must not lend it a lifetime either.
    let harness = build(
        MockBackend::answering(vec![v4(1)], None),
        &cache_config(),
        Duration::from_secs(5),
        64,
    );
    harness
        .resolver
        .resolve_static("peer.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("static resolution");
    for _ in 0..2 {
        harness
            .resolver
            .resolve("peer.test", IpFamily::Any, Duration::from_secs(5))
            .await
            .expect("dynamic resolution");
    }
    assert_eq!(
        harness.backend.calls(),
        3,
        "one static flight plus two TTL-less dynamic flights"
    );

    // A short-TTL dynamic entry expires on its own clock even while the
    // long-lived static entry for the same name is still valid.
    let harness = build(
        MockBackend::answering(vec![v4(1)], Some(Duration::from_millis(60))),
        &cache_config(),
        Duration::from_secs(5),
        64,
    );
    harness
        .resolver
        .resolve("short.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("dynamic resolution");
    harness
        .resolver
        .resolve_static("short.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("static resolution");
    assert_eq!(harness.backend.calls(), 2);
    time::sleep(Duration::from_millis(100)).await;
    harness
        .resolver
        .resolve("short.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("the expired dynamic entry re-resolves");
    assert_eq!(
        harness.backend.calls(),
        3,
        "the static entry must not extend the dynamic lifetime"
    );
    harness
        .resolver
        .resolve_static("short.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("the static entry is still valid");
    assert_eq!(harness.backend.calls(), 3);
}

#[tokio::test]
async fn cross_class_flights_for_one_name_are_independent() {
    // A cold burst of static and dynamic lookups for the same name runs
    // exactly two flights: one per class, each coalescing its waiters.
    let harness = build(
        MockBackend::answering(vec![v4(1)], Some(Duration::from_secs(30)))
            .with_delay(Duration::from_millis(50)),
        &cache_config(),
        Duration::from_secs(5),
        64,
    );
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..32 {
        let resolver = harness.resolver.clone();
        tasks.spawn(async move {
            if index % 2 == 0 {
                resolver
                    .resolve("burst.test", IpFamily::Any, Duration::from_secs(5))
                    .await
            } else {
                resolver
                    .resolve_static("burst.test", IpFamily::Any, Duration::from_secs(5))
                    .await
            }
        });
    }
    while let Some(outcome) = tasks.join_next().await {
        outcome
            .expect("no task panics")
            .expect("every waiter resolves");
    }
    assert_eq!(harness.backend.calls(), 2, "one flight per class");
    assert_eq!(harness.resolver.metrics().upstream_queries, 2);
    assert_eq!(harness.resolver.metrics().coalesced, 30);
    // The completed flights serve an immediate same-class burst.
    for _ in 0..32 {
        harness
            .resolver
            .resolve("burst.test", IpFamily::Any, Duration::from_secs(5))
            .await
            .expect("post-flight dynamic burst hits the cache");
        harness
            .resolver
            .resolve_static("burst.test", IpFamily::Any, Duration::from_secs(5))
            .await
            .expect("post-flight static burst hits the cache");
    }
    assert_eq!(harness.backend.calls(), 2);
}

#[tokio::test]
async fn one_permit_pool_governs_both_classes() {
    // Admission is shared: a dynamic flight holding the only permit
    // denies a static lookup of the same name (which must not join the
    // dynamic flight either).
    let harness = build(
        MockBackend::answering(vec![v4(1)], None).with_delay(Duration::from_millis(200)),
        &cache_config(),
        Duration::from_secs(5),
        1,
    );
    let first = {
        let resolver = harness.resolver.clone();
        tokio::spawn(async move {
            resolver
                .resolve("pool.test", IpFamily::Any, Duration::from_secs(5))
                .await
        })
    };
    time::sleep(Duration::from_millis(20)).await;
    let error = harness
        .resolver
        .resolve_static("pool.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect_err("the single permit is held by the dynamic flight");
    assert!(matches!(error, DnsError::Limit));
    first
        .await
        .expect("first flight must finish")
        .expect("first resolution must succeed");
    assert_eq!(harness.backend.calls(), 1);
}

#[tokio::test]
async fn system_reuse_window_bounds_update_visibility() {
    let cache = DnsCacheConfig {
        system_reuse_ms: Some(80),
        ..cache_config()
    };
    let harness = build_system(
        MockBackend::answering(vec![v4(1)], None),
        &cache,
        Duration::from_secs(5),
        64,
    );
    let addresses = harness
        .resolver
        .resolve("sys.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("first resolution");
    assert_eq!(addresses.as_ref(), &[v4(1)]);
    // The upstream answer changes inside the window: not yet visible.
    harness.backend.set_outcome(MockOutcome::Answer {
        ips: vec![v4(2)],
        ttl: None,
    });
    let addresses = harness
        .resolver
        .resolve("sys.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("the window reuses the recent completion");
    assert_eq!(addresses.as_ref(), &[v4(1)], "inside the window: stale");
    assert_eq!(harness.backend.calls(), 1);
    assert_eq!(harness.resolver.metrics().cache_hits, 1);
    // After the window the updated answer becomes visible.
    time::sleep(Duration::from_millis(120)).await;
    let addresses = harness
        .resolver
        .resolve("sys.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("post-window resolution");
    assert_eq!(addresses.as_ref(), &[v4(2)], "the window bounds staleness");
    assert_eq!(harness.backend.calls(), 2);

    // Window disabled (default): TTL-less answers are never reused.
    let harness = build_system(
        MockBackend::answering(vec![v4(1)], None),
        &cache_config(),
        Duration::from_secs(5),
        64,
    );
    for _ in 0..2 {
        harness
            .resolver
            .resolve("sys.test", IpFamily::Any, Duration::from_secs(5))
            .await
            .expect("resolution");
    }
    assert_eq!(harness.backend.calls(), 2);
}

#[tokio::test]
async fn system_reuse_never_caches_negative_answers() {
    let cache = DnsCacheConfig {
        system_reuse_ms: Some(5_000),
        ..cache_config()
    };
    let backend = MockBackend::answering(vec![], None);
    // The system backend reports negatives without an SOA TTL.
    backend.set_outcome(MockOutcome::NotFound {
        nxdomain: false,
        negative_ttl: None,
    });
    let harness = build_system(backend, &cache, Duration::from_secs(5), 64);
    for _ in 0..2 {
        harness
            .resolver
            .resolve("absent.test", IpFamily::Any, Duration::from_secs(5))
            .await
            .expect_err("the negative answer fails");
    }
    assert_eq!(
        harness.backend.calls(),
        2,
        "the reuse window covers positive answers only"
    );
}

#[tokio::test]
async fn the_entry_bound_counts_both_classes_of_one_name() {
    let cache = DnsCacheConfig {
        max_entries: Some(2),
        ..cache_config()
    };
    let harness = build(
        MockBackend::answering(vec![v4(1)], Some(Duration::from_secs(30))),
        &cache,
        Duration::from_secs(5),
        64,
    );
    harness
        .resolver
        .resolve("one.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("dynamic resolution");
    harness
        .resolver
        .resolve_static("one.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("static resolution");
    assert_eq!(
        harness.resolver.cache_len(),
        2,
        "both class entries count against the shared bound"
    );
    harness
        .resolver
        .resolve("two.test", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("a third entry forces eviction");
    assert!(
        harness.resolver.cache_len() <= 2,
        "the shared bound holds under the split keying"
    );
    assert_eq!(harness.resolver.metrics().evictions, 1);
}

#[tokio::test]
async fn dropping_every_resolver_handle_mid_flight_completes_the_flight() {
    // Shutdown while flights exist: the detached flight holds the inner
    // state alive, finishes its upstream call, and publishes to no one.
    let harness = build(
        MockBackend::answering(vec![v4(1)], Some(Duration::from_secs(30)))
            .with_delay(Duration::from_millis(60)),
        &cache_config(),
        Duration::from_secs(5),
        64,
    );
    let waiter = {
        let resolver = harness.resolver.clone();
        tokio::spawn(async move {
            resolver
                .resolve("orphan.test", IpFamily::Any, Duration::from_secs(5))
                .await
        })
    };
    time::sleep(Duration::from_millis(20)).await;
    drop(harness.resolver);
    waiter.abort();
    // Past the backend delay: the orphaned flight ran to completion
    // without a panic or a hang.
    time::sleep(Duration::from_millis(120)).await;
    assert_eq!(harness.backend.calls(), 1);
}

#[tokio::test]
async fn family_filtering_never_costs_an_extra_upstream_query() {
    let harness = build(
        MockBackend::answering(vec![v4(1)], Some(Duration::from_secs(30))),
        &cache_config(),
        Duration::from_secs(5),
        64,
    );
    let error = harness
        .resolver
        .resolve("v4only.test", IpFamily::Ipv6, Duration::from_secs(5))
        .await
        .expect_err("an A-only answer has no IPv6 address");
    assert!(matches!(error, DnsError::NoAddresses));
    let addresses = harness
        .resolver
        .resolve("v4only.test", IpFamily::Ipv4, Duration::from_secs(5))
        .await
        .expect("the cached A answer serves the IPv4 filter");
    assert_eq!(addresses.as_ref(), &[v4(1)]);
    assert_eq!(harness.backend.calls(), 1);

    let harness = build(
        MockBackend::answering(vec![v4(1), v6(1)], Some(Duration::from_secs(30))),
        &cache_config(),
        Duration::from_secs(5),
        64,
    );
    let addresses = harness
        .resolver
        .resolve("mixed.test", IpFamily::Ipv6, Duration::from_secs(5))
        .await
        .expect("mixed answers filter to IPv6");
    assert_eq!(addresses.as_ref(), &[v6(1)]);
}

#[tokio::test]
async fn upstream_failures_are_never_cached() {
    let backend = MockBackend::answering(vec![], None);
    backend.set_outcome(MockOutcome::Failed);
    let harness = build(backend, &cache_config(), Duration::from_secs(5), 64);
    for _ in 0..2 {
        let error = harness
            .resolver
            .resolve("failing.test", IpFamily::Any, Duration::from_secs(5))
            .await
            .expect_err("an upstream failure must surface");
        assert!(matches!(error, DnsError::Failed(_)));
    }
    assert_eq!(harness.backend.calls(), 2);
    assert_eq!(harness.resolver.metrics().upstream_failures, 2);
    assert_eq!(harness.resolver.cache_len(), 0);
}

#[tokio::test]
async fn literals_and_invalid_names_never_touch_the_backend() {
    let harness = build(
        MockBackend::answering(vec![v4(1)], Some(Duration::from_secs(30))),
        &cache_config(),
        Duration::from_secs(5),
        64,
    );
    let addresses = harness
        .resolver
        .resolve("192.0.2.99", IpFamily::Any, Duration::from_secs(5))
        .await
        .expect("IP literals resolve to themselves");
    assert_eq!(addresses.as_ref(), &[v4(99)]);
    let error = harness
        .resolver
        .resolve(&"a".repeat(300), IpFamily::Any, Duration::from_secs(5))
        .await
        .expect_err("overlong names are rejected");
    assert!(matches!(error, DnsError::InvalidName));
    assert_eq!(harness.backend.calls(), 0);
}
