//! Integration tests for the shared DNS resolver against a local fake DNS
//! server speaking real DNS wire format over UDP. No external network is
//! used: every query stays on loopback.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rust_reality::config::{DnsCacheConfig, DnsConfig, ResourceGovernorConfig};
use rust_reality::runtime::ResourceGovernor;
use rust_reality::server::connector::DestinationConnector;
use rust_reality::server::dns::{DnsError, DnsResolver, IpFamily, install_shared};
use tokio::{
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
    time,
};

/// What the fake server answers for one name.
#[derive(Clone)]
enum Response {
    /// Positive answers: A and AAAA record sets with one TTL. A query type
    /// with an empty record set gets a NODATA answer, like a real zone.
    Answers {
        a: Vec<Ipv4Addr>,
        aaaa: Vec<Ipv6Addr>,
        ttl: u32,
    },
    /// NXDOMAIN with an SOA carrying this negative TTL.
    NxDomain { negative_ttl: u32 },
    /// SERVFAIL without any records.
    ServFail,
    /// The query is dropped on the floor (blackhole).
    Drop,
}

#[derive(Clone)]
struct Scenario {
    response: Response,
    delay: Duration,
}

impl Scenario {
    fn answers(a: &[u8], aaaa: &[[u8; 16]], ttl: u32) -> Self {
        Self {
            response: Response::Answers {
                a: a.iter()
                    .map(|last| Ipv4Addr::new(192, 0, 2, *last))
                    .collect(),
                aaaa: aaaa.iter().map(|octets| Ipv6Addr::from(*octets)).collect(),
                ttl,
            },
            delay: Duration::ZERO,
        }
    }

    fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

/// A minimal but real DNS server: parses the first question, counts every
/// query, and answers from a mutable scenario table.
struct FakeDns {
    addr: SocketAddr,
    queries: Arc<AtomicUsize>,
    scenarios: Arc<Mutex<HashMap<String, Scenario>>>,
    task: JoinHandle<()>,
}

impl FakeDns {
    async fn start() -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("fake DNS socket binds");
        let addr = socket.local_addr().expect("fake DNS address");
        let queries = Arc::new(AtomicUsize::new(0));
        let scenarios: Arc<Mutex<HashMap<String, Scenario>>> = Arc::new(Mutex::new(HashMap::new()));
        let task = {
            let queries = Arc::clone(&queries);
            let scenarios = Arc::clone(&scenarios);
            tokio::spawn(async move {
                let mut buffer = [0_u8; 512];
                loop {
                    let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                        continue;
                    };
                    let packet = buffer[..length].to_vec();
                    let Some(query) = parse_query(&packet) else {
                        continue;
                    };
                    queries.fetch_add(1, Ordering::AcqRel);
                    let scenario = scenarios
                        .lock()
                        .expect("scenario lock")
                        .get(&query.name)
                        .cloned()
                        .unwrap_or(Scenario {
                            response: Response::NxDomain { negative_ttl: 60 },
                            delay: Duration::ZERO,
                        });
                    if !scenario.delay.is_zero() {
                        time::sleep(scenario.delay).await;
                    }
                    let Some(response) = build_response(&packet, &query, &scenario.response) else {
                        continue; // Drop: never answer.
                    };
                    let _ignored = socket.send_to(&response, peer).await;
                }
            })
        };
        Self {
            addr,
            queries,
            scenarios,
            task,
        }
    }

    fn set(&self, name: &str, scenario: Scenario) {
        self.scenarios
            .lock()
            .expect("scenario lock")
            .insert(name.to_owned(), scenario);
    }

    fn query_count(&self) -> usize {
        self.queries.load(Ordering::Acquire)
    }
}

impl Drop for FakeDns {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct ParsedQuery {
    name: String,
    qtype: u16,
    /// End of the question section: the response echoes this prefix.
    question_end: usize,
}

fn parse_query(packet: &[u8]) -> Option<ParsedQuery> {
    if packet.len() < 12 {
        return None;
    }
    let mut offset = 12;
    let mut labels = Vec::new();
    loop {
        let length = *packet.get(offset)? as usize;
        offset += 1;
        if length == 0 {
            break;
        }
        if length & 0xC0 != 0 || offset + length > packet.len() {
            return None; // no compression in queries we accept
        }
        labels.push(
            std::str::from_utf8(&packet[offset..offset + length])
                .ok()?
                .to_owned(),
        );
        offset += length;
    }
    let qtype = u16::from_be_bytes([*packet.get(offset)?, *packet.get(offset + 1)?]);
    let question_end = offset + 4;
    if packet.len() < question_end {
        return None;
    }
    Some(ParsedQuery {
        name: labels.join(".").to_ascii_lowercase(),
        qtype,
        question_end,
    })
}

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_SOA: u16 = 6;
const CLASS_IN: u16 = 1;

/// One answer record: type, TTL, rdata.
type AnswerRecord = (u16, u32, Vec<u8>);

fn build_response(packet: &[u8], query: &ParsedQuery, response: &Response) -> Option<Vec<u8>> {
    let (rcode, answers, negative_ttl): (u8, Vec<AnswerRecord>, Option<u32>) = match response {
        Response::Drop => return None,
        Response::ServFail => (2, Vec::new(), None),
        Response::NxDomain { negative_ttl } => (3, Vec::new(), Some(*negative_ttl)),
        Response::Answers { a, aaaa, ttl } => {
            let records = match query.qtype {
                TYPE_A => a
                    .iter()
                    .map(|ip| (TYPE_A, *ttl, ip.octets().to_vec()))
                    .collect(),
                TYPE_AAAA => aaaa
                    .iter()
                    .map(|ip| (TYPE_AAAA, *ttl, ip.octets().to_vec()))
                    .collect(),
                _ => Vec::new(),
            };
            // A positive scenario with no records of the asked type is a
            // NODATA answer: NOERROR, empty answers, SOA authority.
            let nodata = records.is_empty();
            (0, records, nodata.then_some(*ttl))
        }
    };
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&packet[..query.question_end]); // id, flags, counts, question
    let recursion_desired = u16::from_be_bytes([packet[2], packet[3]]) & 0x0100;
    let flags = 0x8000 | 0x0080 | recursion_desired | u16::from(rcode); // QR | RA | RD | rcode
    out[2..4].copy_from_slice(&flags.to_be_bytes());
    out[4..6].copy_from_slice(&1_u16.to_be_bytes()); // qdcount
    out[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
    out[8..10].copy_from_slice(&(u16::from(negative_ttl.is_some())).to_be_bytes()); // nscount
    out[10..12].copy_from_slice(&0_u16.to_be_bytes()); // arcount
    for (rrtype, ttl, rdata) in answers {
        out.extend_from_slice(&0xC00C_u16.to_be_bytes()); // name: pointer to the question
        out.extend_from_slice(&rrtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    if let Some(negative_ttl) = negative_ttl {
        out.extend_from_slice(&0xC00C_u16.to_be_bytes());
        out.extend_from_slice(&TYPE_SOA.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&negative_ttl.to_be_bytes());
        // rdata: mname "ns." (4 bytes), rname "hostmaster." (12 bytes),
        // serial/refresh/retry/expire/minimum (20 bytes). The negative TTL
        // is min(SOA TTL, minimum).
        let rdata_len = 4 + 12 + 20;
        out.extend_from_slice(&(rdata_len as u16).to_be_bytes());
        out.extend_from_slice(&[2, b'n', b's', 0]);
        out.extend_from_slice(&[10]);
        out.extend_from_slice(b"hostmaster");
        out.extend_from_slice(&[0]);
        for field in [1_u32, 2, 3, 4, negative_ttl] {
            out.extend_from_slice(&field.to_be_bytes());
        }
    }
    Some(out)
}

fn dns_config(server: &FakeDns, timeout_ms: u64) -> DnsConfig {
    DnsConfig {
        servers: vec![format!("127.0.0.1:{}", server.addr.port())],
        timeout_ms,
        cache: DnsCacheConfig {
            min_ttl_seconds: 0,
            ..DnsCacheConfig::default()
        },
    }
}

fn resolver(server: &FakeDns, timeout_ms: u64) -> DnsResolver {
    DnsResolver::from_config(
        &dns_config(server, timeout_ms),
        ResourceGovernor::new(&ResourceGovernorConfig::default()),
    )
    .expect("resolver builds against the fake server")
}

fn v4(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
}

fn v6(last: u16) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last))
}

fn v6_octets(last: u16) -> [u8; 16] {
    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last).octets()
}

const BUDGET: Duration = Duration::from_secs(5);

#[tokio::test]
async fn resolves_a_only_aaaa_only_and_mixed_names() {
    let server = FakeDns::start().await;
    server.set("a-only.test", Scenario::answers(&[1], &[], 300));
    server.set(
        "aaaa-only.test",
        Scenario::answers(&[], &[v6_octets(1)], 300),
    );
    server.set(
        "mixed.test",
        Scenario::answers(&[1, 2, 3], &[v6_octets(1), v6_octets(2)], 300),
    );
    let resolver = resolver(&server, 2_000);

    let addresses = resolver
        .resolve("a-only.test", IpFamily::Any, BUDGET)
        .await
        .expect("A-only name resolves");
    assert_eq!(addresses.as_ref(), &[v4(1)]);

    let addresses = resolver
        .resolve("aaaa-only.test", IpFamily::Any, BUDGET)
        .await
        .expect("AAAA-only name resolves");
    assert_eq!(addresses.as_ref(), &[v6(1)]);

    let mut addresses = resolver
        .resolve("mixed.test", IpFamily::Any, BUDGET)
        .await
        .expect("mixed name resolves")
        .to_vec();
    addresses.sort_unstable();
    assert_eq!(
        addresses,
        vec![v4(1), v4(2), v4(3), v6(1), v6(2)]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn deduplicates_repeated_answer_records() {
    let server = FakeDns::start().await;
    server.set("dup.test", Scenario::answers(&[1, 1, 2, 1], &[], 300));
    let resolver = resolver(&server, 2_000);
    let mut addresses = resolver
        .resolve("dup.test", IpFamily::Any, BUDGET)
        .await
        .expect("duplicate answers resolve")
        .to_vec();
    addresses.sort_unstable();
    assert_eq!(addresses, vec![v4(1), v4(2)]);
}

#[tokio::test]
async fn nxdomain_and_nodata_are_distinguished_and_negatively_cached() {
    let server = FakeDns::start().await;
    server.set(
        "missing.test",
        Scenario {
            response: Response::NxDomain { negative_ttl: 1 },
            delay: Duration::ZERO,
        },
    );
    // NODATA: the name has only AAAA records, so its A query gets NODATA.
    server.set("v6-only.test", Scenario::answers(&[], &[v6_octets(9)], 1));
    let resolver = resolver(&server, 2_000);

    let error = resolver
        .resolve("missing.test", IpFamily::Any, BUDGET)
        .await
        .expect_err("NXDOMAIN fails");
    assert!(
        matches!(error, DnsError::NotFound { nxdomain: true }),
        "unexpected error: {error:?}"
    );
    let after_first = server.query_count();
    let error = resolver
        .resolve("missing.test", IpFamily::Any, BUDGET)
        .await
        .expect_err("the negative answer is cached");
    assert!(
        matches!(error, DnsError::NotFound { nxdomain: true }),
        "unexpected error: {error:?}"
    );
    assert_eq!(
        server.query_count(),
        after_first,
        "a cached NXDOMAIN costs no upstream queries"
    );
    assert_eq!(resolver.metrics().negative_hits, 1);

    // NODATA on the A half of a name that has AAAA records still resolves.
    let addresses = resolver
        .resolve("v6-only.test", IpFamily::Any, BUDGET)
        .await
        .expect("NODATA on A does not hide the AAAA answer");
    assert_eq!(addresses.as_ref(), &[v6(9)]);

    // The negative entry expires with its SOA TTL and re-resolves upstream.
    time::sleep(Duration::from_millis(1_300)).await;
    resolver
        .resolve("missing.test", IpFamily::Any, BUDGET)
        .await
        .expect_err("the expired negative entry re-resolves");
    assert!(
        server.query_count() > after_first,
        "an expired negative entry costs upstream queries again"
    );
}

#[tokio::test]
async fn servfail_is_not_cached() {
    let server = FakeDns::start().await;
    server.set(
        "broken.test",
        Scenario {
            response: Response::ServFail,
            delay: Duration::ZERO,
        },
    );
    let resolver = resolver(&server, 2_000);
    for _ in 0..2 {
        let error = resolver
            .resolve("broken.test", IpFamily::Any, BUDGET)
            .await
            .expect_err("SERVFAIL fails");
        assert!(matches!(error, DnsError::Failed(_)));
    }
    let metrics = resolver.metrics();
    // Two resolutions, one flight each; a SERVFAIL answer is never cached,
    // so the second resolution goes upstream again (hickory may additionally
    // retry SERVFAIL against the TCP fallback transport).
    assert_eq!(metrics.upstream_queries, 2, "SERVFAIL is never cached");
    assert!(server.query_count() >= 4);
    assert!(metrics.upstream_failures >= 2);
}

#[tokio::test]
async fn a_blackholed_server_times_out_and_recovers() {
    let server = FakeDns::start().await;
    server.set(
        "flaky.test",
        Scenario {
            response: Response::Drop,
            delay: Duration::ZERO,
        },
    );
    let resolver = resolver(&server, 200);

    let started = time::Instant::now();
    let error = resolver
        .resolve("flaky.test", IpFamily::Any, BUDGET)
        .await
        .expect_err("a dropped query times out");
    assert!(matches!(error, DnsError::Timeout));
    assert!(started.elapsed() < Duration::from_secs(2));

    // The waiter and the flight share the same 200ms deadline: let the
    // timed-out flight publish and clear its slot before the retry, or the
    // retry would (correctly) join the still-running flight.
    time::sleep(Duration::from_millis(300)).await;
    server.set("flaky.test", Scenario::answers(&[5], &[], 300));
    let before_recovery = server.query_count();
    let addresses = resolver
        .resolve("flaky.test", IpFamily::Any, BUDGET)
        .await
        .expect("the resolver recovers when the server answers again");
    assert!(
        server.query_count() > before_recovery,
        "recovery must send a fresh upstream query"
    );
    assert_eq!(addresses.as_ref(), &[v4(5)]);
}

#[tokio::test]
async fn a_slow_server_is_bounded_by_the_absolute_timeout() {
    let server = FakeDns::start().await;
    server.set(
        "slow.test",
        Scenario::answers(&[6], &[], 300).with_delay(Duration::from_millis(300)),
    );
    let fast_timeout = resolver(&server, 100);
    let error = fast_timeout
        .resolve("slow.test", IpFamily::Any, BUDGET)
        .await
        .expect_err("a slow server exceeds a tight timeout");
    assert!(matches!(error, DnsError::Timeout));

    let slow_timeout = resolver(&server, 2_000);
    let addresses = slow_timeout
        .resolve("slow.test", IpFamily::Any, BUDGET)
        .await
        .expect("a slow server within the timeout still resolves");
    assert_eq!(addresses.as_ref(), &[v4(6)]);
}

#[tokio::test]
async fn positive_entries_follow_the_upstream_ttl() {
    let server = FakeDns::start().await;
    server.set("ttl.test", Scenario::answers(&[7], &[], 1));
    let resolver = resolver(&server, 2_000);

    resolver
        .resolve("ttl.test", IpFamily::Any, BUDGET)
        .await
        .expect("first resolution");
    let after_first = server.query_count();
    resolver
        .resolve("ttl.test", IpFamily::Any, BUDGET)
        .await
        .expect("warm resolution");
    assert_eq!(
        server.query_count(),
        after_first,
        "a TTL-valid entry is served from the cache"
    );
    time::sleep(Duration::from_millis(1_300)).await;
    resolver
        .resolve("ttl.test", IpFamily::Any, BUDGET)
        .await
        .expect("post-expiry resolution");
    assert!(
        server.query_count() > after_first,
        "an expired entry re-resolves upstream"
    );
}

#[tokio::test]
async fn concurrent_identical_lookups_coalesce_to_one_flight() {
    let server = FakeDns::start().await;
    server.set(
        "hot.test",
        Scenario::answers(&[8], &[], 300).with_delay(Duration::from_millis(100)),
    );
    let resolver = resolver(&server, 2_000);

    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..64 {
        let resolver = resolver.clone();
        tasks.spawn(async move { resolver.resolve("hot.test", IpFamily::Any, BUDGET).await });
    }
    let mut successes = 0;
    while let Some(outcome) = tasks.join_next().await {
        let addresses = outcome
            .expect("no task panics")
            .expect("every waiter resolves");
        assert_eq!(addresses.as_ref(), &[v4(8)]);
        successes += 1;
    }
    assert_eq!(successes, 64);
    // One flight = one A query plus one AAAA query, not 64 pairs.
    assert!(
        server.query_count() <= 4,
        "coalescing must collapse 64 waiters to one flight, got {} queries",
        server.query_count()
    );
    assert_eq!(resolver.metrics().coalesced, 63);

    // Warm: a second burst costs zero upstream queries.
    let after_cold = server.query_count();
    for _ in 0..64 {
        resolver
            .resolve("hot.test", IpFamily::Any, BUDGET)
            .await
            .expect("warm resolution");
    }
    assert_eq!(server.query_count(), after_cold);
}

#[tokio::test]
async fn family_filtering_reads_the_same_cached_answer() {
    let server = FakeDns::start().await;
    server.set(
        "families.test",
        Scenario::answers(&[10], &[v6_octets(10)], 300),
    );
    let resolver = resolver(&server, 2_000);
    let addresses = resolver
        .resolve("families.test", IpFamily::Ipv4, BUDGET)
        .await
        .expect("IPv4 filter");
    assert_eq!(addresses.as_ref(), &[v4(10)]);
    let addresses = resolver
        .resolve("families.test", IpFamily::Ipv6, BUDGET)
        .await
        .expect("IPv6 filter");
    assert_eq!(addresses.as_ref(), &[v6(10)]);
    server.set("a-strict.test", Scenario::answers(&[11], &[], 300));
    let error = resolver
        .resolve("a-strict.test", IpFamily::Ipv6, BUDGET)
        .await
        .expect_err("an A-only name has no IPv6 address");
    assert!(matches!(error, DnsError::NoAddresses));
}

#[tokio::test]
async fn connector_dials_cached_static_targets_without_re_resolving() {
    let server = FakeDns::start().await;
    server.set(
        "cover.test",
        Scenario {
            response: Response::Answers {
                a: vec![Ipv4Addr::LOCALHOST],
                aaaa: Vec::new(),
                ttl: 300,
            },
            delay: Duration::ZERO,
        },
    );
    let resolver = DnsResolver::from_config(
        &dns_config(&server, 2_000),
        ResourceGovernor::new(&ResourceGovernorConfig::default()),
    )
    .expect("resolver builds");
    assert!(
        install_shared(resolver).is_ok(),
        "the e2e test installs the shared resolver once"
    );

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener binds");
    let port = listener.local_addr().expect("listener port").port();
    let connector = DestinationConnector::new(Duration::from_secs(2));

    let target = format!("cover.test:{port}");
    let first = connector
        .connect_target(&target)
        .await
        .expect("first connect resolves and dials");
    drop(first);
    let (_accepted, _) = listener.accept().await.expect("first accept");
    let queries_after_first = server.query_count();

    for _ in 0..8 {
        let stream = connector
            .connect_target(&target)
            .await
            .expect("subsequent connects reuse the cached static target");
        drop(stream);
        let (_accepted, _) = listener.accept().await.expect("accept");
    }
    assert_eq!(
        server.query_count(),
        queries_after_first,
        "static configured targets are not re-resolved per connection"
    );
}
