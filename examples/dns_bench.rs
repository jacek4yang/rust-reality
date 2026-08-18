//! Before/after benchmark for the v1.5 shared DNS resolver.
//!
//! "Before" is the pre-v1.5 behavior: every lookup goes upstream (a raw
//! hickory resolver without caching or coalescing). "After" is the shared
//! [`DnsResolver`] with singleflight and the TTL cache. Both run against the
//! same loopback fake DNS server with a fixed per-query delay; the server
//! counts every wire query it receives.
//!
//! Prints one JSON document with cold latency, concurrent-burst latency and
//! upstream query counts, and warm-lookup latency.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use hickory_resolver::{
    Resolver,
    config::{ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
};
use rust_reality::config::{DnsCacheConfig, DnsConfig, ResourceGovernorConfig};
use rust_reality::runtime::ResourceGovernor;
use rust_reality::server::dns::{DnsResolver, IpFamily};
use tokio::net::UdpSocket;

const QUERY_DELAY: Duration = Duration::from_millis(5);
const BURST: usize = 128;
const WARM_ITERATIONS: usize = 200;
const BUDGET: Duration = Duration::from_secs(5);

/// A fixed-answer DNS server: A record 192.0.2.1, NODATA for AAAA, with a
/// constant per-query delay and a wire query counter.
struct BenchDns {
    addr: SocketAddr,
    queries: Arc<AtomicUsize>,
}

impl BenchDns {
    async fn start() -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bench DNS socket binds");
        let addr = socket.local_addr().expect("bench DNS address");
        let queries = Arc::new(AtomicUsize::new(0));
        let task_queries = Arc::clone(&queries);
        tokio::spawn(async move {
            let mut buffer = [0_u8; 512];
            loop {
                let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                    continue;
                };
                task_queries.fetch_add(1, Ordering::AcqRel);
                tokio::time::sleep(QUERY_DELAY).await;
                let packet = &buffer[..length];
                let mut offset = 12;
                loop {
                    let label = packet[offset] as usize;
                    offset += 1;
                    if label == 0 {
                        break;
                    }
                    offset += label;
                }
                let qtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
                let question_end = offset + 4;
                let mut out = packet[..question_end].to_vec();
                out[2] = 0x81;
                out[3] = 0x80;
                out[4..6].copy_from_slice(&1_u16.to_be_bytes());
                let (answers, authority) = if qtype == 1 { (1_u16, 0_u16) } else { (0, 1) };
                out[6..8].copy_from_slice(&answers.to_be_bytes());
                out[8..10].copy_from_slice(&authority.to_be_bytes());
                out[10..12].copy_from_slice(&0_u16.to_be_bytes());
                if qtype == 1 {
                    out.extend_from_slice(&0xC00C_u16.to_be_bytes());
                    out.extend_from_slice(&1_u16.to_be_bytes()); // A
                    out.extend_from_slice(&1_u16.to_be_bytes()); // IN
                    out.extend_from_slice(&30_u32.to_be_bytes()); // TTL
                    out.extend_from_slice(&4_u16.to_be_bytes());
                    out.extend_from_slice(&[192, 0, 2, 1]);
                } else {
                    // NODATA with SOA (negative TTL 30s).
                    out.extend_from_slice(&0xC00C_u16.to_be_bytes());
                    out.extend_from_slice(&6_u16.to_be_bytes()); // SOA
                    out.extend_from_slice(&1_u16.to_be_bytes());
                    out.extend_from_slice(&30_u32.to_be_bytes());
                    out.extend_from_slice(&36_u16.to_be_bytes());
                    out.extend_from_slice(&[2, b'n', b's', 0, 10]);
                    out.extend_from_slice(b"hostmaster");
                    out.extend_from_slice(&[0]);
                    for field in [1_u32, 2, 3, 4, 30] {
                        out.extend_from_slice(&field.to_be_bytes());
                    }
                }
                let _ignored = socket.send_to(&out, peer).await;
            }
        });
        Self { addr, queries }
    }

    fn query_count(&self) -> usize {
        self.queries.load(Ordering::Acquire)
    }
}

/// The pre-v1.5 engine: no cache, no coalescing, every lookup goes upstream.
fn raw_resolver(server: &BenchDns) -> hickory_resolver::TokioResolver {
    let mut udp = ConnectionConfig::udp();
    udp.port = server.addr.port();
    let mut tcp = ConnectionConfig::tcp();
    tcp.port = server.addr.port();
    let ns = NameServerConfig::new(server.addr.ip(), true, vec![udp, tcp]);
    let mut options = ResolverOpts::default();
    options.timeout = Duration::from_millis(2_000);
    options.attempts = 1;
    options.cache_size = 0;
    options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    Resolver::builder_with_config(
        ResolverConfig::from_parts(None, Vec::new(), vec![ns]),
        TokioRuntimeProvider::new(),
    )
    .with_options(options)
    .build()
    .expect("raw resolver builds")
}

fn caching_resolver(server: &BenchDns) -> DnsResolver {
    DnsResolver::from_config(
        &DnsConfig {
            servers: vec![format!("127.0.0.1:{}", server.addr.port())],
            timeout_ms: 2_000,
            cache: DnsCacheConfig {
                min_ttl_seconds: 0,
                ..DnsCacheConfig::default()
            },
        },
        ResourceGovernor::new(&ResourceGovernorConfig::default()),
    )
    .expect("caching resolver builds")
}

fn micros(samples: &[Duration]) -> Vec<u64> {
    samples.iter().map(|d| d.as_micros() as u64).collect()
}

fn percentile(sorted_micros: &[u64], percentile: usize) -> u64 {
    sorted_micros[(sorted_micros.len() - 1) * percentile / 100]
}

fn summarize(mut samples: Vec<Duration>) -> (u64, u64, u64) {
    samples.sort_unstable();
    let micros = micros(&samples);
    (
        percentile(&micros, 50),
        percentile(&micros, 95),
        percentile(&micros, 99),
    )
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let server = BenchDns::start().await;
    let name = "bench.test";

    // ---- Cold latency: one lookup on a fresh resolver.
    let raw = raw_resolver(&server);
    let started = Instant::now();
    raw.lookup_ip(format!("{name}."))
        .await
        .expect("raw cold lookup");
    let before_cold_us = started.elapsed().as_micros() as u64;

    let caching = caching_resolver(&server);
    let started = Instant::now();
    caching
        .resolve(name, IpFamily::Any, BUDGET)
        .await
        .expect("caching cold lookup");
    let after_cold_us = started.elapsed().as_micros() as u64;

    // ---- Concurrent burst of identical lookups (cold cache).
    let before = server.query_count();
    let started = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..BURST {
        let raw = raw_resolver(&server);
        tasks.spawn(async move {
            raw.lookup_ip(format!("{name}."))
                .await
                .expect("raw burst lookup")
        });
    }
    while tasks.join_next().await.is_some() {}
    let before_burst = started.elapsed();
    let before_burst_queries = server.query_count() - before;

    let caching = caching_resolver(&server);
    let before = server.query_count();
    let started = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..BURST {
        let caching = caching.clone();
        tasks.spawn(async move {
            caching
                .resolve(name, IpFamily::Any, BUDGET)
                .await
                .expect("cached burst lookup")
        });
    }
    while tasks.join_next().await.is_some() {}
    let after_burst = started.elapsed();
    let after_burst_queries = server.query_count() - before;
    let after_burst_metrics = caching.metrics();

    // ---- Warm sequential lookups.
    let mut before_warm = Vec::with_capacity(WARM_ITERATIONS);
    let raw = raw_resolver(&server);
    let before = server.query_count();
    for _ in 0..WARM_ITERATIONS {
        let started = Instant::now();
        raw.lookup_ip(format!("{name}."))
            .await
            .expect("raw warm lookup");
        before_warm.push(started.elapsed());
    }
    let before_warm_queries = server.query_count() - before;

    let mut after_warm = Vec::with_capacity(WARM_ITERATIONS);
    let before = server.query_count();
    for _ in 0..WARM_ITERATIONS {
        let started = Instant::now();
        caching
            .resolve(name, IpFamily::Any, BUDGET)
            .await
            .expect("cached warm lookup");
        after_warm.push(started.elapsed());
    }
    let after_warm_queries = server.query_count() - before;

    let (bw50, bw95, bw99) = summarize(before_warm);
    let (aw50, aw95, aw99) = summarize(after_warm);
    let reduction = 100.0 * (1.0 - after_burst_queries as f64 / before_burst_queries.max(1) as f64);
    let report = serde_json::json!({
        "config": {
            "burst_concurrency": BURST,
            "warm_iterations": WARM_ITERATIONS,
            "fake_server_query_delay_ms": QUERY_DELAY.as_millis(),
            "answer_ttl_seconds": 30,
        },
        "cold_lookup_micros": {
            "before": before_cold_us,
            "after": after_cold_us,
        },
        "concurrent_identical_burst": {
            "before": {
                "upstream_queries": before_burst_queries,
                "wall_micros": before_burst.as_micros() as u64,
            },
            "after": {
                "upstream_queries": after_burst_queries,
                "wall_micros": after_burst.as_micros() as u64,
                "coalesced_waiters": after_burst_metrics.coalesced,
                "cache_hits": after_burst_metrics.cache_hits,
            },
            "duplicate_upstream_query_reduction_percent": reduction,
        },
        "warm_lookup_micros": {
            "before": { "p50": bw50, "p95": bw95, "p99": bw99, "upstream_queries": before_warm_queries },
            "after": { "p50": aw50, "p95": aw95, "p99": aw99, "upstream_queries": after_warm_queries },
        },
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("report serializes")
    );
}
