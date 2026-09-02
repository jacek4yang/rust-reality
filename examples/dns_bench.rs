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
//!
//! With the `contention` argument the example instead measures cache-lock
//! contention on the warm lookup path: same-name and distinct-name workloads
//! at 1/64/128/1024 concurrent tasks, reporting wall time, per-lookup
//! latency percentiles, process CPU time, and upstream query counts. This is
//! the evidence base for the v1.5.1 cache-sharding decision; the workload is
//! deterministic (fixed names, fixed iterations, no randomness).

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
use rust_reality::config::node::dns::{DnsCacheConfig, DnsConfig};
use rust_reality::runtime::ResourceGovernor;
use rust_reality::runtime::policy::ResourceGovernorPolicy;
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
        Self::start_with(QUERY_DELAY).await
    }

    async fn start_with(delay: Duration) -> Self {
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
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
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
            servers: Some(vec![format!("127.0.0.1:{}", server.addr.port())]),
            timeout_ms: Some(2_000),
            cache: Some(DnsCacheConfig {
                min_ttl_seconds: Some(0),
                ..DnsCacheConfig::default()
            }),
        },
        ResourceGovernor::new(&ResourceGovernorPolicy::default()),
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

/// Nanosecond variant for the contention report, where one warm lookup costs
/// less than a microsecond and microsecond rounding would hide the signal.
fn summarize_nanos(mut samples: Vec<Duration>) -> (u64, u64, u64) {
    samples.sort_unstable();
    let nanos: Vec<u64> = samples.iter().map(|d| d.as_nanos() as u64).collect();
    (
        percentile(&nanos, 50),
        percentile(&nanos, 95),
        percentile(&nanos, 99),
    )
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("contention") => contention_main().await,
        Some("system-reuse") => system_reuse_main().await,
        _ => original_report_main().await,
    }
}

/// Evidence for the `systemReuseMs` default: burst and sequential latency of
/// the system backend with the reuse window off vs. on, plus the getaddrinfo
/// call counts (one per flight). Uses `localhost`, which NSS resolves from
/// `/etc/hosts` without any network access.
async fn system_reuse_main() {
    const SEQUENTIAL: usize = 2_000;
    const WAVES: usize = 8;
    const BURST: usize = 128;

    let mut windows = serde_json::Map::new();
    for reuse_ms in [0_u64, 250] {
        let resolver = DnsResolver::system(
            ResourceGovernor::new(&ResourceGovernorPolicy::default()),
            Duration::from_millis(2_000),
            &DnsCacheConfig {
                system_reuse_ms: Some(reuse_ms),
                min_ttl_seconds: Some(0),
                ..DnsCacheConfig::default()
            },
        );
        let started = Instant::now();
        for _ in 0..SEQUENTIAL {
            resolver
                .resolve("localhost", IpFamily::Any, BUDGET)
                .await
                .expect("localhost resolves");
        }
        let sequential_wall = started.elapsed();
        let after_sequential = resolver.metrics();

        let started = Instant::now();
        for _ in 0..WAVES {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..BURST {
                let resolver = resolver.clone();
                tasks.spawn(async move {
                    resolver
                        .resolve("localhost", IpFamily::Any, BUDGET)
                        .await
                        .expect("burst lookup resolves");
                });
            }
            while tasks.join_next().await.is_some() {}
        }
        let burst_wall = started.elapsed();
        let after_burst = resolver.metrics();
        windows.insert(
            reuse_ms.to_string(),
            serde_json::json!({
                "sequential": {
                    "lookups": SEQUENTIAL,
                    "wall_micros": sequential_wall.as_micros() as u64,
                    "upstream_queries": after_sequential.upstream_queries,
                    "cache_hits": after_sequential.cache_hits,
                },
                "bursts": {
                    "waves": WAVES,
                    "tasks_per_wave": BURST,
                    "wall_micros": burst_wall.as_micros() as u64,
                    "upstream_queries": after_burst.upstream_queries - after_sequential.upstream_queries,
                    "coalesced": after_burst.coalesced - after_sequential.coalesced,
                },
            }),
        );
    }
    let output = serde_json::json!({
        "config": { "name": "localhost", "comment": "NSS files backend, no network" },
        "reuse_window_ms": windows,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).expect("report serializes")
    );
}

/// Process CPU time (user + system) read from `/proc/self/stat`, in
/// microseconds. Linux reports fields 14/15 in `USER_HZ` (100) clock ticks.
fn process_cpu_micros() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").expect("stat readable");
    let after_comm = stat.rsplit_once(") ").expect("stat comm ends").1;
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // Fields after comm are field 3 onward: index 11 = utime, 12 = stime.
    let utime: u64 = fields[11].parse().expect("utime parses");
    let stime: u64 = fields[12].parse().expect("stime parses");
    (utime + stime) * 10_000
}

/// One contention level: `tasks` concurrent tasks each running `iterations`
/// warm lookups, either all on one hot name or spread over `names`.
async fn run_contention_level(
    resolver: &DnsResolver,
    names: &[String],
    tasks: usize,
    iterations: usize,
) -> serde_json::Value {
    let metrics_before = resolver.metrics();
    let cpu_before = process_cpu_micros();
    let started = Instant::now();
    let mut join = tokio::task::JoinSet::new();
    for task in 0..tasks {
        let resolver = resolver.clone();
        let names: Arc<[String]> = names.iter().cloned().collect();
        join.spawn(async move {
            let mut samples = Vec::with_capacity(iterations);
            for iteration in 0..iterations {
                // Deterministic spread: stride 7 keeps tasks off the same
                // name at the same iteration in the distinct-name workload.
                let name = &names[(task * 7 + iteration) % names.len()];
                let lookup = Instant::now();
                resolver
                    .resolve(name, IpFamily::Any, BUDGET)
                    .await
                    .expect("contention lookup resolves");
                samples.push(lookup.elapsed());
            }
            samples
        });
    }
    let mut samples = Vec::with_capacity(tasks * iterations);
    while let Some(outcome) = join.join_next().await {
        samples.extend(outcome.expect("no contention task panics"));
    }
    let wall = started.elapsed();
    let cpu = process_cpu_micros() - cpu_before;
    let metrics_after = resolver.metrics();
    let (p50, p95, p99) = summarize_nanos(samples);
    serde_json::json!({
        "tasks": tasks,
        "iterations_per_task": iterations,
        "total_lookups": tasks * iterations,
        "wall_micros": wall.as_micros() as u64,
        "cpu_micros": cpu,
        "cpu_per_wall_percent": (100 * cpu) / (wall.as_micros() as u64).max(1),
        "lookup_nanos": { "p50": p50, "p95": p95, "p99": p99 },
        "cache_hits": metrics_after.cache_hits - metrics_before.cache_hits,
        "upstream_queries": metrics_after.upstream_queries - metrics_before.upstream_queries,
    })
}

/// Warm-path lock contention: same hot name vs. 256 distinct cached names at
/// 1/64/128/1024 concurrent tasks. Everything is pre-resolved, so the
/// measured path is lock + clone + family filter, never the backend.
async fn contention_main() {
    const DISTINCT_NAMES: usize = 256;
    const TOTAL_LOOKUPS_PER_LEVEL: usize = 262_144;
    const LEVELS: [usize; 4] = [1, 64, 128, 1024];

    let server = BenchDns::start_with(Duration::ZERO).await;
    let resolver = caching_resolver(&server);

    // Pre-warm the hot name and the distinct-name set.
    resolver
        .resolve("hot.contention.test", IpFamily::Any, BUDGET)
        .await
        .expect("hot name resolves");
    let distinct: Vec<String> = (0..DISTINCT_NAMES)
        .map(|index| format!("d{index}.contention.test"))
        .collect();
    for name in &distinct {
        resolver
            .resolve(name, IpFamily::Any, BUDGET)
            .await
            .expect("distinct name resolves");
    }
    let warm_queries = server.query_count();

    let hot = vec!["hot.contention.test".to_owned()];
    let mut report = serde_json::Map::new();
    for (label, names) in [("same_name", &hot), ("distinct_names", &distinct)] {
        let mut levels = serde_json::Map::new();
        for tasks in LEVELS {
            let iterations = (TOTAL_LOOKUPS_PER_LEVEL / tasks).max(64);
            let result = run_contention_level(&resolver, names, tasks, iterations).await;
            levels.insert(tasks.to_string(), result);
        }
        report.insert(label.to_owned(), serde_json::Value::Object(levels));
    }
    let output = serde_json::json!({
        "config": {
            "distinct_names": DISTINCT_NAMES,
            "levels": LEVELS,
            "total_lookups_per_level": TOTAL_LOOKUPS_PER_LEVEL,
            "fake_server_query_delay_ms": 0,
            "prewarm_upstream_queries": warm_queries,
        },
        "workloads": report,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).expect("report serializes")
    );
}

async fn original_report_main() {
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
