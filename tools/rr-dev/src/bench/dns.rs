//! The DNS cold / warm / burst comparison.
//!
//! Both implementations serve the same VLESS + REALITY + Vision shape and resolve
//! destination names through the same counted loopback resolver, driven by the
//! same unmodified Xray SOCKS client. Because the client sends a `DOMAIN`
//! destination, resolution happens *server-side*, which is the only place it can
//! be attributed to the implementation under test.
//!
//! Three phases, each answering a different question:
//!
//! | phase | names | what it proves |
//! |---|---|---|
//! | `cold` | fresh and unique per round | every miss reaches the upstream |
//! | `warm` | the last cold round's names | a hit costs no upstream query |
//! | `burst` | one fresh name, all at once | concurrent lookups coalesce |
//!
//! The upstream counter is what makes each of those a fact rather than an
//! inference: `cold` must produce at least one query per fresh name, `warm` must
//! produce **zero**, and `burst` must produce far fewer than its connection count
//! if singleflight coalescing works.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use crate::{
    bench::{
        aggregate,
        workload::{Destination, connect_through},
    },
    perf::json_out::Json,
};

/// What one phase run observed.
#[derive(Debug, Clone)]
pub struct PhaseRun {
    /// Connections requested.
    pub requested: usize,
    /// Connections that failed.
    pub failed: usize,
    /// Wall-clock seconds covering the whole set.
    pub wall_seconds: f64,
    /// Successful setup latencies, ascending.
    pub latencies_seconds: Vec<f64>,
    /// Upstream questions the resolver was asked during the run.
    pub upstream_delta: u64,
    /// Names the resolver saw for the first time during the run.
    pub upstream_names: Vec<String>,
}

/// Drives one phase: every name in `names`, at most `concurrency` at a time.
///
/// # Errors
///
/// Returns a message when any connection failed; a phase with a failure cannot be
/// summarised, because the missing latencies are not missing at random.
pub fn run_phase(
    socks_port: u16,
    origin_port: u16,
    names: &[String],
    concurrency: usize,
    dns: &crate::bench::fake_dns::FakeDns,
) -> Result<PhaseRun, String> {
    let before = dns.counts();
    let next = AtomicUsize::new(0);
    let started = Instant::now();
    let mut latencies = Vec::with_capacity(names.len());
    let mut failed = 0_usize;
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..concurrency.clamp(1, names.len().max(1)))
            .map(|_| {
                let next = &next;
                scope.spawn(move || {
                    let mut mine = Vec::new();
                    let mut failures = 0_usize;
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(name) = names.get(index) else {
                            break;
                        };
                        match connect_through(
                            socks_port,
                            &Destination::Domain(name.clone()),
                            origin_port,
                        ) {
                            Some(elapsed) => mine.push(elapsed.as_secs_f64()),
                            None => failures += 1,
                        }
                    }
                    (mine, failures)
                })
            })
            .collect();
        for handle in handles {
            if let Ok((mine, failures)) = handle.join() {
                latencies.extend(mine);
                failed += failures;
            } else {
                failed += 1;
            }
        }
    });
    let wall_seconds = started.elapsed().as_secs_f64();
    latencies.sort_unstable_by(f64::total_cmp);
    let after = dns.counts();
    let new_names: Vec<String> = after
        .by_name
        .keys()
        .filter(|name| !before.by_name.contains_key(*name))
        .cloned()
        .collect();

    if failed > 0 || latencies.is_empty() {
        return Err(format!(
            "phase failed: {failed} of {} connections did not complete",
            names.len()
        ));
    }
    Ok(PhaseRun {
        requested: names.len(),
        failed,
        wall_seconds,
        latencies_seconds: latencies,
        upstream_delta: after.total.saturating_sub(before.total),
        upstream_names: new_names,
    })
}

/// The names one cold round uses: fresh and unique, so nothing can be cached.
#[must_use]
pub fn cold_names(implementation: &str, round: usize, connections: usize) -> Vec<String> {
    (0..connections)
        .map(|index| format!("cold-{implementation}-{round}-{index}.dnsbench"))
        .collect()
}

/// The burst names: one fresh name repeated, so every connection wants the same
/// answer at the same moment.
#[must_use]
pub fn burst_names(implementation: &str, connections: usize) -> Vec<String> {
    vec![format!("burst-{implementation}.dnsbench"); connections]
}

/// A phase's summarised latencies and upstream cost.
fn phase_json(runs: &[PhaseRun], extra: Vec<(String, Json)>) -> Result<Json, String> {
    let latencies: Vec<f64> = runs
        .iter()
        .flat_map(|run| run.latencies_seconds.iter().copied())
        .collect();
    let mut fields: Vec<(String, Json)> = vec![
        (
            "rounds".to_owned(),
            Json::Int(i64::try_from(runs.len()).unwrap_or(i64::MAX)),
        ),
        (
            "connections".to_owned(),
            Json::Int(i64::try_from(latencies.len()).unwrap_or(i64::MAX)),
        ),
        (
            "p50Seconds".to_owned(),
            Json::Float(aggregate::floor_percentile(&latencies, 0.50)?),
        ),
        (
            "p95Seconds".to_owned(),
            Json::Float(aggregate::floor_percentile(&latencies, 0.95)?),
        ),
        (
            "upstreamQueries".to_owned(),
            Json::Int(
                i64::try_from(runs.iter().map(|run| run.upstream_delta).sum::<u64>())
                    .unwrap_or(i64::MAX),
            ),
        ),
    ];
    fields.extend(extra);
    Ok(Json::object(fields))
}

/// The per-implementation summary for the three phases.
///
/// # Errors
///
/// Returns a message when a phase produced no latencies to summarise.
pub fn implementation_json(
    cold: &[PhaseRun],
    warm: &[PhaseRun],
    burst: &PhaseRun,
    expected_minimum_upstream: usize,
) -> Result<Json, String> {
    let cold_json = phase_json(
        cold,
        vec![(
            "expectedMinimumUpstream".to_owned(),
            Json::Int(i64::try_from(expected_minimum_upstream).unwrap_or(i64::MAX)),
        )],
    )?;
    let warm_json = phase_json(warm, Vec::new())?;
    let burst_json = Json::object([
        (
            "connections",
            Json::Int(i64::try_from(burst.requested).unwrap_or(i64::MAX)),
        ),
        ("wallSeconds", Json::Float(burst.wall_seconds)),
        (
            "p50Seconds",
            Json::Float(aggregate::floor_percentile(&burst.latencies_seconds, 0.50)?),
        ),
        (
            "p95Seconds",
            Json::Float(aggregate::floor_percentile(&burst.latencies_seconds, 0.95)?),
        ),
        (
            "upstreamQueries",
            Json::Int(i64::try_from(burst.upstream_delta).unwrap_or(i64::MAX)),
        ),
        (
            "upstreamNames",
            Json::Array(
                burst
                    .upstream_names
                    .iter()
                    .cloned()
                    .map(Json::string)
                    .collect(),
            ),
        ),
    ]);
    Ok(Json::object([
        ("cold", cold_json),
        ("warm", warm_json),
        ("burst", burst_json),
    ]))
}

/// The method block the report records, so a reader knows what was measured.
#[must_use]
pub fn method_json(
    samples: usize,
    warm_samples: usize,
    connections: usize,
    burst_connections: usize,
) -> Json {
    let count = |value: usize| Json::Int(i64::try_from(value).unwrap_or(i64::MAX));
    Json::object([
        (
            "resolver",
            Json::string(
                "loopback fake DNS (bench::fake_dns), TTL 300s, A=127.0.0.1, AAAA NODATA",
            ),
        ),
        (
            "client",
            Json::string("identical Xray SOCKS5 client; DOMAIN destinations resolved server-side"),
        ),
        (
            "coldNames",
            Json::string("fresh unique names per round (never cached)"),
        ),
        ("warmNames", Json::string("final cold round's names repeated")),
        (
            "burstName",
            Json::string("one identical fresh name for all concurrent connections"),
        ),
        ("samplesPerPhase", count(samples)),
        ("warmSamples", count(warm_samples)),
        ("connectionsPerRound", count(connections)),
        ("burstConnections", count(burst_connections)),
    ])
}

/// The limitations the report states about itself.
#[must_use]
pub fn limitations_json() -> Json {
    Json::Array(
        [
            "single-host loopback includes the same Xray client, fake DNS, and origin in both paths",
            "upstream latency is ~0 (loopback UDP); cold numbers isolate resolver/cache plumbing cost",
            "results are measurements of this host and are not a universal performance claim",
        ]
        .into_iter()
        .map(Json::string)
        .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(latencies: &[f64], upstream: u64) -> PhaseRun {
        PhaseRun {
            requested: latencies.len(),
            failed: 0,
            wall_seconds: 1.0,
            latencies_seconds: latencies.to_vec(),
            upstream_delta: upstream,
            upstream_names: Vec::new(),
        }
    }

    /// Cold names must be unique across rounds *and* implementations, or a later
    /// round would be measuring the earlier one's cache.
    #[test]
    fn cold_names_are_unique_per_round_and_implementation() {
        let first = cold_names("rust", 0, 4);
        let second = cold_names("rust", 1, 4);
        let other = cold_names("xray", 0, 4);
        assert_eq!(first.len(), 4);
        let all: std::collections::BTreeSet<&String> =
            first.iter().chain(&second).chain(&other).collect();
        assert_eq!(all.len(), 12, "no name may repeat");
        assert_eq!(first[0], "cold-rust-0-0.dnsbench");
    }

    /// The burst is one name repeated: every connection wants the same answer at
    /// the same moment, which is what coalescing has to survive.
    #[test]
    fn burst_names_are_one_name_repeated() {
        let names = burst_names("xray", 32);
        assert_eq!(names.len(), 32);
        assert_eq!(
            names.iter().collect::<std::collections::BTreeSet<_>>().len(),
            1
        );
        assert_eq!(names[0], "burst-xray.dnsbench");
    }

    #[test]
    fn the_summary_reports_each_phase_with_its_upstream_cost() {
        let cold = vec![run(&[0.01, 0.02, 0.03, 0.04], 4), run(&[0.05, 0.06], 2)];
        let warm = vec![run(&[0.001, 0.002], 0)];
        let burst = PhaseRun {
            requested: 32,
            failed: 0,
            wall_seconds: 0.5,
            latencies_seconds: vec![0.01; 32],
            upstream_delta: 1,
            upstream_names: vec!["burst-rust.dnsbench".to_owned()],
        };
        let rendered = implementation_json(&cold, &warm, &burst, 6)
            .unwrap()
            .to_python_json();
        assert!(rendered.contains("\"expectedMinimumUpstream\": 6"));
        // Cold reached the upstream once per fresh name.
        assert!(rendered.contains("\"upstreamQueries\": 6"));
        // Warm cost nothing upstream: that is the cache-hit claim.
        assert!(rendered.contains("\"upstreamQueries\": 0"));
        // The burst coalesced 32 connections into a single lookup.
        assert!(rendered.contains("\"upstreamQueries\": 1"));
        assert!(rendered.contains("burst-rust.dnsbench"));
        assert!(rendered.contains("\"rounds\": 2"));
    }

    #[test]
    fn a_phase_with_no_latencies_cannot_be_summarised() {
        let empty = vec![run(&[], 0)];
        assert!(implementation_json(&empty, &empty, &run(&[], 0), 0).is_err());
    }

    #[test]
    fn the_method_and_limitations_describe_the_measurement() {
        let rendered = method_json(3, 2, 8, 32).to_python_json();
        assert!(rendered.contains("DOMAIN destinations resolved server-side"));
        assert!(rendered.contains("\"samplesPerPhase\": 3"));
        assert!(rendered.contains("\"burstConnections\": 32"));
        let limits = limitations_json().to_python_json();
        assert!(limits.contains("not a universal performance claim"));
    }
}

// ---------------------------------------------------------------------------
// The runner
// ---------------------------------------------------------------------------

/// The four ports one leg occupies.
#[derive(Debug, Clone, Copy)]
struct LegPorts {
    origin: u16,
    cover: u16,
    server: u16,
    socks: u16,
}

/// Runs all three phases for one implementation.
fn measure_leg(
    suite: &DnsSuite,
    workspace: &crate::bench::workspace::Workspace,
    rust_bin: &std::path::Path,
    xray_bin: &std::path::Path,
    implementation: crate::bench::resolver::Implementation,
    ports: LegPorts,
) -> Result<Json, String> {
    use crate::bench::resolver::{self, LegInputs, ServerPolicy};
    let label = implementation.as_str();
    let leg = resolver::start_leg(&LegInputs {
        implementation,
        workspace,
        rust_bin,
        xray_bin,
        tls_origin_port: ports.cover,
        server_port: ports.server,
        socks_port: ports.socks,
        policy: &ServerPolicy::default(),
    })?;

    // One throwaway connection proves the path before any measured phase.
    run_phase(
        leg.socks_port,
        ports.origin,
        &[format!("warmup-{label}.dnsbench")],
        1,
        &leg.dns,
    )?;

    let mut cold = Vec::with_capacity(suite.samples);
    for round in 0..suite.samples {
        let names = cold_names(label, round, suite.connections);
        cold.push(run_phase(
            leg.socks_port,
            ports.origin,
            &names,
            suite.concurrency,
            &leg.dns,
        )?);
    }
    // Warm repeats the final cold round's names, which are certainly cached.
    let warm_names = cold_names(label, suite.samples - 1, suite.connections);
    let mut warm = Vec::with_capacity(suite.warm_samples);
    for _ in 0..suite.warm_samples {
        warm.push(run_phase(
            leg.socks_port,
            ports.origin,
            &warm_names,
            suite.concurrency,
            &leg.dns,
        )?);
    }
    let burst = run_phase(
        leg.socks_port,
        ports.origin,
        &burst_names(label, suite.burst_connections),
        suite.burst_connections,
        &leg.dns,
    )?;
    implementation_json(&cold, &warm, &burst, suite.samples * suite.connections)
}

/// Everything a DNS comparison run needs.
#[derive(Debug, Clone)]
pub struct DnsSuite {
    /// Repository root, for the Go origin.
    pub repo: std::path::PathBuf,
    /// The rust-reality binary.
    pub rust_bin: std::path::PathBuf,
    /// The Xray binary: comparator server and both clients.
    pub xray_bin: std::path::PathBuf,
    /// Output directory; must not already exist.
    pub out_dir: std::path::PathBuf,
    /// Run identifier.
    pub run_id: String,
    /// Cold rounds per implementation.
    pub samples: usize,
    /// Warm rounds per implementation.
    pub warm_samples: usize,
    /// Connections per cold or warm round.
    pub connections: usize,
    /// Concurrency for the cold and warm phases.
    pub concurrency: usize,
    /// Connections in the burst phase.
    pub burst_connections: usize,
}

/// Validates the DNS parameters.
///
/// # Errors
///
/// Returns the first violated guard.
pub fn validate(suite: &DnsSuite) -> Result<(), String> {
    for (name, value) in [
        ("SAMPLES", suite.samples),
        ("WARM_SAMPLES", suite.warm_samples),
        ("CONNS", suite.connections),
        ("CONCURRENCY", suite.concurrency),
        ("BURST_CONNS", suite.burst_connections),
    ] {
        if value == 0 {
            return Err(format!("{name} must be a positive integer"));
        }
    }
    if suite.run_id.is_empty()
        || !suite
            .run_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err("RUN_ID is required and must be one safe component".to_owned());
    }
    Ok(())
}

/// Runs the DNS comparison end to end.
///
/// # Errors
///
/// Returns the first failure; every resource is RAII-owned.
pub fn run(suite: &DnsSuite) -> Result<crate::bench::paired::SuiteOutcome, String> {
    use crate::bench::{
        evidence::{Publication, RunDirectory},
        host_lock::HostLock,
        identity::{self, Kind},
        resolver::Implementation,
        workspace::Workspace,
    };

    validate(suite)?;
    for program in ["openssl"] {
        if !crate::process::Tool::exists(program) {
            return Err(format!("required program unavailable: {program}"));
        }
    }
    let rust = identity::register("rust-reality", &suite.rust_bin, "", Kind::Rust)?;
    let xray = identity::register("xray", &suite.xray_bin, "", Kind::Xray)?;
    let _lock = HostLock::acquire(&crate::bench::runner::default_lock_path())?;
    let run = RunDirectory::create(&suite.out_dir)?;
    let workspace = Workspace::create("benchmark-dns-comparison")?;

    // Two origins plus a server/SOCKS pair per implementation.
    let port_base = crate::bench::workspace::reserve_block(6)?;
    let (origin_port, cover_port) = (port_base, port_base + 1);
    let _origins =
        crate::bench::resolver::start_origins(suite.repo.as_path(), &workspace, origin_port, cover_port)?;

    let mut summary: Vec<(String, Json)> = Vec::with_capacity(2);
    for (index, implementation) in [Implementation::Rust, Implementation::Xray]
        .into_iter()
        .enumerate()
    {
        let offset = u16::try_from(index * 2).map_err(|_| "too many legs".to_owned())?;
        summary.push((
            implementation.as_str().to_owned(),
            measure_leg(
                suite,
                &workspace,
                &rust.path,
                &xray.path,
                implementation,
                LegPorts {
                    origin: origin_port,
                    cover: cover_port,
                    server: port_base + 2 + offset,
                    socks: port_base + 3 + offset,
                },
            )?,
        ));
    }

    let report = Json::object([
        ("schemaVersion", Json::Int(1)),
        ("harness", Json::string("benchmark-dns-comparison")),
        ("status", Json::string("COMPLETE")),
        ("performanceVerdict", Json::string("NOT_EVALUATED")),
        (
            "method",
            method_json(
                suite.samples,
                suite.warm_samples,
                suite.connections,
                suite.burst_connections,
            ),
        ),
        ("summary", Json::object(summary)),
        ("limitations", limitations_json()),
    ]);
    let summary_json = report.to_python_json();
    run.write_new("summary.json", &summary_json)?;
    run.publish(
        Publication::Environment,
        &summary_json,
        &suite.run_id,
        "benchmark-dns-comparison",
    )?;
    Ok(crate::bench::paired::SuiteOutcome {
        out_dir: suite.out_dir.clone(),
        summary_json,
        slot_count: 2,
    })
}
