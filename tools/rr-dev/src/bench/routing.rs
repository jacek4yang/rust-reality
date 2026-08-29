//! The routing-rule scaling comparison.
//!
//! Both implementations carry semantically equivalent first-match domain rule
//! lists at 10, 100, 1000 and 10000 rules, with no `geosite`/`geoip` files
//! involved, and the measured destination is the **last** rule so every connection
//! walks the whole list. That choice is the experiment: a rule near the front
//! would time a lucky early match rather than the cost of evaluating rules.
//!
//! The name resolves through the same counted loopback resolver as the DNS
//! comparison, and each slot is warmed before it is measured, so the answer is
//! cached and the latency isolates rule evaluation rather than resolution.
//!
//! Scale points interleave `rust`/`xray` in balanced ABBA blocks, so drift over a
//! long run cannot favour whichever implementation happened to go first.

use crate::{
    bench::{aggregate, dns::PhaseRun},
    perf::json_out::Json,
};

/// The scale points a formal run measures.
pub const FORMAL_SCALES: [usize; 4] = [10, 100, 1000, 10_000];

/// The reduced set an exploratory run measures.
pub const EXPLORATORY_SCALES: [usize; 2] = [10, 1000];

/// One measured sample at a scale point.
#[derive(Debug, Clone)]
pub struct ScaleSample {
    /// Which implementation produced it.
    pub implementation: String,
    /// How many rules the server carried.
    pub rule_count: usize,
    /// The ABBA block.
    pub block: usize,
    /// The sample index within the slot.
    pub sample_index: usize,
    /// The measured run.
    pub run: PhaseRun,
}

impl ScaleSample {
    /// Connections per second for this sample.
    #[must_use]
    pub fn connections_per_second(&self) -> f64 {
        if self.run.wall_seconds <= 0.0 {
            return 0.0;
        }
        #[expect(
            clippy::cast_precision_loss,
            reason = "connection counts are small integers"
        )]
        let requested = self.run.requested as f64;
        requested / self.run.wall_seconds
    }

    /// The row as `raw-samples.jsonl` records it.
    #[must_use]
    pub fn to_json(&self) -> Json {
        let count = |value: usize| Json::Int(i64::try_from(value).unwrap_or(i64::MAX));
        Json::object([
            (
                "implementation",
                Json::string(self.implementation.clone()),
            ),
            ("ruleCount", count(self.rule_count)),
            ("block", count(self.block)),
            ("sampleIndex", count(self.sample_index)),
            (
                "targetName",
                Json::string(crate::bench::resolver::worst_case_target(self.rule_count)),
            ),
            (
                "run",
                Json::object([
                    ("requested", count(self.run.requested)),
                    ("failed", count(self.run.failed)),
                    ("wallSeconds", Json::Float(self.run.wall_seconds)),
                    (
                        "latenciesSeconds",
                        Json::Array(
                            self.run
                                .latencies_seconds
                                .iter()
                                .copied()
                                .map(Json::Float)
                                .collect(),
                        ),
                    ),
                ]),
            ),
        ])
    }
}

/// The block order for one scale point: `rust` leads odd blocks, `xray` even.
#[must_use]
pub fn block_order(block: usize) -> [&'static str; 2] {
    if block % 2 == 1 {
        ["rust", "xray"]
    } else {
        ["xray", "rust"]
    }
}

/// Summarises every scale point.
///
/// # Errors
///
/// Returns a message when a scale point has no samples for one implementation,
/// or when a ratio would divide by zero.
pub fn summarise_scales(samples: &[ScaleSample]) -> Result<Json, String> {
    let mut scales: Vec<usize> = samples.iter().map(|sample| sample.rule_count).collect();
    scales.sort_unstable();
    scales.dedup();

    let mut entries: Vec<(String, Json)> = Vec::with_capacity(scales.len());
    for scale in scales {
        let mut per_impl: Vec<(String, Json)> = Vec::with_capacity(2);
        let mut p50s = Vec::with_capacity(2);
        let mut rates = Vec::with_capacity(2);
        for label in ["rust", "xray"] {
            let subset: Vec<&ScaleSample> = samples
                .iter()
                .filter(|sample| sample.rule_count == scale && sample.implementation == label)
                .collect();
            if subset.is_empty() {
                return Err(format!("scale {scale} has no {label} samples"));
            }
            let latencies: Vec<f64> = subset
                .iter()
                .flat_map(|sample| sample.run.latencies_seconds.iter().copied())
                .collect();
            let sample_rates: Vec<f64> = subset
                .iter()
                .map(|sample| sample.connections_per_second())
                .collect();
            let median_rate =
                crate::perf::stats::median(&sample_rates).map_err(|error| error.to_string())?;
            let p50 = aggregate::floor_percentile(&latencies, 0.50)?;
            p50s.push(p50);
            rates.push(median_rate);
            per_impl.push((
                label.to_owned(),
                Json::object([
                    (
                        "samples",
                        Json::Int(i64::try_from(subset.len()).unwrap_or(i64::MAX)),
                    ),
                    (
                        "connections",
                        Json::Int(i64::try_from(latencies.len()).unwrap_or(i64::MAX)),
                    ),
                    ("connectionsPerSecondMedian", Json::Float(median_rate)),
                    ("p50Seconds", Json::Float(p50)),
                    (
                        "p95Seconds",
                        Json::Float(aggregate::floor_percentile(&latencies, 0.95)?),
                    ),
                    (
                        "p99Seconds",
                        Json::Float(aggregate::floor_percentile(&latencies, 0.99)?),
                    ),
                ]),
            ));
        }
        if p50s[0] == 0.0 || rates[1] == 0.0 {
            return Err(format!("scale {scale} produced a zero denominator"));
        }
        per_impl.push((
            "xrayVsRustP50LatencyRatio".to_owned(),
            Json::Float(p50s[1] / p50s[0]),
        ));
        per_impl.push((
            "rustVsXrayConnPerSecondRatio".to_owned(),
            Json::Float(rates[0] / rates[1]),
        ));
        entries.push((scale.to_string(), Json::object(per_impl)));
    }
    Ok(Json::object(entries))
}

/// The method block the report records.
#[must_use]
pub fn method_json() -> Json {
    Json::object([
        (
            "rules",
            Json::string(
                "explicit domain rules, first-match, all -> direct outbound; no geosite/geoip files",
            ),
        ),
        (
            "targetName",
            Json::string("rule-<N-1>.routingbench (LAST rule: worst-case full walk)"),
        ),
        (
            "dns",
            Json::string(
                "loopback fake DNS, answer cached after warm-up; latency isolates rule evaluation",
            ),
        ),
        (
            "client",
            Json::string("identical Xray SOCKS5 client; DOMAIN destination resolved server-side"),
        ),
        (
            "interleave",
            Json::string("balanced ABBA blocks per scale point"),
        ),
    ])
}

/// The limitations the report states about itself.
#[must_use]
pub fn limitations_json() -> Json {
    Json::Array(
        [
            "single-host loopback includes the same Xray client, fake DNS, and origin in both paths",
            "rust-reality domain semantics match Xray plain-domain (exact + subdomain) conditions",
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

    fn sample(label: &str, scale: usize, block: usize, latency: f64) -> ScaleSample {
        ScaleSample {
            implementation: label.to_owned(),
            rule_count: scale,
            block,
            sample_index: 0,
            run: PhaseRun {
                requested: 4,
                failed: 0,
                wall_seconds: 1.0,
                latencies_seconds: vec![latency; 4],
                upstream_delta: 0,
                upstream_names: Vec::new(),
            },
        }
    }

    /// Blocks alternate so drift over a long run cannot favour whichever
    /// implementation happened to go first.
    #[test]
    fn blocks_alternate_which_implementation_leads() {
        assert_eq!(block_order(1), ["rust", "xray"]);
        assert_eq!(block_order(2), ["xray", "rust"]);
        assert_eq!(block_order(3), ["rust", "xray"]);
    }

    #[test]
    fn each_scale_reports_both_implementations_and_their_ratios() {
        let samples = vec![
            sample("rust", 10, 1, 0.001),
            sample("xray", 10, 1, 0.002),
            sample("rust", 1000, 1, 0.001),
            sample("xray", 1000, 1, 0.004),
        ];
        let rendered = summarise_scales(&samples).unwrap().to_python_json();
        assert!(rendered.contains("\"10\""));
        assert!(rendered.contains("\"1000\""));
        // Xray is twice the p50 at ten rules and four times at a thousand.
        assert!(rendered.contains("\"xrayVsRustP50LatencyRatio\": 2.0"));
        assert!(rendered.contains("\"xrayVsRustP50LatencyRatio\": 4.0"));
        assert!(rendered.contains("\"connectionsPerSecondMedian\": 4.0"));
    }

    /// A scale point missing one side has nothing to compare, so it is refused
    /// rather than reported as a one-sided result.
    #[test]
    fn a_scale_missing_one_implementation_is_refused() {
        let samples = vec![sample("rust", 10, 1, 0.001)];
        let error = summarise_scales(&samples).unwrap_err();
        assert!(error.contains("no xray samples"), "{error}");
    }

    #[test]
    fn the_row_records_the_worst_case_target() {
        let rendered = sample("rust", 10_000, 2, 0.01).to_json().to_python_json();
        assert!(rendered.contains("\"targetName\": \"rule-9999.routingbench\""));
        assert!(rendered.contains("\"ruleCount\": 10000"));
        assert!(rendered.contains("\"block\": 2"));
    }

    #[test]
    fn the_scale_sets_match_the_script_defaults() {
        assert_eq!(FORMAL_SCALES, [10, 100, 1000, 10_000]);
        assert_eq!(EXPLORATORY_SCALES, [10, 1000]);
    }

    #[test]
    fn the_method_names_the_worst_case_choice() {
        let rendered = method_json().to_python_json();
        assert!(rendered.contains("LAST rule: worst-case full walk"));
        assert!(rendered.contains("no geosite/geoip files"));
        assert!(limitations_json().to_python_json().contains("exact + subdomain"));
    }
}

// ---------------------------------------------------------------------------
// The runner
// ---------------------------------------------------------------------------

/// Measures every block of one scale point.
///
/// Both legs are built once per scale and measured across every block, so the
/// cost of constructing ten thousand rules is never charged to a sample.
#[expect(
    clippy::too_many_arguments,
    reason = "a scale point's inputs are exactly these"
)]
fn measure_scale(
    suite: &RoutingSuite,
    workspace: &crate::bench::workspace::Workspace,
    rust_bin: &std::path::Path,
    xray_bin: &std::path::Path,
    scale: usize,
    port_base: u16,
    origin_port: u16,
    cover_port: u16,
) -> Result<Vec<ScaleSample>, String> {
    use crate::bench::{
        dns::run_phase,
        resolver::{self, Implementation, LegInputs, ServerPolicy},
    };
    let policy = ServerPolicy {
        domain_rules: resolver::rule_domains(scale),
    };
    let target = resolver::worst_case_target(scale);
    let mut legs = Vec::with_capacity(2);
    for (index, implementation) in [Implementation::Rust, Implementation::Xray]
        .into_iter()
        .enumerate()
    {
        let offset = u16::try_from(index * 2).map_err(|_| "too many legs".to_owned())?;
        legs.push((
            implementation,
            resolver::start_leg(&LegInputs {
                implementation,
                workspace,
                rust_bin,
                xray_bin,
                tls_origin_port: cover_port,
                server_port: port_base + 2 + offset,
                socks_port: port_base + 3 + offset,
                policy: &policy,
            })?,
        ));
    }

    let mut samples = Vec::with_capacity(suite.blocks * 2 * suite.samples);
    for block in 1..=suite.blocks {
        for label in block_order(block) {
            let Some((_, leg)) = legs
                .iter()
                .find(|(implementation, _)| implementation.as_str() == label)
            else {
                return Err(format!("{label} leg is missing at scale {scale}"));
            };
            // Warm up: primes the server-side DNS cache for the target name, so
            // the measured rounds isolate rule evaluation.
            run_phase(
                leg.socks_port,
                origin_port,
                std::slice::from_ref(&target),
                1,
                &leg.dns,
            )?;
            for sample_index in 0..suite.samples {
                let names = vec![target.clone(); suite.connections];
                let phase = run_phase(
                    leg.socks_port,
                    origin_port,
                    &names,
                    suite.concurrency,
                    &leg.dns,
                )?;
                samples.push(ScaleSample {
                    implementation: label.to_owned(),
                    rule_count: scale,
                    block,
                    sample_index,
                    run: phase,
                });
            }
        }
    }
    Ok(samples)
}

/// Everything a routing comparison run needs.
#[derive(Debug, Clone)]
pub struct RoutingSuite {
    /// Repository root, for the Go origin.
    pub repo: std::path::PathBuf,
    /// The rust-reality binary.
    pub rust_bin: std::path::PathBuf,
    /// The Xray binary.
    pub xray_bin: std::path::PathBuf,
    /// Output directory; must not already exist.
    pub out_dir: std::path::PathBuf,
    /// Run identifier.
    pub run_id: String,
    /// Rule counts to measure.
    pub scales: Vec<usize>,
    /// Balanced ABBA blocks per scale point.
    pub blocks: usize,
    /// Measured samples per slot.
    pub samples: usize,
    /// Connections per sample.
    pub connections: usize,
    /// Concurrency within a sample.
    pub concurrency: usize,
}

/// Validates the routing parameters.
///
/// # Errors
///
/// Returns the first violated guard.
pub fn validate(suite: &RoutingSuite) -> Result<(), String> {
    if suite.scales.is_empty() || suite.scales.contains(&0) {
        return Err("every rule scale must be a positive integer".to_owned());
    }
    for (name, value) in [
        ("BLOCKS", suite.blocks),
        ("SAMPLES", suite.samples),
        ("CONNS", suite.connections),
        ("CONCURRENCY", suite.concurrency),
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

/// Runs the routing comparison end to end.
///
/// # Errors
///
/// Returns the first failure; every resource is RAII-owned.
pub fn run(suite: &RoutingSuite) -> Result<crate::bench::paired::SuiteOutcome, String> {
    use crate::bench::{
        evidence::{Publication, RunDirectory},
        host_lock::HostLock,
        identity::{self, Kind},
        resolver,
        workspace::Workspace,
    };

    validate(suite)?;
    for program in ["go", "openssl"] {
        if !crate::process::Tool::exists(program) {
            return Err(format!("required program unavailable: {program}"));
        }
    }
    let rust = identity::register("rust-reality", &suite.rust_bin, "", Kind::Rust)?;
    let xray = identity::register("xray", &suite.xray_bin, "", Kind::Xray)?;
    let _lock = HostLock::acquire(&crate::bench::runner::default_lock_path())?;
    let run = RunDirectory::create(&suite.out_dir)?;
    let workspace = Workspace::create("benchmark-routing-comparison")?;

    let port_base = crate::bench::workspace::reserve_block(6)?;
    let (origin_port, cover_port) = (port_base, port_base + 1);
    let _origins =
        resolver::start_origins(suite.repo.as_path(), &workspace, origin_port, cover_port)?;

    let mut samples: Vec<ScaleSample> = Vec::new();
    for scale in &suite.scales {
        samples.extend(measure_scale(
            suite,
            &workspace,
            &rust.path,
            &xray.path,
            *scale,
            port_base,
            origin_port,
            cover_port,
        )?);
    }

    let raw: Vec<String> = samples
        .iter()
        .map(|sample| sample.to_json().to_compact_json())
        .collect();
    run.write_jsonl("raw-samples.jsonl", &raw)?;

    let report = Json::object([
        ("schemaVersion", Json::Int(1)),
        ("harness", Json::string("benchmark-routing-comparison")),
        ("status", Json::string("COMPLETE")),
        ("performanceVerdict", Json::string("NOT_EVALUATED")),
        ("method", method_json()),
        ("scales", summarise_scales(&samples)?),
        ("limitations", limitations_json()),
    ]);
    let summary_json = report.to_python_json();
    run.write_new("summary.json", &summary_json)?;
    run.publish(
        Publication::Environment,
        &summary_json,
        &suite.run_id,
        "benchmark-routing-comparison",
    )?;
    Ok(crate::bench::paired::SuiteOutcome {
        out_dir: suite.out_dir.clone(),
        summary_json,
        slot_count: samples.len(),
    })
}
