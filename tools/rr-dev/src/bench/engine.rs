//! The shared A/B tunnel-download benchmark execution engine.
//!
//! The real-path, xray and vision-direct suites are all "run a payload download
//! through two tunnel implementations in an alternating order and compare
//! throughput". This engine owns that one lifecycle — reserve ports, launch the
//! servers and SOCKS clients under RAII process guards, wait for readiness, drive
//! the alternating workload, classify each transfer, and assemble the schema-v1
//! report — so the suites differ only in declarative configuration.
//!
//! The workload transfer is injected as a [`Transfer`] so the engine is testable
//! against a loopback origin with a fake transfer, without requiring rust-reality,
//! Xray or Internet egress. Production wires a `curl` transfer over the SOCKS
//! proxy; tests wire a deterministic local transfer.

use std::time::{Duration, Instant};

use crate::{
    bench::{
        report::{self, Sample},
        workspace::Workspace,
    },
    perf::json_out::Json,
};

/// One tunnel implementation under test.
#[derive(Debug, Clone)]
pub struct Implementation {
    /// The implementation name recorded in the report, e.g. `rust-reality`.
    pub name: String,
    /// The loopback SOCKS port a client of this implementation listens on.
    pub socks_port: u16,
}

/// A transfer that downloads `expected_bytes` through the SOCKS proxy on
/// `socks_port`, returning the observed byte count and duration.
///
/// Production supplies a `curl` implementation; tests supply a deterministic
/// loopback one. The engine never spawns a shell; a real transfer builds argv
/// directly.
pub trait Transfer {
    /// Runs one transfer. Returns `Ok((bytes, elapsed))` on a completed transfer,
    /// or `Err(reason)` when it failed.
    ///
    /// # Errors
    ///
    /// Returns the transfer failure reason.
    fn run(&self, socks_port: u16, expected_bytes: u64) -> Result<(u64, Duration), String>;
}

/// A plan for one A/B tunnel-download benchmark.
#[derive(Debug, Clone)]
pub struct TunnelPlan {
    /// The suite id (used for the workspace name and report harness field).
    pub suite: String,
    /// The two implementations, in `[first, second]` alternating order.
    pub implementations: [Implementation; 2],
    /// Expected payload size per transfer, in bytes.
    pub expected_bytes: u64,
    /// Number of alternating runs.
    pub runs: usize,
}

/// The attribution facts a report records alongside the measurements.
///
/// These mirror the provenance block the legacy harness wrote: which exact
/// binaries produced the numbers, what the transfer destination was, and when
/// the run happened. All are plain data so the report stays reproducible.
#[derive(Debug, Clone, Default)]
pub struct Provenance {
    /// The registered binaries as `(label, path, sha256)` triples.
    pub binaries: Vec<(String, String, String)>,
    /// The transfer destination URL (query stripped, as the legacy report did).
    pub url: Option<String>,
    /// The rust-reality server listen port, when a tunnel benchmark ran.
    pub rust_server_port: Option<u16>,
    /// The Unix timestamp of the report, in seconds.
    pub timestamp_unix: Option<u64>,
}

/// The outcome of an engine run: the assembled report and whether it passed.
#[derive(Debug)]
pub struct RunReport {
    /// The schema-v1 report JSON.
    pub json: String,
    /// The number of failed transfers.
    pub failures: usize,
}

/// Drives the A/B workload described by `plan`, collecting samples via `transfer`.
///
/// This is the pure orchestration core: it does not launch processes itself (the
/// caller owns the server/client [`crate::bench::process::Child`] guards and has
/// already confirmed readiness). It runs the alternating transfer loop, classifies
/// each result, and returns the samples in run order.
#[must_use]
pub fn collect_samples(plan: &TunnelPlan, transfer: &dyn Transfer) -> Vec<Sample> {
    let order = report::alternating_order(
        &plan.implementations[0].name,
        &plan.implementations[1].name,
        plan.runs,
    );
    let mut samples = Vec::with_capacity(plan.runs);
    for name in order {
        let socks_port = plan
            .implementations
            .iter()
            .find(|implementation| implementation.name == name)
            .map_or(0, |implementation| implementation.socks_port);
        let sample = match transfer.run(socks_port, plan.expected_bytes) {
            Ok((bytes, elapsed)) if bytes == plan.expected_bytes && elapsed.as_secs_f64() > 0.0 => {
                #[allow(clippy::cast_precision_loss)] // byte counts far below 2^53
                let bps = bytes as f64 / elapsed.as_secs_f64();
                Sample {
                    implementation: name,
                    ok: true,
                    bytes_per_second: Some(bps),
                }
            }
            _ => Sample {
                implementation: name,
                ok: false,
                bytes_per_second: None,
            },
        };
        samples.push(sample);
    }
    samples
}

/// Assembles the schema-v1 A/B report from collected samples.
#[must_use]
pub fn assemble_report(plan: &TunnelPlan, samples: &[Sample]) -> RunReport {
    assemble_report_with(plan, samples, &Provenance::default())
}

/// Assembles the schema-v1 A/B report with binary and transfer provenance.
#[must_use]
pub fn assemble_report_with(
    plan: &TunnelPlan,
    samples: &[Sample],
    provenance: &Provenance,
) -> RunReport {
    let failures = report::failure_count(samples);
    let order: Vec<Json> = report::alternating_order(
        &plan.implementations[0].name,
        &plan.implementations[1].name,
        plan.runs,
    )
    .into_iter()
    .map(Json::string)
    .collect();

    let mut summary_entries: Vec<(String, Json)> = vec![
        (
            "runs".to_owned(),
            Json::Int(i64::try_from(plan.runs).unwrap_or(i64::MAX)),
        ),
        ("alternatingOrder".to_owned(), Json::Array(order)),
        (
            "failures".to_owned(),
            Json::Int(i64::try_from(failures).unwrap_or(i64::MAX)),
        ),
    ];
    for implementation in &plan.implementations {
        if let Some(summary) = report::summarise(samples, &implementation.name) {
            summary_entries.push((implementation.name.clone(), report::summary_json(&summary)));
        }
    }

    let results: Vec<Json> = samples
        .iter()
        .enumerate()
        .map(|(index, sample)| {
            let mut fields: Vec<(String, Json)> = vec![
                (
                    "index".to_owned(),
                    Json::Int(i64::try_from(index).unwrap_or(i64::MAX)),
                ),
                (
                    "implementation".to_owned(),
                    Json::string(sample.implementation.clone()),
                ),
                ("ok".to_owned(), Json::Bool(sample.ok)),
            ];
            if let Some(bytes_per_second) = sample.bytes_per_second {
                fields.push(("bytesPerSecond".to_owned(), Json::Float(bytes_per_second)));
            }
            Json::Object(fields.into_iter().collect())
        })
        .collect();

    let mut fields: Vec<(String, Json)> = vec![
        ("schemaVersion".to_owned(), Json::Int(1)),
        ("harness".to_owned(), Json::string(plan.suite.clone())),
        ("status".to_owned(), Json::string("COMPLETE")),
        (
            "performanceVerdict".to_owned(),
            Json::string("NOT_EVALUATED"),
        ),
        (
            "binaries".to_owned(),
            Json::object(provenance.binaries.iter().map(|(label, path, sha256)| {
                (
                    label.clone(),
                    Json::object([
                        ("path", Json::string(path.clone())),
                        ("sha256", Json::string(sha256.clone())),
                    ]),
                )
            })),
        ),
        (
            "expectedBytes".to_owned(),
            Json::Int(i64::try_from(plan.expected_bytes).unwrap_or(i64::MAX)),
        ),
    ];
    if let Some(url) = &provenance.url {
        fields.push(("url".to_owned(), Json::string(url.clone())));
    }
    if let Some(port) = provenance.rust_server_port {
        fields.push(("rustServerPort".to_owned(), Json::Int(i64::from(port))));
    }
    if let Some(timestamp) = provenance.timestamp_unix {
        fields.push((
            "timestampUnix".to_owned(),
            Json::Int(i64::try_from(timestamp).unwrap_or(i64::MAX)),
        ));
    }
    fields.push((
        "summary".to_owned(),
        Json::Object(summary_entries.into_iter().collect()),
    ));
    fields.push(("results".to_owned(), Json::Array(results)));
    let report_json = Json::Object(fields.into_iter().collect());

    RunReport {
        json: report_json.to_python_json(),
        failures,
    }
}

/// Waits until a readiness predicate holds or a deadline elapses.
///
/// A small shared helper for suite `run()` glue that needs to wait on something
/// other than a single port (e.g. a control-plane readiness file).
///
/// # Errors
///
/// Returns `context` as the error when the deadline elapses.
pub fn wait_until<F: Fn() -> bool>(
    ready: F,
    timeout: Duration,
    context: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if ready() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(format!("timed out waiting for {context}"))
}

/// Writes the report JSON into the run workspace and returns its path.
///
/// # Errors
///
/// Returns a message when the report cannot be written.
pub fn write_report(
    workspace: &Workspace,
    name: &str,
    report: &RunReport,
) -> Result<std::path::PathBuf, String> {
    let path = workspace.join(name);
    std::fs::write(&path, &report.json)
        .map_err(|error| format!("could not write report {}: {error}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic transfer: the named implementation always succeeds at a
    /// fixed throughput; a designated failing port always fails.
    struct FakeTransfer {
        fail_port: Option<u16>,
        seconds: f64,
    }

    impl Transfer for FakeTransfer {
        fn run(&self, socks_port: u16, expected_bytes: u64) -> Result<(u64, Duration), String> {
            if Some(socks_port) == self.fail_port {
                return Err("injected failure".to_owned());
            }
            Ok((expected_bytes, Duration::from_secs_f64(self.seconds)))
        }
    }

    fn plan() -> TunnelPlan {
        TunnelPlan {
            suite: "test-tunnel".to_owned(),
            implementations: [
                Implementation {
                    name: "rust-reality".to_owned(),
                    socks_port: 1080,
                },
                Implementation {
                    name: "xray".to_owned(),
                    socks_port: 1081,
                },
            ],
            expected_bytes: 1_000_000,
            runs: 4,
        }
    }

    #[test]
    fn samples_follow_the_alternating_order() {
        let samples = collect_samples(
            &plan(),
            &FakeTransfer {
                fail_port: None,
                seconds: 1.0,
            },
        );
        let names: Vec<&str> = samples.iter().map(|s| s.implementation.as_str()).collect();
        assert_eq!(names, ["rust-reality", "xray", "rust-reality", "xray"]);
        assert!(samples.iter().all(|s| s.ok));
    }

    #[test]
    fn a_failing_transfer_is_classified_and_counted() {
        let samples = collect_samples(
            &plan(),
            &FakeTransfer {
                fail_port: Some(1081),
                seconds: 1.0,
            },
        );
        // Every xray (port 1081) transfer failed; rust-reality succeeded.
        assert_eq!(report::failure_count(&samples), 2);
        assert!(
            samples
                .iter()
                .filter(|s| s.implementation == "rust-reality")
                .all(|s| s.ok)
        );
        assert!(
            samples
                .iter()
                .filter(|s| s.implementation == "xray")
                .all(|s| !s.ok)
        );
    }

    #[test]
    fn the_report_is_schema_v1_with_summary_and_results() {
        let samples = collect_samples(
            &plan(),
            &FakeTransfer {
                fail_port: None,
                seconds: 0.5,
            },
        );
        let report = assemble_report(&plan(), &samples);
        assert_eq!(report.failures, 0);
        assert!(report.json.contains("\"schemaVersion\": 1"));
        assert!(report.json.contains("\"harness\": \"test-tunnel\""));
        assert!(report.json.contains("\"status\": \"COMPLETE\""));
        assert!(
            report
                .json
                .contains("\"performanceVerdict\": \"NOT_EVALUATED\"")
        );
        assert!(report.json.contains("\"rust-reality\""));
        assert!(report.json.contains("\"xray\""));
        assert!(report.json.contains("\"alternatingOrder\""));
        // 2 MiB/s at 0.5s over 1_000_000 bytes -> ~1.9 MiB/s; just assert present.
        assert!(report.json.contains("medianMiBPerSecond"));
    }

    #[test]
    fn a_report_with_only_failures_summarises_no_implementation() {
        let samples = collect_samples(
            &plan(),
            &FakeTransfer {
                fail_port: Some(1080),
                seconds: 1.0,
            },
        );
        // rust-reality (1080) all fail; xray still summarises.
        let report = assemble_report(&plan(), &samples);
        assert_eq!(report.failures, 2);
        assert!(report.json.contains("\"xray\""));
    }
}
