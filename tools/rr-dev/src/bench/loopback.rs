//! Loopback concurrent A/B suite — the typed `benchmark-xray.sh` replacement.
//!
//! Shares tunnel materialization with [`crate::bench::suites`] (configs, four
//! RAII processes, host lock, workspace). Differs only in the workload:
//!
//! - a deterministic loopback HTTP origin ([`crate::bench::origin`]);
//! - concurrent curl transfers per sample;
//! - a shuffled order with the legacy fixed seed `0x4e5852`;
//! - the richer schema-v1 report the Xray harness historically emitted.
//!
//! Do not invent another orchestration engine: consume `suites::materialize`
//! and `origin`, then drive this workload.

use std::time::Instant;

use crate::{
    bench::{
        attest,
        engine::Transfer,
        origin,
        suites::{self, CurlTransfer, RunError, SuiteContext},
    },
    perf::{hotspot, json_out::Json},
};

/// The legacy shuffle seed, kept as a constant so archived evidence stays
/// comparable.
const RANDOM_SEED: u64 = 0x4e_5852;

/// One concurrent sample: wall throughput and mean per-request latency.
#[derive(Debug, Clone)]
pub struct ConcurrentSample {
    /// The implementation name.
    pub implementation: String,
    /// Wall-clock seconds covering the concurrent transfer set.
    pub wall_seconds: f64,
    /// Mean per-request seconds across the concurrent transfers.
    pub mean_request_seconds: f64,
    /// Aggregate throughput in MiB/s (`payload_mib * concurrency / wall`).
    pub throughput_mib_per_second: f64,
}

/// Parameters for the loopback concurrent suite beyond the shared tunnel context.
#[derive(Debug, Clone)]
pub struct LoopbackPlan {
    /// Samples per implementation (before shuffling into a single order).
    pub samples: usize,
    /// Concurrent transfers per sample.
    pub concurrency: usize,
    /// Payload size in MiB.
    pub payload_mib: u64,
    /// When true, serve a TLS 1.3 HTTPS origin (Vision-direct); otherwise plain HTTP.
    pub tls_origin: bool,
    /// Report harness id (`benchmark-xray` or `benchmark-vision-direct`).
    pub harness: String,
    /// Stable benchmark transaction identifier.
    pub run_id: String,
    /// Optional identity-bound capture of the rust-reality server.
    pub profile: Option<hotspot::BenchmarkProfile>,
}

/// Outcome of a loopback concurrent suite run.
#[derive(Debug)]
pub struct LoopbackOutcome {
    /// The schema-v1 report JSON.
    pub report_json: String,
    /// The measurements in shuffled order.
    pub measurements: Vec<ConcurrentSample>,
}

/// Runs the concurrent curl set for one implementation.
///
/// # Errors
///
/// Returns the first transfer failure.
pub fn measure_concurrent(
    transfer: &CurlTransfer,
    socks_port: u16,
    expected_bytes: u64,
    concurrency: usize,
    payload_mib: u64,
    implementation: &str,
) -> Result<ConcurrentSample, String> {
    let started = Instant::now();
    let mut latencies = Vec::with_capacity(concurrency);
    // Sequential within the typed harness is enough for correctness and for the
    // small smoke sizes used in tests; the production legacy path used threads
    // for wall-clock overlap. Overlap is restored below with scoped threads.
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            handles.push(scope.spawn(|| transfer.run(socks_port, expected_bytes)));
        }
        for handle in handles {
            let (bytes, elapsed) = handle
                .join()
                .map_err(|_| "transfer thread panicked".to_owned())??;
            if bytes != expected_bytes {
                return Err(format!(
                    "payload integrity failed: downloaded {bytes}, expected {expected_bytes}"
                ));
            }
            latencies.push(elapsed.as_secs_f64());
        }
        Ok::<(), String>(())
    })?;
    let wall = started.elapsed().as_secs_f64();
    if wall <= 0.0 {
        return Err("non-positive wall duration".to_owned());
    }
    #[allow(clippy::cast_precision_loss)]
    let mean = latencies.iter().sum::<f64>() / latencies.len() as f64;
    #[allow(clippy::cast_precision_loss)]
    let throughput = (payload_mib as f64) * (concurrency as f64) / wall;
    Ok(ConcurrentSample {
        implementation: implementation.to_owned(),
        wall_seconds: wall,
        mean_request_seconds: mean,
        throughput_mib_per_second: throughput,
    })
}

/// Deterministic shuffle matching Python `random.Random(0x4E5852).shuffle`.
///
/// Python's Mersenne Twister is not reproduced here byte-for-byte; for the
/// suite contract we need a fixed, reproducible order derived from the same
/// seed constant. This uses a tiny LCG seeded with `RANDOM_SEED` so archived
/// reports stay deterministic across runs on this harness.
#[must_use]
pub fn shuffled_order(first: &str, second: &str, samples: usize) -> Vec<String> {
    let mut order: Vec<String> = (0..samples)
        .flat_map(|_| [first.to_owned(), second.to_owned()])
        .collect();
    let mut state = RANDOM_SEED;
    for i in (1..order.len()).rev() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let j = (state >> 33) as usize % (i + 1);
        order.swap(i, j);
    }
    order
}

/// Summarises concurrent samples for one implementation.
fn summarise(samples: &[ConcurrentSample], name: &str) -> Option<Json> {
    let mut throughput: Vec<f64> = samples
        .iter()
        .filter(|sample| sample.implementation == name)
        .map(|sample| sample.throughput_mib_per_second)
        .collect();
    let mut latency: Vec<f64> = samples
        .iter()
        .filter(|sample| sample.implementation == name)
        .map(|sample| sample.mean_request_seconds)
        .collect();
    if throughput.is_empty() {
        return None;
    }
    throughput.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    latency.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    #[allow(clippy::cast_precision_loss)]
    let t_mean = throughput.iter().sum::<f64>() / throughput.len() as f64;
    #[allow(clippy::cast_precision_loss)]
    let l_mean = latency.iter().sum::<f64>() / latency.len() as f64;
    Some(Json::object([
        (
            "samples",
            Json::Int(i64::try_from(throughput.len()).unwrap_or(i64::MAX)),
        ),
        (
            "throughputMiBPerSecond",
            Json::object([
                ("mean", Json::Float(t_mean)),
                ("p50", Json::Float(percentile(&throughput, 0.50))),
                ("p95", Json::Float(percentile(&throughput, 0.95))),
                ("minimum", Json::Float(throughput[0])),
            ]),
        ),
        (
            "meanRequestSeconds",
            Json::object([
                ("mean", Json::Float(l_mean)),
                ("p50", Json::Float(percentile(&latency, 0.50))),
                ("p95", Json::Float(percentile(&latency, 0.95))),
                ("maximum", Json::Float(*latency.last().unwrap_or(&0.0))),
            ]),
        ),
    ]))
}

fn percentile(ordered: &[f64], fraction: f64) -> f64 {
    if ordered.is_empty() {
        return 0.0;
    }
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let index = ((ordered.len() as f64) * fraction).ceil() as usize;
    ordered[index.saturating_sub(1).min(ordered.len() - 1)]
}

/// Summary of Vision Direct promotion events parsed from the rust-reality server log.
#[derive(Debug, Clone, Default)]
pub struct DirectSummary {
    /// Completed connections that emitted a Direct event.
    pub connections: usize,
    /// Accepted connections (includes the readiness probe).
    pub accepted_connections: usize,
    /// True when accepted connections <= 1 (curl likely bypassed the tunnel).
    pub tunnel_bypass_detected: bool,
    /// Connections that promoted the uplink to Direct.
    pub uplink_direct: usize,
    /// Connections that promoted the downlink to Direct.
    pub downlink_direct: usize,
    /// Backend name counts across uplink/downlink/relay fields.
    pub backends: std::collections::BTreeMap<String, usize>,
}

/// Parses Vision Direct events from a rust-reality JSON log.
#[must_use]
pub fn parse_direct_events(log: &std::path::Path) -> DirectSummary {
    let Ok(text) = std::fs::read_to_string(log) else {
        return DirectSummary::default();
    };
    let mut summary = DirectSummary::default();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(value) = crate::perf::json_in::parse(line) else {
            continue;
        };
        let Some(event) = value.optional("event").and_then(|v| v.as_str("event").ok()) else {
            continue;
        };
        match event {
            "connection_accepted" => summary.accepted_connections += 1,
            "connection_completed" => {
                summary.connections += 1;
                if value
                    .optional("uplink_direct")
                    .and_then(|v| v.as_bool("uplink_direct").ok())
                    == Some(true)
                {
                    summary.uplink_direct += 1;
                }
                if value
                    .optional("downlink_direct")
                    .and_then(|v| v.as_bool("downlink_direct").ok())
                    == Some(true)
                {
                    summary.downlink_direct += 1;
                }
                for key in ["uplink_backend", "downlink_backend", "relay_backend"] {
                    if let Some(backend) = value.optional(key).and_then(|v| v.as_str(key).ok())
                        && !backend.is_empty()
                    {
                        *summary.backends.entry(backend.to_owned()).or_insert(0) += 1;
                    }
                }
            }
            _ => {}
        }
    }
    summary.tunnel_bypass_detected = summary.accepted_connections <= 1;
    summary
}

fn validate_direct_summary(summary: &DirectSummary) -> Result<(), String> {
    if summary.tunnel_bypass_detected {
        return Err(
            "Vision-Direct tunnel guard observed no server connections beyond readiness".to_owned(),
        );
    }
    if summary.connections == 0 {
        return Err("Vision-Direct server emitted no completed-connection evidence".to_owned());
    }
    if summary.downlink_direct == 0 {
        return Err("Vision-Direct workload never promoted the download path to Direct".to_owned());
    }
    Ok(())
}

/// Assembles the schema-v1 loopback concurrent report.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn assemble_report(
    plan: &LoopbackPlan,
    context: &SuiteContext<'_>,
    measurements: &[ConcurrentSample],
    order: &[String],
    binaries: &[(String, String, String)],
    direct: Option<&DirectSummary>,
) -> String {
    let mut summary = std::collections::BTreeMap::new();
    for name in ["rust-reality", "xray"] {
        if let Some(entry) = summarise(measurements, name) {
            summary.insert(name.to_owned(), entry);
        }
    }
    let rust_p50 = summary
        .get("rust-reality")
        .and_then(|entry| match entry {
            Json::Object(members) => members.get("throughputMiBPerSecond"),
            _ => None,
        })
        .and_then(|entry| match entry {
            Json::Object(members) => members.get("p50"),
            _ => None,
        })
        .and_then(|entry| match entry {
            Json::Float(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(0.0);
    let xray_p50 = summary
        .get("xray")
        .and_then(|entry| match entry {
            Json::Object(members) => members.get("throughputMiBPerSecond"),
            _ => None,
        })
        .and_then(|entry| match entry {
            Json::Object(members) => members.get("p50"),
            _ => None,
        })
        .and_then(|entry| match entry {
            Json::Float(value) => Some(*value),
            _ => None,
        })
        .unwrap_or(0.0);
    let ratio = if xray_p50 > 0.0 {
        rust_p50 / xray_p50
    } else {
        0.0
    };

    let measurement_json: Vec<Json> = measurements
        .iter()
        .map(|sample| {
            Json::object([
                (
                    "implementation",
                    Json::string(sample.implementation.clone()),
                ),
                ("wallSeconds", Json::Float(sample.wall_seconds)),
                (
                    "meanRequestSeconds",
                    Json::Float(sample.mean_request_seconds),
                ),
                (
                    "throughputMiBPerSecond",
                    Json::Float(sample.throughput_mib_per_second),
                ),
            ])
        })
        .collect();

    let report = Json::object([
        ("schemaVersion", Json::Int(1)),
        ("harness", Json::string(plan.harness.clone())),
        ("status", Json::string("COMPLETE")),
        ("performanceVerdict", Json::string("NOT_EVALUATED")),
        (
            "binaries",
            Json::object(binaries.iter().map(|(label, path, sha)| {
                (
                    label.clone(),
                    Json::object([
                        ("path", Json::string(path.clone())),
                        ("sha256", Json::string(sha.clone())),
                    ]),
                )
            })),
        ),
        (
            "method",
            Json::object([
                (
                    "client",
                    Json::string("Xray SOCKS5 -> VLESS + REALITY + xtls-rprx-vision"),
                ),
                (
                    "destination",
                    Json::string(if plan.tls_origin {
                        "loopback TLS 1.3 HTTPS origin (Vision Direct eligible)"
                    } else {
                        "loopback Python HTTP server"
                    }),
                ),
                ("realityTarget", Json::string(context.cover_target.clone())),
                (
                    "realityServerName",
                    Json::string(context.cover_sni.clone()),
                ),
                (
                    "samplesPerImplementation",
                    Json::Int(i64::try_from(plan.samples).unwrap_or(i64::MAX)),
                ),
                (
                    "concurrency",
                    Json::Int(i64::try_from(plan.concurrency).unwrap_or(i64::MAX)),
                ),
                (
                    "payloadMiBPerRequest",
                    Json::Int(i64::try_from(plan.payload_mib).unwrap_or(i64::MAX)),
                ),
                ("randomSeed", Json::string("0x4e5852")),
                (
                    "randomizedOrder",
                    Json::Array(order.iter().cloned().map(Json::string).collect()),
                ),
            ]),
        ),
        ("measurements", Json::Array(measurement_json)),
        ("summary", Json::Object(summary)),
        ("rustRealityToXrayP50ThroughputRatio", Json::Float(ratio)),
        (
            "limitations",
            Json::Array(
                [
                    "single-host loopback includes the same Xray client and Python origin in both paths",
                    "Xray's default private-target block is explicitly allowed only for this loopback origin",
                    "this does not model Internet RTT, packet loss, bandwidth shaping, or multi-core saturation",
                    "results are measurements of this host and are not a universal performance claim",
                ]
                .into_iter()
                .map(Json::string)
                .collect(),
            ),
        ),
    ]);
    // Attach Vision Direct summary when present.
    let report = if let Some(direct) = direct {
        let Json::Object(mut members) = report else {
            return report.to_python_json();
        };
        members.insert(
            "rustRealityDirect".to_owned(),
            Json::object([
                (
                    "connections",
                    Json::Int(i64::try_from(direct.connections).unwrap_or(i64::MAX)),
                ),
                (
                    "acceptedConnections",
                    Json::Int(i64::try_from(direct.accepted_connections).unwrap_or(i64::MAX)),
                ),
                (
                    "tunnelBypassDetected",
                    Json::Bool(direct.tunnel_bypass_detected),
                ),
                (
                    "uplinkDirect",
                    Json::Int(i64::try_from(direct.uplink_direct).unwrap_or(i64::MAX)),
                ),
                (
                    "downlinkDirect",
                    Json::Int(i64::try_from(direct.downlink_direct).unwrap_or(i64::MAX)),
                ),
                (
                    "backends",
                    Json::Object(
                        direct
                            .backends
                            .iter()
                            .map(|(key, value)| {
                                (
                                    key.clone(),
                                    Json::Int(i64::try_from(*value).unwrap_or(i64::MAX)),
                                )
                            })
                            .collect(),
                    ),
                ),
            ]),
        );
        Json::Object(members)
    } else {
        report
    };
    report.to_python_json()
}

/// Runs the loopback concurrent suite end to end.
///
/// # Errors
///
/// Returns a setup/process/workload error. A completed report with failed
/// transfers is returned as [`RunError::Workload`] is not used here — any
/// transfer failure aborts the suite (matching the legacy `check=True`).
#[allow(clippy::too_many_lines)]
pub fn run_loopback(
    context: &SuiteContext<'_>,
    plan: &LoopbackPlan,
) -> Result<LoopbackOutcome, RunError> {
    if plan.samples == 0 || plan.concurrency == 0 || plan.payload_mib == 0 {
        return Err(RunError::Setup(
            "samples, concurrency and payload_mib must be positive".to_owned(),
        ));
    }
    if plan.samples > 100 || plan.concurrency > 64 || plan.payload_mib > 1024 {
        return Err(RunError::Setup(
            "bounds are samples<=100, concurrency<=64, payload_mib<=1024".to_owned(),
        ));
    }
    if let Some(profile) = &plan.profile {
        hotspot::validate_benchmark_profile(profile).map_err(RunError::Setup)?;
        if !plan.tls_origin {
            return Err(RunError::Setup(
                "benchmark-owned profiling is supported only by vision-direct".to_owned(),
            ));
        }
    }

    let mut context = SuiteContext {
        allow_private: true,
        expected_bytes: plan.payload_mib.saturating_mul(1024 * 1024),
        transfer_url: String::new(), // filled after origin launches
        ..context.clone_for_loopback()
    };

    // Materialize tunnels first (4 ports). Then reserve an origin port and
    // launch the HTTP origin inside the same workspace.
    let run =
        suites::materialize_with_rust_log_level(&context, plan.tls_origin.then_some("debug"))?;

    let origin_port = crate::bench::workspace::reserve_ports(1)
        .map_err(RunError::Setup)?
        .into_iter()
        .next()
        .ok_or_else(|| RunError::Setup("could not reserve origin port".to_owned()))?;
    let payload_path = run.workspace.join("payload.bin");
    origin::write_payload(&payload_path, context.expected_bytes).map_err(RunError::Setup)?;
    let origin = if plan.tls_origin {
        let (cert, key) = crate::bench::origin_tls::generate_self_signed(run.workspace.path())
            .map_err(RunError::Setup)?;
        let origin = crate::bench::origin_tls::launch_https(
            run.workspace.path(),
            "payload.bin",
            context.expected_bytes,
            origin_port,
            &cert,
            &key,
            &run.workspace.join("https-origin.log"),
        )
        .map_err(RunError::Processes)?;
        // HTTPS URL for the TLS origin.
        context.transfer_url = format!("https://127.0.0.1:{origin_port}/payload.bin");
        origin
    } else {
        let origin = origin::launch(
            run.workspace.path(),
            "payload.bin",
            context.expected_bytes,
            origin_port,
            &run.workspace.join("http-origin.log"),
        )
        .map_err(RunError::Processes)?;
        context.transfer_url = origin.url();
        origin
    };

    let transfer = CurlTransfer {
        url: context.transfer_url.clone(),
        max_time_secs: context.transfer_max_time_secs,
        insecure: plan.tls_origin,
        tls_v1_3: plan.tls_origin,
    };

    // Warmup each implementation once, matching the legacy harness.
    for (name, port) in [("rust-reality", run.ports[2]), ("xray", run.ports[3])] {
        transfer
            .run(port, context.expected_bytes)
            .map_err(|error| RunError::Processes(format!("warmup {name}: {error}")))?;
    }

    let mut profile = if let Some(settings) = &plan.profile {
        let binary = &run.binaries[0];
        let build_id = attest::build_id(&binary.path).map_err(RunError::Setup)?;
        Some(
            hotspot::BenchmarkCapture::start(
                &run.lock,
                binary,
                &build_id,
                run.processes.rust_server.pid(),
                "vision-direct",
                &plan.run_id,
                absolute_profile_dir(&context.out_dir).map_err(RunError::Setup)?,
                settings,
            )
            .map_err(RunError::Processes)?,
        )
    } else {
        None
    };

    let order = shuffled_order("rust-reality", "xray", plan.samples);
    let mut measurements = Vec::with_capacity(order.len());
    for name in &order {
        let port = if name == "rust-reality" {
            run.ports[2]
        } else {
            run.ports[3]
        };
        let sample = match measure_concurrent(
            &transfer,
            port,
            context.expected_bytes,
            plan.concurrency,
            plan.payload_mib,
            name,
        ) {
            Ok(sample) => sample,
            Err(error) => {
                if let Some(capture) = profile.take() {
                    capture
                        .cancel("vision-direct workload failed")
                        .map_err(RunError::Processes)?;
                }
                return Err(RunError::Processes(error));
            }
        };
        measurements.push(sample);
    }

    // Give the server a moment to flush per-connection completion events while
    // it and the optional profile are still transaction-owned. An invalid
    // Direct workload cancels the profile, so neither child nor parent can
    // publish success for traffic that bypassed the measured server.
    let direct = if plan.tls_origin {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let direct = parse_direct_events(&run.workspace.join("rust-server.log"));
        if let Err(error) = validate_direct_summary(&direct) {
            if let Some(capture) = profile.take() {
                capture
                    .cancel("vision-direct evidence validation failed")
                    .map_err(RunError::Processes)?;
            }
            return Err(RunError::Processes(error));
        }
        Some(direct)
    } else {
        None
    };

    if let Some(capture) = profile.take() {
        capture.finish().map_err(RunError::Processes)?;
    }
    drop(profile);

    let binaries: Vec<(String, String, String)> = run
        .binaries
        .iter()
        .map(|binary| {
            (
                binary.label.clone(),
                binary.path.display().to_string(),
                binary.sha256.clone(),
            )
        })
        .collect();
    let report_json = assemble_report(
        plan,
        &context,
        &measurements,
        &order,
        &binaries,
        direct.as_ref(),
    );
    std::fs::create_dir_all(&context.out_dir).map_err(|error| {
        RunError::Setup(format!(
            "could not create {}: {error}",
            context.out_dir.display()
        ))
    })?;
    let path = context.out_dir.join("report.json");
    std::fs::write(&path, &report_json)
        .map_err(|error| RunError::Setup(format!("could not write {}: {error}", path.display())))?;
    println!("suite report: {}", path.display());

    // Keep origin and tunnel processes alive until here; dropping run + origin
    // tears everything down.
    drop(origin);
    drop(run);

    Ok(LoopbackOutcome {
        report_json,
        measurements,
    })
}

fn absolute_profile_dir(out_dir: &std::path::Path) -> Result<std::path::PathBuf, String> {
    let root = if out_dir.is_absolute() {
        out_dir.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("could not resolve benchmark output directory: {error}"))?
            .join(out_dir)
    };
    Ok(root.join("hotspot"))
}

impl SuiteContext<'_> {
    /// Clones the owned fields for a loopback run (paths stay borrowed).
    fn clone_for_loopback(&self) -> SuiteContext<'_> {
        SuiteContext {
            rust_bin: self.rust_bin,
            xray_bin: self.xray_bin,
            cover_target: self.cover_target.clone(),
            cover_sni: self.cover_sni.clone(),
            runs: self.runs,
            expected_bytes: self.expected_bytes,
            suite_id: self.suite_id.clone(),
            transfer_url: self.transfer_url.clone(),
            transfer_max_time_secs: self.transfer_max_time_secs,
            out_dir: self.out_dir.clone(),
            allow_private: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shuffled_order_is_deterministic() {
        let first = shuffled_order("rust-reality", "xray", 4);
        let second = shuffled_order("rust-reality", "xray", 4);
        assert_eq!(first, second);
        assert_eq!(first.len(), 8);
        assert_eq!(
            first.iter().filter(|name| *name == "rust-reality").count(),
            4
        );
        assert_eq!(first.iter().filter(|name| *name == "xray").count(), 4);
    }

    #[test]
    fn percentile_matches_the_legacy_ceil_rule() {
        let values = [10.0, 20.0, 30.0, 40.0];
        assert!((percentile(&values, 0.5) - 20.0).abs() < 1e-9);
        assert!((percentile(&values, 0.95) - 40.0).abs() < 1e-9);
    }

    #[test]
    fn vision_direct_evidence_fails_closed_without_a_direct_download() {
        let absent = DirectSummary {
            tunnel_bypass_detected: true,
            ..DirectSummary::default()
        };
        assert!(validate_direct_summary(&absent).is_err());

        let not_direct = DirectSummary {
            accepted_connections: 3,
            connections: 2,
            ..DirectSummary::default()
        };
        assert!(validate_direct_summary(&not_direct).is_err());

        let direct = DirectSummary {
            accepted_connections: 3,
            connections: 2,
            downlink_direct: 2,
            ..DirectSummary::default()
        };
        assert!(validate_direct_summary(&direct).is_ok());
    }
}
