//! Long-lived mixed-traffic soak and resource observations.
//!
//! A soak is one lifecycle with implementation-specific topology. Both sides use
//! the same native origins, workload mix, `/proc` sampler, failure accounting and
//! hash-bound publication. The Xray side is retained as a comparator mode; the
//! rust-reality side additionally owns its Handoff, NXR, SOCKS5 and reload gates.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::{
    bench::{
        ab_suites,
        config::{self, RealityIdentity},
        evidence::{self, Publication, RunDirectory},
        host_lock::HostLock,
        identity::{self, Binary, Kind},
        origin_go::{self, OriginPlan},
        origin_tls,
        process::{Child, proc_starttime},
        runner, suites,
        workspace::{self, Workspace},
    },
    hash,
    perf::json_out::Json,
    process::Tool,
};

const READY_TIMEOUT: Duration = Duration::from_secs(20);
const PAYLOAD_MIB: u64 = 4;
const CHURN_CONNECTIONS: usize = 16;

/// Bounded shared soak inputs.
#[derive(Debug, Clone)]
pub struct SoakPlan {
    /// rust-reality binary used by the native multi-topology soak.
    pub rust_bin: PathBuf,
    /// Xray binary used as server/client for the comparator topology.
    pub xray_bin: PathBuf,
    /// OpenSSL used for the shaped Handoff cover certificate and server.
    pub openssl_bin: PathBuf,
    /// Fresh output directory.
    pub out_dir: PathBuf,
    /// Safe evidence identifier.
    pub run_id: String,
    /// Timed workload window.
    pub duration: Duration,
    /// Delay between completed rounds.
    pub round_sleep: Duration,
    /// Minimum rounds required even when the timed window is very short.
    pub minimum_rounds: usize,
    /// Interval between additional distributed correctness attempts.
    pub distributed_interval: Duration,
}

/// One process's sampled Linux resource state.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessResources {
    /// Process id.
    pub pid: u32,
    /// `/proc/<pid>/stat` start-time identity.
    pub starttime: String,
    /// Open descriptors.
    pub fds: u64,
    /// Resident memory in KiB.
    pub rss_kib: u64,
    /// Proportional resident memory in KiB when `smaps_rollup` is readable.
    pub pss_kib: Option<u64>,
    /// Process-lifetime high-water RSS in KiB.
    pub hwm_kib: u64,
    /// Kernel thread count.
    pub threads: u64,
}

/// One monotonic resource observation.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceSnapshot {
    /// Phase label (`start`, `round-N`, or `end`).
    pub label: String,
    /// Seconds since this native run began.
    pub monotonic_seconds: f64,
    /// Stable process-name map.
    pub processes: BTreeMap<String, ProcessResources>,
}

/// Resource growth computed from a snapshot series.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceSummary {
    /// End minus start descriptors.
    pub fd_growth: i64,
    /// Peak minus start descriptors.
    pub fd_peak_growth: i64,
    /// End minus start threads.
    pub thread_growth: i64,
    /// Peak minus start threads.
    pub thread_peak_growth: i64,
    /// End minus start RSS in MiB.
    pub rss_growth_mib: f64,
    /// HWM peak minus start HWM in MiB.
    pub rss_peak_growth_mib: f64,
    /// Least-squares RSS slope over the second half of samples.
    pub rss_tail_slope_mib_per_hour: f64,
    /// Whether every snapshot exposed proportional-set size.
    pub pss_available: bool,
    /// End minus start PSS in MiB.
    pub pss_growth_mib: Option<f64>,
    /// Sampled PSS peak minus start in MiB.
    pub pss_peak_growth_mib: Option<f64>,
    /// PSS tail slope when available.
    pub pss_tail_slope_mib_per_hour: Option<f64>,
}

/// Successful Xray comparator observations.
#[derive(Debug, Clone)]
pub struct XraySoakOutcome {
    /// Completed mixed-traffic rounds.
    pub rounds: usize,
    /// Failed transfers or churn operations.
    pub transfer_failures: usize,
    /// Server resource growth.
    pub resources: ResourceSummary,
}

/// Validates the bounded native plan.
///
/// # Errors
///
/// Returns a message for unsafe evidence names or unbounded timings.
pub fn validate(plan: &SoakPlan) -> Result<(), String> {
    if plan.run_id.is_empty()
        || !plan
            .run_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err("RUN_ID is required and must be one safe component".to_owned());
    }
    if plan.duration.is_zero() || plan.duration > Duration::from_hours(12) {
        return Err("soak duration must be in 1..43200 seconds".to_owned());
    }
    if plan.round_sleep > Duration::from_mins(1) {
        return Err("soak round sleep must not exceed 60 seconds".to_owned());
    }
    if !(1..=100_000).contains(&plan.minimum_rounds) {
        return Err("soak minimum rounds must be in 1..100000".to_owned());
    }
    if plan.distributed_interval.is_zero() || plan.distributed_interval > Duration::from_mins(30) {
        return Err("distributed interval must be in 1..1800 seconds".to_owned());
    }
    let planned_attempts = 3 + plan
        .duration
        .as_secs()
        .saturating_sub(1)
        .checked_div(plan.distributed_interval.as_secs())
        .unwrap_or(0);
    if planned_attempts > 145 {
        return Err(format!(
            "distributed attempt count {planned_attempts} exceeds hard limit 145"
        ));
    }
    Ok(())
}

/// Runs the Xray comparator under the soak workload and publishes evidence.
///
/// # Errors
///
/// Returns the first identity, process, transfer, sampling or publication error.
#[allow(clippy::too_many_lines)]
pub fn run_xray(plan: &SoakPlan) -> Result<XraySoakOutcome, String> {
    validate(plan)?;
    let xray = identity::register("xray", &plan.xray_bin, "", Kind::Xray)?;
    let rr_dev =
        std::env::current_exe().map_err(|error| format!("could not resolve rr-dev: {error}"))?;
    let rr_dev_sha256 = hash::sha256_file(&rr_dev)?;
    let _lock = HostLock::acquire(&runner::default_lock_path())?;
    let run = RunDirectory::create(&plan.out_dir)?;
    let workspace = Workspace::create("soak-xray")?;
    let ports = workspace::reserve_ports(4)?;
    let [tls_origin_port, clear_origin_port, server_port, socks_port] =
        <[u16; 4]>::try_from(ports).map_err(|_| "could not reserve four ports".to_owned())?;

    let payload = origin_go::write_pattern_payload(workspace.path(), PAYLOAD_MIB)?;
    let payload_sha256 = hash::sha256_file(&payload)?;
    let (certificate, key) = origin_tls::generate_self_signed(workspace.path())?;
    let mut tls_origin = origin_go::start(
        &rr_dev,
        &workspace,
        &OriginPlan {
            label: "soak-origin-https".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            port: tls_origin_port,
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("https-put.jsonl"),
            tls: Some((certificate, key)),
            access_log: None,
            alpn: None,
        },
    )?;
    let mut clear_origin = origin_go::start(
        &rr_dev,
        &workspace,
        &OriginPlan {
            label: "soak-origin-http".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            port: clear_origin_port,
            payload_dir: workspace.path().to_path_buf(),
            put_log: workspace.join("http-put.jsonl"),
            tls: None,
            access_log: None,
            alpn: None,
        },
    )?;

    let identity = RealityIdentity {
        uuid: ab_suites::random_uuid_v4()?,
        short_id: ab_suites::random_short_id()?,
        server_name: "localhost".to_owned(),
        target: format!("127.0.0.1:{tls_origin_port}"),
    };
    let keys = suites::generate_xray_keys(&xray.path)?;
    let server_config = workspace.join("xray-server.json");
    let client_config = workspace.join("xray-client.json");
    std::fs::write(
        &server_config,
        config::xray_server(&identity, server_port, &keys.private, true).to_python_json(),
    )
    .map_err(|error| format!("could not write Xray server config: {error}"))?;
    std::fs::write(
        &client_config,
        config::xray_client(&identity, server_port, socks_port, &keys.public).to_python_json(),
    )
    .map_err(|error| format!("could not write Xray client config: {error}"))?;

    let mut server = Child::spawn_isolated(
        "soak-xray-server",
        &xray.path,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            server_config.display().to_string(),
        ],
        workspace.path(),
        &[("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned())],
        &run.join("server.log"),
    )
    .map_err(|error| error.to_string())?;
    server
        .wait_for_port(server_port, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;
    let server_starttime = proc_starttime(server.pid())
        .ok_or_else(|| "could not capture Xray server start-time".to_owned())?;
    let mut client = Child::spawn_isolated(
        "soak-xray-client",
        &xray.path,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            client_config.display().to_string(),
        ],
        workspace.path(),
        &[("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned())],
        &run.join("client.log"),
    )
    .map_err(|error| error.to_string())?;
    client
        .wait_for_port(socks_port, READY_TIMEOUT)
        .map_err(|error| error.to_string())?;

    let started = Instant::now();
    let mut snapshots = vec![capture_snapshot(
        "start",
        started.elapsed(),
        "xray-server",
        &mut server,
        &server_starttime,
    )?];
    let mut rounds = 0;
    let mut failures = 0;
    while started.elapsed() < plan.duration {
        rounds += 1;
        failures += run_round(
            &workspace,
            rounds,
            socks_port,
            server_port,
            tls_origin_port,
            clear_origin_port,
            &payload_sha256,
        );
        snapshots.push(capture_snapshot(
            &format!("round-{rounds}"),
            started.elapsed(),
            "xray-server",
            &mut server,
            &server_starttime,
        )?);
        if started.elapsed() < plan.duration && !plan.round_sleep.is_zero() {
            std::thread::sleep(plan.round_sleep);
        }
    }
    std::thread::sleep(Duration::from_secs(2));
    snapshots.push(capture_snapshot(
        "end",
        started.elapsed(),
        "xray-server",
        &mut server,
        &server_starttime,
    )?);

    let resources = summarize_resources(&snapshots, "xray-server")?;
    let outcome = XraySoakOutcome {
        rounds,
        transfer_failures: failures,
        resources,
    };
    if rounds < plan.minimum_rounds {
        return Err(format!(
            "soak completed {rounds} rounds, requires {}",
            plan.minimum_rounds
        ));
    }
    if failures != 0 {
        return Err(format!("soak observed {failures} transfer failure(s)"));
    }
    crate::bench::slot::verify_running_image(server.pid(), &xray.sha256, "xray server")?;
    crate::bench::slot::verify_running_image(client.pid(), &xray.sha256, "xray client")?;
    crate::bench::slot::verify_running_image(tls_origin.pid(), &rr_dev_sha256, "HTTPS origin")?;
    crate::bench::slot::verify_running_image(clear_origin.pid(), &rr_dev_sha256, "HTTP origin")?;
    crate::bench::no_ccs::assert_unchanged(&xray)?;

    let rows: Vec<String> = snapshots
        .iter()
        .map(|snapshot| snapshot_json(snapshot).to_compact_json())
        .collect();
    run.write_jsonl("resources.jsonl", &rows)?;
    let summary = xray_summary_json(
        plan,
        &outcome,
        &snapshots,
        &xray,
        &rr_dev,
        &rr_dev_sha256,
        [tls_origin_port, clear_origin_port, server_port, socks_port],
        &payload_sha256,
        &hash::sha256_file(&server_config)?,
        &hash::sha256_file(&client_config)?,
    )?;
    let document = summary.to_python_json();
    run.write_new("xray-resource-summary.json", &document)?;

    client.terminate();
    server.terminate();
    clear_origin.terminate();
    tls_origin.terminate();
    copy_origin_log(&workspace, &run, "soak-origin-http", "origin-http.log")?;
    copy_origin_log(&workspace, &run, "soak-origin-https", "origin-https.log")?;
    run.publish(
        Publication::Environment,
        &document,
        &plan.run_id,
        "soak-xray-resources",
    )?;
    Ok(outcome)
}

fn run_round(
    workspace: &Workspace,
    round: usize,
    socks_port: u16,
    server_port: u16,
    tls_origin_port: u16,
    clear_origin_port: u16,
    expected_sha256: &str,
) -> usize {
    let mut failures = 0;
    for (name, url, socks, insecure) in [
        (
            "direct",
            format!("https://127.0.0.1:{tls_origin_port}/payload-{PAYLOAD_MIB}.bin"),
            Some(socks_port),
            true,
        ),
        (
            "framed",
            format!("http://127.0.0.1:{clear_origin_port}/payload-{PAYLOAD_MIB}.bin"),
            Some(socks_port),
            false,
        ),
        (
            "fallback",
            format!("https://127.0.0.1:{server_port}/payload-{PAYLOAD_MIB}.bin"),
            None,
            true,
        ),
    ] {
        let output = workspace.join(&format!("round-{round}-{name}.bin"));
        if fetch(&url, socks, insecure, &output, Some(expected_sha256)).is_err() {
            failures += 1;
        }
    }
    let fallback = format!("https://127.0.0.1:{server_port}/payload-{PAYLOAD_MIB}.bin");
    for _ in 0..CHURN_CONNECTIONS {
        if fetch_range(&fallback).is_err() {
            failures += 1;
        }
    }
    failures
}

fn fetch(
    url: &str,
    socks_port: Option<u16>,
    insecure: bool,
    output: &Path,
    expected_sha256: Option<&str>,
) -> Result<(), String> {
    let mut args = vec![
        "--fail".to_owned(),
        "--silent".to_owned(),
        "--show-error".to_owned(),
        "--max-time".to_owned(),
        "60".to_owned(),
        "--output".to_owned(),
        output.display().to_string(),
    ];
    if insecure {
        args.push("--insecure".to_owned());
    }
    if let Some(port) = socks_port {
        args.extend(["--socks5-hostname".to_owned(), format!("127.0.0.1:{port}")]);
    }
    args.push(url.to_owned());
    let outcome = clean_curl()
        .args(args)
        .probe()
        .map_err(|error| error.to_string())?;
    if !outcome.success() {
        return Err(format!(
            "curl exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    if let Some(expected) = expected_sha256 {
        let actual = hash::sha256_file(output)?;
        if actual != expected {
            return Err(format!(
                "payload SHA-256 mismatch: {actual}, expected {expected}"
            ));
        }
    }
    Ok(())
}

fn fetch_range(url: &str) -> Result<(), String> {
    let outcome = clean_curl()
        .args([
            "--silent",
            "--show-error",
            "--insecure",
            "--max-time",
            "5",
            "--output",
            "/dev/null",
            "--range",
            "0-1023",
            url,
        ])
        .probe()
        .map_err(|error| error.to_string())?;
    if outcome.success() {
        Ok(())
    } else {
        Err(format!("churn curl exited {:?}", outcome.code))
    }
}

fn clean_curl() -> Tool {
    let mut curl = Tool::new("curl");
    for name in [
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        curl = curl.env(name, "");
    }
    curl
}

fn capture_snapshot(
    label: &str,
    elapsed: Duration,
    process_name: &str,
    child: &mut Child,
    expected_starttime: &str,
) -> Result<ResourceSnapshot, String> {
    if !child.is_alive() {
        return Err(format!("{process_name} exited before snapshot {label}"));
    }
    let resources = process_resources(child.pid(), expected_starttime)?;
    Ok(ResourceSnapshot {
        label: label.to_owned(),
        monotonic_seconds: elapsed.as_secs_f64(),
        processes: [(process_name.to_owned(), resources)].into_iter().collect(),
    })
}

fn process_resources(pid: u32, expected_starttime: &str) -> Result<ProcessResources, String> {
    let observed = proc_starttime(pid).ok_or_else(|| format!("process {pid} exited"))?;
    if observed != expected_starttime {
        return Err(format!(
            "process {pid} identity changed: {expected_starttime} -> {observed}"
        ));
    }
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|error| format!("could not read process {pid} status: {error}"))?;
    let field = |name: &str| -> Result<u64, String> {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|tail| tail.trim_start_matches(':').split_whitespace().next())
            .ok_or_else(|| format!("process status has no {name}"))?
            .parse()
            .map_err(|error| format!("process status {name} is invalid: {error}"))
    };
    let pss_kib = std::fs::read_to_string(format!("/proc/{pid}/smaps_rollup"))
        .ok()
        .and_then(|smaps| {
            smaps
                .lines()
                .find_map(|line| line.strip_prefix("Pss:"))
                .and_then(|tail| tail.split_whitespace().next())
                .and_then(|text| text.parse().ok())
        });
    let fds = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .map_err(|error| format!("could not inspect process {pid} descriptors: {error}"))?
        .count();
    Ok(ProcessResources {
        pid,
        starttime: observed,
        fds: u64::try_from(fds).unwrap_or(u64::MAX),
        rss_kib: field("VmRSS")?,
        pss_kib,
        hwm_kib: field("VmHWM").or_else(|_| field("VmRSS"))?,
        threads: field("Threads")?,
    })
}

/// Summarizes one stable named process across snapshots.
///
/// # Errors
///
/// Returns a message when fewer than two samples exist or the process set drifted.
pub fn summarize_resources(
    snapshots: &[ResourceSnapshot],
    process_name: &str,
) -> Result<ResourceSummary, String> {
    if snapshots.len() < 2 {
        return Err("resource summary needs at least start and end samples".to_owned());
    }
    let values: Vec<&ProcessResources> = snapshots
        .iter()
        .map(|snapshot| {
            snapshot
                .processes
                .get(process_name)
                .ok_or_else(|| format!("snapshot {} lacks {process_name}", snapshot.label))
        })
        .collect::<Result<_, _>>()?;
    let first = values[0];
    let last = values[values.len() - 1];
    let tail_offset = 1.max(values.len() / 2);
    let slope = linear_slope_per_hour(
        &snapshots[tail_offset..]
            .iter()
            .map(|snapshot| snapshot.monotonic_seconds)
            .collect::<Vec<_>>(),
        &values[tail_offset..]
            .iter()
            .map(|value| kib_to_mib(value.rss_kib))
            .collect::<Vec<_>>(),
    );
    let pss_values: Option<Vec<f64>> = values
        .iter()
        .map(|value| value.pss_kib.map(kib_to_mib))
        .collect();
    let pss_summary = pss_values.as_ref().map(|pss| {
        let tail_slope = linear_slope_per_hour(
            &snapshots[tail_offset..]
                .iter()
                .map(|snapshot| snapshot.monotonic_seconds)
                .collect::<Vec<_>>(),
            &pss[tail_offset..],
        );
        (
            pss[pss.len() - 1] - pss[0],
            pss.iter().copied().fold(f64::NEG_INFINITY, f64::max) - pss[0],
            tail_slope,
        )
    });
    Ok(ResourceSummary {
        fd_growth: difference(last.fds, first.fds),
        fd_peak_growth: difference(
            values.iter().map(|value| value.fds).max().unwrap_or(0),
            first.fds,
        ),
        thread_growth: difference(last.threads, first.threads),
        thread_peak_growth: difference(
            values.iter().map(|value| value.threads).max().unwrap_or(0),
            first.threads,
        ),
        rss_growth_mib: kib_to_mib(last.rss_kib) - kib_to_mib(first.rss_kib),
        rss_peak_growth_mib: kib_to_mib(
            values.iter().map(|value| value.hwm_kib).max().unwrap_or(0),
        ) - kib_to_mib(first.hwm_kib),
        rss_tail_slope_mib_per_hour: slope,
        pss_available: pss_summary.is_some(),
        pss_growth_mib: pss_summary.map(|summary| summary.0),
        pss_peak_growth_mib: pss_summary.map(|summary| summary.1),
        pss_tail_slope_mib_per_hour: pss_summary.map(|summary| summary.2),
    })
}

fn linear_slope_per_hour(xs: &[f64], ys: &[f64]) -> f64 {
    if xs.len() < 2 || xs.len() != ys.len() {
        return 0.0;
    }
    let count = f64::from(u32::try_from(xs.len()).unwrap_or(u32::MAX));
    let x_mean = xs.iter().sum::<f64>() / count;
    let y_mean = ys.iter().sum::<f64>() / count;
    let denominator: f64 = xs.iter().map(|x| (x - x_mean).powi(2)).sum();
    if denominator == 0.0 {
        return 0.0;
    }
    3600.0
        * xs.iter()
            .zip(ys)
            .map(|(x, y)| (x - x_mean) * (y - y_mean))
            .sum::<f64>()
        / denominator
}

fn difference(after: u64, before: u64) -> i64 {
    i64::try_from(after).unwrap_or(i64::MAX) - i64::try_from(before).unwrap_or(i64::MAX)
}

fn kib_to_mib(value: u64) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX)) / 1024.0
}

fn snapshot_json(snapshot: &ResourceSnapshot) -> Json {
    let processes: Vec<(String, Json)> = snapshot
        .processes
        .iter()
        .map(|(name, process)| (name.clone(), process_json(process)))
        .collect();
    let totals = totals(&snapshot.processes);
    Json::object([
        ("label", Json::string(&snapshot.label)),
        ("monotonicSeconds", Json::Float(snapshot.monotonic_seconds)),
        ("serverAlive", Json::Bool(true)),
        ("processes", Json::object(processes)),
        ("totals", totals_json(&totals)),
        ("fds", int(totals.fds)),
        ("vmRssKiB", int(totals.rss_kib)),
        ("vmPssKiB", totals.pss_kib.map_or(Json::Null, int)),
        ("vmHwmKiB", int(totals.hwm_kib)),
        ("threads", int(totals.threads)),
    ])
}

fn process_json(process: &ProcessResources) -> Json {
    Json::object([
        ("alive", Json::Bool(true)),
        ("pid", Json::Int(i64::from(process.pid))),
        ("pidStarttime", Json::string(&process.starttime)),
        ("fds", int(process.fds)),
        ("vmRssKiB", int(process.rss_kib)),
        ("vmPssKiB", process.pss_kib.map_or(Json::Null, int)),
        ("vmHwmKiB", int(process.hwm_kib)),
        ("threads", int(process.threads)),
    ])
}

fn resource_summary_json(summary: &ResourceSummary) -> Json {
    Json::object([
        ("fdGrowth", Json::Int(summary.fd_growth)),
        ("fdPeakGrowth", Json::Int(summary.fd_peak_growth)),
        ("threadGrowth", Json::Int(summary.thread_growth)),
        ("threadPeakGrowth", Json::Int(summary.thread_peak_growth)),
        ("rssGrowthMiB", Json::Float(summary.rss_growth_mib)),
        ("rssPeakGrowthMiB", Json::Float(summary.rss_peak_growth_mib)),
        (
            "rssTailSlopeMiBPerHour",
            Json::Float(summary.rss_tail_slope_mib_per_hour),
        ),
        ("pssAvailable", Json::Bool(summary.pss_available)),
        (
            "pssGrowthMiB",
            summary.pss_growth_mib.map_or(Json::Null, Json::Float),
        ),
        (
            "pssSampledPeakGrowthMiB",
            summary.pss_peak_growth_mib.map_or(Json::Null, Json::Float),
        ),
        (
            "pssTailSlopeMiBPerHour",
            summary
                .pss_tail_slope_mib_per_hour
                .map_or(Json::Null, Json::Float),
        ),
    ])
}

#[derive(Default)]
struct Totals {
    fds: u64,
    rss_kib: u64,
    pss_kib: Option<u64>,
    hwm_kib: u64,
    threads: u64,
}

fn totals(processes: &BTreeMap<String, ProcessResources>) -> Totals {
    let mut totals = Totals {
        pss_kib: Some(0),
        ..Totals::default()
    };
    for process in processes.values() {
        totals.fds += process.fds;
        totals.rss_kib += process.rss_kib;
        totals.hwm_kib += process.hwm_kib;
        totals.threads += process.threads;
        totals.pss_kib = match (totals.pss_kib, process.pss_kib) {
            (Some(total), Some(value)) => Some(total + value),
            _ => None,
        };
    }
    totals
}

fn totals_json(totals: &Totals) -> Json {
    Json::object([
        ("fds", int(totals.fds)),
        ("vmRssKiB", int(totals.rss_kib)),
        ("vmPssKiB", totals.pss_kib.map_or(Json::Null, int)),
        ("vmHwmKiB", int(totals.hwm_kib)),
        ("threads", int(totals.threads)),
    ])
}

#[allow(clippy::too_many_arguments)]
fn xray_summary_json(
    plan: &SoakPlan,
    outcome: &XraySoakOutcome,
    snapshots: &[ResourceSnapshot],
    xray: &Binary,
    rr_dev: &Path,
    rr_dev_sha256: &str,
    ports: [u16; 4],
    payload_sha256: &str,
    server_config_sha256: &str,
    client_config_sha256: &str,
) -> Result<Json, String> {
    Ok(Json::object([
        ("schemaVersion", Json::Int(2)),
        ("harness", Json::string("soak")),
        ("implementation", Json::string("xray")),
        ("runId", Json::string(&plan.run_id)),
        ("completedAt", Json::string(evidence::now_utc()?)),
        ("durationSeconds", Json::Float(plan.duration.as_secs_f64())),
        ("rounds", usize_json(outcome.rounds)),
        ("minimumRounds", usize_json(plan.minimum_rounds)),
        ("transferFailures", usize_json(outcome.transfer_failures)),
        ("payloadBytes", int(PAYLOAD_MIB * 1024 * 1024)),
        ("payloadSha256", Json::string(payload_sha256)),
        (
            "xray",
            Json::object([
                ("path", Json::string(xray.path.display().to_string())),
                ("sha256", Json::string(&xray.sha256)),
                ("identity", Json::string(&xray.identity)),
            ]),
        ),
        (
            "nativeOrigins",
            Json::object([
                ("path", Json::string(rr_dev.display().to_string())),
                ("sha256", Json::string(rr_dev_sha256)),
            ]),
        ),
        (
            "configSha256",
            Json::object([
                ("server", Json::string(server_config_sha256)),
                ("client", Json::string(client_config_sha256)),
            ]),
        ),
        (
            "ports",
            Json::object([
                ("httpsOrigin", Json::Int(i64::from(ports[0]))),
                ("httpOrigin", Json::Int(i64::from(ports[1]))),
                ("server", Json::Int(i64::from(ports[2]))),
                ("socks", Json::Int(i64::from(ports[3]))),
            ]),
        ),
        ("resources", resource_summary_json(&outcome.resources)),
        (
            "snapshots",
            Json::Array(snapshots.iter().map(snapshot_json).collect()),
        ),
        ("ok", Json::Bool(true)),
    ]))
}

fn copy_origin_log(
    workspace: &Workspace,
    run: &RunDirectory,
    source_label: &str,
    destination: &str,
) -> Result<(), String> {
    let contents = std::fs::read_to_string(workspace.join(&format!("{source_label}.log")))
        .map_err(|error| format!("could not read native origin log: {error}"))?;
    run.write_new(destination, &contents)?;
    Ok(())
}

fn int(value: u64) -> Json {
    Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

fn usize_json(value: usize) -> Json {
    Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> SoakPlan {
        SoakPlan {
            rust_bin: PathBuf::from("rust-reality"),
            xray_bin: PathBuf::from("xray"),
            openssl_bin: PathBuf::from("openssl"),
            out_dir: PathBuf::from("/out"),
            run_id: "soak-1".to_owned(),
            duration: Duration::from_mins(1),
            round_sleep: Duration::from_secs(5),
            minimum_rounds: 1,
            distributed_interval: Duration::from_mins(30),
        }
    }

    fn process(fds: u64, rss: u64, hwm: u64, threads: u64) -> ProcessResources {
        ProcessResources {
            pid: 1,
            starttime: "10".to_owned(),
            fds,
            rss_kib: rss,
            pss_kib: Some(rss / 2),
            hwm_kib: hwm,
            threads,
        }
    }

    fn snapshot(seconds: f64, resources: ProcessResources) -> ResourceSnapshot {
        ResourceSnapshot {
            label: format!("at-{seconds}"),
            monotonic_seconds: seconds,
            processes: [("server".to_owned(), resources)].into_iter().collect(),
        }
    }

    #[test]
    fn timing_and_identity_inputs_are_bounded() {
        assert!(validate(&plan()).is_ok());
        let mut invalid = plan();
        invalid.run_id = "../escape".to_owned();
        assert!(validate(&invalid).is_err());
        invalid = plan();
        invalid.duration = Duration::ZERO;
        assert!(validate(&invalid).is_err());
        invalid = plan();
        invalid.duration = Duration::from_secs(43_201);
        assert!(validate(&invalid).is_err());
    }

    #[test]
    fn growth_and_tail_slope_follow_the_legacy_formulas() {
        let snapshots = [
            snapshot(0.0, process(10, 10_240, 10_240, 2)),
            snapshot(10.0, process(12, 11_264, 12_288, 3)),
            snapshot(20.0, process(11, 12_288, 13_312, 3)),
            snapshot(30.0, process(11, 13_312, 14_336, 3)),
        ];
        let summary = summarize_resources(&snapshots, "server").unwrap();
        assert_eq!(summary.fd_growth, 1);
        assert_eq!(summary.fd_peak_growth, 2);
        assert_eq!(summary.thread_growth, 1);
        assert!((summary.rss_growth_mib - 3.0).abs() < f64::EPSILON);
        assert!((summary.rss_peak_growth_mib - 4.0).abs() < f64::EPSILON);
        assert!((summary.rss_tail_slope_mib_per_hour - 360.0).abs() < 0.001);
    }

    #[test]
    fn a_changed_process_set_fails_closed() {
        let snapshots = [
            snapshot(0.0, process(1, 1, 1, 1)),
            ResourceSnapshot {
                label: "end".to_owned(),
                monotonic_seconds: 1.0,
                processes: BTreeMap::new(),
            },
        ];
        assert!(summarize_resources(&snapshots, "server").is_err());
    }
}
