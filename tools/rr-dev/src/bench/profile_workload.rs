//! Workloads and exact-identity resource sampling for machine profiles.
//!
//! The measured server remains a real process in a real cgroup. This module
//! owns only repository policy: raw SOCKS5 setup churn, concurrent downloads,
//! the authenticated idle-session ladder, structured event counts and the
//! one-second `/proc`/cgroup series. No command is routed through a shell.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "measurement rows use bounded counts and mirror the evidence schema"
)]

use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{Read as _, Write as _},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{
    bench::process::proc_starttime,
    perf::{json_in, json_out::Json},
};

const SOCKS_TIMEOUT: Duration = Duration::from_secs(30);
const MIB: f64 = 1024.0 * 1024.0;

/// One instantaneous process/cgroup resource sample.
#[derive(Debug, Clone, Default)]
pub struct ResourceSample {
    /// Resident set size in bytes.
    pub rss_bytes: Option<i64>,
    /// Open descriptor count.
    pub fd_count: Option<i64>,
    /// Process CPU seconds.
    pub cpu_seconds: Option<f64>,
    /// Cgroup `memory.current`.
    pub memory_current: Option<i64>,
    /// Cgroup `memory.peak`.
    pub memory_peak: Option<i64>,
    /// Cgroup `memory.swap.current`.
    pub swap_current: Option<i64>,
    /// Cgroup `oom_kill` counter.
    pub oom_kills: Option<i64>,
}

impl ResourceSample {
    /// Renders the live-sample schema used in `cells.jsonl`.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            ("serverRssBytes", optional_int(self.rss_bytes)),
            ("serverFdCount", optional_int(self.fd_count)),
            (
                "serverCpuSeconds",
                self.cpu_seconds.map_or(Json::Null, Json::Float),
            ),
            ("cgroupMemoryCurrent", optional_int(self.memory_current)),
            ("cgroupMemoryPeak", optional_int(self.memory_peak)),
            ("cgroupMemorySwapCurrent", optional_int(self.swap_current)),
            ("cgroupOomKills", optional_int(self.oom_kills)),
        ])
    }
}

fn optional_int(value: Option<i64>) -> Json {
    value.map_or(Json::Null, Json::Int)
}

fn read_i64(path: &Path) -> Option<i64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn process_cpu_seconds(pid: u32) -> Option<f64> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = raw.rfind(')')?;
    let fields: Vec<&str> = raw[end + 1..].split_whitespace().collect();
    let user = fields.get(11)?.parse::<u64>().ok()?;
    let system = fields.get(12)?.parse::<u64>().ok()?;
    Some((user + system) as f64 / 100.0)
}

fn process_rss_bytes(pid: u32) -> Option<i64> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")?
                .split_whitespace()
                .next()?
                .parse::<i64>()
                .ok()
                .and_then(|value| value.checked_mul(1024))
        })
}

fn process_fd_count(pid: u32) -> Option<i64> {
    i64::try_from(std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?.count()).ok()
}

fn oom_kills(cgroup: &Path) -> Option<i64> {
    std::fs::read_to_string(cgroup.join("memory.events"))
        .ok()?
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(' ')?;
            (name == "oom_kill")
                .then(|| value.trim().parse::<i64>().ok())
                .flatten()
        })
}

/// Samples a live process and its cgroup, failing fields closed to `null`.
#[must_use]
pub fn sample_now(pid: u32, cgroup: &Path) -> ResourceSample {
    ResourceSample {
        rss_bytes: process_rss_bytes(pid),
        fd_count: process_fd_count(pid),
        cpu_seconds: process_cpu_seconds(pid),
        memory_current: read_i64(&cgroup.join("memory.current")),
        memory_peak: read_i64(&cgroup.join("memory.peak")),
        swap_current: read_i64(&cgroup.join("memory.swap.current")),
        oom_kills: oom_kills(cgroup),
    }
}

/// Owned one-second resource-series sampler.
pub struct Sampler {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<(), String>>>,
}

impl Sampler {
    /// Starts a write-once sampler bound to one exact PID start time.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if the output cannot be created or the PID cannot
    /// be identified before the thread starts.
    pub fn start(pid: u32, cgroup: PathBuf, output: PathBuf) -> Result<Self, String> {
        let starttime = proc_starttime(pid)
            .ok_or_else(|| format!("could not identify profile server PID {pid}"))?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)
            .map_err(|error| format!("could not create {}: {error}", output.display()))?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("rr-profile-sampler".to_owned())
            .spawn(move || {
                while !thread_stop.load(Ordering::Acquire)
                    && proc_starttime(pid).as_deref() == Some(starttime.as_str())
                {
                    let sample = sample_now(pid, &cgroup);
                    let timestamp = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_or(0, |duration| duration.as_secs());
                    writeln!(
                        file,
                        "{}\t{}\t{}\t{}\t{}",
                        timestamp,
                        sample.rss_bytes.unwrap_or(-1),
                        sample.fd_count.unwrap_or(-1),
                        sample.memory_current.unwrap_or(-1),
                        sample.swap_current.unwrap_or(-1)
                    )
                    .map_err(|error| format!("could not write {}: {error}", output.display()))?;
                    file.flush().map_err(|error| {
                        format!("could not flush {}: {error}", output.display())
                    })?;
                    for _ in 0..10 {
                        if thread_stop.load(Ordering::Acquire) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
                Ok(())
            })
            .map_err(|error| format!("could not start resource sampler: {error}"))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    /// Stops and joins the sampler.
    ///
    /// # Errors
    ///
    /// Returns a writer or thread diagnostic.
    pub fn stop(mut self) -> Result<(), String> {
        self.finish()
    }

    fn finish(&mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::Release);
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        thread
            .join()
            .map_err(|_| "resource sampler thread panicked".to_owned())?
    }
}

impl Drop for Sampler {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

fn read_exact(stream: &mut TcpStream, count: usize) -> Result<Vec<u8>, String> {
    let mut buffer = vec![0_u8; count];
    stream
        .read_exact(&mut buffer)
        .map_err(|error| format!("SOCKS5 reply ended early: {error}"))?;
    Ok(buffer)
}

fn open_socks(socks_port: u16, origin_port: u16) -> Result<TcpStream, String> {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, socks_port));
    let mut stream = TcpStream::connect_timeout(&address, SOCKS_TIMEOUT)
        .map_err(|error| format!("could not connect to SOCKS5 port {socks_port}: {error}"))?;
    stream
        .set_read_timeout(Some(SOCKS_TIMEOUT))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(SOCKS_TIMEOUT))
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|error| error.to_string())?;
    if read_exact(&mut stream, 2)? != [0x05, 0x00] {
        return Err("SOCKS5 greeting was rejected".to_owned());
    }
    let mut request = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    request.extend_from_slice(&origin_port.to_be_bytes());
    stream
        .write_all(&request)
        .map_err(|error| error.to_string())?;
    let head = read_exact(&mut stream, 4)?;
    if head.get(1) != Some(&0) {
        return Err(format!("SOCKS5 CONNECT was rejected with reply {head:?}"));
    }
    let address_length = match head.get(3) {
        Some(0x01) => 4,
        Some(0x04) => 16,
        Some(0x03) => usize::from(read_exact(&mut stream, 1)?[0]),
        _ => return Err("SOCKS5 CONNECT used an invalid address type".to_owned()),
    };
    let _ = read_exact(&mut stream, address_length + 2)?;
    Ok(stream)
}

fn one_churn_connection(socks_port: u16, origin_port: u16) -> Option<f64> {
    let started = Instant::now();
    let mut stream = open_socks(socks_port, origin_port).ok()?;
    stream
        .write_all(b"GET /payload.bin HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        .ok()?;
    let mut response = [0_u8; 4096];
    (stream.read(&mut response).ok()? > 0).then(|| started.elapsed().as_secs_f64())
}

fn percentile(sorted: &[f64], fraction: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let index = ((sorted.len() as f64 * fraction) as usize).min(sorted.len() - 1);
    sorted.get(index).copied()
}

/// Runs the c8/c32 setup-churn cells and returns their JSONL rows.
#[must_use]
pub fn churn(
    socks_port: u16,
    origin_port: u16,
    server_pid: u32,
    concurrencies: &[usize],
    connections: usize,
    samples: usize,
) -> Vec<Json> {
    let mut rows = Vec::new();
    for &concurrency in concurrencies {
        let _ = one_churn_connection(socks_port, origin_port);
        for sample_index in 0..samples {
            let cpu_before = process_cpu_seconds(server_pid).unwrap_or(0.0);
            let started = Instant::now();
            let next = AtomicUsize::new(0);
            let mut latencies = Vec::new();
            let mut failed = 0_usize;
            std::thread::scope(|scope| {
                let workers: Vec<_> = (0..concurrency.clamp(1, connections.max(1)))
                    .map(|_| {
                        let next = &next;
                        scope.spawn(move || {
                            let mut local = Vec::new();
                            let mut failures = 0;
                            loop {
                                if next.fetch_add(1, Ordering::Relaxed) >= connections {
                                    break;
                                }
                                if let Some(elapsed) = one_churn_connection(socks_port, origin_port)
                                {
                                    local.push(elapsed);
                                } else {
                                    failures += 1;
                                }
                            }
                            (local, failures)
                        })
                    })
                    .collect();
                for worker in workers {
                    match worker.join() {
                        Ok((mut local, failures)) => {
                            latencies.append(&mut local);
                            failed += failures;
                        }
                        Err(_) => failed += 1,
                    }
                }
            });
            latencies.sort_unstable_by(f64::total_cmp);
            let wall = started.elapsed().as_secs_f64();
            let cpu = process_cpu_seconds(server_pid).unwrap_or(cpu_before) - cpu_before;
            let mut fields: Vec<(String, Json)> = vec![
                ("cell".to_owned(), Json::string("churn")),
                (
                    "concurrency".to_owned(),
                    Json::Int(i64::try_from(concurrency).unwrap_or(i64::MAX)),
                ),
                (
                    "sampleIndex".to_owned(),
                    Json::Int(i64::try_from(sample_index).unwrap_or(i64::MAX)),
                ),
                ("wallSeconds".to_owned(), Json::Float(wall)),
                ("serverCpuSeconds".to_owned(), Json::Float(cpu)),
                (
                    "connections".to_owned(),
                    Json::Int(i64::try_from(latencies.len()).unwrap_or(i64::MAX)),
                ),
                (
                    "failed".to_owned(),
                    Json::Int(i64::try_from(failed).unwrap_or(i64::MAX)),
                ),
            ];
            if !latencies.is_empty() && wall > 0.0 {
                fields.push((
                    "connectionsPerSecond".to_owned(),
                    Json::Float(latencies.len() as f64 / wall),
                ));
                for (name, fraction) in [
                    ("p50Seconds", 0.50),
                    ("p95Seconds", 0.95),
                    ("p99Seconds", 0.99),
                ] {
                    if let Some(value) = percentile(&latencies, fraction) {
                        fields.push((name.to_owned(), Json::Float(value)));
                    }
                }
            }
            rows.push(Json::object(fields));
        }
    }
    rows
}

fn clean_command(program: &Path) -> Command {
    let mut command = Command::new(program);
    for name in [
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
        "CARGO_HTTP_PROXY",
    ] {
        command.env_remove(name);
    }
    command
}

/// Runs concurrent curl download cells through the measured tunnel.
///
/// # Errors
///
/// Returns a setup diagnostic when curl cannot be launched. Individual curl
/// failures remain recorded in the returned rows for the summary gate.
pub fn download(
    curl: &Path,
    socks_port: u16,
    url: &str,
    expected_bytes: u64,
    server_pid: u32,
    concurrency: usize,
    samples: usize,
) -> Result<Vec<Json>, String> {
    let mut rows = Vec::new();
    for sample_index in 0..samples {
        let cpu_before = process_cpu_seconds(server_pid).unwrap_or(0.0);
        let started = Instant::now();
        let mut children = Vec::new();
        for _ in 0..concurrency {
            let child = clean_command(curl)
                .args([
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "900",
                    "--socks5-hostname",
                    &format!("127.0.0.1:{socks_port}"),
                    "--output",
                    "/dev/null",
                    "--write-out",
                    "%{size_download} %{time_total}",
                    url,
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|error| format!("could not start curl: {error}"))?;
            children.push(child);
        }
        let mut sizes = Vec::new();
        let mut times = Vec::new();
        let mut errors = Vec::new();
        for child in children {
            let output = child
                .wait_with_output()
                .map_err(|error| format!("could not wait for curl: {error}"))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                errors.push(format!(
                    "curl rc={}: {}",
                    output.status.code().unwrap_or(-1),
                    stderr.trim().chars().take(200).collect::<String>()
                ));
                continue;
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut fields = stdout.split_whitespace();
            let Some(size) = fields.next().and_then(|value| value.parse::<u64>().ok()) else {
                errors.push("curl produced no parseable size".to_owned());
                continue;
            };
            let Some(elapsed) = fields.next().and_then(|value| value.parse::<f64>().ok()) else {
                errors.push("curl produced no parseable elapsed time".to_owned());
                continue;
            };
            sizes.push(size);
            times.push(elapsed);
        }
        let wall = started.elapsed().as_secs_f64();
        let cpu = process_cpu_seconds(server_pid).unwrap_or(cpu_before) - cpu_before;
        let total: u64 = sizes.iter().sum();
        rows.push(Json::object([
            ("cell", Json::string("download")),
            (
                "concurrency",
                Json::Int(i64::try_from(concurrency).unwrap_or(i64::MAX)),
            ),
            (
                "sampleIndex",
                Json::Int(i64::try_from(sample_index).unwrap_or(i64::MAX)),
            ),
            ("wallSeconds", Json::Float(wall)),
            ("serverCpuSeconds", Json::Float(cpu)),
            (
                "totalBytes",
                Json::Int(i64::try_from(total).unwrap_or(i64::MAX)),
            ),
            (
                "requests",
                Json::Int(i64::try_from(sizes.len()).unwrap_or(i64::MAX)),
            ),
            (
                "errors",
                Json::Array(errors.into_iter().map(Json::string).collect()),
            ),
            (
                "throughputMiBPerSecond",
                if wall > 0.0 {
                    Json::Float(total as f64 / wall / MIB)
                } else {
                    Json::Null
                },
            ),
            (
                "perRequestSeconds",
                Json::Array(times.into_iter().map(Json::Float).collect()),
            ),
            (
                "sizeMismatches",
                Json::Int(
                    i64::try_from(sizes.iter().filter(|size| **size != expected_bytes).count())
                        .unwrap_or(i64::MAX),
                ),
            ),
        ]));
    }
    Ok(rows)
}

/// Proves the tunnel can carry one HTTP request before measuring it.
///
/// # Errors
///
/// Returns the SOCKS or HTTP failure.
pub fn sanity_probe(socks_port: u16, origin_port: u16) -> Result<(), String> {
    let mut stream = open_socks(socks_port, origin_port)?;
    stream
        .write_all(b"GET /payload.bin HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        .map_err(|error| format!("tunnel request failed: {error}"))?;
    let mut byte = [0_u8; 1];
    if stream
        .read(&mut byte)
        .map_err(|error| format!("tunnel response failed: {error}"))?
        == 0
    {
        return Err("tunnel returned no data".to_owned());
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
struct MarkerCounts {
    values: BTreeMap<&'static str, i64>,
    latest_pressure: Option<String>,
}

fn marker_counts(path: &Path) -> MarkerCounts {
    const KEYS: [&str; 5] = [
        "resource_pressure_changed",
        "descriptor_pressure_changed",
        "admission_limited",
        "connection_rejected",
        "accept_error_recovered",
    ];
    let mut counts = MarkerCounts {
        values: KEYS.into_iter().map(|key| (key, 0)).collect(),
        latest_pressure: None,
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return counts;
    };
    for line in raw.lines() {
        let Ok(row) = json_in::parse(line) else {
            continue;
        };
        let Ok(event) = row
            .field("log", "event")
            .and_then(|event| event.as_str("log.event"))
        else {
            continue;
        };
        if let Some(count) = counts.values.get_mut(event) {
            *count += 1;
        }
        if event == "resource_pressure_changed" {
            counts.latest_pressure = row
                .optional("pressure_state")
                .and_then(|value| value.as_str("pressure_state").ok())
                .map(str::to_owned);
        }
    }
    counts
}

fn marker_json(counts: &MarkerCounts) -> Json {
    Json::object(
        counts
            .values
            .iter()
            .map(|(key, value)| (*key, Json::Int(*value))),
    )
}

fn open_wave(socks_port: u16, origin_port: u16, count: usize) -> Vec<Option<TcpStream>> {
    if count == 0 {
        return Vec::new();
    }
    let next = AtomicUsize::new(0);
    let mut results = Vec::with_capacity(count);
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..count.min(256))
            .map(|_| {
                let next = &next;
                scope.spawn(move || {
                    let mut local = Vec::new();
                    loop {
                        if next.fetch_add(1, Ordering::Relaxed) >= count {
                            break;
                        }
                        local.push(open_socks(socks_port, origin_port).ok());
                    }
                    local
                })
            })
            .collect();
        for worker in workers {
            if let Ok(mut local) = worker.join() {
                results.append(&mut local);
            }
        }
    });
    while results.len() < count {
        results.push(None);
    }
    results
}

fn ladder_sample(
    tag: Option<&str>,
    level: usize,
    held: usize,
    failed: usize,
    server_pid: u32,
    server_starttime: &str,
    cgroup: &Path,
    server_log: &Path,
    baseline_oom: Option<i64>,
    baseline_markers: &MarkerCounts,
) -> Json {
    let resources = sample_now(server_pid, cgroup);
    let markers = marker_counts(server_log);
    Json::object([
        ("cell", Json::string("ladder")),
        ("tag", tag.map_or(Json::Null, Json::string)),
        ("level", Json::Int(i64::try_from(level).unwrap_or(i64::MAX))),
        (
            "connectionsHeld",
            Json::Int(i64::try_from(held).unwrap_or(i64::MAX)),
        ),
        (
            "serverEstablishedSessions",
            Json::Int(i64::try_from(held).unwrap_or(i64::MAX)),
        ),
        (
            "establishmentEvidence",
            Json::string("successful-socks-connect"),
        ),
        (
            "connectionsFailedTotal",
            Json::Int(i64::try_from(failed).unwrap_or(i64::MAX)),
        ),
        (
            "serverAlive",
            Json::Bool(proc_starttime(server_pid).as_deref() == Some(server_starttime)),
        ),
        ("serverRssBytes", optional_int(resources.rss_bytes)),
        ("serverFdCount", optional_int(resources.fd_count)),
        (
            "serverCpuSeconds",
            resources.cpu_seconds.map_or(Json::Null, Json::Float),
        ),
        (
            "cgroupMemoryCurrent",
            optional_int(resources.memory_current),
        ),
        ("cgroupMemoryPeak", optional_int(resources.memory_peak)),
        (
            "cgroupMemorySwapCurrent",
            optional_int(resources.swap_current),
        ),
        (
            "cgroupOomKills",
            optional_int(
                baseline_oom
                    .zip(resources.oom_kills)
                    .map(|(before, after)| after - before),
            ),
        ),
        (
            "logEvents",
            marker_json(&markers),
        ),
        ("logEventBaseline", marker_json(baseline_markers)),
        (
            "latestPressureState",
            markers.latest_pressure.map_or(Json::Null, Json::string),
        ),
    ])
}

fn with_fields(row: Json, additional: &[(&str, Json)]) -> Json {
    let Json::Object(mut fields) = row else {
        return row;
    };
    fields.extend(
        additional
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone())),
    );
    Json::Object(fields)
}

/// Runs one cumulative authenticated idle-session ladder.
#[must_use]
pub fn ladder(
    socks_port: u16,
    origin_port: u16,
    server_pid: u32,
    server_starttime: &str,
    server_log: &Path,
    cgroup: &Path,
    levels: &[usize],
    settle: Duration,
    hold_duration: Duration,
    tag: Option<&str>,
) -> Vec<Json> {
    let baseline_oom = oom_kills(cgroup);
    let baseline_markers = marker_counts(server_log);
    let mut connections: Vec<TcpStream> = Vec::new();
    let mut failed = 0;
    let mut abort_reason = None;
    let mut rows = Vec::new();
    for &level in levels {
        if proc_starttime(server_pid).as_deref() != Some(server_starttime) {
            abort_reason = Some("server process died".to_owned());
            break;
        }
        let wave = level.saturating_sub(connections.len());
        for stream in open_wave(socks_port, origin_port, wave) {
            if let Some(stream) = stream {
                connections.push(stream);
            } else {
                failed += 1;
            }
        }
        std::thread::sleep(settle);
        let sample = ladder_sample(
            tag,
            level,
            connections.len(),
            failed,
            server_pid,
            server_starttime,
            cgroup,
            server_log,
            baseline_oom,
            &baseline_markers,
        );
        let alive = match &sample {
            Json::Object(fields) => matches!(fields.get("serverAlive"), Some(Json::Bool(true))),
            _ => false,
        };
        let swap = match &sample {
            Json::Object(fields) => match fields.get("cgroupMemorySwapCurrent") {
                Some(Json::Int(value)) => Some(*value),
                _ => None,
            },
            _ => None,
        };
        let oom = match &sample {
            Json::Object(fields) => match fields.get("cgroupOomKills") {
                Some(Json::Int(value)) => Some(*value),
                _ => None,
            },
            _ => None,
        };
        rows.push(sample);
        if !alive {
            abort_reason = Some("server process died".to_owned());
            break;
        }
        match oom {
            None => {
                abort_reason = Some("cgroup oom_kill status unavailable".to_owned());
                break;
            }
            Some(value) if value > 0 => {
                abort_reason = Some("cgroup oom_kill".to_owned());
                break;
            }
            Some(_) => {}
        }
        match swap {
            None => {
                abort_reason = Some("cgroup memory.swap.current unavailable".to_owned());
                break;
            }
            Some(value) if value != 0 => {
                abort_reason = Some(format!("cgroup memory.swap.current is non-zero ({value})"));
                break;
            }
            Some(_) => {}
        }
        if wave > 0 && connections.len() * 2 < level {
            abort_reason = Some("majority of the wave failed to connect".to_owned());
            break;
        }
        let plateau = level >= 1000 && connections.len() * 10 < level * 6;
        std::thread::sleep(hold_duration);
        if plateau {
            let recheck = with_fields(
                ladder_sample(
                    tag,
                    level,
                    connections.len(),
                    failed,
                    server_pid,
                    server_starttime,
                    cgroup,
                    server_log,
                    baseline_oom,
                    &baseline_markers,
                ),
                &[("recheck", Json::Bool(true))],
            );
            rows.push(recheck);
            if connections.len() * 10 < level * 6 {
                abort_reason = Some(format!(
                    "server-side sessions plateaued at {} (admission ceiling or pressure)",
                    connections.len()
                ));
                break;
            }
        }
    }
    std::thread::sleep(Duration::from_secs(2));
    let level = levels.last().copied().unwrap_or(0);
    let final_sample = ladder_sample(
        tag,
        level,
        connections.len(),
        failed,
        server_pid,
        server_starttime,
        cgroup,
        server_log,
        baseline_oom,
        &baseline_markers,
    );
    rows.push(with_fields(
        final_sample,
        &[
            ("ladderComplete", Json::Bool(abort_reason.is_none())),
            ("abortReason", abort_reason.map_or(Json::Null, Json::string)),
        ],
    ));
    drop(connections);
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_uses_the_legacy_floor_rank() {
        let values: Vec<f64> = (0..100).map(f64::from).collect();
        assert_eq!(percentile(&values, 0.50), Some(50.0));
        assert_eq!(percentile(&values, 0.95), Some(95.0));
        assert_eq!(percentile(&values, 0.99), Some(99.0));
    }

    #[test]
    fn a_missing_process_samples_as_unknown() {
        let sample = sample_now(u32::MAX, Path::new("/definitely/absent"));
        assert_eq!(sample.rss_bytes, None);
        assert_eq!(sample.fd_count, None);
        assert_eq!(sample.swap_current, None);
    }
}
