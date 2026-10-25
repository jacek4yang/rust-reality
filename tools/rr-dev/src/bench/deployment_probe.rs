//! Deployment routing probes, SOCKS throughput cells, and relay-log evidence.
//!
//! These helpers are shared by the native deployment sections but do not own
//! process lifecycle or netns topology. Keeping them beside `deployment.rs`
//! lets section orchestration stay focused on RunState while the pure probe
//! contracts remain independently reviewable.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read as _, Write as _},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use crate::{
    hash,
    perf::{json_in, json_out::Json},
    process::Tool,
};

use super::deployment_plan::count;

/// Expected outcome of one routing proof case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteExpectation {
    /// The connection must be refused before an HTTP response arrives.
    Blocked,
    /// The response body must have this exact SHA-256.
    Sha256(String),
}

/// One `(user, destination)` routing proof case.
#[derive(Debug, Clone)]
pub struct RouteCase {
    /// Stable user UUID.
    pub uuid: String,
    /// User group name.
    pub group: String,
    /// Rule/default behavior under test.
    pub label: String,
    /// This user's Xray SOCKS listener.
    pub socks_port: u16,
    /// Destination host presented to the server.
    pub host: String,
    /// Destination port presented to the server.
    pub port: u16,
    /// HTTP path.
    pub path: String,
    /// Required classification.
    pub expect: RouteExpectation,
}

/// Observed result of one routing proof case.
#[derive(Debug, Clone)]
pub struct RouteResult {
    /// Original case.
    pub case: RouteCase,
    /// `blocked`, `error`, or `sha256:<digest>`.
    pub observed: String,
    /// Bounded failure detail.
    pub detail: String,
    /// End-to-end case time.
    pub seconds: f64,
    /// Whether observed equals expected.
    pub passed: bool,
}

impl RouteResult {
    /// Renders the legacy per-case evidence shape.
    #[must_use]
    pub fn to_json(&self) -> Json {
        let expected = match &self.case.expect {
            RouteExpectation::Blocked => "blocked".to_owned(),
            RouteExpectation::Sha256(digest) => digest.clone(),
        };
        Json::object([
            ("uuid", Json::string(&self.case.uuid)),
            ("group", Json::string(&self.case.group)),
            ("label", Json::string(&self.case.label)),
            (
                "destination",
                Json::string(format!("{}:{}", self.case.host, self.case.port)),
            ),
            ("expected", Json::string(expected)),
            ("observed", Json::string(&self.observed)),
            ("detail", Json::string(&self.detail)),
            ("seconds", Json::Float(self.seconds)),
            ("pass", Json::Bool(self.passed)),
        ])
    }
}

/// Probes every routing case without retrying failures.
#[must_use]
pub fn probe_routes(cases: &[RouteCase]) -> Vec<RouteResult> {
    cases.iter().cloned().map(probe_route).collect()
}

fn probe_route(case: RouteCase) -> RouteResult {
    let started = Instant::now();
    let result = socks_http_body(&case);
    let (observed, detail) = match result {
        Ok(body) => (format!("sha256:{}", hash::sha256_hex(&body)), String::new()),
        // The legacy probe classified any socket/runtime failure as blocked.
        // Preserve that contract only for cases whose reviewed expectation is
        // blocked; an identical failure on an allowed case remains an error.
        Err(error) if error.blocked || matches!(case.expect, RouteExpectation::Blocked) => {
            ("blocked".to_owned(), error.detail)
        }
        Err(error) => ("error".to_owned(), error.detail),
    };
    let passed = match &case.expect {
        RouteExpectation::Blocked => observed == "blocked",
        RouteExpectation::Sha256(expected) => {
            observed == *expected || observed == format!("sha256:{expected}")
        }
    };
    RouteResult {
        case,
        observed,
        detail,
        seconds: started.elapsed().as_secs_f64(),
        passed,
    }
}

struct RouteError {
    blocked: bool,
    detail: String,
}

fn socks_http_body(case: &RouteCase) -> Result<Vec<u8>, RouteError> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from((Ipv4Addr::LOCALHOST, case.socks_port)),
        Duration::from_secs(30),
    )
    .map_err(route_blocked)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(route_error)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(route_error)?;
    stream.write_all(&[5, 1, 0]).map_err(route_error)?;
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).map_err(route_error)?;
    if greeting != [5, 0] {
        return Err(route_blocked("SOCKS greeting rejected"));
    }
    let mut connect = vec![5, 1, 0];
    if let Ok(address) = case.host.parse::<Ipv4Addr>() {
        connect.push(1);
        connect.extend_from_slice(&address.octets());
    } else {
        let host = case.host.as_bytes();
        let length = u8::try_from(host.len()).map_err(|_| route_error("domain too long"))?;
        connect.extend([3, length]);
        connect.extend_from_slice(host);
    }
    connect.extend_from_slice(&case.port.to_be_bytes());
    stream.write_all(&connect).map_err(route_error)?;
    let mut reply = [0_u8; 4];
    stream.read_exact(&mut reply).map_err(route_blocked)?;
    if reply[1] != 0 {
        return Err(route_blocked(format!(
            "SOCKS connect rejected ({})",
            reply[1]
        )));
    }
    let bound = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0_u8];
            stream.read_exact(&mut length).map_err(route_error)?;
            usize::from(length[0])
        }
        _ => return Err(route_error("SOCKS reply has unknown address type")),
    };
    let mut discard = vec![0_u8; bound + 2];
    stream.read_exact(&mut discard).map_err(route_error)?;
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        case.path, case.host, case.port
    );
    stream.write_all(request.as_bytes()).map_err(route_error)?;
    let mut response = Vec::new();
    stream
        .take(8 * 1024 * 1024)
        .read_to_end(&mut response)
        .map_err(route_error)?;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| route_error("HTTP response has no header terminator"))?;
    let (head, body) = response.split_at(split + 4);
    let status = std::str::from_utf8(head)
        .ok()
        .and_then(|text| text.lines().next())
        .and_then(|line| line.split_whitespace().nth(1));
    if status != Some("200") {
        return Err(route_error(format!("HTTP status {status:?}")));
    }
    Ok(body.to_vec())
}

fn route_blocked(error: impl std::fmt::Display) -> RouteError {
    RouteError {
        blocked: true,
        detail: bounded_detail(error),
    }
}

fn route_error(error: impl std::fmt::Display) -> RouteError {
    RouteError {
        blocked: false,
        detail: bounded_detail(error),
    }
}

fn bounded_detail(error: impl std::fmt::Display) -> String {
    error.to_string().chars().take(200).collect()
}

/// Routing correctness cardinality/verdict document.
#[must_use]
pub fn routing_summary(results: &[RouteResult]) -> Json {
    let passed = results.iter().filter(|result| result.passed).count();
    Json::object([
        ("cases", count(results.len())),
        ("passed", count(passed)),
        ("failed", count(results.len().saturating_sub(passed))),
        (
            "verdict",
            Json::string(if passed == results.len() {
                "PASS"
            } else {
                "FAIL"
            }),
        ),
    ])
}

/// One SOCKS-mediated throughput program.
#[derive(Debug, Clone)]
pub struct SocksThroughputPlan {
    /// Evidence label.
    pub label: String,
    /// Local Xray SOCKS listener.
    pub socks_port: u16,
    /// Exact payload URL.
    pub url: String,
    /// Payload MiB.
    pub payload_mib: u64,
    /// Samples for each concurrency.
    pub samples: usize,
    /// Concurrency levels.
    pub concurrencies: Vec<usize>,
    /// Exact payload SHA-256.
    pub expected_sha256: String,
    /// Ephemeral directory for the first-transfer integrity file.
    pub workspace: PathBuf,
}

/// One SOCKS throughput cell result.
#[derive(Debug, Clone)]
pub struct SocksThroughputRow {
    /// Evidence label.
    pub label: String,
    /// Concurrent transfers.
    pub concurrency: usize,
    /// Sample index.
    pub sample_index: usize,
    /// Wall-clock seconds.
    pub wall_seconds: f64,
    /// Per-request seconds.
    pub per_request_seconds: Vec<f64>,
    /// Aggregate MiB/s.
    pub throughput_mib_per_second: f64,
    /// Whether this row performed and passed exact integrity.
    pub integrity: Option<bool>,
}

impl SocksThroughputRow {
    /// Renders the deployment-driver row shape.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            ("label", Json::string(&self.label)),
            ("concurrency", count(self.concurrency)),
            ("sampleIndex", count(self.sample_index)),
            ("wallSeconds", Json::Float(self.wall_seconds)),
            ("transfers", count(self.per_request_seconds.len())),
            (
                "perRequestSeconds",
                Json::Array(
                    self.per_request_seconds
                        .iter()
                        .copied()
                        .map(Json::Float)
                        .collect(),
                ),
            ),
            (
                "throughputMiBPerSecond",
                Json::Float(self.throughput_mib_per_second),
            ),
            (
                "integrity",
                Json::string(match self.integrity {
                    Some(true) => "pass",
                    Some(false) => "fail",
                    None => "skip",
                }),
            ),
        ])
    }
}

/// Runs every SOCKS throughput cell and requires exact byte integrity.
///
/// # Errors
///
/// Returns the first failed transfer or integrity mismatch.
pub fn run_socks_throughput(plan: &SocksThroughputPlan) -> Result<Vec<SocksThroughputRow>, String> {
    if plan.samples == 0 || plan.concurrencies.is_empty() || plan.payload_mib == 0 {
        return Err("SOCKS throughput dimensions must be positive".to_owned());
    }
    let mut rows = Vec::with_capacity(plan.samples * plan.concurrencies.len());
    for concurrency in &plan.concurrencies {
        for sample_index in 0..plan.samples {
            rows.push(run_socks_throughput_sample(
                plan,
                *concurrency,
                sample_index,
            )?);
        }
    }
    Ok(rows)
}

fn run_socks_throughput_sample(
    plan: &SocksThroughputPlan,
    concurrency: usize,
    sample_index: usize,
) -> Result<SocksThroughputRow, String> {
    if concurrency == 0 {
        return Err("SOCKS throughput concurrency must be positive".to_owned());
    }
    let verify = plan.workspace.join(format!(
        ".verify-{}-c{concurrency}-s{sample_index}.bin",
        plan.label
    ));
    let next = AtomicUsize::new(0);
    let started = Instant::now();
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..concurrency)
            .map(|_| {
                let next = &next;
                let verify = &verify;
                scope.spawn(move || {
                    let mut mine = Vec::new();
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        if index >= concurrency {
                            break;
                        }
                        let output = (sample_index == 0 && index == 0).then_some(verify.as_path());
                        mine.push(curl_socks(plan, output));
                    }
                    mine
                })
            })
            .collect();
        let mut results = Vec::with_capacity(concurrency);
        for handle in handles {
            results.extend(handle.join().map_err(|_| "throughput worker panicked")?);
        }
        Ok::<_, &str>(results)
    })
    .map_err(str::to_owned)?;
    let per_request_seconds: Vec<f64> = results.into_iter().collect::<Result<_, _>>()?;
    let integrity = if sample_index == 0 {
        let observed = hash::sha256_file(&verify)?;
        let _ = std::fs::remove_file(&verify);
        if observed != plan.expected_sha256 {
            return Err(format!(
                "{} c{concurrency} integrity mismatch: expected {}, observed {observed}",
                plan.label, plan.expected_sha256
            ));
        }
        Some(true)
    } else {
        None
    };
    let wall_seconds = started.elapsed().as_secs_f64();
    #[expect(clippy::cast_precision_loss, reason = "bounded benchmark dimensions")]
    let throughput_mib_per_second = (plan.payload_mib as f64) * (concurrency as f64) / wall_seconds;
    Ok(SocksThroughputRow {
        label: plan.label.clone(),
        concurrency,
        sample_index,
        wall_seconds,
        per_request_seconds,
        throughput_mib_per_second,
        integrity,
    })
}

fn curl_socks(plan: &SocksThroughputPlan, output: Option<&Path>) -> Result<f64, String> {
    let expected_bytes = plan.payload_mib * 1024 * 1024;
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
    let outcome = curl
        .args([
            "--fail".to_owned(),
            "--silent".to_owned(),
            "--show-error".to_owned(),
            "--max-time".to_owned(),
            "300".to_owned(),
            "--socks5-hostname".to_owned(),
            format!("127.0.0.1:{}", plan.socks_port),
            "--output".to_owned(),
            output.map_or_else(|| "/dev/null".to_owned(), |path| path.display().to_string()),
            "--write-out".to_owned(),
            "%{size_download} %{time_total}".to_owned(),
            plan.url.clone(),
        ])
        .probe()
        .map_err(|error| format!("could not run throughput curl: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "throughput curl exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    let mut fields = outcome.trimmed_stdout().split_whitespace();
    let bytes = fields
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| "throughput curl returned no byte count".to_owned())?;
    let seconds = fields
        .next()
        .and_then(|value| value.parse::<f64>().ok())
        .ok_or_else(|| "throughput curl returned no duration".to_owned())?;
    if bytes != expected_bytes {
        return Err(format!(
            "throughput short read: {bytes} of {expected_bytes}"
        ));
    }
    Ok(seconds)
}

/// Aggregated long-flow relay log evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEvidence {
    /// Availability by backend name.
    pub backend_report: BTreeMap<String, bool>,
    /// Accepted connections.
    pub accepted: usize,
    /// Cleanly closed connections.
    pub closed: usize,
    /// Rejected connections.
    pub rejected: usize,
    /// Completion events.
    pub completed: usize,
    /// Backends named on completion events.
    pub completed_backends: BTreeSet<String>,
    /// Completion events missing backend attribution.
    pub missing_backend: usize,
}

impl RelayEvidence {
    /// Whether the legacy splice-evidence contract passes.
    #[must_use]
    pub fn passes(&self, expected: &str) -> bool {
        self.backend_report.get(expected) == Some(&true)
            && self.accepted >= 1
            && self.closed >= 1
            && self.rejected == 0
            && self.missing_backend == 0
            && (self.completed == 0
                || self.completed_backends == BTreeSet::from([expected.to_owned()]))
    }

    /// Renders the long-flow report, including the no-per-connection caveat.
    #[must_use]
    pub fn to_json(&self, log: &Path, expected: &str) -> Json {
        let emitted = self.completed > 0;
        Json::object([
            ("log", Json::string(log.display().to_string())),
            ("expectedBackend", Json::string(expected)),
            (
                "backendReport",
                Json::object(
                    self.backend_report
                        .iter()
                        .map(|(name, available)| (name.clone(), Json::Bool(*available))),
                ),
            ),
            (
                "expectedBackendAvailable",
                Json::Bool(self.backend_report.get(expected) == Some(&true)),
            ),
            ("connectionAccepted", count(self.accepted)),
            ("connectionClosed", count(self.closed)),
            ("connectionRejected", count(self.rejected)),
            ("connectionCompletedEvents", count(self.completed)),
            (
                "relayBackends",
                Json::Array(self.completed_backends.iter().map(Json::string).collect()),
            ),
            ("eventsMissingRelayBackend", count(self.missing_backend)),
            (
                "perConnectionBackendEvidence",
                Json::string(if emitted { "emitted" } else { "not-emitted" }),
            ),
            (
                "verdict",
                Json::string(if self.passes(expected) {
                    "PASS"
                } else {
                    "FAIL"
                }),
            ),
        ])
    }
}

/// Parses structured server logs into the long-flow relay contract.
#[must_use]
pub fn relay_evidence(log: &str) -> RelayEvidence {
    let mut evidence = RelayEvidence {
        backend_report: BTreeMap::new(),
        accepted: 0,
        closed: 0,
        rejected: 0,
        completed: 0,
        completed_backends: BTreeSet::new(),
        missing_backend: 0,
    };
    for value in log
        .lines()
        .filter_map(|line| json_in::parse(line.trim()).ok())
    {
        let event = value.optional("event").and_then(json_string);
        match event {
            Some("relay_backend_report") => {
                if let Some(json_in::Value::Array(backends)) = value.optional("backends") {
                    for backend in backends {
                        if let (Some(name), Some(available)) = (
                            backend.optional("backend").and_then(json_string),
                            backend.optional("available").and_then(json_bool),
                        ) {
                            evidence.backend_report.insert(name.to_owned(), available);
                        }
                    }
                }
            }
            Some("connection_accepted") => evidence.accepted += 1,
            Some("connection_closed") => evidence.closed += 1,
            Some("connection_rejected") => evidence.rejected += 1,
            Some("connection_completed") => {
                evidence.completed += 1;
                if let Some(backend) = value.optional("relay_backend").and_then(json_string) {
                    evidence.completed_backends.insert(backend.to_owned());
                } else {
                    evidence.missing_backend += 1;
                }
            }
            _ => {}
        }
    }
    evidence
}

pub(crate) fn json_string(value: &json_in::Value) -> Option<&str> {
    match value {
        json_in::Value::Str(value) => Some(value),
        _ => None,
    }
}

pub(crate) const fn json_bool(value: &json_in::Value) -> Option<bool> {
    match value {
        json_in::Value::Bool(value) => Some(*value),
        _ => None,
    }
}
