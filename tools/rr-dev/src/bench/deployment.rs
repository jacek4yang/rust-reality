//! Deployment-characterization plan and native suite orchestration.
//!
//! The legacy harness looked like one benchmark but carried five distinct
//! sections. Keeping their dimensions in a typed plan prevents an execution
//! refactor from silently narrowing the formal evidence: a full run still means
//! routing correctness, routing cost, four deployment topologies, the complete
//! one-leg netem matrix, and long-flow relay evidence.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read as _, Write as _},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use crate::{
    deploy::netem::LEGS,
    hash,
    perf::{json_in, json_out::Json},
    process::Tool,
};

/// One deployment-characterization section, in required execution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Section {
    /// Multi-user routing correctness.
    Routing,
    /// Routing decision setup cost.
    Cost,
    /// Direct, NXR, SOCKS5, and Xray deployment topologies.
    Nxr,
    /// Controlled one-leg RTT/loss matrix.
    Rtt,
    /// Large post-auth NXR relay and byte-integrity proof.
    Longflow,
}

impl Section {
    /// Stable evidence name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Routing => "routing",
            Self::Cost => "cost",
            Self::Nxr => "nxr",
            Self::Rtt => "rtt",
            Self::Longflow => "longflow",
        }
    }
}

/// Which reviewed deployment program a plan represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanKind {
    /// Every correctness, topology, netem, and relay section.
    Full,
    /// The concurrency-one, zero-loss controlled-RTT claim.
    Mechanism,
    /// The full RTT/loss/concurrency robustness matrix only.
    Robustness,
    /// Tiny non-formal local mechanism acceptance.
    Smoke,
}

impl PlanKind {
    /// Parses the CLI spelling.
    ///
    /// # Errors
    ///
    /// Returns the accepted names when the value is unknown.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "full" => Ok(Self::Full),
            "mechanism" => Ok(Self::Mechanism),
            "robustness" => Ok(Self::Robustness),
            "smoke" => Ok(Self::Smoke),
            _ => Err("deployment plan must be full, mechanism, robustness, or smoke".to_owned()),
        }
    }

    /// Stable evidence name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Mechanism => "mechanism",
            Self::Robustness => "robustness",
            Self::Smoke => "smoke",
        }
    }

    /// Whether this plan can make a formal release claim.
    #[must_use]
    pub const fn formal(self) -> bool {
        !matches!(self, Self::Smoke)
    }
}

/// One throughput cell: payload MiB and concurrent transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThroughputCell {
    /// Payload size in MiB.
    pub payload_mib: u64,
    /// Concurrent transfers.
    pub concurrency: usize,
}

/// The complete, admitted deployment-characterization dimensions.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    /// Reviewed program.
    pub kind: PlanKind,
    /// Sections in execution order.
    pub sections: Vec<Section>,
    /// Samples for non-netem setup cells.
    pub samples: usize,
    /// Connections in each non-netem setup sample.
    pub connections: usize,
    /// Non-netem setup concurrencies.
    pub concurrencies: Vec<usize>,
    /// Samples in each throughput cell.
    pub throughput_samples: usize,
    /// Required topology throughput cells.
    pub throughput_cells: Vec<ThroughputCell>,
    /// Long-flow payload MiB.
    pub longflow_mib: u64,
    /// Target round-trip delays in milliseconds.
    pub rtts_ms: Vec<u32>,
    /// Per-direction packet loss percentages.
    pub losses_percent: Vec<f64>,
    /// Connections in each controlled-netem setup sample.
    pub rtt_connections: usize,
    /// Controlled-netem setup concurrencies.
    pub rtt_concurrencies: Vec<usize>,
    /// Evaluate the controlled RTT performance claim.
    pub evaluate_netem_performance: bool,
}

impl Plan {
    /// Returns the reviewed dimensions for one program.
    #[must_use]
    pub fn reviewed(kind: PlanKind) -> Self {
        match kind {
            PlanKind::Full => Self {
                kind,
                sections: all_sections(),
                samples: 3,
                connections: 96,
                concurrencies: vec![8, 32],
                throughput_samples: 3,
                throughput_cells: formal_throughput(),
                longflow_mib: 512,
                rtts_ms: vec![1, 10, 50, 100, 200],
                losses_percent: vec![0.0, 0.1, 1.0],
                rtt_connections: 512,
                rtt_concurrencies: vec![1, 8, 32, 128, 512],
                evaluate_netem_performance: true,
            },
            PlanKind::Mechanism => Self {
                kind,
                sections: vec![Section::Rtt],
                samples: 3,
                connections: 96,
                concurrencies: vec![8, 32],
                throughput_samples: 3,
                throughput_cells: formal_throughput(),
                longflow_mib: 512,
                rtts_ms: vec![50, 100, 200],
                losses_percent: vec![0.0],
                rtt_connections: 32,
                rtt_concurrencies: vec![1],
                evaluate_netem_performance: true,
            },
            PlanKind::Robustness => Self {
                kind,
                sections: vec![Section::Rtt],
                samples: 3,
                connections: 96,
                concurrencies: vec![8, 32],
                throughput_samples: 3,
                throughput_cells: formal_throughput(),
                longflow_mib: 512,
                rtts_ms: vec![1, 10, 50, 100, 200],
                losses_percent: vec![0.0, 0.1, 1.0],
                rtt_connections: 512,
                rtt_concurrencies: vec![1, 8, 32, 128, 512],
                evaluate_netem_performance: true,
            },
            PlanKind::Smoke => Self {
                kind,
                sections: vec![Section::Routing, Section::Cost, Section::Nxr, Section::Longflow],
                samples: 1,
                connections: 2,
                concurrencies: vec![2],
                throughput_samples: 1,
                throughput_cells: vec![ThroughputCell {
                    payload_mib: 1,
                    concurrency: 2,
                }],
                longflow_mib: 1,
                rtts_ms: vec![20],
                losses_percent: vec![0.0],
                rtt_connections: 2,
                rtt_concurrencies: vec![1],
                evaluate_netem_performance: false,
            },
        }
    }

    /// Validates the full dimensional contract.
    ///
    /// # Errors
    ///
    /// Returns every detected narrowing or malformed dimension.
    pub fn validate(&self) -> Result<(), String> {
        let expected = Self::reviewed(self.kind);
        if self != &expected {
            return Err(format!(
                "deployment {} dimensions differ from the reviewed plan",
                self.kind.name()
            ));
        }
        let unique: BTreeSet<Section> = self.sections.iter().copied().collect();
        if unique.len() != self.sections.len() {
            return Err("deployment sections contain a duplicate".to_owned());
        }
        Ok(())
    }

    /// Every `(RTT, loss)` profile name in stable order.
    #[must_use]
    pub fn profile_names(&self) -> Vec<String> {
        self.rtts_ms
            .iter()
            .flat_map(|rtt| {
                self.losses_percent.iter().map(move |loss| {
                    format!(
                        "rtt{rtt}-loss{}",
                        loss_token(*loss)
                    )
                })
            })
            .collect()
    }

    /// Every setup evidence label the plan requires.
    #[must_use]
    pub fn setup_labels(&self) -> BTreeSet<String> {
        let mut labels = BTreeSet::new();
        if self.sections.contains(&Section::Cost) {
            labels.extend(
                [
                    "cost-simple",
                    "cost-medium",
                    "cost-complex",
                    "cost-complex-ipifnonmatch",
                    "cost-complex-ipondemand",
                ]
                .into_iter()
                .map(str::to_owned),
            );
        }
        if self.sections.contains(&Section::Nxr) {
            labels.extend(['a', 'b', 'c', 'd'].map(|name| format!("topo-{name}")));
        }
        if self.sections.contains(&Section::Rtt) {
            for profile in self.profile_names() {
                labels.extend(LEGS.map(|leg| format!("{profile}-{leg}")));
            }
        }
        labels
    }

    /// Renders the admitted plan as durable evidence.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            ("schemaVersion", Json::Int(1)),
            ("kind", Json::string(self.kind.name())),
            ("formal", Json::Bool(self.kind.formal())),
            (
                "sections",
                Json::Array(self.sections.iter().map(|section| Json::string(section.name())).collect()),
            ),
            ("samples", count(self.samples)),
            ("connectionsPerSample", count(self.connections)),
            ("concurrencies", counts(&self.concurrencies)),
            ("throughputSamples", count(self.throughput_samples)),
            (
                "throughputCells",
                Json::Array(
                    self.throughput_cells
                        .iter()
                        .map(|cell| {
                            Json::object([
                                ("payloadMiB", count(cell.payload_mib)),
                                ("concurrency", count(cell.concurrency)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("longflowMiB", count(self.longflow_mib)),
            (
                "rttsMs",
                Json::Array(self.rtts_ms.iter().map(|value| count(*value)).collect()),
            ),
            (
                "perDirectionLossPercent",
                Json::Array(self.losses_percent.iter().map(|value| Json::Float(*value)).collect()),
            ),
            ("rttConnectionsPerSample", count(self.rtt_connections)),
            ("rttConcurrencies", counts(&self.rtt_concurrencies)),
            (
                "evaluateNetemPerformance",
                Json::Bool(self.evaluate_netem_performance),
            ),
        ])
    }
}

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
        Err(error) if error.blocked => ("blocked".to_owned(), error.detail),
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
        return Err(route_blocked(format!("SOCKS connect rejected ({})", reply[1])));
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
            Json::string(if passed == results.len() { "PASS" } else { "FAIL" }),
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
pub fn run_socks_throughput(
    plan: &SocksThroughputPlan,
) -> Result<Vec<SocksThroughputRow>, String> {
    if plan.samples == 0 || plan.concurrencies.is_empty() || plan.payload_mib == 0 {
        return Err("SOCKS throughput dimensions must be positive".to_owned());
    }
    let mut rows = Vec::with_capacity(plan.samples * plan.concurrencies.len());
    for concurrency in &plan.concurrencies {
        for sample_index in 0..plan.samples {
            rows.push(run_socks_throughput_sample(plan, *concurrency, sample_index)?);
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
    let throughput_mib_per_second =
        (plan.payload_mib as f64) * (concurrency as f64) / wall_seconds;
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
        "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
        "NO_PROXY", "no_proxy",
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
        return Err(format!("throughput short read: {bytes} of {expected_bytes}"));
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
                Json::Array(
                    self.completed_backends
                        .iter()
                        .map(Json::string)
                        .collect(),
                ),
            ),
            ("eventsMissingRelayBackend", count(self.missing_backend)),
            (
                "perConnectionBackendEvidence",
                Json::string(if emitted { "emitted" } else { "not-emitted" }),
            ),
            (
                "verdict",
                Json::string(if self.passes(expected) { "PASS" } else { "FAIL" }),
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
    for value in log.lines().filter_map(|line| json_in::parse(line.trim()).ok()) {
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

fn json_string(value: &json_in::Value) -> Option<&str> {
    match value {
        json_in::Value::Str(value) => Some(value),
        _ => None,
    }
}

const fn json_bool(value: &json_in::Value) -> Option<bool> {
    match value {
        json_in::Value::Bool(value) => Some(*value),
        _ => None,
    }
}

fn all_sections() -> Vec<Section> {
    vec![Section::Routing, Section::Cost, Section::Nxr, Section::Rtt, Section::Longflow]
}

fn formal_throughput() -> Vec<ThroughputCell> {
    vec![
        ThroughputCell {
            payload_mib: 32,
            concurrency: 1,
        },
        ThroughputCell {
            payload_mib: 32,
            concurrency: 32,
        },
        ThroughputCell {
            payload_mib: 512,
            concurrency: 32,
        },
    ]
}

fn loss_token(loss: f64) -> String {
    if loss.fract() == 0.0 {
        format!("{loss:.0}")
    } else {
        loss.to_string().replace('.', "p")
    }
}

fn count(value: impl TryInto<i64>) -> Json {
    Json::Int(value.try_into().unwrap_or(i64::MAX))
}

fn counts(values: &[usize]) -> Json {
    Json::Array(values.iter().map(|value| count(*value)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_full_plan_cannot_narrow_the_legacy_matrix() {
        let plan = Plan::reviewed(PlanKind::Full);
        plan.validate().unwrap();
        assert_eq!(plan.sections, all_sections());
        assert_eq!(plan.profile_names().len(), 15);
        assert_eq!(plan.setup_labels().len(), 99);
        assert_eq!(plan.throughput_cells, formal_throughput());
        assert_eq!(plan.rtt_concurrencies, [1, 8, 32, 128, 512]);
    }

    #[test]
    fn focused_formal_programs_retain_their_exact_dimensions() {
        let mechanism = Plan::reviewed(PlanKind::Mechanism);
        assert_eq!(mechanism.sections, [Section::Rtt]);
        assert_eq!(mechanism.profile_names().len(), 3);
        assert_eq!(mechanism.setup_labels().len(), 18);
        assert_eq!(mechanism.rtt_concurrencies, [1]);

        let robustness = Plan::reviewed(PlanKind::Robustness);
        assert_eq!(robustness.sections, [Section::Rtt]);
        assert_eq!(robustness.profile_names().len(), 15);
        assert_eq!(robustness.setup_labels().len(), 90);
    }

    #[test]
    fn smoke_is_small_and_explicitly_non_formal() {
        let smoke = Plan::reviewed(PlanKind::Smoke);
        assert!(!smoke.kind.formal());
        assert!(!smoke.sections.contains(&Section::Rtt));
        assert_eq!(smoke.samples, 1);
        assert_eq!(smoke.connections, 2);
        assert_eq!(smoke.longflow_mib, 1);
        assert!(smoke.to_json().to_python_json().contains("\"formal\": false"));
    }

    #[test]
    fn a_mutated_reviewed_plan_is_rejected() {
        let mut plan = Plan::reviewed(PlanKind::Full);
        plan.rtts_ms.pop();
        assert!(plan.validate().unwrap_err().contains("differ"));
    }

    #[test]
    fn route_summary_requires_every_case() {
        let case = RouteCase {
            uuid: "u".to_owned(),
            group: "alpha".to_owned(),
            label: "block".to_owned(),
            socks_port: 1,
            host: "blocked.example".to_owned(),
            port: 80,
            path: "/payload-1.bin".to_owned(),
            expect: RouteExpectation::Blocked,
        };
        let results = vec![RouteResult {
            case,
            observed: "blocked".to_owned(),
            detail: String::new(),
            seconds: 0.1,
            passed: true,
        }];
        assert!(routing_summary(&results).to_python_json().contains("\"verdict\": \"PASS\""));
    }

    #[test]
    fn relay_evidence_preserves_the_no_completion_caveat() {
        let log = r#"
{"event":"relay_backend_report","backends":[{"backend":"splice","available":true}]}
{"event":"connection_accepted"}
{"event":"connection_closed"}
"#;
        let evidence = relay_evidence(log);
        assert!(evidence.passes("splice"));
        let rendered = evidence.to_json(Path::new("landing.log"), "splice").to_python_json();
        assert!(rendered.contains("\"perConnectionBackendEvidence\": \"not-emitted\""));
    }

    #[test]
    fn relay_evidence_rejects_missing_or_wrong_completion_backends() {
        let missing = relay_evidence(
            r#"{"event":"relay_backend_report","backends":[{"backend":"splice","available":true}]}
{"event":"connection_accepted"}
{"event":"connection_closed"}
{"event":"connection_completed"}"#,
        );
        assert!(!missing.passes("splice"));
        let wrong = relay_evidence(
            r#"{"event":"relay_backend_report","backends":[{"backend":"splice","available":true}]}
{"event":"connection_accepted"}
{"event":"connection_closed"}
{"event":"connection_completed","relay_backend":"copy"}"#,
        );
        assert!(!wrong.passes("splice"));
    }
}
