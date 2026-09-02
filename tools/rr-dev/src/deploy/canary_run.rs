//! Typed plan and evidence model for the active dual-VPS release canary.
//!
//! Live traffic is a mechanism; the release decision is recorded policy. This
//! module owns the deterministic phase schedule, exact candidate/comparator
//! identities, resource samples, journal aggregation, and report serialization.
//! The resulting report is always re-admitted through [`super::canary`].

use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{
    bench::process::Child,
    deploy::{
        executor::{self, SystemCandidateValidator},
        host::{Host, HostRole, Topology},
        plan,
        remote::{SystemTransport, Transport, checked},
        snapshot::{HostSnapshot, inspect},
    },
    hash,
    perf::{
        json_in::{self, Value},
        json_out::Json,
    },
    process::Tool,
};

/// Identity of the rust-reality candidate running on both remote hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Full source commit.
    pub commit: String,
    /// Exact binary SHA-256.
    pub sha256: String,
    /// ELF build id.
    pub build_id: String,
    /// Product version.
    pub version: String,
    /// Rust target triple.
    pub target: String,
    /// Rust compiler identity.
    pub rustc: String,
}

impl Candidate {
    /// Validates shape-only identity contracts.
    ///
    /// # Errors
    ///
    /// Returns every malformed identity field in one diagnostic.
    pub fn validate(&self) -> Result<(), String> {
        let mut errors = Vec::new();
        if !lower_hex(&self.commit, 40) {
            errors.push("candidate commit must be 40 lowercase hex characters");
        }
        if !lower_hex(&self.sha256, 64) {
            errors.push("candidate sha256 must be 64 lowercase hex characters");
        }
        if self.build_id.is_empty()
            || self
                .build_id
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            errors.push("candidate build id must be non-empty lowercase hex");
        }
        for (label, value) in [
            ("version", self.version.as_str()),
            ("target", self.target.as_str()),
            ("rustc", self.rustc.as_str()),
        ] {
            if value.trim().is_empty() {
                errors.push(match label {
                    "version" => "candidate version must be non-empty",
                    "target" => "candidate target must be non-empty",
                    _ => "candidate rustc must be non-empty",
                });
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    fn to_json(&self) -> Json {
        Json::object([
            ("commit", Json::string(self.commit.clone())),
            ("sha256", Json::string(self.sha256.clone())),
            ("buildId", Json::string(self.build_id.clone())),
            ("version", Json::string(self.version.clone())),
            ("target", Json::string(self.target.clone())),
            ("rustc", Json::string(self.rustc.clone())),
        ])
    }
}

/// Exact stock-Xray comparator identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparator {
    /// Comparator name (`Xray`).
    pub name: String,
    /// Xray version.
    pub version: String,
    /// Exact binary SHA-256.
    pub sha256: String,
    /// ELF build id.
    pub build_id: String,
}

impl Comparator {
    fn to_json(&self) -> Json {
        Json::object([
            ("name", Json::string(self.name.clone())),
            ("version", Json::string(self.version.clone())),
            ("sha256", Json::string(self.sha256.clone())),
            ("buildId", Json::string(self.build_id.clone())),
        ])
    }
}

/// Inputs whose shapes define one active canary.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Exact candidate identity expected on LINE and LANDING.
    pub candidate: Candidate,
    /// Stock Xray binary on the controller.
    pub xray_bin: PathBuf,
    /// Required Xray binary SHA-256.
    pub xray_sha256: String,
    /// Xray config with a loopback SOCKS listener.
    pub xray_config: PathBuf,
    /// Loopback SOCKS port in that config.
    pub socks_port: u16,
    /// LINE's public IPv4, used to validate LANDING firewall ownership.
    pub line_public_ipv4: Ipv4Addr,
    /// Small request URL for active connection traffic.
    pub small_url: String,
    /// Exact one-MiB download URL.
    pub one_mib_url: String,
    /// Exact large download URL.
    pub large_url: String,
    /// Upload endpoint.
    pub upload_url: String,
    /// Local exact one-MiB reference payload.
    pub payload_one_mib: PathBuf,
    /// Local exact large reference payload.
    pub payload_large: PathBuf,
    /// New durable evidence directory.
    pub out_dir: PathBuf,
    /// Total active canary duration.
    pub duration_seconds: u64,
    /// Remote resource sampling interval.
    pub sample_interval_seconds: u64,
    /// Restore PREVIOUS on both hosts after any failure.
    pub rollback_on_failure: bool,
}

impl Plan {
    /// Validates all non-live input contracts.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed diagnostic before any host is contacted.
    pub fn validate(&self) -> Result<(), String> {
        self.candidate.validate()?;
        if !lower_hex(&self.xray_sha256, 64) {
            return Err("Xray SHA-256 must be 64 lowercase hex characters".to_owned());
        }
        if !(480..=900).contains(&self.duration_seconds) {
            return Err("canary duration must be in 480..=900 seconds".to_owned());
        }
        if !(1..=30).contains(&self.sample_interval_seconds) {
            return Err("sample interval must be in 1..=30 seconds".to_owned());
        }
        if self.socks_port < 1024 {
            return Err("SOCKS port must be in 1024..=65535".to_owned());
        }
        for (label, path) in [
            ("Xray binary", self.xray_bin.as_path()),
            ("Xray config", self.xray_config.as_path()),
            ("one-MiB payload", self.payload_one_mib.as_path()),
            ("large payload", self.payload_large.as_path()),
        ] {
            if !path.is_file() {
                return Err(format!("{label} is not a file: {}", path.display()));
            }
        }
        let observed_xray = hash::sha256_file(&self.xray_bin)?;
        if observed_xray != self.xray_sha256 {
            return Err(format!(
                "Xray SHA-256 mismatch: expected {}, observed {observed_xray}",
                self.xray_sha256
            ));
        }
        let config_text = std::fs::read_to_string(&self.xray_config)
            .map_err(|error| format!("read Xray config {}: {error}", self.xray_config.display()))?;
        let config = json_in::parse(&config_text)
            .map_err(|error| format!("Xray config is not JSON: {error}"))?;
        let inbounds = config
            .array_field("xray", "inbounds")
            .map_err(|error| error.to_string())?;
        let has_loopback_socks = inbounds.iter().any(|inbound| {
            inbound.optional("protocol").and_then(string) == Some("socks")
                && inbound.optional("listen").and_then(string) == Some("127.0.0.1")
                && inbound
                    .optional("port")
                    .and_then(|value| value.as_int("xray.inbounds[].port").ok())
                    == Some(i64::from(self.socks_port))
        });
        if !has_loopback_socks {
            return Err(format!(
                "Xray config has no 127.0.0.1:{} SOCKS inbound",
                self.socks_port
            ));
        }
        if self.out_dir.exists() || self.out_dir.is_symlink() {
            return Err(format!(
                "canary output must not exist: {}",
                self.out_dir.display()
            ));
        }
        for (label, url) in [
            ("small", self.small_url.as_str()),
            ("one-MiB", self.one_mib_url.as_str()),
            ("large", self.large_url.as_str()),
            ("upload", self.upload_url.as_str()),
        ] {
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(format!("{label} URL must use http:// or https://"));
            }
        }
        Ok(())
    }

    /// Deterministic phase schedule scaled from the reviewed ten-minute plan.
    #[must_use]
    pub fn schedule(&self) -> Schedule {
        Schedule::for_duration(self.duration_seconds)
    }

    /// Renders the fully validated, non-mutating canary plan.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            ("schemaVersion", Json::Int(1)),
            ("candidate", self.candidate.to_json()),
            (
                "xrayBinary",
                Json::string(self.xray_bin.display().to_string()),
            ),
            ("xraySha256", Json::string(self.xray_sha256.clone())),
            (
                "xrayConfig",
                Json::string(self.xray_config.display().to_string()),
            ),
            ("socksPort", Json::Int(i64::from(self.socks_port))),
            (
                "linePublicIpv4",
                Json::string(self.line_public_ipv4.to_string()),
            ),
            ("smallUrl", Json::string(self.small_url.clone())),
            ("oneMibUrl", Json::string(self.one_mib_url.clone())),
            ("largeUrl", Json::string(self.large_url.clone())),
            ("uploadUrl", Json::string(self.upload_url.clone())),
            (
                "payloadOneMib",
                Json::string(self.payload_one_mib.display().to_string()),
            ),
            (
                "payloadLarge",
                Json::string(self.payload_large.display().to_string()),
            ),
            (
                "evidenceDirectory",
                Json::string(self.out_dir.display().to_string()),
            ),
            (
                "sampleIntervalSeconds",
                Json::Int(i64::try_from(self.sample_interval_seconds).unwrap_or(i64::MAX)),
            ),
            ("schedule", self.schedule().to_json()),
            ("rollbackOnFailure", Json::Bool(self.rollback_on_failure)),
        ])
    }
}

/// One bounded traffic/quiet phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phase {
    /// Stable phase name.
    pub name: &'static str,
    /// Inclusive offset from canary start.
    pub start_second: u64,
    /// Exclusive offset from canary start.
    pub end_second: u64,
    /// Parallel request workers; zero is a quiet phase.
    pub concurrency: usize,
    /// Requests launched by one worker batch.
    pub batch: usize,
}

/// The reviewed active-canary timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schedule {
    /// Total duration.
    pub duration_seconds: u64,
    /// Ordered, gap-free phases.
    pub phases: Vec<Phase>,
    /// Offset of the LINE reload.
    pub line_reload_second: u64,
    /// Offset of the LANDING restart.
    pub landing_restart_second: u64,
    /// Offset after which exact integrity traffic runs.
    pub integrity_second: u64,
    /// Offset of the final LINE reload/resource recovery tail.
    pub final_reload_second: u64,
}

impl Schedule {
    fn for_duration(duration: u64) -> Self {
        let scaled = |second: u64| duration.saturating_mul(second) / 600;
        let points = [
            0,
            scaled(45),
            scaled(135),
            scaled(210),
            scaled(270),
            scaled(330),
            scaled(390),
            scaled(450),
            scaled(540),
            duration.saturating_sub(30),
            duration,
        ];
        let specifications = [
            ("warmup", 4, 16),
            ("steady-handoff", 8, 32),
            ("connection-churn", 32, 96),
            ("bounded-burst", 32, 96),
            ("quiet-retirement", 0, 0),
            ("post-line-reload", 8, 32),
            ("post-landing-restart", 16, 64),
            ("integrity-recovery", 16, 64),
            ("final-steady", 8, 32),
            ("quiet-resource-recovery", 0, 0),
        ];
        let phases = specifications
            .into_iter()
            .enumerate()
            .map(|(index, (name, concurrency, batch))| Phase {
                name,
                start_second: points[index],
                end_second: points[index + 1],
                concurrency,
                batch,
            })
            .collect();
        Self {
            duration_seconds: duration,
            phases,
            line_reload_second: scaled(330),
            landing_restart_second: scaled(390),
            integrity_second: scaled(450),
            final_reload_second: duration,
        }
    }

    /// Renders the non-mutating schedule evidence.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            (
                "durationSeconds",
                Json::Int(i64::try_from(self.duration_seconds).unwrap_or(i64::MAX)),
            ),
            (
                "phases",
                Json::Array(
                    self.phases
                        .iter()
                        .map(|phase| {
                            Json::object([
                                ("name", Json::string(phase.name)),
                                (
                                    "startSecond",
                                    Json::Int(
                                        i64::try_from(phase.start_second).unwrap_or(i64::MAX),
                                    ),
                                ),
                                (
                                    "endSecond",
                                    Json::Int(i64::try_from(phase.end_second).unwrap_or(i64::MAX)),
                                ),
                                (
                                    "concurrency",
                                    Json::Int(i64::try_from(phase.concurrency).unwrap_or(i64::MAX)),
                                ),
                                (
                                    "batch",
                                    Json::Int(i64::try_from(phase.batch).unwrap_or(i64::MAX)),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "lineReloadSecond",
                Json::Int(i64::try_from(self.line_reload_second).unwrap_or(i64::MAX)),
            ),
            (
                "landingRestartSecond",
                Json::Int(i64::try_from(self.landing_restart_second).unwrap_or(i64::MAX)),
            ),
            (
                "integritySecond",
                Json::Int(i64::try_from(self.integrity_second).unwrap_or(i64::MAX)),
            ),
            (
                "finalReloadSecond",
                Json::Int(i64::try_from(self.final_reload_second).unwrap_or(i64::MAX)),
            ),
        ])
    }
}

/// One remote process resource observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceSample {
    /// Milliseconds since the canary started.
    pub elapsed_millis: u64,
    /// Main process id (zero while absent).
    pub pid: u32,
    /// Resident memory in KiB.
    pub rss_kib: i64,
    /// Proportional set size in KiB, when available.
    pub pss_kib: Option<i64>,
    /// Open descriptor count.
    pub fd: i64,
    /// Thread count.
    pub threads: i64,
}

impl ResourceSample {
    fn to_json(&self) -> Json {
        Json::object([
            (
                "elapsedMillis",
                Json::Int(i64::try_from(self.elapsed_millis).unwrap_or(i64::MAX)),
            ),
            ("pid", Json::Int(i64::from(self.pid))),
            ("rssKiB", Json::Int(self.rss_kib)),
            ("pssKiB", self.pss_kib.map_or(Json::Null, Json::Int)),
            ("fd", Json::Int(self.fd)),
            ("threads", Json::Int(self.threads)),
        ])
    }
}

/// Aggregated Handoff-pool and LANDING rejection evidence from journals.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JournalEvidence {
    /// Handoff pool checkout hits.
    pub checkout_hit: i64,
    /// Handoff pool checkout misses.
    pub checkout_miss: i64,
    /// Cold fallback count.
    pub cold_fallback: i64,
    /// Peak ready target count.
    pub target_ready_peak: i64,
    /// Peak connecting count.
    pub connecting_peak: i64,
    /// Total LANDING connection rejections.
    pub landing_rejections: i64,
    /// Authentication or protocol LANDING rejections.
    pub authentication_rejections: i64,
    /// Number of Handoff pool summary events.
    pub pool_summary_events: usize,
}

/// Aggregates JSON journal lines; unrelated/non-JSON lines are inert.
#[must_use]
pub fn aggregate_journals(line_journal: &str, landing_journal: &str) -> JournalEvidence {
    let mut evidence = JournalEvidence::default();
    for value in json_records(line_journal) {
        if value.optional("event").and_then(string) == Some("transport_pool_summary")
            && value.optional("transport").and_then(string) == Some("handoff")
        {
            evidence.pool_summary_events += 1;
            evidence.checkout_hit += integer_field(&value, "pool_checkout_hit");
            evidence.checkout_miss += integer_field(&value, "pool_checkout_miss");
            evidence.cold_fallback += integer_field(&value, "pool_cold_fallback");
            evidence.target_ready_peak = evidence
                .target_ready_peak
                .max(integer_field(&value, "pool_target_ready"));
            evidence.connecting_peak = evidence
                .connecting_peak
                .max(integer_field(&value, "pool_connecting"));
        }
    }
    for value in json_records(landing_journal) {
        if value.optional("event").and_then(string) == Some("connection_rejected") {
            evidence.landing_rejections += 1;
            if matches!(
                value.optional("reason").and_then(string),
                Some("authentication" | "protocol")
            ) {
                evidence.authentication_rejections += 1;
            }
        }
    }
    evidence
}

fn json_records(text: &str) -> impl Iterator<Item = Value> + '_ {
    text.lines().filter_map(|line| {
        let line = line.trim();
        line.starts_with('{')
            .then(|| json_in::parse(line).ok())
            .flatten()
    })
}

fn string(value: &Value) -> Option<&str> {
    match value {
        Value::Str(text) => Some(text),
        _ => None,
    }
}

fn integer_field(value: &Value, key: &str) -> i64 {
    value
        .optional(key)
        .and_then(|value| value.as_int(key).ok())
        .unwrap_or(0)
}

/// Complete canary input report consumed by the evaluator.
#[derive(Debug, Clone)]
pub struct Report {
    /// Candidate identity.
    pub candidate: Candidate,
    /// Comparator identity.
    pub comparator: Comparator,
    /// Active duration.
    pub elapsed_seconds: i64,
    /// Exact required-check values.
    pub checks: BTreeMap<String, bool>,
    /// Attempted active requests.
    pub connections_attempted: i64,
    /// Successful active requests.
    pub connections_successful: i64,
    /// Journal evidence.
    pub journals: JournalEvidence,
    /// LINE resource samples.
    pub line_resources: Vec<ResourceSample>,
    /// LANDING resource samples.
    pub landing_resources: Vec<ResourceSample>,
}

impl Report {
    /// Builds all required check keys at once.
    #[must_use]
    pub fn checks(default: bool) -> BTreeMap<String, bool> {
        super::canary::REQUIRED_CHECKS
            .iter()
            .map(|name| ((*name).to_owned(), default))
            .collect()
    }

    /// Renders the evaluator input JSON.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            ("schemaVersion", Json::Int(1)),
            ("candidate", self.candidate.to_json()),
            ("comparator", self.comparator.to_json()),
            ("elapsedSeconds", Json::Int(self.elapsed_seconds)),
            (
                "checks",
                Json::object(
                    self.checks
                        .iter()
                        .map(|(name, value)| (name.clone(), Json::Bool(*value))),
                ),
            ),
            (
                "traffic",
                Json::object([
                    (
                        "connectionsAttempted",
                        Json::Int(self.connections_attempted),
                    ),
                    (
                        "connectionsSuccessful",
                        Json::Int(self.connections_successful),
                    ),
                ]),
            ),
            (
                "handoffPool",
                Json::object([
                    ("checkoutHit", Json::Int(self.journals.checkout_hit)),
                    ("checkoutMiss", Json::Int(self.journals.checkout_miss)),
                    ("coldFallback", Json::Int(self.journals.cold_fallback)),
                    (
                        "targetReadyPeak",
                        Json::Int(self.journals.target_ready_peak),
                    ),
                    ("maxReady", Json::Int(256)),
                    ("connectingPeak", Json::Int(self.journals.connecting_peak)),
                    ("maxConnecting", Json::Int(64)),
                ]),
            ),
            (
                "landingRejections",
                Json::object([
                    ("count", Json::Int(self.journals.landing_rejections)),
                    (
                        "authenticationOrProtocol",
                        Json::Int(self.journals.authentication_rejections),
                    ),
                ]),
            ),
            (
                "resources",
                Json::object([
                    (
                        "line",
                        Json::Array(
                            self.line_resources
                                .iter()
                                .map(ResourceSample::to_json)
                                .collect(),
                        ),
                    ),
                    (
                        "landing",
                        Json::Array(
                            self.landing_resources
                                .iter()
                                .map(ResourceSample::to_json)
                                .collect(),
                        ),
                    ),
                ]),
            ),
        ])
    }
}

/// Result of one complete native active canary.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    /// Fail-closed evaluator verdict.
    pub verdict: String,
    /// Whether the evaluator accepted every canary invariant.
    pub ok: bool,
}

/// Runs the active canary through the fixed topology.
///
/// This function performs live remote reload/restart operations. Callers must
/// enforce the explicit mutation authorization boundary before invoking it.
///
/// # Errors
///
/// Returns preflight, traffic, integrity, sampling, journal, or rollback errors.
/// A report that is structurally valid but fails policy returns `Ok` with
/// [`RunOutcome::ok`] false after the requested rollback is attempted.
#[allow(clippy::too_many_lines)]
pub fn run(plan: &Plan, topology: &Topology) -> Result<RunOutcome, String> {
    let result = run_inner(plan, topology);
    let failed = result.as_ref().map_or(true, |outcome| !outcome.ok);
    if failed && plan.rollback_on_failure {
        let rollback = rollback_hosts(topology);
        if let Err(rollback_error) = rollback {
            return Err(match result {
                Ok(_) => format!("canary failed; rollback failed: {rollback_error}"),
                Err(error) => format!("canary failed ({error}); rollback failed: {rollback_error}"),
            });
        }
    }
    result
}

#[allow(clippy::too_many_lines)]
fn run_inner(plan: &Plan, topology: &Topology) -> Result<RunOutcome, String> {
    plan.validate()?;
    if let Some(parent) = plan.out_dir.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create canary parent {}: {error}", parent.display()))?;
    }
    std::fs::create_dir(&plan.out_dir).map_err(|error| {
        format!(
            "create canary evidence directory {}: {error}",
            plan.out_dir.display()
        )
    })?;
    std::fs::write(
        plan.out_dir.join("plan.json"),
        plan.to_json().to_python_json(),
    )
    .map_err(|error| format!("write canary plan: {error}"))?;

    let line = topology.host(HostRole::Line);
    let landing = topology.host(HostRole::Landing);
    let mut transport = SystemTransport;
    let line_before = inspect(&mut transport, line)?;
    let landing_before = inspect(&mut transport, landing)?;
    verify_candidate(&line_before, &plan.candidate)?;
    verify_candidate(&landing_before, &plan.candidate)?;
    if !line_before.unexpected_public_ports().is_empty()
        || !landing_before.unexpected_public_ports().is_empty()
    {
        return Err("LINE or LANDING exposes an unexpected wildcard listener".to_owned());
    }
    let firewall = checked(
        &mut transport,
        landing,
        true,
        &["iptables-save".to_owned()],
        "inspect LANDING firewall",
    )?;
    if !firewall_line_only(&firewall, plan.line_public_ipv4) {
        return Err("LANDING firewall does not allow exactly LINE-origin TCP/443".to_owned());
    }
    let comparator = comparator_identity(plan)?;

    let mut xray = Child::spawn_isolated(
        "deployment-canary-xray",
        &plan.xray_bin,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            plan.xray_config.display().to_string(),
        ],
        &plan.out_dir,
        &[],
        &plan.out_dir.join("xray.log"),
    )
    .map_err(|error| error.to_string())?;
    xray.wait_for_port(plan.socks_port, Duration::from_secs(10))
        .map_err(|error| error.to_string())?;

    let schedule = plan.schedule();
    let started = Instant::now();
    let started_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock before Unix epoch: {error}"))?
        .as_secs();
    let attempted = AtomicI64::new(0);
    let successful = AtomicI64::new(0);
    let sampler = ResourceSampler::start(
        line.clone(),
        landing.clone(),
        started,
        Duration::from_secs(plan.sample_interval_seconds),
    );
    let mut line_reload = false;
    let mut landing_restart = false;
    let mut restart_recovery = false;
    let mut integrity = IntegrityStatus::Pending;

    for phase in &schedule.phases {
        match phase.name {
            "post-line-reload" => {
                remote_unit(&mut transport, line, "reload")?;
                line_reload = true;
            }
            "post-landing-restart" => {
                remote_unit(&mut transport, landing, "restart")?;
                landing_restart = true;
                restart_recovery = wait_candidate(&mut transport, landing, &plan.candidate)?;
            }
            "integrity-recovery" => {
                run_integrity(plan, &mut transport, landing)?;
                integrity = IntegrityStatus::Passed;
            }
            _ => {}
        }
        let phase_deadline = Duration::from_secs(phase.end_second);
        while started.elapsed() < phase_deadline {
            if phase.concurrency > 0 {
                run_request_batch(
                    plan,
                    phase.batch,
                    phase.concurrency,
                    &attempted,
                    &successful,
                );
            } else {
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
    remote_unit(&mut transport, line, "reload")?;
    std::thread::sleep(Duration::from_secs(2));
    let (line_resources, landing_resources) = sampler.finish()?;
    xray.terminate();

    let line_after = inspect(&mut transport, line)?;
    let landing_after = inspect(&mut transport, landing)?;
    verify_candidate(&line_after, &plan.candidate)?;
    verify_candidate(&landing_after, &plan.candidate)?;
    let line_journal = journal_since(&mut transport, line, started_epoch)?;
    let landing_journal = journal_since(&mut transport, landing, started_epoch)?;
    std::fs::write(plan.out_dir.join("line-journal.jsonl"), &line_journal)
        .map_err(|error| format!("write LINE journal: {error}"))?;
    std::fs::write(plan.out_dir.join("landing-journal.jsonl"), &landing_journal)
        .map_err(|error| format!("write LANDING journal: {error}"))?;
    let journals = aggregate_journals(&line_journal, &landing_journal);

    let mut checks = Report::checks(false);
    for name in [
        "lineSsh",
        "landingSsh",
        "lineServiceActive",
        "landingServiceActive",
        "linePublicPortsRestricted",
        "landingPublicPortsRestricted",
        "landingFirewallLineOnly",
        "lineCandidateIdentity",
        "landingCandidateIdentity",
        "stockXray",
        "noReplayRegression",
    ] {
        checks.insert(name.to_owned(), true);
    }
    for name in [
        "oneMiBIntegrity",
        "largeIntegrity",
        "uploadIntegrity",
        "bidirectionalIntegrity",
    ] {
        checks.insert(name.to_owned(), integrity.passed());
    }
    checks.insert("lineReload".to_owned(), line_reload);
    checks.insert(
        "generationRetirement".to_owned(),
        journals.pool_summary_events > 0,
    );
    checks.insert("landingRestart".to_owned(), landing_restart);
    checks.insert("restartRecovery".to_owned(), restart_recovery);
    checks.insert("coldFallback".to_owned(), journals.cold_fallback > 0);
    checks.insert("warmHandoff".to_owned(), journals.checkout_hit > 0);
    checks.insert(
        "noRestartLoop".to_owned(),
        line_before.restarts == line_after.restarts
            && landing_before.restarts == landing_after.restarts,
    );
    checks.insert(
        "noAuthenticationRegression".to_owned(),
        journals.authentication_rejections == 0,
    );

    let report = Report {
        candidate: plan.candidate.clone(),
        comparator,
        elapsed_seconds: i64::try_from(started.elapsed().as_secs()).unwrap_or(i64::MAX),
        checks,
        connections_attempted: attempted.load(Ordering::Relaxed),
        connections_successful: successful.load(Ordering::Relaxed),
        journals,
        line_resources,
        landing_resources,
    }
    .to_json()
    .to_python_json();
    let input = plan.out_dir.join("canary-input.json");
    std::fs::write(&input, &report)
        .map_err(|error| format!("write {}: {error}", input.display()))?;
    let (verdict, ok) = match super::canary::evaluate_text(&report) {
        super::canary::Outcome::Evaluated { verdict, ok } => (verdict, ok),
        super::canary::Outcome::Inadmissible(error) => {
            return Err(format!("native canary report was inadmissible: {error}"));
        }
    };
    std::fs::write(plan.out_dir.join("canary-verdict.json"), &verdict)
        .map_err(|error| format!("write canary verdict: {error}"))?;
    Ok(RunOutcome { verdict, ok })
}

fn verify_candidate(snapshot: &HostSnapshot, candidate: &Candidate) -> Result<(), String> {
    if !snapshot.service_healthy() || !snapshot.ssh_22_present {
        return Err(format!(
            "candidate host is unhealthy: {}",
            snapshot.summary_line()
        ));
    }
    if snapshot.executable_sha256.as_deref() != Some(candidate.sha256.as_str()) {
        return Err(format!(
            "candidate SHA-256 mismatch on {}: {:?}",
            snapshot.alias, snapshot.executable_sha256
        ));
    }
    let observed_version = snapshot
        .version
        .as_deref()
        .and_then(|version| version.split_whitespace().nth(1));
    if observed_version != Some(candidate.version.as_str()) {
        return Err(format!(
            "candidate version mismatch on {}: {:?}",
            snapshot.alias, snapshot.version
        ));
    }
    Ok(())
}

fn comparator_identity(plan: &Plan) -> Result<Comparator, String> {
    let version = Tool::new(plan.xray_bin.display().to_string())
        .arg("version")
        .run()
        .map_err(|error| format!("Xray version: {error}"))?;
    let version = version
        .trimmed_stdout()
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| "Xray version output has no version field".to_owned())?
        .to_owned();
    let notes = Tool::new("readelf")
        .args(["-n".to_owned(), plan.xray_bin.display().to_string()])
        .run()
        .map_err(|error| format!("Xray build id: {error}"))?;
    let build_id = notes
        .stdout
        .lines()
        .find_map(|line| line.split_once("Build ID:").map(|(_, value)| value.trim()))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Xray ELF has no build id".to_owned())?
        .to_owned();
    Ok(Comparator {
        name: "Xray".to_owned(),
        version,
        sha256: plan.xray_sha256.clone(),
        build_id,
    })
}

/// Checks that exactly one INPUT ACCEPT rule exposes TCP/443 and it is scoped to
/// LINE's `/32`; unrelated non-443 rules are ignored.
#[must_use]
pub fn firewall_line_only(iptables_save: &str, line: Ipv4Addr) -> bool {
    let source = format!("{line}/32");
    let rules: Vec<Vec<&str>> = iptables_save
        .lines()
        .map(|rule| rule.split_whitespace().collect::<Vec<_>>())
        .filter(|tokens| {
            tokens.starts_with(&["-A", "INPUT"])
                && token_value(tokens, "--dport") == Some("443")
                && token_value(tokens, "-j") == Some("ACCEPT")
        })
        .collect();
    rules.len() == 1
        && token_value(&rules[0], "-s") == Some(source.as_str())
        && token_value(&rules[0], "-p") == Some("tcp")
}

fn token_value<'a>(tokens: &'a [&str], key: &str) -> Option<&'a str> {
    tokens
        .windows(2)
        .find_map(|pair| (pair[0] == key).then_some(pair[1]))
}

fn remote_unit(transport: &mut impl Transport, host: &Host, action: &str) -> Result<(), String> {
    checked(
        transport,
        host,
        true,
        &[
            "systemctl".to_owned(),
            action.to_owned(),
            host.service().to_owned(),
        ],
        &format!("{action} {}", host.alias()),
    )
    .map(|_| ())
}

fn wait_candidate(
    transport: &mut impl Transport,
    host: &Host,
    candidate: &Candidate,
) -> Result<bool, String> {
    let mut last = String::new();
    for _ in 0..100 {
        match inspect(transport, host)
            .and_then(|snapshot| verify_candidate(&snapshot, candidate).map(|()| snapshot))
        {
            Ok(_) => return Ok(true),
            Err(error) => last = error,
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!(
        "{} did not recover within 10 seconds: {last}",
        host.alias()
    ))
}

fn run_request_batch(
    plan: &Plan,
    count: usize,
    concurrency: usize,
    attempted: &AtomicI64,
    successful: &AtomicI64,
) {
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..concurrency {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= count {
                        break;
                    }
                    attempted.fetch_add(1, Ordering::Relaxed);
                    if curl_request(plan, &plan.small_url, None, None, 20).is_ok() {
                        successful.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });
}

fn curl_request(
    plan: &Plan,
    url: &str,
    output: Option<&Path>,
    upload: Option<&Path>,
    max_time: u64,
) -> Result<(), String> {
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
    let mut arguments = vec![
        "--fail".to_owned(),
        "--silent".to_owned(),
        "--show-error".to_owned(),
        "--noproxy".to_owned(),
        String::new(),
        "--max-time".to_owned(),
        max_time.to_string(),
        "--socks5-hostname".to_owned(),
        format!("127.0.0.1:{}", plan.socks_port),
    ];
    if let Some(path) = upload {
        arguments.extend(["--upload-file".to_owned(), path.display().to_string()]);
    }
    arguments.extend([
        "--output".to_owned(),
        output.map_or_else(|| "/dev/null".to_owned(), |path| path.display().to_string()),
        url.to_owned(),
    ]);
    curl.args(arguments)
        .run()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[derive(Debug, Default)]
enum IntegrityStatus {
    #[default]
    Pending,
    Passed,
}

impl IntegrityStatus {
    const fn passed(&self) -> bool {
        matches!(self, Self::Passed)
    }
}

fn run_integrity(
    plan: &Plan,
    transport: &mut impl Transport,
    landing: &Host,
) -> Result<(), String> {
    let one = plan.out_dir.join("download-1mib.bin");
    curl_request(plan, &plan.one_mib_url, Some(&one), None, 60)?;
    compare_files(&one, &plan.payload_one_mib)?;
    let large = plan.out_dir.join("download-large.bin");
    curl_request(plan, &plan.large_url, Some(&large), None, 120)?;
    compare_files(&large, &plan.payload_large)?;
    curl_request(plan, &plan.upload_url, None, Some(&plan.payload_large), 120)?;
    let bidi = plan.out_dir.join("download-bidirectional.bin");
    let bidi_url = format!("{}/bidi", plan.upload_url.trim_end_matches('/'));
    let (download, upload) = std::thread::scope(|scope| {
        let download = scope.spawn(|| curl_request(plan, &plan.large_url, Some(&bidi), None, 120));
        let upload =
            scope.spawn(|| curl_request(plan, &bidi_url, None, Some(&plan.payload_large), 120));
        (
            download
                .join()
                .unwrap_or_else(|_| Err("download worker panicked".to_owned())),
            upload
                .join()
                .unwrap_or_else(|_| Err("upload worker panicked".to_owned())),
        )
    });
    download?;
    upload?;
    compare_files(&bidi, &plan.payload_large)?;
    let put_log = checked(
        transport,
        landing,
        true,
        &[
            "cat".to_owned(),
            "/var/lib/rust-reality/canary-put.jsonl".to_owned(),
        ],
        "read LANDING canary upload log",
    )?;
    let expected_bytes = i64::try_from(
        plan.payload_large
            .metadata()
            .map_err(|error| format!("large payload metadata: {error}"))?
            .len(),
    )
    .map_err(|_| "large payload length exceeds evaluator range".to_owned())?;
    let matching_puts = json_records(&put_log)
        .filter(|value| integer_field(value, "bytes") == expected_bytes)
        .count();
    if matching_puts < 2 {
        return Err(format!(
            "LANDING upload log has {matching_puts} matching writes, expected at least 2"
        ));
    }
    Ok(())
}

fn compare_files(observed: &Path, expected: &Path) -> Result<(), String> {
    let observed_size = observed
        .metadata()
        .map_err(|error| format!("download {}: {error}", observed.display()))?
        .len();
    let expected_size = expected
        .metadata()
        .map_err(|error| format!("reference {}: {error}", expected.display()))?
        .len();
    if observed_size != expected_size
        || hash::sha256_file(observed)? != hash::sha256_file(expected)?
    {
        return Err(format!(
            "download integrity mismatch: {} versus {}",
            observed.display(),
            expected.display()
        ));
    }
    Ok(())
}

fn sample_pair(
    transport: &mut impl Transport,
    line: &Host,
    landing: &Host,
    started: Instant,
    line_samples: &mut Vec<ResourceSample>,
    landing_samples: &mut Vec<ResourceSample>,
) -> Result<(), String> {
    line_samples.push(sample_host(transport, line, started)?);
    landing_samples.push(sample_host(transport, landing, started)?);
    Ok(())
}

type ResourceSeries = (Vec<ResourceSample>, Vec<ResourceSample>);

struct ResourceSampler {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Result<ResourceSeries, String>>>,
}

impl ResourceSampler {
    fn start(line: Host, landing: Host, started: Instant, interval: Duration) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let mut transport = SystemTransport;
            let mut line_resources = Vec::new();
            let mut landing_resources = Vec::new();
            while !worker_stop.load(Ordering::Acquire) {
                sample_pair(
                    &mut transport,
                    &line,
                    &landing,
                    started,
                    &mut line_resources,
                    &mut landing_resources,
                )?;
                std::thread::park_timeout(interval);
            }
            Ok((line_resources, landing_resources))
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> Result<ResourceSeries, String> {
        self.stop();
        self.join()
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = &self.handle {
            handle.thread().unpark();
        }
    }

    fn join(&mut self) -> Result<ResourceSeries, String> {
        self.handle
            .take()
            .ok_or_else(|| "resource sampler was already joined".to_owned())?
            .join()
            .map_err(|_| "resource sampler panicked".to_owned())?
    }
}

impl Drop for ResourceSampler {
    fn drop(&mut self) {
        self.stop();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn sample_host(
    transport: &mut impl Transport,
    host: &Host,
    started: Instant,
) -> Result<ResourceSample, String> {
    let elapsed_millis = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let pid_text = checked(
        transport,
        host,
        true,
        &[
            "systemctl".to_owned(),
            "show".to_owned(),
            host.service().to_owned(),
            "-p".to_owned(),
            "MainPID".to_owned(),
            "--value".to_owned(),
        ],
        "sample service pid",
    )?;
    let pid = pid_text.trim().parse::<u32>().unwrap_or(0);
    if pid == 0 {
        return Ok(ResourceSample {
            elapsed_millis,
            pid,
            rss_kib: 0,
            pss_kib: None,
            fd: 0,
            threads: 0,
        });
    }
    let status = checked(
        transport,
        host,
        true,
        &["cat".to_owned(), format!("/proc/{pid}/status")],
        "sample process status",
    )?;
    let rss_kib = proc_status_value(&status, "VmRSS:").unwrap_or(0);
    let threads = proc_status_value(&status, "Threads:").unwrap_or(0);
    let descriptors = checked(
        transport,
        host,
        true,
        &[
            "find".to_owned(),
            format!("/proc/{pid}/fd"),
            "-mindepth".to_owned(),
            "1".to_owned(),
            "-maxdepth".to_owned(),
            "1".to_owned(),
            "-printf".to_owned(),
            "x\\n".to_owned(),
        ],
        "sample descriptors",
    )?;
    let rollup = transport.run(
        host,
        true,
        &["cat".to_owned(), format!("/proc/{pid}/smaps_rollup")],
    )?;
    let pss_kib = rollup
        .success()
        .then(|| proc_status_value(&rollup.stdout, "Pss:"))
        .flatten();
    Ok(ResourceSample {
        elapsed_millis,
        pid,
        rss_kib,
        pss_kib,
        fd: i64::try_from(descriptors.lines().count()).unwrap_or(i64::MAX),
        threads,
    })
}

fn proc_status_value(text: &str, prefix: &str) -> Option<i64> {
    text.lines().find_map(|line| {
        line.strip_prefix(prefix)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|value| value.parse().ok())
    })
}

fn journal_since(
    transport: &mut impl Transport,
    host: &Host,
    started_epoch: u64,
) -> Result<String, String> {
    checked(
        transport,
        host,
        true,
        &[
            "journalctl".to_owned(),
            "-u".to_owned(),
            host.service().to_owned(),
            "--since".to_owned(),
            format!("@{started_epoch}"),
            "--no-pager".to_owned(),
            "-o".to_owned(),
            "cat".to_owned(),
        ],
        "collect service journal",
    )
}

fn rollback_hosts(topology: &Topology) -> Result<(), String> {
    let mut failures = Vec::new();
    for role in [HostRole::Line, HostRole::Landing] {
        let host = topology.host(role);
        let mut transport = SystemTransport;
        let result = inspect(&mut transport, host)
            .and_then(|snapshot| {
                plan::plan_rollback(&snapshot).map(|rollback| (snapshot, rollback))
            })
            .and_then(|(snapshot, rollback)| {
                executor::execute(
                    &mut transport,
                    &mut SystemCandidateValidator,
                    host,
                    &rollback,
                    &snapshot,
                    None,
                    None,
                )
                .map(|_| ())
            });
        if let Err(error) = result {
            failures.push(format!("{}: {error}", host.alias()));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate() -> Candidate {
        Candidate {
            commit: "a".repeat(40),
            sha256: "b".repeat(64),
            build_id: "c".repeat(40),
            version: "1.9.0".to_owned(),
            target: "x86_64-unknown-linux-gnu".to_owned(),
            rustc: "rustc 1.96.0".to_owned(),
        }
    }

    fn samples() -> Vec<ResourceSample> {
        (0..24)
            .map(|index| ResourceSample {
                elapsed_millis: index * 5_000,
                pid: 42,
                rss_kib: 20_000 + i64::try_from(index % 4).unwrap() * 64,
                pss_kib: Some(18_000),
                fd: 20 + i64::try_from(index % 5).unwrap(),
                threads: 4,
            })
            .collect()
    }

    #[test]
    fn scaled_schedule_is_gap_free_for_every_admitted_duration() {
        for duration in [480, 600, 900] {
            let schedule = Schedule::for_duration(duration);
            assert_eq!(schedule.phases.first().unwrap().start_second, 0);
            assert_eq!(schedule.phases.last().unwrap().end_second, duration);
            assert!(schedule.phases.windows(2).all(|pair| {
                pair[0].end_second == pair[1].start_second
                    && pair[0].start_second <= pair[0].end_second
            }));
            assert!(schedule.line_reload_second < schedule.landing_restart_second);
            assert!(schedule.landing_restart_second < schedule.integrity_second);
        }
    }

    #[test]
    fn journal_aggregation_matches_the_legacy_fields() {
        let line = r#"
not json
{"event":"transport_pool_summary","transport":"handoff","pool_checkout_hit":10,"pool_checkout_miss":2,"pool_cold_fallback":1,"pool_target_ready":8,"pool_connecting":3}
{"event":"transport_pool_summary","transport":"handoff","pool_checkout_hit":5,"pool_checkout_miss":1,"pool_cold_fallback":0,"pool_target_ready":4,"pool_connecting":7}
"#;
        let landing = r#"
{"event":"connection_rejected","reason":"overload"}
{"event":"connection_rejected","reason":"authentication"}
"#;
        assert_eq!(
            aggregate_journals(line, landing),
            JournalEvidence {
                checkout_hit: 15,
                checkout_miss: 3,
                cold_fallback: 1,
                target_ready_peak: 8,
                connecting_peak: 7,
                landing_rejections: 2,
                authentication_rejections: 1,
                pool_summary_events: 2,
            }
        );
    }

    #[test]
    fn native_report_is_admitted_by_the_fail_closed_evaluator() {
        let report = Report {
            candidate: candidate(),
            comparator: Comparator {
                name: "Xray".to_owned(),
                version: "26.7.28".to_owned(),
                sha256: "d".repeat(64),
                build_id: "e".repeat(40),
            },
            elapsed_seconds: 600,
            checks: Report::checks(true),
            connections_attempted: 1_000,
            connections_successful: 999,
            journals: JournalEvidence {
                checkout_hit: 995,
                checkout_miss: 5,
                cold_fallback: 5,
                target_ready_peak: 64,
                connecting_peak: 24,
                landing_rejections: 4,
                authentication_rejections: 0,
                pool_summary_events: 2,
            },
            line_resources: samples(),
            landing_resources: samples(),
        };
        let json = report.to_json().to_python_json();
        match super::super::canary::evaluate_text(&json) {
            super::super::canary::Outcome::Evaluated { ok, verdict } => {
                assert!(ok, "{verdict}");
            }
            super::super::canary::Outcome::Inadmissible(error) => panic!("{error}"),
        }
    }

    #[test]
    fn malformed_candidate_identity_is_rejected_before_live_work() {
        let mut candidate = candidate();
        candidate.sha256 = "UPPER".to_owned();
        assert!(candidate.validate().is_err());
    }

    #[test]
    fn firewall_requires_one_exact_line_scoped_tcp_rule() {
        let line = "203.0.113.7".parse().unwrap();
        let fixture = "-A INPUT -p tcp -s 203.0.113.7/32 --dport 443 -j ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n";
        assert!(firewall_line_only(fixture, line));
        assert!(!firewall_line_only(
            "-A INPUT -p tcp -s 0.0.0.0/0 --dport 443 -j ACCEPT\n",
            line
        ));
        assert!(!firewall_line_only(
            &format!("{fixture}-A INPUT -p tcp -s 198.51.100.1/32 --dport 443 -j ACCEPT\n"),
            line
        ));
    }
}
