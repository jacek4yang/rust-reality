//! Typed plan and evidence model for the active dual-VPS release canary.
//!
//! Live traffic is a mechanism; the release decision is recorded policy. This
//! module owns the deterministic phase schedule, exact candidate/comparator
//! identities, resource samples, journal aggregation, and report serialization.
//! The resulting report is always re-admitted through [`super::canary`].

use std::{collections::BTreeMap, net::Ipv4Addr, path::PathBuf};

use crate::{
    hash,
    perf::{
        json_in::{self, Value},
        json_out::Json,
    },
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
        let config_text = std::fs::read_to_string(&self.xray_config).map_err(|error| {
            format!("read Xray config {}: {error}", self.xray_config.display())
        })?;
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
            ("xrayBinary", Json::string(self.xray_bin.display().to_string())),
            ("xraySha256", Json::string(self.xray_sha256.clone())),
            ("xrayConfig", Json::string(self.xray_config.display().to_string())),
            ("socksPort", Json::Int(i64::from(self.socks_port))),
            ("linePublicIpv4", Json::string(self.line_public_ipv4.to_string())),
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
            ("evidenceDirectory", Json::string(self.out_dir.display().to_string())),
            (
                "sampleIntervalSeconds",
                Json::Int(i64::try_from(self.sample_interval_seconds).unwrap_or(i64::MAX)),
            ),
            ("schedule", self.schedule().to_json()),
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
            final_reload_second: duration.saturating_sub(30),
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
            (
                "pssKiB",
                self.pss_kib.map_or(Json::Null, Json::Int),
            ),
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
                    (
                        "connectingPeak",
                        Json::Int(self.journals.connecting_peak),
                    ),
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
}
