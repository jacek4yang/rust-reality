//! The three-implementation loopback matrix.
//!
//! `benchmark-matrix.sh` is the broadest harness in the family: three
//! implementations (a pinned `baseline`, the `final` candidate, and `xray`) each
//! fronted by an unmodified Xray SOCKS client, measured across six scenarios ×
//! payload size × concurrency. It is the only suite that asks about *direction*
//! and *shape* rather than a single number.
//!
//! ## The scenarios are not variations on one workload
//!
//! Each isolates a different path through the datapath, which is why they are an
//! enum rather than a flag:
//!
//! | scenario | what it exercises |
//! |---|---|
//! | `framed-download` | plain-HTTP origin; Vision stays framed |
//! | `direct-download` | TLS 1.3 origin; Vision reaches Direct |
//! | `framed-upload` | `PUT` with `Content-Length` to the plain origin |
//! | `direct-upload` | the same against the TLS origin |
//! | `bidi` | downloads and uploads in flight together, one wall time |
//! | `fallback` | straight to the listener, no REALITY client at all |
//!
//! ## Ordering
//!
//! Within a cell the two rust builds run in balanced ABBA and an `xray` sample is
//! interleaved after each pair, so comparator drift is visible without disturbing
//! the release-candidate comparison. That ordering lives in
//! [`crate::bench::plan::interleaved_order`], which also proves it is the same
//! parity rule the other harnesses use.

use std::path::Path;
use std::time::Instant;

use crate::{perf::json_out::Json, process::Tool};

/// The six scenarios, in the order the matrix plans them.
pub const SCENARIOS: [Scenario; 6] = [
    Scenario::FramedDownload,
    Scenario::DirectDownload,
    Scenario::FramedUpload,
    Scenario::DirectUpload,
    Scenario::Bidi,
    Scenario::Fallback,
];

/// The three implementations, in report order.
pub const IMPLEMENTATIONS: [&str; 3] = ["baseline", "final", "xray"];

/// The two rust builds the ABBA comparison alternates between.
pub const RUST_LABELS: [&str; 2] = ["baseline", "final"];

/// The comparator interleaved after each ABBA pair.
pub const COMPARATOR: &str = "xray";

/// One measurement scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scenario {
    /// Plain-HTTP origin download; Vision stays framed.
    FramedDownload,
    /// TLS 1.3 origin download; Vision reaches Direct.
    DirectDownload,
    /// `PUT` upload to the plain-HTTP origin.
    FramedUpload,
    /// `PUT` upload to the TLS 1.3 origin.
    DirectUpload,
    /// Concurrent downloads and uploads through one client.
    Bidi,
    /// Straight to the server listener, exercising the fallback relay.
    Fallback,
}

impl Scenario {
    /// The name used in cell keys and records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FramedDownload => "framed-download",
            Self::DirectDownload => "direct-download",
            Self::FramedUpload => "framed-upload",
            Self::DirectUpload => "direct-upload",
            Self::Bidi => "bidi",
            Self::Fallback => "fallback",
        }
    }

    /// Parses a scenario name.
    ///
    /// # Errors
    ///
    /// Returns a message naming the unknown scenario.
    pub fn parse(text: &str) -> Result<Self, String> {
        SCENARIOS
            .into_iter()
            .find(|scenario| scenario.as_str() == text)
            .ok_or_else(|| format!("unknown scenario {text}"))
    }

    /// The direction recorded alongside every sample.
    #[must_use]
    pub const fn direction(self) -> &'static str {
        match self {
            Self::FramedDownload | Self::DirectDownload | Self::Fallback => "download",
            Self::FramedUpload | Self::DirectUpload => "upload",
            Self::Bidi => "bidi",
        }
    }

    /// Which origin this scenario actually exercises.
    ///
    /// A `fallback` request never reaches the TLS origin: the fallback servers
    /// relay it to the plain-HTTP one, which is what makes it a fallback test.
    #[must_use]
    pub const fn origin_scheme(self) -> &'static str {
        match self {
            Self::FramedDownload | Self::FramedUpload | Self::Fallback => "http",
            Self::DirectDownload | Self::DirectUpload | Self::Bidi => "https",
        }
    }

    /// Whether this scenario issues `PUT` requests the origin logs.
    #[must_use]
    pub const fn uploads(self) -> bool {
        matches!(self, Self::FramedUpload | Self::DirectUpload | Self::Bidi)
    }

    /// Connections a sample opens at `concurrency`.
    ///
    /// `bidi` runs a download *and* an upload per unit of concurrency, so it opens
    /// twice as many; the tunnel-bypass guard compares against this number.
    #[must_use]
    pub const fn connections(self, concurrency: usize) -> usize {
        match self {
            Self::Bidi => concurrency * 2,
            _ => concurrency,
        }
    }
}

/// One planned cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cell {
    /// The scenario measured.
    pub scenario: Scenario,
    /// Payload size in MiB.
    pub payload_mib: u64,
    /// Concurrency.
    pub concurrency: usize,
}

impl Cell {
    /// The `<scenario>:<mib>:<concurrency>` key used in filters and the report.
    #[must_use]
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.scenario.as_str(),
            self.payload_mib,
            self.concurrency
        )
    }
}

/// The cell plan a run measures.
#[derive(Debug, Clone)]
pub struct CellPlan {
    /// Payload sizes in MiB.
    pub payloads_mib: Vec<u64>,
    /// Concurrencies for payloads below the large threshold.
    pub concurrencies: Vec<usize>,
    /// Concurrencies for payloads at or above the large threshold.
    pub large_concurrencies: Vec<usize>,
    /// The payload size at which the large plan takes over.
    pub large_payload_mib: u64,
    /// `CELLS` include patterns; empty means every planned cell.
    pub include: Vec<String>,
    /// `SKIP` exclude patterns.
    pub exclude: Vec<String>,
}

impl CellPlan {
    /// The cells this plan selects, in scenario × payload × concurrency order.
    #[must_use]
    pub fn cells(&self) -> Vec<Cell> {
        let mut payloads: Vec<u64> = self.payloads_mib.clone();
        payloads.sort_unstable();
        payloads.dedup();
        let mut cells = Vec::new();
        for scenario in SCENARIOS {
            for payload_mib in &payloads {
                let concurrencies = if *payload_mib >= self.large_payload_mib {
                    &self.large_concurrencies
                } else {
                    &self.concurrencies
                };
                let mut levels = concurrencies.clone();
                levels.sort_unstable();
                levels.dedup();
                for concurrency in levels {
                    cells.push(Cell {
                        scenario,
                        payload_mib: *payload_mib,
                        concurrency,
                    });
                }
            }
        }
        cells
            .into_iter()
            .filter(|cell| {
                let key = cell.key();
                let included = self.include.is_empty()
                    || self.include.iter().any(|pattern| matches(pattern, &key));
                let excluded = self.exclude.iter().any(|pattern| matches(pattern, &key));
                included && !excluded
            })
            .collect()
    }

    /// Samples per implementation for a payload size.
    #[must_use]
    pub const fn samples_for(&self, payload_mib: u64, small: usize, large: usize) -> usize {
        if payload_mib >= self.large_payload_mib {
            large
        } else {
            small
        }
    }
}

/// Whether `pattern` matches `text` under `fnmatch` semantics.
///
/// The matrix's filters are shell globs, not regular expressions: `*` spans any
/// run of characters (including `:`), `?` is one character, and everything else
/// is literal. Character classes are not supported, because the recorded filters
/// never used them and silently accepting `[` would change what a pattern means.
#[must_use]
pub fn matches(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0_usize, 0_usize);
    let (mut star, mut resume) = (None, 0_usize);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            resume = t;
            p += 1;
        } else if let Some(position) = star {
            p = position + 1;
            resume += 1;
            t = resume;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

/// The loopback endpoints a matrix workload talks to.
#[derive(Debug, Clone, Copy)]
pub struct Endpoints {
    /// The SOCKS port of the Xray client fronting this implementation's tunnel.
    pub socks: u16,
    /// This implementation's fallback listener.
    pub fallback: u16,
    /// The plain-HTTP origin.
    pub http: u16,
    /// The TLS 1.3 origin.
    pub https: u16,
}

/// The per-transfer deadline, as the driver computed it.
///
/// A 2 GiB integrity transfer cannot share a deadline with a 1 MiB one, so the
/// budget grows with the payload while keeping a generous floor.
#[must_use]
pub const fn max_time_for(payload_mib: u64) -> u64 {
    let scaled = payload_mib / 8 + 120;
    if scaled > 180 { scaled } else { 180 }
}

/// One completed transfer: bytes moved and seconds taken.
type Transfer = Result<(u64, f64), String>;

/// Runs one curl with the proxy environment stripped.
///
/// A curl that inherited `NO_PROXY=127.0.0.1` would bypass an explicit
/// `--socks5-hostname` and measure a direct fetch, reporting it as tunnel
/// throughput. Stripping is the first line of defence; the
/// `connection_accepted` guard is the second.
fn run_curl(args: &[String], payload_mib: u64) -> Transfer {
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
    let mut command = vec![
        "--fail".to_owned(),
        "--silent".to_owned(),
        "--show-error".to_owned(),
        "--max-time".to_owned(),
        max_time_for(payload_mib).to_string(),
    ];
    command.extend_from_slice(args);
    let outcome = curl
        .args(command)
        .probe()
        .map_err(|error| format!("could not run curl: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "curl rc={:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    let mut fields = outcome.trimmed_stdout().split_whitespace();
    let (Some(size), Some(seconds), None) = (fields.next(), fields.next(), fields.next()) else {
        return Err("malformed curl measurement line".to_owned());
    };
    let (Ok(size), Ok(seconds)) = (size.parse::<u64>(), seconds.parse::<f64>()) else {
        return Err("malformed curl measurement line".to_owned());
    };
    Ok((size, seconds))
}

/// Downloads the payload through the tunnel's SOCKS client.
fn curl_download(endpoints: Endpoints, payload_mib: u64, scheme: &str) -> Transfer {
    let port = if scheme == "https" {
        endpoints.https
    } else {
        endpoints.http
    };
    let mut args = Vec::new();
    if scheme == "https" {
        args.extend(["--insecure".to_owned(), "--tlsv1.3".to_owned()]);
    }
    args.extend([
        "--socks5-hostname".to_owned(),
        format!("127.0.0.1:{}", endpoints.socks),
        "--output".to_owned(),
        "/dev/null".to_owned(),
        "--write-out".to_owned(),
        "%{size_download} %{time_total}".to_owned(),
        format!("{scheme}://127.0.0.1:{port}/payload-{payload_mib}.bin"),
    ]);
    run_curl(&args, payload_mib)
}

/// Uploads the payload through the tunnel's SOCKS client.
fn curl_upload(
    endpoints: Endpoints,
    payload_mib: u64,
    scheme: &str,
    payload_dir: &Path,
) -> Transfer {
    let port = if scheme == "https" {
        endpoints.https
    } else {
        endpoints.http
    };
    let mut args = Vec::new();
    if scheme == "https" {
        args.extend(["--insecure".to_owned(), "--tlsv1.3".to_owned()]);
    }
    args.extend([
        "--socks5-hostname".to_owned(),
        format!("127.0.0.1:{}", endpoints.socks),
        "--upload-file".to_owned(),
        payload_dir
            .join(format!("payload-{payload_mib}.bin"))
            .display()
            .to_string(),
        "--output".to_owned(),
        "/dev/null".to_owned(),
        "--write-out".to_owned(),
        "%{size_upload} %{time_total}".to_owned(),
        format!("{scheme}://127.0.0.1:{port}/upload/{payload_mib}"),
    ]);
    run_curl(&args, payload_mib)
}

/// Downloads straight from the fallback listener, with no REALITY client.
fn curl_fallback(endpoints: Endpoints, payload_mib: u64) -> Transfer {
    run_curl(
        &[
            "--output".to_owned(),
            "/dev/null".to_owned(),
            "--write-out".to_owned(),
            "%{size_download} %{time_total}".to_owned(),
            format!(
                "http://127.0.0.1:{}/payload-{payload_mib}.bin",
                endpoints.fallback
            ),
        ],
        payload_mib,
    )
}

/// What one scenario run produced.
#[derive(Debug)]
pub struct WorkloadOutcome {
    /// Wall-clock seconds covering the whole parallel set.
    pub wall_seconds: f64,
    /// Per-request seconds.
    pub per_request_seconds: Vec<f64>,
    /// Requests issued.
    pub requests: usize,
}

/// Runs one scenario's parallel transfer set.
///
/// Every transfer's byte count is checked against the payload size: a truncated
/// transfer is a failure, not a fast one.
///
/// # Errors
///
/// Returns the first transfer failure, or a length mismatch naming the counts.
pub fn run_workload(
    scenario: Scenario,
    endpoints: Endpoints,
    payload_mib: u64,
    concurrency: usize,
    payload_dir: &Path,
) -> Result<WorkloadOutcome, String> {
    let expected = payload_mib * 1024 * 1024;
    let started = Instant::now();
    let results: Vec<Transfer> = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..concurrency {
            match scenario {
                Scenario::FramedDownload => {
                    handles.push(scope.spawn(move || curl_download(endpoints, payload_mib, "http")));
                }
                Scenario::DirectDownload => {
                    handles
                        .push(scope.spawn(move || curl_download(endpoints, payload_mib, "https")));
                }
                Scenario::FramedUpload => {
                    handles.push(scope.spawn(move || {
                        curl_upload(endpoints, payload_mib, "http", payload_dir)
                    }));
                }
                Scenario::DirectUpload => {
                    handles.push(scope.spawn(move || {
                        curl_upload(endpoints, payload_mib, "https", payload_dir)
                    }));
                }
                Scenario::Bidi => {
                    handles
                        .push(scope.spawn(move || curl_download(endpoints, payload_mib, "https")));
                    handles.push(scope.spawn(move || {
                        curl_upload(endpoints, payload_mib, "https", payload_dir)
                    }));
                }
                Scenario::Fallback => {
                    handles.push(scope.spawn(move || curl_fallback(endpoints, payload_mib)));
                }
            }
        }
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|_| Err("transfer thread panicked".to_owned()))
            })
            .collect()
    });
    let wall_seconds = started.elapsed().as_secs_f64();

    let mut per_request = Vec::with_capacity(results.len());
    let mut mismatches = Vec::new();
    for result in &results {
        match result {
            Ok((size, seconds)) => {
                if *size == expected {
                    per_request.push(*seconds);
                } else {
                    mismatches.push(*size);
                }
            }
            Err(reason) => return Err(reason.clone()),
        }
    }
    if let Some(first) = mismatches.first() {
        return Err(format!(
            "payload length mismatch: {}/{} requests returned {first} != {expected} bytes",
            mismatches.len(),
            results.len()
        ));
    }
    Ok(WorkloadOutcome {
        wall_seconds,
        per_request_seconds: per_request,
        requests: results.len(),
    })
}

/// One recorded matrix sample.
#[derive(Debug, Clone)]
pub struct SampleRecord {
    /// The repository commit the run was taken at.
    pub commit: String,
    /// The implementation measured.
    pub implementation: String,
    /// The cell.
    pub cell: Cell,
    /// Sample index within the cell for this implementation.
    pub sample_index: usize,
    /// Wall-clock seconds, absent when the workload failed.
    pub wall_seconds: Option<f64>,
    /// Aggregate throughput in MiB/s, absent when the workload failed.
    pub throughput_mib_per_second: Option<f64>,
    /// Per-request seconds.
    pub per_request_seconds: Vec<f64>,
    /// Whether every transferred byte count matched.
    pub bytes_verified: bool,
    /// Whether the sample must not be interpreted.
    pub invalid: bool,
    /// Why, when it is invalid.
    pub invalid_reason: Option<String>,
}

impl SampleRecord {
    /// Renders the record as the driver wrote it.
    #[must_use]
    pub fn to_json(&self) -> Json {
        let optional_float = |value: Option<f64>| value.map_or(Json::Null, Json::Float);
        Json::object([
            ("schemaVersion", Json::Int(1)),
            ("commit", Json::string(self.commit.clone())),
            (
                "implementation",
                Json::string(self.implementation.clone()),
            ),
            ("scenario", Json::string(self.cell.scenario.as_str())),
            ("direction", Json::string(self.cell.scenario.direction())),
            (
                "payloadBytes",
                Json::Int(
                    i64::try_from(self.cell.payload_mib * 1024 * 1024).unwrap_or(i64::MAX),
                ),
            ),
            (
                "concurrency",
                Json::Int(i64::try_from(self.cell.concurrency).unwrap_or(i64::MAX)),
            ),
            (
                "sampleIndex",
                Json::Int(i64::try_from(self.sample_index).unwrap_or(i64::MAX)),
            ),
            ("wallSeconds", optional_float(self.wall_seconds)),
            (
                "throughputMiBPerSecond",
                optional_float(self.throughput_mib_per_second),
            ),
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
            ("bytesVerified", Json::Bool(self.bytes_verified)),
            ("invalid", Json::Bool(self.invalid)),
            (
                "invalidReason",
                self.invalid_reason
                    .clone()
                    .map_or(Json::Null, Json::string),
            ),
        ])
    }

    /// Marks the sample invalid, appending `reason` to any existing one.
    pub fn invalidate(&mut self, reason: &str) {
        self.invalid = true;
        self.invalid_reason = Some(match self.invalid_reason.take() {
            Some(existing) => format!("{existing}; {reason}"),
            None => reason.to_owned(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> CellPlan {
        CellPlan {
            payloads_mib: vec![1, 32, 512],
            concurrencies: vec![1, 4, 32],
            large_concurrencies: vec![1, 32],
            large_payload_mib: 512,
            include: Vec::new(),
            exclude: Vec::new(),
        }
    }

    /// The script's documented default plan: 6 scenarios × (2 small payloads × 3
    /// concurrencies) + 6 × (1 large payload × 2 concurrencies) = 48 cells.
    #[test]
    fn the_default_plan_is_forty_eight_cells() {
        let cells = plan().cells();
        assert_eq!(cells.len(), 48);
        assert_eq!(
            cells.iter().filter(|cell| cell.payload_mib == 512).count(),
            12,
            "the large payload uses the reduced concurrency set"
        );
        for scenario in SCENARIOS {
            assert_eq!(
                cells.iter().filter(|cell| cell.scenario == scenario).count(),
                8
            );
        }
    }

    #[test]
    fn cell_keys_follow_the_filter_syntax() {
        let cell = Cell {
            scenario: Scenario::DirectUpload,
            payload_mib: 32,
            concurrency: 1,
        };
        assert_eq!(cell.key(), "direct-upload:32:1");
    }

    /// The filters from the script's own documentation.
    #[test]
    fn the_documented_filters_select_what_the_script_says() {
        let mut context = plan();
        context.include = vec!["direct-*:32:*".to_owned(), "fallback:*:*".to_owned()];
        context.exclude = vec!["*:512:32".to_owned()];
        let cells = context.cells();
        assert!(
            cells
                .iter()
                .all(|cell| cell.key().starts_with("direct-") || cell.key().starts_with("fallback:"))
        );
        assert!(
            !cells.iter().any(|cell| cell.key().ends_with(":512:32")),
            "the skip pattern must win over the include"
        );
        // Included: direct-{download,upload}:32:{1,4,32} = 6, plus fallback at
        // 1 and 32 MiB × {1,4,32} and at 512 MiB × {1,32} = 8, so 14. The skip
        // then removes fallback:512:32, leaving 13.
        assert_eq!(cells.len(), 13);
        assert!(cells.iter().any(|cell| cell.key() == "fallback:512:1"));
    }

    #[test]
    fn glob_matching_follows_fnmatch() {
        assert!(matches("*", "anything:1:1"));
        assert!(matches("direct-*:32:*", "direct-upload:32:4"));
        assert!(!matches("direct-*:32:*", "framed-upload:32:4"));
        assert!(matches("*:512:32", "bidi:512:32"));
        assert!(!matches("*:512:32", "bidi:512:1"));
        // `*` spans separators, as fnmatch does.
        assert!(matches("bidi*32", "bidi:512:32"));
        assert!(matches("?idi:1:1", "bidi:1:1"));
        assert!(!matches("?idi:1:1", "bbidi:1:1"));
        assert!(matches("framed-download:1:1", "framed-download:1:1"));
        assert!(!matches("framed-download:1:1", "framed-download:1:10"));
        // Trailing stars may match nothing at all.
        assert!(matches("bidi:1:1***", "bidi:1:1"));
    }

    #[test]
    fn a_scenario_knows_its_direction_origin_and_connection_count() {
        assert_eq!(Scenario::FramedDownload.direction(), "download");
        assert_eq!(Scenario::DirectUpload.direction(), "upload");
        assert_eq!(Scenario::Bidi.direction(), "bidi");
        // A fallback request never reaches the TLS origin; it is relayed to the
        // plain one, which is what makes it a fallback test.
        assert_eq!(Scenario::Fallback.origin_scheme(), "http");
        assert_eq!(Scenario::DirectDownload.origin_scheme(), "https");
        assert_eq!(Scenario::Bidi.origin_scheme(), "https");
        // bidi opens a download and an upload per unit of concurrency.
        assert_eq!(Scenario::Bidi.connections(4), 8);
        assert_eq!(Scenario::FramedDownload.connections(4), 4);
        assert!(Scenario::Bidi.uploads());
        assert!(!Scenario::Fallback.uploads());
    }

    #[test]
    fn scenarios_round_trip_through_their_names() {
        for scenario in SCENARIOS {
            assert_eq!(Scenario::parse(scenario.as_str()).unwrap(), scenario);
        }
        assert!(Scenario::parse("sideways").is_err());
    }

    #[test]
    fn the_sample_count_follows_the_payload_size() {
        let plan = plan();
        assert_eq!(plan.samples_for(32, 5, 3), 5);
        assert_eq!(plan.samples_for(512, 5, 3), 3);
    }

    #[test]
    fn the_record_document_matches_the_driver_shape() {
        let mut record = SampleRecord {
            commit: "a".repeat(40),
            implementation: "final".to_owned(),
            cell: Cell {
                scenario: Scenario::Bidi,
                payload_mib: 32,
                concurrency: 4,
            },
            sample_index: 2,
            wall_seconds: Some(2.0),
            throughput_mib_per_second: Some(128.0),
            per_request_seconds: vec![0.5, 0.6],
            bytes_verified: true,
            invalid: false,
            invalid_reason: None,
        };
        let rendered = record.to_json().to_python_json();
        assert!(rendered.contains("\"schemaVersion\": 1"));
        assert!(rendered.contains("\"scenario\": \"bidi\""));
        assert!(rendered.contains("\"direction\": \"bidi\""));
        assert!(rendered.contains("\"payloadBytes\": 33554432"));
        assert!(rendered.contains("\"bytesVerified\": true"));
        assert!(rendered.contains("\"invalidReason\": null"));

        // Reasons accumulate rather than replacing each other, so a sample that
        // failed twice says both things.
        record.invalidate("origin error");
        record.invalidate("tunnel bypass suspected");
        let rendered = record.to_json().to_python_json();
        assert!(rendered.contains("\"invalid\": true"));
        assert!(rendered.contains("origin error; tunnel bypass suspected"));

        // A failed workload records nulls rather than zeros, which would look
        // like a real measurement of nothing.
        let failed = SampleRecord {
            wall_seconds: None,
            throughput_mib_per_second: None,
            per_request_seconds: Vec::new(),
            bytes_verified: false,
            ..record
        };
        let rendered = failed.to_json().to_python_json();
        assert!(rendered.contains("\"wallSeconds\": null"));
        assert!(rendered.contains("\"throughputMiBPerSecond\": null"));
    }
}

// ---------------------------------------------------------------------------
// The runner
// ---------------------------------------------------------------------------

/// Everything a matrix run needs.
#[derive(Debug, Clone)]
pub struct MatrixSuite {
    /// Repository root.
    pub repo: std::path::PathBuf,
    /// The pinned baseline ELF.
    pub baseline_bin: std::path::PathBuf,
    /// The candidate ELF.
    pub final_bin: std::path::PathBuf,
    /// The Xray binary: comparator server and every SOCKS client.
    pub xray_bin: std::path::PathBuf,
    /// Output directory; must not already exist.
    pub out_dir: std::path::PathBuf,
    /// Run identifier.
    pub run_id: String,
    /// The REALITY cover target the tunnel servers use, as in production.
    pub cover_target: String,
    /// The cover SNI.
    pub cover_sni: String,
    /// The cell plan.
    pub plan: CellPlan,
    /// Samples per implementation for payloads below the large threshold.
    pub samples: usize,
    /// Samples per implementation at or above it.
    pub samples_large: usize,
    /// Payload size for the end-to-end integrity run; `0` skips it.
    pub integrity_mib: u64,
    /// Which rust build leads block one.
    pub abba_start: String,
    /// Whether to raise `fs.pipe-user-pages-soft` for the run.
    pub manage_pipe_pages: bool,
}

/// What a matrix run produced.
#[derive(Debug)]
pub struct MatrixOutcome {
    /// The published output directory.
    pub out_dir: std::path::PathBuf,
    /// The `summary.json` document.
    pub summary_json: String,
    /// Cells measured.
    pub cells: usize,
    /// Samples recorded.
    pub samples: usize,
    /// Samples marked invalid.
    pub invalid: usize,
}

/// Validates the matrix parameters.
///
/// # Errors
///
/// Returns the first violated guard.
pub fn validate(suite: &MatrixSuite) -> Result<(), String> {
    if suite.samples == 0 || suite.samples_large == 0 {
        return Err("SAMPLES and SAMPLES_LARGE must be positive".to_owned());
    }
    if suite.plan.payloads_mib.is_empty() || suite.plan.payloads_mib.contains(&0) {
        return Err("every payload size must be a positive integer".to_owned());
    }
    for levels in [&suite.plan.concurrencies, &suite.plan.large_concurrencies] {
        if levels.is_empty() || levels.contains(&0) {
            return Err("every concurrency must be a positive integer".to_owned());
        }
    }
    if !RUST_LABELS.contains(&suite.abba_start.as_str()) {
        return Err(format!(
            "ABBA_START must be baseline or final, got {}",
            suite.abba_start
        ));
    }
    if suite.run_id.is_empty()
        || !suite
            .run_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err("RUN_ID is required and must be one safe component".to_owned());
    }
    if suite.plan.cells().is_empty() {
        return Err("the cell filters selected no cells".to_owned());
    }
    Ok(())
}

/// The peak concurrency a plan reaches, which sizes the pipe-page budget.
#[must_use]
pub fn peak_concurrency(plan: &CellPlan) -> u64 {
    plan.concurrencies
        .iter()
        .chain(plan.large_concurrencies.iter())
        .copied()
        .max()
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(1)
}

/// The nine proxy processes and two origins a matrix run owns.
///
/// Each implementation gets a *tunnel* server whose REALITY cover is the public
/// target, a *fallback* server whose cover is the local plain origin, and an Xray
/// SOCKS client in front of the tunnel. Dropping this stops all of them.
struct Topology {
    _children: Vec<crate::bench::process::Child>,
    endpoints: std::collections::BTreeMap<String, Endpoints>,
    log_paths: std::collections::BTreeMap<String, (std::path::PathBuf, std::path::PathBuf)>,
    http_port: u16,
    https_port: u16,
}

/// The ports one implementation occupies.
struct ImplementationPorts {
    tunnel: u16,
    fallback: u16,
    socks: u16,
}

/// Brings up both origins and all nine proxy processes.
fn start_topology(
    suite: &MatrixSuite,
    workspace: &crate::bench::workspace::Workspace,
    binaries: &std::collections::BTreeMap<String, crate::bench::identity::Binary>,
    port_base: u16,
) -> Result<Topology, String> {
    use crate::bench::{config::RealityIdentity, process::Child, suites};

    let plain = port_base;
    let secure = port_base + 1;
    let mut children = start_origins(suite, workspace, plain, secure)?;

    // One shared Xray identity for the comparator, as the script fixed it.
    let xray_keys = suites::generate_xray_keys(&suite.xray_bin)?;
    let xray_identity = RealityIdentity {
        uuid: "11111111-1111-1111-1111-111111111111".to_owned(),
        short_id: "0123456789abcdef".to_owned(),
        server_name: suite.cover_sni.clone(),
        target: suite.cover_target.clone(),
    };

    let mut endpoints = std::collections::BTreeMap::new();
    let mut log_paths = std::collections::BTreeMap::new();
    let mut clients = Vec::new();
    for (index, label) in IMPLEMENTATIONS.iter().enumerate() {
        let offset = u16::try_from(index * 3).map_err(|_| "too many implementations".to_owned())?;
        let ports = ImplementationPorts {
            tunnel: port_base + 2 + offset,
            fallback: port_base + 3 + offset,
            socks: port_base + 4 + offset,
        };
        let (public_key, identity) = if *label == COMPARATOR {
            start_xray_pair(
                suite,
                workspace,
                &xray_identity,
                &xray_keys,
                &ports,
                plain,
                &mut children,
            )?;
            (xray_keys.public.clone(), xray_identity.clone())
        } else {
            start_rust_pair(suite, workspace, binaries, label, &ports, plain, &mut children)?
        };

        let client_config =
            crate::bench::config::xray_client(&identity, ports.tunnel, ports.socks, &public_key)
                .to_python_json();
        let client_path = workspace.join(&format!("{label}-client.json"));
        std::fs::write(&client_path, &client_config)
            .map_err(|error| format!("could not write {}: {error}", client_path.display()))?;
        clients.push((label, ports.socks, client_path));

        endpoints.insert(
            (*label).to_owned(),
            Endpoints {
                socks: ports.socks,
                fallback: ports.fallback,
                http: plain,
                https: secure,
            },
        );
        log_paths.insert(
            (*label).to_owned(),
            (
                workspace.join(&format!("{label}.log")),
                workspace.join(&format!("{label}-fallback.log")),
            ),
        );
    }

    // Clients start after every server is listening, as the script ordered them.
    for (label, socks, config) in clients {
        let mut child = Child::spawn(
            format!("{label}-client"),
            &suite.xray_bin,
            &[
                "run".to_owned(),
                "-config".to_owned(),
                config.display().to_string(),
            ],
            workspace.path(),
            &[],
            &workspace.join(&format!("{label}-client.log")),
        )
        .map_err(|error| error.to_string())?;
        child
            .wait_for_port(socks, std::time::Duration::from_secs(30))
            .map_err(|error| error.to_string())?;
        children.push(child);
    }

    Ok(Topology {
        _children: children,
        endpoints,
        log_paths,
        http_port: plain,
        https_port: secure,
    })
}

/// Builds the Go origin and starts the plain and TLS listeners.
fn start_origins(
    suite: &MatrixSuite,
    workspace: &crate::bench::workspace::Workspace,
    plain: u16,
    secure: u16,
) -> Result<Vec<crate::bench::process::Child>, String> {
    use crate::bench::{origin_go, origin_tls};
    let binary = origin_go::build(&suite.repo, workspace)?;
    let (cert, key) = origin_tls::generate_self_signed(workspace.path())?;
    let mut children = Vec::with_capacity(2);
    for (label, port, tls, put_log) in [
        ("origin-http", plain, None, "http-put.jsonl"),
        ("origin-https", secure, Some((cert, key)), "https-put.jsonl"),
    ] {
        children.push(origin_go::start(
            &binary,
            workspace,
            &origin_go::OriginPlan {
                label: label.to_owned(),
                listen_address: "127.0.0.1".to_owned(),
                port,
                payload_dir: workspace.path().to_path_buf(),
                put_log: workspace.join(put_log),
                tls,
            },
        )?);
    }
    Ok(children)
}

/// Starts one rust implementation's tunnel and fallback servers.
fn start_rust_pair(
    suite: &MatrixSuite,
    workspace: &crate::bench::workspace::Workspace,
    binaries: &std::collections::BTreeMap<String, crate::bench::identity::Binary>,
    label: &str,
    ports: &ImplementationPorts,
    http_port: u16,
    children: &mut Vec<crate::bench::process::Child>,
) -> Result<(String, crate::bench::config::RealityIdentity), String> {
    use crate::bench::{config::RealityIdentity, process::Child, suites};

    let binary = binaries
        .get(label)
        .ok_or_else(|| format!("{label} was never registered"))?;
    // The tunnel server's cover is the public target, exactly like production.
    let tunnel = suites::generate_rust_identity(
        workspace,
        &binary.path,
        ports.tunnel,
        &suite.cover_target,
        &suite.cover_sni,
        None,
    )?;
    // The fallback server's cover is the local origin, so a direct request with
    // no REALITY handshake is relayed to it.
    let fallback = suites::generate_rust_identity(
        workspace,
        &binary.path,
        ports.fallback,
        &format!("127.0.0.1:{http_port}"),
        "localhost",
        None,
    )?;
    for (suffix, port, json) in [
        ("", ports.tunnel, &tunnel.server_json),
        ("-fallback", ports.fallback, &fallback.server_json),
    ] {
        let path = workspace.join(&format!("{label}{suffix}.json"));
        std::fs::write(&path, json)
            .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        let mut child = Child::spawn(
            format!("{label}{suffix}-server"),
            &binary.path,
            &[
                "serve".to_owned(),
                "--config".to_owned(),
                path.display().to_string(),
            ],
            workspace.path(),
            &[],
            &workspace.join(&format!("{label}{suffix}.log")),
        )
        .map_err(|error| error.to_string())?;
        child
            .wait_for_port(port, std::time::Duration::from_secs(30))
            .map_err(|error| error.to_string())?;
        children.push(child);
    }
    Ok((
        tunnel.public_key.clone(),
        RealityIdentity {
            uuid: tunnel.uuid.clone(),
            short_id: tunnel.short_id.clone(),
            server_name: suite.cover_sni.clone(),
            target: suite.cover_target.clone(),
        },
    ))
}

/// Starts the Xray comparator's tunnel and fallback servers.
fn start_xray_pair(
    suite: &MatrixSuite,
    workspace: &crate::bench::workspace::Workspace,
    identity: &crate::bench::config::RealityIdentity,
    keys: &crate::bench::suites::XrayKeys,
    ports: &ImplementationPorts,
    http_port: u16,
    children: &mut Vec<crate::bench::process::Child>,
) -> Result<(), String> {
    use crate::bench::{config, config::RealityIdentity, process::Child};

    let fallback_identity = RealityIdentity {
        server_name: "localhost".to_owned(),
        target: format!("127.0.0.1:{http_port}"),
        ..identity.clone()
    };
    let configs = [
        (
            "",
            ports.tunnel,
            config::xray_server(identity, ports.tunnel, &keys.private, true),
        ),
        (
            "-fallback",
            ports.fallback,
            // Xray must be told where an unauthenticated connection goes; rust
            // falls back on its own.
            config::xray_server_with_fallback(
                &fallback_identity,
                ports.fallback,
                &keys.private,
                true,
                Some(&format!("127.0.0.1:{http_port}")),
            ),
        ),
    ];
    for (suffix, port, document) in configs {
        let path = workspace.join(&format!("{COMPARATOR}{suffix}-server.json"));
        std::fs::write(&path, document.to_python_json())
            .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        let mut child = Child::spawn(
            format!("{COMPARATOR}{suffix}-server"),
            &suite.xray_bin,
            &[
                "run".to_owned(),
                "-config".to_owned(),
                path.display().to_string(),
            ],
            workspace.path(),
            &[],
            &workspace.join(&format!("{COMPARATOR}{suffix}.log")),
        )
        .map_err(|error| error.to_string())?;
        child
            .wait_for_port(port, std::time::Duration::from_secs(30))
            .map_err(|error| error.to_string())?;
        children.push(child);
    }
    Ok(())
}
