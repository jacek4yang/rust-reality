//! Identity-bound `perf` environment evidence — the typed form of
//! `perf-stat-evidence.py` and `perf-c2c-evidence.py`.
//!
//! Both capture a `perf` measurement of a workload that must execute a specific,
//! hash-identified binary, then write atomic JSON recording the environment and a
//! three-valued status. The distinction the scripts drew is preserved: a run that
//! `perf` refused for permission or capability reasons is `UNAVAILABLE` (a true
//! fact about the host, never a fabricated number), a clean run is `PASS`, and a
//! genuine failure is `FAIL`. The binary SHA-256 and the requirement that the
//! workload command executes exactly that binary are load-bearing: evidence is
//! only meaningful when bound to the artifact it measured.
//!
//! `perf` stays external mechanism; this module owns identity binding, status
//! classification, environment capture and atomic evidence writing.

use std::path::{Path, PathBuf};

use crate::{perf::json_out::Json, process::Tool};

/// The fixed `perf stat` event set, matching the script.
const STAT_EVENTS: &str = "task-clock,cycles,instructions,branches,branch-misses,cache-references,cache-misses,context-switches,cpu-migrations,page-faults";

/// Substrings in `perf` diagnostics that mean the measurement was unavailable.
const UNAVAILABLE_MARKERS: [&str; 4] = [
    "permission",
    "not supported",
    "no permission",
    "access to performance monitoring",
];

/// Which perf tool to run.
#[derive(Debug, Clone, Copy)]
pub enum Kind {
    /// `perf stat -x ';' -e <events>`.
    Stat,
    /// `perf c2c record` then `perf c2c report --stdio`.
    C2c,
}

/// Arguments common to both evidence captures.
pub struct Options<'a> {
    /// Where to write the evidence JSON (atomically).
    pub output: &'a Path,
    /// The binary the workload must execute.
    pub binary: &'a Path,
    /// The expected lowercase-hex SHA-256 of that binary.
    pub binary_sha256: &'a str,
    /// The workload command and its arguments (argv[0] must be the binary).
    pub command: &'a [String],
}

/// Captures identity-bound perf evidence.
///
/// # Errors
///
/// Returns a message on an empty command, a binary hash mismatch, a workload that
/// does not execute the identified binary, or a `perf` run classified `FAIL`. The
/// evidence file is written before a `FAIL` is returned, matching the scripts.
pub fn capture(kind: Kind, options: &Options) -> Result<String, String> {
    if options.command.is_empty() {
        return Err("a workload command is required".to_owned());
    }
    let binary = canonical(options.binary)?;
    let actual = crate::hash::sha256_file(&binary)?;
    if actual != options.binary_sha256.to_ascii_lowercase() {
        return Err("binary SHA-256 mismatch".to_owned());
    }
    let command_binary = canonical(Path::new(&options.command[0]))?;
    if command_binary != binary {
        return Err("workload must execute the identified binary".to_owned());
    }
    if let Some(parent) = options.output.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("could not create output directory: {error}"))?;
    }

    let capture = match kind {
        Kind::Stat => run_stat(options.command),
        Kind::C2c => run_c2c(options.command),
    }?;

    let evidence = build_evidence(kind, options, &binary, &capture);
    write_atomic(options.output, &evidence.to_python_json())?;

    if capture.status == Status::Fail {
        return Err(format!("perf {} evidence: FAIL", kind_tool(kind)));
    }
    Ok(format!(
        "perf {} evidence: {} -> {}",
        kind_tool(kind),
        capture.status.as_str(),
        options.output.display()
    ))
}

/// Three-valued measurement status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Pass,
    Unavailable,
    Fail,
}

impl Status {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Unavailable => "UNAVAILABLE",
            Self::Fail => "FAIL",
        }
    }
}

/// The outcome of running the perf tool.
struct Capture {
    status: Status,
    exit_code: Option<i32>,
    report_exit_code: Option<i32>,
    raw: String,
    report: String,
    diagnostic: String,
    unavailable_reason: Option<String>,
    workload_stdout_sha256: String,
}

fn run_stat(command: &[String]) -> Result<Capture, String> {
    let scratch = crate::release::package::tempdir("rr-perf-stat")?;
    let raw_path = scratch.path().join("perf.csv");
    let outcome = Tool::new("perf")
        .args(["stat", "-x", ";", "-e", STAT_EVENTS, "-o"])
        .arg(raw_path.to_string_lossy().into_owned())
        .arg("--")
        .args(command.iter().cloned())
        .probe()
        .map_err(|error| format!("perf stat failed to start: {error}"))?;
    let raw = std::fs::read_to_string(&raw_path).unwrap_or_default();
    let diagnostic = format!("{raw}{}", outcome.stderr);
    let unavailable = !outcome.success() && is_unavailable(&diagnostic);
    let status = classify(outcome.success(), unavailable);
    Ok(Capture {
        status,
        exit_code: outcome.code,
        report_exit_code: None,
        raw,
        report: String::new(),
        diagnostic: outcome.stderr.clone(),
        unavailable_reason: unavailable.then(|| diagnostic.trim().to_owned()),
        workload_stdout_sha256: crate::hash::sha256_hex(outcome.stdout.as_bytes()),
    })
}

fn run_c2c(command: &[String]) -> Result<Capture, String> {
    let scratch = crate::release::package::tempdir("rr-perf-c2c")?;
    let data_path = scratch.path().join("perf.data");
    let record = Tool::new("perf")
        .args(["c2c", "record", "-o"])
        .arg(data_path.to_string_lossy().into_owned())
        .arg("--")
        .args(command.iter().cloned())
        .probe()
        .map_err(|error| format!("perf c2c record failed to start: {error}"))?;
    let report = if record.success() {
        Some(
            Tool::new("perf")
                .args(["c2c", "report", "-i"])
                .arg(data_path.to_string_lossy().into_owned())
                .arg("--stdio")
                .probe()
                .map_err(|error| format!("perf c2c report failed to start: {error}"))?,
        )
    } else {
        None
    };
    let report_stderr = report
        .as_ref()
        .map(|r| r.stderr.clone())
        .unwrap_or_default();
    let diagnostic = format!("{}{report_stderr}", record.stderr);
    let unavailable = !record.success() && is_unavailable(&diagnostic);
    let report_ok = report
        .as_ref()
        .is_some_and(crate::process::Outcome::success);
    let status = if unavailable {
        Status::Unavailable
    } else if record.success() && report_ok {
        Status::Pass
    } else {
        Status::Fail
    };
    Ok(Capture {
        status,
        exit_code: record.code,
        report_exit_code: report.as_ref().and_then(|r| r.code),
        raw: String::new(),
        report: report
            .as_ref()
            .map(|r| r.stdout.clone())
            .unwrap_or_default(),
        diagnostic,
        unavailable_reason: unavailable.then(|| {
            format!("{}{report_stderr}", record.stderr)
                .trim()
                .to_owned()
        }),
        workload_stdout_sha256: String::new(),
    })
}

fn build_evidence(kind: Kind, options: &Options, binary: &Path, capture: &Capture) -> Json {
    let command: Vec<Json> = options.command.iter().cloned().map(Json::string).collect();
    let mut entries: Vec<(String, Json)> = vec![
        ("schemaVersion".to_owned(), Json::Int(1)),
        (
            "tool".to_owned(),
            Json::string(format!("perf-{}", kind_tool(kind))),
        ),
        ("status".to_owned(), Json::string(capture.status.as_str())),
        (
            "binary".to_owned(),
            Json::object([
                ("path", Json::string(binary.to_string_lossy().into_owned())),
                (
                    "sha256",
                    Json::string(options.binary_sha256.to_ascii_lowercase()),
                ),
            ]),
        ),
        ("command".to_owned(), Json::Array(command)),
        ("perfVersion".to_owned(), Json::string(perf_version())),
        (
            "kernel".to_owned(),
            Json::string(platform("uname", &["-r"])),
        ),
        (
            "machine".to_owned(),
            Json::string(platform("uname", &["-m"])),
        ),
    ];
    match kind {
        Kind::Stat => {
            let events: Vec<Json> = STAT_EVENTS.split(',').map(Json::string).collect();
            entries.push(("events".to_owned(), Json::Array(events)));
            entries.push(("exitCode".to_owned(), int_or_null(capture.exit_code)));
            entries.push(("raw".to_owned(), Json::string(capture.raw.clone())));
            entries.push((
                "workloadStdoutSha256".to_owned(),
                Json::string(capture.workload_stdout_sha256.clone()),
            ));
        }
        Kind::C2c => {
            entries.push(("recordExitCode".to_owned(), int_or_null(capture.exit_code)));
            entries.push((
                "reportExitCode".to_owned(),
                int_or_null(capture.report_exit_code),
            ));
            entries.push(("report".to_owned(), Json::string(capture.report.clone())));
        }
    }
    entries.push((
        "diagnostic".to_owned(),
        Json::string(capture.diagnostic.clone()),
    ));
    entries.push((
        "unavailableReason".to_owned(),
        capture
            .unavailable_reason
            .clone()
            .map_or(Json::Null, Json::string),
    ));
    Json::Object(entries.into_iter().collect())
}

fn classify(success: bool, unavailable: bool) -> Status {
    if unavailable {
        Status::Unavailable
    } else if success {
        Status::Pass
    } else {
        Status::Fail
    }
}

fn is_unavailable(diagnostic: &str) -> bool {
    let lowered = diagnostic.to_ascii_lowercase();
    UNAVAILABLE_MARKERS
        .iter()
        .any(|marker| lowered.contains(marker))
}

const fn kind_tool(kind: Kind) -> &'static str {
    match kind {
        Kind::Stat => "stat",
        Kind::C2c => "c2c",
    }
}

fn int_or_null(code: Option<i32>) -> Json {
    code.map_or(Json::Null, |value| Json::Int(i64::from(value)))
}

fn perf_version() -> String {
    Tool::new("perf")
        .arg("--version")
        .probe()
        .map(|outcome| outcome.trimmed_stdout().to_owned())
        .unwrap_or_default()
}

fn platform(program: &str, args: &[&str]) -> String {
    Tool::new(program)
        .args(args.iter().copied())
        .probe()
        .map(|outcome| outcome.trimmed_stdout().to_owned())
        .unwrap_or_default()
}

fn canonical(path: &Path) -> Result<PathBuf, String> {
    std::fs::canonicalize(path).map_err(|error| format!("{}: {error}", path.display()))
}

/// Writes `contents` to `path` atomically via a sibling temp file.
fn write_atomic(path: &Path, contents: &str) -> Result<(), String> {
    let temp = path.with_file_name(format!(
        ".{}.tmp",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    std::fs::write(&temp, contents)
        .map_err(|error| format!("could not write evidence: {error}"))?;
    std::fs::rename(&temp, path).map_err(|error| format!("could not place evidence: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_diagnostics_are_classified_unavailable() {
        assert!(is_unavailable(
            "Error: Access to performance monitoring is restricted"
        ));
        assert!(is_unavailable("perf_event_open: Permission denied"));
        assert!(!is_unavailable("workload exited with status 1"));
    }

    #[test]
    fn status_classification_is_three_valued() {
        assert_eq!(classify(true, false), Status::Pass);
        assert_eq!(classify(false, true), Status::Unavailable);
        assert_eq!(classify(false, false), Status::Fail);
        // Unavailable dominates even if the tool technically failed.
        assert_eq!(classify(false, true), Status::Unavailable);
    }
}
