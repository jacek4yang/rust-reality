//! The canonical repository quality gate.
//!
//! This is the typed repository gate that replaced `scripts/check.sh` and its
//! external Python policy validators. Repository policy runs in process; Cargo
//! and mature audit/build tools remain external mechanisms invoked with typed
//! argv.
//!
//! The terminal is a compact projection of the gate result. Complete stdout and
//! stderr remain available in finite, per-stage local logs, while human, agent,
//! and JSON modes expose the same decision through different renderings.

use std::{
    fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use clap::ValueEnum;

use crate::{
    perf::json_out::Json,
    process::{DEFAULT_CAPTURE_LIMIT, Tool, ToolError, terminal_excerpt},
};

/// How much of the gate to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Formatting, lint and the default test profile. The fast local loop.
    Fast,
    /// Everything CI enforces.
    All,
}

impl Scope {
    const fn label(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::All => "all",
        }
    }
}

/// Terminal representation of a check result.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputMode {
    /// Short readable progress lines plus one final decision.
    #[default]
    Human,
    /// Stable token-efficient records for a coding agent.
    Agent,
    /// One compact JSON result object on standard output.
    Json,
}

/// One gate step.
///
/// A step is either an external tool or a check rr-dev implements itself. Native
/// checks run in process rather than re-invoking `rr-dev` as a subprocess: that
/// keeps one implementation, avoids a second process per check, and means a
/// failure surfaces as a typed value instead of a parsed exit code.
enum Step {
    /// Delegate to an external program.
    External {
        /// Stable result label.
        label: String,
        /// The invocation.
        tool: Tool,
    },
    /// Run a check implemented inside rr-dev.
    Native {
        /// Stable result label.
        label: String,
        /// The check, returning complete bounded log text or a failure report.
        run: fn(&Path) -> Result<String, String>,
    },
    /// Run `RustSec` with its existing fresh-then-cached authority.
    Audit,
}

impl Step {
    /// The stable label for this step.
    fn label(&self) -> &str {
        match self {
            Self::External { label, .. } | Self::Native { label, .. } => label,
            Self::Audit => "cargo audit --deny warnings",
        }
    }

    /// Runs one step while retaining its complete bounded output streams.
    fn execute(&self, repo: &Path, logs: &StageLogs) -> StepExecution {
        let started = Instant::now();
        let result = match self {
            Self::External { tool, .. } => tool
                .clone()
                .log_output(&logs.stdout_path, &logs.stderr_path)
                .run()
                .map(|_| ())
                .map_err(|error| error.to_string()),
            Self::Native { run, .. } => execute_native(repo, logs, *run),
            Self::Audit => execute_audit(repo, logs),
        };
        StepExecution {
            elapsed: started.elapsed(),
            result,
        }
    }
}

struct StepExecution {
    elapsed: Duration,
    result: Result<(), String>,
}

/// The documentation policy, as a gate step.
fn docs_step() -> Step {
    Step::Native {
        label: "cargo dev docs check".to_owned(),
        run: |repo| {
            let report = crate::docs::check(repo);
            if report.is_clean() {
                Ok(report.render())
            } else {
                Err(report.render())
            }
        },
    }
}

/// The repository-layout policy, as a gate step.
fn repo_step() -> Step {
    Step::Native {
        label: "cargo dev repo check".to_owned(),
        run: |repo| {
            let report = crate::repo::check(repo);
            if report.is_clean() {
                Ok(report.render())
            } else {
                Err(report.render())
            }
        },
    }
}

impl Scope {
    /// Builds the ordered step list for this scope.
    ///
    /// Cheap native policy checks run before formatting, lint, and the expensive
    /// test profiles so structural failures are reported quickly.
    fn steps(self, repo: &Path) -> Vec<Step> {
        let mut steps = Vec::new();
        steps.push(repo_step());
        steps.push(docs_step());
        steps.extend(validator_steps());
        steps.extend(self.cargo_steps(repo));
        steps
    }

    /// The cargo half of the gate.
    ///
    /// Every stage names `--workspace` explicitly. Without it, cargo selects
    /// the default members — which for this repository is the root package
    /// alone — so `crates/rr-linux` and `crates/rr-session` would be neither
    /// linted, documented, nor tested by a gate that reports `PASS`. That is
    /// not a hypothetical: this gate once reported 15/15 while a workspace
    /// crate held a clippy error, and it ran 816 of the workspace's 874 tests.
    fn cargo_steps(self, repo: &Path) -> Vec<Step> {
        let mut steps = Vec::new();
        steps.push(cargo(
            repo,
            "cargo fmt --all --check",
            &["fmt", "--all", "--check"],
        ));
        steps.push(cargo(
            repo,
            "cargo clippy --workspace --all-targets --all-features --locked -- -D warnings",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--locked",
                "--",
                "-D",
                "warnings",
            ],
        ));

        if self == Self::All {
            steps.push(cargo(
                repo,
                "cargo deny --all-features check bans licenses sources",
                &[
                    "deny",
                    "--all-features",
                    "check",
                    "bans",
                    "licenses",
                    "sources",
                ],
            ));
            steps.push(Step::External {
                label: "cargo doc --workspace --all-features --locked --no-deps".to_owned(),
                tool: Tool::new("cargo")
                    .args([
                        "doc",
                        "--workspace",
                        "--all-features",
                        "--locked",
                        "--no-deps",
                    ])
                    .env("RUSTDOCFLAGS", "-D warnings")
                    .current_dir(repo),
            });
        }

        steps.push(Step::External {
            label: "cargo nextest run --workspace --all-features --locked".to_owned(),
            tool: Tool::new("cargo")
                .args([
                    "nextest",
                    "run",
                    "--profile",
                    "default",
                    "--workspace",
                    "--all-features",
                    "--locked",
                ])
                .current_dir(repo),
        });

        if self == Self::All {
            steps.push(cargo(
                repo,
                "cargo test --workspace --doc --all-features --locked",
                &["test", "--workspace", "--doc", "--all-features", "--locked"],
            ));
            steps.push(cargo(
                repo,
                "cargo test --workspace --release --all-features --locked",
                &[
                    "test",
                    "--workspace",
                    "--release",
                    "--all-features",
                    "--locked",
                ],
            ));
            steps.push(cargo(
                repo,
                "cargo test --workspace --benches --all-features --locked --no-run",
                &[
                    "test",
                    "--workspace",
                    "--benches",
                    "--all-features",
                    "--locked",
                    "--no-run",
                ],
            ));
            steps.push(Step::Audit);
        }

        steps
    }
}

/// Runs the advisory audit with the existing cached-retry fallback.
///
/// A transient registry outage must not turn a clean tree red, but a real
/// advisory still fails the gate. Both attempts share the one per-stage output
/// bound and append to the same stage logs.
fn execute_audit(repo: &Path, logs: &StageLogs) -> Result<(), String> {
    let fresh = Tool::new("cargo")
        .args(["audit", "--deny", "warnings"])
        .current_dir(repo)
        .log_output(&logs.stdout_path, &logs.stderr_path)
        .probe()
        .map_err(|error| error.to_string())?;
    if fresh.success() {
        return Ok(());
    }
    drop(fresh);

    append_bounded_log(
        &logs.stderr_path,
        b"\nfresh advisory retrieval failed; retrying the cached database without network access\n",
    )?;
    let stdout_remaining = remaining_log_capacity(&logs.stdout_path)?;
    let stderr_remaining = remaining_log_capacity(&logs.stderr_path)?;
    let remaining = stdout_remaining.min(stderr_remaining);
    Tool::new("cargo")
        .args(["audit", "--no-fetch", "--deny", "warnings"])
        .current_dir(repo)
        .capture_limit(remaining)
        .append_output(&logs.stdout_path, &logs.stderr_path)
        .run()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn execute_native(
    repo: &Path,
    logs: &StageLogs,
    run: fn(&Path) -> Result<String, String>,
) -> Result<(), String> {
    create_empty_logs(logs)?;
    match run(repo) {
        Ok(stdout) => write_bounded_log(&logs.stdout_path, stdout.as_bytes()),
        Err(stderr) => {
            write_bounded_log(&logs.stderr_path, stderr.as_bytes())?;
            Err(terminal_excerpt(&stderr))
        }
    }
}

fn create_empty_logs(logs: &StageLogs) -> Result<(), String> {
    write_bounded_log(&logs.stdout_path, b"")?;
    write_bounded_log(&logs.stderr_path, b"")
}

fn write_bounded_log(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let retained = bytes.len().min(DEFAULT_CAPTURE_LIMIT);
    fs::write(path, &bytes[..retained])
        .map_err(|error| format!("could not write stage log {}: {error}", path.display()))?;
    if retained != bytes.len() {
        return Err(format!(
            "native stage produced more than {DEFAULT_CAPTURE_LIMIT} bytes for {}",
            path.display()
        ));
    }
    Ok(())
}

fn append_bounded_log(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let remaining = remaining_log_capacity(path)?;
    if bytes.len() > remaining {
        return Err(format!(
            "stage log {} exceeded its {DEFAULT_CAPTURE_LIMIT}-byte bound",
            path.display()
        ));
    }
    let mut handle = fs::OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|error| format!("could not append stage log {}: {error}", path.display()))?;
    handle
        .write_all(bytes)
        .map_err(|error| format!("could not append stage log {}: {error}", path.display()))
}

fn remaining_log_capacity(path: &Path) -> Result<usize, String> {
    let bytes = fs::metadata(path)
        .map_err(|error| format!("could not inspect stage log {}: {error}", path.display()))?
        .len();
    let bytes = usize::try_from(bytes).unwrap_or(usize::MAX);
    Ok(DEFAULT_CAPTURE_LIMIT.saturating_sub(bytes))
}

/// The gate validators.
///
/// Every repository policy validator here is native rr-dev code. External tools
/// remain mechanisms in the cargo steps, never repository-owned Python policy.
fn validator_steps() -> Vec<Step> {
    vec![
        Step::Native {
            label: "fuzz target manifest".to_owned(),
            run: |repo| {
                crate::fuzz::targets::all(repo)
                    .map(|_| String::new())
                    .map_err(|error| error.to_string())
            },
        },
        Step::Native {
            label: "active-probe manifest".to_owned(),
            run: |repo| {
                crate::checks::probe_manifest::check(repo)
                    .map(|line| format!("{line}\n"))
                    .map_err(|error| error.to_string())
            },
        },
        Step::Native {
            label: "performance/cache contract".to_owned(),
            run: |repo| {
                crate::checks::perf_contract::check(repo)
                    .map(|line| format!("{line}\n"))
                    .map_err(|error| error.to_string())
            },
        },
        Step::Native {
            label: "deployment summary contract".to_owned(),
            run: |_repo| crate::deploy::summary::check_contract().map(|line| format!("{line}\n")),
        },
    ]
}

fn cargo(repo: &Path, label: &str, args: &[&str]) -> Step {
    Step::External {
        label: label.to_owned(),
        tool: Tool::new("cargo")
            .args(args.iter().copied())
            .current_dir(repo),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Pass,
    Fail,
}

impl Status {
    const fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone)]
struct StageLogs {
    stdout_file: String,
    stderr_file: String,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl StageLogs {
    fn new(run_dir: &Path, index: usize, label: &str) -> Self {
        let slug = stage_slug(label);
        let stdout_file = format!("{index:02}-{slug}.stdout.log");
        let stderr_file = format!("{index:02}-{slug}.stderr.log");
        Self {
            stdout_path: run_dir.join(&stdout_file),
            stderr_path: run_dir.join(&stderr_file),
            stdout_file,
            stderr_file,
        }
    }
}

#[derive(Debug, Clone)]
struct StageReport {
    index: usize,
    label: String,
    status: Status,
    elapsed: Duration,
    logs: StageLogs,
    reason: Option<String>,
}

#[derive(Debug)]
struct RunReport {
    scope: Scope,
    status: Status,
    total: usize,
    elapsed: Duration,
    log_dir: PathBuf,
    stages: Vec<StageReport>,
}

impl RunReport {
    fn passed(&self) -> usize {
        self.stages
            .iter()
            .filter(|stage| stage.status == Status::Pass)
            .count()
    }

    fn slowest(&self) -> Option<&StageReport> {
        self.stages.iter().max_by_key(|stage| stage.elapsed)
    }

    fn to_json(&self) -> Json {
        let stages = self
            .stages
            .iter()
            .map(|stage| {
                Json::object([
                    ("elapsedMilliseconds", duration_json(stage.elapsed)),
                    ("index", usize_json(stage.index)),
                    ("label", Json::string(stage.label.clone())),
                    (
                        "reason",
                        stage
                            .reason
                            .as_ref()
                            .map_or(Json::Null, |reason| Json::string(reason.clone())),
                    ),
                    ("status", Json::string(stage.status.label())),
                    ("stderrLog", Json::string(stage.logs.stderr_file.clone())),
                    ("stdoutLog", Json::string(stage.logs.stdout_file.clone())),
                ])
            })
            .collect();
        let slowest = self.slowest().map_or(Json::Null, |stage| {
            Json::object([
                ("elapsedMilliseconds", duration_json(stage.elapsed)),
                ("index", usize_json(stage.index)),
                ("label", Json::string(stage.label.clone())),
            ])
        });
        Json::object([
            ("attempted", usize_json(self.stages.len())),
            ("command", Json::string("check")),
            ("elapsedMilliseconds", duration_json(self.elapsed)),
            (
                "logDirectory",
                Json::string(self.log_dir.display().to_string()),
            ),
            ("passed", usize_json(self.passed())),
            ("protocol", Json::string("rr-dev-result/v1")),
            ("schemaVersion", Json::Int(1)),
            ("scope", Json::string(self.scope.label())),
            ("slowestStage", slowest),
            ("stages", Json::Array(stages)),
            ("status", Json::string(self.status.label())),
            ("total", usize_json(self.total)),
        ])
    }
}

/// Runs the gate, stopping at the first failure.
///
/// Every attempted stage gets independent stdout and stderr logs below a fresh
/// local directory. The return value is the gate decision; setup and log failures
/// fail the command closed just like a stage failure.
#[must_use]
pub fn run(
    repo: &Path,
    scope: Scope,
    output: OutputMode,
    requested_log_dir: Option<&Path>,
) -> bool {
    let steps = scope.steps(repo);
    let total = steps.len();
    let log_dir = match create_log_directory(repo, requested_log_dir) {
        Ok(path) => path,
        Err(error) => {
            emit_setup_failure(output, scope, total, requested_log_dir, &error);
            return false;
        }
    };
    emit(output, &render_start(output, scope, total, &log_dir));

    let started = Instant::now();
    let mut stages = Vec::with_capacity(total);
    if Tool::exists("cargo") {
        for (offset, step) in steps.iter().enumerate() {
            let index = offset + 1;
            let logs = StageLogs::new(&log_dir, index, step.label());
            let execution = step.execute(repo, &logs);
            let (status, reason) = match execution.result {
                Ok(()) => (Status::Pass, None),
                Err(error) => (Status::Fail, Some(error)),
            };
            let stage = StageReport {
                index,
                label: step.label().to_owned(),
                status,
                elapsed: execution.elapsed,
                logs,
                reason,
            };
            emit(output, &render_stage(output, total, &log_dir, &stage));
            stages.push(stage);
            if status == Status::Fail {
                break;
            }
        }
    } else {
        let mut error = ToolError::NotFound {
            program: "cargo".to_owned(),
        }
        .to_string();
        let logs = StageLogs::new(&log_dir, 1, steps[0].label());
        if let Err(log_error) = create_empty_logs(&logs) {
            error.push_str("; ");
            error.push_str(&log_error);
        }
        let stage = StageReport {
            index: 1,
            label: steps[0].label().to_owned(),
            status: Status::Fail,
            elapsed: Duration::ZERO,
            logs,
            reason: Some(error),
        };
        emit(output, &render_stage(output, total, &log_dir, &stage));
        stages.push(stage);
    }

    let status = if stages.len() == total && stages.iter().all(|stage| stage.status == Status::Pass)
    {
        Status::Pass
    } else {
        Status::Fail
    };
    let report = RunReport {
        scope,
        status,
        total,
        elapsed: started.elapsed(),
        log_dir,
        stages,
    };
    emit(output, &render_final(output, &report));
    status == Status::Pass
}

fn create_log_directory(repo: &Path, requested: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(requested) = requested {
        let path = if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            repo.join(requested)
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!("could not create log parent {}: {error}", parent.display())
            })?;
        }
        fs::create_dir(&path).map_err(|error| {
            format!(
                "check log directory must be new ({}): {error}",
                path.display()
            )
        })?;
        return Ok(path);
    }

    let parent = repo.join("target/rr-dev/check");
    fs::create_dir_all(&parent).map_err(|error| {
        format!(
            "could not create default check log parent {}: {error}",
            parent.display()
        )
    })?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock predates Unix epoch: {error}"))?
        .as_millis();
    for suffix in 0_u16..=u16::MAX {
        let discriminator = if suffix == 0 {
            String::new()
        } else {
            format!("-{suffix}")
        };
        let path = parent.join(format!("{stamp}-{}{}", std::process::id(), discriminator));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!(
                    "could not create check log directory {}: {error}",
                    path.display()
                ));
            }
        }
    }
    Err(format!(
        "could not allocate a unique check log directory below {}",
        parent.display()
    ))
}

fn stage_slug(label: &str) -> String {
    let mut slug = String::new();
    let mut separated = false;
    for byte in label.bytes() {
        if byte.is_ascii_alphanumeric() {
            if separated && !slug.is_empty() {
                slug.push('-');
            }
            slug.push(char::from(byte.to_ascii_lowercase()));
            separated = false;
        } else {
            separated = true;
        }
        if slug.len() >= 64 {
            break;
        }
    }
    slug.trim_end_matches('-').to_owned()
}

fn render_start(mode: OutputMode, scope: Scope, total: usize, log_dir: &Path) -> String {
    match mode {
        OutputMode::Human => format!(
            "check {}: {total} stages; full logs: {}\n",
            scope.label(),
            log_dir.display()
        ),
        OutputMode::Agent => format!(
            "CHECK_START scope={} total={total} logs={}\n",
            scope.label(),
            json_string(&log_dir.display().to_string())
        ),
        OutputMode::Json => String::new(),
    }
}

fn render_stage(mode: OutputMode, total: usize, log_dir: &Path, stage: &StageReport) -> String {
    match mode {
        OutputMode::Human => {
            let mut rendered = format!(
                "[{index:02}/{total:02}] {status} {label} ({elapsed})\n",
                index = stage.index,
                status = stage.status.label(),
                label = stage.label,
                elapsed = human_duration(stage.elapsed)
            );
            if let Some(reason) = &stage.reason {
                rendered.push_str("reason: ");
                rendered.push_str(reason);
                rendered.push('\n');
                rendered.push_str("stderr log: ");
                rendered.push_str(&log_dir.join(&stage.logs.stderr_file).display().to_string());
                rendered.push('\n');
            }
            rendered
        }
        OutputMode::Agent => {
            let reason = stage
                .reason
                .as_ref()
                .map_or_else(|| "null".to_owned(), |reason| json_string(reason));
            format!(
                "CHECK_STAGE index={index} total={total} status={status} elapsed_ms={elapsed} label={label} stdout={stdout} stderr={stderr} reason={reason}\n",
                index = stage.index,
                status = stage.status.label(),
                elapsed = stage.elapsed.as_millis(),
                label = json_string(&stage.label),
                stdout = json_string(&stage.logs.stdout_file),
                stderr = json_string(&stage.logs.stderr_file),
            )
        }
        OutputMode::Json => String::new(),
    }
}

fn render_final(mode: OutputMode, report: &RunReport) -> String {
    match mode {
        OutputMode::Human => {
            let slowest = report.slowest().map_or_else(
                || "none".to_owned(),
                |stage| format!("{} ({})", stage.label, human_duration(stage.elapsed)),
            );
            format!(
                "{status} check {scope}: {passed}/{total} passed in {elapsed}; slowest: {slowest}; logs: {logs}\n",
                status = report.status.label(),
                scope = report.scope.label(),
                passed = report.passed(),
                total = report.total,
                elapsed = human_duration(report.elapsed),
                logs = report.log_dir.display(),
            )
        }
        OutputMode::Agent => {
            let slowest = report.slowest();
            format!(
                "CHECK_RESULT status={status} scope={scope} passed={passed} attempted={attempted} total={total} elapsed_ms={elapsed} slowest_index={slowest_index} slowest_ms={slowest_ms} logs={logs}\n",
                status = report.status.label(),
                scope = report.scope.label(),
                passed = report.passed(),
                attempted = report.stages.len(),
                total = report.total,
                elapsed = report.elapsed.as_millis(),
                slowest_index = slowest.map_or(0, |stage| stage.index),
                slowest_ms = slowest.map_or(0, |stage| stage.elapsed.as_millis()),
                logs = json_string(&report.log_dir.display().to_string()),
            )
        }
        OutputMode::Json => format!("{}\n", report.to_json().to_jq_json()),
    }
}

fn emit_setup_failure(
    mode: OutputMode,
    scope: Scope,
    total: usize,
    requested_log_dir: Option<&Path>,
    reason: &str,
) {
    let logs =
        requested_log_dir.map_or(Json::Null, |path| Json::string(path.display().to_string()));
    let rendered = match mode {
        OutputMode::Human => format!("FAIL check {} setup: {reason}\n", scope.label()),
        OutputMode::Agent => format!(
            "CHECK_RESULT status=FAIL scope={} passed=0 attempted=0 total={total} elapsed_ms=0 slowest_index=0 slowest_ms=0 logs={} reason={}\n",
            scope.label(),
            requested_log_dir.map_or_else(
                || "null".to_owned(),
                |path| { json_string(&path.display().to_string()) }
            ),
            json_string(reason)
        ),
        OutputMode::Json => {
            Json::object([
                ("attempted", Json::Int(0)),
                ("command", Json::string("check")),
                ("elapsedMilliseconds", Json::Int(0)),
                ("logDirectory", logs),
                ("passed", Json::Int(0)),
                ("protocol", Json::string("rr-dev-result/v1")),
                ("reason", Json::string(reason)),
                ("schemaVersion", Json::Int(1)),
                ("scope", Json::string(scope.label())),
                ("slowestStage", Json::Null),
                ("stages", Json::Array(Vec::new())),
                ("status", Json::string("FAIL")),
                ("total", usize_json(total)),
            ])
            .to_jq_json()
                + "\n"
        }
    };
    emit(mode, &rendered);
}

fn emit(mode: OutputMode, rendered: &str) {
    if rendered.is_empty() {
        return;
    }
    print!("{rendered}");
    if mode != OutputMode::Json {
        let _ = io::stdout().flush();
    }
}

fn json_string(text: &str) -> String {
    Json::string(text).to_jq_json()
}

fn usize_json(value: usize) -> Json {
    Json::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

fn duration_json(value: Duration) -> Json {
    Json::Int(i64::try_from(value.as_millis()).unwrap_or(i64::MAX))
}

fn human_duration(value: Duration) -> String {
    if value < Duration::from_secs(1) {
        format!("{}ms", value.as_millis())
    } else {
        format!("{:.1}s", value.as_secs_f64())
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    fn repo_root() -> PathBuf {
        // tools/rr-dev/src -> tools/rr-dev -> tools -> repository root
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("the manifest must sit three levels below the repository root")
            .to_path_buf()
    }

    fn sample_report(status: Status) -> RunReport {
        let log_dir = PathBuf::from("/repo/target/rr-dev/check/example");
        let logs = StageLogs::new(&log_dir, 1, "cargo fmt --all --check");
        RunReport {
            scope: Scope::All,
            status,
            total: 15,
            elapsed: Duration::from_millis(1250),
            log_dir,
            stages: vec![StageReport {
                index: 1,
                label: "cargo fmt --all --check".to_owned(),
                status,
                elapsed: Duration::from_millis(20),
                logs,
                reason: (status == Status::Fail).then(|| "format mismatch".to_owned()),
            }],
        }
    }

    #[test]
    fn the_full_scope_is_a_superset_of_the_fast_scope() {
        let repo = repo_root();
        let fast: Vec<String> = Scope::Fast
            .steps(&repo)
            .into_iter()
            .map(|step| step.label().to_owned())
            .collect();
        let all: Vec<String> = Scope::All
            .steps(&repo)
            .into_iter()
            .map(|step| step.label().to_owned())
            .collect();
        for label in &fast {
            assert!(
                all.contains(label),
                "the fast scope must never run a step the full scope skips: {label}"
            );
        }
        assert!(
            all.len() > fast.len(),
            "the full scope must add steps, otherwise the split is pointless"
        );
    }

    #[test]
    fn every_cargo_build_stage_covers_the_whole_workspace() {
        // Without `--workspace`, cargo selects the default members — the root
        // package alone — so `crates/rr-linux` and `crates/rr-session` would be
        // silently excluded from a gate that still reports `PASS`. `fmt --all`
        // and `deny`, which read the whole workspace by construction, and
        // `audit`, which reads the lockfile, are the deliberate exceptions.
        let repo = repo_root();
        for step in Scope::All.steps(&repo) {
            let Step::External { label, tool } = &step else {
                continue;
            };
            let rendered = tool.redacted();
            let selects_by_default = label.contains("cargo fmt") || label.contains("cargo deny");
            if selects_by_default {
                continue;
            }
            assert!(
                rendered.contains("--workspace"),
                "gate stage must not silently skip workspace crates: {label}"
            );
        }
    }

    #[test]
    fn steps_never_route_through_a_shell_interpreter() {
        let repo = repo_root();
        for step in Scope::All.steps(&repo) {
            let rendered = match &step {
                Step::External { tool, .. } => tool.redacted(),
                Step::Native { label, .. } => label.clone(),
                Step::Audit => step.label().to_owned(),
            };
            assert!(
                !rendered.contains("sh -c"),
                "no gate step may build a shell command line: {rendered}"
            );
        }
    }

    #[test]
    fn repository_policy_steps_are_native() {
        for step in validator_steps() {
            assert!(
                matches!(step, Step::Native { .. }),
                "repository validators must not invoke external scripts"
            );
        }
    }

    #[test]
    fn json_mode_is_one_compact_protocol_record() {
        let rendered = render_final(OutputMode::Json, &sample_report(Status::Pass));
        assert_eq!(rendered.lines().count(), 1);
        assert!(rendered.contains("\"protocol\":\"rr-dev-result/v1\""));
        assert!(rendered.contains("\"status\":\"PASS\""));
        assert!(rendered.contains("\"stdoutLog\":\"01-cargo-fmt-all-check.stdout.log\""));
    }

    #[test]
    fn agent_mode_keeps_a_failure_on_one_parseable_line() {
        let report = sample_report(Status::Fail);
        let rendered = render_stage(
            OutputMode::Agent,
            report.total,
            &report.log_dir,
            &report.stages[0],
        );
        assert_eq!(rendered.lines().count(), 1);
        assert!(rendered.contains("status=FAIL"));
        assert!(rendered.contains("reason=\"format mismatch\""));
    }

    #[test]
    fn human_mode_names_the_decision_and_retained_logs() {
        let report = sample_report(Status::Pass);
        let rendered = render_final(OutputMode::Human, &report);
        assert!(rendered.starts_with("PASS check all: 1/15 passed"));
        assert!(rendered.contains("logs: /repo/target/rr-dev/check/example"));
    }

    #[test]
    fn stage_log_names_are_bounded_and_path_safe() {
        let logs = StageLogs::new(
            Path::new("/tmp/logs"),
            9,
            "cargo clippy --all-targets -- -D warnings / ../../secret",
        );
        assert!(logs.stdout_file.starts_with("09-cargo-clippy-all-targets"));
        assert!(!logs.stdout_file.contains('/'));
        assert!(logs.stdout_file.len() < 100);
    }

    #[test]
    fn a_requested_log_directory_is_fresh_and_never_overwritten() {
        let scratch = std::env::temp_dir().join(format!(
            "rr-dev-check-dir-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let created = create_log_directory(Path::new("/repo"), Some(&scratch)).unwrap();
        assert_eq!(created, scratch);
        let error = create_log_directory(Path::new("/repo"), Some(&scratch)).unwrap_err();
        assert!(error.contains("must be new"), "{error}");
        fs::remove_dir_all(scratch).unwrap();
    }

    #[test]
    fn native_failure_retains_the_complete_report_but_returns_a_terminal_excerpt() {
        fn fail(_repo: &Path) -> Result<String, String> {
            let report = (1..=40).fold(String::new(), |mut report, line| {
                writeln!(report, "line {line}").expect("writing to a string cannot fail");
                report
            });
            Err(report)
        }

        let scratch = std::env::temp_dir().join(format!(
            "rr-dev-check-native-log-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&scratch).unwrap();
        let logs = StageLogs::new(&scratch, 1, "native failure");
        let error = execute_native(Path::new("/repo"), &logs, fail).unwrap_err();
        let retained = fs::read_to_string(&logs.stderr_path).unwrap();
        assert!(retained.starts_with("line 1\n"));
        assert!(retained.ends_with("line 40\n"));
        assert!(error.starts_with("… 20 earlier lines omitted"), "{error}");
        assert!(!error.contains("line 1\n"), "{error}");
        fs::remove_dir_all(scratch).unwrap();
    }
}
