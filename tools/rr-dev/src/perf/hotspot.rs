//! Identity-bound `perf record` capture for hotspot investigation.
//!
//! Rust owns the policy formerly split across `profile-forensics.sh` and its
//! compatibility wrapper: bounded arguments, immutable binary identity, exact
//! PID/start-time ownership, host exclusion, archival, perf invocation, report
//! generation, checksums, failure state and final publication. `perf`, `readelf`
//! and `sudo` remain external mechanisms invoked with typed argv.

#![allow(
    clippy::too_many_lines,
    reason = "the capture lifecycle and its bounded evidence schemas are intentionally explicit"
)]

use std::{
    fmt::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    bench::{
        attest,
        evidence::{Publication, RunDirectory, utc_timestamp},
        host_lock::HostLock,
        identity::{self, Kind},
        process::{Child, proc_starttime},
        runner,
    },
    hash,
    perf::{json_in, json_out::Json},
    process::{Outcome, Tool},
};

#[path = "hotspot_bundle.rs"]
pub mod bundle;

const MAX_RECORD_SECONDS: u64 = 300;
const MAX_DURATION_MS: u64 = 600_000;
const MIN_BENCHMARK_WARMUP_MS: u64 = 1;
const MAX_BENCHMARK_WARMUP_MS: u64 = 10_000;
const MAX_FREQUENCY: u32 = 9_999;
const MAX_DWARF_BYTES: u32 = 65_528;
const MAX_PERF_OUTPUT_BYTES: usize = 64 * 1024;
const PERF_STDOUT: &str = "perf.stdout";
const PERF_STDERR: &str = "perf.stderr";

/// Which process supplies samples to `perf record`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Launch and own `rust-reality benchmark`.
    BuiltIn,
    /// Attach to an already-running, exactly identified server.
    AttachServer,
}

impl Mode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::BuiltIn => "built-in",
            Self::AttachServer => "attach-server",
        }
    }
}

/// One forensic profile capture request.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Repository root used as the child working directory.
    pub repo: PathBuf,
    /// Capture mode.
    pub mode: Mode,
    /// Exact rust-reality binary.
    pub binary: PathBuf,
    /// Required expected binary SHA-256.
    pub binary_sha256: String,
    /// Required source commit embedded in the binary identity.
    pub expected_source_commit: String,
    /// Existing server PID for attach mode.
    pub server_pid: Option<u32>,
    /// New absolute evidence directory.
    pub out_dir: PathBuf,
    /// Stable publication identifier.
    pub run_id: String,
    /// Maximum capture duration.
    pub record_seconds: u64,
    /// Built-in benchmark duration.
    pub duration_ms: u64,
    /// Built-in benchmark warmup.
    pub warmup_ms: u64,
    /// `perf record` event selector.
    pub event: String,
    /// Sampling frequency.
    pub frequency: u32,
    /// `perf record --call-graph` value.
    pub call_graph: String,
}

#[derive(Debug, Clone)]
struct ProcessIdentity {
    pid: u32,
    starttime: String,
    sha256_pre: String,
    sha256_post: Option<String>,
    build_id_pre: String,
    build_id_post: Option<String>,
}

#[derive(Debug, Default)]
struct Status {
    perf_exit: Option<i32>,
    perf_elapsed_millis: Option<u64>,
    workload_exit: Option<i32>,
    process: Option<ProcessIdentity>,
}

#[derive(Debug, Clone, Copy)]
struct PerfRecord {
    exit_code: i32,
    elapsed_millis: u64,
}

#[derive(Debug, Clone, Copy)]
enum ContractState<'a> {
    Running,
    Failed(&'a str),
    Complete(&'a str),
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_call_graph(value: &str) -> bool {
    if matches!(value, "fp" | "lbr" | "dwarf") {
        return true;
    }
    value
        .strip_prefix("dwarf,")
        .and_then(|bytes| bytes.parse::<u32>().ok())
        .is_some_and(|bytes| bytes > 0 && bytes <= MAX_DWARF_BYTES)
}

/// Validates a plan without touching the host.
///
/// # Errors
///
/// Returns one actionable argument diagnostic.
pub fn validate(plan: &Plan) -> Result<(), String> {
    if !valid_hex(&plan.binary_sha256, 64) {
        return Err("--binary-sha256 must be 64 lowercase hexadecimal characters".to_owned());
    }
    if !valid_hex(&plan.expected_source_commit, 40) {
        return Err(
            "--expected-source-commit must be 40 lowercase hexadecimal characters".to_owned(),
        );
    }
    if plan.out_dir.as_os_str().is_empty() || !plan.out_dir.is_absolute() {
        return Err("--out-dir must be an absolute path".to_owned());
    }
    if plan.out_dir.symlink_metadata().is_ok() {
        return Err(format!(
            "--out-dir must not already exist: {}",
            plan.out_dir.display()
        ));
    }
    if plan.run_id.is_empty() {
        return Err("--run-id must not be empty".to_owned());
    }
    if plan.record_seconds == 0 || plan.record_seconds > MAX_RECORD_SECONDS {
        return Err("--record-seconds must be in 1..=300".to_owned());
    }
    if plan.duration_ms == 0 || plan.duration_ms > MAX_DURATION_MS {
        return Err("--duration-ms must be in 1..=600000".to_owned());
    }
    if !(MIN_BENCHMARK_WARMUP_MS..=MAX_BENCHMARK_WARMUP_MS).contains(&plan.warmup_ms)
    {
        return Err("--warmup-ms must be in 1..=10000".to_owned());
    }
    if plan.frequency == 0 || plan.frequency > MAX_FREQUENCY {
        return Err("--frequency must be in 1..=9999".to_owned());
    }
    if plan.event.is_empty() {
        return Err("--event must not be empty".to_owned());
    }
    if !validate_call_graph(&plan.call_graph) {
        return Err("--call-graph must be fp, lbr, dwarf, or dwarf,BYTES<=65528".to_owned());
    }
    match (plan.mode, plan.server_pid) {
        (Mode::BuiltIn, None) | (Mode::AttachServer, Some(1..)) => Ok(()),
        (Mode::BuiltIn, Some(_)) => Err("--pid is valid only with --mode attach-server".to_owned()),
        (Mode::AttachServer, _) => {
            Err("--pid is required and must be positive with --mode attach-server".to_owned())
        }
    }
}

fn embedded_commit(identity: &str) -> Result<String, String> {
    json_in::parse(identity)
        .and_then(|value| {
            value
                .field("environment", "gitCommit")
                .and_then(|commit| commit.as_str("environment.gitCommit"))
                .map(str::to_owned)
                .map_err(|error| error.to_string())
        })
        .map_err(|error| format!("rust-reality binary identity: {error}"))
}

fn inspect_process(pid: u32, expected_sha: &str, expected_build_id: &str) -> Result<ProcessIdentity, String> {
    let starttime = proc_starttime(pid).ok_or_else(|| format!("PID {pid} is not alive"))?;
    let sha256 = attest::running_executable_sha256(pid)?;
    if sha256 != expected_sha {
        return Err(format!(
            "PID {pid} executable SHA-256 mismatch: expected {expected_sha}, got {sha256}"
        ));
    }
    let build_id = attest::build_id(&PathBuf::from(format!("/proc/{pid}/exe")))?;
    if build_id != expected_build_id {
        return Err(format!(
            "PID {pid} executable Build ID mismatch: expected {expected_build_id}, got {build_id}"
        ));
    }
    Ok(ProcessIdentity {
        pid,
        starttime,
        sha256_pre: sha256,
        sha256_post: None,
        build_id_pre: build_id,
        build_id_post: None,
    })
}

fn verify_process(identity: &mut ProcessIdentity) -> Result<(), String> {
    let observed = proc_starttime(identity.pid)
        .ok_or_else(|| format!("PID {} exited during profile capture", identity.pid))?;
    if observed != identity.starttime {
        return Err(format!(
            "PID {} starttime changed during profile capture",
            identity.pid
        ));
    }
    let sha256 = attest::running_executable_sha256(identity.pid)?;
    let build_id = attest::build_id(&PathBuf::from(format!(
        "/proc/{}/exe",
        identity.pid
    )))?;
    if sha256 != identity.sha256_pre || build_id != identity.build_id_pre {
        return Err(format!(
            "PID {} executable identity changed during profile capture",
            identity.pid
        ));
    }
    identity.sha256_post = Some(sha256);
    identity.build_id_post = Some(build_id);
    Ok(())
}

fn tool_stdout(program: &str, args: &[&str]) -> String {
    Tool::new(program)
        .args(args.iter().copied())
        .probe()
        .ok()
        .filter(crate::process::Outcome::success)
        .map_or_else(String::new, |outcome| outcome.trimmed_stdout().to_owned())
}

fn metadata(
    plan: &Plan,
    state: &str,
    exit_code: Option<i32>,
    binary: &identity::Binary,
    build_id: &str,
    archived: &Path,
    status: &Status,
) -> Json {
    let process = status.process.as_ref().map_or(Json::Null, |process| {
        Json::object([
            ("pid", Json::Int(i64::from(process.pid))),
            (
                "starttime",
                Json::Int(process.starttime.parse::<i64>().unwrap_or(-1)),
            ),
            ("exeSha256Pre", Json::string(&process.sha256_pre)),
            (
                "exeSha256Post",
                process
                    .sha256_post
                    .as_deref()
                    .map_or(Json::Null, Json::string),
            ),
            ("exeBuildIdPre", Json::string(&process.build_id_pre)),
            (
                "exeBuildIdPost",
                process
                    .build_id_post
                    .as_deref()
                    .map_or(Json::Null, Json::string),
            ),
        ])
    });
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    Json::object([
        ("schemaVersion", Json::Int(2)),
        ("state", Json::string(state)),
        (
            "exitCode",
            exit_code.map_or(Json::Null, |code| Json::Int(i64::from(code))),
        ),
        ("runId", Json::string(&plan.run_id)),
        ("mode", Json::string(plan.mode.as_str())),
        (
            "updatedAt",
            Json::string(utc_timestamp(i64::try_from(now).unwrap_or(i64::MAX))),
        ),
        ("sourceBinary", Json::string(binary.path.display().to_string())),
        ("archivedBinary", Json::string(archived.display().to_string())),
        ("binarySha256", Json::string(&binary.sha256)),
        ("binaryBuildId", Json::string(build_id)),
        (
            "binarySourceCommit",
            Json::string(&plan.expected_source_commit),
        ),
        ("profileProcess", process),
        (
            "perf",
            Json::object([
                ("version", Json::string(tool_stdout("perf", &["--version"]))),
                ("event", Json::string(&plan.event)),
                ("frequency", Json::Int(i64::from(plan.frequency))),
                ("callGraph", Json::string(&plan.call_graph)),
                (
                    "recordSeconds",
                    Json::Int(i64::try_from(plan.record_seconds).unwrap_or(i64::MAX)),
                ),
                (
                    "exitCode",
                    status
                        .perf_exit
                        .map_or(Json::Null, |code| Json::Int(i64::from(code))),
                ),
                (
                    "elapsedMillis",
                    status.perf_elapsed_millis.map_or(Json::Null, |millis| {
                        Json::Int(i64::try_from(millis).unwrap_or(i64::MAX))
                    }),
                ),
            ]),
        ),
        (
            "builtIn",
            (plan.mode == Mode::BuiltIn).then_or(Json::Null, || {
                Json::object([
                    (
                        "durationMs",
                        Json::Int(i64::try_from(plan.duration_ms).unwrap_or(i64::MAX)),
                    ),
                    (
                        "warmupMs",
                        Json::Int(i64::try_from(plan.warmup_ms).unwrap_or(i64::MAX)),
                    ),
                    (
                        "exitCode",
                        status
                            .workload_exit
                            .map_or(Json::Null, |code| Json::Int(i64::from(code))),
                    ),
                ])
            }),
        ),
        (
            "host",
            Json::object([
                ("hostname", Json::string(tool_stdout("hostname", &[]))),
                ("kernel", Json::string(tool_stdout("uname", &["-r"]))),
                ("machine", Json::string(tool_stdout("uname", &["-m"]))),
                (
                    "logicalCpus",
                    Json::Int(
                        std::thread::available_parallelism()
                            .map_or(0, |count| i64::try_from(count.get()).unwrap_or(i64::MAX)),
                    ),
                ),
            ]),
        ),
    ])
}

trait ThenOr {
    fn then_or<F>(self, otherwise: Json, value: F) -> Json
    where
        F: FnOnce() -> Json;
}

impl ThenOr for bool {
    fn then_or<F>(self, otherwise: Json, value: F) -> Json
    where
        F: FnOnce() -> Json,
    {
        if self { value() } else { otherwise }
    }
}

fn contract(
    plan: &Plan,
    state: ContractState<'_>,
    lock: &HostLock,
    binary: &identity::Binary,
    build_id: &str,
) -> Json {
    let (phase, exit_code, error, perf_data) = match state {
        ContractState::Running => ("running", None, None, Json::Null),
        ContractState::Failed(error) => ("failed", Some(1), Some(error), Json::Null),
        ContractState::Complete(sha256) => (
            "complete",
            Some(0),
            None,
            Json::object([
                ("relativePath", Json::string("perf.data")),
                ("sha256", Json::string(sha256)),
            ]),
        ),
    };
    Json::object([
        ("schemaVersion", Json::Int(2)),
        ("runId", Json::string(&plan.run_id)),
        ("collector", Json::string("perf-hotspot")),
        ("phase", Json::string(phase)),
        (
            "exitCode",
            exit_code.map_or(Json::Null, |code| Json::Int(i64::from(code))),
        ),
        ("error", error.map_or(Json::Null, Json::string)),
        (
            "hostExclusiveLock",
            Json::object([
                ("path", Json::string(lock.path().display().to_string())),
                ("deviceInode", Json::string(lock.device_inode())),
            ]),
        ),
        (
            "binary",
            Json::object([
                ("path", Json::string(binary.path.display().to_string())),
                ("sha256", Json::string(&binary.sha256)),
                ("buildId", Json::string(build_id)),
                (
                    "sourceCommit",
                    Json::string(&plan.expected_source_commit),
                ),
            ]),
        ),
        ("perfData", perf_data),
    ])
}

pub(super) fn build_id_list_contains(output: &str, expected: &str) -> bool {
    output.lines().any(|line| {
        line.split_whitespace()
            .next()
            .is_some_and(|observed| observed.eq_ignore_ascii_case(expected))
    })
}

fn atomic_metadata(path: &Path, document: &Json) -> Result<(), String> {
    let temporary = path.with_file_name(".metadata.json.tmp");
    std::fs::write(&temporary, document.to_python_json())
        .map_err(|error| format!("could not write {}: {error}", temporary.display()))?;
    std::fs::rename(&temporary, path).map_err(|error| {
        format!(
            "could not publish {} over {}: {error}",
            temporary.display(),
            path.display()
        )
    })
}

fn numeric_id(flag: &str) -> Result<String, String> {
    Tool::new("id")
        .arg(flag)
        .run()
        .map(|outcome| outcome.trimmed_stdout().to_owned())
        .map_err(|error| format!("id {flag}: {error}"))
}

fn capture_perf_output(run_dir: &RunDirectory, tool: Tool) -> Result<Outcome, String> {
    let output = tool
        .capture_limit(MAX_PERF_OUTPUT_BYTES)
        .probe()
        .map_err(|error| format!("perf record mechanism failed: {error}"))?;
    run_dir.write_new(PERF_STDOUT, &output.stdout)?;
    run_dir.write_new(PERF_STDERR, &output.stderr)?;
    Ok(output)
}

fn record_perf(
    plan: &Plan,
    run_dir: &RunDirectory,
    pid: u32,
    perf_data: &Path,
) -> Result<PerfRecord, String> {
    let tool = Tool::new("sudo").args([
        "-n".to_owned(),
        "perf".to_owned(),
        "record".to_owned(),
        "-e".to_owned(),
        plan.event.clone(),
        "-F".to_owned(),
        plan.frequency.to_string(),
        "-g".to_owned(),
        "--call-graph".to_owned(),
        plan.call_graph.clone(),
        "-p".to_owned(),
        pid.to_string(),
        "-o".to_owned(),
        perf_data.display().to_string(),
        "--".to_owned(),
        "sleep".to_owned(),
        plan.record_seconds.to_string(),
    ]);
    let output = capture_perf_output(run_dir, tool)?;
    Ok(PerfRecord {
        exit_code: output.code.unwrap_or(128),
        elapsed_millis: u64::try_from(output.elapsed.as_millis()).unwrap_or(u64::MAX),
    })
}

fn perf_failure(run_dir: &RunDirectory, exit_code: i32) -> String {
    format!(
        "perf record failed with exit code {exit_code}; see {} and {}",
        run_dir.join(PERF_STDERR).display(),
        run_dir.join(PERF_STDOUT).display()
    )
}

fn execute(
    plan: &Plan,
    run_dir: &RunDirectory,
    binary: &identity::Binary,
    build_id: &str,
    archived: &Path,
    status: &mut Status,
) -> Result<(), String> {
    let perf_data = run_dir.join("perf.data");
    let benchmark_json = run_dir.join("benchmark.json");
    let benchmark_stderr = run_dir.join("benchmark.stderr");
    let mut owned = match plan.mode {
        Mode::BuiltIn => {
            let mut child = Child::spawn_split_isolated(
                "built-in hotspot workload",
                &binary.path,
                &[
                    "benchmark".to_owned(),
                    "--duration-ms".to_owned(),
                    plan.duration_ms.to_string(),
                    "--warmup-ms".to_owned(),
                    plan.warmup_ms.to_string(),
                ],
                &plan.repo,
                &[(
                    "PATH".to_owned(),
                    "/usr/local/bin:/usr/bin:/bin".to_owned(),
                )],
                &benchmark_json,
                &benchmark_stderr,
            )
            .map_err(|error| error.to_string())?;
            std::thread::sleep(Duration::from_millis(500));
            if !child.is_alive() {
                return Err(format!(
                    "built-in benchmark exited before perf attached; see {}",
                    benchmark_stderr.display()
                ));
            }
            status.process = Some(inspect_process(child.pid(), &binary.sha256, build_id)?);
            Some(child)
        }
        Mode::AttachServer => {
            let pid = plan.server_pid.expect("validated attach PID");
            status.process = Some(inspect_process(pid, &binary.sha256, build_id)?);
            None
        }
    };
    let pid = status
        .process
        .as_ref()
        .expect("process identity recorded")
        .pid;
    let perf = record_perf(plan, run_dir, pid, &perf_data)?;
    status.perf_exit = Some(perf.exit_code);
    status.perf_elapsed_millis = Some(perf.elapsed_millis);
    if let Some(child) = owned.as_mut() {
        status.workload_exit = Some(child.wait()?);
    } else if perf.exit_code == 0
        && let Some(process) = status.process.as_mut()
    {
        verify_process(process)?;
    }
    if perf.exit_code != 0 {
        return Err(perf_failure(run_dir, perf.exit_code));
    }
    if status.workload_exit.is_some_and(|code| code != 0) {
        return Err(format!(
            "built-in workload failed with exit code {}",
            status.workload_exit.unwrap_or(128)
        ));
    }
    if !perf_data.metadata().is_ok_and(|metadata| metadata.len() > 0) {
        return Err("perf produced no data".to_owned());
    }
    let uid = numeric_id("-u")?;
    let gid = numeric_id("-g")?;
    Tool::new("sudo")
        .args([
            "-n".to_owned(),
            "chown".to_owned(),
            format!("{uid}:{gid}"),
            perf_data.display().to_string(),
        ])
        .run()
        .map_err(|error| format!("could not take ownership of perf data: {error}"))?;
    if plan.mode == Mode::BuiltIn {
        let raw = std::fs::read_to_string(&benchmark_json)
            .map_err(|error| format!("could not read {}: {error}", benchmark_json.display()))?;
        let measured = json_in::parse(&raw)
            .and_then(|value| {
                value
                    .field("benchmark", "environment")
                    .and_then(|environment| environment.field("benchmark.environment", "gitCommit"))
                    .and_then(|commit| commit.as_str("benchmark.environment.gitCommit"))
                    .map(str::to_owned)
                    .map_err(|error| error.to_string())
            })
            .map_err(|error| format!("built-in benchmark JSON: {error}"))?;
        if measured != plan.expected_source_commit {
            return Err(format!(
                "built-in benchmark source identity changed: expected {}, got {measured}",
                plan.expected_source_commit
            ));
        }
    }
    if hash::sha256_file(&binary.path)? != binary.sha256 {
        return Err("source binary changed after profiling".to_owned());
    }
    if attest::build_id(&binary.path)? != build_id {
        return Err("source binary Build ID changed after profiling".to_owned());
    }
    let buildids = Tool::new("perf")
        .args(["buildid-list", "-i", &perf_data.display().to_string()])
        .run()
        .map_err(|error| format!("perf buildid-list failed: {error}"))?
        .stdout;
    if !build_id_list_contains(&buildids, build_id) {
        return Err(format!(
            "perf data does not contain archived binary Build ID {build_id}"
        ));
    }
    run_dir.write_new("perf-buildids.txt", &buildids)?;
    let report_outcome = Tool::new("perf")
        .args([
            "report",
            "--stdio",
            "--no-children",
            "--sort",
            "comm,dso,symbol",
            "-i",
            &perf_data.display().to_string(),
        ])
        .probe()
        .map_err(|error| format!("perf report could not start: {error}"))?;
    if !report_outcome.success() {
        return Err(format!(
            "perf report failed with exit code {}: {}",
            report_outcome.code.unwrap_or(128),
            report_outcome.stderr.trim()
        ));
    }
    let report = format!("{}{}", report_outcome.stdout, report_outcome.stderr);
    run_dir.write_new("perf-report.txt", &report)?;
    let report_path = run_dir.join("perf-report.txt");
    let buildids_path = run_dir.join("perf-buildids.txt");
    let perf_stdout_path = run_dir.join(PERF_STDOUT);
    let perf_stderr_path = run_dir.join(PERF_STDERR);
    let checksum_files = [
        archived,
        perf_data.as_path(),
        report_path.as_path(),
        buildids_path.as_path(),
        perf_stdout_path.as_path(),
        perf_stderr_path.as_path(),
    ];
    let mut checksums = String::new();
    for path in checksum_files {
        let _ = writeln!(
            checksums,
            "{}  {}",
            hash::sha256_file(path)?,
            path.display()
        );
    }
    run_dir.write_new("SHA256SUMS", &checksums)?;
    Ok(())
}

/// Captures and publishes an identity-bound hotspot profile.
///
/// # Errors
///
/// Returns a setup, mechanism, identity or publication diagnostic. An output
/// directory created before failure remains visibly marked `FAILED`.
pub fn run(plan: &Plan) -> Result<String, String> {
    validate(plan)?;
    for program in ["hostname", "id", "perf", "readelf", "sudo", "uname"] {
        if !Tool::exists(program) {
            return Err(format!("required tool unavailable: {program}"));
        }
    }
    let sudo = Tool::new("sudo")
        .args(["-n", "true"])
        .probe()
        .map_err(|error| format!("passwordless sudo preflight failed: {error}"))?;
    if !sudo.success() {
        return Err("passwordless sudo is required for perf".to_owned());
    }
    let lock = HostLock::acquire(&runner::default_lock_path())?;
    let binary = identity::register(
        "rust-reality",
        &plan.binary,
        &plan.binary_sha256,
        Kind::Rust,
    )?;
    let observed_commit = embedded_commit(&binary.identity)?;
    if observed_commit != plan.expected_source_commit {
        return Err(format!(
            "rust-reality embedded commit mismatch: expected {}, got {observed_commit}",
            plan.expected_source_commit
        ));
    }
    let build_id = attest::build_id(&binary.path)?;
    let run_dir = RunDirectory::create(&plan.out_dir)?;
    let binary_dir = run_dir.join("binary");
    std::fs::create_dir(&binary_dir)
        .map_err(|error| format!("could not create {}: {error}", binary_dir.display()))?;
    let name = binary
        .path
        .file_name()
        .ok_or_else(|| "binary path has no file name".to_owned())?;
    let archived = binary_dir.join(name);
    std::fs::copy(&binary.path, &archived)
        .map_err(|error| format!("could not archive {}: {error}", binary.path.display()))?;
    let mut permissions = std::fs::metadata(&archived)
        .map_err(|error| format!("could not stat {}: {error}", archived.display()))?
        .permissions();
    permissions.set_mode(permissions.mode() & !0o222);
    std::fs::set_permissions(&archived, permissions)
        .map_err(|error| format!("could not make {} read-only: {error}", archived.display()))?;
    if hash::sha256_file(&archived)? != binary.sha256 || attest::build_id(&archived)? != build_id {
        return Err("archived binary identity changed during copy".to_owned());
    }
    run_dir.write_new(
        "run-contract.json",
        &contract(plan, ContractState::Running, &lock, &binary, &build_id).to_python_json(),
    )?;
    let mut status = Status::default();
    let metadata_path = run_dir.join("metadata.json");
    atomic_metadata(
        &metadata_path,
        &metadata(
            plan,
            "RUNNING",
            None,
            &binary,
            &build_id,
            &archived,
            &status,
        ),
    )?;
    if let Err(error) = execute(
        plan,
        &run_dir,
        &binary,
        &build_id,
        &archived,
        &mut status,
    ) {
        let _ = atomic_metadata(
            &metadata_path,
            &metadata(
                plan,
                "FAILED",
                Some(1),
                &binary,
                &build_id,
                &archived,
                &status,
            ),
        );
        let failed = contract(
            plan,
            ContractState::Failed(&error),
            &lock,
            &binary,
            &build_id,
        );
        let _ = std::fs::write(run_dir.join("run-contract.json"), failed.to_python_json());
        return Err(error);
    }
    let perf_data_sha256 = hash::sha256_file(&run_dir.join("perf.data"))?;
    atomic_metadata(
        &metadata_path,
        &metadata(
            plan,
            "COMPLETE",
            Some(0),
            &binary,
            &build_id,
            &archived,
            &status,
        ),
    )?;
    run_dir.publish(
        Publication::Contract,
        &contract(
            plan,
            ContractState::Complete(&perf_data_sha256),
            &lock,
            &binary,
            &build_id,
        )
        .to_python_json(),
        &plan.run_id,
        "perf-hotspot",
    )?;
    Ok(format!(
        "forensic hotspot profile complete: {}",
        plan.out_dir.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "rr-hotspot-{name}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_nanos())
            ));
            std::fs::create_dir_all(&path).expect("create scratch directory");
            Self(path)
        }

        fn join(&self, relative: &str) -> PathBuf {
            self.0.join(relative)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn plan() -> Plan {
        Plan {
            repo: PathBuf::from("/repo"),
            mode: Mode::BuiltIn,
            binary: PathBuf::from("/readonly/rust-reality"),
            binary_sha256: "a".repeat(64),
            expected_source_commit: "b".repeat(40),
            server_pid: None,
            out_dir: PathBuf::from("/tmp/hotspot-new"),
            run_id: "hotspot-test".to_owned(),
            record_seconds: 35,
            duration_ms: 10_000,
            warmup_ms: 1_000,
            event: "cycles:u".to_owned(),
            frequency: 999,
            call_graph: "fp".to_owned(),
        }
    }

    #[test]
    fn bounded_capture_arguments_are_validated() {
        assert!(validate(&plan()).is_ok());
        let mut invalid = plan();
        invalid.record_seconds = 301;
        assert!(validate(&invalid).is_err());
        invalid = plan();
        invalid.call_graph = "dwarf,65529".to_owned();
        assert!(validate(&invalid).is_err());
        invalid = plan();
        invalid.mode = Mode::AttachServer;
        assert!(validate(&invalid).is_err());
        invalid.server_pid = Some(42);
        assert!(validate(&invalid).is_ok());
    }

    #[test]
    fn call_graph_accepts_only_the_legacy_bounded_forms() {
        for value in ["fp", "lbr", "dwarf", "dwarf,8192", "dwarf,65528"] {
            assert!(validate_call_graph(value), "{value}");
        }
        for value in ["", "none", "dwarf,0", "dwarf,-1", "dwarf,65529"] {
            assert!(!validate_call_graph(value), "{value}");
        }
    }

    #[test]
    fn perf_build_id_membership_requires_an_exact_first_field() {
        let expected = "36b5a89ab69cb83898eac9980943d6c9da0a98bb";
        assert!(build_id_list_contains(
            &format!("{expected} /usr/bin/rust-reality\n"),
            expected
        ));
        assert!(!build_id_list_contains(
            &format!("00{expected} /usr/bin/rust-reality\n"),
            expected
        ));
        assert!(!build_id_list_contains(
            &format!("0123 /tmp/{expected}/rust-reality\n"),
            expected
        ));
    }

    #[test]
    fn built_in_warmup_matches_the_benchmark_cli_contract() {
        for warmup_ms in [MIN_BENCHMARK_WARMUP_MS, MAX_BENCHMARK_WARMUP_MS] {
            let mut valid = plan();
            valid.warmup_ms = warmup_ms;
            assert!(validate(&valid).is_ok(), "{warmup_ms}");
        }
        for warmup_ms in [0, MAX_BENCHMARK_WARMUP_MS + 1] {
            let mut invalid = plan();
            invalid.warmup_ms = warmup_ms;
            assert_eq!(
                validate(&invalid).unwrap_err(),
                "--warmup-ms must be in 1..=10000"
            );
        }
    }

    #[test]
    fn a_failing_perf_mechanism_retains_bounded_diagnostics_without_completion() {
        let scratch = Scratch::new("diagnostics");
        let run = RunDirectory::create(&scratch.join("run")).expect("create run directory");
        let output = capture_perf_output(
            &run,
            Tool::new("sh").args([
                "-c",
                "printf 'bounded stdout'; printf 'intentional perf diagnostic' >&2; exit 42",
            ]),
        )
        .expect("capture a non-zero mechanism outcome");

        assert_eq!(output.code, Some(42));
        assert_eq!(
            std::fs::read_to_string(run.join(PERF_STDOUT)).expect("read perf stdout"),
            "bounded stdout"
        );
        assert_eq!(
            std::fs::read_to_string(run.join(PERF_STDERR)).expect("read perf stderr"),
            "intentional perf diagnostic"
        );
        let error = perf_failure(&run, output.code.unwrap_or(128));
        assert!(error.contains(&run.join(PERF_STDERR).display().to_string()));
        assert!(error.contains(&run.join(PERF_STDOUT).display().to_string()));
        assert!(!error.contains("intentional perf diagnostic"));
        assert!(!run.join(Publication::Contract.marker_name()).exists());
    }
}
