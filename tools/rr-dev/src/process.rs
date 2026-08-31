//! Typed execution of external development tools.
//!
//! `rr-dev` orchestrates `cargo`, `git`, `gh`, `ssh`, `perf` and friends. It does
//! not reimplement them. Everything in this module exists to make those calls
//! typed, inspectable, redactable and testable.
//!
//! Two rules are load-bearing:
//!
//! 1. **No shell.** Commands are built as argv vectors and handed to
//!    [`std::process::Command`] directly. There is no `sh -c` path, so nothing a
//!    caller passes can be reinterpreted as shell syntax. This removes the entire
//!    quoting-and-injection class of bug that the Bash scripts had to defend
//!    against by hand.
//! 2. **Nothing sensitive is ever printed.** Arguments are matched against a
//!    redaction policy before they reach a diagnostic, so a REALITY private key,
//!    a UUID, a token or a password cannot leak through an error message.

use std::{
    ffi::OsStr,
    fmt, io,
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[cfg(unix)]
use rustix::process::{kill_process_group, Pid, Signal};

/// Default upper bound for one external development-tool invocation.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_mins(30);

/// Maximum bytes retained from each captured output stream by default.
pub const DEFAULT_CAPTURE_LIMIT: usize = 64 * 1024 * 1024;

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const TERMINATION_GRACE: Duration = Duration::from_millis(250);

type OutputReader = JoinHandle<io::Result<CapturedOutput>>;

#[derive(Debug, Default)]
struct CapturedOutput {
    bytes: Vec<u8>,
    exceeded_limit: bool,
}

/// Argument values that must never appear in a diagnostic.
///
/// Matching is substring-based on the *flag* that introduces a value, plus a
/// direct check for material that looks like key bytes. Redaction is deliberately
/// eager: a false positive costs one unreadable diagnostic, a false negative
/// leaks a production secret.
const SENSITIVE_FLAGS: &[&str] = &[
    "--private-key",
    "--privatekey",
    "--uuid",
    "--password",
    "--token",
    "--secret",
    "--short-id",
    "--psk",
];

/// The placeholder substituted for any redacted value.
const REDACTED: &str = "<redacted>";

/// How a tool invocation finished.
#[derive(Debug)]
pub struct Outcome {
    /// Exit status code, or `None` if the process was terminated by a signal.
    pub code: Option<i32>,
    /// Captured standard output, when capture was requested.
    pub stdout: String,
    /// Captured standard error, when capture was requested.
    pub stderr: String,
    /// Wall-clock duration of the invocation.
    pub elapsed: Duration,
}

impl Outcome {
    /// Whether the tool reported success.
    #[must_use]
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// Returns stdout with trailing newlines removed.
    #[must_use]
    pub fn trimmed_stdout(&self) -> &str {
        self.stdout.trim_end()
    }
}

/// Why a tool invocation could not be completed or did not succeed.
#[derive(Debug)]
pub enum ToolError {
    /// The executable could not be found on `PATH`.
    NotFound {
        /// The program that was looked up.
        program: String,
    },
    /// The process could not be spawned or waited on.
    Spawn {
        /// The program that was being started.
        program: String,
        /// The underlying operating-system error.
        source: io::Error,
    },
    /// The process ran to completion but reported failure.
    Failed {
        /// The redacted command line, safe to print.
        command: String,
        /// Exit status code, or `None` when terminated by a signal.
        code: Option<i32>,
        /// Captured standard error, truncated for readability.
        stderr: String,
    },
    /// The child exceeded its execution deadline and was terminated.
    Timeout {
        /// The redacted command line.
        command: String,
        /// The deadline that was exceeded.
        timeout: Duration,
    },
    /// A captured stream exceeded its configured memory bound.
    OutputTooLarge {
        /// The redacted command line.
        command: String,
        /// Which output stream exceeded the bound.
        stream: &'static str,
        /// Maximum bytes retained for one stream.
        limit: usize,
    },
    /// A captured stream was not valid UTF-8.
    InvalidOutput {
        /// The redacted command line.
        command: String,
        /// Which output stream was invalid.
        stream: &'static str,
    },
}

impl fmt::Display for ToolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { program } => {
                write!(formatter, "`{program}` was not found on PATH")
            }
            Self::Spawn { program, source } => {
                write!(formatter, "could not run `{program}`: {source}")
            }
            Self::Failed {
                command,
                code,
                stderr,
            } => {
                let status = match code {
                    Some(code) => format!("exit status {code}"),
                    None => "terminated by signal".to_owned(),
                };
                if stderr.is_empty() {
                    write!(formatter, "`{command}` failed with {status}")
                } else {
                    write!(formatter, "`{command}` failed with {status}\n{stderr}")
                }
            }
            Self::Timeout { command, timeout } => {
                write!(
                    formatter,
                    "`{command}` exceeded its {}s timeout",
                    timeout.as_secs()
                )
            }
            Self::OutputTooLarge {
                command,
                stream,
                limit,
            } => {
                write!(
                    formatter,
                    "`{command}` produced more than {limit} bytes on {stream}"
                )
            }
            Self::InvalidOutput { command, stream } => {
                write!(formatter, "`{command}` produced non-UTF-8 {stream}")
            }
        }
    }
}

impl std::error::Error for ToolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn { source, .. } => Some(source),
            Self::NotFound { .. }
            | Self::Failed { .. }
            | Self::Timeout { .. }
            | Self::OutputTooLarge { .. }
            | Self::InvalidOutput { .. } => None,
        }
    }
}

/// One external tool invocation, built argv-first.
///
/// Construct with [`Tool::new`], add arguments, then run. Nothing is executed
/// until a `run` method is called, so a caller can build and inspect an
/// invocation — which is what makes dry-run modes and unit tests possible
/// without touching the host.
#[derive(Debug, Clone)]
pub struct Tool {
    program: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
    cwd: Option<PathBuf>,
    inherit_stdio: bool,
    timeout: Duration,
    capture_limit: usize,
}

impl Tool {
    /// Starts building an invocation of `program`.
    #[must_use]
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            inherit_stdio: false,
            timeout: DEFAULT_TIMEOUT,
            capture_limit: DEFAULT_CAPTURE_LIMIT,
        }
    }

    /// Appends one argument.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Appends several arguments in order.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Sets one environment variable for the child only.
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Runs the child in `dir` instead of the current directory.
    #[must_use]
    pub fn current_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    /// Streams child output straight to the terminal instead of capturing it.
    ///
    /// Used for long interactive steps such as a test run, where a developer
    /// wants to watch progress rather than receive one block at the end.
    #[must_use]
    pub const fn streaming(mut self) -> Self {
        self.inherit_stdio = true;
        self
    }

    /// Sets the maximum time allowed for this invocation.
    #[allow(
        dead_code,
        reason = "the public builder is reserved for commands needing a tighter deadline"
    )]
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the maximum bytes retained from each captured output stream.
    #[allow(
        dead_code,
        reason = "the public builder is reserved for commands needing a tighter bound"
    )]
    #[must_use]
    pub const fn capture_limit(mut self, limit: usize) -> Self {
        self.capture_limit = limit;
        self
    }

    /// Returns the command line with sensitive values replaced.
    ///
    /// This is the only representation that may be printed or embedded in an
    /// error. It is what makes secret redaction structural rather than a habit
    /// each call site has to remember.
    #[must_use]
    pub fn redacted(&self) -> String {
        let mut rendered = String::from(&self.program);
        let mut redact_next = false;
        for arg in &self.args {
            rendered.push(' ');
            if redact_next {
                rendered.push_str(REDACTED);
                redact_next = false;
                continue;
            }
            let lowered = arg.to_ascii_lowercase();
            if let Some((flag, _)) = arg.split_once('=')
                && SENSITIVE_FLAGS.contains(&flag.to_ascii_lowercase().as_str())
            {
                rendered.push_str(flag);
                rendered.push('=');
                rendered.push_str(REDACTED);
                continue;
            }
            if SENSITIVE_FLAGS.contains(&lowered.as_str()) {
                redact_next = true;
            }
            rendered.push_str(arg);
        }
        rendered
    }

    /// Runs the tool and returns its outcome regardless of exit status.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::NotFound`] when the executable is absent and
    /// [`ToolError::Spawn`] when the process cannot be started or awaited.
    pub fn probe(&self) -> Result<Outcome, ToolError> {
        let started = Instant::now();
        let mut child = self.build().spawn().map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                ToolError::NotFound {
                    program: self.program.clone(),
                }
            } else {
                ToolError::Spawn {
                    program: self.program.clone(),
                    source,
                }
            }
        })?;

        // Drain captured pipes concurrently while polling. Waiting for the child
        // before draining can deadlock when a tool fills a pipe.
        let capture_limit = self.capture_limit;
        let stdout_reader = child
            .stdout
            .take()
            .map(|pipe| thread::spawn(move || read_bounded(pipe, capture_limit)));
        let stderr_reader = child
            .stderr
            .take()
            .map(|pipe| thread::spawn(move || read_bounded(pipe, capture_limit)));
        let mut status = None;
        let status = loop {
            if status.is_none() {
                match child.try_wait() {
                    Ok(observed) => status = observed,
                    Err(source) => {
                        terminate_and_reap(child, stdout_reader, stderr_reader);
                        return Err(ToolError::Spawn {
                            program: self.program.clone(),
                            source,
                        });
                    }
                }
            }
            if let Some(observed) = status
                && readers_finished(stdout_reader.as_ref(), stderr_reader.as_ref())
            {
                break observed;
            }
            if started.elapsed() >= self.timeout {
                terminate_and_reap(child, stdout_reader, stderr_reader);
                return Err(ToolError::Timeout {
                    command: self.redacted(),
                    timeout: self.timeout,
                });
            }
            thread::sleep(POLL_INTERVAL);
        };
        let stdout = join_reader(stdout_reader, "stdout").map_err(|source| ToolError::Spawn {
            program: self.program.clone(),
            source,
        })?;
        let stderr = join_reader(stderr_reader, "stderr").map_err(|source| ToolError::Spawn {
            program: self.program.clone(),
            source,
        })?;
        Ok(Outcome {
            code: status.code(),
            stdout: self.decode_output(stdout, "stdout")?,
            stderr: self.decode_output(stderr, "stderr")?,
            elapsed: started.elapsed(),
        })
    }

    /// Runs the tool and fails unless it exits zero.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Failed`] on a non-zero exit, plus the errors
    /// documented on [`Tool::probe`].
    pub fn run(&self) -> Result<Outcome, ToolError> {
        let outcome = self.probe()?;
        if outcome.success() {
            return Ok(outcome);
        }
        Err(ToolError::Failed {
            command: self.redacted(),
            code: outcome.code,
            stderr: truncate(&outcome.stderr),
        })
    }

    /// Whether the executable resolves on `PATH` at all.
    #[must_use]
    pub fn exists(program: &str) -> bool {
        which(program).is_some()
    }

    fn build(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(self.args.iter().map(OsStr::new));
        for (key, value) in &self.env {
            command.env(key, value);
        }
        if let Some(dir) = &self.cwd {
            command.current_dir(dir);
        }
        if self.inherit_stdio {
            command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        } else {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        #[cfg(unix)]
        command.process_group(0);
        command
    }

    fn decode_output(
        &self,
        capture: CapturedOutput,
        stream: &'static str,
    ) -> Result<String, ToolError> {
        if capture.exceeded_limit {
            return Err(ToolError::OutputTooLarge {
                command: self.redacted(),
                stream,
                limit: self.capture_limit,
            });
        }
        String::from_utf8(capture.bytes).map_err(|_| ToolError::InvalidOutput {
            command: self.redacted(),
            stream,
        })
    }
}

fn readers_finished(stdout: Option<&OutputReader>, stderr: Option<&OutputReader>) -> bool {
    stdout.is_none_or(JoinHandle::is_finished) && stderr.is_none_or(JoinHandle::is_finished)
}

fn read_bounded(mut pipe: impl Read, limit: usize) -> io::Result<CapturedOutput> {
    let mut capture = CapturedOutput {
        bytes: Vec::with_capacity(limit.min(16 * 1024)),
        exceeded_limit: false,
    };
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        let count = pipe.read(&mut chunk)?;
        if count == 0 {
            return Ok(capture);
        }
        let retained = count.min(limit.saturating_sub(capture.bytes.len()));
        capture.bytes.extend_from_slice(&chunk[..retained]);
        capture.exceeded_limit |= retained != count;
    }
}

fn join_reader(reader: Option<OutputReader>, stream: &str) -> io::Result<CapturedOutput> {
    match reader {
        None => Ok(CapturedOutput::default()),
        Some(reader) => reader
            .join()
            .map_err(|_| io::Error::other(format!("{stream} reader panicked")))?,
    }
}

fn terminate_and_reap(
    mut child: Child,
    stdout_reader: Option<OutputReader>,
    stderr_reader: Option<OutputReader>,
) {
    terminate_process_group(&mut child);
    let deadline = Instant::now() + TERMINATION_GRACE;
    let mut reaped = false;
    while Instant::now() < deadline {
        if !reaped {
            reaped = child.try_wait().is_ok_and(|status| status.is_some());
        }
        if reaped && readers_finished(stdout_reader.as_ref(), stderr_reader.as_ref()) {
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }
    if reaped {
        drop(child);
    } else {
        let _ = thread::Builder::new()
            .name("rr-dev-child-reaper".to_owned())
            .spawn(move || {
                let _ = child.wait();
            });
    }
    join_reader_if_finished(stdout_reader);
    join_reader_if_finished(stderr_reader);
}

fn join_reader_if_finished(reader: Option<OutputReader>) {
    if let Some(reader) = reader
        && reader.is_finished()
    {
        let _ = reader.join();
    }
}

#[cfg(unix)]
fn terminate_process_group(child: &mut Child) {
    let _ = kill_process_group(Pid::from_child(child), Signal::KILL);
    let _ = child.kill();
}

#[cfg(not(unix))]
fn terminate_process_group(child: &mut Child) {
    let _ = child.kill();
}

/// Resolves `program` against `PATH`, returning its full path.
#[must_use]
pub fn which(program: &str) -> Option<PathBuf> {
    if program.contains('/') {
        let direct = Path::new(program);
        return direct.is_file().then(|| direct.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join(program);
        candidate.is_file().then_some(candidate)
    })
}

/// Shortens captured stderr so one failing step cannot flood the terminal.
fn truncate(text: &str) -> String {
    const MAX_LINES: usize = 20;
    let trimmed = text.trim_end();
    if trimmed.is_empty() {
        return String::new();
    }
    let lines: Vec<&str> = trimmed.lines().collect();
    if lines.len() <= MAX_LINES {
        return trimmed.to_owned();
    }
    let kept = &lines[lines.len() - MAX_LINES..];
    format!(
        "… {} earlier lines omitted\n{}",
        lines.len() - MAX_LINES,
        kept.join("\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_separated_sensitive_value_is_redacted() {
        let tool = Tool::new("rust-reality")
            .arg("--private-key")
            .arg("QK3s_realsecret_bytes")
            .arg("--port")
            .arg("443");
        let rendered = tool.redacted();
        assert!(
            !rendered.contains("realsecret"),
            "the secret must not survive redaction: {rendered}"
        );
        assert!(rendered.contains("--private-key <redacted>"));
        assert!(
            rendered.contains("--port 443"),
            "non-sensitive arguments must stay readable: {rendered}"
        );
    }

    #[test]
    fn an_inline_sensitive_value_is_redacted() {
        let rendered = Tool::new("tool")
            .arg("--uuid=11111111-2222-3333-4444-555555555555")
            .redacted();
        assert_eq!(rendered, "tool --uuid=<redacted>");
    }

    #[test]
    fn redaction_is_case_insensitive_on_the_flag() {
        let rendered = Tool::new("tool").arg("--PrivateKey").arg("abc").redacted();
        assert!(!rendered.contains("abc"), "{rendered}");
    }

    #[test]
    fn a_missing_executable_is_reported_as_not_found() {
        let error = Tool::new("rr-dev-nonexistent-program-xyz")
            .probe()
            .expect_err("a missing program must not appear to succeed");
        assert!(matches!(error, ToolError::NotFound { .. }), "{error:?}");
    }

    #[test]
    fn a_nonzero_exit_is_an_error_but_probe_still_reports_it() {
        let tool = Tool::new("false");
        if !Tool::exists("false") {
            return;
        }
        let probed = tool.probe().expect("probe must capture a failing exit");
        assert!(!probed.success());
        assert!(matches!(tool.run(), Err(ToolError::Failed { .. })));
    }

    #[test]
    fn captured_stdout_is_available_and_trimmed() {
        if !Tool::exists("echo") {
            return;
        }
        let outcome = Tool::new("echo").arg("hello").run().expect("echo must run");
        assert_eq!(outcome.trimmed_stdout(), "hello");
    }

    #[test]
    fn a_child_that_exceeds_its_deadline_is_killed_and_reported() {
        if !Tool::exists("sleep") {
            return;
        }
        let error = Tool::new("sleep")
            .arg("1")
            .timeout(Duration::from_millis(20))
            .probe()
            .expect_err("a child beyond its deadline must fail closed");
        assert!(matches!(error, ToolError::Timeout { .. }), "{error:?}");
    }

    #[cfg(unix)]
    #[test]
    fn a_descendant_holding_capture_pipes_cannot_outlive_the_deadline() {
        if !Tool::exists("sh") || !Tool::exists("sleep") {
            return;
        }
        let started = Instant::now();
        let error = Tool::new("sh")
            .args(["-c", "sleep 5 &"])
            .timeout(Duration::from_millis(50))
            .probe()
            .expect_err("an inherited output pipe must not defeat the deadline");
        assert!(matches!(error, ToolError::Timeout { .. }), "{error:?}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "process-tree cleanup must itself remain bounded"
        );
    }

    #[cfg(unix)]
    #[test]
    fn captured_streams_are_drained_but_never_grow_past_their_bound() {
        if !Tool::exists("sh") || !Tool::exists("head") {
            return;
        }
        let error = Tool::new("sh")
            .args([
                "-c",
                "head -c 262144 /dev/zero; head -c 262144 /dev/zero >&2",
            ])
            .capture_limit(1024)
            .timeout(Duration::from_secs(2))
            .probe()
            .expect_err("oversized output must fail closed after both pipes drain");
        assert!(matches!(
            error,
            ToolError::OutputTooLarge {
                stream: "stdout",
                limit: 1024,
                ..
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_tool_output_is_refused_instead_of_lossily_rewritten() {
        if !Tool::exists("sh") {
            return;
        }
        let error = Tool::new("sh")
            .args(["-c", "printf '\\377'"])
            .probe()
            .expect_err("invalid UTF-8 must not become apparently valid evidence");
        assert!(matches!(
            error,
            ToolError::InvalidOutput {
                stream: "stdout",
                ..
            }
        ));
    }

    #[test]
    fn truncation_keeps_the_tail_and_says_what_it_dropped() {
        let mut long = String::new();
        for line in 1..=40 {
            long.push_str("line");
            long.push_str(&line.to_string());
            long.push('\n');
        }
        let shortened = truncate(&long);
        assert!(shortened.contains("20 earlier lines omitted"));
        assert!(shortened.contains("line40"));
        assert!(!shortened.contains("line1\n"));
    }
}
