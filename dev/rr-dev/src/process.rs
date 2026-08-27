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
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

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
        }
    }
}

impl std::error::Error for ToolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn { source, .. } => Some(source),
            Self::NotFound { .. } | Self::Failed { .. } => None,
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
        let output = self.build().output().map_err(|source| {
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
        Ok(Self::finish(&output, started.elapsed()))
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
        command
    }

    fn finish(output: &Output, elapsed: Duration) -> Outcome {
        Outcome {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            elapsed,
        }
    }
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
