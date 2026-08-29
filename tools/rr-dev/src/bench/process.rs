//! Long-lived benchmark child processes, owned by RAII.
//!
//! Benchmark suites launch origin servers, helper processes and the measured
//! implementations, then must guarantee none survive the run. The legacy scripts
//! did this with a registered PID plus a `/proc/<pid>/stat` start-time check so a
//! recycled PID could never be signalled by mistake; [`Child`] reproduces that
//! exact-identity discipline and terminates on drop, so a panic or early return
//! cannot leak a process.
//!
//! Nothing here routes through a shell: the program and its arguments are handed
//! to [`std::process::Command`] directly.

use std::{
    fs::File,
    net::{SocketAddr, TcpStream},
    path::Path,
    process::{Child as StdChild, Command, Stdio},
    time::{Duration, Instant},
};

/// A launched process owned for the lifetime of this guard.
///
/// Dropping the guard terminates the process by its exact PID+start-time
/// identity: `SIGTERM`, a bounded wait, then `SIGKILL`. A process whose identity
/// no longer matches (it already exited and the PID was recycled) is never
/// signalled.
#[derive(Debug)]
pub struct Child {
    label: String,
    pid: u32,
    starttime: Option<String>,
    handle: Option<StdChild>,
}

/// Why a child could not be started or observed.
#[derive(Debug)]
pub enum Error {
    /// The process could not be spawned.
    Spawn {
        /// The program that failed to start.
        program: String,
        /// The underlying error text.
        detail: String,
    },
    /// A readiness condition was not met before the deadline.
    Readiness(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn { program, detail } => {
                write!(formatter, "could not start {program}: {detail}")
            }
            Self::Readiness(reason) => write!(formatter, "{reason}"),
        }
    }
}

impl std::error::Error for Error {}

impl Child {
    /// Spawns `program` with `args`, redirecting stdout and stderr to `log`.
    ///
    /// The child's PID start-time is captured immediately so later termination can
    /// prove it is signalling the same process.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Spawn`] when the process cannot be started or its log file
    /// cannot be created.
    pub fn spawn(
        label: impl Into<String>,
        program: &Path,
        args: &[String],
        cwd: &Path,
        env: &[(String, String)],
        log: &Path,
    ) -> Result<Self, Error> {
        Self::spawn_inner(label, program, args, cwd, env, log, false)
    }

    /// Spawns a child with only the explicitly supplied environment variables.
    ///
    /// Measurement children use this when inheriting proxy or trust-store state
    /// would change the mechanism being exercised. The program and arguments are
    /// still passed directly; no shell is involved.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Spawn`] under the same conditions as [`Self::spawn`].
    pub fn spawn_isolated(
        label: impl Into<String>,
        program: &Path,
        args: &[String],
        cwd: &Path,
        env: &[(String, String)],
        log: &Path,
    ) -> Result<Self, Error> {
        Self::spawn_inner(label, program, args, cwd, env, log, true)
    }

    fn spawn_inner(
        label: impl Into<String>,
        program: &Path,
        args: &[String],
        cwd: &Path,
        env: &[(String, String)],
        log: &Path,
        clear_environment: bool,
    ) -> Result<Self, Error> {
        let label = label.into();
        let log_file = File::create(log).map_err(|error| Error::Spawn {
            program: program.display().to_string(),
            detail: format!("log {}: {error}", log.display()),
        })?;
        let stderr = log_file.try_clone().map_err(|error| Error::Spawn {
            program: program.display().to_string(),
            detail: error.to_string(),
        })?;
        let mut command = Command::new(program);
        if clear_environment {
            command.env_clear();
        }
        let handle = command
            .args(args)
            .current_dir(cwd)
            .envs(
                env.iter()
                    .map(|(key, value)| (key.as_str(), value.as_str())),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(stderr))
            .spawn()
            .map_err(|error| Error::Spawn {
                program: program.display().to_string(),
                detail: error.to_string(),
            })?;
        let pid = handle.id();
        let starttime = proc_starttime(pid);
        Ok(Self {
            label,
            pid,
            starttime,
            handle: Some(handle),
        })
    }

    /// The child's process id.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// The label this child was launched under.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Whether the process is still the exact one that was launched.
    #[must_use]
    pub fn is_alive(&mut self) -> bool {
        // Prefer the owned handle: try_wait reaps and reports exit without a
        // signal. If it has exited, it is not alive.
        if let Some(handle) = self.handle.as_mut()
            && matches!(handle.try_wait(), Ok(Some(_)))
        {
            return false;
        }
        // Confirm identity via /proc start-time where available, else assume the
        // un-reaped handle means it is still running.
        match (&self.starttime, proc_starttime(self.pid)) {
            (Some(registered), Some(current)) => *registered == current,
            _ => self.handle.is_some(),
        }
    }

    /// Waits until `port` accepts a loopback TCP connection or the timeout elapses.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Readiness`] if the port never accepts, or if the child
    /// exits before it does.
    pub fn wait_for_port(&mut self, port: u16, timeout: Duration) -> Result<(), Error> {
        self.wait_for_address(SocketAddr::from(([127, 0, 0, 1], port)), timeout)
    }

    /// Waits until `address` accepts a TCP connection or the timeout elapses.
    ///
    /// Unlike [`Self::wait_for_port`], this supports explicit IPv6 listeners.
    /// Keeping readiness in the child guard means an early process exit is still
    /// reported immediately instead of being mistaken for a slow bind.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Readiness`] if the address never accepts, or if the child
    /// exits before it does.
    pub fn wait_for_address(
        &mut self,
        address: SocketAddr,
        timeout: Duration,
    ) -> Result<(), Error> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
                return Ok(());
            }
            if !self.is_alive() {
                return Err(Error::Readiness(format!(
                    "{} exited before {address} became ready",
                    self.label
                )));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Err(Error::Readiness(format!(
            "{} address {address} did not become ready within {:.1}s",
            self.label,
            timeout.as_secs_f64()
        )))
    }

    /// Terminates the process: `SIGTERM` via the external `kill`, a bounded wait,
    /// then `SIGKILL` through the owned handle.
    ///
    /// Idempotent and safe to call more than once. `SIGTERM` is only sent while
    /// the exact process (matched by start-time when available) is still alive, so
    /// a recycled PID is never signalled; the fallback `SIGKILL` targets only the
    /// owned child handle.
    pub fn terminate(&mut self) {
        if self.is_alive() {
            // Graceful stop via the external kill(1); argv-based, no shell, no FFI.
            let _ = std::process::Command::new("kill")
                .arg("-TERM")
                .arg(self.pid.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            for _ in 0..50 {
                if !self.is_alive() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        if let Some(mut handle) = self.handle.take() {
            // SIGKILL the owned child if it is still running, then reap it.
            let _ = handle.kill();
            let _ = handle.wait();
        }
    }

    /// Sends `SIGHUP` to the exact owned process for configuration reload.
    ///
    /// # Errors
    ///
    /// Returns a message when the child has exited or `kill` rejects the signal.
    pub fn reload(&mut self) -> Result<(), String> {
        if !self.is_alive() {
            return Err(format!("{} exited before reload", self.label));
        }
        let status = std::process::Command::new("kill")
            .arg("-HUP")
            .arg(self.pid.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| format!("could not signal {}: {error}", self.label))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("could not reload {}: {status}", self.label))
        }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        self.terminate();
    }
}

/// Reads a PID's start-time (field 22 of `/proc/<pid>/stat`) as a stable identity.
///
/// Returns `None` on a non-Linux host or when the process is gone; callers then
/// fall back to the owned child handle for liveness.
#[must_use]
pub fn proc_starttime(pid: u32) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The comm field is parenthesised and may contain spaces; split after the
    // last ") ". Field 22 (start-time) is index 19 of the remainder.
    let rest = &stat[stat.rfind(") ")? + 2..];
    rest.split_whitespace().nth(19).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(program: &str) -> Option<std::path::PathBuf> {
        std::env::split_paths(&std::env::var_os("PATH")?)
            .map(|dir| dir.join(program))
            .find(|candidate| candidate.is_file())
    }

    #[test]
    fn a_child_is_terminated_on_drop() {
        let Some(sleep) = tool("sleep") else {
            return;
        };
        let scratch = std::env::temp_dir().join(format!("rr-bench-proc-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).unwrap();
        let log = scratch.join("sleep.log");
        let pid;
        {
            let mut child = Child::spawn("sleep", &sleep, &["30".to_owned()], &scratch, &[], &log)
                .expect("sleep must start");
            pid = child.pid();
            assert!(child.is_alive(), "the child must be alive after spawn");
        }
        // After drop the exact process must be gone (start-time no longer present).
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            proc_starttime(pid).is_none(),
            "the child must not survive the guard drop"
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn readiness_fails_fast_when_the_child_exits() {
        let Some(true_bin) = tool("true") else {
            return;
        };
        let scratch = std::env::temp_dir().join(format!("rr-bench-proc2-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).unwrap();
        let log = scratch.join("true.log");
        let mut child =
            Child::spawn("true", &true_bin, &[], &scratch, &[], &log).expect("true must start");
        // `true` exits immediately; a port wait must report the exit, not hang.
        let result = child.wait_for_port(1, Duration::from_secs(2));
        assert!(result.is_err(), "a port wait on an exited child must fail");
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn starttime_is_readable_for_the_current_process() {
        // On Linux this proves the /proc parsing; elsewhere it returns None and
        // the guard uses the signal-0 fallback.
        let mine = proc_starttime(std::process::id());
        if cfg!(target_os = "linux") {
            assert!(mine.is_some(), "own start-time must be readable on Linux");
        }
    }

    #[test]
    fn an_isolated_child_receives_only_explicit_environment() {
        let Some(env_bin) = tool("env") else {
            return;
        };
        let scratch =
            std::env::temp_dir().join(format!("rr-bench-isolated-env-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        let log = scratch.join("env.log");
        let mut child = Child::spawn_isolated(
            "isolated-env",
            &env_bin,
            &[],
            &scratch,
            &[("RR_EXPLICIT_MARKER".to_owned(), "present".to_owned())],
            &log,
        )
        .unwrap();
        for _ in 0..100 {
            if !child.is_alive() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.terminate();
        let output = std::fs::read_to_string(&log).unwrap();
        assert_eq!(output, "RR_EXPLICIT_MARKER=present\n");
        let _ = std::fs::remove_dir_all(&scratch);
    }
}
