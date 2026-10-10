//! CI helpers owned by `cargo-dev` (no repository Python scripts).
//!
//! GitHub Actions qualification workflows use a **bash-native** custom shell
//! (`bash --noprofile --norc -e -o pipefail {0}`) so cancel/timeout cannot dump
//! Python `KeyboardInterrupt` stacks (ADR 0044). This module is the typed
//! `cargo-dev` twin: local proof, explicit script runs, and policy tests that
//! workflows never reintroduce a Python Actions shell.

use std::{
    io,
    path::Path,
    process::{Command, ExitStatus},
};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

/// Why a CI helper invocation failed before producing an exit status.
#[derive(Debug)]
pub enum CiError {
    /// The Actions/script path is missing or not a file.
    Script {
        /// Path that was requested.
        path: String,
        /// Underlying I/O error when available.
        source: Option<io::Error>,
    },
    /// `bash` could not be spawned.
    Spawn {
        /// Underlying OS error.
        source: io::Error,
    },
    /// Waiting on the child failed.
    Wait {
        /// Underlying OS error.
        source: io::Error,
    },
}

impl std::fmt::Display for CiError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Script { path, source } => {
                write!(formatter, "gha-shell script `{path}`")?;
                if let Some(source) = source {
                    write!(formatter, ": {source}")?;
                }
                Ok(())
            }
            Self::Spawn { source } => write!(formatter, "gha-shell spawn bash: {source}"),
            Self::Wait { source } => write!(formatter, "gha-shell wait: {source}"),
        }
    }
}

impl std::error::Error for CiError {}

/// Runs one Actions-style script the same way qualification `defaults.run.shell` does.
///
/// Spawns `bash --noprofile --norc -e -o pipefail SCRIPT` in its own process
/// group on Unix so interrupt targets the script tree. Exit status follows the
/// child (`128+signal` when killed by signal). Rust has no `KeyboardInterrupt`
/// traceback path — that was the Python Actions-shell defect this replaces.
///
/// # Errors
///
/// Returns [`CiError`] when the script path is unusable or bash cannot be
/// spawned/waited.
pub fn run_gha_shell(script: &Path) -> Result<ExitStatus, CiError> {
    if !script.is_file() {
        return Err(CiError::Script {
            path: script.display().to_string(),
            source: None,
        });
    }

    let mut command = Command::new("bash");
    command
        .arg("--noprofile")
        .arg("--norc")
        .arg("-e")
        .arg("-o")
        .arg("pipefail")
        .arg(script);
    #[cfg(unix)]
    command.process_group(0);

    let mut child = command
        .spawn()
        .map_err(|source| CiError::Spawn { source })?;
    child.wait().map_err(|source| CiError::Wait { source })
}

/// Maps a child [`ExitStatus`] to a shell-style process exit code.
#[must_use]
pub fn shell_exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

/// Actions `defaults.run.shell` argv prefix every qualification workflow MUST use.
pub const GHA_BASH_SHELL: &str = "bash --noprofile --norc -e -o pipefail {0}";

/// Returns true when workflow text still uses a forbidden Python Actions shell.
#[must_use]
pub fn workflow_uses_python_actions_shell(text: &str) -> bool {
    text.contains("gha_pipefail_shell.py")
        || text.contains("subprocess.call(['bash'")
        || text.contains("subprocess.call([\"bash\"")
        || (text.contains("python3 -c \"") && text.contains("pipefail"))
}

/// Qualification workflows that MUST keep the bash-native Actions shell.
pub const QUALIFICATION_WORKFLOWS: &[&str] = &[
    ".github/workflows/qualification.yml",
    ".github/workflows/qemu-specialist.yml",
    ".github/workflows/frozen-qualification.yml",
];

/// Validates Actions shell policy for qualification workflows under `repo`.
#[must_use]
pub fn workflow_shell_failures(repo: &Path) -> Vec<String> {
    let mut failures = Vec::new();
    for relative in QUALIFICATION_WORKFLOWS {
        let path = repo.join(relative);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => {
                failures.push(format!("{relative}: cannot read workflow ({error})"));
                continue;
            }
        };
        if workflow_uses_python_actions_shell(&text) {
            failures.push(format!(
                "{relative}: Python Actions shell is forbidden (ADR 0044); use `{GHA_BASH_SHELL}`"
            ));
        }
        if !text.contains(GHA_BASH_SHELL) {
            failures.push(format!(
                "{relative}: missing bash-native defaults.run.shell `{GHA_BASH_SHELL}`"
            ));
        }
    }
    if repo.join("tools/ci/gha_pipefail_shell.py").exists() {
        failures.push(
            "tools/ci/gha_pipefail_shell.py must remain deleted (use cargo-dev ci gha-shell / bash-native shell)"
                .to_owned(),
        );
    }
    failures
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::Read,
        path::{Path, PathBuf},
        process::{Child, Command, ExitStatus, Stdio},
        thread,
        time::{Duration, Instant},
    };

    #[cfg(unix)]
    use rustix::process::{Pid, Signal, kill_process_group};

    /// Poll interval while waiting for a semantic ready ACK (not a timing guess).
    const READY_POLL: Duration = Duration::from_millis(10);
    /// Bound for the child to publish its ready ACK after spawn.
    const READY_BOUND: Duration = Duration::from_secs(5);
    /// Bound for cooperative SIGINT to reap the script leader before escalating.
    #[cfg(unix)]
    const INT_REAP_BOUND: Duration = Duration::from_secs(2);

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repository root")
    }

    fn write_temp_script(body: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "rr-gha-shell-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("tempdir");
        let script = dir.join("step.sh");
        fs::write(&script, body).expect("write script");
        (dir, script)
    }

    /// Waits until `path` exists as a file, or panics with a diagnosable miss.
    ///
    /// This is a bounded semantic wait for an ACK the child publishes only after
    /// its INT trap is armed. It is not a fixed sleep that races startup.
    fn wait_for_ready_ack(path: &Path, bound: Duration) {
        let deadline = Instant::now() + bound;
        loop {
            if path.is_file() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "ready ACK missing before bound ({bound:?}): {}",
                path.display()
            );
            thread::sleep(READY_POLL);
        }
    }

    /// Live member PIDs of `pgid` (Linux `/proc`), excluding the caller's view races.
    #[cfg(unix)]
    fn live_pids_in_process_group(pgid: u32) -> Vec<u32> {
        let Ok(entries) = fs::read_dir("/proc") else {
            return Vec::new();
        };
        let mut pids = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(pid_str) = name.to_str() else {
                continue;
            };
            let Ok(member) = pid_str.parse::<u32>() else {
                continue;
            };
            let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
                continue;
            };
            // `/proc/<pid>/stat`: `pid (comm) state ppid pgrp ...` — comm may contain
            // spaces/parens, so locate the final `)` then take field index 4 (pgrp).
            let Some(close) = stat.rfind(')') else {
                continue;
            };
            let rest = stat[close + 1..].split_whitespace().collect::<Vec<_>>();
            // after `)`: state ppid pgrp → indices 0,1,2
            let Some(pgrp_str) = rest.get(2) else {
                continue;
            };
            if pgrp_str.parse::<u32>().ok() == Some(pgid) {
                pids.push(member);
            }
        }
        pids.sort_unstable();
        pids
    }

    /// SIGINT the owned group, escalate to SIGKILL on a bound, then reap pipes.
    ///
    /// `Child::wait_with_output` alone is unsafe here: a surviving `sleep` inherits
    /// the piped stdout/stderr write ends and blocks the parent forever after the
    /// bash leader exits (Class B hang on Actions stage-14 tools tests).
    #[cfg(unix)]
    fn interrupt_reap_script_group(mut child: Child) -> (ExitStatus, String) {
        let pgid = Pid::from_child(&child);
        let pgid_u32 = child.id();
        let _ = kill_process_group(pgid, Signal::INT);

        let deadline = Instant::now() + INT_REAP_BOUND;
        let mut status = None;
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(done)) => {
                    status = Some(done);
                    break;
                }
                Ok(None) => thread::sleep(READY_POLL),
                Err(error) => panic!("try_wait after SIGINT: {error}"),
            }
        }

        // Always SIGKILL the group: reaps `sleep` orphans that kept pipe write ends
        // open after the leader exited (or never honored INT).
        let _ = kill_process_group(pgid, Signal::KILL);
        let _ = child.kill();

        let status = match status {
            Some(done) => done,
            None => child.wait().expect("wait after SIGKILL"),
        };

        let mut err = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            let mut bytes = Vec::new();
            let _ = stderr.read_to_end(&mut bytes);
            err = String::from_utf8_lossy(&bytes).into_owned();
        }

        let leftovers = live_pids_in_process_group(pgid_u32);
        assert!(
            leftovers.is_empty(),
            "process group {pgid_u32} still has live members after INT+KILL: {leftovers:?}; \
             sleep orphans are forbidden"
        );
        (status, err)
    }

    #[test]
    fn success_and_pipefail() {
        let (dir, script) = write_temp_script("#!/bin/bash\necho ok\n");
        let status = run_gha_shell(&script).expect("run");
        assert!(status.success());
        assert_eq!(shell_exit_code(status), 0);
        let _ = fs::remove_dir_all(&dir);

        let (dir, script) = write_temp_script("#!/bin/bash\nfalse | true\n");
        let status = run_gha_shell(&script).expect("run");
        assert!(!status.success());
        assert_ne!(shell_exit_code(status), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn sigint_to_script_group_exits_without_python_noise() {
        let (dir, script) = write_temp_script(
            "#!/bin/bash\n\
             # Arm INT before publishing readiness so SIGINT cannot race trap setup.\n\
             trap 'exit 130' INT\n\
             : >\"${RR_GHA_SHELL_READY}\"\n\
             # Long blocker proves group kill — correctness is INT/KILL+wait, not sleep end.\n\
             while :; do sleep 3600; done\n",
        );
        let ready = dir.join("ready.ack");
        let mut command = Command::new("bash");
        command
            .arg("--noprofile")
            .arg("--norc")
            .arg("-e")
            .arg("-o")
            .arg("pipefail")
            .arg(&script)
            .env("RR_GHA_SHELL_READY", &ready)
            // stdout null avoids a second inherited write-end; stderr stays piped so
            // KeyboardInterrupt/Traceback absence remains observable.
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        command.process_group(0);
        let child = command.spawn().expect("spawn");
        wait_for_ready_ack(&ready, READY_BOUND);
        let (status, err) = interrupt_reap_script_group(child);
        let _ = fs::remove_dir_all(&dir);
        assert!(
            !err.contains("KeyboardInterrupt") && !err.contains("Traceback"),
            "stderr was:\n{err}"
        );
        assert!(
            !status.success(),
            "expected interrupted failure after ready ACK, code={:?} stderr={err}",
            status.code()
        );
        let code = shell_exit_code(status);
        // Cooperative trap exits 130; escalation SIGKILL yields 128+9 when INT did not finish.
        assert!(
            code == 130 || code == 128 + libc_sigint() || code == 128 + libc_sigkill(),
            "interrupted exit should be 130, 128+SIGINT, or 128+SIGKILL after escalate, got {code} stderr={err}"
        );
    }

    #[cfg(unix)]
    fn libc_sigint() -> i32 {
        2
    }

    #[cfg(unix)]
    fn libc_sigkill() -> i32 {
        9
    }

    #[cfg(unix)]
    #[test]
    fn sigint_proof_refuses_to_fire_before_ready_ack() {
        // Meta-contract: wait_for_ready_ack fails closed when the child never
        // publishes readiness, so interrupt proofs cannot silently race startup.
        let missing = std::env::temp_dir().join(format!(
            "rr-gha-shell-missing-ready-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        let result = std::panic::catch_unwind(|| {
            wait_for_ready_ack(&missing, Duration::from_millis(50));
        });
        assert!(
            result.is_err(),
            "missing ready ACK must fail closed rather than proceed to kill"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sigint_group_kill_reaps_sleep_orphan_holding_pipes() {
        // Regression for Actions hang: leader can exit while `sleep` still holds
        // inherited pipe write ends; parent must SIGKILL the pgid before draining.
        let (dir, script) = write_temp_script(
            "#!/bin/bash\n\
             trap 'exit 130' INT\n\
             : >\"${RR_GHA_SHELL_READY}\"\n\
             # Start sleep then exit the leader without waiting — deliberate orphan.\n\
             sleep 3600 &\n\
             exit 130\n",
        );
        let ready = dir.join("ready.ack");
        let mut command = Command::new("bash");
        command
            .arg("--noprofile")
            .arg("--norc")
            .arg("-e")
            .arg("-o")
            .arg("pipefail")
            .arg(&script)
            .env("RR_GHA_SHELL_READY", &ready)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.process_group(0);
        let child = command.spawn().expect("spawn");
        let pgid_u32 = child.id();
        wait_for_ready_ack(&ready, READY_BOUND);
        // Leader may already be exiting; still run the same INT→KILL→assert path.
        let (_status, _err) = interrupt_reap_script_group(child);
        let leftovers = live_pids_in_process_group(pgid_u32);
        let _ = fs::remove_dir_all(&dir);
        assert!(
            leftovers.is_empty(),
            "orphan sleep must be reaped with the process group, still live: {leftovers:?}"
        );
    }

    #[test]
    fn qualification_workflows_use_bash_native_shell() {
        let failures = workflow_shell_failures(&repo_root());
        assert!(failures.is_empty(), "{failures:?}");
    }
}
