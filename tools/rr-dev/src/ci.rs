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
        path::PathBuf,
        process::{Command, Stdio},
        thread,
        time::Duration,
    };

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

    #[test]
    fn sigint_to_script_group_exits_without_python_noise() {
        let (dir, script) = write_temp_script("#!/bin/bash\ntrap 'exit 130' INT\nsleep 30\n");
        let mut command = Command::new("bash");
        command
            .arg("--noprofile")
            .arg("--norc")
            .arg("-e")
            .arg("-o")
            .arg("pipefail")
            .arg(&script)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        command.process_group(0);
        let child = command.spawn().expect("spawn");
        let pid = child.id();
        thread::sleep(Duration::from_millis(200));
        let _ = Command::new("kill")
            .args(["-INT", &format!("-{pid}")])
            .status();
        let output = child.wait_with_output().expect("wait");
        let _ = fs::remove_dir_all(&dir);
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(
            !err.contains("KeyboardInterrupt") && !err.contains("Traceback"),
            "stderr was:\n{err}"
        );
        assert!(
            !output.status.success(),
            "expected interrupted failure, stderr={err}"
        );
    }

    #[test]
    fn qualification_workflows_use_bash_native_shell() {
        let failures = workflow_shell_failures(&repo_root());
        assert!(failures.is_empty(), "{failures:?}");
    }
}
