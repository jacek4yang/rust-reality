//! Local proof for `tools/ci/gha_pipefail_shell.py` (ADR 0044).

#[cfg(test)]
mod tests {
    use std::{
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

    fn shell_py() -> PathBuf {
        repo_root().join("tools/ci/gha_pipefail_shell.py")
    }

    fn run_script(body: &str, signal_name: Option<&str>, delay_ms: u64) -> (i32, String, String) {
        let dir = std::env::temp_dir().join(format!(
            "rr-gha-shell-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("tempdir");
        let script = dir.join("step.sh");
        std::fs::write(&script, body).expect("write script");
        let child = Command::new("python3")
            .arg(shell_py())
            .arg(&script)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn wrapper");
        if let Some(signal_name) = signal_name {
            let pid = child.id().to_string();
            let signal_name = signal_name.to_owned();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(delay_ms));
                let _ = Command::new("kill").args([&signal_name, &pid]).status();
            });
        }
        let output = child.wait_with_output().expect("wait wrapper");
        let _ = std::fs::remove_dir_all(&dir);
        (
            output.status.code().unwrap_or(1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    #[test]
    fn success_and_pipefail_without_traceback() {
        let (code, out, err) = run_script("#!/bin/bash\necho ok\n", None, 0);
        assert_eq!(code, 0, "{err}");
        assert!(out.contains("ok"));
        assert!(!err.contains("KeyboardInterrupt"));
        assert!(!err.contains("Traceback"));

        let (code, _, err) = run_script("#!/bin/bash\nfalse | true\n", None, 0);
        assert_ne!(code, 0, "{err}");
        assert!(!err.contains("KeyboardInterrupt"));
    }

    #[test]
    fn sigint_cancel_has_no_keyboardinterrupt_stack() {
        let (code, _, err) = run_script(
            "#!/bin/bash\ntrap 'exit 130' INT\nsleep 30\n",
            Some("-INT"),
            300,
        );
        assert!(
            !err.contains("KeyboardInterrupt") && !err.contains("Traceback"),
            "stderr was:\n{err}"
        );
        assert!(
            code == 130 || code == 128 + 2,
            "unexpected exit {code}, stderr={err}"
        );
    }

    #[test]
    fn workflows_do_not_use_bare_subprocess_call_shell() {
        let workflows = repo_root().join(".github/workflows");
        let mut offenders = Vec::new();
        for entry in std::fs::read_dir(&workflows).expect("workflows") {
            let entry = entry.expect("entry");
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("yml") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read");
            if text.contains("subprocess.call(['bash'")
                || text.contains("subprocess.call([\"bash\"")
            {
                offenders.push(
                    path.file_name()
                        .expect("name")
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
        assert!(
            offenders.is_empty(),
            "bare subprocess.call bash shell still present in {offenders:?}"
        );
        for name in [
            "qemu-specialist.yml",
            "qualification.yml",
            "frozen-qualification.yml",
        ] {
            let text = std::fs::read_to_string(workflows.join(name)).expect(name);
            assert!(
                text.contains("tools/ci/gha_pipefail_shell.py"),
                "{name} must use the signal-safe shell"
            );
            assert!(
                !text.contains("${{ github.workspace }}/tools/ci/gha_pipefail_shell.py"),
                "{name} must not use github.workspace in defaults.run.shell"
            );
        }
    }
}
