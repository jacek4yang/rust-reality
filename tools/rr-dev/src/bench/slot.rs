//! Executing one measurement slot: run the workload, optionally under `perf`.
//!
//! A slot is the unit the ABBA design is built from — one implementation, fresh
//! processes, fresh ports, its own evidence directory. This module owns the two
//! steps that are identical across every harness in the family: driving the
//! workload child, and proving the process being measured is really the binary
//! that was registered.
//!
//! Everything else about a slot — which servers to launch, what configs they get,
//! what `identity.json` records — differs per suite and stays with the suite. That
//! is the split the plan asks for: share the lifecycle, not the shape of the
//! evidence.
//!
//! ## Why the workload is a child
//!
//! `perf stat -p <server_pid> -- <command>` counts the attached server for exactly
//! as long as `<command>` runs. The command *is* the measurement window, so the
//! workload has to be a separate process. Long-lived servers use
//! [`crate::bench::process::Child`], which terminates on drop; the workload uses
//! [`Tool`], which waits for completion.

use std::path::Path;

use crate::{
    bench::{attest, attribution, workload::SetupRatePlan},
    process::Tool,
};

/// How a slot's server CPU is attributed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attribution {
    /// No attribution; the workload runs unwrapped.
    ///
    /// `benchmark-setup-rate-xray.sh` calls this `MEASURE_MODE=wall`, the
    /// exploratory mode that records rates without a CPU claim.
    Wall,
    /// `perf stat` over the given events, attached to the server process.
    Perf(&'static [&'static str]),
    /// The server runs *under* `strace -c`, counting its receive syscalls.
    ///
    /// Unlike `perf`, this wraps the server rather than the workload, so the
    /// workload itself runs unwrapped.
    Strace,
    /// Server CPU read from `/proc/<pid>/task/*/schedstat` around the workload.
    ///
    /// Wraps nothing: the workload runs unwrapped and the caller samples the
    /// server's accumulated per-thread runtime on either side of it. This is
    /// the mode for a host that has no `perf` binary, which a host can be
    /// while still being entirely representative of production hardware.
    Schedstat,
}

/// Builds the argv for the workload child.
///
/// `output` is omitted for a warm-up-only run, which is how the drivers signalled
/// `samples == 0`.
///
/// # Errors
///
/// Returns a message when this executable's own path cannot be resolved, which is
/// what the child re-invokes.
pub fn workload_argv(plan: &SetupRatePlan, output: Option<&Path>) -> Result<Vec<String>, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("could not resolve the rr-dev executable: {error}"))?;
    let concurrencies = plan
        .concurrencies
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let mut argv = vec![
        executable.display().to_string(),
        "bench".to_owned(),
        "workload".to_owned(),
        "--socks-port".to_owned(),
        plan.socks_port.to_string(),
        "--origin-port".to_owned(),
        plan.origin_port.to_string(),
        "--connections".to_owned(),
        plan.connections.to_string(),
        "--concurrencies".to_owned(),
        concurrencies,
        "--samples".to_owned(),
        plan.samples.to_string(),
        "--implementation".to_owned(),
        plan.implementation.clone(),
        "--block".to_owned(),
        plan.block.to_string(),
        "--position".to_owned(),
        plan.position.to_string(),
    ];
    if plan.record_latencies {
        argv.push("--record-latencies".to_owned());
    }
    if let Some(output) = output {
        argv.push("--output".to_owned());
        argv.push(output.display().to_string());
    }
    Ok(argv)
}

/// Runs the workload child and waits for it.
///
/// # Errors
///
/// Returns a message when the child cannot start or exits non-zero. The child's
/// own diagnostic is included, because it names the cell that failed.
pub fn run_workload(argv: &[String], cwd: &Path) -> Result<(), String> {
    let (program, rest) = argv
        .split_first()
        .ok_or_else(|| "the workload command is empty".to_owned())?;
    let outcome = Tool::new(program.clone())
        .current_dir(cwd)
        .args(rest.to_vec())
        .probe()
        .map_err(|error| format!("could not run the workload: {error}"))?;
    if outcome.success() {
        return Ok(());
    }
    Err(format!(
        "the workload exited {:?}: {}",
        outcome.code,
        outcome.stderr.trim_end()
    ))
}

/// Runs the workload under `perf stat` attached to `server_pid`.
///
/// Writes the raw capture to `csv`; validating it is
/// [`attribution::parse_csv`]'s job, kept separate so a suite can apply the
/// stricter or the weaker contract as its evidence requires.
///
/// # Errors
///
/// Returns a message when `perf` cannot run or the workload exits non-zero.
pub fn run_workload_under_perf(
    argv: &[String],
    server_pid: u32,
    events: &[&str],
    csv: &Path,
    cwd: &Path,
) -> Result<(), String> {
    let (elevate, wrapped) = attribution::stat_command(server_pid, events, csv, argv);
    let outcome = Tool::new(elevate)
        .current_dir(cwd)
        .args(wrapped)
        .probe()
        .map_err(|error| format!("could not run perf stat: {error}"))?;
    if outcome.success() {
        return Ok(());
    }
    Err(format!(
        "perf stat exited {:?}: {}",
        outcome.code,
        outcome.stderr.trim_end()
    ))
}

/// Drives one slot's workload under the chosen attribution.
///
/// # Errors
///
/// Returns the workload or `perf` failure.
pub fn drive(
    plan: &SetupRatePlan,
    output: &Path,
    attribution: Attribution,
    server_pid: u32,
    perf_csv: &Path,
    cwd: &Path,
) -> Result<(), String> {
    let argv = workload_argv(plan, Some(output))?;
    match attribution {
        // strace wraps the server, not the workload, and schedstat wraps
        // nothing at all, so in both cases the workload runs plain.
        Attribution::Wall | Attribution::Strace | Attribution::Schedstat => {
            run_workload(&argv, cwd)
        }
        Attribution::Perf(events) => {
            run_workload_under_perf(&argv, server_pid, events, perf_csv, cwd)
        }
    }
}

/// The `strace` argv that wraps a server process.
///
/// `--kill-on-exit` stops a tracee outliving the tracer, `-f` follows threads,
/// `-qq` suppresses the exit-status chatter, `-c` asks for the counting summary
/// rather than a line per call, and the traced set is exactly the receive path the
/// harness reasons about.
#[must_use]
pub fn strace_command(
    output: &Path,
    program: &Path,
    program_args: &[String],
) -> (String, Vec<String>) {
    let mut args = vec![
        "--kill-on-exit".to_owned(),
        "-f".to_owned(),
        "-qq".to_owned(),
        "-c".to_owned(),
        "-e".to_owned(),
        "trace=recvfrom,recvmsg,read".to_owned(),
        "-o".to_owned(),
        output.display().to_string(),
        program.display().to_string(),
    ];
    args.extend_from_slice(program_args);
    ("strace".to_owned(), args)
}

/// Finds the traced server beneath an `strace` wrapper.
///
/// `strace` execs the tracee as its own child, so the pid the harness must
/// measure and signal is not the pid it spawned. The child is matched by resolved
/// executable rather than by position, because the wrapper may briefly have
/// others.
///
/// # Errors
///
/// Returns a message when no child running `binary` appears before `timeout`.
pub fn find_traced_child(
    wrapper_pid: u32,
    binary: &Path,
    timeout: std::time::Duration,
) -> Result<u32, String> {
    let expected = binary
        .canonicalize()
        .map_err(|error| format!("could not resolve {}: {error}", binary.display()))?;
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        let path = format!("/proc/{wrapper_pid}/task/{wrapper_pid}/children");
        if let Ok(raw) = std::fs::read_to_string(&path) {
            for field in raw.split_whitespace() {
                let Ok(child) = field.parse::<u32>() else {
                    continue;
                };
                if std::fs::canonicalize(format!("/proc/{child}/exe"))
                    .is_ok_and(|actual| actual == expected)
                {
                    return Ok(child);
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    Err(format!(
        "cannot identify the straced server beneath PID {wrapper_pid}"
    ))
}

/// Warms the slot's path up before it is measured.
///
/// # Errors
///
/// Returns the warm-up failure, which is fatal: a tunnel that never carried
/// traffic must not be measured.
pub fn warm_up(plan: &SetupRatePlan, cwd: &Path) -> Result<(), String> {
    let mut warm = plan.clone();
    warm.samples = 0;
    let argv = workload_argv(&warm, None)?;
    run_workload(&argv, cwd)
}

/// Proves the process being measured is running the registered binary.
///
/// A slot that launched a stale build on `PATH`, or whose binary was replaced
/// mid-run, would produce numbers attributed to the wrong artifact. The originals
/// compared `sha256sum /proc/<pid>/exe` against the registered digest before
/// measuring, and so does this.
///
/// # Errors
///
/// Returns a message when the image cannot be read or does not match.
pub fn verify_running_image(pid: u32, expected_sha256: &str, label: &str) -> Result<(), String> {
    let observed = attest::running_executable_sha256(pid)?;
    if observed == expected_sha256 {
        return Ok(());
    }
    Err(format!(
        "{label} server ELF mismatch: PID {pid} is running {observed}, expected {expected_sha256}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> SetupRatePlan {
        SetupRatePlan {
            socks_port: 1080,
            origin_port: 8080,
            connections: 96,
            concurrencies: vec![1, 8, 32],
            samples: 3,
            implementation: "rust".to_owned(),
            block: 2,
            position: 3,
            record_latencies: true,
        }
    }

    #[test]
    fn the_workload_argv_carries_every_plan_field() {
        let argv = workload_argv(&plan(), Some(Path::new("/out/samples.json"))).unwrap();
        let joined = argv.join(" ");
        assert!(joined.contains("bench workload"));
        assert!(joined.contains("--socks-port 1080"));
        assert!(joined.contains("--origin-port 8080"));
        assert!(joined.contains("--connections 96"));
        assert!(joined.contains("--concurrencies 1 8 32"));
        assert!(joined.contains("--samples 3"));
        assert!(joined.contains("--implementation rust"));
        assert!(joined.contains("--block 2"));
        assert!(joined.contains("--position 3"));
        assert!(joined.contains("--record-latencies"));
        assert!(joined.contains("--output /out/samples.json"));
        assert!(
            argv[0].ends_with("rr-dev") || argv[0].contains("rr_dev"),
            "argv[0] must be this executable, got {}",
            argv[0]
        );
    }

    /// A warm-up run carries no output path, which is how the drivers signalled
    /// `samples == 0`.
    #[test]
    fn a_warm_up_argv_has_no_output_and_no_samples() {
        let mut warm = plan();
        warm.samples = 0;
        let argv = workload_argv(&warm, None).unwrap();
        let joined = argv.join(" ");
        assert!(joined.contains("--samples 0"));
        assert!(!joined.contains("--output"));
    }

    #[test]
    fn the_comparator_omits_the_latency_flag_when_not_recording() {
        let mut quiet = plan();
        quiet.record_latencies = false;
        let argv = workload_argv(&quiet, None).unwrap();
        assert!(!argv.join(" ").contains("--record-latencies"));
    }

    /// The perf wrapper must place the whole workload argv after `--`, or perf
    /// would measure the wrong window.
    #[test]
    fn perf_wraps_the_workload_after_the_separator() {
        let argv = workload_argv(&plan(), Some(Path::new("/out/samples.json"))).unwrap();
        let (elevate, wrapped) = attribution::stat_command(
            4242,
            &attribution::TASK_CLOCK_ONLY,
            Path::new("/out/perf.csv"),
            &argv,
        );
        assert_eq!(elevate, "sudo");
        let separator = wrapped.iter().position(|item| item == "--").unwrap();
        assert_eq!(&wrapped[separator + 1..], argv.as_slice());
        assert!(wrapped.contains(&"-p".to_owned()));
        assert!(wrapped.contains(&"4242".to_owned()));
    }

    #[test]
    fn a_failing_workload_reports_the_child_diagnostic() {
        // `false` exits 1 with no output; the message must still name the exit.
        let error = run_workload(&["false".to_owned()], &std::env::temp_dir()).unwrap_err();
        assert!(error.contains("the workload exited"), "{error}");

        let error = run_workload(&[], &std::env::temp_dir()).unwrap_err();
        assert!(error.contains("command is empty"), "{error}");
    }

    #[test]
    fn a_successful_workload_is_accepted() {
        run_workload(&["true".to_owned()], &std::env::temp_dir()).expect("a zero exit is success");
    }

    #[test]
    fn the_running_image_must_match_the_registered_digest() {
        let own = attest::running_executable_sha256(std::process::id()).unwrap();
        verify_running_image(std::process::id(), &own, "test").expect("the image matches");
        let error = verify_running_image(std::process::id(), &"0".repeat(64), "test").unwrap_err();
        assert!(error.contains("server ELF mismatch"), "{error}");
    }

    #[test]
    fn the_strace_command_traces_only_the_receive_path() {
        let (program, args) = strace_command(
            Path::new("/out/slot/strace.txt"),
            Path::new("/bin/rust-reality"),
            &["run".to_owned(), "-c".to_owned(), "/w/s.json".to_owned()],
        );
        assert_eq!(program, "strace");
        assert_eq!(
            args,
            [
                "--kill-on-exit",
                "-f",
                "-qq",
                "-c",
                "-e",
                "trace=recvfrom,recvmsg,read",
                "-o",
                "/out/slot/strace.txt",
                "/bin/rust-reality",
                "run",
                "-c",
                "/w/s.json",
            ]
        );
    }

    /// A wrapper with no matching child must time out rather than return a pid it
    /// has not identified.
    #[test]
    fn an_absent_traced_child_fails_closed() {
        let error = find_traced_child(
            std::process::id(),
            &std::env::current_exe().unwrap(),
            std::time::Duration::from_millis(60),
        )
        .unwrap_err();
        assert!(
            error.contains("cannot identify the straced server"),
            "{error}"
        );
    }
}
