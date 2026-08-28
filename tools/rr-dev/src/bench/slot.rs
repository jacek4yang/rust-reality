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
        Attribution::Wall => run_workload(&argv, cwd),
        Attribution::Perf(events) => {
            run_workload_under_perf(&argv, server_pid, events, perf_csv, cwd)
        }
    }
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
        let error = run_workload(
            &["false".to_owned()],
            &std::env::temp_dir(),
        )
        .unwrap_err();
        assert!(error.contains("the workload exited"), "{error}");

        let error = run_workload(&[], &std::env::temp_dir()).unwrap_err();
        assert!(error.contains("command is empty"), "{error}");
    }

    #[test]
    fn a_successful_workload_is_accepted() {
        run_workload(&["true".to_owned()], &std::env::temp_dir())
            .expect("a zero exit is success");
    }

    #[test]
    fn the_running_image_must_match_the_registered_digest() {
        let own = attest::running_executable_sha256(std::process::id()).unwrap();
        verify_running_image(std::process::id(), &own, "test").expect("the image matches");
        let error = verify_running_image(std::process::id(), &"0".repeat(64), "test").unwrap_err();
        assert!(error.contains("server ELF mismatch"), "{error}");
    }
}
