//! Execute required checks and retain their raw receipts in a frozen bundle.

use std::{
    fs,
    io::Read as _,
    path::{Path, PathBuf},
    time::Duration,
};

use super::{checks, collect, schema, workload};
use crate::process::Tool;

pub(super) struct CollectionLock(PathBuf);

impl CollectionLock {
    pub(super) fn acquire(root: &Path) -> Result<Self, String> {
        let path = root.join("evidence.lock");
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| format!("required-check collection is already reserved: {error}"))?;
        Ok(Self(path))
    }
}

impl Drop for CollectionLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
use clap::{Args, ValueEnum};

/// Required checks executed outside the VM workload.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Case {
    /// Authoritative local check covering both workspaces.
    LocalFullGate,
    /// Successful CI run at the frozen source commit.
    ExactHeadCi,
    /// Successful Security run at the frozen source commit.
    ExactHeadSecurity,
    /// Unfiltered library tests proving all required lifecycle regressions.
    Lifecycle,
    /// Stock-Xray byte-exact interoperability with the pinned OpenSSL cover.
    NativeInterop,
    /// Reviewed native RTT/mechanism and performance matrix.
    NativeMechanism,
    /// Fixed descriptor-pressure admission and recovery workload.
    NativeDescriptorPressure,
    /// Thirty-minute native ownership workload and fixed recovery checkpoints.
    NativeResources,
}

impl Case {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::LocalFullGate => "local-full-gate",
            Self::ExactHeadCi => "exact-head-ci",
            Self::ExactHeadSecurity => "exact-head-security",
            Self::Lifecycle => "lifecycle",
            Self::NativeInterop => "native-interop",
            Self::NativeMechanism => "native-mechanism",
            Self::NativeDescriptorPressure => "native-descriptor-pressure",
            Self::NativeResources => "native-resources",
        }
    }

    fn native(self) -> bool {
        matches!(
            self,
            Self::NativeInterop
                | Self::NativeMechanism
                | Self::NativeDescriptorPressure
                | Self::NativeResources
        )
    }
}

/// Collect one required check without replacing an earlier attempt.
#[derive(Args)]
pub struct Plan {
    /// Frozen campaign evidence to extend; raw observations are never rewritten.
    #[arg(long)]
    pub evidence: PathBuf,
    /// Fixed check program to execute.
    #[arg(long, value_enum)]
    pub case: Case,
    /// GitHub Actions run ID, required only for CI and Security.
    #[arg(long)]
    pub run_id: Option<u64>,
}

fn source_binding(repo: &Path, identity: &schema::Identity) -> Result<(), String> {
    let head = Tool::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .run()
        .map_err(|error| error.to_string())?;
    let status = Tool::new("git")
        .args(["status", "--porcelain"])
        .current_dir(repo)
        .run()
        .map_err(|error| error.to_string())?;
    if head.stdout.trim() != identity.source_commit
        || !status.stdout.is_empty()
        || rust_reality::BUILD_COMMIT != identity.source_commit
        || collect::running_image_digest()? != identity.evaluator.sha256
    {
        return Err(
            "required checks need the clean frozen source and exact frozen harness".to_owned(),
        );
    }
    Ok(())
}

fn command(
    plan: &Plan,
    directory: &Path,
    identity: &schema::Identity,
) -> Result<Vec<String>, String> {
    let ci = matches!(plan.case, Case::ExactHeadCi | Case::ExactHeadSecurity);
    if ci != plan.run_id.is_some() || plan.run_id == Some(0) {
        return Err("a positive --run-id is required only for CI or Security".to_owned());
    }
    Ok(match plan.case {
        Case::ExactHeadCi | Case::ExactHeadSecurity => vec![
            "gh".to_owned(),
            "run".to_owned(),
            "view".to_owned(),
            plan.run_id.expect("validated run ID").to_string(),
            "--json".to_owned(),
            checks::CI_FIELDS.to_owned(),
        ],
        Case::LocalFullGate => vec![
            identity.evaluator.path.clone(),
            "check".to_owned(),
            "--all".to_owned(),
            "--output".to_owned(),
            "json".to_owned(),
            "--log-dir".to_owned(),
            directory.join("logs").display().to_string(),
        ],
        Case::Lifecycle => [
            "cargo", "test", "--lib", "--locked", "--", "--color", "never",
        ]
        .map(str::to_owned)
        .to_vec(),
        Case::NativeInterop
        | Case::NativeMechanism
        | Case::NativeDescriptorPressure
        | Case::NativeResources => super::native_check::command(plan.case, directory, identity)?,
    })
}

fn write(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

/// Run the fixed command, preserve failure output, and independently verify its receipt.
///
/// # Errors
/// Rejects stale identities, repeated attempts, missing outputs and failed checks.
#[allow(
    clippy::too_many_lines,
    reason = "keep the execution and failure-finalization transaction together"
)]
pub fn run(repo: &Path, plan: &Plan) -> Result<(), String> {
    let path = plan
        .evidence
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let root = path.parent().ok_or("missing evidence directory")?;
    let _lock = CollectionLock::acquire(root)?;
    let mut bytes = Vec::new();
    fs::File::open(&path)
        .map_err(|error| error.to_string())?
        .take((schema::MAX_EVIDENCE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let mut evidence = schema::parse(&bytes)?;
    source_binding(repo, &evidence.identity)?;
    for artifact in super::artifacts(&evidence) {
        super::verify_artifact(root, artifact)?;
    }
    let contract: schema::Contract =
        serde_json::from_str(schema::CONTRACT).expect("compiled contract");
    let names: Vec<_> = if matches!(plan.case, Case::Lifecycle) {
        contract.deterministic_tests.keys().cloned().collect()
    } else {
        vec![plan.case.name().to_owned()]
    };
    if evidence
        .checks
        .iter()
        .any(|check| names.contains(&check.name))
    {
        return Err(
            "check already attempted; preserve this bundle and freeze a fresh attempt".to_owned(),
        );
    }
    let directory = root.join(format!("required-{}", plan.case.name()));
    let argv = command(plan, &directory, &evidence.identity)?;
    if plan.case.native() {
        super::native_check::verify_inputs(root, &evidence.identity)?;
    }
    // The fresh directory reserves this attempt even if execution is interrupted.
    fs::create_dir(&directory).map_err(|error| error.to_string())?;
    fs::write(directory.join("evidence-before.json"), &bytes).map_err(|error| error.to_string())?;
    write(&directory.join("command.json"), &argv)?;
    let output = directory.join("output.json");
    let stderr = directory.join("stderr.log");
    fs::write(&output, []).map_err(|error| error.to_string())?;
    fs::write(&stderr, []).map_err(|error| error.to_string())?;
    let executable = if matches!(plan.case, Case::LocalFullGate) || plan.case.native() {
        std::env::current_exe().map_err(|error| error.to_string())?
    } else {
        PathBuf::from(&argv[0])
    };
    let started = collect::unix_ms()?;
    let mut finalization_errors = Vec::new();
    let boot_id =
        fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|error| error.to_string())?;
    let mut pid = None;
    let mut start_ticks = None;
    let tool = Tool::new(executable.display().to_string())
        .args(argv[1..].iter().cloned())
        .current_dir(repo)
        .env("RUST_REALITY_GIT_COMMIT", &evidence.identity.source_commit)
        .timeout(Duration::from_hours(2))
        .log_output(&output, &stderr);
    let result = match tool.spawn() {
        Ok(child) => {
            pid = child.pid();
            start_ticks = pid.and_then(crate::bench::process::proc_starttime);
            if start_ticks.is_none() {
                finalization_errors.push("owned check child identity was not observed".to_owned());
            }
            child.wait()
        }
        Err(error) => Err(error),
    };
    let primary = match &result {
        Ok(outcome) if outcome.success() => None,
        Ok(outcome) => Some(format!("{} exited {:?}", plan.case.name(), outcome.code)),
        Err(error) => Some(error.to_string()),
    };
    if let Err(error) = source_binding(repo, &evidence.identity) {
        finalization_errors.push(error);
    }
    if plan.case.native()
        && let Err(error) = super::native_check::verify_inputs(root, &evidence.identity)
    {
        finalization_errors.push(error);
    }
    for artifact in [&evidence.identity.evaluator, &evidence.identity.contract] {
        if let Err(error) = super::verify_artifact(root, artifact) {
            finalization_errors.push(error);
        }
    }
    if fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .as_ref()
        != Some(&boot_id)
    {
        finalization_errors
            .push("host boot identity changed or could not be reobserved".to_owned());
    }
    let mut retain_digest = |result: Result<String, String>| match result {
        Ok(value) => value,
        Err(error) => {
            finalization_errors.push(error);
            String::new()
        }
    };
    let candidate_after = retain_digest(collect::file_digest(
        &root.join(&evidence.identity.candidate.path),
    ));
    let evaluator_after = retain_digest(collect::running_image_digest());
    if candidate_after != evidence.identity.candidate.sha256
        || evaluator_after != evidence.identity.evaluator.sha256
    {
        finalization_errors.push("frozen executable changed during check".to_owned());
    }
    let completed = match collect::unix_ms() {
        Ok(value) => value,
        Err(error) => {
            finalization_errors.push(error);
            0
        }
    };
    let terminal = (|| {
        write(
            &directory.join("terminal.json"),
            &checks::Execution {
                argv: argv.clone(),
                started_unix_ms: started,
                completed_unix_ms: completed,
                pid,
                start_ticks,
                boot_id,
                exit_code: result.as_ref().ok().and_then(|outcome| outcome.code),
                primary_error: primary.clone(),
                finalization_errors: finalization_errors.clone(),
                source_commit: [
                    evidence.identity.source_commit.clone(),
                    evidence.identity.source_commit.clone(),
                ],
                candidate_sha256: [evidence.identity.candidate.sha256.clone(), candidate_after],
                evaluator_sha256: [evidence.identity.evaluator.sha256.clone(), evaluator_after],
                stdout: workload::artifact(root, &output)?,
                stderr: workload::artifact(root, &stderr)?,
            },
        )
    })();
    let retained = (|| {
        terminal?;
        let output = if plan.case.native() {
            let proof = directory
                .join("run")
                .join(super::native_check::proof(plan.case));
            // A failed suite may have no summary. Preserve the actual command output;
            // the component evaluator will reject the missing proof independently.
            workload::artifact(root, if proof.is_file() { &proof } else { &output })?
        } else {
            workload::artifact(root, &output)?
        };
        let execution = workload::artifact(root, &directory.join("terminal.json"))?;
        let mut observations = Vec::new();
        if plan.case.native() {
            super::native_check::retain(root, &directory.join("run"), &mut observations)?;
            observations.push(workload::artifact(root, &root.join("xray"))?);
            observations.push(workload::artifact(root, &root.join("openssl"))?);
        }
        if matches!(plan.case, Case::LocalFullGate) && directory.join("logs").is_dir() {
            for entry in fs::read_dir(directory.join("logs")).map_err(|error| error.to_string())? {
                let entry = entry.map_err(|error| error.to_string())?;
                observations.push(workload::artifact(root, &entry.path())?);
            }
            observations.sort_by(|left, right| left.path.cmp(&right.path));
        }
        let mut errors = Vec::new();
        for name in names {
            let executed_cases = match plan.case {
                Case::LocalFullGate => crate::check::required_stage_labels().len() as u64,
                Case::Lifecycle => contract.deterministic_tests[&name].len() as u64,
                Case::NativeMechanism => 18,
                _ => 1,
            };
            let check = schema::Check {
                name,
                source_commit: evidence.identity.source_commit.clone(),
                candidate_sha256: evidence.identity.candidate.sha256.clone(),
                argv: argv.clone(),
                exit_code: result.as_ref().ok().and_then(|outcome| outcome.code),
                completed: result.is_ok() && finalization_errors.is_empty(),
                executed_cases,
                failed_cases: u64::from(primary.is_some() || !finalization_errors.is_empty()),
                execution: execution.clone(),
                output: output.clone(),
                observations: observations.clone(),
            };
            match super::verify_required_check(root, &check, &evidence.identity) {
                Ok(report) if report.verdict == super::evaluate::Verdict::Pass => {}
                Ok(report) => errors.push(format!(
                    "{}: {:?}: {:?}",
                    check.name, report.verdict, report.findings
                )),
                Err(error) => errors.push(format!("{}: {error}", check.name)),
            }
            evidence.checks.push(check);
        }
        // Refuse to overwrite a concurrently changed aggregate.
        if fs::read(&path).map_err(|error| error.to_string())? != bytes {
            write(&directory.join("evidence-after.json"), &evidence)?;
            return Err(
                "aggregate changed concurrently; attempted evidence retained separately".to_owned(),
            );
        }
        let next = directory.join("evidence-after.json");
        write(&next, &evidence)?;
        let pending = directory.join("aggregate-next.json");
        fs::copy(&next, &pending).map_err(|error| error.to_string())?;
        fs::rename(&pending, &path).map_err(|error| error.to_string())?;
        errors.extend(finalization_errors);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    })();
    match (primary, retained) {
        (Some(primary), Err(secondary)) => {
            Err(format!("{primary}; evidence finalization: {secondary}"))
        }
        (Some(primary), Ok(())) => Err(primary),
        (None, result) => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collection_reservation_prevents_concurrent_writers_and_releases_after_failure() {
        let workspace = crate::bench::workspace::Workspace::create("check-reservation").unwrap();
        let evidence = workspace.join("evidence.json");
        fs::write(&evidence, b"invalid evidence\n").unwrap();
        let plan = Plan {
            evidence: evidence.clone(),
            case: Case::Lifecycle,
            run_id: None,
        };
        let lock = CollectionLock::acquire(workspace.path()).unwrap();
        assert!(
            run(workspace.path(), &plan)
                .unwrap_err()
                .contains("reserved")
        );
        drop(lock);
        assert!(run(workspace.path(), &plan).is_err());
        assert!(!workspace.join("evidence.lock").exists());
        assert_eq!(fs::read(evidence).unwrap(), b"invalid evidence\n");
        assert!(!workspace.join("required-lifecycle").exists());
    }

    #[test]
    fn commands_fix_coverage_and_require_explicit_ci_identity() {
        let evidence: schema::Evidence =
            serde_json::from_value(super::super::tests::fixture()).unwrap();
        let mut plan = Plan {
            evidence: PathBuf::new(),
            case: Case::Lifecycle,
            run_id: None,
        };
        let directory = Path::new("/retained/required");
        assert_eq!(
            command(&plan, directory, &evidence.identity).unwrap(),
            [
                "cargo", "test", "--lib", "--locked", "--", "--color", "never"
            ]
        );
        plan.case = Case::LocalFullGate;
        let argv = command(&plan, directory, &evidence.identity).unwrap();
        assert_eq!(argv[6], "/retained/required/logs");
        plan.case = Case::ExactHeadCi;
        assert!(command(&plan, directory, &evidence.identity).is_err());
        plan.run_id = Some(0);
        assert!(command(&plan, directory, &evidence.identity).is_err());
        plan.run_id = Some(123);
        assert_eq!(
            command(&plan, directory, &evidence.identity).unwrap()[3],
            "123"
        );
        plan.case = Case::Lifecycle;
        assert!(command(&plan, directory, &evidence.identity).is_err());
    }
}
