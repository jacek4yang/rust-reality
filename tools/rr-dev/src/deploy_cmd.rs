//! CLI dispatch for `cargo dev deploy` subcommands.
//!
//! Keeps typed clap command handling out of `main` so deploy domain modules
//! (`deploy::*`) stay focused on planning, inspection, and mutation while this
//! module owns `ExitCode` mapping and flag gating (`--mutate-remote`, output
//! path rules).

use std::{path::Path, process::ExitCode};

use crate::cli::{CanaryArgs, DeployCommand, DeployPlanOperation, DeployTarget};
use crate::deploy;

/// Runs the netem Cartesian-product validator.
#[allow(clippy::too_many_arguments)]
fn run_deploy_netem(
    profiles: &Path,
    pool_summaries: &Path,
    output: &Path,
    rtts: &str,
    losses: &str,
    concurrencies: &str,
    samples: i64,
    connections: i64,
    evaluate_performance: bool,
) -> ExitCode {
    if output.exists() {
        eprintln!("deploy netem: output must not exist: {}", output.display());
        return ExitCode::from(2);
    }
    let args = match (
        deploy::netem::parse_i64_list(rtts),
        deploy::netem::parse_f64_list(losses),
        deploy::netem::parse_i64_list(concurrencies),
    ) {
        (Ok(rtts), Ok(losses), Ok(concurrencies)) => deploy::netem::NetemArgs {
            profiles: profiles.to_path_buf(),
            pool_summaries: pool_summaries.to_path_buf(),
            rtts,
            losses,
            concurrencies,
            samples,
            connections,
            evaluate_performance,
        },
        (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => {
            eprintln!("deploy netem: {error}");
            return ExitCode::from(2);
        }
    };
    match deploy::netem::validate(&args) {
        Ok(report) => {
            if let Err(error) = std::fs::write(output, &report.json) {
                eprintln!(
                    "deploy netem: could not write {}: {error}",
                    output.display()
                );
                return ExitCode::from(2);
            }
            print!("{}", report.json);
            if report.passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("deploy netem: {error}");
            ExitCode::from(2)
        }
    }
}

fn emit_deploy_json(output: Option<&Path>, json: &str) -> Result<(), String> {
    if let Some(path) = output {
        if path.exists() || path.is_symlink() {
            return Err(format!("output must not already exist: {}", path.display()));
        }
        std::fs::write(path, json)
            .map_err(|error| format!("could not write {}: {error}", path.display()))?;
    } else {
        print!("{json}");
    }
    Ok(())
}

fn run_deploy_inspect(target: DeployTarget, output: Option<&Path>) -> ExitCode {
    let topology = match deploy::host::Topology::canonical() {
        Ok(topology) => topology,
        Err(error) => {
            eprintln!("deploy inspect: {error}");
            return ExitCode::from(2);
        }
    };
    let host = topology.host(target.role());
    let mut transport = deploy::remote::SystemTransport;
    match deploy::snapshot::inspect(&mut transport, host) {
        Ok(snapshot) => {
            eprintln!("{}", snapshot.summary_line());
            let json = snapshot.to_json().to_python_json();
            if let Err(error) = emit_deploy_json(output, &json) {
                eprintln!("deploy inspect: {error}");
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("deploy inspect: {error}");
            ExitCode::FAILURE
        }
    }
}

fn build_canary_plan(
    arguments: CanaryArgs,
    rollback_on_failure: bool,
) -> Result<deploy::canary_run::Plan, String> {
    let supplemental = match (
        arguments.supplemental_line_service, arguments.supplemental_line_port,
        arguments.public_socks_port, arguments.public_url, arguments.public_payload,
    ) {
        (None, None, None, None, None) => None,
        (Some(service), Some(port), Some(public_socks_port), Some(public_url), Some(public_payload)) => Some(deploy::canary_run::Supplemental {
            service, port, public_socks_port, public_url, public_payload,
        }),
        _ => return Err("supplemental Handoff requires --supplemental-line-service, --supplemental-line-port, --public-socks-port, --public-url and --public-payload together".to_owned()),
    };
    Ok(deploy::canary_run::Plan {
        line_baseline: arguments.line_baseline,
        landing_baseline: arguments.landing_baseline,
        origin_access_log: arguments.origin_access_log,
        supplemental,
        candidate: deploy::canary_run::Candidate {
            commit: arguments.candidate_commit,
            sha256: arguments.candidate_sha256,
            build_id: arguments.candidate_build_id,
            version: arguments.candidate_version,
            target: arguments.candidate_target,
            rustc: arguments.candidate_rustc,
        },
        xray_bin: arguments.xray_bin,
        xray_sha256: arguments.xray_sha256,
        xray_config: arguments.xray_config,
        socks_port: arguments.socks_port,
        line_public_ipv4: arguments.line_public_ipv4,
        small_url: arguments.small_url,
        one_mib_url: arguments.one_mib_url,
        large_url: arguments.large_url,
        upload_url: arguments.upload_url,
        payload_one_mib: arguments.payload_one_mib,
        payload_large: arguments.payload_large,
        out_dir: arguments.out_dir,
        duration_seconds: arguments.duration_seconds,
        sample_interval_seconds: arguments.sample_interval_seconds,
        rollback_on_failure,
    })
}

fn run_canary_plan(arguments: CanaryArgs, output: Option<&Path>) -> ExitCode {
    let plan = match build_canary_plan(arguments, true) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("deploy canary-plan: {error}");
            return ExitCode::from(2);
        }
    };
    if let Err(error) = plan.validate() {
        eprintln!("deploy canary-plan: {error}");
        return ExitCode::from(2);
    }
    let json = plan.to_json().to_python_json();
    if let Err(error) = emit_deploy_json(output, &json) {
        eprintln!("deploy canary-plan: {error}");
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

fn run_canary_live(
    arguments: CanaryArgs,
    mutate_remote: bool,
    rollback_on_failure: bool,
) -> ExitCode {
    if !mutate_remote {
        eprintln!(
            "deploy canary-run: LINE reload and LANDING restart require --mutate-remote; use `deploy canary-plan` for non-live validation"
        );
        return ExitCode::from(2);
    }
    let plan = match build_canary_plan(arguments, rollback_on_failure) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("deploy canary-run: {error}");
            return ExitCode::from(2);
        }
    };
    let topology = match deploy::host::Topology::canonical() {
        Ok(topology) => topology,
        Err(error) => {
            eprintln!("deploy canary-run: {error}");
            return ExitCode::from(2);
        }
    };
    match deploy::canary_run::run(&plan, &topology) {
        Ok(outcome) => {
            print!("{}", outcome.verdict);
            if outcome.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("deploy canary-run: {error}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_deploy_plan(
    operation: DeployPlanOperation,
    target: DeployTarget,
    snapshot_path: &Path,
    release_id: Option<&str>,
    baseline_binary: Option<&str>,
    baseline_config: Option<&str>,
    binary: Option<&Path>,
    config: Option<&Path>,
    expected_sha256: Option<&str>,
    expected_version: Option<&str>,
    source_commit: Option<&str>,
    prune_old_releases: bool,
    output: Option<&Path>,
) -> ExitCode {
    let text = match std::fs::read_to_string(snapshot_path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!(
                "deploy plan: could not read {}: {error}",
                snapshot_path.display()
            );
            return ExitCode::from(2);
        }
    };
    let snapshot = match deploy::snapshot::from_json(&text) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!("deploy plan: inadmissible snapshot: {error}");
            return ExitCode::from(2);
        }
    };
    let topology = match deploy::host::Topology::canonical() {
        Ok(topology) => topology,
        Err(error) => {
            eprintln!("deploy plan: {error}");
            return ExitCode::from(2);
        }
    };
    let expected_alias = topology.host(target.role()).alias();
    if snapshot.alias != expected_alias {
        eprintln!(
            "deploy plan: snapshot alias {:?} does not match target {:?}",
            snapshot.alias, expected_alias
        );
        return ExitCode::from(2);
    }

    let plan = match operation {
        DeployPlanOperation::Bootstrap => release_id
            .ok_or_else(|| "--release-id is required for bootstrap".to_owned())
            .and_then(|release_id| {
                let baseline_binary = baseline_binary
                    .ok_or_else(|| "--baseline-binary is required for bootstrap".to_owned())?;
                let baseline_config = baseline_config
                    .ok_or_else(|| "--baseline-config is required for bootstrap".to_owned())?;
                deploy::plan::plan_bootstrap(
                    &snapshot,
                    release_id,
                    baseline_binary,
                    baseline_config,
                )
            }),
        DeployPlanOperation::Stage => deploy_artifact(
            operation,
            release_id,
            binary,
            config,
            expected_sha256,
            expected_version,
            source_commit,
        )
        .and_then(|artifact| deploy::plan::plan_stage(&snapshot, &artifact)),
        DeployPlanOperation::Cutover => deploy_artifact(
            operation,
            release_id,
            binary,
            config,
            expected_sha256,
            expected_version,
            source_commit,
        )
        .and_then(|artifact| deploy::plan::plan_cutover(&snapshot, &artifact)),
        DeployPlanOperation::Rollback => deploy::plan::plan_rollback(&snapshot),
        DeployPlanOperation::Promote => release_id
            .ok_or_else(|| "--release-id is required for promote".to_owned())
            .and_then(|release_id| {
                deploy::plan::plan_promote(&snapshot, release_id, prune_old_releases)
            }),
    };
    let plan = match plan {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("deploy plan: {error}");
            return ExitCode::from(2);
        }
    };
    eprint!("{}", plan.describe());
    if deploy::plan::rollback_for(&plan).is_some() {
        eprintln!("  rollback: constructed and required on execution failure");
    }
    let json = plan.to_json().to_python_json();
    if let Err(error) = emit_deploy_json(output, &json) {
        eprintln!("deploy plan: {error}");
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

#[allow(clippy::too_many_arguments)]
fn deploy_artifact(
    operation: DeployPlanOperation,
    release_id: Option<&str>,
    binary: Option<&Path>,
    config: Option<&Path>,
    expected_sha256: Option<&str>,
    expected_version: Option<&str>,
    source_commit: Option<&str>,
) -> Result<deploy::plan::ArtifactIdentity, String> {
    let required = |value: Option<&str>, name: &str| {
        value
            .map(str::to_owned)
            .ok_or_else(|| format!("--{name} is required for {operation:?}"))
    };
    let path = |value: Option<&Path>, name: &str| {
        value
            .ok_or_else(|| format!("--{name} is required for {operation:?}"))?
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("--{name} must be valid UTF-8"))
    };
    Ok(deploy::plan::ArtifactIdentity {
        release_id: required(release_id, "release-id")?,
        binary_path: path(binary, "binary")?,
        config_path: path(config, "config")?,
        binary_sha256: required(expected_sha256, "expected-sha256")?,
        version: required(expected_version, "expected-version")?,
        source_commit: source_commit.map(str::to_owned),
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn run_deploy_apply(
    repo: &Path,
    operation: DeployPlanOperation,
    target: DeployTarget,
    release_id: Option<&str>,
    baseline_binary: Option<&str>,
    baseline_config: Option<&str>,
    binary: Option<&Path>,
    config: Option<&Path>,
    expected_sha256: Option<&str>,
    expected_version: Option<&str>,
    source_commit: Option<&str>,
    prune_old_releases: bool,
    mutate_remote: bool,
    output: Option<&Path>,
) -> ExitCode {
    if !mutate_remote {
        eprintln!(
            "deploy apply: remote mutation requires --mutate-remote; use `deploy plan` for a non-mutating transaction"
        );
        return ExitCode::from(2);
    }
    let topology = match deploy::host::Topology::canonical() {
        Ok(topology) => topology,
        Err(error) => {
            eprintln!("deploy apply: {error}");
            return ExitCode::from(2);
        }
    };
    let host = topology.host(target.role());
    let mut transport = deploy::remote::SystemTransport;
    let before = match deploy::snapshot::inspect(&mut transport, host) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!("deploy apply: pre-mutation inspection failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    let artifact = match operation {
        DeployPlanOperation::Stage | DeployPlanOperation::Cutover => match deploy_artifact(
            operation,
            release_id,
            binary,
            config,
            expected_sha256,
            expected_version,
            source_commit,
        ) {
            Ok(artifact) => Some(artifact),
            Err(error) => {
                eprintln!("deploy apply: {error}");
                return ExitCode::from(2);
            }
        },
        DeployPlanOperation::Bootstrap
        | DeployPlanOperation::Rollback
        | DeployPlanOperation::Promote => None,
    };
    let plan = match operation {
        DeployPlanOperation::Bootstrap => release_id
            .ok_or_else(|| "--release-id is required for bootstrap".to_owned())
            .and_then(|release_id| {
                let baseline_binary = baseline_binary
                    .ok_or_else(|| "--baseline-binary is required for bootstrap".to_owned())?;
                let baseline_config = baseline_config
                    .ok_or_else(|| "--baseline-config is required for bootstrap".to_owned())?;
                deploy::plan::plan_bootstrap(&before, release_id, baseline_binary, baseline_config)
            }),
        DeployPlanOperation::Stage => deploy::plan::plan_stage(
            &before,
            artifact.as_ref().expect("stage artifact was constructed"),
        ),
        DeployPlanOperation::Cutover => deploy::plan::plan_cutover(
            &before,
            artifact.as_ref().expect("cutover artifact was constructed"),
        ),
        DeployPlanOperation::Rollback => deploy::plan::plan_rollback(&before),
        DeployPlanOperation::Promote => release_id
            .ok_or_else(|| "--release-id is required for promote".to_owned())
            .and_then(|id| deploy::plan::plan_promote(&before, id, prune_old_releases)),
    };
    let plan = match plan {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("deploy apply: {error}");
            return ExitCode::from(2);
        }
    };
    eprint!("{}", plan.describe());
    let mut validator = deploy::executor::SystemCandidateValidator;
    let unit_file = (operation == DeployPlanOperation::Bootstrap)
        .then(|| repo.join("deploy/rust-reality-vps.service"));
    match deploy::executor::execute(
        &mut transport,
        &mut validator,
        host,
        &plan,
        &before,
        artifact.as_ref(),
        unit_file.as_deref(),
    ) {
        Ok(report) => {
            let json = report.to_json().to_python_json();
            if let Err(error) = emit_deploy_json(output, &json) {
                eprintln!("deploy apply: transaction succeeded but evidence failed: {error}");
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("deploy apply: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Dispatches a `cargo dev deploy` subcommand.
///
/// The canary evaluator is fail-closed and three-valued, mirroring
/// `cargo dev perf evaluate`: exit 0 on pass, 1 on a real canary failure, and 2
/// when the recorded report could not be admitted at all.
#[allow(clippy::too_many_lines)]
pub(crate) fn run_deploy(repo: &Path, command: DeployCommand) -> ExitCode {
    match command {
        DeployCommand::CanaryPlan { plan, output } => run_canary_plan(plan, output.as_deref()),
        DeployCommand::CanaryRun {
            plan,
            mutate_remote,
            rollback_on_failure,
        } => run_canary_live(plan, mutate_remote, rollback_on_failure),
        DeployCommand::Inspect { target, output } => run_deploy_inspect(target, output.as_deref()),
        DeployCommand::Plan {
            operation,
            target,
            snapshot,
            release_id,
            baseline_binary,
            baseline_config,
            binary,
            config,
            expected_sha256,
            expected_version,
            source_commit,
            prune_old_releases,
            output,
        } => run_deploy_plan(
            operation,
            target,
            &snapshot,
            release_id.as_deref(),
            baseline_binary.as_deref(),
            baseline_config.as_deref(),
            binary.as_deref(),
            config.as_deref(),
            expected_sha256.as_deref(),
            expected_version.as_deref(),
            source_commit.as_deref(),
            prune_old_releases,
            output.as_deref(),
        ),
        DeployCommand::Apply {
            operation,
            target,
            release_id,
            baseline_binary,
            baseline_config,
            binary,
            config,
            expected_sha256,
            expected_version,
            source_commit,
            prune_old_releases,
            mutate_remote,
            output,
        } => run_deploy_apply(
            repo,
            operation,
            target,
            release_id.as_deref(),
            baseline_binary.as_deref(),
            baseline_config.as_deref(),
            binary.as_deref(),
            config.as_deref(),
            expected_sha256.as_deref(),
            expected_version.as_deref(),
            source_commit.as_deref(),
            prune_old_releases,
            mutate_remote,
            output.as_deref(),
        ),
        DeployCommand::Netem {
            profiles,
            pool_summaries,
            output,
            rtts,
            losses,
            concurrencies,
            samples,
            connections,
            evaluate_performance,
        } => run_deploy_netem(
            &profiles,
            &pool_summaries,
            &output,
            &rtts,
            &losses,
            &concurrencies,
            samples,
            connections,
            evaluate_performance,
        ),
        DeployCommand::Canary { input, output } => match deploy::canary::evaluate_file(&input) {
            deploy::canary::Outcome::Evaluated { verdict, ok } => {
                if let Some(path) = output
                    && let Err(error) = std::fs::write(&path, &verdict)
                {
                    eprintln!("deploy canary: {error}");
                    return ExitCode::from(2);
                }
                print!("{verdict}");
                if ok {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                }
            }
            deploy::canary::Outcome::Inadmissible(reason) => {
                eprintln!("canary evaluation failed: {reason}");
                ExitCode::from(2)
            }
        },
    }
}
