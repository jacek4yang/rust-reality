//! Exact-candidate stability qualification and offline evidence verification.

pub mod action;
pub mod campaign;
pub mod checks;
pub mod clock;
pub mod collect;
pub mod evaluate;
pub mod execution;
pub mod fixture;
pub mod guest;
pub mod native;
pub mod native_evaluate;
pub mod native_interop;
pub mod native_pressure;
pub mod observation;
pub mod schema;
pub mod test_receipt;
pub mod transfer;
pub mod vm;
pub mod workload;

use std::{
    fs::File,
    io::Read as _,
    path::{Component, Path},
};

use crate::hash;
use evaluate::{Report, Verdict};
use schema::{Artifact, Evidence};

/// Verify all referenced objects and calculate acceptance without running peers.
///
/// # Errors
/// Returns an I/O or schema error. Such errors are INVALID, never PASS.
pub fn evaluate_path(path: &Path) -> Result<Report, String> {
    let file = File::open(path).map_err(|error| format!("read stability evidence: {error}"))?;
    let mut bytes = Vec::new();
    file.take((schema::MAX_EVIDENCE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read stability evidence: {error}"))?;
    let evidence = schema::parse(&bytes)?;
    let mut report = evaluate::evaluate(&evidence, &hash::sha256_hex(schema::CONTRACT.as_bytes()));
    if evidence.identity.source_commit != rust_reality::BUILD_COMMIT {
        report.reject(
            Verdict::Invalid,
            "evaluator",
            "harness build commit differs from the candidate source",
        );
    }
    let root = path.parent().unwrap_or_else(|| Path::new("."));
    for artifact in artifacts(&evidence) {
        if let Err(error) = verify_artifact(root, artifact) {
            report.reject(Verdict::Invalid, "artifact", &error);
        }
    }
    for check in &evidence.checks {
        match verify_required_check(root, check, &evidence.identity) {
            Ok(native) => report.extend(native),
            Err(error) => report.reject(Verdict::Invalid, &check.name, &error),
        }
    }
    let contract: schema::Contract =
        serde_json::from_str(schema::CONTRACT).expect("compiled stability contract");
    let mut observation_hashes = std::collections::BTreeSet::new();
    for cell in &evidence.cells {
        if let Err(error) = verify_cell_execution(root, cell, &evidence.identity, &contract) {
            report.reject(Verdict::Invalid, &cell.name, &error);
        }
        if let Err(error) = verify_cell_actions(root, cell, &contract) {
            report.reject(Verdict::Invalid, &cell.name, &error);
        }
        verify_cell_transfers(root, cell, &mut report);
        for (started_ms, checkpoint) in cell
            .cycles
            .iter()
            .flat_map(|cycle| {
                cycle
                    .checkpoints
                    .iter()
                    .map(move |checkpoint| (cycle.started_ms, checkpoint))
            })
            .chain(cell.faults.iter().flat_map(|fault| {
                fault
                    .checkpoints
                    .iter()
                    .map(move |checkpoint| (fault.started_ms, checkpoint))
            }))
            .chain(
                cell.integrity_checkpoints
                    .iter()
                    .map(|checkpoint| (contract.integrity_start(), checkpoint)),
            )
        {
            for sample in &checkpoint.samples {
                if !observation_hashes.insert(&sample.observation.sha256) {
                    report.reject(
                        Verdict::Invalid,
                        &cell.name,
                        "raw observation reused across checkpoints",
                    );
                }
                if let Some(role) = cell.roles.iter().find(|role| role.name == sample.role) {
                    let verified = read_artifact(root, &sample.observation).and_then(|bytes| {
                        let raw = schema::parse_observation(&bytes)?;
                        clock::checkpoint(
                            &raw,
                            cell.started_unix_ms,
                            started_ms
                                .checked_add(checkpoint.offset_ms)
                                .ok_or("checkpoint overflow")?,
                            &contract,
                        )?;
                        observation::verify(&raw, sample, &role.policy)
                    });
                    if let Err(error) = verified {
                        report.reject(Verdict::Invalid, &cell.name, &error);
                    }
                }
            }
        }
    }
    if hash::sha256_file(Path::new("/proc/self/exe"))? != evidence.identity.evaluator.sha256 {
        report.reject(
            Verdict::Invalid,
            "evaluator",
            "execute the frozen evaluator named by this evidence",
        );
    }
    Ok(report)
}

fn verify_required_check(
    root: &Path,
    check: &schema::Check,
    identity: &schema::Identity,
) -> Result<Report, String> {
    let contract: schema::Contract =
        serde_json::from_str(schema::CONTRACT).expect("compiled contract");
    match check.name.as_str() {
        "native-interop" => verify_interop_receipt(root, check, identity),
        "native-descriptor-pressure" => verify_pressure_receipt(root, check, identity),
        "native-resources" => verify_native_receipt(root, &check.output, identity),
        "local-full-gate" => {
            let gate = checks::verify_gate(&read_artifact(root, &check.output)?, check, identity,
                &crate::check::required_stage_labels())?;
            let mut names = std::collections::BTreeSet::new();
            for stage in &gate.stages {
                for name in [&stage.stdout_log, &stage.stderr_log] {
                    if Path::new(name).components().count() != 1 || !names.insert(name) {
                        return Err("gate stage logs were reused or escaped their directory".to_owned());
                    }
                    let path = Path::new(&check.argv[6]).join(name);
                    let artifact = check.observations.iter().find(|artifact| Path::new(&artifact.path) == path)
                        .ok_or("missing retained gate stage log")?;
                    verify_artifact(root, artifact)?;
                }
            }
            if check.observations.len() != names.len() {
                return Err("duplicated or unrelated gate observations".to_owned());
            }
            Ok(Report { verdict: Verdict::Pass, findings: Vec::new() })
        }
        "exact-head-ci" | "exact-head-security" => {
            checks::verify_ci(&read_artifact(root, &check.output)?, check, identity)?;
            Ok(Report { verdict: Verdict::Pass, findings: Vec::new() })
        }
        _ if contract.deterministic_tests.contains_key(&check.name) => {
            test_receipt::verify(&read_artifact(root, &check.output)?, check, &contract)?;
            Ok(Report { verdict: Verdict::Pass, findings: Vec::new() })
        }
        _ => Err("required check lacks a supported executable receipt; an opaque success claim cannot qualify".to_owned()),
    }
}

pub(super) fn verify_pressure_receipt(
    root: &Path,
    check: &schema::Check,
    identity: &schema::Identity,
) -> Result<Report, String> {
    let receipt = native_pressure::parse(&read_artifact(root, &check.output)?)?;
    let environment =
        native_interop::parse_environment(&read_artifact(root, &identity.environment)?)?;
    native_pressure::verify(&receipt, &environment, check, identity)?;
    let directory = Path::new(&check.output.path)
        .parent()
        .ok_or("missing pressure directory")?;
    let observation = |name: &str| -> Result<Vec<u8>, String> {
        let path = directory.join(name);
        let mut found = check
            .observations
            .iter()
            .filter(|artifact| Path::new(&artifact.path) == path);
        let artifact = found.next().ok_or("missing pressure raw observation")?;
        if found.next().is_some() {
            return Err("duplicate pressure observation".to_owned());
        }
        read_artifact(root, artifact)
    };
    native_pressure::transitions(&observation("server.log")?, &receipt)?;
    for (name, count, digest) in [
        ("control-received.bin", 4096, &receipt.result.control_sha256),
        (
            "recovery-received.bin",
            65536,
            &receipt.result.recovery_sha256,
        ),
    ] {
        let bytes = observation(name)?;
        if bytes.len() != count
            || !bytes.iter().copied().eq((0_u8..=255).cycle().take(count))
            || hash::sha256_hex(&bytes) != *digest
        {
            return Err("pressure control/recovery bytes differ from the fixed payload".to_owned());
        }
    }
    Ok(Report {
        verdict: Verdict::Pass,
        findings: Vec::new(),
    })
}

fn verify_interop_receipt(
    root: &Path,
    check: &schema::Check,
    identity: &schema::Identity,
) -> Result<Report, String> {
    let receipt = native_interop::parse(&read_artifact(root, &check.output)?)?;
    let environment =
        native_interop::parse_environment(&read_artifact(root, &identity.environment)?)?;
    native_interop::verify(
        &receipt,
        &environment,
        check,
        identity,
        crate::bench::no_ccs::REQUIRED_OPENSSL_PREFIX,
    )?;
    let directory = Path::new(&check.output.path)
        .parent()
        .ok_or("missing interop directory")?;
    let observation = |name: &str| -> Result<Vec<u8>, String> {
        let path = directory.join(name);
        let mut found = check
            .observations
            .iter()
            .filter(|artifact| Path::new(&artifact.path) == path);
        let artifact = found
            .next()
            .ok_or("missing interoperability raw observation")?;
        if found.next().is_some() {
            return Err("duplicate interoperability observation".to_owned());
        }
        read_artifact(root, artifact)
    };
    let source = observation("payload-1.bin")?;
    let received = observation("download.bin")?;
    if source.len() as u64 != receipt.assertions.payload_bytes
        || source != received
        || hash::sha256_hex(&source) != receipt.assertions.payload_sha256
        || !source
            .iter()
            .copied()
            .eq((0_u8..=255).cycle().take(source.len()))
    {
        return Err(
            "interoperability payload does not reproduce the exact received bytes".to_owned(),
        );
    }
    let trace = observation(&receipt.trace)?;
    crate::bench::no_ccs::assert_no_server_ccs(
        std::str::from_utf8(&trace).map_err(|error| error.to_string())?,
    )?;
    Ok(Report {
        verdict: Verdict::Pass,
        findings: Vec::new(),
    })
}

fn verify_cell_actions(
    root: &Path,
    cell: &schema::Cell,
    contract: &schema::Contract,
) -> Result<(), String> {
    let mut configuration_digests = std::collections::BTreeMap::new();
    for fault in &cell.faults {
        let mut coverage = std::collections::BTreeSet::new();
        for artifact in &fault.actions {
            let receipt = action::parse(&read_artifact(root, artifact)?)?;
            let role = cell
                .roles
                .iter()
                .find(|role| role.name == receipt.role)
                .ok_or("unknown action role")?;
            action::verify(&receipt, role, cell, fault, contract)?;
            if !coverage.insert((&role.name, receipt.begin)) {
                return Err("duplicated fault action".to_owned());
            }
            let key = (role.name.clone(), receipt.warm_tcp);
            if let Some(expected) =
                configuration_digests.insert(key, receipt.configuration_sha256.clone())
                && expected != receipt.configuration_sha256
            {
                return Err("configuration changed outside the fixed warm/cold variants".to_owned());
            }
            action::publication(
                &read_artifact(
                    root,
                    role.server_logs.first().ok_or("missing pre-restart log")?,
                )?,
                &receipt,
                contract.checkpoint_tolerance_ms,
            )?;
        }
        if coverage.len() != contract.roles.len() * 2 {
            return Err("missing fault actions or restoration receipts".to_owned());
        }
    }
    for role in &cell.roles {
        if role.name != "landing"
            && configuration_digests.get(&(role.name.clone(), Some(true)))
                == configuration_digests.get(&(role.name.clone(), Some(false)))
        {
            return Err("warm and cold configuration bytes were identical".to_owned());
        }
    }
    Ok(())
}

fn verify_role_clocks(
    root: &Path,
    role: &schema::Role,
    contract: &schema::Contract,
    started: u64,
    completed_after: u64,
) -> Result<(), String> {
    for (index, artifact) in role.clocks.iter().enumerate() {
        let probe = clock::parse(&read_artifact(root, artifact)?)?;
        clock::verify_lifetime(&probe, contract, role, index == 0, started, completed_after)?;
    }
    Ok(())
}

fn verify_cell_execution(
    root: &Path,
    cell: &schema::Cell,
    identity: &schema::Identity,
    contract: &schema::Contract,
) -> Result<(), String> {
    let terminal: execution::CellTerminal =
        serde_json::from_slice(&read_artifact(root, &cell.terminal)?)
            .map_err(|error| error.to_string())?;
    if terminal.primary_error.is_some()
        || !terminal.finalization_errors.is_empty()
        || !cell.completed
    {
        return Err("cell execution or finalization failed".to_owned());
    }
    let completed_after = cell
        .started_unix_ms
        .checked_add(contract.integrity_start())
        .and_then(|start| start.checked_add(contract.integrity_offsets()[3]))
        .ok_or("terminal schedule overflow")?;
    let mut oom_kills = 0_u64;
    let mut panics = 0_u64;
    let mut rejections = 0_u64;
    for role in &cell.roles {
        verify_role_clocks(root, role, contract, cell.started_unix_ms, completed_after)?;
        execution::startup(&read_artifact(root, &role.startup)?, role)?;
        let before = execution::parse_environment(&read_artifact(root, &role.environment[0])?)?;
        let after = execution::parse_environment(&read_artifact(root, &role.environment[1])?)?;
        if after.observed_unix_ms < completed_after {
            return Err("terminal kernel census preceded integrity recovery".to_owned());
        }
        oom_kills = oom_kills
            .checked_add(execution::environment_pair(&before, &after, role, cell)?)
            .ok_or("OOM count overflow")?;
        execution::terminal(
            &read_artifact(root, &role.terminal_status)?,
            role,
            cell,
            identity,
            after.observed_unix_ms,
        )?;
        if role.server_logs.len() != if role.name == "landing" { 2 } else { 1 } {
            return Err("incomplete product process-lifetime logs".to_owned());
        }
        let mut log_hashes = std::collections::BTreeSet::new();
        for log in &role.server_logs {
            if !log_hashes.insert(&log.sha256) {
                return Err("product log reused across process lifetimes".to_owned());
            }
            let counts = execution::product_log(&read_artifact(root, log)?)?;
            panics += counts.panics;
            rejections += counts.rejections;
        }
        let baseline = cell
            .cycles
            .first()
            .and_then(|cycle| cycle.checkpoints.first())
            .and_then(|checkpoint| {
                checkpoint
                    .samples
                    .iter()
                    .find(|sample| sample.role == role.name)
            })
            .ok_or("missing startup ownership observation")?;
        let raw = schema::parse_observation(&read_artifact(root, &baseline.observation)?)?;
        if observation::startup_policy(&raw, 1)? != role.policy {
            return Err("declared startup resource policy was substituted".to_owned());
        }
        let recovered = cell
            .integrity_checkpoints
            .last()
            .and_then(|checkpoint| {
                checkpoint
                    .samples
                    .iter()
                    .find(|sample| sample.role == role.name)
            })
            .ok_or("missing terminal recovery observation")?;
        let final_raw = schema::parse_observation(&read_artifact(root, &recovered.observation)?)?;
        for (observation, log) in [
            (&raw, role.server_logs.first()),
            (&final_raw, role.server_logs.last()),
        ] {
            let log = read_artifact(root, log.ok_or("missing product log")?)?;
            if !log.starts_with(
                observation
                    .ownership_log
                    .as_ref()
                    .ok_or("missing sampled log")?
                    .as_bytes(),
            ) {
                return Err("product log differs from its sampled process lifetime".to_owned());
            }
        }
    }
    if oom_kills != cell.oom_kills
        || panics != cell.panics
        || rejections != cell.unexpected_rejections
    {
        return Err("kernel or product failures were misreported".to_owned());
    }
    Ok(())
}

fn verify_cell_transfers(root: &Path, cell: &schema::Cell, report: &mut Report) {
    for transfer in cell
        .cycles
        .iter()
        .flat_map(|cycle| &cycle.transfers)
        .chain(cell.integrity.iter())
        .chain(cell.faults.iter().flat_map(|fault| {
            fault
                .during_transfers
                .iter()
                .chain(&fault.recovery_transfers)
                .chain(std::iter::once(&fault.affected_prefix))
        }))
    {
        if let Err(error) = verify_transfer_files(root, transfer) {
            report.reject(Verdict::Invalid, &transfer.id, &error);
        }
    }
}

fn verify_transfer_files(root: &Path, transfer: &schema::Transfer) -> Result<(), String> {
    let source = read_artifact(root, &transfer.source)?;
    if u64::try_from(source.len()).ok() != Some(transfer.expected_bytes)
        || transfer.source.sha256 != transfer.expected_sha256
    {
        return Err("source payload does not reproduce the expected bytes and digest".to_owned());
    }
    match (&transfer.download, transfer.direction.as_str()) {
        (None, "upload") => {}
        (Some(download), "download" | "bidirectional") => {
            let received = read_artifact(root, download)?;
            if received != source
                || u64::try_from(received.len()).ok() != Some(transfer.received_bytes)
                || download.sha256 != transfer.received_sha256
            {
                return Err("received payload or prefix differs from retained source".to_owned());
            }
        }
        _ => return Err("missing or unrelated received payload artifact".to_owned()),
    }
    if let Some(upload) = &transfer.upload {
        transfer::verify_upload(
            &read_artifact(root, &upload.access_log_before)?,
            &read_artifact(root, &upload.access_log_after)?,
            upload,
        )?;
    }
    Ok(())
}

fn read_artifact(root: &Path, artifact: &Artifact) -> Result<Vec<u8>, String> {
    verify_artifact(root, artifact)?;
    let file = File::open(root.join(&artifact.path)).map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    file.take((schema::MAX_EVIDENCE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > schema::MAX_EVIDENCE_BYTES {
        return Err("evidence object exceeds 64 MiB".to_owned());
    }
    Ok(bytes)
}

fn verify_native_receipt(
    root: &Path,
    artifact: &Artifact,
    identity: &schema::Identity,
) -> Result<Report, String> {
    let receipt = schema::parse_native(&read_artifact(root, artifact)?)?;
    let contract: schema::Contract =
        serde_json::from_str(schema::CONTRACT).expect("compiled contract");
    let mut report = native_evaluate::evaluate(
        &receipt,
        &identity.source_commit,
        &identity.candidate.sha256,
        &identity.evaluator.sha256,
        &identity.contract.sha256,
    );
    let root = root.join(
        Path::new(&artifact.path)
            .parent()
            .ok_or("native receipt has no directory")?,
    );
    for checkpoint in &receipt.checkpoints {
        for artifact in &checkpoint.observations {
            if let Err(error) = verify_artifact(&root, artifact) {
                report.reject(Verdict::Invalid, "native-resources", &error);
            }
        }
        for sample in &checkpoint.samples {
            let result = (|| {
                let raw = schema::parse_observation(&read_artifact(&root, &sample.observation)?)?;
                let policy = &receipt
                    .policies
                    .iter()
                    .find(|policy| policy.role == sample.role)
                    .ok_or("missing native policy")?
                    .policy;
                let scheduled = if let Some(offset) = checkpoint.phase.strip_prefix("recovery-") {
                    receipt
                        .recovery_started_unix_ms
                        .and_then(|start| {
                            offset
                                .parse::<u64>()
                                .ok()
                                .and_then(|offset| start.checked_add(offset))
                        })
                        .ok_or("invalid native recovery schedule")?
                } else {
                    checkpoint.started_unix_ms
                };
                observation::verify_checkpoint_time(
                    &raw,
                    0,
                    scheduled,
                    contract.checkpoint_tolerance_ms,
                )?;
                observation::verify(&raw, sample, policy)?;
                if checkpoint.phase == "baseline" {
                    if receipt
                        .workload_started_unix_ms
                        .is_none_or(|start| raw.completed_unix_ms > start)
                        || observation::startup_policy(&raw, policy.listener_sockets)? != *policy
                    {
                        return Err("native baseline or policy was substituted".to_owned());
                    }
                } else if checkpoint.phase.starts_with("round-")
                    && receipt
                        .recovery_started_unix_ms
                        .is_none_or(|start| raw.completed_unix_ms > start)
                {
                    return Err("native round observation continued into recovery".to_owned());
                }
                Ok(())
            })();
            if let Err(error) = result {
                report.reject(Verdict::Invalid, "native-resources", &error);
            }
        }
    }
    Ok(report)
}

fn artifacts(evidence: &Evidence) -> Vec<&Artifact> {
    let identity = &evidence.identity;
    let mut artifacts = vec![
        &identity.source_archive,
        &identity.candidate,
        &identity.evaluator,
        &identity.contract,
        &identity.environment,
        &identity.workload,
    ];
    artifacts.extend(evidence.checks.iter().map(|check| &check.output));
    artifacts.extend(evidence.checks.iter().flat_map(|check| &check.observations));
    for cell in &evidence.cells {
        artifacts.push(&cell.terminal);
        artifacts.extend(cell.roles.iter().map(|role| &role.startup));
        artifacts.extend(cell.roles.iter().flat_map(|role| &role.clocks));
    }
    artifacts
}

fn verify_artifact(root: &Path, artifact: &Artifact) -> Result<(), String> {
    let relative = Path::new(&artifact.path);
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        || !evaluate::digest(&artifact.sha256, 64)
    {
        return Err("invalid artifact path or SHA-256".to_owned());
    }
    // Reject symlinks at every component, including links that happen to point
    // inside this bundle. Offline evidence must not depend on external files.
    let mut path = root.to_path_buf();
    for component in relative.components() {
        path.push(component);
        let metadata = path
            .symlink_metadata()
            .map_err(|error| format!("missing artifact {}: {error}", artifact.path))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("artifact {} traverses a symlink", artifact.path));
        }
    }
    if !path.is_file() || hash::sha256_file(&path)? != artifact.sha256 {
        return Err(format!("artifact {} is missing or changed", artifact.path));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
