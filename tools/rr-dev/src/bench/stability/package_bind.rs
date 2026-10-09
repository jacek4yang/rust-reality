//! Bind independently retained native package receipts without inventing executions.

use super::{evaluate::Verdict, qualification::CollectionLock, schema, workload};
use crate::release::{matrix::Tier, receipt};
use clap::Args;
use std::{
    fs,
    io::Read as _,
    path::{Component, Path, PathBuf},
};

/// Inputs for one native package receipt import.
#[derive(Args)]
pub struct Plan {
    /// Existing frozen campaign aggregate to extend.
    #[arg(long)]
    pub evidence: PathBuf,
    /// Freshly downloaded native smoke receipt directory, never an asset-only bundle.
    #[arg(long)]
    pub receipt_dir: PathBuf,
}

fn bounded_json(path: &Path) -> Result<Vec<u8>, String> {
    if !fs::symlink_metadata(path)
        .map_err(|e| e.to_string())?
        .is_file()
    {
        return Err("receipt input must be a regular file".to_owned());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take((schema::MAX_EVIDENCE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > schema::MAX_EVIDENCE_BYTES {
        return Err("receipt input exceeds its bound".to_owned());
    }
    Ok(bytes)
}

fn copy_image(source: &Path, destination: &Path, name: &str) -> Result<(), String> {
    let mut parts = Path::new(name).components();
    if !matches!(parts.next(), Some(Component::Normal(_))) || parts.next().is_some() {
        return Err("package receipt filename is not a single safe component".to_owned());
    }
    let input = source.join(name);
    let metadata = fs::symlink_metadata(&input).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > 256 * 1024 * 1024 {
        return Err("package receipt file is non-regular or oversized".to_owned());
    }
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination.join(name))
        .map_err(|e| e.to_string())?;
    let mut input = fs::File::open(input)
        .map_err(|e| e.to_string())?
        .take(256 * 1024 * 1024 + 1);
    if std::io::copy(&mut input, &mut output).map_err(|e| e.to_string())? > 256 * 1024 * 1024 {
        return Err("package receipt grew beyond its bound".to_owned());
    }
    Ok(())
}

/// Verify the native receipt and append one check atomically. Failed imports remain separate.
///
/// # Errors
/// Rejects mismatched sources, binaries, native hosts, receipts, duplicate attempts or file changes.
pub fn run(plan: &Plan) -> Result<(), String> {
    let path = plan.evidence.canonicalize().map_err(|e| e.to_string())?;
    let root = path.parent().ok_or("missing aggregate directory")?;
    let _reservation = CollectionLock::acquire(root)?;
    let before = bounded_json(&path)?;
    let mut evidence = schema::parse(&before)?;
    if evidence.identity.contract.sha256 != crate::hash::sha256_hex(schema::CONTRACT.as_bytes()) {
        return Err(
            "package import requires the frozen contract supported by this collector".to_owned(),
        );
    }
    for artifact in super::artifacts(&evidence) {
        super::verify_artifact(root, artifact)?;
    }
    let bytes = bounded_json(&plan.receipt_dir.join("receipt.json"))?;
    let native = receipt::parse(&bytes)?;
    let tier = Tier::resolve(&native.tier)?;
    receipt::verify(&native, &evidence.identity.source_commit, tier)?;
    let name = match native.tier.as_str() {
        "linux-x86_64-generic" => "package-gnu",
        "linux-x86_64-musl" => "package-musl",
        "linux-x86_64-v3" => "package-v3",
        "linux-aarch64-generic" => "package-aarch64",
        _ => return Err("unsupported package tier".to_owned()),
    };
    if evidence.checks.iter().any(|check| check.name == name) {
        return Err("package check already attempted; preserve the existing bundle".to_owned());
    }
    let directory = root.join(format!("required-{name}"));
    fs::create_dir(&directory).map_err(|e| e.to_string())?;
    fs::write(directory.join("evidence-before.json"), &before).map_err(|e| e.to_string())?;
    fs::write(directory.join("receipt.json"), &bytes).map_err(|e| e.to_string())?;
    let names = [
        native.archive.path.clone(),
        native.binary.path.clone(),
        native.harness.path.clone(),
        format!("{}.tier.json", tier.id),
        "cpuinfo.txt".to_owned(),
    ];
    let mut observations = Vec::new();
    for file in &names {
        copy_image(&plan.receipt_dir, &directory, file)?;
        observations.push(workload::artifact(root, &directory.join(file))?);
    }
    let output = workload::artifact(root, &directory.join("receipt.json"))?;
    let harness = workload::artifact(root, &directory.join("rr-dev"))?;
    let check = schema::Check {
        name: name.to_owned(),
        source_commit: evidence.identity.source_commit.clone(),
        candidate_sha256: evidence.identity.candidate.sha256.clone(),
        argv: vec![
            harness.path,
            "release".to_owned(),
            "smoke".to_owned(),
            native.tag,
            tier.id.to_owned(),
            native.assets_directory,
            "--receipt-dir".to_owned(),
            native.output_directory,
        ],
        exit_code: Some(0),
        completed: true,
        executed_cases: 7,
        failed_cases: 0,
        execution: output.clone(),
        output,
        observations,
    };
    // Derive acceptance from the retained seven executions and actual archive bytes.
    // Never accept a success label, missing receipt or same-source/different GNU binary.
    let report = super::verify_required_check(root, &check, &evidence.identity)?;
    if report.verdict != Verdict::Pass {
        return Err(format!("package receipt rejected: {:?}", report.findings));
    }
    evidence.checks.push(check);
    if fs::read(&path).map_err(|e| e.to_string())? != before {
        return Err("aggregate changed during package import".to_owned());
    }
    let next = serde_json::to_vec_pretty(&evidence).map_err(|e| e.to_string())?;
    fs::write(directory.join("evidence-after.json"), &next).map_err(|e| e.to_string())?;
    let pending = directory.join("aggregate-next.json");
    fs::write(&pending, next).map_err(|e| e.to_string())?;
    fs::rename(pending, path).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn coordinated_workflow_uses_one_package_and_requires_frozen_acceptance() {
        let coordinator = include_str!("../../../../../.github/workflows/frozen-qualification.yml");
        let campaign = include_str!("../../../../../.github/workflows/qemu-specialist.yml");
        let packages = include_str!("../../../../../.github/workflows/candidate-packages.yml");
        assert!(coordinator.contains("needs: packages"));
        assert!(coordinator.contains("package_artifact: package-receipt-"));
        assert!(coordinator.contains("bench stability-bind-package"));
        assert!(coordinator.contains("bench stability-evaluate"));
        assert!(coordinator.contains("--case long-lived-connections"));
        assert!(coordinator.contains("--case local-full-gate"));
        assert!(coordinator.contains(
            "native-interop native-mechanism native-descriptor-pressure native-resources"
        ));
        assert!(!coordinator.contains("continue-on-error"));
        assert!(!coordinator.contains("contents: write"));
        assert!(!coordinator.contains("cancel-in-progress: true"));
        // Workflow may still be the sequential campaign until a token with
        // `workflow` scope publishes the ADR 0042 matrix rewrite.
        assert!(
            campaign.contains("--candidate \"$CANDIDATE_BIN\"")
                || campaign
                    .contains("--candidate \"$RUNNER_TEMP/rr-qemu-prepare/bin/rust-reality\"")
        );
        assert!(campaign.contains("bench stability-run"));
        assert!(
            campaign.contains("hosted-qemu-campaign-${{ inputs.candidate_sha")
                || campaign.contains("hosted-qemu-campaign-${{ env.HEAD_SHA }}")
        );
        if campaign.contains("stability-merge-cells") {
            assert!(campaign.contains("--cell \"$MATRIX_CELL\""));
            assert!(campaign.contains("fail-fast: false"));
        }
        assert!(packages.contains("--receipt-dir"));
        assert!(coordinator.contains(
            "source.name in ['evidence.json','evidence-before.json','evidence-after.json']"
        ));
        assert!(!coordinator.contains(
            "references(json.loads(source.read_text()))\n              elif source.suffix"
        ));
    }

    #[test]
    fn package_input_paths_cannot_escape_or_follow_symlinks() {
        let work = crate::bench::workspace::Workspace::create("package-import-paths").unwrap();
        for name in ["../outside", "/absolute", "a/b", ".", ""] {
            assert!(copy_image(work.path(), work.path(), name).is_err());
        }
        let oversized = fs::File::create(work.join("oversized")).unwrap();
        oversized.set_len(256 * 1024 * 1024 + 1).unwrap();
        assert!(copy_image(work.path(), work.path(), "oversized").is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/dev/null", work.join("linked")).unwrap();
            assert!(copy_image(work.path(), work.path(), "linked").is_err());
            assert!(bounded_json(&work.join("linked")).is_err());
        }
    }
}
