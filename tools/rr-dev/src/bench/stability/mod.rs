//! Exact-candidate stability qualification and offline evidence verification.

pub mod collect;
pub mod evaluate;
pub mod fixture;
pub mod observation;
pub mod schema;
pub mod vm;

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
    let root = path.parent().unwrap_or_else(|| Path::new("."));
    for artifact in artifacts(&evidence) {
        if let Err(error) = verify_artifact(root, artifact) {
            report.reject(Verdict::Invalid, "artifact", &error);
        }
    }
    let contract: schema::Contract =
        serde_json::from_str(schema::CONTRACT).expect("compiled stability contract");
    for cell in &evidence.cells {
        for checkpoint in cell.cycles.iter().flat_map(|cycle| &cycle.checkpoints) {
            for sample in &checkpoint.samples {
                if let Some(role) = cell.roles.iter().find(|role| role.name == sample.role) {
                    let verified = verify_artifact(root, &sample.observation).and_then(|()| {
                        let file = File::open(root.join(&sample.observation.path))
                            .map_err(|error| error.to_string())?;
                        let mut bytes = Vec::new();
                        file.take((schema::MAX_EVIDENCE_BYTES + 1) as u64)
                            .read_to_end(&mut bytes)
                            .map_err(|error| error.to_string())?;
                        let raw = schema::parse_observation(&bytes)?;
                        observation::verify_checkpoint_time(
                            &raw,
                            cell.started_unix_ms,
                            checkpoint.observed_ms,
                            contract.checkpoint_tolerance_ms,
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
    let evaluator =
        std::env::current_exe().map_err(|error| format!("locate evaluator: {error}"))?;
    if hash::sha256_file(&evaluator)? != evidence.identity.evaluator.sha256 {
        report.reject(
            Verdict::Invalid,
            "evaluator",
            "execute the frozen evaluator named by this evidence",
        );
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
    for cell in &evidence.cells {
        artifacts.push(&cell.terminal);
        artifacts.extend(cell.roles.iter().map(|role| &role.startup));
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
