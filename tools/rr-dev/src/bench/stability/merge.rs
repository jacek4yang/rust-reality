//! Merge per-cell QEMU campaign directories into one identity-bound evidence bundle.
//!
//! Hosted four-cell parallelism (ADR 0042) runs each contract cell on its own
//! runner. Aggregation must fail closed on identity drift and missing cells, and
//! retain per-cell diagnosis so a framework defect is named in minutes.

use super::{
    diagnosis::classify,
    schema::{self, Evidence, Identity},
};
use clap::Args;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

/// Inputs for merging parallel cell campaign outputs.
#[derive(Args, Debug)]
pub struct Plan {
    /// Fresh directory for the merged campaign bundle.
    #[arg(long)]
    pub output: PathBuf,
    /// One or more `stability-run --cell` output directories (repeatable).
    #[arg(long = "cell-dir", required = true)]
    pub cell_dirs: Vec<PathBuf>,
}

fn save(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("write merge receipt: {error}"))
}

fn load_evidence(root: &Path) -> Result<Evidence, String> {
    let bytes = fs::read(root.join("evidence.json"))
        .map_err(|error| format!("{}: read evidence: {error}", root.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("{}: parse evidence: {error}", root.display()))
}

fn identity_fingerprint(identity: &Identity) -> Result<String, String> {
    serde_json::to_string(identity).map_err(|error| error.to_string())
}

fn copy_file(src_root: &Path, dst_root: &Path, relative: &str) -> Result<(), String> {
    let source = src_root.join(relative);
    let destination = dst_root.join(relative);
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    if destination.exists() {
        let left = fs::read(&source).map_err(|error| error.to_string())?;
        let right = fs::read(&destination).map_err(|error| error.to_string())?;
        if left != right {
            return Err(format!(
                "merged path {relative} differs across cell directories"
            ));
        }
        return Ok(());
    }
    fs::copy(&source, &destination)
        .map_err(|error| format!("copy {relative} from {}: {error}", src_root.display()))?;
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path) -> Result<(), String> {
    if !src.is_dir() {
        return Err(format!("missing cell tree {}", src.display()));
    }
    fs::create_dir_all(dst).map_err(|error| error.to_string())?;
    for entry in fs::read_dir(src).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        let target = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if file_type.is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            fs::copy(entry.path(), &target).map_err(|error| error.to_string())?;
        } else {
            return Err(format!("refusing non-regular {}", entry.path().display()));
        }
    }
    Ok(())
}

fn identity_files(identity: &Identity) -> [&str; 6] {
    [
        identity.source_archive.path.as_str(),
        identity.candidate.path.as_str(),
        identity.evaluator.path.as_str(),
        identity.contract.path.as_str(),
        identity.environment.path.as_str(),
        identity.workload.path.as_str(),
    ]
}

fn absorb_fail_closed_summary(
    root: &Path,
    summary: &mut Vec<Value>,
    cell_errors: &mut Vec<String>,
) {
    let Ok(bytes) = fs::read(root.join("cells-summary.json")) else {
        return;
    };
    let Ok(Value::Array(items)) = serde_json::from_slice::<Value>(&bytes) else {
        return;
    };
    for item in items {
        if let Some(name) = item.get("cell").and_then(Value::as_str)
            && item.get("result").and_then(Value::as_str) == Some("fail-closed")
        {
            let error = item
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("cell failed");
            cell_errors.push(format!("{name}: {error}"));
            if !summary.iter().any(|row| {
                row.get("cell").and_then(Value::as_str) == Some(name)
                    && row.get("result").and_then(Value::as_str) == Some("fail-closed")
            }) {
                let mut row = item.clone();
                if row.get("class_hint").is_none() {
                    row["class_hint"] = json!(classify(error).label());
                }
                summary.push(row);
            }
        }
    }
}

fn absorb_terminal(root: &Path, cell_errors: &mut Vec<String>) -> Result<(), String> {
    let terminal = root.join("campaign-terminal.json");
    if !terminal.is_file() {
        return Ok(());
    }
    let value: Value =
        serde_json::from_slice(&fs::read(&terminal).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    if value.get("completed").and_then(Value::as_bool) != Some(true) {
        let primary = value
            .get("primary_error")
            .and_then(Value::as_str)
            .unwrap_or("cell campaign incomplete");
        cell_errors.push(format!("{}: {primary}", root.display()));
    }
    Ok(())
}

fn ingest_cell(
    root: &Path,
    out: &Path,
    expected: &BTreeSet<String>,
    seen: &mut BTreeSet<String>,
    merged: &mut Evidence,
    summary: &mut Vec<Value>,
    cell_errors: &mut Vec<String>,
) -> Result<(), String> {
    let evidence = load_evidence(root)?;
    for relative in identity_files(&evidence.identity) {
        copy_file(root, out, relative)?;
    }
    for name in ["rust-reality", "rr-dev", "xray", "openssl"] {
        if root.join(name).is_file() {
            copy_file(root, out, name)?;
        }
    }
    for cell in &evidence.cells {
        if !expected.contains(&cell.name) {
            return Err(format!("unexpected cell {}", cell.name));
        }
        if !seen.insert(cell.name.clone()) {
            return Err(format!("duplicate cell {}", cell.name));
        }
        let cell_dir_name = cell.name.replace('/', "-");
        copy_tree(&root.join(&cell_dir_name), &out.join(&cell_dir_name))?;
        for side in ["cell-diagnosis.json", "cell-terminal.json"] {
            let path = root.join(side);
            if path.is_file() {
                let dest_name = format!("{cell_dir_name}-{side}");
                fs::copy(&path, out.join(dest_name)).map_err(|error| error.to_string())?;
            }
        }
        let diagnosis_path = root.join(&cell_dir_name).join("cell-diagnosis.json");
        if diagnosis_path.is_file() {
            let diagnosis: Value = serde_json::from_slice(
                &fs::read(&diagnosis_path).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            summary.push(diagnosis);
        } else if cell.completed {
            summary.push(json!({
                "cell": cell.name,
                "result": "pass",
                "faults": cell.faults.iter().map(|fault| &fault.name).collect::<Vec<_>>(),
                "class_hint": null,
            }));
        } else {
            let message = format!("{}: cell incomplete after merge intake", cell.name);
            summary.push(json!({
                "cell": cell.name,
                "result": "fail-closed",
                "error": message,
                "class_hint": classify(&message).label(),
            }));
            cell_errors.push(message);
        }
        merged.cells.push(cell.clone());
    }
    absorb_fail_closed_summary(root, summary, cell_errors);
    absorb_terminal(root, cell_errors)?;
    Ok(())
}

fn write_diagnosis(out: &Path, summary: &[Value], cell_errors: &[String]) -> Result<(), String> {
    let mut class_counts = BTreeMap::<&str, usize>::new();
    for row in summary {
        if let Some(label) = row.get("class_hint").and_then(Value::as_str) {
            *class_counts.entry(label).or_default() += 1;
        }
    }
    save(
        &out.join("merge-diagnosis.json"),
        &json!({
            "schema": "rr-stability-merge-diagnosis/v1",
            "cells": summary,
            "class_counts": class_counts,
            "fail_closed": !cell_errors.is_empty(),
        }),
    )
}

fn finalize(out: &Path, cell_errors: &[String]) -> Result<(), String> {
    if !cell_errors.is_empty() {
        let joined = cell_errors.join("; ");
        let _ = save(
            &out.join("campaign-terminal.json"),
            &json!({
                "primary_error": joined,
                "completed": false,
                "class_hint": classify(&joined).label(),
            }),
        );
        return Err(format!(
            "merged campaign fail-closed ({})",
            classify(&joined).label()
        ));
    }
    let report = super::evaluate_path(&out.join("evidence.json"))?;
    save(&out.join("verdict.json"), &report)?;
    save(
        &out.join("campaign-terminal.json"),
        &json!({"primary_error": Value::Null, "completed": true}),
    )?;
    if matches!(
        report.verdict,
        super::evaluate::Verdict::Fail | super::evaluate::Verdict::Invalid
    ) {
        return Err(
            "merged VM evidence failed offline evaluation; verdict and raw files retained"
                .to_owned(),
        );
    }
    println!(
        "Merged four-cell campaign; aggregate qualification verdict {:?} (required check receipts must also be bound).",
        report.verdict
    );
    Ok(())
}

/// Merge cell campaign directories into one offline-evaluable bundle.
///
/// # Errors
/// Fails closed on identity mismatch, duplicate/missing cells, or I/O errors.
pub fn run(plan: &Plan) -> Result<(), String> {
    if plan.cell_dirs.is_empty() {
        return Err("stability-merge-cells requires at least one --cell-dir".to_owned());
    }
    fs::create_dir(&plan.output).map_err(|error| format!("fresh merge directory: {error}"))?;
    let out = plan
        .output
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let contract: schema::Contract =
        serde_json::from_str(schema::CONTRACT).expect("compiled contract");
    let expected: BTreeSet<String> = contract.cells.iter().cloned().collect();
    let mut seen = BTreeSet::new();
    let first = load_evidence(&plan.cell_dirs[0])?;
    let fingerprint = identity_fingerprint(&first.identity)?;
    let mut merged = Evidence {
        schema: "rr-stability-evidence/v1".to_owned(),
        identity: first.identity,
        checks: Vec::new(),
        cells: Vec::new(),
    };
    let mut summary = Vec::new();
    let mut cell_errors = Vec::new();

    for dir in &plan.cell_dirs {
        let root = dir
            .canonicalize()
            .map_err(|error| format!("cell-dir {}: {error}", dir.display()))?;
        let evidence = load_evidence(&root)?;
        if identity_fingerprint(&evidence.identity)? != fingerprint {
            return Err(format!(
                "{}: identity mismatch versus first cell-dir (source/artifact binding must match)",
                root.display()
            ));
        }
        if !evidence.checks.is_empty() {
            return Err(format!(
                "{}: cell directories must not carry required-check receipts; bind those after merge",
                root.display()
            ));
        }
        ingest_cell(
            &root,
            &out,
            &expected,
            &mut seen,
            &mut merged,
            &mut summary,
            &mut cell_errors,
        )?;
    }

    let missing: Vec<_> = expected.difference(&seen).cloned().collect();
    if !missing.is_empty() {
        return Err(format!(
            "merged campaign missing cells: {}",
            missing.join(", ")
        ));
    }
    save(&out.join("cells-summary.json"), &summary)?;
    save(&out.join("evidence.json"), &merged)?;
    write_diagnosis(&out, &summary, &cell_errors)?;
    finalize(&out, &cell_errors)
}

#[cfg(test)]
mod tests {
    use super::super::diagnosis::Class;
    use super::*;
    use crate::bench::workspace::Workspace;

    fn minimal_identity() -> Identity {
        let art = |path: &str| schema::Artifact {
            path: path.to_owned(),
            sha256: "a".repeat(64),
        };
        Identity {
            source_commit: "abc".to_owned(),
            source_archive: art("source.tar"),
            candidate: art("rust-reality"),
            evaluator: art("rr-dev"),
            contract: art("contract.json"),
            environment: art("environment.json"),
            workload: art("workload.json"),
        }
    }

    fn write_identity_files(root: &Path) {
        for name in [
            "source.tar",
            "rust-reality",
            "rr-dev",
            "contract.json",
            "environment.json",
            "workload.json",
        ] {
            fs::write(root.join(name), name.as_bytes()).unwrap();
        }
    }

    #[test]
    fn merge_rejects_identity_drift() {
        let work = Workspace::create("stability-merge-identity").unwrap();
        let left = work.join("left");
        let right = work.join("right");
        fs::create_dir(&left).unwrap();
        fs::create_dir(&right).unwrap();
        write_identity_files(&left);
        write_identity_files(&right);
        let mut identity = minimal_identity();
        save(
            &left.join("evidence.json"),
            &Evidence {
                schema: "rr-stability-evidence/v1".into(),
                identity: identity.clone(),
                checks: vec![],
                cells: vec![],
            },
        )
        .unwrap();
        identity.source_commit = "other".into();
        save(
            &right.join("evidence.json"),
            &Evidence {
                schema: "rr-stability-evidence/v1".into(),
                identity,
                checks: vec![],
                cells: vec![],
            },
        )
        .unwrap();
        let err = run(&Plan {
            output: work.join("out"),
            cell_dirs: vec![left, right],
        })
        .unwrap_err();
        assert!(err.contains("identity mismatch"), "{err}");
        assert_eq!(classify(&err), Class::B);
    }

    #[test]
    fn merge_rejects_missing_contract_cells() {
        let work = Workspace::create("stability-merge-missing").unwrap();
        let only = work.join("only");
        fs::create_dir(&only).unwrap();
        write_identity_files(&only);
        save(
            &only.join("evidence.json"),
            &Evidence {
                schema: "rr-stability-evidence/v1".into(),
                identity: minimal_identity(),
                checks: vec![],
                cells: vec![],
            },
        )
        .unwrap();
        let err = run(&Plan {
            output: work.join("out"),
            cell_dirs: vec![only],
        })
        .unwrap_err();
        assert!(err.contains("missing cells"), "{err}");
    }
}
