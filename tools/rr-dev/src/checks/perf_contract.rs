//! Protected-metric and cache-foundation manifest validator.
//!
//! Migrated from `check-performance-contract.py`. It enforces the same semantic
//! invariants over `benchmarks/contracts/protected-metrics-v1.json` and
//! `benchmarks/baselines/v1.6.1-cache-foundation.json`: schema versions, the exact
//! concurrency and CPU grids, the required workload families, non-negative
//! equivalence margins with descriptors pinned at zero, and the zero-allocation
//! baselines.
//!
//! The Python script additionally `compile()`-checked `perf-stat-evidence.py` and
//! `perf-c2c-evidence.py`. That step is intentionally not carried over: it only
//! proved two other soon-to-be-migrated scripts parse, which the shell gate's
//! `bash -n`/`python` sweep already covered while they exist, and it becomes
//! meaningless once those scripts are gone. This validator owns the contract data
//! rules and nothing about unrelated files.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use crate::perf::json_in::{self, Value};

const CONTRACT: &str = "benchmarks/contracts/protected-metrics-v1.json";
const BASELINE: &str = "benchmarks/baselines/v1.6.1-cache-foundation.json";

/// The eight workload families the contract must always cover.
const REQUIRED_WORKLOADS: [&str; 8] = [
    "setup-x25519",
    "setup-x25519mlkem768",
    "traffic-small-interactive",
    "traffic-large-sustained",
    "traffic-sparse",
    "traffic-half-close",
    "traffic-reset",
    "traffic-idle",
];

/// Why the contract check failed.
#[derive(Debug)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "performance/cache contract: {}", self.0)
    }
}

impl std::error::Error for Error {}

/// Validates both manifests, returning a PASS line on success.
///
/// # Errors
///
/// Returns [`Error`] naming the first violated invariant.
pub fn check(repo: &Path) -> Result<String, Error> {
    let contract = read(repo, CONTRACT)?;
    let baseline = read(repo, BASELINE)?;

    require(int(&contract, "schemaVersion")? == 1, "contract schemaVersion must be 1")?;
    require(int(&baseline, "schemaVersion")? == 1, "baseline schemaVersion must be 1")?;

    let families = string_array(&contract, "workloadFamilies")?;
    let unique: BTreeSet<&String> = families.iter().collect();
    require(unique.len() == families.len(), "workloadFamilies must be unique")?;

    require(
        int_array(&contract, "concurrency")? == [1, 8, 32, 64],
        "concurrency must be [1, 8, 32, 64]",
    )?;
    require(
        int_array(&contract, "effectiveCpuCounts")? == [1, 2, 4, 8],
        "effectiveCpuCounts must be [1, 2, 4, 8]",
    )?;

    let policy = contract
        .optional("policyCardinalities")
        .ok_or_else(|| Error("policyCardinalities missing".to_owned()))?;
    require(
        int_array(policy, "users")? == [1, 64, 128, 512, 1000, 10000],
        "policyCardinalities.users mismatch",
    )?;
    require(
        int_array(policy, "routingRules")? == [10, 100, 1000, 10000],
        "policyCardinalities.routingRules mismatch",
    )?;

    for workload in REQUIRED_WORKLOADS {
        require(
            unique.iter().any(|family| family.as_str() == workload),
            &format!("required workload family absent: {workload}"),
        )?;
    }

    let margins = contract
        .optional("equivalenceMarginsPercent")
        .and_then(|value| value.as_object("equivalenceMarginsPercent").ok())
        .ok_or_else(|| Error("equivalenceMarginsPercent missing".to_owned()))?;
    for (key, value) in margins {
        let number = value
            .as_f64(key)
            .map_err(|_| Error(format!("equivalence margin {key} is not a number")))?;
        require(number >= 0.0, &format!("equivalence margin {key} must be >= 0"))?;
    }
    let descriptors = margins
        .get("descriptors")
        .and_then(|value| value.as_f64("descriptors").ok())
        .ok_or_else(|| Error("descriptors margin missing".to_owned()))?;
    require((descriptors - 0.0).abs() < f64::EPSILON, "descriptors margin must be 0")?;

    let host = baseline
        .optional("host")
        .ok_or_else(|| Error("baseline host missing".to_owned()))?;
    require(
        str_field(host, "architecture")? == "x86_64",
        "baseline host architecture must be x86_64",
    )?;
    require(
        str_field(&baseline, "binarySha256")?.len() == 64,
        "binarySha256 must be 64 hex chars",
    )?;
    require(
        str_field(&baseline, "sourceCommit")?.len() == 40,
        "sourceCommit must be a 40-char commit",
    )?;
    let pmu_status = str_field(
        baseline
            .optional("pmu")
            .ok_or_else(|| Error("pmu missing".to_owned()))?,
        "status",
    )?;
    require(
        pmu_status == "PASS" || pmu_status == "UNAVAILABLE_WITH_HARNESS",
        "pmu.status must be PASS or UNAVAILABLE_WITH_HARNESS",
    )?;

    let sizes = baseline
        .optional("structureSizesBytes")
        .and_then(|value| value.as_object("structureSizesBytes").ok())
        .ok_or_else(|| Error("structureSizesBytes missing".to_owned()))?;
    for (key, value) in sizes {
        let bytes = value
            .as_f64(key)
            .map_err(|_| Error(format!("structure size {key} is not a number")))?;
        require(bytes > 0.0, &format!("structure size {key} must be > 0"))?;
    }

    let allocations = baseline
        .optional("allocationBaselines")
        .and_then(|value| value.as_object("allocationBaselines").ok())
        .ok_or_else(|| Error("allocationBaselines missing".to_owned()))?;
    for (key, value) in allocations {
        if key == "source" {
            continue;
        }
        let count = value
            .as_f64(key)
            .map_err(|_| Error(format!("allocation baseline {key} is not a number")))?;
        require((count - 0.0).abs() < f64::EPSILON, &format!("allocation baseline {key} must be 0"))?;
    }

    Ok("performance/cache contract: PASS".to_owned())
}

fn read(repo: &Path, relative: &str) -> Result<Value, Error> {
    let path: PathBuf = repo.join(relative);
    let text = std::fs::read_to_string(&path)
        .map_err(|error| Error(format!("{}: {error}", path.display())))?;
    json_in::parse(&text).map_err(|error| Error(format!("{relative}: {error}")))
}

fn require(condition: bool, message: &str) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(Error(message.to_owned()))
    }
}

fn int(value: &Value, key: &str) -> Result<i64, Error> {
    value
        .optional(key)
        .and_then(|inner| inner.as_int(key).ok())
        .ok_or_else(|| Error(format!("{key} must be an integer")))
}

fn int_array(value: &Value, key: &str) -> Result<Vec<i64>, Error> {
    let items = value
        .optional(key)
        .and_then(|inner| inner.as_array(key).ok())
        .ok_or_else(|| Error(format!("{key} must be an array")))?;
    items
        .iter()
        .map(|item| item.as_int(key).map_err(|_| Error(format!("{key} must contain integers"))))
        .collect()
}

fn string_array(value: &Value, key: &str) -> Result<Vec<String>, Error> {
    let items = value
        .optional(key)
        .and_then(|inner| inner.as_array(key).ok())
        .ok_or_else(|| Error(format!("{key} must be an array")))?;
    items
        .iter()
        .map(|item| {
            item.as_str(key)
                .map(str::to_owned)
                .map_err(|_| Error(format!("{key} must contain strings")))
        })
        .collect()
}

fn str_field(value: &Value, key: &str) -> Result<String, Error> {
    value
        .optional(key)
        .and_then(|inner| inner.as_str(key).ok())
        .map(str::to_owned)
        .ok_or_else(|| Error(format!("{key} must be a string")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("the manifest must sit three levels below the repository root")
            .to_path_buf()
    }

    #[test]
    fn the_checked_in_contracts_pass() {
        let line = check(&repo_root()).expect("committed contract and baseline must validate");
        assert_eq!(line, "performance/cache contract: PASS");
    }
}
