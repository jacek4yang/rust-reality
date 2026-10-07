//! Strict bindings around the existing native netem mechanism evaluator.
#![allow(missing_docs)]

use serde::Deserialize;
use serde_json::Value;

use super::schema::{Check, Identity};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Summary {
    schema_version: u64,
    status: String,
    pub program: Value,
    completed_sections: Vec<String>,
    pub netem_profiles: Value,
    data_quality_failures: Vec<String>,
    integrity_failures: Vec<String>,
    transfer_errors: Vec<String>,
    failed_sections: Vec<String>,
    data_quality_verdict: String,
    correctness_verdict: String,
    performance_verdict: String,
    gate_verdict: String,
    overall_verdict: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Environment {
    schema_version: u64,
    pub run_id: String,
    harness_commit: String,
    harness_sha256: String,
    rust_reality_bin: String,
    rust_reality_sha256: String,
    #[serde(deserialize_with = "source_identity")]
    rust_reality_identity: SourceIdentity,
    xray_bin: String,
    pub xray_sha256: String,
    pub xray_identity: String,
    host_lock: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceIdentity {
    git_commit: String,
    version: String,
}

fn source_identity<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<SourceIdentity, D::Error> {
    let text = String::deserialize(deserializer)?;
    serde_json::from_str(&text).map_err(serde::de::Error::custom)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Link {
    pub path: String,
    pub sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Contract {
    schema_version: u64,
    phase: String,
    suite: String,
    run_id: String,
    plan: Value,
    pub summary: Link,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Completion {
    schema_version: u64,
    status: String,
    exit_code: i32,
    run_id: String,
    collector: String,
    pub evidence: Link,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Terminal {
    ok: bool,
    #[serde(deserialize_with = "required_option")]
    primary_error: Option<String>,
    checks: Vec<FinalCheck>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalCheck {
    name: String,
    ok: bool,
    #[serde(deserialize_with = "required_option")]
    error: Option<String>,
}

fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(deserializer)
}

pub fn verify(
    summary: &Summary,
    environment: &Environment,
    check: &Check,
    identity: &Identity,
    program: &Value,
) -> Result<(), String> {
    let source = &environment.rust_reality_identity;
    if summary.schema_version != 1
        || summary.status != "COMPLETE"
        || summary.program != *program
        || summary.completed_sections != ["rtt"]
        || !summary.data_quality_failures.is_empty()
        || !summary.integrity_failures.is_empty()
        || !summary.transfer_errors.is_empty()
        || !summary.failed_sections.is_empty()
        || [
            &summary.data_quality_verdict,
            &summary.correctness_verdict,
            &summary.performance_verdict,
            &summary.gate_verdict,
            &summary.overall_verdict,
        ]
        .iter()
        .any(|verdict| *verdict != "PASS")
        || environment.schema_version != 1
        || environment.run_id.is_empty()
        || environment.harness_commit != identity.source_commit
        || environment.harness_sha256 != identity.evaluator.sha256
        || environment.rust_reality_sha256 != identity.candidate.sha256
        || source.git_commit != identity.source_commit
        || source.version.is_empty()
        || environment.xray_identity.is_empty()
        || environment.host_lock.is_empty()
        || !super::evaluate::digest(&environment.xray_sha256, 64)
        || !check
            .observations
            .iter()
            .any(|artifact| artifact.sha256 == environment.xray_sha256)
        || check.executed_cases != 18
        || check.argv.len() != 15
    {
        return Err("incomplete or substituted native mechanism receipt".to_owned());
    }
    let expected = [
        identity.evaluator.path.as_str(),
        "bench",
        "run",
        "--suite",
        "deployment",
        "--deployment-plan",
        "mechanism",
        "--rust-bin",
        &environment.rust_reality_bin,
        "--xray-bin",
        &environment.xray_bin,
        "--run-id",
        &environment.run_id,
        "--out-dir",
        &check.argv[14],
    ];
    if !check.argv.iter().map(String::as_str).eq(expected)
        || !std::path::Path::new(&check.argv[14]).is_absolute()
    {
        return Err("mechanism command differs from its canonical fixed workload".to_owned());
    }
    Ok(())
}

pub fn verify_completion(
    contract: &Contract,
    completion: &Completion,
    terminal: &Terminal,
    environment: &Environment,
    summary: &Summary,
) -> Result<(), String> {
    if contract.schema_version != 1
        || contract.phase != "complete"
        || contract.suite != "benchmark-deployment"
        || contract.run_id != environment.run_id
        || contract.plan != summary.program
        || completion.schema_version != 1
        || completion.status != "COMPLETE"
        || completion.exit_code != 0
        || completion.run_id != environment.run_id
        || completion.collector != "benchmark-deployment"
        || !terminal.ok
        || terminal.primary_error.is_some()
        || terminal
            .checks
            .iter()
            .any(|check| !check.ok || check.error.is_some())
        || !terminal.checks.iter().map(|check| check.name.as_str()).eq([
            "file:rust-reality",
            "file:xray",
            "image:harness",
        ])
    {
        return Err("mechanism completion or final identity verification is incomplete".to_owned());
    }
    Ok(())
}
