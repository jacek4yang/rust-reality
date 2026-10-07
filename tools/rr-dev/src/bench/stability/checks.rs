//! Required check receipts must prove their named case, not just an exit code.
#![allow(missing_docs)]

use serde::Deserialize;

use super::schema::{Check, Identity};

pub const CI_FIELDS: &str = "headSha,workflowName,status,conclusion,databaseId,url,event";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CiRun {
    head_sha: String,
    workflow_name: String,
    status: String,
    conclusion: String,
    database_id: u64,
    url: String,
    event: String,
}

pub fn parse_ci(bytes: &[u8]) -> Result<CiRun, String> {
    serde_json::from_slice(bytes).map_err(|error| error.to_string())
}

pub fn verify_ci(bytes: &[u8], check: &Check, identity: &Identity) -> Result<(), String> {
    let run = parse_ci(bytes)?;
    let expected_workflow = match check.name.as_str() {
        "exact-head-ci" => "CI",
        "exact-head-security" => "Security",
        _ => return Err("not a CI check".to_owned()),
    };
    let expected_argv = [
        "gh".to_owned(),
        "run".to_owned(),
        "view".to_owned(),
        run.database_id.to_string(),
        "--json".to_owned(),
        CI_FIELDS.to_owned(),
    ];
    if check.argv != expected_argv
        || check.executed_cases != 1
        || run.database_id == 0
        || run.head_sha != identity.source_commit
        || run.workflow_name != expected_workflow
        || run.status != "completed"
        || run.conclusion != "success"
        || !matches!(
            run.event.as_str(),
            "push" | "pull_request" | "workflow_dispatch"
        )
        || run.url
            != format!(
                "https://github.com/jacek4yang/rust-reality/actions/runs/{}",
                run.database_id
            )
    {
        return Err(
            "CI receipt does not prove the required successful exact-head workflow".to_owned(),
        );
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GateStage {
    elapsed_milliseconds: u64,
    index: usize,
    label: String,
    #[serde(deserialize_with = "required_option")]
    reason: Option<String>,
    status: String,
    pub stderr_log: String,
    pub stdout_log: String,
}

fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(deserializer)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SlowestStage {
    elapsed_milliseconds: u64,
    index: usize,
    label: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FullGate {
    attempted: usize,
    command: String,
    elapsed_milliseconds: u64,
    pub log_directory: String,
    passed: usize,
    protocol: String,
    schema_version: u64,
    scope: String,
    slowest_stage: SlowestStage,
    pub stages: Vec<GateStage>,
    status: String,
    total: usize,
}

pub fn parse_gate(bytes: &[u8]) -> Result<FullGate, String> {
    serde_json::from_slice(bytes).map_err(|error| error.to_string())
}

pub fn verify_gate(
    bytes: &[u8],
    check: &Check,
    identity: &Identity,
    labels: &[String],
) -> Result<FullGate, String> {
    let gate = parse_gate(bytes)?;
    if check.argv.len() != 7
        || check.argv[0] != identity.evaluator.path
        || check.argv[1..6] != ["check", "--all", "--output", "json", "--log-dir"]
        || check.argv[6].is_empty()
        || check.name != "local-full-gate"
        || check.executed_cases != labels.len() as u64
        || gate.protocol != "rr-dev-result/v1"
        || gate.schema_version != 1
        || gate.command != "check"
        || gate.scope != "all"
        || gate.status != "PASS"
        || gate.log_directory != check.argv[6]
        || !std::path::Path::new(&gate.log_directory).is_absolute()
        || gate.attempted != labels.len()
        || gate.passed != labels.len()
        || gate.total != labels.len()
        || gate.stages.len() != labels.len()
        || gate.elapsed_milliseconds == 0
    {
        return Err("receipt does not prove the authoritative full gate".to_owned());
    }
    for (index, (stage, label)) in gate.stages.iter().zip(labels).enumerate() {
        if stage.index != index + 1
            || stage.label != *label
            || stage.status != "PASS"
            || stage.reason.is_some()
            || stage.stdout_log.is_empty()
            || stage.stderr_log.is_empty()
            || stage.elapsed_milliseconds > gate.elapsed_milliseconds
        {
            return Err("full gate omitted or substituted a required stage".to_owned());
        }
    }
    let slowest = gate
        .stages
        .iter()
        .max_by_key(|stage| stage.elapsed_milliseconds)
        .ok_or("empty gate")?;
    if gate.slowest_stage.index != slowest.index
        || gate.slowest_stage.label != slowest.label
        || gate.slowest_stage.elapsed_milliseconds != slowest.elapsed_milliseconds
    {
        return Err("gate timing summary does not reproduce its stages".to_owned());
    }
    Ok(gate)
}
