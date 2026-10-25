//! Deployment run summary, environment, and artifact helpers.
//!
//! Owns environment.json writing, section summary aggregation, cost/topology
//! artifact verification, publication contract JSON, and parsed-JSON conversion.
//! Process lifecycle still rides on [`super::deployment_state::RunState`].

use std::path::Path;

use crate::{
    hash,
    perf::{json_in, json_in::Value, json_out::Json},
    process::Tool,
};

use super::deployment_plan::{Section, count};
use super::deployment_probe::json_string;
use super::deployment_state::RunState;

pub(crate) fn write_environment(state: &RunState<'_>) -> Result<(), String> {
    let commit = Tool::new("git")
        .args([
            "-C".to_owned(),
            state.plan.repo.display().to_string(),
            "rev-parse".to_owned(),
            "HEAD".to_owned(),
        ])
        .probe()
        .map_err(|error| format!("could not identify harness commit: {error}"))?;
    if !commit.success() {
        return Err(format!(
            "could not identify harness commit: {}",
            commit.stderr.trim_end()
        ));
    }
    let environment = Json::object([
        ("schemaVersion", Json::Int(1)),
        ("runId", Json::string(&state.plan.run_id)),
        ("harnessCommit", Json::string(commit.trimmed_stdout())),
        ("harnessSha256", Json::string(&state.harness_sha256)),
        (
            "rustRealityBin",
            Json::string(state.rust.path.display().to_string()),
        ),
        ("rustRealitySha256", Json::string(&state.rust.sha256)),
        ("rustRealityIdentity", Json::string(&state.rust.identity)),
        (
            "xrayBin",
            Json::string(state.xray.path.display().to_string()),
        ),
        ("xraySha256", Json::string(&state.xray.sha256)),
        ("xrayIdentity", Json::string(&state.xray.identity)),
        ("hostLock", Json::string(state.lock.device_inode())),
    ]);
    state
        .run
        .write_new("environment.json", &environment.to_python_json())?;
    Ok(())
}

pub(crate) fn deployment_run_summary(state: &RunState<'_>) -> Result<Json, String> {
    let mut fields = vec![
        ("schemaVersion", Json::Int(1)),
        ("status", Json::string("COMPLETE")),
        ("program", state.plan.program.to_json()),
        (
            "completedSections",
            Json::Array(
                state
                    .plan
                    .program
                    .sections
                    .iter()
                    .map(|section| Json::string(section.name()))
                    .collect(),
            ),
        ),
    ];
    let mut performance = "NOT_EVALUATED".to_owned();
    for section in &state.plan.program.sections {
        match section {
            Section::Routing => {
                let routing = read_report(&state.run.join("summary-routing.json"), "routing")?;
                if routing.str_field("routing", "verdict") != Ok("PASS")
                    || routing.int_field("routing", "cases") != Ok(26)
                    || routing.int_field("routing", "passed") != Ok(26)
                    || routing.int_field("routing", "failed") != Ok(0)
                {
                    return Err("routing summary does not prove all 26 cases".to_owned());
                }
                fields.push(("routingCorrectness", parsed_to_json(&routing)?));
            }
            Section::Cost => fields.push(("routingCost", cost_artifacts(state)?)),
            Section::Nxr => fields.push(("deploymentTopologies", topology_artifacts(state)?)),
            Section::Rtt => {
                let netem = read_report(&state.run.join("summary-netem.json"), "netem")?;
                if netem.str_field("netem", "verdict") != Ok("PASS")
                    || netem.str_field("netem", "dataQualityVerdict") != Ok("PASS")
                {
                    return Err("netem summary does not prove the complete matrix".to_owned());
                }
                netem
                    .str_field("netem", "performanceVerdict")
                    .map_err(|error| error.to_string())?
                    .clone_into(&mut performance);
                let expected = if state.plan.program.evaluate_netem_performance {
                    "PASS"
                } else {
                    "NOT_EVALUATED"
                };
                if performance != expected {
                    return Err(format!(
                        "netem performance verdict {performance} differs from expected {expected}"
                    ));
                }
                fields.push(("netemProfiles", parsed_to_json(&netem)?));
            }
            Section::Longflow => {
                throughput_artifact(
                    state,
                    &format!(
                        "tput-longflow-{}mib-c1.jsonl",
                        state.plan.program.longflow_mib
                    ),
                    1,
                )?;
                let relay = read_report(&state.run.join("summary-longflow.json"), "longflow")?;
                if relay.str_field("longflow", "verdict") != Ok("PASS") {
                    return Err("long-flow relay summary did not pass".to_owned());
                }
                fields.push(("longFlowRelay", parsed_to_json(&relay)?));
            }
        }
    }
    let formal = state.plan.program.kind.formal();
    if formal && performance != "PASS" {
        return Err(format!(
            "formal deployment plan requires PASS performance, got {performance}"
        ));
    }
    fields.extend([
        ("dataQualityFailures", Json::Array(Vec::new())),
        ("integrityFailures", Json::Array(Vec::new())),
        ("transferErrors", Json::Array(Vec::new())),
        ("dataQualityVerdict", Json::string("PASS")),
        ("correctnessVerdict", Json::string("PASS")),
        ("performanceVerdict", Json::string(performance)),
        ("gateVerdict", Json::string("PASS")),
        (
            "overallVerdict",
            Json::string(if formal { "PASS" } else { "NOT_EVALUATED" }),
        ),
        ("failedSections", Json::Array(Vec::new())),
    ]);
    Ok(Json::object(fields))
}

fn cost_artifacts(state: &RunState<'_>) -> Result<Json, String> {
    let expected_rows = state.plan.program.samples * state.plan.program.concurrencies.len();
    super::deployment_cost::COST_VARIANTS
        .iter()
        .map(|variant| {
            setup_artifact(
                state,
                &format!("setup-cost-{}.jsonl", variant.label),
                expected_rows,
                state.plan.program.connections,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Json::Array)
}

fn topology_artifacts(state: &RunState<'_>) -> Result<Json, String> {
    let expected_setup = state.plan.program.samples * state.plan.program.concurrencies.len();
    let mut setup = Vec::new();
    let mut throughput = Vec::new();
    for topology in ["topo-a", "topo-b", "topo-c", "topo-d"] {
        setup.push(setup_artifact(
            state,
            &format!("setup-{topology}.jsonl"),
            expected_setup,
            state.plan.program.connections,
        )?);
        for cell in &state.plan.program.throughput_cells {
            let name = format!(
                "tput-{topology}-{}mib-c{}.jsonl",
                cell.payload_mib, cell.concurrency
            );
            throughput.push(throughput_artifact(
                state,
                &name,
                state.plan.program.throughput_samples,
            )?);
        }
    }
    Ok(Json::object([
        ("setup", Json::Array(setup)),
        ("throughput", Json::Array(throughput)),
    ]))
}

fn setup_artifact(
    state: &RunState<'_>,
    name: &str,
    expected_rows: usize,
    expected_connections: usize,
) -> Result<Json, String> {
    let path = state.run.join(name);
    let rows = read_jsonl(&path)?;
    if rows.len() != expected_rows
        || rows.iter().any(|row| {
            row.optional("failed")
                .and_then(|value| value.as_int("failed").ok())
                != Some(0)
                || row
                    .optional("connections")
                    .and_then(|value| value.as_int("connections").ok())
                    != i64::try_from(expected_connections).ok()
        })
    {
        return Err(format!(
            "{name} does not contain {expected_rows} complete setup rows"
        ));
    }
    artifact_json(&path, rows.len())
}

fn throughput_artifact(
    state: &RunState<'_>,
    name: &str,
    expected_rows: usize,
) -> Result<Json, String> {
    let path = state.run.join(name);
    let rows = read_jsonl(&path)?;
    let integrity_passes = rows
        .iter()
        .filter(|row| row.optional("integrity").and_then(json_string) == Some("pass"))
        .count();
    if rows.len() != expected_rows
        || integrity_passes != 1
        || rows
            .iter()
            .any(|row| row.optional("integrity").and_then(json_string) == Some("fail"))
    {
        return Err(format!(
            "{name} does not contain {expected_rows} complete integrity-checked rows"
        ));
    }
    artifact_json(&path, rows.len())
}

fn artifact_json(path: &Path, rows: usize) -> Result<Json, String> {
    Ok(Json::object([
        ("path", Json::string(path.display().to_string())),
        ("sha256", Json::string(hash::sha256_file(path)?)),
        ("rows", count(rows)),
    ]))
}

fn read_report(path: &Path, label: &str) -> Result<Value, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|error| format!("could not read {label} report {}: {error}", path.display()))?;
    json_in::parse(&raw).map_err(|error| format!("{label} report is invalid JSON: {error}"))
}

fn read_jsonl(path: &Path) -> Result<Vec<Value>, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    json_in::parse_lines(&raw).map_err(|error| format!("{}: {error}", path.display()))
}

pub(crate) fn run_contract(state: &RunState<'_>, summary: &Path) -> Result<Json, String> {
    Ok(Json::object([
        ("schemaVersion", Json::Int(1)),
        ("phase", Json::string("complete")),
        ("suite", Json::string("benchmark-deployment")),
        ("runId", Json::string(&state.plan.run_id)),
        ("plan", state.plan.program.to_json()),
        (
            "summary",
            Json::object([
                ("path", Json::string(summary.display().to_string())),
                ("sha256", Json::string(hash::sha256_file(summary)?)),
            ]),
        ),
    ]))
}

pub(crate) fn parsed_to_json(value: &Value) -> Result<Json, String> {
    match value {
        Value::Null => Ok(Json::Null),
        Value::Bool(value) => Ok(Json::Bool(*value)),
        Value::Number(value) => value
            .parse::<i64>()
            .map(Json::Int)
            .or_else(|_| value.parse::<f64>().map(Json::Float))
            .map_err(|error| format!("could not convert JSON number {value}: {error}")),
        Value::Str(value) => Ok(Json::string(value)),
        Value::Array(values) => values
            .iter()
            .map(parsed_to_json)
            .collect::<Result<Vec<_>, _>>()
            .map(Json::Array),
        Value::Object(values) => values
            .iter()
            .map(|(key, value)| Ok((key.clone(), parsed_to_json(value)?)))
            .collect::<Result<Vec<_>, String>>()
            .map(Json::object),
    }
}
