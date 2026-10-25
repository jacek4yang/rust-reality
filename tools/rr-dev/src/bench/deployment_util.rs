//! Deployment shared free-standing helpers.
//!
//! Owns UUID generation, isolated child env, sample-row JSON, public-config
//! generation, generated-rust process spawn, and small file/jsonl utilities used
//! by section runners. Process lifecycle still rides on
//! [`super::deployment_state::RunState`].

use std::{
    io::Write as _,
    path::{Path, PathBuf},
};

use crate::{
    bench::{identity::Binary, soak},
    perf::json_out::Json,
    process::Tool,
};

use super::deployment_plan::count;
use super::deployment_state::RunState;
use super::suites;

pub(crate) fn setup_row_json(row: &super::workload::SampleRow) -> String {
    let mut fields = vec![
        ("label", Json::string(&row.implementation)),
        ("concurrency", count(row.concurrency)),
        ("sampleIndex", count(row.sample_index)),
        ("wallSeconds", Json::Float(row.wall_seconds)),
        ("connections", count(row.connections)),
        ("failed", count(row.failed)),
    ];
    if let Some(rate) = row.connections_per_second() {
        fields.push(("connectionsPerSecond", Json::Float(rate)));
        for (name, fraction) in [
            ("p50Seconds", 0.50),
            ("p90Seconds", 0.90),
            ("p95Seconds", 0.95),
            ("p99Seconds", 0.99),
        ] {
            if let Ok(value) = super::aggregate::floor_percentile(&row.latencies_seconds, fraction)
            {
                fields.push((name, Json::Float(value)));
            }
        }
    }
    Json::object(fields).to_compact_json()
}

pub(crate) fn deployment_public_config(
    state: &RunState<'_>,
    label: &str,
    spec: &soak::PublicNodeSpec,
) -> Result<soak::GeneratedPublicConfig, String> {
    let mut generated =
        soak::generated_public_config(spec, &state.workspace, &format!("assets-{label}"))?;
    generated.json = suites::set_rust_log_level(&generated.json, "warn")?;
    Ok(generated)
}

pub(crate) fn spawn_generated_rust(
    state: &mut RunState<'_>,
    label: &str,
    port: u16,
    json: &str,
) -> Result<PathBuf, String> {
    let path = state.workspace.join(&format!("{label}.json"));
    soak::write_config(&path, json)?;
    soak::check_config(&state.rust.path, &path)?;
    let child = soak::spawn_rust(
        &format!("deployment-{label}"),
        &state.rust,
        &path,
        &state.workspace,
        &isolated_environment(),
        &state.workspace.join(&format!("{label}.log")),
        port,
    )?;
    state.children.push(child);
    Ok(path)
}

pub(crate) fn jsonl_body(rows: &[String]) -> String {
    let mut body = rows.join("\n");
    body.push('\n');
    body
}

pub(crate) fn write_new_file(path: &Path, contents: &str) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("could not create {}: {error}", path.display()))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| format!("could not write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("could not sync {}: {error}", path.display()))
}

pub(crate) fn generate_uuids(binary: &Binary, count: usize) -> Result<Vec<String>, String> {
    let outcome = Tool::new(binary.path.display().to_string())
        .args(["uuid".to_owned(), count.to_string()])
        .probe()
        .map_err(|error| format!("rust-reality uuid failed: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "rust-reality uuid exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    let values = outcome
        .trimmed_stdout()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if values.len() != count {
        return Err(format!(
            "rust-reality uuid returned {} values, expected {count}",
            values.len()
        ));
    }
    Ok(values)
}

pub(crate) fn isolated_environment() -> Vec<(String, String)> {
    vec![(
        "PATH".to_owned(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned(),
    )]
}
