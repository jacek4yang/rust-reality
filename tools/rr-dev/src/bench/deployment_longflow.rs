//! Long-flow NXR LINE+LANDING throughput + relay evidence helpers.
//!
//! Owns the reviewed long-flow section: spawn LANDING+LINE, drive a large SOCKS
//! download, and require splice-backend relay evidence from the LANDING log.
//! Process lifecycle still rides on [`super::deployment::RunState`].

use std::path::Path;
use std::time::{Duration, Instant};

use crate::{
    bench::{process::Child, soak},
    hash,
};

use super::deployment::{
    RunState, SharedFixture, deployment_public_config, isolated_environment, spawn_generated_rust,
};
use super::deployment_probe::{SocksThroughputPlan, relay_evidence, run_socks_throughput};
use super::deployment_transport::{identity_for, landing_config, line_spec};

pub(crate) fn run_longflow_section(
    state: &mut RunState<'_>,
    fixture: &SharedFixture,
) -> Result<(), String> {
    let line_port = state.port()?;
    let landing_port = state.port()?;
    let socks_port = state.port()?;
    let key = soak::node_key(&state.rust.path)?;
    let line = deployment_public_config(
        state,
        "longflow-line",
        &line_spec(line_port, fixture.cover_port, landing_port, &key),
    )?;
    let landing = landing_config(landing_port, &key, "debug")?;
    let landing_path = state.workspace.join("longflow-landing.json");
    let landing_log = state.workspace.join("longflow-landing.log");
    soak::write_config(&landing_path, &landing)?;
    soak::check_config(&state.rust.path, &landing_path)?;
    let mut landing_process = Child::spawn_isolated(
        "deployment-longflow-landing",
        &state.rust.path,
        &[
            "run".to_owned(),
            "--config".to_owned(),
            landing_path.display().to_string(),
        ],
        state.workspace.path(),
        &isolated_environment(),
        &landing_log,
    )
    .map_err(|error| error.to_string())?;
    wait_for_log_event(
        &mut landing_process,
        &landing_log,
        "\"event\":\"listener_started\"",
        Duration::from_secs(30),
    )?;
    spawn_generated_rust(state, "longflow-line", line_port, &line.json)?;
    let client_identity = identity_for(&line, fixture.cover_port);
    state.spawn_xray_client(
        "deployment-longflow-client",
        line_port,
        socks_port,
        &line.public_key,
        &client_identity,
    )?;
    let payload_mib = state.plan.program.longflow_mib;
    let payload = fixture.payload_a.join(format!("payload-{payload_mib}.bin"));
    let rows = run_socks_throughput(&SocksThroughputPlan {
        label: "longflow".to_owned(),
        socks_port,
        url: format!(
            "http://127.0.0.1:{}/payload-{payload_mib}.bin",
            fixture.route_origin_port
        ),
        payload_mib,
        samples: 1,
        concurrencies: vec![1],
        expected_sha256: hash::sha256_file(&payload)?,
        workspace: state.workspace.path().to_path_buf(),
    })?;
    state.run.write_jsonl(
        &format!("tput-longflow-{payload_mib}mib-c1.jsonl"),
        &rows
            .iter()
            .map(|row| row.to_json().to_compact_json())
            .collect::<Vec<_>>(),
    )?;
    std::thread::sleep(Duration::from_millis(200));
    landing_process.terminate();
    let log = std::fs::read_to_string(&landing_log)
        .map_err(|error| format!("could not read {}: {error}", landing_log.display()))?;
    state.run.write_new("longflow-landing.log", &log)?;
    let evidence = relay_evidence(&log);
    state.run.write_new(
        "summary-longflow.json",
        &evidence
            .to_json(&state.run.join("longflow-landing.log"), "splice")
            .to_python_json(),
    )?;
    if evidence.passes("splice") {
        Ok(())
    } else {
        Err("long-flow relay evidence did not prove the splice backend".to_owned())
    }
}

fn wait_for_log_event(
    child: &mut Child,
    log: &Path,
    needle: &str,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::fs::read_to_string(log).is_ok_and(|contents| contents.contains(needle)) {
            return Ok(());
        }
        if !child.is_alive() {
            return Err(format!(
                "{} exited before publishing {needle}",
                child.label()
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(format!(
        "{} did not publish {needle} within {:.1}s",
        child.label(),
        timeout.as_secs_f64()
    ))
}
