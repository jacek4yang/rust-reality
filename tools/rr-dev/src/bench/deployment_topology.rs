//! Four-topology setup/throughput orchestration helpers.
//!
//! Owns the reviewed topo-a..d comparison section: standalone, NXR LINE+LANDING,
//! SOCKS-outbound LINE, and stock Xray comparator, plus per-topology setup-rate
//! and SOCKS throughput cells. Process lifecycle still rides on
//! [`super::deployment_state::RunState`].

use std::time::Duration;

use crate::{
    bench::{
        config::{self, RealityIdentity},
        process::Child,
        soak,
    },
    hash,
};

use super::deployment::{
    SharedFixture, deployment_public_config, generate_uuids, isolated_environment, setup_row_json,
    spawn_generated_rust,
};
use super::deployment_plan::ThroughputCell;
use super::deployment_probe::{SocksThroughputPlan, run_socks_throughput};
use super::deployment_state::RunState;
use super::deployment_transport::{identity_for, landing_config, line_spec};
use super::suites;

#[derive(Clone, Copy)]
pub(crate) struct Topology {
    pub(crate) label: &'static str,
    pub(crate) socks_port: u16,
}

#[expect(
    clippy::too_many_lines,
    reason = "the four reviewed topologies are materialized together for direct comparison"
)]
pub(crate) fn run_topology_section(
    state: &mut RunState<'_>,
    fixture: &SharedFixture,
) -> Result<(), String> {
    let upstream_socks = state.port()?;
    state.spawn_helper(
        "deployment-transparent-socks",
        &[
            "bench".to_owned(),
            "socks-server".to_owned(),
            "--port".to_owned(),
            upstream_socks.to_string(),
        ],
        "transparent-socks.log",
        upstream_socks,
    )?;

    let standalone_port = state.port()?;
    let standalone_socks = state.port()?;
    let standalone = deployment_public_config(
        state,
        "standalone",
        &soak::PublicNodeSpec::standalone(
            standalone_port,
            &format!("127.0.0.1:{}", fixture.cover_port),
        ),
    )?;
    spawn_generated_rust(state, "topo-a", standalone_port, &standalone.json)?;
    let standalone_identity = identity_for(&standalone, fixture.cover_port);
    state.spawn_xray_client(
        "deployment-topo-a-client",
        standalone_port,
        standalone_socks,
        &standalone.public_key,
        &standalone_identity,
    )?;

    let nxr_key = soak::node_key(&state.rust.path)?;
    let nxr_line_port = state.port()?;
    let nxr_landing_port = state.port()?;
    let nxr_socks = state.port()?;
    let nxr_line = deployment_public_config(
        state,
        "nxr-line",
        &line_spec(
            nxr_line_port,
            fixture.cover_port,
            nxr_landing_port,
            &nxr_key,
        ),
    )?;
    let nxr_landing = landing_config(nxr_landing_port, &nxr_key, "warn")?;
    spawn_generated_rust(state, "topo-b-landing", nxr_landing_port, &nxr_landing)?;
    spawn_generated_rust(state, "topo-b-line", nxr_line_port, &nxr_line.json)?;
    let nxr_identity = identity_for(&nxr_line, fixture.cover_port);
    state.spawn_xray_client(
        "deployment-topo-b-client",
        nxr_line_port,
        nxr_socks,
        &nxr_line.public_key,
        &nxr_identity,
    )?;

    let socks_line_port = state.port()?;
    let socks_client_port = state.port()?;
    let socks_line = deployment_public_config(
        state,
        "socks-line",
        &line_spec(socks_line_port, fixture.cover_port, 9, &nxr_key),
    )?;
    let socks_json = soak::patch_socks_outbound(&socks_line.json, upstream_socks)?;
    spawn_generated_rust(state, "topo-c-line", socks_line_port, &socks_json)?;
    let socks_identity = identity_for(&socks_line, fixture.cover_port);
    state.spawn_xray_client(
        "deployment-topo-c-client",
        socks_line_port,
        socks_client_port,
        &socks_line.public_key,
        &socks_identity,
    )?;

    let xray_server_port = state.port()?;
    let xray_client_port = state.port()?;
    let keys = suites::generate_xray_keys(&state.xray.path)?;
    let xray_uuid = generate_uuids(&state.rust, 1)?
        .pop()
        .ok_or_else(|| "rust-reality uuid returned no comparator UUID".to_owned())?;
    let xray_identity = RealityIdentity {
        uuid: xray_uuid,
        short_id: "0123456789abcdef".to_owned(),
        server_name: "localhost".to_owned(),
        target: format!("127.0.0.1:{}", fixture.cover_port),
    };
    let xray_server_config = state.workspace.join("topo-d-xray-server.json");
    soak::write_config(
        &xray_server_config,
        &config::xray_server_with_socks(
            &xray_identity,
            xray_server_port,
            &keys.private,
            upstream_socks,
        )
        .to_python_json(),
    )?;
    let mut xray_server = Child::spawn_isolated(
        "deployment-topo-d-server",
        &state.xray.path,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            xray_server_config.display().to_string(),
        ],
        state.workspace.path(),
        &isolated_environment(),
        &state.workspace.join("topo-d-xray-server.log"),
    )
    .map_err(|error| error.to_string())?;
    xray_server
        .wait_for_port(xray_server_port, Duration::from_secs(30))
        .map_err(|error| error.to_string())?;
    state.children.push(xray_server);
    state.spawn_xray_client(
        "deployment-topo-d-client",
        xray_server_port,
        xray_client_port,
        &keys.public,
        &xray_identity,
    )?;

    let topologies = [
        Topology {
            label: "topo-a",
            socks_port: standalone_socks,
        },
        Topology {
            label: "topo-b",
            socks_port: nxr_socks,
        },
        Topology {
            label: "topo-c",
            socks_port: socks_client_port,
        },
        Topology {
            label: "topo-d",
            socks_port: xray_client_port,
        },
    ];
    for topology in topologies {
        run_topology_setup(state, fixture, topology)?;
        for cell in &state.plan.program.throughput_cells {
            run_topology_throughput(state, fixture, topology, *cell)?;
        }
    }
    Ok(())
}

fn run_topology_setup(
    state: &RunState<'_>,
    fixture: &SharedFixture,
    topology: Topology,
) -> Result<(), String> {
    let destination = super::workload::Destination::Loopback;
    if super::workload::connect_through(
        topology.socks_port,
        &destination,
        fixture.route_origin_port,
    )
    .is_none()
    {
        return Err(format!(
            "{} warm-up did not reach the native origin",
            topology.label
        ));
    }
    let rows = super::workload::run_slot(&super::workload::SetupRatePlan {
        socks_port: topology.socks_port,
        origin_port: fixture.route_origin_port,
        connections: state.plan.program.connections,
        concurrencies: state.plan.program.concurrencies.clone(),
        samples: state.plan.program.samples,
        implementation: topology.label.to_owned(),
        block: 0,
        position: 0,
        record_latencies: false,
    })?;
    state.run.write_jsonl(
        &format!("setup-{}.jsonl", topology.label),
        &rows.iter().map(setup_row_json).collect::<Vec<_>>(),
    )?;
    Ok(())
}

fn run_topology_throughput(
    state: &RunState<'_>,
    fixture: &SharedFixture,
    topology: Topology,
    cell: ThroughputCell,
) -> Result<(), String> {
    let payload = fixture
        .payload_a
        .join(format!("payload-{}.bin", cell.payload_mib));
    let rows = run_socks_throughput(&SocksThroughputPlan {
        label: topology.label.to_owned(),
        socks_port: topology.socks_port,
        url: format!(
            "http://127.0.0.1:{}/payload-{}.bin",
            fixture.route_origin_port, cell.payload_mib
        ),
        payload_mib: cell.payload_mib,
        samples: state.plan.program.throughput_samples,
        concurrencies: vec![cell.concurrency],
        expected_sha256: hash::sha256_file(&payload)?,
        workspace: state.workspace.path().to_path_buf(),
    })?;
    state.run.write_jsonl(
        &format!(
            "tput-{}-{}mib-c{}.jsonl",
            topology.label, cell.payload_mib, cell.concurrency
        ),
        &rows
            .iter()
            .map(|row| row.to_json().to_compact_json())
            .collect::<Vec<_>>(),
    )?;
    Ok(())
}
