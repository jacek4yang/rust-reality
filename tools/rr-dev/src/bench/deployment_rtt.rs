//! Deployment RTT / netem matrix orchestration helpers.
//!
//! Owns the one-leg netns RTT characterization section: warm/cold NXR, SOCKS,
//! and Handoff pairs plus pool-summary evidence. Process lifecycle still rides
//! on [`super::deployment::RunState`]; this module keeps the netem matrix
//! independently reviewable beside the broader deployment suite.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::{
    bench::{
        config::{self, RealityIdentity},
        process::Child,
        soak,
    },
    deploy::netem::{self, NetemArgs},
    perf::{json_in, json_in::Value, json_out::Json},
};

use super::deployment::{
    RunState, SharedFixture, deployment_public_config, isolated_environment, jsonl_body,
    parsed_to_json, setup_row_json, write_new_file,
};
use super::deployment_plan::{count, loss_token};
use super::deployment_probe::json_string;
use super::deployment_transport::{
    identity_for, landing_config_at, landing_variant_config, line_spec_to, transport_line_config,
    xray_client_ports,
};
use super::suites;

struct RttRuntime {
    socks_ports: BTreeMap<&'static str, u16>,
    children: Vec<Child>,
    warm_children: BTreeMap<&'static str, usize>,
    warm_logs: BTreeMap<&'static str, PathBuf>,
}

#[expect(
    clippy::too_many_lines,
    reason = "the six-leg netem topology is one jointly owned mechanism"
)]
pub(crate) fn run_rtt_section(
    state: &mut RunState<'_>,
    fixture: &SharedFixture,
) -> Result<(), String> {
    let rtt_dir = state.run.join("rtt");
    std::fs::create_dir(&rtt_dir)
        .map_err(|error| format!("could not create {}: {error}", rtt_dir.display()))?;
    let mut topology = super::deployment_netns::Topology::create(&state.plan.run_id)?;
    let mut runtime = build_rtt_runtime(state, fixture, &topology)?;
    let run_root = std::fs::canonicalize(state.run.path())
        .map_err(|error| format!("could not canonicalize deployment evidence: {error}"))?;
    let profiles_path = run_root.join("rtt/profiles.jsonl");
    let pool_path = run_root.join("rtt/pool-summaries.json");
    let mut profile_rows = Vec::new();
    let mut netstate = topology.describe()?;

    for rtt_ms in &state.plan.program.rtts_ms {
        for loss in &state.plan.program.losses_percent {
            topology.apply_profile(*rtt_ms, *loss)?;
            let observed = topology.observed_rtt_ms().ok();
            let profile = format!("rtt{rtt_ms}-loss{}", loss_token(*loss));
            let _ = write!(
                netstate,
                "\nprofile={profile} targetRttMs={rtt_ms} perDirectionLossPercent={loss} observedRttMs={}\n",
                observed.map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
            );
            netstate.push_str(&topology.describe()?);
            let mut raw = Vec::new();
            for prefix in ["nxr", "socks", "handoff"] {
                let warm = runtime.socks_ports[&match prefix {
                    "nxr" => "nxr-warm",
                    "socks" => "socks-warm",
                    _ => "handoff-warm",
                }];
                let cold = runtime.socks_ports[&match prefix {
                    "nxr" => "nxr-cold",
                    "socks" => "socks-cold",
                    _ => "handoff-cold",
                }];
                let (warm_path, cold_path) = run_setup_abba_pair(
                    state,
                    &profile,
                    prefix,
                    warm,
                    cold,
                    fixture.route_origin_port,
                )?;
                raw.push((format!("{prefix}-warm"), warm_path));
                raw.push((format!("{prefix}-cold"), cold_path));
            }
            let mut fields = vec![
                ("profile", Json::string(&profile)),
                ("targetRttMs", count(*rtt_ms)),
                ("perDirectionLossPercent", Json::Float(*loss)),
                (
                    "raw",
                    Json::object(
                        raw.into_iter()
                            .map(|(leg, path)| (leg, Json::string(path.display().to_string()))),
                    ),
                ),
            ];
            if let Some(observed) = observed {
                fields.push(("observedRttMs", Json::Float(observed)));
            }
            profile_rows.push(Json::object(fields).to_compact_json());
        }
    }
    write_new_file(&profiles_path, &jsonl_body(&profile_rows))?;

    let pool_summaries = collect_pool_summaries(state, &mut runtime)?;
    write_new_file(&pool_path, &Json::Array(pool_summaries).to_python_json())?;
    let report = netem::validate(&NetemArgs {
        profiles: profiles_path,
        pool_summaries: pool_path,
        rtts: state
            .plan
            .program
            .rtts_ms
            .iter()
            .map(|value| i64::from(*value))
            .collect(),
        losses: state.plan.program.losses_percent.clone(),
        concurrencies: state
            .plan
            .program
            .rtt_concurrencies
            .iter()
            .map(|value| i64::try_from(*value).unwrap_or(i64::MAX))
            .collect(),
        samples: i64::try_from(state.plan.program.samples * 2).unwrap_or(i64::MAX),
        connections: i64::try_from(state.plan.program.rtt_connections).unwrap_or(i64::MAX),
        evaluate_performance: state.plan.program.evaluate_netem_performance,
    })?;
    state.run.write_new("summary-netem.json", &report.json)?;
    netstate.push_str("\nstateBeforeTeardown\n");
    netstate.push_str(&topology.describe()?);
    for child in &mut runtime.children {
        child.terminate();
    }
    topology.teardown()?;
    netstate.push_str("\nteardownVerified=true\n");
    state.run.write_new("rtt/netstate.txt", &netstate)?;
    if report.passed {
        Ok(())
    } else {
        Err("deployment netem validator rejected the complete RTT matrix".to_owned())
    }
}

fn build_rtt_runtime(
    state: &mut RunState<'_>,
    fixture: &SharedFixture,
    topology: &super::deployment_netns::Topology,
) -> Result<RttRuntime, String> {
    let mut runtime = RttRuntime {
        socks_ports: BTreeMap::new(),
        children: Vec::new(),
        warm_children: BTreeMap::new(),
        warm_logs: BTreeMap::new(),
    };
    spawn_rtt_namespace_origin(state, fixture, topology, &mut runtime)?;
    let peer_socks = state.port()?;
    spawn_rtt_namespace_socks(state, topology, peer_socks, &mut runtime)?;
    build_rtt_nxr_pair(state, fixture, topology, &mut runtime)?;
    build_rtt_socks_pair(state, fixture, topology, peer_socks, &mut runtime)?;
    build_rtt_handoff_pair(state, fixture, topology, &mut runtime)?;
    Ok(runtime)
}

fn spawn_rtt_namespace_origin(
    state: &RunState<'_>,
    fixture: &SharedFixture,
    topology: &super::deployment_netns::Topology,
    runtime: &mut RttRuntime,
) -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("could not identify rr-dev executable: {error}"))?;
    let args = vec![
        "bench".to_owned(),
        "origin".to_owned(),
        "--listen-address".to_owned(),
        "127.0.0.1".to_owned(),
        "--port".to_owned(),
        fixture.route_origin_port.to_string(),
        "--payload-dir".to_owned(),
        fixture.payload_a.display().to_string(),
        "--put-log".to_owned(),
        state
            .workspace
            .join("rtt-origin-put.jsonl")
            .display()
            .to_string(),
        "--label".to_owned(),
        "deployment-rtt-origin".to_owned(),
    ];
    let mut child = super::ipv6_netns::spawn_in(
        topology.namespace(),
        "deployment-rtt-origin",
        &executable,
        &args,
        state.workspace.path(),
        &isolated_environment(),
        &state.workspace.join("rtt-origin.log"),
    )?;
    wait_for_namespace_http(
        topology.namespace(),
        &mut child,
        fixture.route_origin_port,
        &isolated_environment(),
    )?;
    runtime.children.push(child);
    Ok(())
}

fn spawn_rtt_namespace_socks(
    state: &RunState<'_>,
    topology: &super::deployment_netns::Topology,
    port: u16,
    runtime: &mut RttRuntime,
) -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("could not identify rr-dev executable: {error}"))?;
    let args = vec![
        "bench".to_owned(),
        "socks-server".to_owned(),
        "--listen".to_owned(),
        "0.0.0.0".to_owned(),
        "--port".to_owned(),
        port.to_string(),
    ];
    let mut child = super::ipv6_netns::spawn_in(
        topology.namespace(),
        "deployment-rtt-socks",
        &executable,
        &args,
        state.workspace.path(),
        &isolated_environment(),
        &state.workspace.join("rtt-socks-peer.log"),
    )?;
    child
        .wait_for_address(
            SocketAddr::from((
                super::deployment_netns::PEER_ADDRESS
                    .parse::<Ipv4Addr>()
                    .map_err(|error| format!("invalid deployment peer address: {error}"))?,
                port,
            )),
            Duration::from_secs(30),
        )
        .map_err(|error| error.to_string())?;
    runtime.children.push(child);
    Ok(())
}

fn wait_for_namespace_http(
    namespace: &str,
    child: &mut Child,
    port: u16,
    environment: &[(String, String)],
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let args = vec![
        "--silent".to_owned(),
        "--show-error".to_owned(),
        "--fail".to_owned(),
        "--max-time".to_owned(),
        "1".to_owned(),
        format!("http://127.0.0.1:{port}/payload.bin"),
    ];
    while Instant::now() < deadline {
        let ready = super::ipv6_netns::command_in(namespace, Path::new("curl"), &args, environment)
            .is_ok_and(|outcome| outcome.success());
        if ready {
            return Ok(());
        }
        if !child.is_alive() {
            return Err(format!(
                "{} exited before namespace HTTP readiness",
                child.label()
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!(
        "{} did not become ready on namespace loopback port {port}",
        child.label()
    ))
}

fn build_rtt_nxr_pair(
    state: &mut RunState<'_>,
    fixture: &SharedFixture,
    topology: &super::deployment_netns::Topology,
    runtime: &mut RttRuntime,
) -> Result<(), String> {
    let landing_port = state.port()?;
    let warm_line_port = state.port()?;
    let cold_line_port = state.port()?;
    let warm_socks = state.port()?;
    let cold_socks = state.port()?;
    let key = soak::node_key(&state.rust.path)?;
    let landing = landing_config_at("0.0.0.0", landing_port, &key, "warn")?;
    spawn_rtt_namespace_rust(
        state,
        topology,
        runtime,
        "rtt-nxr-landing",
        landing_port,
        &landing,
    )?;
    let generated = deployment_public_config(
        state,
        "rtt-nxr-line-base",
        &line_spec_to(
            warm_line_port,
            fixture.cover_port,
            super::deployment_netns::PEER_ADDRESS,
            landing_port,
            &key,
        ),
    )?;
    let warm_log = state.workspace.join("rtt-nxr-warm-line.log");
    let warm = transport_line_config(
        &generated.json,
        warm_line_port,
        "nxr",
        super::deployment_netns::PEER_ADDRESS,
        landing_port,
        true,
        "info",
        &state.workspace.join("assets-rtt-nxr-warm"),
    )?;
    let warm_index = spawn_rtt_host_rust(
        state,
        runtime,
        "rtt-nxr-warm-line",
        warm_line_port,
        &warm,
        &warm_log,
    )?;
    let cold = transport_line_config(
        &generated.json,
        cold_line_port,
        "nxr",
        super::deployment_netns::PEER_ADDRESS,
        landing_port,
        false,
        "warn",
        &state.workspace.join("assets-rtt-nxr-cold"),
    )?;
    spawn_rtt_host_rust(
        state,
        runtime,
        "rtt-nxr-cold-line",
        cold_line_port,
        &cold,
        &state.workspace.join("rtt-nxr-cold-line.log"),
    )?;
    let identity = identity_for(&generated, fixture.cover_port);
    spawn_rtt_xray_client(
        state,
        runtime,
        "rtt-nxr-warm-client",
        warm_line_port,
        warm_socks,
        &identity,
        &generated.public_key,
    )?;
    spawn_rtt_xray_client(
        state,
        runtime,
        "rtt-nxr-cold-client",
        cold_line_port,
        cold_socks,
        &identity,
        &generated.public_key,
    )?;
    runtime.socks_ports.insert("nxr-warm", warm_socks);
    runtime.socks_ports.insert("nxr-cold", cold_socks);
    runtime.warm_children.insert("nxr", warm_index);
    runtime.warm_logs.insert("nxr", warm_log);
    Ok(())
}

fn spawn_rtt_namespace_rust(
    state: &RunState<'_>,
    topology: &super::deployment_netns::Topology,
    runtime: &mut RttRuntime,
    label: &str,
    port: u16,
    json: &str,
) -> Result<usize, String> {
    let config_path = state.workspace.join(&format!("{label}.json"));
    soak::write_config(&config_path, json)?;
    soak::check_config(&state.rust.path, &config_path)?;
    let mut child = super::ipv6_netns::spawn_in(
        topology.namespace(),
        &format!("deployment-{label}"),
        &state.rust.path,
        &[
            "run".to_owned(),
            "--config".to_owned(),
            config_path.display().to_string(),
        ],
        state.workspace.path(),
        &isolated_environment(),
        &state.workspace.join(&format!("{label}.log")),
    )?;
    let peer = super::deployment_netns::PEER_ADDRESS
        .parse::<Ipv4Addr>()
        .map_err(|error| format!("invalid deployment peer address: {error}"))?;
    child
        .wait_for_address(SocketAddr::from((peer, port)), Duration::from_secs(30))
        .map_err(|error| error.to_string())?;
    let index = runtime.children.len();
    runtime.children.push(child);
    Ok(index)
}

fn spawn_rtt_host_rust(
    state: &RunState<'_>,
    runtime: &mut RttRuntime,
    label: &str,
    port: u16,
    json: &str,
    log: &Path,
) -> Result<usize, String> {
    let config_path = state.workspace.join(&format!("{label}.json"));
    soak::write_config(&config_path, json)?;
    soak::check_config(&state.rust.path, &config_path)?;
    let child = soak::spawn_rust(
        &format!("deployment-{label}"),
        &state.rust,
        &config_path,
        &state.workspace,
        &isolated_environment(),
        log,
        port,
    )?;
    let index = runtime.children.len();
    runtime.children.push(child);
    Ok(index)
}

fn spawn_rtt_xray_client(
    state: &RunState<'_>,
    runtime: &mut RttRuntime,
    label: &str,
    server_port: u16,
    socks_port: u16,
    identity: &RealityIdentity,
    public_key: &str,
) -> Result<(), String> {
    let config_path = state.workspace.join(&format!("{label}.json"));
    soak::write_config(
        &config_path,
        &config::xray_client(identity, server_port, socks_port, public_key).to_python_json(),
    )?;
    let child = soak::spawn_xray_client(
        &format!("deployment-{label}"),
        &state.xray,
        &config_path,
        &state.workspace,
        &state.workspace.join(&format!("{label}.log")),
        socks_port,
    )?;
    runtime.children.push(child);
    Ok(())
}

fn build_rtt_socks_pair(
    state: &mut RunState<'_>,
    fixture: &SharedFixture,
    _topology: &super::deployment_netns::Topology,
    peer_socks: u16,
    runtime: &mut RttRuntime,
) -> Result<(), String> {
    let warm_line_port = state.port()?;
    let cold_line_port = state.port()?;
    let warm_socks = state.port()?;
    let cold_socks = state.port()?;
    let key = soak::node_key(&state.rust.path)?;
    let generated = deployment_public_config(
        state,
        "rtt-socks-line-base",
        &line_spec_to(
            warm_line_port,
            fixture.cover_port,
            super::deployment_netns::PEER_ADDRESS,
            9,
            &key,
        ),
    )?;
    let socks_base = soak::patch_socks_outbound(&generated.json, peer_socks)?;
    let warm_log = state.workspace.join("rtt-socks-warm-line.log");
    let warm = transport_line_config(
        &socks_base,
        warm_line_port,
        "socks5",
        super::deployment_netns::PEER_ADDRESS,
        peer_socks,
        true,
        "info",
        &state.workspace.join("assets-rtt-socks-warm"),
    )?;
    let warm_index = spawn_rtt_host_rust(
        state,
        runtime,
        "rtt-socks-warm-line",
        warm_line_port,
        &warm,
        &warm_log,
    )?;
    let cold = transport_line_config(
        &socks_base,
        cold_line_port,
        "socks5",
        super::deployment_netns::PEER_ADDRESS,
        peer_socks,
        false,
        "warn",
        &state.workspace.join("assets-rtt-socks-cold"),
    )?;
    spawn_rtt_host_rust(
        state,
        runtime,
        "rtt-socks-cold-line",
        cold_line_port,
        &cold,
        &state.workspace.join("rtt-socks-cold-line.log"),
    )?;
    let identity = identity_for(&generated, fixture.cover_port);
    spawn_rtt_xray_client(
        state,
        runtime,
        "rtt-socks-warm-client",
        warm_line_port,
        warm_socks,
        &identity,
        &generated.public_key,
    )?;
    spawn_rtt_xray_client(
        state,
        runtime,
        "rtt-socks-cold-client",
        cold_line_port,
        cold_socks,
        &identity,
        &generated.public_key,
    )?;
    runtime.socks_ports.insert("socks-warm", warm_socks);
    runtime.socks_ports.insert("socks-cold", cold_socks);
    runtime.warm_children.insert("socks5", warm_index);
    runtime.warm_logs.insert("socks5", warm_log);
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "generated Handoff line, landing, and client variants are one atomic topology"
)]
fn build_rtt_handoff_pair(
    state: &mut RunState<'_>,
    fixture: &SharedFixture,
    topology: &super::deployment_netns::Topology,
    runtime: &mut RttRuntime,
) -> Result<(), String> {
    let warm_line_port = state.port()?;
    let cold_line_port = state.port()?;
    let warm_landing_port = state.port()?;
    let cold_landing_port = state.port()?;
    let warm_socks = state.port()?;
    let cold_socks = state.port()?;

    // A Handoff pair is two independent secrets: the shared pre-shared key, and
    // the landing's own X25519 pair whose public half the line node carries.
    let handoff_psk = soak::node_key(&state.rust.path)?;
    let landing_pair = rust_reality::crypto::generate_x25519_key_pair()
        .map_err(|error| format!("could not generate the landing key pair: {error}"))?;
    let (landing_private, landing_public) = landing_pair.into_parts();
    let reality = rust_reality::crypto::generate_x25519_key_pair()
        .map_err(|error| format!("could not generate the REALITY key pair: {error}"))?;
    let (reality_private, reality_public) = reality.into_parts();
    let uuid = rust_reality::crypto::generate_uuid()
        .map_err(|error| format!("could not generate a UUID: {error}"))?
        .to_string();
    let short_id = rust_reality::crypto::generate_short_id(8)
        .map_err(|error| format!("could not generate a short ID: {error}"))?;

    let identity = crate::bench::config::RealityIdentity {
        uuid: uuid.clone(),
        short_id: short_id.clone(),
        server_name: "localhost".to_owned(),
        target: format!("127.0.0.1:{}", fixture.cover_port),
    };
    let link = crate::bench::config::LandingLink {
        protocol: "handoff",
        address: super::deployment_netns::PEER_ADDRESS.to_owned(),
        port: warm_landing_port,
        psk: handoff_psk,
        landing_public_key: Some(landing_public),
    };
    let line_raw =
        crate::bench::config::RustServer::new(&identity, warm_line_port, reality_private.expose())
            .through_landing(&link)
            .build()
            .to_python_json();
    let landing_raw = crate::bench::config::rust_landing(
        super::deployment_netns::PEER_ADDRESS,
        warm_landing_port,
        &link,
        Some(landing_private.expose()),
    )
    .to_python_json();
    let xray_raw =
        crate::bench::config::xray_client(&identity, warm_line_port, warm_socks, &reality_public)
            .to_python_json();

    let line_base = soak::patch_server_config(
        &line_raw,
        &state.workspace,
        "assets-rtt-handoff-base",
        false,
    )?;
    let landing_base = suites::set_rust_log_level(
        &soak::patch_server_config(
            &landing_raw,
            &state.workspace,
            "assets-rtt-handoff-landing-base",
            false,
        )?,
        "warn",
    )?;
    let warm_landing = landing_variant_config(&landing_base, warm_landing_port)?;
    let cold_landing = landing_variant_config(&landing_base, cold_landing_port)?;
    spawn_rtt_namespace_rust(
        state,
        topology,
        runtime,
        "rtt-handoff-warm-landing",
        warm_landing_port,
        &warm_landing,
    )?;
    spawn_rtt_namespace_rust(
        state,
        topology,
        runtime,
        "rtt-handoff-cold-landing",
        cold_landing_port,
        &cold_landing,
    )?;
    let warm_log = state.workspace.join("rtt-handoff-warm-line.log");
    let warm_line = transport_line_config(
        &line_base,
        warm_line_port,
        "handoff",
        super::deployment_netns::PEER_ADDRESS,
        warm_landing_port,
        true,
        "info",
        &state.workspace.join("assets-rtt-handoff-warm-line"),
    )?;
    let warm_index = spawn_rtt_host_rust(
        state,
        runtime,
        "rtt-handoff-warm-line",
        warm_line_port,
        &warm_line,
        &warm_log,
    )?;
    let cold_line = transport_line_config(
        &line_base,
        cold_line_port,
        "handoff",
        super::deployment_netns::PEER_ADDRESS,
        cold_landing_port,
        false,
        "warn",
        &state.workspace.join("assets-rtt-handoff-cold-line"),
    )?;
    spawn_rtt_host_rust(
        state,
        runtime,
        "rtt-handoff-cold-line",
        cold_line_port,
        &cold_line,
        &state.workspace.join("rtt-handoff-cold-line.log"),
    )?;
    spawn_rtt_xray_config(
        state,
        runtime,
        "rtt-handoff-warm-client",
        warm_socks,
        &xray_client_ports(&xray_raw, warm_line_port, warm_socks)?,
    )?;
    spawn_rtt_xray_config(
        state,
        runtime,
        "rtt-handoff-cold-client",
        cold_socks,
        &xray_client_ports(&xray_raw, cold_line_port, cold_socks)?,
    )?;
    runtime.socks_ports.insert("handoff-warm", warm_socks);
    runtime.socks_ports.insert("handoff-cold", cold_socks);
    runtime.warm_children.insert("handoff", warm_index);
    runtime.warm_logs.insert("handoff", warm_log);
    Ok(())
}

fn spawn_rtt_xray_config(
    state: &RunState<'_>,
    runtime: &mut RttRuntime,
    label: &str,
    socks_port: u16,
    json: &str,
) -> Result<(), String> {
    let config_path = state.workspace.join(&format!("{label}.json"));
    soak::write_config(&config_path, json)?;
    let child = soak::spawn_xray_client(
        &format!("deployment-{label}"),
        &state.xray,
        &config_path,
        &state.workspace,
        &state.workspace.join(&format!("{label}.log")),
        socks_port,
    )?;
    runtime.children.push(child);
    Ok(())
}

fn run_setup_abba_pair(
    state: &RunState<'_>,
    profile: &str,
    prefix: &str,
    warm_socks: u16,
    cold_socks: u16,
    origin_port: u16,
) -> Result<(PathBuf, PathBuf), String> {
    let mut warm_rows = Vec::new();
    let mut cold_rows = Vec::new();
    for block in 0..state.plan.program.samples {
        let first = block * 2;
        for (mode, socks_port, sample_index) in [
            ("warm", warm_socks, first),
            ("cold", cold_socks, first),
            ("cold", cold_socks, first + 1),
            ("warm", warm_socks, first + 1),
        ] {
            super::workload::warm_up(socks_port, origin_port)?;
            for concurrency in &state.plan.program.rtt_concurrencies {
                let row = super::workload::run_sample(
                    &super::workload::SetupRatePlan {
                        socks_port,
                        origin_port,
                        connections: state.plan.program.rtt_connections,
                        concurrencies: state.plan.program.rtt_concurrencies.clone(),
                        samples: 1,
                        implementation: format!("{profile}-{prefix}-{mode}"),
                        block,
                        position: usize::from(mode == "cold"),
                        record_latencies: false,
                    },
                    *concurrency,
                    sample_index,
                );
                if row.failed != 0 || row.connections != state.plan.program.rtt_connections {
                    return Err(format!(
                        "{profile}-{prefix}-{mode} c{concurrency} sample {sample_index} completed {} of {} connections with {} failures",
                        row.connections, state.plan.program.rtt_connections, row.failed
                    ));
                }
                if mode == "warm" {
                    warm_rows.push(setup_row_json(&row));
                } else {
                    cold_rows.push(setup_row_json(&row));
                }
            }
        }
    }
    let warm_name = format!("setup-{profile}-{prefix}-warm.jsonl");
    let cold_name = format!("setup-{profile}-{prefix}-cold.jsonl");
    state.run.write_jsonl(&warm_name, &warm_rows)?;
    state.run.write_jsonl(&cold_name, &cold_rows)?;
    let root = std::fs::canonicalize(state.run.path())
        .map_err(|error| format!("could not canonicalize deployment evidence: {error}"))?;
    Ok((root.join(warm_name), root.join(cold_name)))
}

fn collect_pool_summaries(
    state: &RunState<'_>,
    runtime: &mut RttRuntime,
) -> Result<Vec<Json>, String> {
    let mut summaries = Vec::new();
    for transport in ["handoff", "nxr", "socks5"] {
        let index = *runtime
            .warm_children
            .get(transport)
            .ok_or_else(|| format!("missing {transport} warm child identity"))?;
        runtime.children[index].terminate();
        let log = runtime
            .warm_logs
            .get(transport)
            .ok_or_else(|| format!("missing {transport} warm log path"))?;
        let contents = std::fs::read_to_string(log)
            .map_err(|error| format!("could not read {}: {error}", log.display()))?;
        state
            .run
            .write_new(&format!("rtt/{transport}-warm-server.log"), &contents)?;
        summaries.push(pool_summary(&contents, transport)?);
    }
    Ok(summaries)
}

fn pool_summary(log: &str, transport: &str) -> Result<Json, String> {
    let rows = json_in::parse_lines(log)
        .map_err(|error| format!("{transport} warm log is not JSON Lines: {error}"))?;
    let summary = rows
        .into_iter()
        .find(|row| {
            row.optional("event").and_then(json_string) == Some("transport_pool_summary")
                && row.optional("transport").and_then(json_string) == Some(transport)
        })
        .ok_or_else(|| format!("{transport} warm log has no transport_pool_summary"))?;
    let Value::Object(mut fields) = summary else {
        return Err(format!("{transport} pool summary is not an object"));
    };
    let total = fields
        .get("pool_checkout_total")
        .ok_or_else(|| format!("{transport} pool summary has no checkout total"))?
        .as_int("pool_checkout_total")
        .map_err(|error| error.to_string())?;
    let hits = fields
        .get("pool_checkout_hit")
        .ok_or_else(|| format!("{transport} pool summary has no checkout hits"))?
        .as_int("pool_checkout_hit")
        .map_err(|error| error.to_string())?;
    let stale = fields
        .get("pool_stale_discard")
        .ok_or_else(|| format!("{transport} pool summary has no stale discard count"))?
        .as_int("pool_stale_discard")
        .map_err(|error| error.to_string())?;
    #[expect(
        clippy::cast_precision_loss,
        reason = "runtime pool counters are far below f64's exact integer range"
    )]
    let denominator = if total == 0 { 1.0 } else { total as f64 };
    #[expect(
        clippy::cast_precision_loss,
        reason = "runtime pool counters are far below f64's exact integer range"
    )]
    let acquisition = if total == 0 {
        0.0
    } else {
        hits as f64 / denominator
    };
    #[expect(
        clippy::cast_precision_loss,
        reason = "runtime pool counters are far below f64's exact integer range"
    )]
    let successful = if total == 0 {
        0.0
    } else {
        (hits - stale).max(0) as f64 / denominator
    };
    fields.insert(
        "checkoutAcquisitionRatio".to_owned(),
        Value::Number(acquisition.to_string()),
    );
    fields.insert(
        "successfulWarmRatioLowerBound".to_owned(),
        Value::Number(successful.to_string()),
    );
    parsed_to_json(&Value::Object(fields))
}
