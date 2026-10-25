//! Deployment-characterization native suite orchestration.
//!
//! The legacy harness looked like one benchmark but carried five distinct
//! sections. Plan dimensions live in [`super::deployment_plan`] so an execution
//! refactor cannot silently narrow the formal evidence: a full run still means
//! routing correctness, routing cost, four deployment topologies, the complete
//! one-leg netem matrix, and long-flow relay evidence. Routing probes, SOCKS
//! throughput cells, and relay-log evidence live in [`super::deployment_probe`].
//! Routing policy builders and geosite/geoip fixtures live in [`super::deployment_routing`].

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    io::Write as _,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::{
    bench::{
        config::{self, RealityIdentity},
        evidence::{Publication, RunDirectory},
        host_lock::HostLock,
        identity::{self, Binary, Kind},
        process::Child,
        runner, soak,
        workspace::{self, Workspace},
    },
    deploy::netem::{self, NetemArgs},
    hash,
    perf::{json_in, json_in::Value, json_out::Json},
    process::Tool,
};

use super::deployment_plan::{self, count, loss_token};
use super::suites;

use super::deployment_probe::json_string;
#[expect(
    unused_imports,
    reason = "public re-exports preserve the historical deployment:: probe API"
)]
pub use super::deployment_probe::{
    RelayEvidence, RouteCase, RouteExpectation, RouteResult, SocksThroughputPlan,
    SocksThroughputRow, probe_routes, relay_evidence, routing_summary, run_socks_throughput,
};
pub use deployment_plan::{Plan, PlanKind, Section, ThroughputCell};

use super::deployment_json::{number, root_object, string};
#[expect(
    unused_imports,
    reason = "pub(crate) re-exports preserve the historical deployment:: routing API"
)]
pub(crate) use super::deployment_routing::{
    ROUTING_GEOSITE_LABEL, RouteMatrixInput, RoutingConfig, RoutingConfigInput, ScaleConfigInput,
    route_cases, routing_config, scale_config, write_routing_assets,
};

#[derive(Debug, Clone)]
pub(crate) struct RunPlan {
    pub(crate) repo: PathBuf,
    pub(crate) rust_bin: PathBuf,
    pub(crate) xray_bin: PathBuf,
    pub(crate) out_dir: PathBuf,
    pub(crate) run_id: String,
    pub(crate) program: Plan,
    pub(crate) keep_work: bool,
}

#[derive(Debug)]
pub(crate) struct RunOutcome {
    pub(crate) summary_path: PathBuf,
    pub(crate) marker_path: PathBuf,
}

struct RunState<'a> {
    plan: &'a RunPlan,
    rust: Binary,
    xray: Binary,
    harness_sha256: String,
    run: RunDirectory,
    workspace: Workspace,
    lock: HostLock,
    children: Vec<Child>,
    next_port: u16,
    port_limit: u16,
}

struct SharedFixture {
    route_origin_port: u16,
    fixed_origin_port: u16,
    cover_port: u16,
    payload_a: PathBuf,
    payload_b: PathBuf,
    sha_a: String,
    sha_b: String,
}

impl RunState<'_> {
    fn port(&mut self) -> Result<u16, String> {
        if self.next_port >= self.port_limit {
            return Err("deployment runtime exhausted its reserved port block".to_owned());
        }
        let port = self.next_port;
        self.next_port += 1;
        Ok(port)
    }

    fn spawn_helper(
        &mut self,
        label: &str,
        args: &[String],
        log_name: &str,
        port: u16,
    ) -> Result<(), String> {
        let executable = std::env::current_exe()
            .map_err(|error| format!("could not identify rr-dev executable: {error}"))?;
        let mut child = Child::spawn_isolated(
            label,
            &executable,
            args,
            self.workspace.path(),
            &isolated_environment(),
            &self.workspace.join(log_name),
        )
        .map_err(|error| error.to_string())?;
        child
            .wait_for_port(port, Duration::from_secs(30))
            .map_err(|error| error.to_string())?;
        self.children.push(child);
        Ok(())
    }

    fn spawn_origin(
        &mut self,
        label: &str,
        directory: &Path,
        port: u16,
        tls: Option<(&Path, &Path)>,
    ) -> Result<(), String> {
        let mut args = vec![
            "bench".to_owned(),
            "origin".to_owned(),
            "--port".to_owned(),
            port.to_string(),
            "--payload-dir".to_owned(),
            directory.display().to_string(),
            "--put-log".to_owned(),
            self.workspace
                .join(&format!("{label}-put.jsonl"))
                .display()
                .to_string(),
            "--label".to_owned(),
            label.to_owned(),
        ];
        if let Some((certificate, key)) = tls {
            args.extend([
                "--tls-cert".to_owned(),
                certificate.display().to_string(),
                "--tls-key".to_owned(),
                key.display().to_string(),
            ]);
        }
        self.spawn_helper(label, &args, &format!("{label}.log"), port)
    }

    fn spawn_xray_client(
        &mut self,
        label: &str,
        server_port: u16,
        socks_port: u16,
        public_key: &str,
        identity: &RealityIdentity,
    ) -> Result<(), String> {
        let path = self.workspace.join(&format!("{label}.json"));
        soak::write_config(
            &path,
            &config::xray_client(identity, server_port, socks_port, public_key).to_python_json(),
        )?;
        let child = soak::spawn_xray_client(
            label,
            &self.xray,
            &path,
            &self.workspace,
            &self.workspace.join(&format!("{label}.log")),
            socks_port,
        )?;
        self.children.push(child);
        Ok(())
    }
}

pub(crate) fn run(plan: &RunPlan) -> Result<RunOutcome, String> {
    plan.program.validate()?;
    if plan.run_id.trim().is_empty() {
        return Err("deployment run ID must not be empty".to_owned());
    }
    let rust = identity::register("rust-reality", &plan.rust_bin, "", Kind::Rust)?;
    let xray = identity::register("xray", &plan.xray_bin, "", Kind::Xray)?;
    let lock = HostLock::acquire(&runner::default_lock_path())?;
    let mut workspace = Workspace::create("deployment")?;
    if plan.keep_work {
        workspace.keep();
    }
    let run = RunDirectory::create(&plan.out_dir)?;
    let base_port = workspace::reserve_block(96)?;
    let mut state = RunState {
        plan,
        rust,
        xray,
        harness_sha256: hash::sha256_file(Path::new("/proc/self/exe"))?,
        run,
        workspace,
        lock,
        children: Vec::new(),
        next_port: base_port,
        port_limit: base_port + 96,
    };
    state
        .run
        .write_new("plan.json", &plan.program.to_json().to_python_json())?;
    write_environment(&state)?;
    let attempted = execute_sections(&mut state).and_then(|()| deployment_run_summary(&state));
    let checks = [
        (
            "file:rust-reality".to_owned(),
            super::no_ccs::assert_unchanged(&state.rust),
        ),
        (
            "file:xray".to_owned(),
            super::no_ccs::assert_unchanged(&state.xray),
        ),
        (
            "image:harness".to_owned(),
            super::slot::verify_running_image(std::process::id(), &state.harness_sha256, "harness"),
        ),
    ];
    let summary = soak::finalize_native_attempt(&state.run, attempted, &checks)?;
    let summary_path = state
        .run
        .write_new("summary.json", &summary.to_python_json())?;
    let contract = run_contract(&state, &summary_path)?;
    let marker_path = state.run.publish(
        Publication::Contract,
        &contract.to_python_json(),
        &plan.run_id,
        "benchmark-deployment",
    )?;
    Ok(RunOutcome {
        summary_path,
        marker_path,
    })
}

fn execute_sections(state: &mut RunState<'_>) -> Result<(), String> {
    let plan = state.plan;
    let fixture = prepare_shared_fixture(state)?;
    if plan.program.sections.contains(&Section::Routing) {
        run_routing_section(state, &fixture)?;
    }
    if plan.program.sections.contains(&Section::Cost) {
        run_cost_section(state, &fixture)?;
    }
    if plan.program.sections.contains(&Section::Nxr) {
        run_topology_section(state, &fixture)?;
    }
    if plan.program.sections.contains(&Section::Rtt) {
        run_rtt_section(state, &fixture)?;
    }
    if plan.program.sections.contains(&Section::Longflow) {
        run_longflow_section(state, &fixture)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct CostVariant {
    label: &'static str,
    uuids: usize,
    rules: usize,
    global_rules: usize,
    strategy: &'static str,
    domain_destination: bool,
    with_ip: bool,
}

const COST_VARIANTS: [CostVariant; 5] = [
    CostVariant {
        label: "simple",
        uuids: 1,
        rules: 0,
        global_rules: 0,
        strategy: "AsIs",
        domain_destination: false,
        with_ip: false,
    },
    CostVariant {
        label: "medium",
        uuids: 100,
        rules: 16,
        global_rules: 4,
        strategy: "AsIs",
        domain_destination: false,
        with_ip: true,
    },
    CostVariant {
        label: "complex",
        uuids: 1_000,
        rules: 64,
        global_rules: 8,
        strategy: "AsIs",
        domain_destination: false,
        with_ip: true,
    },
    CostVariant {
        label: "complex-ipifnonmatch",
        uuids: 1_000,
        rules: 64,
        global_rules: 8,
        strategy: "IPIfNonMatch",
        domain_destination: true,
        with_ip: true,
    },
    CostVariant {
        label: "complex-ipondemand",
        uuids: 1_000,
        rules: 64,
        global_rules: 8,
        strategy: "IPOnDemand",
        domain_destination: true,
        with_ip: true,
    },
];

fn run_cost_section(state: &mut RunState<'_>, fixture: &SharedFixture) -> Result<(), String> {
    for variant in COST_VARIANTS {
        let server_port = state.port()?;
        let socks_port = state.port()?;
        let uuids = generate_uuids(&state.rust, variant.uuids)?;
        let generated = soak::generated_public_config(
            &soak::PublicNodeSpec::standalone(
                server_port,
                &format!("127.0.0.1:{}", fixture.cover_port),
            ),
            &state.workspace,
            &format!("assets-cost-{}", variant.label),
        )?;
        let json = scale_config(&ScaleConfigInput {
            base: &generated.json,
            uuids: &uuids,
            rules: variant.rules,
            global_rules: variant.global_rules,
            with_ip: variant.with_ip,
            strategy: variant.strategy,
            assets: &state
                .workspace
                .join(&format!("assets-cost-{}", variant.label)),
        })?;
        let config_path = state
            .workspace
            .join(&format!("cost-{}.json", variant.label));
        soak::write_config(&config_path, &json)?;
        soak::check_config(&state.rust.path, &config_path)?;
        let server = soak::spawn_rust(
            &format!("deployment-cost-{}-server", variant.label),
            &state.rust,
            &config_path,
            &state.workspace,
            &isolated_environment(),
            &state
                .workspace
                .join(&format!("cost-{}-server.log", variant.label)),
            server_port,
        )?;
        state.children.push(server);
        let identity = RealityIdentity {
            uuid: uuids[0].clone(),
            short_id: generated.short_id,
            server_name: "localhost".to_owned(),
            target: format!("127.0.0.1:{}", fixture.cover_port),
        };
        state.spawn_xray_client(
            &format!("deployment-cost-{}-client", variant.label),
            server_port,
            socks_port,
            &generated.public_key,
            &identity,
        )?;
        let destination = if variant.domain_destination {
            super::workload::Destination::Domain("localhost".to_owned())
        } else {
            super::workload::Destination::Loopback
        };
        if super::workload::connect_through(socks_port, &destination, fixture.route_origin_port)
            .is_none()
        {
            return Err(format!(
                "deployment cost {} warm-up did not reach the native origin",
                variant.label
            ));
        }
        let rows = super::workload::run_slot_to(
            &super::workload::SetupRatePlan {
                socks_port,
                origin_port: fixture.route_origin_port,
                connections: state.plan.program.connections,
                concurrencies: state.plan.program.concurrencies.clone(),
                samples: state.plan.program.samples,
                implementation: format!("cost-{}", variant.label),
                block: 0,
                position: 0,
                record_latencies: false,
            },
            &destination,
        )?;
        state.run.write_jsonl(
            &format!("setup-cost-{}.jsonl", variant.label),
            &rows.iter().map(setup_row_json).collect::<Vec<_>>(),
        )?;
    }
    Ok(())
}

fn setup_row_json(row: &super::workload::SampleRow) -> String {
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

#[derive(Clone, Copy)]
struct Topology {
    label: &'static str,
    socks_port: u16,
}

#[expect(
    clippy::too_many_lines,
    reason = "the four reviewed topologies are materialized together for direct comparison"
)]
fn run_topology_section(state: &mut RunState<'_>, fixture: &SharedFixture) -> Result<(), String> {
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
    let nxr_landing = landing_config(state, "nxr-landing", nxr_landing_port, &nxr_key, "warn")?;
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

fn deployment_public_config(
    state: &RunState<'_>,
    label: &str,
    spec: &soak::PublicNodeSpec,
) -> Result<soak::GeneratedPublicConfig, String> {
    let mut generated =
        soak::generated_public_config(spec, &state.workspace, &format!("assets-{label}"))?;
    generated.json = suites::set_rust_log_level(&generated.json, "warn")?;
    Ok(generated)
}

fn line_spec(
    line_port: u16,
    cover_port: u16,
    landing_port: u16,
    key: &str,
) -> soak::PublicNodeSpec {
    line_spec_to(line_port, cover_port, "127.0.0.1", landing_port, key)
}

fn line_spec_to(
    line_port: u16,
    cover_port: u16,
    peer_address: &str,
    peer_port: u16,
    key: &str,
) -> soak::PublicNodeSpec {
    soak::PublicNodeSpec::line(
        line_port,
        &format!("127.0.0.1:{cover_port}"),
        crate::bench::config::LandingLink {
            protocol: "nxr",
            address: peer_address.to_owned(),
            port: peer_port,
            psk: key.to_owned(),
            landing_public_key: None,
        },
    )
}

fn landing_config(
    state: &RunState<'_>,
    label: &str,
    port: u16,
    key: &str,
    level: &str,
) -> Result<String, String> {
    landing_config_at(state, label, "127.0.0.1", port, key, level)
}

fn landing_config_at(
    state: &RunState<'_>,
    label: &str,
    listen: &str,
    port: u16,
    key: &str,
    level: &str,
) -> Result<String, String> {
    let _ = (state, label);
    let rendered = crate::bench::config::rust_landing(
        listen,
        port,
        &crate::bench::config::LandingLink {
            protocol: "nxr",
            address: listen.to_owned(),
            port,
            psk: key.to_owned(),
            landing_public_key: None,
        },
        None,
    )
    .to_python_json();
    suites::set_rust_log_level(&rendered, level)
}

fn spawn_generated_rust(
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

#[expect(
    clippy::too_many_arguments,
    reason = "a transport variant's exact endpoint and sole warm/cold difference stay explicit"
)]
fn transport_line_config(
    raw: &str,
    inbound_port: u16,
    protocol: &str,
    address: &str,
    outbound_port: u16,
    warm_tcp: bool,
    log_level: &str,
    cache: &Path,
) -> Result<String, String> {
    let mut root = root_object(raw)?;
    let Some(Value::Object(log)) = root.get_mut("log") else {
        return Err("generated transport config has no log object".to_owned());
    };
    log.insert("level".to_owned(), string(log_level));
    let Some(Value::Object(assets)) = root.get_mut("assets") else {
        return Err("generated transport config has no assets object".to_owned());
    };
    assets.insert(
        "cacheDirectory".to_owned(),
        string(cache.display().to_string()),
    );
    replace_listener_port(&mut root, inbound_port)?;
    let Some(Value::Object(outbounds)) = root.get_mut("outbounds") else {
        return Err("generated transport config has no outbounds object".to_owned());
    };
    let outbound = outbounds
        .values_mut()
        .find(|outbound| outbound.str_field("outbound", "type") == Ok(protocol))
        .ok_or_else(|| format!("generated transport config has no {protocol} outbound"))?;
    let Value::Object(outbound) = outbound else {
        unreachable!("the type lookup only matches outbound objects")
    };
    outbound.insert("address".to_owned(), string(address));
    outbound.insert("port".to_owned(), number(u64::from(outbound_port)));
    outbound.insert("warmTcp".to_owned(), Value::Bool(warm_tcp));
    Ok(suites::render_compact(&Value::Object(root)))
}

fn replace_listener_port(root: &mut BTreeMap<String, Value>, port: u16) -> Result<(), String> {
    let Some(Value::Array(listeners)) = root.get_mut("listeners") else {
        return Err("generated transport config has no listeners array".to_owned());
    };
    let [Value::Object(listener)] = listeners.as_mut_slice() else {
        return Err("generated transport config must have exactly one listener object".to_owned());
    };
    listener.insert("port".to_owned(), number(u64::from(port)));
    Ok(())
}

fn landing_variant_config(raw: &str, inbound_port: u16) -> Result<String, String> {
    let mut root = root_object(raw)?;
    // Current landing nodes have no entry-side asset cache.
    replace_listener_port(&mut root, inbound_port)?;
    Ok(suites::render_compact(&Value::Object(root)))
}

fn xray_client_ports(raw: &str, server_port: u16, socks_port: u16) -> Result<String, String> {
    let mut root = root_object(raw)?;
    let Some(Value::Array(inbounds)) = root.get_mut("inbounds") else {
        return Err("generated Xray client has no inbounds array".to_owned());
    };
    let Some(Value::Object(inbound)) = inbounds.first_mut() else {
        return Err("generated Xray client has no first inbound".to_owned());
    };
    inbound.insert("port".to_owned(), number(u64::from(socks_port)));
    let Some(Value::Array(outbounds)) = root.get_mut("outbounds") else {
        return Err("generated Xray client has no outbounds array".to_owned());
    };
    let Some(Value::Object(outbound)) = outbounds.first_mut() else {
        return Err("generated Xray client has no first outbound".to_owned());
    };
    let Some(Value::Object(settings)) = outbound.get_mut("settings") else {
        return Err("generated Xray client outbound has no settings".to_owned());
    };
    let Some(Value::Array(servers)) = settings.get_mut("vnext") else {
        return Err("generated Xray client has no vnext array".to_owned());
    };
    let Some(Value::Object(server)) = servers.first_mut() else {
        return Err("generated Xray client has no first vnext server".to_owned());
    };
    server.insert("port".to_owned(), number(u64::from(server_port)));
    Ok(suites::render_compact(&Value::Object(root)))
}

fn identity_for(generated: &soak::GeneratedPublicConfig, cover_port: u16) -> RealityIdentity {
    RealityIdentity {
        uuid: generated.uuid.clone(),
        short_id: generated.short_id.clone(),
        server_name: "localhost".to_owned(),
        target: format!("127.0.0.1:{cover_port}"),
    }
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
fn run_rtt_section(state: &mut RunState<'_>, fixture: &SharedFixture) -> Result<(), String> {
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
    let landing = landing_config_at(
        state,
        "rtt-nxr-landing",
        "0.0.0.0",
        landing_port,
        &key,
        "warn",
    )?;
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

fn jsonl_body(rows: &[String]) -> String {
    let mut body = rows.join("\n");
    body.push('\n');
    body
}

fn write_new_file(path: &Path, contents: &str) -> Result<(), String> {
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

fn run_longflow_section(state: &mut RunState<'_>, fixture: &SharedFixture) -> Result<(), String> {
    let line_port = state.port()?;
    let landing_port = state.port()?;
    let socks_port = state.port()?;
    let key = soak::node_key(&state.rust.path)?;
    let line = deployment_public_config(
        state,
        "longflow-line",
        &line_spec(line_port, fixture.cover_port, landing_port, &key),
    )?;
    let landing = landing_config(state, "longflow-landing", landing_port, &key, "debug")?;
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

fn prepare_shared_fixture(state: &mut RunState<'_>) -> Result<SharedFixture, String> {
    let route_origin_port = state.port()?;
    let fixed_origin_port = state.port()?;
    let cover_port = state.port()?;
    let payload_a = state.workspace.join("payload-a");
    let payload_b = state.workspace.join("payload-b");
    std::fs::create_dir_all(&payload_a)
        .map_err(|error| format!("could not create {}: {error}", payload_a.display()))?;
    std::fs::create_dir_all(&payload_b)
        .map_err(|error| format!("could not create {}: {error}", payload_b.display()))?;
    super::origin_go::write_setup_payload(&payload_a)?;
    super::origin::write_payload(&payload_a.join("payload-0.bin"), 256)?;
    let mut sizes = BTreeSet::from([1_u64, state.plan.program.longflow_mib]);
    sizes.extend(
        state
            .plan
            .program
            .throughput_cells
            .iter()
            .map(|cell| cell.payload_mib),
    );
    for mebibytes in sizes {
        super::origin::write_payload(
            &payload_a.join(format!("payload-{mebibytes}.bin")),
            mebibytes * 1024 * 1024,
        )?;
    }
    write_inverted_payload(&payload_b.join("payload-1.bin"), 1024 * 1024)?;
    write_routing_assets(&payload_a)?;
    let sha_a = hash::sha256_file(&payload_a.join("payload-1.bin"))?;
    let sha_b = hash::sha256_file(&payload_b.join("payload-1.bin"))?;
    let (certificate, key) = super::origin_tls::generate_self_signed(state.workspace.path())?;
    state.spawn_origin("deployment-origin-a", &payload_a, route_origin_port, None)?;
    state.spawn_origin("deployment-origin-b", &payload_b, fixed_origin_port, None)?;
    state.spawn_origin(
        "deployment-cover",
        &payload_a,
        cover_port,
        Some((&certificate, &key)),
    )?;
    Ok(SharedFixture {
        route_origin_port,
        fixed_origin_port,
        cover_port,
        payload_a,
        payload_b,
        sha_a,
        sha_b,
    })
}

fn run_routing_section(state: &mut RunState<'_>, fixture: &SharedFixture) -> Result<(), String> {
    let fixed_socks_port = state.port()?;
    let server_port = state.port()?;
    let socks_ports = [state.port()?, state.port()?, state.port()?, state.port()?];
    state.spawn_helper(
        "deployment-fixed-socks",
        &[
            "bench".to_owned(),
            "socks-server".to_owned(),
            "--port".to_owned(),
            fixed_socks_port.to_string(),
            "--fixed-target".to_owned(),
            format!("127.0.0.1:{}", fixture.fixed_origin_port),
        ],
        "fixed-socks.log",
        fixed_socks_port,
    )?;
    let uuids = generate_uuids(&state.rust, 4)?;
    let generated = soak::generated_public_config(
        &soak::PublicNodeSpec::standalone(
            server_port,
            &format!("127.0.0.1:{}", fixture.cover_port),
        ),
        &state.workspace,
        "assets-routing-base",
    )?;
    let routing_assets = state.workspace.join("assets-routing");
    write_routing_assets(&routing_assets)?;
    let routing = routing_config(&RoutingConfigInput {
        base: &generated.json,
        uuids: &uuids,
        origin_a_port: fixture.route_origin_port,
        socks_b_port: fixed_socks_port,
        blocked_port: 9666,
        geosite_label: ROUTING_GEOSITE_LABEL,
        assets: &routing_assets,
    })?;
    let server_config = state.workspace.join("routing-server.json");
    soak::write_config(&server_config, &routing.json)?;
    soak::check_config(&state.rust.path, &server_config)?;
    let server = soak::spawn_rust(
        "deployment-routing-server",
        &state.rust,
        &server_config,
        &state.workspace,
        &isolated_environment(),
        &state.workspace.join("routing-server.log"),
        server_port,
    )?;
    state.children.push(server);
    for index in 0..4 {
        let identity = RealityIdentity {
            uuid: uuids[index].clone(),
            short_id: routing.short_ids[index].clone(),
            server_name: "localhost".to_owned(),
            target: format!("127.0.0.1:{}", fixture.cover_port),
        };
        state.spawn_xray_client(
            &format!("deployment-routing-client-{index}"),
            server_port,
            socks_ports[index],
            &generated.public_key,
            &identity,
        )?;
    }
    let cases = route_cases(&RouteMatrixInput {
        uuids: &uuids,
        socks_ports: &socks_ports,
        origin_a_port: fixture.route_origin_port,
        origin_b_port: fixture.fixed_origin_port,
        blocked_port: 9666,
        sha_a: &fixture.sha_a,
        sha_b: &fixture.sha_b,
    })?;
    let results = probe_routes(&cases);
    state.run.write_jsonl(
        "routing-correctness.jsonl",
        &results
            .iter()
            .map(|result| result.to_json().to_compact_json())
            .collect::<Vec<_>>(),
    )?;
    let summary = routing_summary(&results);
    state
        .run
        .write_new("summary-routing.json", &summary.to_python_json())?;
    if results.iter().all(|result| result.passed) {
        Ok(())
    } else {
        Err(format!(
            "deployment routing correctness failed {}/{} cases",
            results.iter().filter(|result| !result.passed).count(),
            results.len()
        ))
    }
}

fn generate_uuids(binary: &Binary, count: usize) -> Result<Vec<String>, String> {
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

fn write_inverted_payload(path: &Path, size: u64) -> Result<(), String> {
    let chunk: Vec<u8> = (0_u8..=255).rev().cycle().take(256 * 4096).collect();
    let mut file = std::fs::File::create(path)
        .map_err(|error| format!("could not create {}: {error}", path.display()))?;
    let mut remaining = size;
    while remaining > 0 {
        let take = usize::try_from(remaining.min(chunk.len() as u64)).unwrap_or(chunk.len());
        file.write_all(&chunk[..take])
            .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        remaining -= take as u64;
    }
    Ok(())
}

fn write_environment(state: &RunState<'_>) -> Result<(), String> {
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

fn deployment_run_summary(state: &RunState<'_>) -> Result<Json, String> {
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
    COST_VARIANTS
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

fn run_contract(state: &RunState<'_>, summary: &Path) -> Result<Json, String> {
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

fn parsed_to_json(value: &Value) -> Result<Json, String> {
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

fn isolated_environment() -> Vec<(String, String)> {
    vec![(
        "PATH".to_owned(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned(),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transport_fixture(protocol: &'static str) -> (String, config::LandingLink) {
        let identity = config::RealityIdentity {
            uuid: "11111111-2222-4333-8444-555555555555".to_owned(),
            short_id: "0123abcd".to_owned(),
            server_name: "localhost".to_owned(),
            target: "127.0.0.1:443".to_owned(),
        };
        let key = "ERERERERERERERERERERERERERERERERERERERERERE";
        let link = config::LandingLink {
            protocol,
            address: "127.0.0.1".to_owned(),
            port: 7443,
            psk: "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI".to_owned(),
            landing_public_key: (protocol == "handoff")
                .then(|| "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM".to_owned()),
        };
        let raw = config::RustServer::new(&identity, 8443, key)
            .assets_cache("/tmp/assets-original")
            .through_landing(&link)
            .build()
            .to_python_json();
        (raw, link)
    }

    #[test]
    fn rtt_transport_variants_validate_current_schema_and_preserve_identity() {
        for protocol in ["nxr", "handoff", "socks5"] {
            let (mut raw, _) = transport_fixture(if protocol == "socks5" {
                "nxr"
            } else {
                protocol
            });
            if protocol == "socks5" {
                raw = soak::patch_socks_outbound(&raw, 1080).unwrap();
            }
            let original = json_in::parse(&raw).unwrap();
            for warm in [false, true] {
                let changed = transport_line_config(
                    &raw,
                    9443,
                    protocol,
                    "192.0.2.2",
                    7444,
                    warm,
                    "info",
                    Path::new("/tmp/assets-variant"),
                )
                .unwrap();
                rust_reality::config::load_bytes(Path::new("variant.json"), changed.as_bytes())
                    .unwrap_or_else(|error| panic!("{protocol} warm={warm}: {error}"));
                let changed = json_in::parse(&changed).unwrap();
                for field in ["role", "reality", "users", "routing"] {
                    assert_eq!(changed.field("", field), original.field("", field));
                }
                assert_eq!(
                    changed.array_field("", "listeners").unwrap()[0]
                        .int_field("listener", "port")
                        .unwrap(),
                    9443
                );
                let mut expected = root_object(&raw).unwrap();
                replace_listener_port(&mut expected, 9443).unwrap();
                assert_eq!(
                    changed.field("", "listeners").unwrap(),
                    expected.get("listeners").unwrap()
                );
                let Value::Object(outbounds) = changed.field("", "outbounds").unwrap() else {
                    panic!()
                };
                let outbound = outbounds
                    .values()
                    .find(|o| o.str_field("", "type") == Ok(protocol))
                    .unwrap();
                assert_eq!(outbound.str_field("", "address").unwrap(), "192.0.2.2");
                assert_eq!(outbound.int_field("", "port").unwrap(), 7444);
                assert_eq!(outbound.field("", "warmTcp").unwrap(), &Value::Bool(warm));
                let Value::Object(original_outbounds) = original.field("", "outbounds").unwrap()
                else {
                    panic!()
                };
                let previous = original_outbounds
                    .values()
                    .find(|o| o.str_field("", "type") == Ok(protocol))
                    .unwrap();
                for field in ["psk", "landingPublicKey", "username", "password"] {
                    assert_eq!(outbound.optional(field), previous.optional(field));
                }
            }
        }
    }

    #[test]
    fn rtt_landing_variants_validate_without_entry_assets() {
        for protocol in ["nxr", "handoff"] {
            let (_, link) = transport_fixture(protocol);
            let raw = config::rust_landing(
                "192.0.2.2",
                7443,
                &link,
                (protocol == "handoff").then_some("REREREREREREREREREREREREREREREREREREREREREQ"),
            )
            .to_python_json();
            let changed = landing_variant_config(&raw, 7444).unwrap();
            rust_reality::config::load_bytes(Path::new("landing.json"), changed.as_bytes())
                .unwrap();
            let mut expected = root_object(&raw).unwrap();
            replace_listener_port(&mut expected, 7444).unwrap();
            assert_eq!(json_in::parse(&changed).unwrap(), Value::Object(expected));
            assert!(!changed.contains("assets"));
        }
    }

    #[test]
    fn rtt_variants_reject_retired_or_ambiguous_listener_shapes() {
        for raw in [
            r#"{"inbounds":[{"port":8443}]}"#,
            r#"{"listeners":[]}"#,
            r#"{"listeners":[{"port":8443},{"port":8444}]}"#,
        ] {
            assert!(landing_variant_config(raw, 9443).is_err());
        }
    }

    fn generated_base() -> &'static str {
        r#"{
          "sentinel":"keep",
          "log":{"level":"info","format":"json"},
          "assets":{"cacheDirectory":"old","sentinel":true},
          "inbounds":[{
            "port":8443,
            "settings":{"clients":[{
              "id":"base","flow":"xtls-rprx-vision","shortIds":["0123456789abcdef"]
            }]},
            "streamSettings":{"sentinel":true}
          }],
          "outbounds":[{"protocol":"direct","tag":"old-direct"}],
          "routing":{"users":[{"name":"old","userIds":["base"]}]}
        }"#
    }

    fn uuids(count: usize) -> Vec<String> {
        (0..count)
            .map(|index| format!("00000000-0000-4000-8000-{index:012}"))
            .collect()
    }

    #[test]
    fn routing_config_replaces_only_the_owned_policy_subtrees() {
        let uuids = uuids(4);
        let config = routing_config(&RoutingConfigInput {
            base: generated_base(),
            uuids: &uuids,
            origin_a_port: 8080,
            socks_b_port: 1080,
            blocked_port: 9666,
            geosite_label: "google",
            assets: Path::new("/tmp/assets"),
        })
        .unwrap();
        assert_eq!(config.short_ids.len(), 4);
        assert_eq!(config.short_ids[0], "0123456789abcdef");
        assert_eq!(config.short_ids.iter().collect::<BTreeSet<_>>().len(), 4);
        let value = json_in::parse(&config.json).unwrap();
        assert_eq!(value.str_field("", "sentinel").unwrap(), "keep");
        assert!(
            value.array_field("", "inbounds").unwrap()[0]
                .field("inbounds[0]", "streamSettings")
                .unwrap()
                .field("inbounds[0].streamSettings", "sentinel")
                .unwrap()
                .as_bool("sentinel")
                .unwrap()
        );
        assert_eq!(
            value
                .field("", "assets")
                .unwrap()
                .str_field("assets", "geosite")
                .unwrap(),
            "https://127.0.0.1:9/geosite.dat"
        );
        let clients = value.array_field("", "inbounds").unwrap()[0]
            .field("inbounds[0]", "settings")
            .unwrap()
            .array_field("inbounds[0].settings", "clients")
            .unwrap();
        assert_eq!(clients.len(), 4);
        let routing = value.field("", "routing").unwrap();
        assert_eq!(routing.array_field("routing", "users").unwrap().len(), 2);
        assert_eq!(
            routing.array_field("routing", "globalRules").unwrap().len(),
            3
        );
        assert!(
            value
                .field("", "assets")
                .unwrap()
                .field("assets", "sentinel")
                .unwrap()
                .as_bool("assets.sentinel")
                .unwrap()
        );
    }

    #[test]
    fn routing_cost_scale_retains_generated_identity_and_exact_dimensions() {
        let uuids = uuids(5);
        let json = scale_config(&ScaleConfigInput {
            base: generated_base(),
            uuids: &uuids,
            rules: 16,
            global_rules: 4,
            with_ip: true,
            strategy: "IPOnDemand",
            assets: Path::new("/tmp/scale-assets"),
        })
        .unwrap();
        let value = json_in::parse(&json).unwrap();
        assert_eq!(value.str_field("", "sentinel").unwrap(), "keep");
        let clients = value.array_field("", "inbounds").unwrap()[0]
            .field("inbounds[0]", "settings")
            .unwrap()
            .array_field("inbounds[0].settings", "clients")
            .unwrap();
        assert_eq!(clients.len(), 5);
        let routing = value.field("", "routing").unwrap();
        assert_eq!(
            routing.str_field("routing", "domainStrategy").unwrap(),
            "IPOnDemand"
        );
        let users = routing.array_field("routing", "users").unwrap();
        assert_eq!(users.len(), 2);
        assert_eq!(
            users[0]
                .array_field("routing.users[0]", "rules")
                .unwrap()
                .len(),
            16
        );
        let global = routing.array_field("routing", "globalRules").unwrap();
        assert_eq!(global.len(), 4);
        assert!(global.iter().all(|rule| {
            rule.str_field("rule", "name")
                .unwrap()
                .starts_with("global-")
        }));
    }

    #[test]
    fn routing_assets_and_case_matrix_are_bounded_and_complete() {
        let root = std::env::temp_dir().join(format!(
            "rr-deployment-routing-assets-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        write_routing_assets(&root).unwrap();
        assert_ne!(
            std::fs::read(root.join("geosite.dat")).unwrap(),
            Vec::<u8>::new()
        );
        assert_ne!(
            std::fs::read(root.join("geoip.dat")).unwrap(),
            Vec::<u8>::new()
        );
        let uuids = uuids(4);
        let cases = route_cases(&RouteMatrixInput {
            uuids: &uuids,
            socks_ports: &[1001, 1002, 1003, 1004],
            origin_a_port: 8080,
            origin_b_port: 8081,
            blocked_port: 9666,
            sha_a: "a",
            sha_b: "b",
        })
        .unwrap();
        assert_eq!(cases.len(), 26);
        assert_eq!(
            cases.iter().filter(|case| case.group == "alpha").count(),
            14
        );
        assert_eq!(cases.iter().filter(|case| case.group == "beta").count(), 12);
        assert_eq!(
            cases
                .iter()
                .filter(|case| matches!(case.expect, RouteExpectation::Sha256(_)))
                .count(),
            6
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn route_summary_requires_every_case() {
        let case = RouteCase {
            uuid: "u".to_owned(),
            group: "alpha".to_owned(),
            label: "block".to_owned(),
            socks_port: 1,
            host: "blocked.example".to_owned(),
            port: 80,
            path: "/payload-1.bin".to_owned(),
            expect: RouteExpectation::Blocked,
        };
        let results = vec![RouteResult {
            case,
            observed: "blocked".to_owned(),
            detail: String::new(),
            seconds: 0.1,
            passed: true,
        }];
        assert!(
            routing_summary(&results)
                .to_python_json()
                .contains("\"verdict\": \"PASS\"")
        );
    }

    #[test]
    fn relay_evidence_preserves_the_no_completion_caveat() {
        let log = r#"
{"event":"relay_backend_report","backends":[{"backend":"splice","available":true}]}
{"event":"connection_accepted"}
{"event":"connection_closed"}
"#;
        let evidence = relay_evidence(log);
        assert!(evidence.passes("splice"));
        let rendered = evidence
            .to_json(Path::new("landing.log"), "splice")
            .to_python_json();
        assert!(rendered.contains("\"perConnectionBackendEvidence\": \"not-emitted\""));
    }

    #[test]
    fn relay_evidence_rejects_missing_or_wrong_completion_backends() {
        let missing = relay_evidence(
            r#"{"event":"relay_backend_report","backends":[{"backend":"splice","available":true}]}
{"event":"connection_accepted"}
{"event":"connection_closed"}
{"event":"connection_completed"}"#,
        );
        assert!(!missing.passes("splice"));
        let wrong = relay_evidence(
            r#"{"event":"relay_backend_report","backends":[{"backend":"splice","available":true}]}
{"event":"connection_accepted"}
{"event":"connection_closed"}
{"event":"connection_completed","relay_backend":"copy"}"#,
        );
        assert!(!wrong.passes("splice"));
    }
}
