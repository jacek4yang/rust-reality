//! Deployment-characterization native suite orchestration.
//!
//! The legacy harness looked like one benchmark but carried five distinct
//! sections. Plan dimensions live in [`super::deployment_plan`] so an execution
//! refactor cannot silently narrow the formal evidence: a full run still means
//! routing correctness, routing cost, four deployment topologies, the complete
//! one-leg netem matrix, and long-flow relay evidence. Routing probes, SOCKS
//! throughput cells, and relay-log evidence live in [`super::deployment_probe`].
//! Routing policy builders and geosite/geoip fixtures live in [`super::deployment_routing`].
//! Transport / landing JSON mutations live in [`super::deployment_transport`].
//! RTT / netem matrix orchestration lives in [`super::deployment_rtt`].
//! Four-topology setup/throughput orchestration lives in [`super::deployment_topology`].
//! Routing-cost variant matrix lives in [`super::deployment_cost`].
//! Long-flow LINE+LANDING throughput / relay evidence lives in [`super::deployment_longflow`].

use std::{
    collections::BTreeSet,
    io::Write as _,
    path::{Path, PathBuf},
    time::Duration,
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
    hash,
    perf::{json_in, json_in::Value, json_out::Json},
    process::Tool,
};

use super::deployment_plan::{self, count};
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
#[expect(
    unused_imports,
    reason = "public re-export preserves the historical deployment:: ThroughputCell API"
)]
pub use deployment_plan::{Plan, PlanKind, Section, ThroughputCell};

#[expect(
    unused_imports,
    reason = "pub(crate) re-exports preserve the historical deployment:: routing API"
)]
pub(crate) use super::deployment_routing::{
    ROUTING_GEOSITE_LABEL, RouteMatrixInput, RoutingConfig, RoutingConfigInput, ScaleConfigInput,
    route_cases, routing_config, scale_config, write_routing_assets,
};

#[expect(
    unused_imports,
    reason = "pub(crate) re-exports preserve the historical deployment:: transport API for tests"
)]
pub(crate) use super::deployment_transport::{
    landing_config_at, landing_variant_config, line_spec_to, transport_line_config,
    xray_client_ports,
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

pub(crate) struct RunState<'a> {
    pub(crate) plan: &'a RunPlan,
    pub(crate) rust: Binary,
    pub(crate) xray: Binary,
    pub(crate) harness_sha256: String,
    pub(crate) run: RunDirectory,
    pub(crate) workspace: Workspace,
    pub(crate) lock: HostLock,
    pub(crate) children: Vec<Child>,
    pub(crate) next_port: u16,
    pub(crate) port_limit: u16,
}

pub(crate) struct SharedFixture {
    pub(crate) route_origin_port: u16,
    pub(crate) fixed_origin_port: u16,
    pub(crate) cover_port: u16,
    pub(crate) payload_a: PathBuf,
    pub(crate) payload_b: PathBuf,
    pub(crate) sha_a: String,
    pub(crate) sha_b: String,
}

impl RunState<'_> {
    pub(crate) fn port(&mut self) -> Result<u16, String> {
        if self.next_port >= self.port_limit {
            return Err("deployment runtime exhausted its reserved port block".to_owned());
        }
        let port = self.next_port;
        self.next_port += 1;
        Ok(port)
    }

    pub(crate) fn spawn_helper(
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

    pub(crate) fn spawn_origin(
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

    pub(crate) fn spawn_xray_client(
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
        super::deployment_rtt::run_rtt_section(state, &fixture)?;
    }
    if plan.program.sections.contains(&Section::Longflow) {
        run_longflow_section(state, &fixture)?;
    }
    Ok(())
}

fn run_cost_section(state: &mut RunState<'_>, fixture: &SharedFixture) -> Result<(), String> {
    super::deployment_cost::run_cost_section(state, fixture)
}

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

fn run_topology_section(state: &mut RunState<'_>, fixture: &SharedFixture) -> Result<(), String> {
    super::deployment_topology::run_topology_section(state, fixture)
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

fn run_longflow_section(state: &mut RunState<'_>, fixture: &SharedFixture) -> Result<(), String> {
    super::deployment_longflow::run_longflow_section(state, fixture)
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

pub(crate) fn isolated_environment() -> Vec<(String, String)> {
    vec![(
        "PATH".to_owned(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned(),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bench::deployment_json::root_object;
    use crate::bench::deployment_transport::replace_listener_port;

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
