//! Deployment-characterization native suite orchestration.
//!
//! The legacy harness looked like one benchmark but carried five distinct
//! sections. Plan dimensions live in [`super::deployment_plan`] so an execution
//! refactor cannot silently narrow the formal evidence: a full run still means
//! routing correctness, routing cost, four deployment topologies, the complete
//! one-leg netem matrix, and long-flow relay evidence. Routing probes, SOCKS
//! throughput cells, and relay-log evidence live in [`super::deployment_probe`].
//! Routing correctness builders + section runner live in [`super::deployment_routing`].
//! Transport / landing JSON mutations live in [`super::deployment_transport`].
//! RTT / netem matrix orchestration lives in [`super::deployment_rtt`].
//! Four-topology setup/throughput orchestration lives in [`super::deployment_topology`].
//! Routing-cost variant matrix lives in [`super::deployment_cost`].
//! Long-flow LINE+LANDING throughput / relay evidence lives in [`super::deployment_longflow`].
//! Environment / section summary / artifact verification lives in [`super::deployment_summary`].
//! Shared origin/cover fixture preparation lives in [`super::deployment_fixture`].
//! Shared free-standing helpers live in [`super::deployment_util`].

use std::{
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
};

use super::deployment_plan;
use super::deployment_summary::{deployment_run_summary, run_contract, write_environment};

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

pub(crate) use super::deployment_summary::parsed_to_json;

pub(crate) use super::deployment_fixture::SharedFixture;
use super::deployment_fixture::prepare_shared_fixture;

pub(crate) use super::deployment_util::{
    deployment_public_config, generate_uuids, isolated_environment, jsonl_body, setup_row_json,
    spawn_generated_rust, write_new_file,
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

fn run_topology_section(state: &mut RunState<'_>, fixture: &SharedFixture) -> Result<(), String> {
    super::deployment_topology::run_topology_section(state, fixture)
}

fn run_longflow_section(state: &mut RunState<'_>, fixture: &SharedFixture) -> Result<(), String> {
    super::deployment_longflow::run_longflow_section(state, fixture)
}

fn run_routing_section(state: &mut RunState<'_>, fixture: &SharedFixture) -> Result<(), String> {
    super::deployment_routing::run_routing_section(state, fixture)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::perf::{json_in, json_in::Value};

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
