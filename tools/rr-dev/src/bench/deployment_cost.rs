//! Routing-cost characterization section helpers.
//!
//! Owns the reviewed cost-variant matrix (simple → complex IP strategies) and
//! its SOCKS setup-rate cells. Process lifecycle still rides on
//! [`super::deployment_state::RunState`].

use crate::bench::{config::RealityIdentity, soak};

use super::deployment::{SharedFixture, generate_uuids, isolated_environment, setup_row_json};
use super::deployment_routing::{ScaleConfigInput, scale_config};
use super::deployment_state::RunState;

#[derive(Clone, Copy)]
pub(crate) struct CostVariant {
    pub(crate) label: &'static str,
    pub(crate) uuids: usize,
    pub(crate) rules: usize,
    pub(crate) global_rules: usize,
    pub(crate) strategy: &'static str,
    pub(crate) domain_destination: bool,
    pub(crate) with_ip: bool,
}

pub(crate) const COST_VARIANTS: [CostVariant; 5] = [
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

pub(crate) fn run_cost_section(
    state: &mut RunState<'_>,
    fixture: &SharedFixture,
) -> Result<(), String> {
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
        )
        .map_err(|error| error.to_string())?;
        state.run.write_jsonl(
            &format!("setup-cost-{}.jsonl", variant.label),
            &rows.iter().map(setup_row_json).collect::<Vec<_>>(),
        )?;
    }
    Ok(())
}
