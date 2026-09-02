// Command implementations: the behavior behind each CLI subcommand.

use std::{
    fmt,
    io::{self, Write},
    sync::Arc,
    time::Duration,
};

use crate::{
    assets::AssetSnapshot,
    benchmark::{BenchmarkOptions, run_benchmarks},
    config::{load, node::reality::RealityConfig},
    crypto::{generate_node_key, generate_short_id, generate_uuid, generate_x25519_key_pair},
    server::{
        probe::{DestinationProbeError, probe_destination},
        production::ProductionServer,
        routing::RoutingTable,
    },
};
use serde_json::json;

use super::model::{
    BenchmarkArgs, CheckCoverArgs, Cli, CliError, Command, ConfigPath, ExplainArgs, GenerateCommand,
};

pub fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Run(arguments) => run_server(arguments),
        Command::Check(arguments) => {
            let node = load(&arguments.config)?;
            write_stdout(format_args!(
                "{} is a valid {} node\n",
                arguments.config.display(),
                node.role().as_str()
            ))
        }
        Command::Doctor(arguments) => run_doctor(arguments),
        Command::Explain(arguments) => run_explain(arguments),
        Command::Format(arguments) => run_format(arguments),
        Command::CheckCover(arguments) => run_check_cover(arguments),
        Command::Generate { command } => run_generate(command),
        Command::Schema => write_stdout(crate::config::node::schema_json()?),
        Command::Benchmark(arguments) => run_benchmark(arguments),
    }
}

pub(crate) fn run_benchmark(arguments: BenchmarkArgs) -> Result<(), CliError> {
    let report = run_benchmarks(BenchmarkOptions {
        duration: Duration::from_millis(arguments.duration_ms),
        warmup: Duration::from_millis(arguments.warmup_ms),
    })?;
    let output = serde_json::to_string_pretty(&report)?;
    write_stdout(format_args!("{output}\n"))
}

pub(crate) fn run_server(arguments: ConfigPath) -> Result<(), CliError> {
    // Bootstrap order: parse the CLI, load and validate the configuration,
    // inspect the cgroup/machine view, choose the runtime topology, build the
    // runtime, then serve. Detection is one cheap pass of /proc and rlimit
    // reads — never a benchmark — so readiness is not delayed, and the server
    // reuses this report instead of detecting again.
    let config = load(&arguments.config)?;
    let machine = crate::runtime::machine::MachineReport::detect();
    let resource_mode =
        crate::runtime::policy::resolve_resource_mode(config.node().runtime().profile(), &machine);
    let topology =
        crate::runtime::plan::RuntimeTopology::for_mode(resource_mode, machine.effective_cpus());
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    // The dedicated posture sizes both pools from the cgroup-aware CPU view;
    // the shared posture keeps the tokio defaults.
    if let Some(worker_threads) = topology.worker_threads {
        builder.worker_threads(worker_threads);
    }
    if let Some(max_blocking_threads) = topology.max_blocking_threads {
        builder.max_blocking_threads(max_blocking_threads);
    }
    let runtime = builder.enable_all().build()?;
    let server = ProductionServer::from_loaded(config, Some(arguments.config.clone()), machine)?;
    let result = runtime.block_on(server.run());
    runtime.shutdown_timeout(Duration::from_secs(5));
    result?;
    Ok(())
}

/// Reports what this configuration resolves to on this machine.
///
/// Everything here is offline and read-only: one machine detection, the same
/// derivation `run` would perform, and no listener, socket, or file write.
pub(crate) fn run_explain(arguments: ExplainArgs) -> Result<(), CliError> {
    let config = load(&arguments.config)?;
    let machine = crate::runtime::machine::MachineReport::detect();
    let explanation = crate::explain::explain_config(config.node(), &machine);
    if arguments.json {
        let mut output = serde_json::to_string_pretty(&explanation)?;
        output.push('\n');
        write_stdout(output)
    } else {
        write_stdout(format_args!("{explanation}"))
    }
}

/// Rewrites a configuration in the canonical form, or prints it.
///
/// Unlike a generic JSON formatter this parses and validates first, so its
/// output is always a configuration this binary accepts, and it orders keys
/// the way the reference documents them. It never adds a field the operator
/// omitted and never drops one they wrote.
pub(crate) fn run_format(arguments: super::model::FormatArgs) -> Result<(), CliError> {
    let config = load(&arguments.config)?;
    let mut rendered = serde_json::to_string_pretty(config.node())?;
    rendered.push('\n');
    if arguments.write {
        super::atomic::write_atomic(&arguments.config, rendered.as_bytes())?;
        write_stdout(format_args!("{}\n", arguments.config.display()))
    } else {
        write_stdout(rendered)
    }
}

/// Verifies that this configuration can work on this machine and network.
///
/// This is the environment-sensitive counterpart to `check`: it repeats the
/// same validation and then contacts the things the configuration names.
pub(crate) fn run_doctor(arguments: ConfigPath) -> Result<(), CliError> {
    let config = load(&arguments.config)?;
    let node = config.node();
    let machine = crate::runtime::machine::MachineReport::detect();
    let resource_mode =
        crate::runtime::policy::resolve_resource_mode(node.runtime().profile(), &machine);
    let policy = crate::runtime::plan::resolve_policy(
        &node.runtime().limits(),
        node.runtime().objective(),
        &machine,
        resource_mode,
        node.listeners().len(),
    )
    .policy;
    let probe_timeout = Duration::from_millis(policy.governor.connect_timeout_ms);

    let Some(entry) = node.as_entry() else {
        // A landing node has no cover target and no routing, so there is
        // nothing to reach out to; validation is the whole check.
        let output = serde_json::to_string_pretty(&json!({
            "configuration": "ok",
            "role": node.role().as_str(),
        }))?;
        return write_stdout(format_args!("{output}\n"));
    };

    let assets = Arc::new(AssetSnapshot::load(entry)?);
    let summary = assets.summary();
    RoutingTable::compile(
        &entry.routing,
        &entry.users,
        assets,
        crate::runtime::ResourceGovernor::new(&policy.governor),
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let network = entry.network.unwrap_or_default();
    let cover_reports = runtime.block_on(async {
        let mut reports = Vec::new();
        let network_environment = crate::network::NetworkEnvironment::detect();
        for server_name in entry.reality.effective_server_names() {
            reports.push(
                crate::server::probe::probe_destination_pattern_with_network(
                    &entry.reality.cover,
                    server_name,
                    probe_timeout,
                    &network,
                    network_environment.clone(),
                )
                .await?,
            );
        }
        Ok::<_, DestinationProbeError>(reports)
    })?;
    let output = serde_json::to_string_pretty(&json!({
        "configuration": "ok",
        "role": node.role().as_str(),
        "assets": summary,
        "routing": "ok",
        "cover": cover_reports,
    }))?;
    write_stdout(format_args!("{output}\n"))
}

/// Evaluates a candidate REALITY cover target before it is committed to a
/// configuration.
///
/// This is the first step of every deployment, and it has to run from the host
/// that will front the cover: whether a target is usable depends on the network
/// path, so an answer from somewhere else does not transfer.
pub(crate) fn run_check_cover(arguments: CheckCoverArgs) -> Result<(), CliError> {
    let server_name = match arguments.server_name {
        Some(name) => name,
        None => {
            // Default to the cover host, exactly as an omitted
            // `reality.serverNames` does.
            let probe = RealityConfig {
                cover: arguments.cover.clone(),
                private_key: crate::config::SecretString::new(String::new()),
                server_names: None,
                max_time_diff_ms: None,
                cover_optimization: None,
            };
            probe
                .cover_host()
                .ok_or(CliError::InvalidArgument(
                    "--cover must be host:port, so the name to probe can be taken from the host",
                ))?
                .to_owned()
        }
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let report = runtime.block_on(probe_destination(
        &arguments.cover,
        &server_name,
        Duration::from_millis(arguments.timeout_ms),
    ))?;
    let output = serde_json::to_string_pretty(&report)?;
    write_stdout(format_args!("{output}\n"))
}

/// Generates one piece of material an operator should not invent by hand.
///
/// Each subcommand emits exactly what was asked for. Nothing here assembles a
/// configuration: composing the JSON is the operator's job, because an operator
/// who received an opaque file cannot reason about a routing change, a
/// credential rotation, or a failure.
pub(crate) fn run_generate(command: GenerateCommand) -> Result<(), CliError> {
    match command {
        GenerateCommand::Uuid { count, json } => {
            let mut values = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                values.push(generate_uuid()?.to_string());
            }
            if json {
                emit_json(&json!({ "uuids": values }))
            } else {
                write_stdout(values.join("\n") + "\n")
            }
        }
        GenerateCommand::X25519 { json } => {
            let pair = generate_x25519_key_pair()?;
            if json {
                emit_json(&json!({
                    "privateKey": pair.private_key().expose(),
                    "publicKey": pair.public_key(),
                }))
            } else {
                write_stdout(format_args!(
                    "private key (keep secret): {}\npublic key  (give to peers): {}\n",
                    pair.private_key().expose(),
                    pair.public_key()
                ))
            }
        }
        GenerateCommand::ShortId { count, bytes, json } => {
            let mut values = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                values.push(generate_short_id(bytes)?);
            }
            if json {
                emit_json(&json!({ "shortIds": values }))
            } else {
                write_stdout(values.join("\n") + "\n")
            }
        }
        GenerateCommand::Psk { json } => {
            let key = generate_node_key()?;
            if json {
                emit_json(&json!({ "psk": key.expose() }))
            } else {
                write_stdout(format_args!("{}\n", key.expose()))
            }
        }
    }
}

fn emit_json(value: &serde_json::Value) -> Result<(), CliError> {
    let mut output = serde_json::to_string_pretty(value)?;
    output.push('\n');
    write_stdout(output)
}

pub(crate) fn write_stdout(output: impl fmt::Display) -> Result<(), CliError> {
    write!(io::stdout().lock(), "{output}").map_err(CliError::Io)
}

#[cfg(test)]
mod tests {
    use super::run_generate;
    use crate::cli::model::GenerateCommand;

    #[test]
    fn every_generator_emits_only_what_was_asked_for() {
        // The generators write to stdout, so the contract under test is that
        // each one succeeds and that none of them needs a configuration.
        for command in [
            GenerateCommand::Uuid {
                count: 2,
                json: true,
            },
            GenerateCommand::X25519 { json: true },
            GenerateCommand::ShortId {
                count: 2,
                bytes: 8,
                json: true,
            },
            GenerateCommand::Psk { json: true },
        ] {
            run_generate(command).expect("a generator must not need a configuration");
        }
    }
}
