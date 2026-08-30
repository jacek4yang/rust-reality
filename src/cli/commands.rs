// Command implementations: the behavior behind each CLI subcommand.

use std::{
    fmt,
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use crate::{
    assets::AssetSnapshot,
    autotune::{AutotuneOptions, autotune_config},
    benchmark::{BenchmarkOptions, run_benchmarks},
    config::{format_config, format_config_schema, load_config},
    crypto::{generate_node_key, generate_uuid, generate_x25519_key_pair},
    server::{
        probe::{DestinationProbeError, probe_destination},
        production::ProductionServer,
        routing::RoutingTable,
    },
};
use serde_json::json;

use super::atomic::write_atomic;
use super::generate::{run_config_generate, run_mldsa65};
use super::model::{
    AutotuneArgs, BenchmarkArgs, Cli, CliError, Command, ConfigCommand, ConfigPath,
    ProbeDestinationArgs, RuntimeCommand,
};

pub fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Check(arguments) => {
            let _config = load_config(&arguments.config)?;
            write_stdout(format_args!(
                "configuration {} is valid\n",
                arguments.config.display()
            ))
        }
        Command::Config { command } => run_config(command),
        Command::Uuid { count } => {
            let mut output = String::new();
            for _ in 0..count {
                output.push_str(&generate_uuid()?.to_string());
                output.push('\n');
            }
            write_stdout(output)
        }
        Command::X25519 => {
            let pair = generate_x25519_key_pair()?;
            let output = serde_json::to_string_pretty(&json!({
                "privateKey": pair.private_key(),
                "publicKey": pair.public_key(),
            }))?;
            write_stdout(format_args!("{output}\n"))
        }
        Command::Mldsa65(arguments) => run_mldsa65(arguments),
        Command::NodeKeygen => {
            let key = generate_node_key()?;
            let output = serde_json::to_string_pretty(&json!({
                "preSharedKey": key,
            }))?;
            write_stdout(format_args!("{output}\n"))
        }
        Command::ProbeDest(arguments) => run_probe_destination(arguments),
        Command::Schema => write_stdout(format_config_schema()?),
        Command::Serve(arguments) | Command::Run(arguments) => run_server(arguments),
        Command::Runtime { command } => run_runtime(command),
        Command::SelfTest(arguments) => run_self_test(arguments),
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
    // Bootstrap order (design §4.2): parse the CLI, load and validate the
    // configuration, inspect the cgroup/machine view, choose the runtime
    // topology, build the runtime, then serve. Detection is one cheap pass
    // of /proc and rlimit reads — never a benchmark — so readiness is not
    // delayed, and the server reuses this report instead of detecting again.
    let config = load_config(&arguments.config)?;
    let machine = crate::runtime::machine::MachineReport::detect();
    let resource_mode = config.runtime.resolve_resource_mode(&machine);
    let topology =
        crate::runtime::plan::RuntimeTopology::for_mode(resource_mode, machine.effective_cpus());
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    // The dedicated posture sizes both pools from the cgroup-aware CPU view;
    // the shared/standard posture keeps the tokio defaults (no explicit
    // settings), exactly as v1.5 built the runtime.
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

pub(crate) fn run_runtime(command: RuntimeCommand) -> Result<(), CliError> {
    match command {
        RuntimeCommand::Explain(arguments) => {
            let config = load_config(&arguments.config)?;
            let machine = crate::runtime::machine::MachineReport::detect();
            let explanation = crate::explain::explain_config(&config, &machine);
            if arguments.json {
                let mut output = serde_json::to_string_pretty(&explanation)?;
                output.push('\n');
                write_stdout(output)
            } else {
                write_stdout(format_args!("{explanation}"))
            }
        }
        RuntimeCommand::Report(arguments) => {
            let status = crate::runtime::adaptive::read_status(&arguments.status_file)?;
            if arguments.json {
                let mut output = serde_json::to_string_pretty(&status)?;
                output.push('\n');
                write_stdout(output)
            } else {
                write_stdout(format_args!("{status}"))
            }
        }
    }
}

pub(crate) fn run_self_test(arguments: ConfigPath) -> Result<(), CliError> {
    let config = load_config(&arguments.config)?;
    let assets = Arc::new(AssetSnapshot::load(&config)?);
    let summary = assets.summary();
    RoutingTable::compile(
        &config.routing,
        assets,
        crate::runtime::ResourceGovernor::new(&config.advanced.limits.resource_governor),
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let probe_timeout =
        Duration::from_millis(config.advanced.limits.resource_governor.connect_timeout_ms);
    let reality_destinations = runtime.block_on(async {
        let mut reports = Vec::new();
        let network_environment = crate::network::NetworkEnvironment::detect();
        for inbound in &config.inbounds {
            let Some(inbound) = inbound.as_vless() else {
                continue;
            };
            for server_name in &inbound.stream_settings.reality_settings.server_names {
                reports.push(
                    crate::server::probe::probe_destination_pattern_with_network(
                        &inbound.stream_settings.reality_settings.target,
                        server_name,
                        probe_timeout,
                        &config.network,
                        network_environment.clone(),
                    )
                    .await?,
                );
            }
        }
        Ok::<_, DestinationProbeError>(reports)
    })?;
    let output = serde_json::to_string_pretty(&json!({
        "configuration": "ok",
        "assets": summary,
        "routing": "ok",
        "realityDestinations": reality_destinations,
    }))?;
    write_stdout(format_args!("{output}\n"))
}

pub(crate) fn run_probe_destination(arguments: ProbeDestinationArgs) -> Result<(), CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let report = runtime.block_on(probe_destination(
        &arguments.target,
        &arguments.server_name,
        Duration::from_millis(arguments.timeout_ms),
    ))?;
    let output = serde_json::to_string_pretty(&report)?;
    write_stdout(format_args!("{output}\n"))
}

pub(crate) fn run_config(command: ConfigCommand) -> Result<(), CliError> {
    match command {
        ConfigCommand::Generate { role } => run_config_generate(role),
        ConfigCommand::Autotune(arguments) => run_config_autotune(arguments),
        ConfigCommand::Format(arguments) => {
            let config = load_config(arguments.config)?;
            write_stdout(format_config(&config)?)
        }
    }
}

pub(crate) fn run_config_autotune(arguments: AutotuneArgs) -> Result<(), CliError> {
    if arguments.config == arguments.output {
        return Err(CliError::InvalidArgument(
            "--output must differ from --config; autotune never overwrites its input",
        ));
    }
    let report_path = arguments.report.unwrap_or_else(|| {
        let mut path = arguments.output.as_os_str().to_os_string();
        path.push(".report.json");
        PathBuf::from(path)
    });
    if report_path == arguments.config || report_path == arguments.output {
        return Err(CliError::InvalidArgument(
            "--report must differ from both --config and --output",
        ));
    }
    let source = load_config(&arguments.config)?;
    let tuned = autotune_config(
        &source,
        &AutotuneOptions {
            benchmark_duration: Duration::from_millis(arguments.duration_ms),
            benchmark_warmup: Duration::from_millis(arguments.warmup_ms),
            storage_bytes: u64::from(arguments.storage_mib) * 1024 * 1024,
            network_bytes: u64::from(arguments.network_mib) * 1024 * 1024,
            scratch_directory: arguments
                .scratch_directory
                .unwrap_or_else(std::env::temp_dir),
            dedicated: arguments.dedicated,
        },
    )?;
    let config_json = format_config(tuned.config())?;
    let mut report_json = serde_json::to_string_pretty(tuned.report())?;
    report_json.push('\n');
    // Publish the non-authoritative report first and the validated config
    // last. A crash can leave an orphan report, but never advertises a config
    // whose matching report was only partially written.
    write_atomic(&report_path, report_json.as_bytes())?;
    write_atomic(&arguments.output, config_json.as_bytes())?;
    write_stdout(format_args!(
        "tuned configuration: {}\nmeasurement report: {}\n",
        arguments.output.display(),
        report_path.display()
    ))
}

pub(crate) fn write_stdout(output: impl fmt::Display) -> Result<(), CliError> {
    write!(io::stdout().lock(), "{output}").map_err(CliError::Io)
}
