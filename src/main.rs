use std::{
    error::Error,
    fmt,
    fs::{File, OpenOptions},
    io::{self, Write},
    net::{IpAddr, Ipv4Addr},
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use clap::{Args, Parser, Subcommand};
use rust_reality::{
    assets::{AssetLoadError, AssetSnapshot},
    autotune::{AutotuneError, AutotuneOptions, autotune_config},
    benchmark::{BenchmarkError, BenchmarkOptions, run_benchmarks},
    config::{
        ConfigLoadError, ConfigLoadReport, GenerateConfigError, GenerateConfigInput,
        GenerateHandoffConfigInput, GenerateLandingConfigInput, GenerateLineConfigInput,
        GenerateMultiHandoffConfigInput, GeneratedHandoffConfigs, GeneratedMultiHandoffConfigs,
        HandoffLandingInput, SecretString, format_config, format_config_schema,
        generate_handoff_configs, generate_landing_config, generate_line_config,
        generate_minimal_config, generate_multi_handoff_configs, load_config_with_report,
    },
    crypto::{
        KeyGenerationError, generate_mldsa65_key_pair, generate_mldsa65_key_pair_from_seed,
        generate_node_key, generate_uuid, generate_x25519_key_pair,
    },
    server::{
        probe::{DestinationProbeError, probe_destination},
        production::{ProductionServer, ProductionServerError},
        routing::{RoutingCompileError, RoutingTable},
    },
};
use serde_json::json;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(
    name = "rust-reality",
    version,
    about = "Linux-focused VLESS + REALITY + Vision proxy"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate a complete JSON configuration without starting the server.
    Check(ConfigPath),
    /// Generate or format strict JSON configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Generate RFC 4122 version 4 UUIDs using operating-system entropy.
    Uuid {
        /// Number of UUIDs to generate.
        #[arg(default_value_t = 1, value_parser = clap::value_parser!(u16).range(1..=1024))]
        count: u16,
    },
    /// Generate one REALITY-compatible X25519 key pair.
    X25519,
    /// Generate an Xray-compatible ML-DSA-65 seed and verification key.
    Mldsa65(MlDsa65Args),
    /// Generate one independent 32-byte NXR pre-shared key.
    NodeKeygen,
    /// Test a real cover target for strict REALITY TLS 1.3 compatibility.
    ProbeDest(ProbeDestinationArgs),
    /// Print the complete JSON Schema to standard output.
    Schema,
    /// Run the foreground production server until SIGINT or SIGTERM.
    Serve(ConfigPath),
    /// Alias for `serve`, suitable for service-manager command lines.
    Run(ConfigPath),
    /// Validate configuration, download/revalidate assets, and compile routing.
    SelfTest(ConfigPath),
    /// Quantify bounded protocol hot paths and print a machine-readable report.
    Benchmark(BenchmarkArgs),
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Generate a directly usable standalone, line-node, or landing-node configuration.
    Generate {
        #[command(subcommand)]
        role: GenerateRole,
    },
    /// Benchmark this host and write a validated automatically tuned copy.
    Autotune(AutotuneArgs),
    /// Validate and print a canonical pretty JSON configuration.
    Format(ConfigPath),
}

#[derive(Debug, Args)]
struct AutotuneArgs {
    /// Existing valid configuration whose routing and secrets are preserved.
    #[arg(short, long, value_name = "PATH")]
    config: PathBuf,
    /// New tuned configuration path.
    #[arg(short, long, value_name = "PATH")]
    output: PathBuf,
    /// Measurement report path; defaults to OUTPUT.report.json.
    #[arg(long, value_name = "PATH")]
    report: Option<PathBuf>,
    /// Measured milliseconds for each protocol hot-path case.
    #[arg(long, default_value_t = 900, value_parser = clap::value_parser!(u64).range(90..=30_000))]
    duration_ms: u64,
    /// Warm-up milliseconds before each protocol case.
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u64).range(1..=10_000))]
    warmup_ms: u64,
    /// MiB written/read in the bounded temporary storage probe.
    #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u16).range(1..=256))]
    storage_mib: u16,
    /// MiB transferred in each direction through TCP loopback.
    #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u16).range(1..=256))]
    network_mib: u16,
    /// Storage-probe directory; defaults to the operating-system temp directory.
    #[arg(long, value_name = "DIR")]
    scratch_directory: Option<PathBuf>,
    /// Declare this process the exclusive owner of the host or cgroup.
    #[arg(long)]
    dedicated: bool,
}

#[derive(Debug, Args)]
struct ConfigPath {
    /// JSON configuration path.
    #[arg(short, long, value_name = "PATH")]
    config: PathBuf,
}

#[derive(Debug, Args)]
struct PublicGenerateArgs {
    /// Public listener address.
    #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::UNSPECIFIED))]
    listen: IpAddr,
    /// Public listener port.
    #[arg(long, default_value_t = 443, value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,
    /// REALITY cover endpoint, including its port.
    #[arg(long, value_name = "HOST:PORT")]
    target: String,
    /// Client-facing REALITY SNI.
    #[arg(long, value_name = "DNS_NAME")]
    server_name: String,
}

#[derive(Debug, Subcommand)]
enum GenerateRole {
    /// Public VLESS + REALITY + Vision server with direct routing.
    Standalone(PublicGenerateArgs),
    /// Public VLESS + REALITY + Vision line node routed to an NXR landing node.
    Line(LineGenerateArgs),
    /// Firewall-restricted internal NXR landing node.
    Landing(LandingGenerateArgs),
    /// Handoff line/landing node pair plus a matching Xray client, written as
    /// line.json, landing.json (or landing-N.json per landing with repeated
    /// --landing-address), and xray-client.json.
    Handoff(HandoffGenerateArgs),
}

#[derive(Debug, Args)]
struct HandoffGenerateArgs {
    #[command(flatten)]
    public: PublicGenerateArgs,
    /// Public address of the line node that clients dial.
    #[arg(long, value_name = "HOST")]
    server_address: String,
    /// Internal Handoff landing-node address reachable by the line node.
    /// Repeat for a multi-landing deployment: each landing gets its own UUID
    /// group (landing-N) on the line node and independent key material.
    #[arg(long, value_name = "HOST", required = true)]
    landing_address: Vec<String>,
    /// Firewall-restricted Handoff landing-node port. With repeated
    /// --landing-address, either pass one port applied to every landing or
    /// repeat the flag exactly once per address.
    #[arg(long, default_value = "7443", value_parser = clap::value_parser!(u16).range(1..))]
    landing_port: Vec<u16>,
    /// Directory the generated files are written to.
    #[arg(long, value_name = "DIR")]
    output_dir: PathBuf,
}

#[derive(Debug, Args)]
struct LineGenerateArgs {
    #[command(flatten)]
    public: PublicGenerateArgs,
    /// Internal NXR landing-node address.
    #[arg(long, value_name = "HOST")]
    nxr_address: String,
    /// Firewall-restricted NXR landing-node port.
    #[arg(long, default_value_t = 7_443, value_parser = clap::value_parser!(u16).range(1..))]
    nxr_port: u16,
    /// URL-safe unpadded base64 PSK produced by `node-keygen`.
    #[arg(long, value_name = "BASE64")]
    nxr_key: String,
}

#[derive(Debug, Args)]
struct LandingGenerateArgs {
    /// Internal listener address; restrict this port at the firewall.
    #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::UNSPECIFIED))]
    listen: IpAddr,
    /// Firewall-restricted internal NXR listener port.
    #[arg(long, default_value_t = 7_443, value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,
    /// URL-safe unpadded base64 PSK produced by `node-keygen`.
    #[arg(long, value_name = "BASE64")]
    nxr_key: String,
}

#[derive(Debug, Args)]
struct MlDsa65Args {
    /// Optional Xray-compatible 32-byte URL-safe unpadded base64 seed.
    #[arg(long, value_name = "BASE64")]
    seed: Option<String>,
}

#[derive(Debug, Args)]
struct BenchmarkArgs {
    /// Measured milliseconds for each benchmark case.
    #[arg(long, default_value_t = 1_000, value_parser = clap::value_parser!(u64).range(90..=30_000))]
    duration_ms: u64,
    /// Warm-up milliseconds before each case.
    #[arg(long, default_value_t = 250, value_parser = clap::value_parser!(u64).range(1..=10_000))]
    warmup_ms: u64,
}

#[derive(Debug, Args)]
struct ProbeDestinationArgs {
    /// Cover endpoint, including its port.
    #[arg(long, value_name = "HOST:PORT")]
    target: String,
    /// DNS name sent in the ephemeral TLS ClientHello.
    #[arg(long, value_name = "DNS_NAME")]
    server_name: String,
    /// Absolute DNS, connect, write, and ServerHello deadline.
    #[arg(long, default_value_t = 5_000, value_parser = clap::value_parser!(u64).range(1..=60_000))]
    timeout_ms: u64,
}

#[derive(Debug)]
enum CliError {
    Config(ConfigLoadError),
    Generate(GenerateConfigError),
    Key(KeyGenerationError),
    Probe(DestinationProbeError),
    Assets(AssetLoadError),
    Routing(RoutingCompileError),
    Server(ProductionServerError),
    Json(serde_json::Error),
    Io(io::Error),
    InvalidArgument(&'static str),
    Benchmark(BenchmarkError),
    Autotune(AutotuneError),
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(source) => source.fmt(formatter),
            Self::Generate(source) => source.fmt(formatter),
            Self::Key(source) => source.fmt(formatter),
            Self::Probe(source) => source.fmt(formatter),
            Self::Assets(source) => source.fmt(formatter),
            Self::Routing(source) => source.fmt(formatter),
            Self::Server(source) => source.fmt(formatter),
            Self::Json(_) => formatter.write_str("failed to encode JSON output"),
            Self::Io(_) => formatter.write_str("failed to write command output"),
            Self::InvalidArgument(message) => formatter.write_str(message),
            Self::Benchmark(source) => source.fmt(formatter),
            Self::Autotune(source) => source.fmt(formatter),
        }
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(source) => Some(source),
            Self::Generate(source) => Some(source),
            Self::Key(source) => Some(source),
            Self::Probe(source) => Some(source),
            Self::Assets(source) => Some(source),
            Self::Routing(source) => Some(source),
            Self::Server(source) => Some(source),
            Self::Json(source) => Some(source),
            Self::Io(source) => Some(source),
            Self::InvalidArgument(_) => None,
            Self::Benchmark(source) => Some(source),
            Self::Autotune(source) => Some(source),
        }
    }
}

impl From<ConfigLoadError> for CliError {
    fn from(source: ConfigLoadError) -> Self {
        Self::Config(source)
    }
}

impl From<GenerateConfigError> for CliError {
    fn from(source: GenerateConfigError) -> Self {
        Self::Generate(source)
    }
}

impl From<KeyGenerationError> for CliError {
    fn from(source: KeyGenerationError) -> Self {
        Self::Key(source)
    }
}

impl From<DestinationProbeError> for CliError {
    fn from(source: DestinationProbeError) -> Self {
        Self::Probe(source)
    }
}

impl From<AssetLoadError> for CliError {
    fn from(source: AssetLoadError) -> Self {
        Self::Assets(source)
    }
}

impl From<RoutingCompileError> for CliError {
    fn from(source: RoutingCompileError) -> Self {
        Self::Routing(source)
    }
}

impl From<ProductionServerError> for CliError {
    fn from(source: ProductionServerError) -> Self {
        Self::Server(source)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(source: serde_json::Error) -> Self {
        Self::Json(source)
    }
}

impl From<io::Error> for CliError {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

impl From<BenchmarkError> for CliError {
    fn from(source: BenchmarkError) -> Self {
        Self::Benchmark(source)
    }
}

impl From<AutotuneError> for CliError {
    fn from(source: AutotuneError) -> Self {
        Self::Autotune(source)
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Check(arguments) => {
            let (_config, report) = load_config_with_report(&arguments.config)?;
            warn_policy_alias(&report);
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
        Command::SelfTest(arguments) => run_self_test(arguments),
        Command::Benchmark(arguments) => run_benchmark(arguments),
    }
}

fn run_benchmark(arguments: BenchmarkArgs) -> Result<(), CliError> {
    let report = run_benchmarks(BenchmarkOptions {
        duration: Duration::from_millis(arguments.duration_ms),
        warmup: Duration::from_millis(arguments.warmup_ms),
    })?;
    let output = serde_json::to_string_pretty(&report)?;
    write_stdout(format_args!("{output}\n"))
}

fn run_server(arguments: ConfigPath) -> Result<(), CliError> {
    let server = ProductionServer::from_path(&arguments.config)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(server.run());
    runtime.shutdown_timeout(Duration::from_secs(5));
    result?;
    Ok(())
}

fn run_self_test(arguments: ConfigPath) -> Result<(), CliError> {
    let (config, report) = load_config_with_report(&arguments.config)?;
    warn_policy_alias(&report);
    let assets = Arc::new(AssetSnapshot::load(&config)?);
    let summary = assets.summary();
    RoutingTable::compile(
        &config.routing,
        assets,
        rust_reality::runtime::ResourceGovernor::new(&config.advanced.limits.resource_governor),
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let probe_timeout =
        Duration::from_millis(config.advanced.limits.resource_governor.connect_timeout_ms);
    let reality_destinations = runtime.block_on(async {
        let mut reports = Vec::new();
        let network_environment = rust_reality::network::NetworkEnvironment::detect();
        for inbound in &config.inbounds {
            let Some(inbound) = inbound.as_vless() else {
                continue;
            };
            for server_name in &inbound.stream_settings.reality_settings.server_names {
                reports.push(
                    rust_reality::server::probe::probe_destination_pattern_with_network(
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

fn run_probe_destination(arguments: ProbeDestinationArgs) -> Result<(), CliError> {
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

fn run_config(command: ConfigCommand) -> Result<(), CliError> {
    match command {
        ConfigCommand::Generate { role } => run_config_generate(role),
        ConfigCommand::Autotune(arguments) => run_config_autotune(arguments),
        ConfigCommand::Format(arguments) => {
            let (config, report) = load_config_with_report(arguments.config)?;
            warn_policy_alias(&report);
            write_stdout(format_config(&config)?)
        }
    }
}

fn run_config_autotune(arguments: AutotuneArgs) -> Result<(), CliError> {
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
    let (source, report) = load_config_with_report(&arguments.config)?;
    warn_policy_alias(&report);
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

/// Writes one complete owner-only file through a same-directory temporary and
/// rename, so readers observe either the previous generation or the new one.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let directory = directory.unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or(CliError::InvalidArgument("output path must name a file"))?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let temporary = directory.join(format!(
        ".{}.{}.{timestamp}.tmp",
        name.to_string_lossy(),
        std::process::id()
    ));
    let mut pending = PendingFile::create(&temporary)?;
    pending.file.write_all(bytes)?;
    pending.file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    pending.committed = true;
    File::open(directory)?.sync_all()?;
    Ok(())
}

struct PendingFile {
    file: File,
    path: PathBuf,
    committed: bool,
}

impl PendingFile {
    fn create(path: &Path) -> Result<Self, CliError> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        Ok(Self {
            file,
            path: path.to_owned(),
            committed: false,
        })
    }
}

impl Drop for PendingFile {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn run_config_generate(role: GenerateRole) -> Result<(), CliError> {
    match role {
        GenerateRole::Standalone(arguments) => {
            let generated = generate_minimal_config(public_generation_input(arguments))?;
            write_public_config(&generated)
        }
        GenerateRole::Line(arguments) => {
            let generated = generate_line_config(GenerateLineConfigInput {
                public: public_generation_input(arguments.public),
                nxr_address: arguments.nxr_address,
                nxr_port: arguments.nxr_port,
                pre_shared_key: SecretString::new(arguments.nxr_key),
            })?;
            write_public_config(&generated)
        }
        GenerateRole::Landing(arguments) => {
            let config = generate_landing_config(GenerateLandingConfigInput {
                listen: arguments.listen,
                port: arguments.port,
                pre_shared_key: SecretString::new(arguments.nxr_key),
            })?;
            write_stdout(format_config(&config)?)
        }
        GenerateRole::Handoff(arguments) => {
            let output_dir = arguments.output_dir.clone();
            let landings =
                resolve_handoff_landings(&arguments.landing_address, &arguments.landing_port)?;
            if let [landing] = landings.as_slice() {
                let generated = generate_handoff_configs(GenerateHandoffConfigInput {
                    public: public_generation_input(arguments.public),
                    server_address: arguments.server_address,
                    landing_address: landing.address.clone(),
                    landing_port: landing.port,
                })?;
                write_handoff_configs(&output_dir, &generated)
            } else {
                let generated = generate_multi_handoff_configs(GenerateMultiHandoffConfigInput {
                    public: public_generation_input(arguments.public),
                    server_address: arguments.server_address,
                    landings,
                })?;
                write_multi_handoff_configs(&output_dir, &generated)
            }
        }
    }
}

/// Zips repeated `--landing-address`/`--landing-port` values into one entry
/// per landing: a single port applies to every landing, otherwise the flag
/// counts must match exactly.
fn resolve_handoff_landings(
    addresses: &[String],
    ports: &[u16],
) -> Result<Vec<HandoffLandingInput>, CliError> {
    let ports: Vec<u16> = match ports {
        [port] => vec![*port; addresses.len()],
        _ if ports.len() == addresses.len() => ports.to_vec(),
        _ => {
            return Err(CliError::InvalidArgument(
                "--landing-port must appear at most once, or exactly once per --landing-address",
            ));
        }
    };
    Ok(addresses
        .iter()
        .cloned()
        .zip(ports)
        .map(|(address, port)| HandoffLandingInput { address, port })
        .collect())
}

fn public_generation_input(arguments: PublicGenerateArgs) -> GenerateConfigInput {
    GenerateConfigInput {
        listen: arguments.listen,
        port: arguments.port,
        target: arguments.target,
        server_name: arguments.server_name,
    }
}

fn write_public_config(generated: &rust_reality::config::GeneratedConfig) -> Result<(), CliError> {
    let public_key = generated.reality_public_key();
    write_stdout(format_config(generated.config())?)?;
    writeln!(
        io::stderr().lock(),
        "REALITY public key for the client: {public_key}"
    )?;
    Ok(())
}

/// Writes the Handoff deployment as `line.json`, `landing.json`, and
/// `xray-client.json` inside `output_dir`.
///
/// The client-facing public values go to stderr, mirroring the other
/// generators; the Handoff PSK and the private keys exist only in the two
/// server files. stdout lists the written paths.
fn write_handoff_configs(
    output_dir: &Path,
    generated: &GeneratedHandoffConfigs,
) -> Result<(), CliError> {
    std::fs::create_dir_all(output_dir)?;
    let line = output_dir.join("line.json");
    let landing = output_dir.join("landing.json");
    let client = output_dir.join("xray-client.json");
    std::fs::write(&line, format_config(generated.line().config())?)?;
    std::fs::write(&landing, format_config(generated.landing())?)?;
    let mut client_json = serde_json::to_string_pretty(generated.client())?;
    client_json.push('\n');
    std::fs::write(&client, client_json)?;
    let public_key = generated.line().reality_public_key();
    let uuid = generated.client_uuid();
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "REALITY public key for the client: {public_key}")?;
    writeln!(stderr, "UUID for the client: {uuid}")?;
    write_stdout(format_args!(
        "{}\n{}\n{}\n",
        line.display(),
        landing.display(),
        client.display()
    ))
}

/// Writes a multi-landing Handoff deployment as `line.json`, one
/// `landing-N.json` per landing, and `xray-client.json` inside `output_dir`.
///
/// Mirrors `write_handoff_configs`; the client file keeps its single-UUID
/// shape and references the first landing's UUID — assigning the other
/// generated UUIDs to clients is an operator choice, noted on stderr.
fn write_multi_handoff_configs(
    output_dir: &Path,
    generated: &GeneratedMultiHandoffConfigs,
) -> Result<(), CliError> {
    std::fs::create_dir_all(output_dir)?;
    let line = output_dir.join("line.json");
    std::fs::write(&line, format_config(generated.line().config())?)?;
    let mut paths = vec![line.display().to_string()];
    for (index, landing) in generated.landings().iter().enumerate() {
        let path = output_dir.join(format!("landing-{}.json", index + 1));
        std::fs::write(&path, format_config(landing)?)?;
        paths.push(path.display().to_string());
    }
    let client = output_dir.join("xray-client.json");
    let mut client_json = serde_json::to_string_pretty(generated.client())?;
    client_json.push('\n');
    std::fs::write(&client, client_json)?;
    paths.push(client.display().to_string());
    let public_key = generated.line().reality_public_key();
    let uuid = generated.client_uuid();
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "REALITY public key for the client: {public_key}")?;
    writeln!(stderr, "UUID for the client: {uuid}")?;
    writeln!(
        stderr,
        "line.json routes one UUID group per landing (landing-1 .. landing-{}); \
         xray-client.json uses the first UUID — using further UUIDs in a client is an operator choice.",
        generated.landings().len()
    )?;
    write_stdout(format_args!("{}\n", paths.join("\n")))
}

fn run_mldsa65(arguments: MlDsa65Args) -> Result<(), CliError> {
    let pair = if let Some(seed) = arguments.seed {
        let decoded = Zeroizing::new(
            BASE64_URL_SAFE_NO_PAD
                .decode(seed)
                .map_err(|_| CliError::InvalidArgument("ML-DSA-65 seed must be valid base64"))?,
        );
        let seed: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
            CliError::InvalidArgument("ML-DSA-65 seed must contain exactly 32 bytes")
        })?;
        generate_mldsa65_key_pair_from_seed(seed)
    } else {
        generate_mldsa65_key_pair()?
    };
    let output = serde_json::to_string_pretty(&json!({
        "seed": pair.seed(),
        "verify": pair.verification_key(),
    }))?;
    write_stdout(format_args!("{output}\n"))
}

fn write_stdout(output: impl fmt::Display) -> Result<(), CliError> {
    write!(io::stdout().lock(), "{output}").map_err(CliError::Io)
}

/// Reports a rewritten deprecated alias exactly once per load, never silently.
fn warn_policy_alias(report: &ConfigLoadReport) {
    if report.policy_alias_used {
        let _ = writeln!(
            io::stderr().lock(),
            "warning: top-level \"policy\" is deprecated; its values were merged into \
             \"advanced.limits\" and \"runtime.tuning.mode\" was forced to \"fixed\" unless \
             explicitly set"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use clap::Parser;

    use super::{Cli, Command, ConfigCommand, GenerateRole, write_atomic};

    #[test]
    fn atomic_output_is_complete_owner_only_and_replaceable() {
        let directory = std::env::temp_dir().join(format!(
            "rust-reality-atomic-output-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir(&directory).expect("unique temporary directory must be created");
        let output = directory.join("config.json");

        write_atomic(&output, b"first\n").expect("first atomic write must succeed");
        assert_eq!(
            std::fs::read(&output).expect("output must read"),
            b"first\n"
        );
        assert_eq!(
            std::fs::metadata(&output)
                .expect("metadata must read")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        write_atomic(&output, b"second generation\n")
            .expect("replacement atomic write must succeed");
        assert_eq!(
            std::fs::read(&output).expect("replacement must read"),
            b"second generation\n"
        );
        assert_eq!(
            std::fs::read_dir(&directory)
                .expect("directory must read")
                .count(),
            1,
            "no temporary file may remain"
        );
        std::fs::remove_dir_all(directory).expect("temporary directory must be removed");
    }

    #[test]
    fn parses_bounded_config_autotune() {
        let cli = Cli::try_parse_from([
            "rust-reality",
            "config",
            "autotune",
            "--config",
            "/etc/rust-reality/config.json",
            "--output",
            "/etc/rust-reality/config.tuned.json",
            "--report",
            "/var/lib/rust-reality/autotune.json",
            "--duration-ms",
            "250",
            "--warmup-ms",
            "10",
            "--storage-mib",
            "1",
            "--network-mib",
            "1",
            "--dedicated",
        ])
        .expect("autotune command must parse");

        assert!(matches!(
            cli.command,
            Command::Config {
                command: ConfigCommand::Autotune(_)
            }
        ));
        assert!(
            Cli::try_parse_from([
                "rust-reality",
                "config",
                "autotune",
                "--config",
                "input.json",
                "--output",
                "output.json",
                "--storage-mib",
                "0",
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_handoff_generator() {
        let cli = Cli::try_parse_from([
            "rust-reality",
            "config",
            "generate",
            "handoff",
            "--server-address",
            "line.example.com",
            "--target",
            "cover.example.com:443",
            "--server-name",
            "cover.example.com",
            "--landing-address",
            "10.0.0.2",
            "--landing-port",
            "7443",
            "--output-dir",
            "/tmp/generated",
        ])
        .expect("handoff generator must parse");

        assert!(matches!(
            cli.command,
            Command::Config {
                command: ConfigCommand::Generate {
                    role: GenerateRole::Handoff(_)
                }
            }
        ));
    }

    #[test]
    fn handoff_generator_writes_three_valid_files() {
        use std::net::IpAddr;
        use std::str::FromStr as _;

        use rust_reality::config::{
            GenerateConfigInput, GenerateHandoffConfigInput, generate_handoff_configs, load_config,
            validate_config,
        };

        use super::write_handoff_configs;

        let generated = generate_handoff_configs(GenerateHandoffConfigInput {
            public: GenerateConfigInput {
                listen: IpAddr::from_str("0.0.0.0").expect("address must parse"),
                port: 443,
                target: "cover.example.com:443".to_owned(),
                server_name: "cover.example.com".to_owned(),
            },
            server_address: "line.example.com".to_owned(),
            landing_address: "10.0.0.2".to_owned(),
            landing_port: 7_443,
        })
        .expect("handoff generation must succeed");
        let directory = std::env::temp_dir().join(format!(
            "rust-reality-handoff-generate-{}",
            std::process::id()
        ));
        write_handoff_configs(&directory, &generated).expect("the three files must be written");

        for name in ["line.json", "landing.json"] {
            let path = directory.join(name);
            let config = load_config(&path).expect("generated configuration must load");
            validate_config(&config).expect("generated configuration must validate");
        }
        let client: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(directory.join("xray-client.json"))
                .expect("client configuration must read"),
        )
        .expect("client configuration must parse");
        assert_eq!(
            client["outbounds"][0]["settings"]["vnext"][0]["address"],
            "line.example.com"
        );
        assert_eq!(client["outbounds"][0]["settings"]["vnext"][0]["port"], 443);
        assert_eq!(
            client["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"].as_str(),
            Some(generated.client_uuid())
        );
        assert_eq!(
            client["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"].as_str(),
            Some(generated.line().reality_public_key())
        );
        std::fs::remove_dir_all(&directory).expect("temporary directory must be removed");
    }

    #[test]
    fn parses_multi_landing_handoff_generator() {
        let cli = Cli::try_parse_from([
            "rust-reality",
            "config",
            "generate",
            "handoff",
            "--server-address",
            "line.example.com",
            "--target",
            "cover.example.com:443",
            "--server-name",
            "cover.example.com",
            "--landing-address",
            "10.0.0.2",
            "--landing-port",
            "7443",
            "--landing-address",
            "10.0.0.3",
            "--landing-port",
            "8443",
            "--output-dir",
            "/tmp/generated",
        ])
        .expect("multi-landing handoff generator must parse");

        let Command::Config {
            command:
                ConfigCommand::Generate {
                    role: GenerateRole::Handoff(arguments),
                },
        } = cli.command
        else {
            panic!("command must be the handoff generator");
        };
        assert_eq!(arguments.landing_address, ["10.0.0.2", "10.0.0.3"]);
        assert_eq!(arguments.landing_port, [7_443, 8_443]);
    }

    #[test]
    fn resolves_repeated_landing_ports() {
        use super::resolve_handoff_landings;

        let addresses = vec!["10.0.0.2".to_owned(), "10.0.0.3".to_owned()];
        let broadcast = resolve_handoff_landings(&addresses, &[7_443])
            .expect("a single port must apply to every landing");
        assert_eq!(
            broadcast
                .iter()
                .map(|landing| landing.port)
                .collect::<Vec<_>>(),
            [7_443, 7_443]
        );
        let zipped = resolve_handoff_landings(&addresses, &[7_443, 8_443])
            .expect("equal counts must zip in order");
        assert_eq!(
            zipped
                .iter()
                .map(|landing| landing.port)
                .collect::<Vec<_>>(),
            [7_443, 8_443]
        );
        assert_eq!(zipped[0].address, "10.0.0.2");
        assert_eq!(zipped[1].address, "10.0.0.3");
        assert!(resolve_handoff_landings(&addresses, &[7_443, 8_443, 9_443]).is_err());
        assert!(resolve_handoff_landings(&addresses[..1], &[7_443, 8_443]).is_err());
    }

    #[test]
    fn multi_handoff_generator_writes_valid_files() {
        use std::net::IpAddr;
        use std::str::FromStr as _;

        use rust_reality::config::{
            GenerateConfigInput, GenerateMultiHandoffConfigInput, HandoffLandingInput,
            generate_multi_handoff_configs, load_config, validate_config,
        };

        use super::write_multi_handoff_configs;

        let generated = generate_multi_handoff_configs(GenerateMultiHandoffConfigInput {
            public: GenerateConfigInput {
                listen: IpAddr::from_str("0.0.0.0").expect("address must parse"),
                port: 443,
                target: "cover.example.com:443".to_owned(),
                server_name: "cover.example.com".to_owned(),
            },
            server_address: "line.example.com".to_owned(),
            landings: vec![
                HandoffLandingInput {
                    address: "10.0.0.2".to_owned(),
                    port: 7_443,
                },
                HandoffLandingInput {
                    address: "10.0.0.3".to_owned(),
                    port: 7_443,
                },
            ],
        })
        .expect("multi-landing generation must succeed");
        let directory = std::env::temp_dir().join(format!(
            "rust-reality-multi-handoff-generate-{}",
            std::process::id()
        ));
        write_multi_handoff_configs(&directory, &generated)
            .expect("the multi-landing files must be written");

        for name in ["line.json", "landing-1.json", "landing-2.json"] {
            let path = directory.join(name);
            let config = load_config(&path).expect("generated configuration must load");
            validate_config(&config).expect("generated configuration must validate");
        }
        assert!(
            !directory.join("landing.json").exists(),
            "multi-landing output must use numbered landing files only"
        );
        let client: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(directory.join("xray-client.json"))
                .expect("client configuration must read"),
        )
        .expect("client configuration must parse");
        assert_eq!(
            client["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"].as_str(),
            Some(generated.client_uuid())
        );
        std::fs::remove_dir_all(&directory).expect("temporary directory must be removed");
    }

    #[test]
    fn parses_nested_generate_command() {
        let cli = Cli::try_parse_from([
            "rust-reality",
            "config",
            "generate",
            "standalone",
            "--target",
            "www.example.com:443",
            "--server-name",
            "www.example.com",
        ])
        .expect("command must parse");

        assert!(matches!(
            cli.command,
            Command::Config {
                command: ConfigCommand::Generate {
                    role: GenerateRole::Standalone(_)
                }
            }
        ));
    }

    #[test]
    fn parses_explicit_line_and_landing_generators() {
        let line = Cli::try_parse_from([
            "rust-reality",
            "config",
            "generate",
            "line",
            "--target",
            "www.example.com:443",
            "--server-name",
            "www.example.com",
            "--nxr-address",
            "10.0.0.2",
            "--nxr-key",
            "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
        ])
        .expect("line generator must parse");
        let landing = Cli::try_parse_from([
            "rust-reality",
            "config",
            "generate",
            "landing",
            "--nxr-key",
            "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
        ])
        .expect("landing generator must parse");

        assert!(matches!(
            line.command,
            Command::Config {
                command: ConfigCommand::Generate {
                    role: GenerateRole::Line(_)
                }
            }
        ));
        assert!(matches!(
            landing.command,
            Command::Config {
                command: ConfigCommand::Generate {
                    role: GenerateRole::Landing(_)
                }
            }
        ));
    }

    #[test]
    fn rejects_zero_uuid_count() {
        assert!(Cli::try_parse_from(["rust-reality", "uuid", "0"]).is_err());
    }

    #[test]
    fn parses_bounded_destination_probe() {
        let cli = Cli::try_parse_from([
            "rust-reality",
            "probe-dest",
            "--target",
            "www.example.com:443",
            "--server-name",
            "www.example.com",
            "--timeout-ms",
            "2500",
        ])
        .expect("destination probe must parse");

        assert!(matches!(cli.command, Command::ProbeDest(_)));
        assert!(
            Cli::try_parse_from([
                "rust-reality",
                "probe-dest",
                "--target",
                "www.example.com:443",
                "--server-name",
                "www.example.com",
                "--timeout-ms",
                "0",
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_self_test_config_path() {
        let cli = Cli::try_parse_from([
            "rust-reality",
            "self-test",
            "--config",
            "/etc/rust-reality/config.json",
        ])
        .expect("self-test command must parse");

        assert!(matches!(cli.command, Command::SelfTest(_)));
    }

    #[test]
    fn parses_serve_and_run_config_paths() {
        for command in ["serve", "run"] {
            let cli = Cli::try_parse_from([
                "rust-reality",
                command,
                "--config",
                "/etc/rust-reality/config.json",
            ])
            .expect("server command must parse");
            assert!(matches!(cli.command, Command::Serve(_) | Command::Run(_)));
        }
    }

    #[test]
    fn bounds_builtin_benchmark_duration() {
        assert!(
            Cli::try_parse_from([
                "rust-reality",
                "benchmark",
                "--duration-ms",
                "90",
                "--warmup-ms",
                "1",
            ])
            .is_ok()
        );
        assert!(Cli::try_parse_from(["rust-reality", "benchmark", "--duration-ms", "89"]).is_err());
    }
}
