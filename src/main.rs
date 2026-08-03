use std::{
    error::Error,
    fmt,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use clap::{Args, Parser, Subcommand};
use rust_reality::{
    assets::{AssetLoadError, AssetSnapshot},
    benchmark::{BenchmarkError, BenchmarkOptions, run_benchmarks},
    config::{
        ConfigLoadError, GenerateConfigError, GenerateConfigInput, GenerateLandingConfigInput,
        GenerateLineConfigInput, SecretString, format_config, format_config_schema,
        generate_landing_config, generate_line_config, generate_minimal_config, load_config,
    },
    crypto::{
        KeyGenerationError, generate_mldsa65_key_pair, generate_mldsa65_key_pair_from_seed,
        generate_node_key, generate_uuid, generate_x25519_key_pair,
    },
    server::{
        probe::{DestinationProbeError, probe_destination, probe_destination_pattern},
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
    /// Validate and print a canonical pretty JSON configuration.
    Format(ConfigPath),
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
            load_config(&arguments.config)?;
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
    let config = load_config(&arguments.config)?;
    let assets = Arc::new(AssetSnapshot::load(&config)?);
    let summary = assets.summary();
    RoutingTable::compile(&config.routing, assets)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let probe_timeout = Duration::from_millis(config.policy.resource_governor.connect_timeout_ms);
    let reality_destinations = runtime.block_on(async {
        let mut reports = Vec::new();
        for inbound in &config.inbounds {
            let Some(inbound) = inbound.as_vless() else {
                continue;
            };
            for server_name in &inbound.stream_settings.reality_settings.server_names {
                reports.push(
                    probe_destination_pattern(
                        &inbound.stream_settings.reality_settings.target,
                        server_name,
                        probe_timeout,
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
        ConfigCommand::Format(arguments) => {
            let config = load_config(arguments.config)?;
            write_stdout(format_config(&config)?)
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
    }
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Command, ConfigCommand, GenerateRole};

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
