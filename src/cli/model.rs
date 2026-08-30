// CLI surface model: argument types, the command tree, and the error type.
//
// This module owns WHAT the command line looks like. `commands` owns what the
// commands DO; `generate` owns configuration generation; `atomic` owns the
// crash-safe output writer.

use std::{
    error::Error,
    fmt, io,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

use clap::{Args, Parser, Subcommand};

use crate::{
    assets::AssetLoadError,
    autotune::AutotuneError,
    benchmark::BenchmarkError,
    config::{ConfigLoadError, GenerateConfigError},
    crypto::KeyGenerationError,
    server::{
        probe::DestinationProbeError, production::ProductionServerError,
        routing::RoutingCompileError,
    },
};

#[derive(Debug, Parser)]
#[command(
    name = "rust-reality",
    version,
    about = "Linux-focused VLESS + REALITY + Vision proxy"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
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
    /// Inspect the runtime resource plan without starting the server.
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommand,
    },
    /// Validate configuration, download/revalidate assets, and compile routing.
    SelfTest(ConfigPath),
    /// Quantify bounded protocol hot paths and print a machine-readable report.
    Benchmark(BenchmarkArgs),
}

#[derive(Debug, Subcommand)]
pub enum RuntimeCommand {
    /// Explain the detected machine, resolved profile, bootstrap sizing, and
    /// the effective numeric policy, field by field. Fully offline.
    Explain(RuntimeExplainArgs),
    /// Print the last adaptive-controller snapshot a running instance
    /// published to its status file.
    Report(RuntimeReportArgs),
}

#[derive(Debug, Args)]
pub struct RuntimeExplainArgs {
    /// JSON configuration path.
    #[arg(short, long, value_name = "PATH")]
    pub config: PathBuf,
    /// Print the machine-readable JSON report instead of the human summary.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RuntimeReportArgs {
    /// Status-file path the running instance publishes
    /// (`runtime.statusFile`); consulted only in `adaptive` tuning mode.
    #[arg(long, value_name = "PATH")]
    pub status_file: PathBuf,
    /// Print the machine-readable JSON snapshot instead of the human summary.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
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
pub struct AutotuneArgs {
    /// Existing valid configuration whose routing and secrets are preserved.
    #[arg(short, long, value_name = "PATH")]
    pub config: PathBuf,
    /// New tuned configuration path.
    #[arg(short, long, value_name = "PATH")]
    pub output: PathBuf,
    /// Measurement report path; defaults to OUTPUT.report.json.
    #[arg(long, value_name = "PATH")]
    pub report: Option<PathBuf>,
    /// Measured milliseconds for each protocol hot-path case.
    #[arg(long, default_value_t = 900, value_parser = clap::value_parser!(u64).range(90..=30_000))]
    pub duration_ms: u64,
    /// Warm-up milliseconds before each protocol case.
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u64).range(1..=10_000))]
    pub warmup_ms: u64,
    /// MiB written/read in the bounded temporary storage probe.
    #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u16).range(1..=256))]
    pub storage_mib: u16,
    /// MiB transferred in each direction through TCP loopback.
    #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u16).range(1..=256))]
    pub network_mib: u16,
    /// Storage-probe directory; defaults to the operating-system temp directory.
    #[arg(long, value_name = "DIR")]
    pub scratch_directory: Option<PathBuf>,
    /// Declare this process the exclusive owner of the host or cgroup.
    #[arg(long)]
    pub dedicated: bool,
}

#[derive(Debug, Args)]
pub struct ConfigPath {
    /// JSON configuration path.
    #[arg(short, long, value_name = "PATH")]
    pub config: PathBuf,
}

#[derive(Debug, Args)]
pub struct PublicGenerateArgs {
    /// Public listener address.
    #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::UNSPECIFIED))]
    pub listen: IpAddr,
    /// Public listener port.
    #[arg(long, default_value_t = 443, value_parser = clap::value_parser!(u16).range(1..))]
    pub port: u16,
    /// REALITY cover endpoint, including its port.
    #[arg(long, value_name = "HOST:PORT")]
    pub target: String,
    /// Client-facing REALITY SNI.
    #[arg(long, value_name = "DNS_NAME")]
    pub server_name: String,
}

#[derive(Debug, Subcommand)]
pub enum GenerateRole {
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
pub struct HandoffGenerateArgs {
    #[command(flatten)]
    pub public: PublicGenerateArgs,
    /// Public address of the line node that clients dial.
    #[arg(long, value_name = "HOST")]
    pub server_address: String,
    /// Internal Handoff landing-node address reachable by the line node.
    /// Repeat for a multi-landing deployment: each landing gets its own UUID
    /// group (landing-N) on the line node and independent key material.
    #[arg(long, value_name = "HOST", required = true)]
    pub landing_address: Vec<String>,
    /// Firewall-restricted Handoff landing-node port. With repeated
    /// --landing-address, either pass one port applied to every landing or
    /// repeat the flag exactly once per address.
    #[arg(long, default_value = "7443", value_parser = clap::value_parser!(u16).range(1..))]
    pub landing_port: Vec<u16>,
    /// Directory the generated files are written to.
    #[arg(long, value_name = "DIR")]
    pub output_dir: PathBuf,
}

#[derive(Debug, Args)]
pub struct LineGenerateArgs {
    #[command(flatten)]
    pub public: PublicGenerateArgs,
    /// Internal NXR landing-node address.
    #[arg(long, value_name = "HOST")]
    pub nxr_address: String,
    /// Firewall-restricted NXR landing-node port.
    #[arg(long, default_value_t = 7_443, value_parser = clap::value_parser!(u16).range(1..))]
    pub nxr_port: u16,
    /// URL-safe unpadded base64 PSK produced by `node-keygen`.
    #[arg(long, value_name = "BASE64")]
    pub nxr_key: String,
}

#[derive(Debug, Args)]
pub struct LandingGenerateArgs {
    /// Internal listener address; restrict this port at the firewall.
    #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::UNSPECIFIED))]
    pub listen: IpAddr,
    /// Firewall-restricted internal NXR listener port.
    #[arg(long, default_value_t = 7_443, value_parser = clap::value_parser!(u16).range(1..))]
    pub port: u16,
    /// URL-safe unpadded base64 PSK produced by `node-keygen`.
    #[arg(long, value_name = "BASE64")]
    pub nxr_key: String,
}

#[derive(Debug, Args)]
pub struct MlDsa65Args {
    /// Optional Xray-compatible 32-byte URL-safe unpadded base64 seed.
    #[arg(long, value_name = "BASE64")]
    pub seed: Option<String>,
}

#[derive(Debug, Args)]
pub struct BenchmarkArgs {
    /// Measured milliseconds for each benchmark case.
    #[arg(long, default_value_t = 1_000, value_parser = clap::value_parser!(u64).range(90..=30_000))]
    pub duration_ms: u64,
    /// Warm-up milliseconds before each case.
    #[arg(long, default_value_t = 250, value_parser = clap::value_parser!(u64).range(1..=10_000))]
    pub warmup_ms: u64,
}

#[derive(Debug, Args)]
pub struct ProbeDestinationArgs {
    /// Cover endpoint, including its port.
    #[arg(long, value_name = "HOST:PORT")]
    pub target: String,
    /// DNS name sent in the ephemeral TLS ClientHello.
    #[arg(long, value_name = "DNS_NAME")]
    pub server_name: String,
    /// Absolute DNS, connect, write, and ServerHello deadline.
    #[arg(long, default_value_t = 5_000, value_parser = clap::value_parser!(u64).range(1..=60_000))]
    pub timeout_ms: u64,
}

#[derive(Debug)]
pub enum CliError {
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
    StatusReport(crate::runtime::adaptive::StatusReadError),
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
            Self::StatusReport(source) => source.fmt(formatter),
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
            Self::StatusReport(source) => Some(source),
        }
    }
}

impl From<crate::runtime::adaptive::StatusReadError> for CliError {
    fn from(source: crate::runtime::adaptive::StatusReadError) -> Self {
        Self::StatusReport(source)
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Command;
    use crate::cli::model::{Cli, ConfigCommand, GenerateRole};

    #[test]
    fn parses_runtime_explain() {
        let cli = Cli::try_parse_from([
            "rust-reality",
            "runtime",
            "explain",
            "--config",
            "/etc/rust-reality/config.json",
            "--json",
        ])
        .expect("runtime explain must parse");

        assert!(matches!(
            cli.command,
            Command::Runtime {
                command: super::RuntimeCommand::Explain(_)
            }
        ));
        assert!(
            Cli::try_parse_from(["rust-reality", "runtime", "explain"]).is_err(),
            "the configuration path is required"
        );
    }

    #[test]
    fn parses_runtime_report() {
        let cli = Cli::try_parse_from([
            "rust-reality",
            "runtime",
            "report",
            "--status-file",
            "/run/rust-reality/status.json",
            "--json",
        ])
        .expect("runtime report must parse");

        assert!(matches!(
            cli.command,
            Command::Runtime {
                command: super::RuntimeCommand::Report(_)
            }
        ));
        assert!(
            Cli::try_parse_from(["rust-reality", "runtime", "report"]).is_err(),
            "the status-file path is required"
        );
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

        use crate::config::{
            GenerateConfigInput, GenerateHandoffConfigInput, generate_handoff_configs, load_config,
            validate_config,
        };

        use crate::cli::generate::write_handoff_configs;

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
        use crate::cli::generate::resolve_handoff_landings;

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

        use crate::config::{
            GenerateConfigInput, GenerateMultiHandoffConfigInput, HandoffLandingInput,
            generate_multi_handoff_configs, load_config, validate_config,
        };

        use crate::cli::generate::write_multi_handoff_configs;

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
