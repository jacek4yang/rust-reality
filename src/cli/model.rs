// CLI surface model: argument types, the command tree, and the error type.
//
// This module owns WHAT the command line looks like; `commands` owns what the
// commands DO and `atomic` owns the crash-safe output writer.
//
// Every top-level command is a job an operator intentionally does. A command
// does not exist because an internal subsystem can expose one: benchmark
// suites, profiling, repository checks, and documentation verification live in
// `cargo dev`, because the deployed daemon is not the project's engineering
// toolbox.

use std::{error::Error, fmt, io, path::PathBuf, sync::OnceLock};

use clap::{Args, Parser, Subcommand};

use crate::{
    assets::AssetLoadError,
    config::LoadError,
    crypto::EntropyError,
    server::{
        probe::DestinationProbeError, production::ProductionServerError,
        routing::RoutingCompileError,
    },
};

/// The `--version` body: the release version, then the source commit.
///
/// The first line stays exactly `rust-reality <version>`, which is the release
/// contract asserted by the musl CI check, the release workflow and the release
/// smoke test. The commit follows on its own line so an operator reporting a
/// problem, and the measurement harness attributing a benchmark, can both name
/// the exact source a binary was built from.
fn long_version() -> &'static str {
    static LONG_VERSION: OnceLock<String> = OnceLock::new();
    LONG_VERSION
        .get_or_init(|| {
            format!(
                "{}\ncommit: {}",
                env!("CARGO_PKG_VERSION"),
                crate::BUILD_COMMIT
            )
        })
        .as_str()
}

#[derive(Debug, Parser)]
#[command(
    name = "rust-reality",
    version,
    long_version = long_version(),
    about = "Linux-focused VLESS + REALITY + Vision proxy"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Serve traffic until SIGINT or SIGTERM.
    Run(ConfigPath),
    /// Check that a configuration is internally valid. Never touches the
    /// network, binds a port, or downloads anything.
    Check(ConfigPath),
    /// Check that a configuration will work on this machine and network.
    Doctor(ConfigPath),
    /// Report what a configuration resolves to here: chosen defaults, derived
    /// limits, detected machine, and the listeners that would be bound.
    Explain(ExplainArgs),
    /// Rewrite a configuration in the canonical, validated form.
    Format(FormatArgs),
    /// Check whether a host is usable as a REALITY cover target.
    CheckCover(CheckCoverArgs),
    /// Generate cryptographic and identity material.
    Generate {
        #[command(subcommand)]
        command: GenerateCommand,
    },
}

/// Material an operator should not invent by hand.
///
/// Each subcommand emits exactly what was asked for and nothing else. There is
/// deliberately no command that assembles a whole configuration: the operator
/// composes the JSON, so they understand what they deploy.
#[derive(Debug, Subcommand)]
pub enum GenerateCommand {
    /// Generate RFC 4122 version 4 UUIDs, for `users[].id`.
    Uuid {
        /// How many to generate.
        #[arg(default_value_t = 1, value_parser = clap::value_parser!(u16).range(1..=1024))]
        count: u16,
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Generate an X25519 key pair, for `reality.privateKey` or a Handoff
    /// landing's `landing.privateKey`. Generate one pair per purpose.
    X25519 {
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Generate REALITY short IDs, for `users[].shortIds`.
    ShortId {
        /// How many to generate.
        #[arg(default_value_t = 1, value_parser = clap::value_parser!(u16).range(1..=1024))]
        count: u16,
        /// Length in bytes; the value is written as twice this many hex
        /// characters.
        #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u8).range(1..=8))]
        bytes: u8,
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Generate a 32-byte pre-shared key, for an NXR or Handoff `psk`.
    /// Generate one per landing.
    Psk {
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Args)]
pub struct ConfigPath {
    /// Configuration path.
    #[arg(short, long, value_name = "PATH")]
    pub config: PathBuf,
}

#[derive(Debug, Args)]
pub struct ExplainArgs {
    /// Configuration path.
    #[arg(short, long, value_name = "PATH")]
    pub config: PathBuf,
    /// Print the machine-readable JSON report instead of the human summary.
    #[arg(long)]
    pub json: bool,
    /// Answer which outbound one destination would take, instead of reporting
    /// the whole configuration. Accepts `host` or `host:port`.
    #[arg(long, value_name = "HOST")]
    pub route: Option<String>,
}

#[derive(Debug, Args)]
pub struct FormatArgs {
    /// Configuration path.
    #[arg(short, long, value_name = "PATH")]
    pub config: PathBuf,
    /// Rewrite the file in place instead of printing to standard output.
    #[arg(long)]
    pub write: bool,
}

#[derive(Debug, Args)]
pub struct CheckCoverArgs {
    /// Candidate cover endpoint, including its port.
    #[arg(long, value_name = "HOST:PORT")]
    pub cover: String,
    /// Name to send in the ephemeral TLS ClientHello. Defaults to the cover
    /// host, which is what an omitted `reality.serverNames` accepts.
    #[arg(long, value_name = "DNS_NAME")]
    pub server_name: Option<String>,
    /// Absolute DNS, connect, write, and ServerHello deadline.
    #[arg(long, default_value_t = 5_000, value_parser = clap::value_parser!(u64).range(1..=60_000))]
    pub timeout_ms: u64,
}

#[derive(Debug)]
pub enum CliError {
    Config(LoadError),
    Key(EntropyError),
    Probe(DestinationProbeError),
    Assets(AssetLoadError),
    Routing(RoutingCompileError),
    Route(crate::explain::RouteQueryError),
    Server(ProductionServerError),
    Json(serde_json::Error),
    Io(io::Error),
    InvalidArgument(&'static str),
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(source) => source.fmt(formatter),
            Self::Key(source) => source.fmt(formatter),
            Self::Probe(source) => source.fmt(formatter),
            Self::Assets(source) => source.fmt(formatter),
            Self::Routing(source) => source.fmt(formatter),
            Self::Route(source) => source.fmt(formatter),
            Self::Server(source) => source.fmt(formatter),
            Self::Json(_) => formatter.write_str("failed to encode JSON output"),
            Self::Io(_) => formatter.write_str("failed to write command output"),
            Self::InvalidArgument(message) => formatter.write_str(message),
        }
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(source) => Some(source),
            Self::Key(source) => Some(source),
            Self::Probe(source) => Some(source),
            Self::Assets(source) => Some(source),
            Self::Routing(source) => Some(source),
            Self::Route(source) => Some(source),
            Self::Server(source) => Some(source),
            Self::Json(source) => Some(source),
            Self::Io(source) => Some(source),
            Self::InvalidArgument(_) => None,
        }
    }
}

impl From<LoadError> for CliError {
    fn from(source: LoadError) -> Self {
        Self::Config(source)
    }
}

impl From<EntropyError> for CliError {
    fn from(source: EntropyError) -> Self {
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

impl From<crate::explain::RouteQueryError> for CliError {
    fn from(source: crate::explain::RouteQueryError) -> Self {
        Self::Route(source)
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

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::{Cli, Command, GenerateCommand};

    fn parse(arguments: &[&str]) -> Cli {
        Cli::try_parse_from(arguments).unwrap_or_else(|error| panic!("must parse: {error}"))
    }

    #[test]
    fn long_version_states_the_release_line_then_the_source_commit() {
        // Three release checks match a whole line against `rust-reality
        // <version>` — the musl CI check, the release workflow, and the release
        // smoke test — so the first line is a contract, not a preference.
        let rendered = format!("rust-reality {}", super::long_version());
        let mut lines = rendered.lines();
        assert_eq!(
            lines.next().unwrap(),
            concat!("rust-reality ", env!("CARGO_PKG_VERSION"))
        );

        // The second line is what the measurement harness reads to attribute a
        // benchmark to an exact source commit; `tools/rr-dev/src/bench/
        // identity.rs` parses precisely this shape.
        let commit = lines.next().unwrap().strip_prefix("commit: ").unwrap();
        assert_eq!(commit, crate::BUILD_COMMIT);
        assert!(lines.next().is_none(), "no third line: {rendered:?}");

        // An unstamped build says so rather than guessing a commit.
        assert!(
            commit == "unknown"
                || (commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit())),
            "commit must be `unknown` or 40 hex characters: {commit:?}"
        );
    }

    #[test]
    fn every_config_command_accepts_the_short_flag() {
        for verb in ["run", "check", "doctor", "explain", "format"] {
            let cli = parse(&["rust-reality", verb, "-c", "/etc/rust-reality/config.json"]);
            let path = match &cli.command {
                Command::Run(arguments)
                | Command::Check(arguments)
                | Command::Doctor(arguments) => &arguments.config,
                Command::Explain(arguments) => &arguments.config,
                Command::Format(arguments) => &arguments.config,
                other => panic!("{verb} parsed as {other:?}"),
            };
            assert_eq!(path.to_string_lossy(), "/etc/rust-reality/config.json");
        }
    }

    #[test]
    fn a_configuration_path_is_required() {
        for verb in ["run", "check", "doctor", "explain", "format"] {
            assert!(
                Cli::try_parse_from(["rust-reality", verb]).is_err(),
                "{verb} must require a configuration"
            );
        }
    }

    #[test]
    fn generate_covers_every_kind_of_material_a_configuration_names() {
        assert!(matches!(
            parse(&["rust-reality", "generate", "uuid"]).command,
            Command::Generate {
                command: GenerateCommand::Uuid { count: 1, .. }
            }
        ));
        assert!(matches!(
            parse(&["rust-reality", "generate", "x25519"]).command,
            Command::Generate {
                command: GenerateCommand::X25519 { .. }
            }
        ));
        assert!(matches!(
            parse(&["rust-reality", "generate", "short-id", "4"]).command,
            Command::Generate {
                command: GenerateCommand::ShortId { count: 4, .. }
            }
        ));
        assert!(matches!(
            parse(&["rust-reality", "generate", "psk", "--json"]).command,
            Command::Generate {
                command: GenerateCommand::Psk { json: true }
            }
        ));
    }

    #[test]
    fn generate_bounds_its_counts_and_sizes() {
        assert!(Cli::try_parse_from(["rust-reality", "generate", "uuid", "0"]).is_err());
        assert!(Cli::try_parse_from(["rust-reality", "generate", "short-id", "0"]).is_err());
        assert!(
            Cli::try_parse_from(["rust-reality", "generate", "short-id", "--bytes", "9"]).is_err(),
            "a short ID is at most eight bytes on the wire"
        );
    }

    #[test]
    fn check_cover_defaults_its_name_to_the_cover_host() {
        let cli = parse(&[
            "rust-reality",
            "check-cover",
            "--cover",
            "www.example.com:443",
        ]);

        let Command::CheckCover(arguments) = cli.command else {
            panic!("must be the cover check");
        };
        assert_eq!(arguments.cover, "www.example.com:443");
        assert_eq!(arguments.server_name, None);
        assert_eq!(arguments.timeout_ms, 5_000);
    }

    #[test]
    fn format_writes_in_place_only_when_asked() {
        let printing = parse(&["rust-reality", "format", "-c", "config.json"]);
        let Command::Format(arguments) = printing.command else {
            panic!("must be the formatter");
        };
        assert!(!arguments.write, "printing is the default");

        let writing = parse(&["rust-reality", "format", "-c", "config.json", "--write"]);
        let Command::Format(arguments) = writing.command else {
            panic!("must be the formatter");
        };
        assert!(arguments.write);
    }

    #[test]
    fn the_removed_commands_are_gone_without_aliases() {
        for removed in [
            vec!["serve", "-c", "config.json"],
            vec!["self-test", "-c", "config.json"],
            vec!["probe-dest", "--target", "a:443", "--server-name", "a"],
            vec!["uuid"],
            vec!["x25519"],
            vec!["node-keygen"],
            vec!["mldsa65"],
            vec!["config", "generate", "standalone"],
            vec!["config", "autotune"],
            vec!["config", "format", "-c", "config.json"],
            vec!["runtime", "explain", "-c", "config.json"],
            vec!["runtime", "report", "--status-file", "s.json"],
        ] {
            let mut arguments = vec!["rust-reality"];
            arguments.extend(removed.iter().copied());
            assert!(
                Cli::try_parse_from(&arguments).is_err(),
                "{removed:?} must not resolve to anything"
            );
        }
    }
}
