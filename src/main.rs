use std::{
    error::Error,
    fmt,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    process::ExitCode,
};

use clap::{Args, Parser, Subcommand};
use rust_reality::{
    config::{
        ConfigLoadError, GenerateConfigError, GenerateConfigInput, format_config,
        format_config_schema, generate_minimal_config, load_config,
    },
    crypto::{KeyGenerationError, generate_uuid, generate_x25519_key_pair},
};
use serde_json::json;

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
    /// Print the complete JSON Schema to standard output.
    Schema,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Generate a minimal direct-routing server configuration.
    Generate(GenerateArgs),
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
struct GenerateArgs {
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

#[derive(Debug)]
enum CliError {
    Config(ConfigLoadError),
    Generate(GenerateConfigError),
    Key(KeyGenerationError),
    Json(serde_json::Error),
    Io(io::Error),
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(source) => source.fmt(formatter),
            Self::Generate(source) => source.fmt(formatter),
            Self::Key(source) => source.fmt(formatter),
            Self::Json(_) => formatter.write_str("failed to encode JSON output"),
            Self::Io(_) => formatter.write_str("failed to write command output"),
        }
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Config(source) => Some(source),
            Self::Generate(source) => Some(source),
            Self::Key(source) => Some(source),
            Self::Json(source) => Some(source),
            Self::Io(source) => Some(source),
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
        Command::Schema => write_stdout(format_config_schema()?),
    }
}

fn run_config(command: ConfigCommand) -> Result<(), CliError> {
    match command {
        ConfigCommand::Generate(arguments) => {
            let generated = generate_minimal_config(GenerateConfigInput {
                listen: arguments.listen,
                port: arguments.port,
                target: arguments.target,
                server_name: arguments.server_name,
            })?;
            let public_key = generated.reality_public_key().to_owned();
            let output = format_config(generated.config())?;
            write_stdout(output)?;
            writeln!(
                io::stderr().lock(),
                "REALITY public key for the client: {public_key}"
            )?;
            Ok(())
        }
        ConfigCommand::Format(arguments) => {
            let config = load_config(arguments.config)?;
            write_stdout(format_config(&config)?)
        }
    }
}

fn write_stdout(output: impl fmt::Display) -> Result<(), CliError> {
    write!(io::stdout().lock(), "{output}").map_err(CliError::Io)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Command, ConfigCommand};

    #[test]
    fn parses_nested_generate_command() {
        let cli = Cli::try_parse_from([
            "rust-reality",
            "config",
            "generate",
            "--target",
            "www.example.com:443",
            "--server-name",
            "www.example.com",
        ])
        .expect("command must parse");

        assert!(matches!(
            cli.command,
            Command::Config {
                command: ConfigCommand::Generate(_)
            }
        ));
    }

    #[test]
    fn rejects_zero_uuid_count() {
        assert!(Cli::try_parse_from(["rust-reality", "uuid", "0"]).is_err());
    }
}
