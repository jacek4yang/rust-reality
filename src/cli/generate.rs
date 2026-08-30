// Configuration generation: the `config generate` role implementations and
// the deployment writers.

use std::{
    io::{self, Write},
    path::Path,
};

use crate::config::{
    GenerateConfigInput, GenerateHandoffConfigInput, GenerateLandingConfigInput,
    GenerateLineConfigInput, GenerateMultiHandoffConfigInput, GeneratedHandoffConfigs,
    GeneratedMultiHandoffConfigs, HandoffLandingInput, SecretString, format_config,
    generate_handoff_configs, generate_landing_config, generate_line_config,
    generate_minimal_config, generate_multi_handoff_configs,
};
use crate::crypto::{generate_mldsa65_key_pair, generate_mldsa65_key_pair_from_seed};

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
use serde_json::json;
use zeroize::Zeroizing;

use super::commands::write_stdout;
use super::model::MlDsa65Args;
use super::model::{CliError, GenerateRole, PublicGenerateArgs};

pub(crate) fn run_config_generate(role: GenerateRole) -> Result<(), CliError> {
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
pub(crate) fn resolve_handoff_landings(
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

pub(crate) fn public_generation_input(arguments: PublicGenerateArgs) -> GenerateConfigInput {
    GenerateConfigInput {
        listen: arguments.listen,
        port: arguments.port,
        target: arguments.target,
        server_name: arguments.server_name,
    }
}

pub(crate) fn write_public_config(
    generated: &crate::config::GeneratedConfig,
) -> Result<(), CliError> {
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
pub(crate) fn write_handoff_configs(
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
pub(crate) fn write_multi_handoff_configs(
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

pub(crate) fn run_mldsa65(arguments: MlDsa65Args) -> Result<(), CliError> {
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
