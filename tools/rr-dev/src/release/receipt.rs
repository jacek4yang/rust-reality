//! Secret-free package execution receipts, shared by collection and qualification.
#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Image {
    pub path: String,
    #[serde(deserialize_with = "required_option")]
    pub before: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub after: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub argv: Vec<String>,
    #[serde(deserialize_with = "required_option")]
    pub pid: Option<u32>,
    #[serde(deserialize_with = "required_option")]
    pub start_ticks: Option<u64>,
    pub started_unix_ms: u64,
    pub completed_unix_ms: u64,
    #[serde(deserialize_with = "required_option")]
    pub exit_code: Option<i32>,
    #[serde(deserialize_with = "required_option")]
    pub stdout: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub stderr: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub stdout_sha256: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub stderr_sha256: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema: String,
    pub source_commit: String,
    pub tag: String,
    pub tier: String,
    pub assets_directory: String,
    pub output_directory: String,
    pub archive: Image,
    pub binary: Image,
    pub harness: Image,
    pub host_architecture: String,
    pub host_kernel: String,
    pub host_boot_id: String,
    pub host_cpuinfo_sha256: String,
    pub runner: Vec<String>,
    pub cover_target: String,
    pub cover_server_name: String,
    pub commands: Vec<Command>,
    #[serde(deserialize_with = "required_option")]
    pub primary_error: Option<String>,
    pub finalization_errors: Vec<String>,
}

fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(deserializer)
}

pub fn parse(bytes: &[u8]) -> Result<Receipt, String> {
    serde_json::from_slice(bytes).map_err(|error| error.to_string())
}

fn digest(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn verify(receipt: &Receipt, source: &str, tier: &super::matrix::Tier) -> Result<(), String> {
    if receipt.schema != "rr-package-execution/v1"
        || receipt.source_commit != source
        || !digest(source, 40)
        || receipt.tier != tier.id
        || receipt.primary_error.is_some()
        || !receipt.finalization_errors.is_empty()
        || !receipt.runner.is_empty()
        || receipt.host_architecture != tier.target.split('-').next().unwrap_or_default()
        || receipt.host_kernel.is_empty()
        || receipt.host_boot_id.is_empty()
        || !digest(&receipt.host_cpuinfo_sha256, 64)
        || receipt.commands.len() != 7
        || receipt.archive.path != format!("rust-reality-{}-{}.tar.gz", receipt.tag, tier.id)
        || !std::path::Path::new(&receipt.assets_directory).is_absolute()
        || !std::path::Path::new(&receipt.output_directory).is_absolute()
        || receipt.binary.path != "rust-reality"
        || receipt.harness.path != "rr-dev"
        || receipt.cover_target.is_empty()
        || receipt.cover_server_name.is_empty()
    {
        return Err("incomplete or substituted native package execution".to_owned());
    }
    for image in [&receipt.archive, &receipt.binary, &receipt.harness] {
        if image.before.as_ref().is_none_or(|value| !digest(value, 64))
            || image.after != image.before
        {
            return Err(
                "package, executable or harness changed or lacks final identity verification"
                    .to_owned(),
            );
        }
    }
    let config = receipt.commands[5]
        .argv
        .get(2)
        .ok_or("missing package configuration command")?;
    if config.is_empty() {
        return Err("empty package configuration path".to_owned());
    }
    let expected: [&[&str]; 7] = [
        &["--version"],
        &["--help"],
        &["generate", "x25519", "--json"],
        &["generate", "uuid"],
        &["generate", "short-id"],
        &["check", "--config", config],
        &["doctor", "--config", config],
    ];
    let mut processes = std::collections::BTreeSet::new();
    let mut end = 0;
    for (index, command) in receipt.commands.iter().enumerate() {
        if !command
            .argv
            .iter()
            .map(String::as_str)
            .eq(expected[index].iter().copied())
            || command.exit_code != Some(0)
            || command.error.is_some()
            || command.pid.is_none_or(|pid| pid == 0)
            || command.start_ticks.is_none_or(|ticks| ticks == 0)
            || !processes.insert((command.pid, command.start_ticks))
            || command.started_unix_ms == 0
            || command.started_unix_ms < end
            || command.completed_unix_ms < command.started_unix_ms
            || [&command.stdout_sha256, &command.stderr_sha256]
                .iter()
                .any(|value| value.as_ref().is_none_or(|value| !digest(value, 64)))
        {
            return Err("missing, reordered or failed packaged command".to_owned());
        }
        verify_output(command, index)?;
        end = command.completed_unix_ms;
    }
    let version = receipt.commands[0]
        .stdout
        .as_deref()
        .ok_or("missing packaged version")?;
    let expected_version = format!(
        "rust-reality {}",
        receipt.tag.strip_prefix('v').ok_or("invalid package tag")?
    );
    if version.lines().next() != Some(&expected_version)
        || version
            .lines()
            .find_map(|line| line.trim().strip_prefix("commit:"))
            .map(str::trim)
            != Some(source)
    {
        return Err("packaged executable reports a different version or source".to_owned());
    }
    Ok(())
}

fn verify_output(command: &Command, index: usize) -> Result<(), String> {
    let secret = (2..=4).contains(&index);
    if command.stdout.is_none() != secret
        || command.stderr.is_none() != secret
        || (secret && command.stdout_sha256 == Some(crate::hash::sha256_hex(b"")))
    {
        return Err(
            "package output is missing or contains unredacted generated secrets".to_owned(),
        );
    }
    for (text, digest) in [
        (&command.stdout, &command.stdout_sha256),
        (&command.stderr, &command.stderr_sha256),
    ] {
        if let Some(text) = text
            && Some(crate::hash::sha256_hex(text.as_bytes())) != *digest
        {
            return Err("packaged command output differs from its digest".to_owned());
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Fragment {
    schema_version: u64,
    package: String,
    version: String,
    tag: String,
    commit: String,
    source_date_epoch: u64,
    compiler: String,
    cargo_features: Vec<String>,
    tier: String,
    cpu_tier: String,
    artifact: String,
    sha256: String,
    target: String,
    target_cpu: String,
    target_features: Vec<String>,
    measured_natively: bool,
    requirements: serde_json::Value,
}

pub fn verify_fragment(
    fragment: &Fragment,
    receipt: &Receipt,
    tier: &super::matrix::Tier,
) -> Result<(), String> {
    let requirements: serde_json::Value =
        serde_json::from_str(&tier.requirements_json()).map_err(|error| error.to_string())?;
    if fragment.schema_version != 3
        || fragment.package != "rust-reality"
        || Some(fragment.version.as_str()) != receipt.tag.strip_prefix('v')
        || fragment.tag != receipt.tag
        || fragment.commit != receipt.source_commit
        || fragment.source_date_epoch == 0
        || !fragment.compiler.starts_with("rustc ")
        || fragment.cargo_features != ["default"]
        || fragment.tier != tier.id
        || fragment.cpu_tier != tier.cpu_tier
        || fragment.artifact != receipt.archive.path
        || Some(&fragment.sha256) != receipt.archive.before.as_ref()
        || fragment.target != tier.target
        || fragment.target_cpu != tier.target_cpu
        || fragment.target_features != tier.feature_list()
        || !fragment.measured_natively
        || fragment.requirements != requirements
    {
        return Err("package fragment does not bind the reviewed tier and source".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn package_receipts_reject_missing_changed_emulated_and_secret_observations() {
        let fixture: Value = serde_json::from_slice(include_bytes!(
            "../../../../fuzz/seeds/stability_evidence/seed_package.json"
        ))
        .unwrap();
        let tier = super::super::matrix::Tier::resolve("linux-x86_64-generic").unwrap();
        let check = |value: &Value| -> Result<(), String> {
            verify(
                &parse(&serde_json::to_vec(value).unwrap())?,
                &"a".repeat(40),
                tier,
            )
        };
        check(&fixture).unwrap();
        for (pointer, value) in [
            ("/source_commit", json!("b".repeat(40))),
            ("/archive/after", json!("b".repeat(64))),
            ("/binary/after", Value::Null),
            ("/harness/after", json!("b".repeat(64))),
            ("/host_architecture", json!("aarch64")),
            ("/runner", json!(["qemu-x86_64"])),
            ("/commands/0/stdout", json!("another binary")),
            ("/commands/1/stdout_sha256", json!("0".repeat(64))),
            (
                "/commands/2/stdout",
                json!("private-key-must-not-be-retained"),
            ),
            ("/commands/3/exit_code", json!(1)),
            ("/commands/3/pid", Value::Null),
            ("/commands/4/started_unix_ms", json!(0)),
            ("/commands/5/start_ticks", Value::Null),
            ("/commands/6/argv", json!(["--help"])),
            ("/primary_error", json!("interrupted")),
            ("/finalization_errors", json!(["changed image"])),
        ] {
            let mut changed = fixture.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(check(&changed).is_err(), "{pointer}");
        }
        let mut changed = fixture.clone();
        changed["commands"].as_array_mut().unwrap().pop();
        assert!(check(&changed).is_err());
        let mut changed = fixture.clone();
        changed["commands"][0]
            .as_object_mut()
            .unwrap()
            .remove("exit_code");
        assert!(check(&changed).is_err());
        let mut changed = fixture;
        changed["unknown"] = json!(true);
        assert!(check(&changed).is_err());
    }
}
