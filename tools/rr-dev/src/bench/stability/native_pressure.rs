//! Fixed native descriptor-pressure receipt and transition reconstruction.
#![allow(missing_docs)]

use serde::Deserialize;

use super::schema::{Check, Identity};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Binary {
    path: String,
    sha256: String,
    identity: String,
    immutable_during_run: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Helper {
    path: String,
    sha256: String,
    immutable_during_run: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Binaries {
    rust_reality: Binary,
    xray: Binary,
    openssl: Binary,
    rr_dev_helpers: Helper,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    soft: u64,
    hard: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    server: String,
    xray: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ports {
    server: u16,
    socks: u16,
    cover: u16,
    echo: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultReceipt {
    ok: bool,
    server_pid: u32,
    effective_budget: u64,
    baseline_fd_count: u64,
    pressure_fd_count: u64,
    successful_held_connections_at_pressure: u64,
    fill_failures: u64,
    storm_successes: u64,
    storm_failures: u64,
    high_transition_units: u64,
    normal_transition_units: u64,
    pub control_sha256: String,
    pub recovery_sha256: String,
    expected_recovery_sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    schema_version: u64,
    run_id: String,
    gate: String,
    completed_at: String,
    repository_head: String,
    launcher: String,
    nofile: Limits,
    binaries: Binaries,
    config_sha256: Config,
    ports: Ports,
    pub result: ResultReceipt,
    ok: bool,
}

pub fn parse(bytes: &[u8]) -> Result<Receipt, String> {
    serde_json::from_slice(bytes).map_err(|error| error.to_string())
}

pub fn verify(
    receipt: &Receipt,
    environment: &super::native_interop::Environment,
    check: &Check,
    identity: &Identity,
) -> Result<(), String> {
    let result = &receipt.result;
    let binaries = &receipt.binaries;
    let mut ports = [
        receipt.ports.server,
        receipt.ports.socks,
        receipt.ports.cover,
        receipt.ports.echo,
    ];
    ports.sort_unstable();
    if !receipt.ok
        || !result.ok
        || receipt.schema_version != 1
        || receipt.gate != "descriptor-pressure-recovery"
        || receipt.launcher != "prlimit-direct-exec"
        || receipt.run_id.is_empty()
        || receipt.completed_at.is_empty()
        || receipt.repository_head != identity.source_commit
        || receipt.nofile.soft != 192
        || receipt.nofile.hard != 192
        || result.server_pid == 0
        || result.effective_budget == 0
        || result.effective_budget > 192
        || result.pressure_fd_count <= result.baseline_fd_count
        || result.pressure_fd_count > 192
        || !(8..96).contains(&result.successful_held_connections_at_pressure)
        || result.fill_failures != 1
        || result.storm_failures == 0
        || result.storm_successes.checked_add(result.storm_failures) != Some(12)
        || result.high_transition_units > result.effective_budget
        || result.high_transition_units <= result.normal_transition_units
        || result.recovery_sha256 != result.expected_recovery_sha256
        || binaries.rust_reality.sha256 != identity.candidate.sha256
        || !environment.binds_external_images(&binaries.xray.sha256, &binaries.openssl.sha256)
        || binaries.rr_dev_helpers.sha256 != identity.evaluator.sha256
        || !binaries.rr_dev_helpers.immutable_during_run
        || binaries.rr_dev_helpers.path.is_empty()
        || ports[0] == 0
        || ports.windows(2).any(|pair| pair[0] == pair[1])
        || check.executed_cases != 1
        || check.argv.len() != 21
    {
        return Err("incomplete or substituted descriptor-pressure receipt".to_owned());
    }
    for digest in [
        &receipt.config_sha256.server,
        &receipt.config_sha256.xray,
        &result.control_sha256,
        &result.recovery_sha256,
    ] {
        if !super::evaluate::digest(digest, 64) {
            return Err("invalid pressure digest".to_owned());
        }
    }
    for binary in [&binaries.rust_reality, &binaries.xray, &binaries.openssl] {
        if binary.path.is_empty()
            || binary.identity.is_empty()
            || !binary.immutable_during_run
            || !super::evaluate::digest(&binary.sha256, 64)
        {
            return Err("unbound pressure executable".to_owned());
        }
    }
    for binary in [&binaries.xray, &binaries.openssl] {
        if !check
            .observations
            .iter()
            .any(|artifact| artifact.sha256 == binary.sha256)
        {
            return Err("external pressure executable was not retained".to_owned());
        }
    }
    let expected = [
        identity.evaluator.path.as_str(),
        "bench",
        "run",
        "--suite",
        "descriptor-pressure",
        "--rust-bin",
        &binaries.rust_reality.path,
        "--xray-bin",
        &binaries.xray.path,
        "--openssl-bin",
        &binaries.openssl.path,
        "--nofile-limit",
        "192",
        "--max-held-connections",
        "96",
        "--storm-connections",
        "12",
        "--run-id",
        &receipt.run_id,
        "--out-dir",
        &check.argv[20],
    ];
    if check.argv != expected || check.argv[20].is_empty() {
        return Err("pressure workload command was substituted".to_owned());
    }
    Ok(())
}

/// Require startup, pressure and recovery in order, bound to the observed budget.
pub fn transitions(bytes: &[u8], receipt: &Receipt) -> Result<(), String> {
    #[derive(Deserialize)]
    struct Event {
        event: String,
        #[serde(rename = "timestampUnixMs")]
        timestamp: u64,
    }
    #[derive(Deserialize)]
    struct Budget {
        fd_effective_budget: u64,
    }
    #[derive(Deserialize)]
    struct Pressure {
        #[serde(rename = "fd_effective_budget")]
        budget: u64,
        #[serde(rename = "fd_units_in_use")]
        units: u64,
        #[serde(rename = "fd_pressure_state")]
        state: String,
    }
    if super::execution::product_log(bytes)?.panics != 0 {
        return Err("pressure process panicked".to_owned());
    }
    let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    let mut startup = None;
    let mut high = None;
    let mut recovered = false;
    for line in text.lines() {
        let event: Event = serde_json::from_str(line).map_err(|error| error.to_string())?;
        if event.event == "descriptor_budget_report" {
            let budget: Budget = serde_json::from_str(line).map_err(|error| error.to_string())?;
            if startup.is_some() || budget.fd_effective_budget != receipt.result.effective_budget {
                return Err("repeated or changed descriptor budget".to_owned());
            }
            startup = Some(event.timestamp);
        } else if event.event == "descriptor_pressure_changed" {
            let pressure: Pressure =
                serde_json::from_str(line).map_err(|error| error.to_string())?;
            if startup.is_none_or(|time| time > event.timestamp)
                || pressure.budget != receipt.result.effective_budget
            {
                return Err("pressure precedes its bound startup policy".to_owned());
            }
            match pressure.state.as_str() {
                "high" if high.is_none() => {
                    if pressure.units != receipt.result.high_transition_units {
                        return Err("pressure units differ from the raw transition".to_owned());
                    }
                    high = Some(event.timestamp);
                }
                "normal" if !recovered => {
                    if high.is_none_or(|time| time > event.timestamp)
                        || pressure.units != receipt.result.normal_transition_units
                    {
                        return Err(
                            "recovery units or transition ordering was substituted".to_owned()
                        );
                    }
                    recovered = true;
                }
                "high" | "normal" => {}
                _ => return Err("invalid descriptor pressure state".to_owned()),
            }
        }
    }
    if !recovered {
        return Err("missing pressure/recovery observations".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_reject_changed_units_order_duplicates_and_truncation() {
        let receipt = parse(include_bytes!(
            "../../../../../fuzz/seeds/stability_evidence/seed_native_pressure"
        ))
        .unwrap();
        let log =
            include_str!("../../../../../fuzz/seeds/stability_evidence/seed_pressure_events.jsonl");
        assert!(transitions(log.as_bytes(), &receipt).is_ok());
        for changed in [
            log.replace("\"fd_units_in_use\":60", "\"fd_units_in_use\":59"),
            log.replace("\"fd_units_in_use\":4", "\"fd_units_in_use\":-1"),
            log.replace("\"timestampUnixMs\":1", "\"timestampUnixMs\":4"),
            log.replace("\"timestampUnixMs\":3", "\"timestampUnixMs\":1"),
            log.replace(
                "\"fd_pressure_state\":\"high\"",
                "\"fd_pressure_state\":\"normal\"",
            ),
            log.replace(
                "\"fd_units_in_use\":60",
                "\"fd_units_in_use\":60,\"fd_units_in_use\":60",
            ),
            log.trim_end().to_owned(),
            format!("{log}panicked at pressure\n"),
            format!("{}\n", log.lines().take(2).collect::<Vec<_>>().join("\n")),
        ] {
            assert!(transitions(changed.as_bytes(), &receipt).is_err());
        }
    }
}
