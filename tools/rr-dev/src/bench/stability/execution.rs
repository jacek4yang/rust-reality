//! Reconstruct VM execution claims from raw startup, kernel and terminal receipts.
#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

use super::schema::{Cell, Identity, Role};

fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(deserializer)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub observed_unix_ms: u64,
    pub boot_id: Option<String>,
    pub online_cpus: Option<String>,
    pub meminfo: Option<String>,
    pub swaps: Option<String>,
    pub vmstat: Option<String>,
    pub kernel: Option<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Startup {
    pub label: String,
    pub pid: u32,
    pub start_ticks: Option<String>,
    pub image_sha256: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub image_error: Option<String>,
    #[serde(deserialize_with = "required_option")]
    pub readiness_error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Terminal {
    pub role: String,
    pub boot_id: String,
    pub started_unix_ms: u64,
    pub completed_unix_ms: u64,
    pub candidate_sha256: String,
    pub evaluator_sha256: String,
    #[serde(deserialize_with = "required_option")]
    pub primary_error: Option<String>,
    pub finalization_errors: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CellTerminal {
    #[serde(deserialize_with = "required_option")]
    pub primary_error: Option<String>,
    pub finalization_errors: Vec<String>,
}

fn integer(text: &str) -> Result<u64, String> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid kernel counter".to_owned());
    }
    text.parse()
        .map_err(|_| "kernel counter overflow".to_owned())
}

fn counter(text: &str, name: &str, units: &[&str]) -> Result<u64, String> {
    let mut rows = text
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .filter(|fields| fields.first() == Some(&name));
    let fields = rows.next().ok_or_else(|| format!("missing {name}"))?;
    if rows.next().is_some() || fields.len() != units.len() + 2 || fields[2..] != *units {
        return Err(format!("malformed or duplicate {name}"));
    }
    integer(fields[1])
}

pub fn parse_environment(bytes: &[u8]) -> Result<Environment, String> {
    let value: Environment = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    validate_environment(&value)?;
    Ok(value)
}

fn validate_environment(value: &Environment) -> Result<(u64, u64), String> {
    if !value.errors.is_empty()
        || value.observed_unix_ms == 0
        || value
            .boot_id
            .as_deref()
            .is_none_or(|boot| boot.trim().is_empty())
        || value
            .kernel
            .as_deref()
            .is_none_or(|kernel| kernel.trim().is_empty())
        || !matches!(
            value.online_cpus.as_deref().map(str::trim),
            Some("0" | "0-1")
        )
    {
        return Err("incomplete guest environment observation".to_owned());
    }
    let swaps = value.swaps.as_deref().ok_or("missing swaps")?;
    if swaps.split_whitespace().collect::<Vec<_>>()
        != ["Filename", "Type", "Size", "Used", "Priority"]
    {
        return Err("guest swap is present or unobserved".to_owned());
    }
    let memory = value.meminfo.as_deref().ok_or("missing meminfo")?;
    if counter(memory, "SwapTotal:", &["kB"])? != 0 {
        return Err("guest swap capacity is nonzero".to_owned());
    }
    Ok((
        counter(memory, "MemTotal:", &["kB"])?,
        counter(
            value.vmstat.as_deref().ok_or("missing vmstat")?,
            "oom_kill",
            &[],
        )?,
    ))
}

pub fn environment_pair(
    before: &Environment,
    after: &Environment,
    role: &Role,
    cell: &Cell,
) -> Result<u64, String> {
    let (memory, oom_before) = validate_environment(before)?;
    let (memory_after, oom_after) = validate_environment(after)?;
    let expected_cpus = if role.name == "landing" && cell.name.ends_with("/ordinary") {
        "0-1"
    } else {
        "0"
    };
    let expected_memory = if expected_cpus == "0-1" {
        2_147_483_648
    } else {
        1_073_741_824
    };
    if before.boot_id.as_deref().map(str::trim) != Some(role.process.boot_id.as_str())
        || after.boot_id != before.boot_id
        || after.kernel != before.kernel
        || before.online_cpus.as_deref().map(str::trim) != Some(expected_cpus)
        || after.online_cpus != before.online_cpus
        || role.vcpus != if expected_cpus == "0-1" { 2 } else { 1 }
        || role.memory_limit_bytes != expected_memory
        || role.swap_limit_bytes != 0
        || memory != memory_after
        || memory < expected_memory / 1024 * 9 / 10
        || memory > expected_memory / 1024
        || before.observed_unix_ms >= cell.started_unix_ms
        || after.observed_unix_ms <= cell.started_unix_ms
    {
        return Err("guest resource profile, identity or environment interval changed".to_owned());
    }
    oom_after
        .checked_sub(oom_before)
        .ok_or_else(|| "guest OOM counter moved backwards".to_owned())
}

pub fn startup(bytes: &[u8], role: &Role) -> Result<(), String> {
    let value: Startup = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if value.label != "server"
        || value.pid != role.process.pid
        || value
            .start_ticks
            .as_deref()
            .and_then(|ticks| integer(ticks).ok())
            != Some(role.process.start_ticks)
        || value.image_sha256.as_deref() != Some(role.process.executable_sha256.as_str())
        || value.image_error.is_some()
        || value.readiness_error.is_some()
    {
        return Err("startup did not verify the initial candidate process".to_owned());
    }
    Ok(())
}

pub fn terminal(
    bytes: &[u8],
    role: &Role,
    cell: &Cell,
    identity: &Identity,
    completed_after: u64,
) -> Result<(), String> {
    let value: Terminal = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if value.role != role.name
        || value.boot_id != role.process.boot_id
        || value.started_unix_ms != cell.started_unix_ms
        || value.completed_unix_ms < completed_after
        || value.candidate_sha256 != identity.candidate.sha256
        || value.evaluator_sha256 != identity.evaluator.sha256
        || value.primary_error.is_some()
        || !value.finalization_errors.is_empty()
    {
        return Err("guest execution or terminal identity verification failed".to_owned());
    }
    Ok(())
}

#[derive(Default, Debug)]
pub struct LogCounts {
    pub panics: u64,
    pub rejections: u64,
}

/// Unexpected protocol rejection is never hidden by successful later transfers.
pub fn product_log(bytes: &[u8]) -> Result<LogCounts, String> {
    product_log_with_evictions(bytes, &mut Vec::new())
}

/// Consume each proven injected eviction at most once across all process logs.
pub(super) fn product_log_with_evictions(
    bytes: &[u8],
    evictions: &mut Vec<(String, u64, u64)>,
) -> Result<LogCounts, String> {
    #[derive(Deserialize)]
    struct Record {
        event: String,
        #[serde(rename = "timestampUnixMs")]
        timestamp_unix_ms: u64,
        level: String,
        peer: Option<String>,
        reason: Option<String>,
    }
    let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    if text.is_empty() || !text.ends_with('\n') {
        return Err("empty or truncated product log".to_owned());
    }
    let mut counts = LogCounts::default();
    for line in text.lines() {
        if line.contains("panicked at") || line.contains("memory allocation of") {
            counts.panics += 1;
            continue;
        }
        let event: Record = serde_json::from_str(line).map_err(|error| error.to_string())?;
        if event.timestamp_unix_ms == 0 || event.level.is_empty() || event.event.is_empty() {
            return Err("malformed product event".to_owned());
        }
        if matches!(
            event.event.as_str(),
            "connection_rejected" | "configuration_rejected" | "admission_limited"
        ) {
            let injected = (event.event == "connection_rejected"
                && event.reason.as_deref() == Some("authentication"))
            .then(|| {
                evictions.iter().position(|(peer, start, end)| {
                    event.peer.as_ref() == Some(peer)
                        && event.timestamp_unix_ms >= *start
                        && event.timestamp_unix_ms <= *end
                })
            })
            .flatten();
            if let Some(index) = injected {
                evictions.remove(index);
            } else {
                counts.rejections += 1;
            }
        }
    }
    Ok(counts)
}
