//! Verify normalized evidence against the retained raw process observation.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use super::schema::{Observation, Owners, Policy, Sample};

fn field(text: &str, name: &str) -> Result<u64, String> {
    let mut matches = text.lines().filter_map(|line| line.strip_prefix(name));
    let value = matches.next().ok_or_else(|| format!("missing {name}"))?;
    if matches.next().is_some() {
        return Err(format!("duplicate {name}"));
    }
    value
        .split_whitespace()
        .next()
        .ok_or_else(|| format!("empty {name}"))?
        .parse()
        .map_err(|_| format!("invalid {name}"))
}

#[derive(Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    ConfigurationPublished {
        #[serde(rename = "timestampUnixMs")]
        timestamp: u64,
        level: String,
        generation: u64,
    },
    GenerationRetired {
        #[serde(rename = "timestampUnixMs")]
        timestamp: u64,
        level: String,
        generation: u64,
    },
    ConnectionTaskOwnership {
        #[serde(rename = "timestampUnixMs")]
        timestamp: u64,
        level: String,
        address: String,
        tracked_tasks: u64,
    },
    ResourceOwnership {
        handshakes: u64,
        fallbacks: u64,
        crypto_operations: u64,
        dns_lookups: u64,
        pre_auth_idle_connections: u64,
        pre_auth_idle_capacity: u64,
        fd_capacity: u64,
        pipe_pair_capacity: Option<u64>,
        warm_socket_capacity: u64,
        replay_capacity: u64,
        replay_expiry_ms: u64,
        retirement_deadline_ms: u64,
        #[serde(rename = "timestampUnixMs")]
        timestamp: u64,
        level: String,
        generation: u64,
        admitted_connections: u64,
        replay_entries: u64,
        fd_units_in_use: u64,
        retained_pipe_pairs: Option<u64>,
        retained_pipe_bytes: Option<u64>,
        warm_ready: u64,
        warm_connecting: u64,
    },
}

/// Ownership reconstructed solely from fresh debug records.
pub struct Ownership {
    pre_auth_idle_capacity: u64,
    fd_capacity: u64,
    pipe_capacity: u64,
    warm_capacity: u64,
    replay_capacity: u64,
    replay_expiry_ms: u64,
    retirement_deadline_ms: u64,
    owners: Owners,
    permits: u64,
    pipe_pairs: u64,
    pipe_bytes: u64,
    warm_sockets: u64,
}

/// Reconstruct resource owners without inventing absent observations.
///
/// # Errors
/// Rejects malformed records, incomplete generations and stale/missing counters.
#[allow(clippy::too_many_lines)]
pub fn read_ownership(observation: &Observation, listeners: u64) -> Result<Ownership, String> {
    let log = observation
        .ownership_log
        .as_deref()
        .ok_or("missing ownership log")?;
    let mut published = BTreeSet::new();
    let mut retired = BTreeSet::new();
    let mut tasks = BTreeMap::new();
    let mut resources = None;
    let mut current = None;
    for line in log.split_inclusive('\n') {
        // A writer may be partway through its final record. Earlier complete
        // records remain usable only if they meet the fixed freshness bound.
        if !line.ends_with('\n') {
            break;
        }
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|error| format!("invalid debug log: {error}"))?;
        if !matches!(
            value["event"].as_str(),
            Some(
                "configuration_published"
                    | "generation_retired"
                    | "connection_task_ownership"
                    | "resource_ownership"
            )
        ) {
            continue;
        }
        let event: Event = serde_json::from_str(line)
            .map_err(|error| format!("invalid ownership event: {error}"))?;
        match event {
            Event::ConfigurationPublished {
                timestamp,
                level,
                generation,
            } => {
                if timestamp > observation.completed_unix_ms
                    || level != "info"
                    || !published.insert(generation)
                {
                    return Err("invalid generation publication history".to_owned());
                }
                current = Some(generation);
            }
            Event::GenerationRetired {
                timestamp,
                level,
                generation,
            } => {
                if timestamp > observation.completed_unix_ms
                    || level != "debug"
                    || !retired.insert(generation)
                {
                    return Err("invalid generation retirement history".to_owned());
                }
            }
            Event::ConnectionTaskOwnership {
                timestamp,
                level,
                address,
                tracked_tasks,
            } => {
                if level != "debug" {
                    return Err("task ownership is not a debug observation".to_owned());
                }
                tasks.insert(address, (timestamp, tracked_tasks));
            }
            Event::ResourceOwnership {
                handshakes,
                fallbacks,
                crypto_operations,
                dns_lookups,
                pre_auth_idle_connections,
                pre_auth_idle_capacity,
                fd_capacity,
                pipe_pair_capacity,
                warm_socket_capacity,
                replay_capacity,
                replay_expiry_ms,
                retirement_deadline_ms,
                timestamp,
                level,
                generation,
                admitted_connections,
                replay_entries,
                fd_units_in_use,
                retained_pipe_pairs,
                retained_pipe_bytes,
                warm_ready,
                warm_connecting,
            } => {
                if level != "debug" {
                    return Err("resource ownership is not a debug observation".to_owned());
                }
                resources = Some((
                    timestamp,
                    generation,
                    Ownership {
                        pre_auth_idle_capacity,
                        fd_capacity,
                        pipe_capacity: pipe_pair_capacity.ok_or("unobserved pipe capacity")?,
                        warm_capacity: warm_socket_capacity,
                        replay_capacity,
                        replay_expiry_ms,
                        retirement_deadline_ms,
                        owners: Owners {
                            handshakes,
                            fallbacks,
                            crypto_operations,
                            dns_lookups,
                            pre_auth_idle_connections,
                            admitted_connections,
                            tracked_connection_tasks: 0,
                            retired_generations: 0,
                            replay_entries,
                        },
                        permits: fd_units_in_use,
                        pipe_pairs: retained_pipe_pairs.ok_or("unobserved retained pipe count")?,
                        pipe_bytes: retained_pipe_bytes
                            .ok_or("unobserved retained pipe contents")?,
                        warm_sockets: warm_ready
                            .checked_add(warm_connecting)
                            .ok_or("warm socket count overflow")?,
                    },
                ));
            }
        }
    }
    let fresh = |timestamp: u64| {
        observation
            .completed_unix_ms
            .checked_sub(timestamp)
            .is_some_and(|age| age <= 2000)
    };
    let (timestamp, generation, mut ownership) =
        resources.ok_or("missing resource ownership event")?;
    if !fresh(timestamp)
        || current != Some(generation)
        || !published.contains(&0)
        || retired.contains(&generation)
    {
        return Err("stale ownership or incomplete generation history".to_owned());
    }
    if u64::try_from(tasks.len()).ok() != Some(listeners)
        || tasks.values().any(|(timestamp, _)| !fresh(*timestamp))
    {
        return Err("missing or stale listener task observations".to_owned());
    }
    ownership.owners.tracked_connection_tasks = tasks
        .values()
        .try_fold(0_u64, |total, (_, count)| total.checked_add(*count))
        .ok_or("task count overflow")?;
    ownership.owners.retired_generations = u64::try_from(
        published
            .iter()
            .filter(|id| **id != generation && !retired.contains(id))
            .count(),
    )
    .map_err(|_| "generation count overflow")?;
    Ok(ownership)
}

/// Reject normalized samples that cannot be reproduced from their raw receipt.
///
/// # Errors
/// Missing reads, races, substituted processes and mismatching normalized fields
/// are evidence errors; the caller must report INVALID, never PASS.
#[allow(clippy::too_many_lines)]
pub fn verify(raw: &Observation, sample: &Sample, policy: &Policy) -> Result<(), String> {
    if !raw.errors.is_empty()
        || !raw.closed_during_read.is_empty()
        || raw.completed_unix_ms < raw.started_unix_ms
        || raw.completed_unix_ms - raw.started_unix_ms > 2000
    {
        return Err("failed, raced or excessively long observation".to_owned());
    }
    let expected = &sample.process;
    if raw.pid != expected.pid
        || raw
            .initial_start_ticks
            .as_deref()
            .and_then(|value| value.parse::<u64>().ok())
            != Some(expected.start_ticks)
        || raw.final_start_ticks != raw.initial_start_ticks
        || raw.boot_id.as_deref().map(str::trim) != Some(expected.boot_id.as_str())
        || raw.initial_executable_sha256.as_ref() != Some(&expected.executable_sha256)
        || raw.final_executable_sha256 != raw.initial_executable_sha256
    {
        return Err("observation process identity mismatch".to_owned());
    }
    let status = raw.status.as_deref().ok_or("missing status")?;
    let smaps = raw.smaps_rollup.as_deref().ok_or("missing smaps_rollup")?;
    if field(status, "VmRSS:")? != sample.rss_kib
        || field(status, "Threads:")? != sample.threads
        || field(smaps, "Pss:")? != sample.pss_kib
        || field(smaps, "Anonymous:")? != sample.anonymous_kib
        || u64::try_from(raw.descriptors.len()).ok() != Some(sample.descriptors.total)
    {
        return Err("normalized resource numbers differ from raw observations".to_owned());
    }
    let limits = raw.limits.as_deref().ok_or("missing descriptor limits")?;
    if field(limits, "Max open files")? != policy.soft_fd_limit {
        return Err("descriptor limit differs from startup policy".to_owned());
    }
    let observed = read_ownership(raw, policy.listener_sockets)?;
    if observed.pre_auth_idle_capacity != policy.idle_inbound_capacity
        || observed.fd_capacity != policy.dynamic_fd_budget
        || observed.pipe_capacity != policy.pipe_pair_capacity
        || observed.warm_capacity != policy.warm_socket_capacity
        || observed.replay_capacity != policy.replay_capacity
        || observed.replay_expiry_ms != policy.replay_expiry_ms
        || observed.retirement_deadline_ms != policy.retirement_deadline_ms
    {
        return Err("declared capacity differs from observed startup authorities".to_owned());
    }
    if observed.owners != sample.owners
        || observed.permits != sample.descriptors.held_dynamic_permits
        || observed.pipe_pairs != sample.descriptors.retained_pipe_pairs
        || observed.pipe_bytes != sample.descriptors.dirty_retained_pipe_bytes
        || observed.warm_sockets != sample.descriptors.warm_sockets
    {
        return Err("normalized ownership differs from debug observations".to_owned());
    }
    let mut fixed = policy.fixed_descriptor_targets.clone();
    let mut sockets = 0_u64;
    let mut pipes = 0_u64;
    for target in raw.descriptors.values() {
        if let Some(index) = fixed.iter().position(|expected| expected == target) {
            fixed.swap_remove(index);
        } else if target.starts_with("socket:[") && target.ends_with(']') {
            sockets += 1;
        } else if target.starts_with("pipe:[") && target.ends_with(']') {
            pipes += 1;
        } else {
            return Err("descriptor has no startup, socket or pipe owner".to_owned());
        }
    }
    let expected_sockets = sample
        .descriptors
        .listener_sockets
        .checked_add(sample.descriptors.warm_sockets)
        .and_then(|total| total.checked_add(sample.descriptors.active_sockets))
        .and_then(|total| total.checked_add(sample.descriptors.idle_inbound_sockets));
    let expected_pipes = sample
        .descriptors
        .retained_pipe_pairs
        .checked_mul(2)
        .and_then(|total| total.checked_add(sample.descriptors.active_relay_fds));
    if !fixed.is_empty() || Some(sockets) != expected_sockets || Some(pipes) != expected_pipes {
        return Err("descriptor census differs from ownership accounting".to_owned());
    }
    Ok(())
}

/// Bind a raw observation to its declared checkpoint rather than a reused window.
///
/// # Errors
/// Rejects arithmetic overflow and observations outside the declared interval.
pub fn verify_checkpoint_time(
    raw: &Observation,
    cell_started_unix_ms: u64,
    checkpoint_ms: u64,
    tolerance_ms: u64,
) -> Result<(), String> {
    let start = cell_started_unix_ms
        .checked_add(checkpoint_ms)
        .ok_or("checkpoint epoch overflow")?;
    let end = start
        .checked_add(tolerance_ms)
        .ok_or("checkpoint deadline overflow")?;
    if raw.started_unix_ms < start || raw.completed_unix_ms > end {
        return Err("raw observation was substituted from another checkpoint".to_owned());
    }
    Ok(())
}
