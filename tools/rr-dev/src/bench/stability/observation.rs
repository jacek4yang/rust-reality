//! Verify normalized evidence against the retained raw process observation.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use super::schema::{Artifact, Descriptors, Observation, Owners, Policy, ProcessIdentity, Sample};

fn field(text: &str, name: &str) -> Result<u64, String> {
    let mut matches = text.lines().filter_map(|line| line.strip_prefix(name));
    let value = matches.next().ok_or_else(|| format!("missing {name}"))?;
    if matches.next().is_some() {
        return Err(format!("duplicate {name}"));
    }
    let fields: Vec<_> = value.split_whitespace().collect();
    let number = match (name, fields.as_slice()) {
        ("Threads:", [number]) | ("VmRSS:" | "VmHWM:" | "Pss:" | "Anonymous:", [number, "kB"]) => {
            *number
        }
        ("Max open files", [soft, hard, "files"])
            if *hard == "unlimited" || hard.parse::<u64>().is_ok() =>
        {
            *soft
        }
        _ => return Err(format!("invalid fields or units for {name}")),
    };
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("invalid {name}"));
    }
    number.parse().map_err(|_| format!("invalid {name}"))
}

/// Read the exact coreutils digest receipt for a known file argument.
///
/// # Errors
/// Rejects malformed, additional or substituted file records.
pub fn digest_receipt(output: &str, file: &str) -> Result<String, String> {
    let suffix = format!("  {file}\n");
    let digest = output
        .strip_suffix(&suffix)
        .ok_or("digest receipt names another file")?;
    if !super::evaluate::digest(digest, 64) {
        return Err("invalid digest receipt".to_owned());
    }
    Ok(digest.to_owned())
}

fn unix_rows(table: &str) -> Result<BTreeMap<u64, &str>, String> {
    let mut lines = table.lines();
    if lines
        .next()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        != Some(vec![
            "Num", "RefCount", "Protocol", "Flags", "Type", "St", "Inode", "Path",
        ])
    {
        return Err("invalid Unix socket table header".to_owned());
    }
    let mut rows = BTreeMap::new();
    for line in lines {
        let fields: Vec<_> = line.split_whitespace().take(7).collect();
        if fields.len() != 7
            || !fields[0].ends_with(':')
            || fields[1..6]
                .iter()
                .any(|field| u64::from_str_radix(field, 16).is_err())
        {
            return Err("invalid Unix socket table row".to_owned());
        }
        let inode = fields[6]
            .parse::<u64>()
            .map_err(|_| "invalid Unix socket inode")?;
        if inode == 0 || rows.insert(inode, line).is_some() {
            return Err("duplicate or zero Unix socket inode".to_owned());
        }
    }
    Ok(rows)
}

fn socket_inode(target: &str) -> Result<Option<u64>, String> {
    target
        .strip_prefix("socket:[")
        .map(|number| {
            number
                .strip_suffix(']')
                .and_then(|number| number.parse::<u64>().ok())
                .filter(|inode| *inode > 0)
                .ok_or_else(|| "invalid socket descriptor target".to_owned())
        })
        .transpose()
}

/// Retain unmodified kernel rows only for sockets owned by the selected process.
/// Other namespace sockets and their potentially private paths are not evidence.
///
/// # Errors
/// Rejects malformed kernel tables and descriptor targets.
pub fn owned_unix_rows(table: &str, descriptors: &BTreeMap<u32, String>) -> Result<String, String> {
    let rows = unix_rows(table)?;
    let mut owned = BTreeSet::new();
    for target in descriptors.values() {
        if let Some(inode) = socket_inode(target)? {
            owned.insert(inode);
        }
    }
    let mut output = "Num RefCount Protocol Flags Type St Inode Path\n".to_owned();
    for (inode, row) in rows {
        if owned.contains(&inode) {
            output.push_str(row);
            output.push('\n');
        }
    }
    Ok(output)
}

fn runtime_unix_count(raw: &Observation) -> Result<u64, String> {
    let rows = unix_rows(
        raw.unix_sockets
            .as_deref()
            .ok_or("missing Unix socket observation")?,
    )?;
    let mut count = 0;
    for target in raw.descriptors.values() {
        if socket_inode(target)?.is_some_and(|inode| rows.contains_key(&inode)) {
            count += 1;
        }
    }
    Ok(count)
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
pub fn read_ownership(observation: &Observation, listeners: u64) -> Result<Ownership, String> {
    read_ownership_at_checkpoint(observation, listeners, true)
}

#[allow(clippy::too_many_lines)]
fn read_ownership_at_checkpoint(
    observation: &Observation,
    listeners: u64,
    require_current_generation: bool,
) -> Result<Ownership, String> {
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
                    || Some(generation)
                        != current.map_or(Some(0), |previous: u64| previous.checked_add(1))
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
        || !published.contains(&generation)
        || !published.contains(&0)
        || !retired.is_subset(&published)
        || current.is_none_or(|current| retired.contains(&current))
        || (require_current_generation && current != Some(generation))
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
            .filter(|id| Some(**id) != current && !retired.contains(id))
            .count(),
    )
    .map_err(|_| "generation count overflow")?;
    Ok(ownership)
}

// Establish read validity before deriving ownership differences. A disappearing
// FD is a non-atomic census, not evidence that the product omitted its permit.
fn verify_read(raw: &Observation) -> Result<(), String> {
    if !raw.errors.is_empty() {
        return Err(format!("failed raw observation: {:?}", raw.errors));
    }
    if !raw.closed_during_read.is_empty() {
        return Err(format!(
            "descriptor census raced; closed during read: {:?}",
            raw.closed_during_read
        ));
    }
    let reads = &raw.descriptor_reads;
    if reads.len() > super::schema::MAX_DESCRIPTOR_READS
        || reads.iter().any(|read| !read.errors.is_empty())
        || !super::schema::complete_descriptor_pair(reads)
        || reads.last().map(|read| &read.descriptors) != Some(&raw.descriptors)
        || (2..reads.len()).any(|end| super::schema::complete_descriptor_pair(&reads[..end]))
    {
        return Err(
            "descriptor census is incomplete, inconsistent or not the first stable pair".to_owned(),
        );
    }
    if raw.completed_unix_ms < raw.started_unix_ms
        || raw.completed_unix_ms - raw.started_unix_ms > 2000
    {
        return Err("invalid or excessively long observation interval".to_owned());
    }
    Ok(())
}

/// Reject normalized samples that cannot be reproduced from their raw receipt.
///
/// # Errors
/// Missing reads, races, substituted processes and mismatching normalized fields
/// are evidence errors; the caller must report INVALID, never PASS.
#[allow(clippy::too_many_lines)]
pub fn verify(raw: &Observation, sample: &Sample, policy: &Policy) -> Result<(), String> {
    verify_read(raw)?;
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
        || field(status, "VmHWM:")? != sample.hwm_kib
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
    let observed = read_ownership_at_checkpoint(
        raw,
        policy.listener_sockets,
        sample.descriptors.reconciliation.is_some(),
    )?;
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
    let unix_count = runtime_unix_count(raw)?;
    if unix_count != policy.runtime_unix_sockets
        || unix_count != sample.descriptors.runtime_unix_sockets
    {
        return Err("runtime Unix socket count differs from startup inventory".to_owned());
    }
    let unix = unix_rows(raw.unix_sockets.as_deref().ok_or("missing Unix sockets")?)?;
    let mut sockets = 0_u64;
    let mut pipes = 0_u64;
    for target in raw.descriptors.values() {
        if let Some(index) = fixed.iter().position(|expected| expected == target) {
            fixed.swap_remove(index);
        } else if let Some(inode) = socket_inode(target)? {
            if !unix.contains_key(&inode) {
                sockets += 1;
            }
        } else if target.starts_with("pipe:[") && target.ends_with(']') {
            pipes += 1;
        } else {
            return Err("descriptor has no startup, socket or pipe owner".to_owned());
        }
    }
    if !fixed.is_empty()
        || sockets != sample.descriptors.observed_tcp_sockets
        || pipes != sample.descriptors.observed_pipe_fds
    {
        return Err("descriptor census differs from retained raw counts".to_owned());
    }
    if let Some(actual) = &sample.descriptors.reconciliation {
        let expected = reconcile(&observed, sockets, pipes, policy.listener_sockets)?;
        if actual.active_sockets != expected.active_sockets
            || actual.active_relay_fds != expected.active_relay_fds
            || actual.reserved_dynamic_permits != expected.reserved_dynamic_permits
        {
            return Err("normalized ownership reconciliation differs from observations".to_owned());
        }
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

/// Derive the descriptor inventory and capacity bounds before workload starts.
/// Subsequent observations must use this same policy, never refit their census.
///
/// # Errors
/// Missing startup authorities or limits cannot establish a baseline.
pub fn startup_policy(raw: &Observation, listeners: u64) -> Result<Policy, String> {
    let ownership = read_ownership(raw, listeners)?;
    let mut fixed_descriptor_targets: Vec<_> = raw
        .descriptors
        .values()
        .filter(|target| !target.starts_with("socket:[") && !target.starts_with("pipe:["))
        .cloned()
        .collect();
    // Harness pipes inherited from the collector are startup inventory, not
    // product permits. Match multiset-style so duplicate inodes stay paired.
    let mut inherited = raw.collector_pipe_targets.clone();
    for target in raw.descriptors.values() {
        if !target.starts_with("pipe:[") {
            continue;
        }
        if let Some(index) = inherited.iter().position(|candidate| candidate == target) {
            inherited.swap_remove(index);
            fixed_descriptor_targets.push(target.clone());
        }
    }
    Ok(Policy {
        runtime_unix_sockets: runtime_unix_count(raw)?,
        fixed_fds: u64::try_from(fixed_descriptor_targets.len())
            .map_err(|_| "descriptor count overflow")?,
        fixed_descriptor_targets,
        listener_sockets: listeners,
        idle_inbound_capacity: ownership.pre_auth_idle_capacity,
        dynamic_fd_budget: ownership.fd_capacity,
        pipe_pair_capacity: ownership.pipe_capacity,
        warm_socket_capacity: ownership.warm_capacity,
        // Both remain additionally subject to the one shared descriptor budget.
        active_socket_capacity: ownership.fd_capacity,
        relay_fd_capacity: ownership.fd_capacity,
        soft_fd_limit: field(
            raw.limits.as_deref().ok_or("missing startup limits")?,
            "Max open files",
        )?,
        replay_capacity: ownership.replay_capacity,
        replay_expiry_ms: ownership.replay_expiry_ms,
        retirement_deadline_ms: ownership.retirement_deadline_ms,
    })
}

/// Count pipe FDs that are not part of the fixed startup inventory.
fn dynamic_pipe_fds(raw: &Observation, policy: &Policy) -> Result<u64, String> {
    let mut fixed_pipes: Vec<_> = policy
        .fixed_descriptor_targets
        .iter()
        .filter(|target| target.starts_with("pipe:["))
        .cloned()
        .collect();
    let mut pipes = 0_u64;
    for target in raw.descriptors.values() {
        if !(target.starts_with("pipe:[") && target.ends_with(']')) {
            continue;
        }
        if let Some(index) = fixed_pipes.iter().position(|fixed| fixed == target) {
            fixed_pipes.swap_remove(index);
            continue;
        }
        pipes = pipes.checked_add(1).ok_or("pipe count overflow")?;
    }
    if !fixed_pipes.is_empty() {
        return Err("fixed pipe inventory is missing from the descriptor census".to_owned());
    }
    Ok(pipes)
}

fn reconcile(
    ownership: &Ownership,
    sockets: u64,
    pipes: u64,
    listeners: u64,
) -> Result<super::schema::DescriptorReconciliation, String> {
    let active_sockets = sockets
        .checked_sub(listeners)
        .and_then(|count| count.checked_sub(ownership.warm_sockets))
        .and_then(|count| count.checked_sub(ownership.owners.pre_auth_idle_connections))
        .ok_or("ownership evidence is not coherent: socket owners exceed census")?;
    let active_relay_fds = ownership
        .pipe_pairs
        .checked_mul(2)
        .and_then(|retained| pipes.checked_sub(retained))
        .ok_or("ownership evidence is not coherent: retained pipes exceed census")?;
    let dynamic = sockets
        .checked_sub(listeners)
        .and_then(|sockets| sockets.checked_add(pipes))
        .ok_or("dynamic descriptor overflow")?;
    let reserved = ownership
        .permits
        .checked_sub(dynamic)
        .ok_or("ownership evidence is not coherent: census exceeds recorded permits")?;
    Ok(super::schema::DescriptorReconciliation {
        active_sockets,
        active_relay_fds,
        reserved_dynamic_permits: reserved,
    })
}

/// Reconstruct a quiet checkpoint, including its required ownership accounting.
/// The caller retains the raw observation even when reconciliation fails.
///
/// # Errors
/// Rejects missing fields, inconsistent accounting, raw reads and identity.
pub fn normalize(
    raw: &Observation,
    policy: &Policy,
    role: &str,
    artifact: Artifact,
) -> Result<Sample, String> {
    normalize_with_ownership(raw, policy, role, artifact, true)
}

/// Normalize an active-load census without subtracting asynchronous owner logs.
///
/// # Errors
/// Rejects invalid reads, identity, raw census categories and log provenance.
pub fn normalize_active(
    raw: &Observation,
    policy: &Policy,
    role: &str,
    artifact: Artifact,
) -> Result<Sample, String> {
    normalize_with_ownership(raw, policy, role, artifact, false)
}

#[allow(clippy::too_many_lines)]
fn normalize_with_ownership(
    raw: &Observation,
    policy: &Policy,
    role: &str,
    artifact: Artifact,
    reconcile_ownership: bool,
) -> Result<Sample, String> {
    verify_read(raw)?;
    let ownership =
        read_ownership_at_checkpoint(raw, policy.listener_sockets, reconcile_ownership)?;
    let status = raw.status.as_deref().ok_or("missing status")?;
    let smaps = raw.smaps_rollup.as_deref().ok_or("missing smaps_rollup")?;
    let unix_count = runtime_unix_count(raw)?;
    let sockets = u64::try_from(
        raw.descriptors
            .values()
            .filter(|target| target.starts_with("socket:["))
            .count(),
    )
    .map_err(|_| "socket count overflow")?
    .checked_sub(unix_count)
    .ok_or("Unix socket count overflow")?;
    let pipes = dynamic_pipe_fds(raw, policy)?;
    let reconciliation = if reconcile_ownership {
        Some(reconcile(
            &ownership,
            sockets,
            pipes,
            policy.listener_sockets,
        )?)
    } else {
        None
    };
    let sample = Sample {
        observation: artifact,
        role: role.to_owned(),
        process: ProcessIdentity {
            pid: raw.pid,
            start_ticks: raw
                .initial_start_ticks
                .as_deref()
                .ok_or("missing start ticks")?
                .parse()
                .map_err(|_| "invalid start ticks")?,
            boot_id: raw
                .boot_id
                .as_deref()
                .ok_or("missing boot identity")?
                .trim()
                .to_owned(),
            executable_sha256: raw
                .initial_executable_sha256
                .clone()
                .ok_or("missing executable identity")?,
        },
        rss_kib: field(status, "VmRSS:")?,
        hwm_kib: field(status, "VmHWM:")?,
        pss_kib: field(smaps, "Pss:")?,
        anonymous_kib: field(smaps, "Anonymous:")?,
        threads: field(status, "Threads:")?,
        descriptors: Descriptors {
            runtime_unix_sockets: unix_count,
            total: u64::try_from(raw.descriptors.len()).map_err(|_| "descriptor overflow")?,
            fixed: policy.fixed_fds,
            listener_sockets: policy.listener_sockets,
            idle_inbound_sockets: ownership.owners.pre_auth_idle_connections,
            warm_sockets: ownership.warm_sockets,
            observed_tcp_sockets: sockets,
            observed_pipe_fds: pipes,
            reconciliation,
            retained_pipe_pairs: ownership.pipe_pairs,
            dirty_retained_pipe_bytes: ownership.pipe_bytes,
            held_dynamic_permits: ownership.permits,
            // Verification below must account for every descriptor before this
            // sample is returned. Unknown targets cannot be classified away.
            unexplained: 0,
        },
        owners: ownership.owners,
    };
    verify(raw, &sample, policy)?;
    Ok(sample)
}
