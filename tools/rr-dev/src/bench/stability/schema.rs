//! Strict stability evidence vocabulary, shared verbatim with the fuzz target.
//!
//! No I/O or verdict calculation lives here. Integer observations reject NaN,
//! infinity, negative values and overflow at the deserialization boundary.
#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

pub const CONTRACT: &str = include_str!("../../../../../benchmarks/contracts/stability.json");
pub const MAX_EVIDENCE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    pub schema: String,
    pub cycles: usize,
    pub transfers_per_line: u64,
    pub concurrency: Vec<u64>,
    pub checkpoint_offsets_ms: Vec<u64>,
    pub checkpoint_tolerance_ms: u64,
    pub cycle_interval_ms: u64,
    pub recovery_deadline_ms: u64,
    pub transfer_deadline_ms: u64,
    pub recovered_rss_growth_kib: u64,
    pub peak_rss_growth_kib: u64,
    pub recovered_thread_growth: u64,
    pub peak_thread_growth: u64,
    pub recovered_line_fds: u64,
    pub peak_line_fds: u64,
    pub peak_landing_fds: u64,
    pub cells: Vec<String>,
    pub roles: Vec<String>,
    pub faults: Vec<String>,
    pub payload_bytes: Vec<u64>,
    pub directions: Vec<String>,
    pub required_checks: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub source_commit: String,
    pub source_archive: Artifact,
    pub candidate: Artifact,
    pub evaluator: Artifact,
    pub contract: Artifact,
    pub environment: Artifact,
    pub workload: Artifact,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub schema: String,
    pub identity: Identity,
    pub checks: Vec<Check>,
    pub cells: Vec<Cell>,
}

/// A tool-owned command receipt, with raw output and exact candidate binding.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub name: String,
    pub source_commit: String,
    pub candidate_sha256: String,
    pub argv: Vec<String>,
    pub exit_code: Option<i32>,
    pub completed: bool,
    pub executed_cases: u64,
    pub failed_cases: u64,
    pub output: Artifact,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cell {
    pub name: String,
    pub started: bool,
    pub completed: bool,
    pub roles: Vec<Role>,
    pub final_processes: Vec<ProcessBinding>,
    pub cycles: Vec<Cycle>,
    pub faults: Vec<Fault>,
    pub integrity: Vec<Transfer>,
    pub unexpected_exits: u64,
    pub panics: u64,
    pub oom_kills: u64,
    pub unexpected_rejections: u64,
    pub terminal: Artifact,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_ticks: u64,
    pub boot_id: String,
    pub executable_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessBinding {
    pub role: String,
    pub identity: ProcessIdentity,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Role {
    pub name: String,
    pub process: ProcessIdentity,
    pub vcpus: u64,
    pub memory_limit_bytes: u64,
    pub swap_limit_bytes: u64,
    pub policy: Policy,
    pub startup: Artifact,
}

/// Capacities derived from actual startup policy, never fitted to observations.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub fixed_fds: u64,
    pub listener_sockets: u64,
    pub dynamic_fd_budget: u64,
    pub pipe_pair_capacity: u64,
    pub warm_socket_capacity: u64,
    pub active_socket_capacity: u64,
    pub relay_fd_capacity: u64,
    pub soft_fd_limit: u64,
    pub replay_capacity: u64,
    pub replay_expiry_ms: u64,
    pub retirement_deadline_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cycle {
    pub index: usize,
    pub started_ms: u64,
    pub concurrency: u64,
    pub transfers: Vec<Transfer>,
    pub checkpoints: Vec<Checkpoint>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub offset_ms: u64,
    pub observed_ms: u64,
    pub samples: Vec<Sample>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub role: String,
    pub process: ProcessIdentity,
    pub rss_kib: u64,
    pub pss_kib: u64,
    pub anonymous_kib: u64,
    pub threads: u64,
    pub descriptors: Descriptors,
    pub owners: Owners,
}

/// OS census reconciled with owner counts, not merely FD target categories.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptors {
    pub total: u64,
    pub fixed: u64,
    pub listener_sockets: u64,
    pub warm_sockets: u64,
    pub active_sockets: u64,
    pub active_relay_fds: u64,
    pub retained_pipe_pairs: u64,
    pub dirty_retained_pipe_bytes: u64,
    pub held_dynamic_permits: u64,
    pub reserved_dynamic_permits: u64,
    pub unexplained: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Owners {
    pub active_connections: u64,
    pub completed_connections: u64,
    pub retired_generations: u64,
    pub cancelled_operations: u64,
    pub replay_entries: u64,
    pub expired_replay_entries: u64,
    pub unattributed_retained_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Transfer {
    pub id: String,
    pub line: String,
    pub direction: String,
    pub started_ms: u64,
    pub completed_ms: u64,
    pub expected_bytes: u64,
    pub received_bytes: u64,
    pub expected_sha256: String,
    pub received_sha256: String,
    pub upload: Option<UploadReceipt>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UploadReceipt {
    pub path: String,
    pub log_boundary: u64,
    pub receipt_offset: u64,
    pub appended_matches: u64,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Fault {
    pub name: String,
    pub started_ms: u64,
    pub restored_ms: u64,
    pub first_admission_ms: u64,
    pub before_processes: Vec<ProcessBinding>,
    pub after_processes: Vec<ProcessBinding>,
    pub recovery_transfers: Vec<Transfer>,
    pub affected_prefix: Transfer,
    pub line_b_progress_bytes: u64,
    pub expected_failures: Vec<u64>,
    pub unexpected_failures: u64,
}

pub fn parse(bytes: &[u8]) -> Result<Evidence, String> {
    if bytes.len() > MAX_EVIDENCE_BYTES {
        return Err("stability evidence exceeds 64 MiB".to_owned());
    }
    serde_json::from_slice(bytes).map_err(|error| format!("invalid stability evidence: {error}"))
}
