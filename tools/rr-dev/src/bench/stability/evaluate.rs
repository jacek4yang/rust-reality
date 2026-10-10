//! Offline acceptance decisions. No subprocesses, timers, or sampling windows.
#![allow(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::schema::{self, Cell, Contract, Evidence, Policy, Sample, Transfer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Pass,
    Fail,
    NotRun,
    Invalid,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub verdict: Verdict,
    pub scope: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn reject(&mut self, verdict: Verdict, scope: &str, reason: &str) {
        self.findings.push(Finding {
            verdict,
            scope: scope.to_owned(),
            reason: reason.to_owned(),
        });
        // INVALID evidence cannot substantiate a verdict, even if another case
        // has already demonstrated failure. Preserve both findings.
        self.verdict = [
            Verdict::Invalid,
            Verdict::Fail,
            Verdict::NotRun,
            Verdict::Pass,
        ]
        .into_iter()
        .find(|value| *value == self.verdict || *value == verdict)
        .expect("the precedence contains every verdict");
    }

    pub(super) fn require(&mut self, condition: bool, verdict: Verdict, scope: &str, reason: &str) {
        if !condition {
            self.reject(verdict, scope, reason);
        }
    }

    pub(super) fn extend(&mut self, other: Self) {
        for finding in other.findings {
            self.reject(finding.verdict, &finding.scope, &finding.reason);
        }
    }
}

pub fn digest(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[allow(clippy::too_many_lines)]
pub fn evaluate(evidence: &Evidence, contract_sha256: &str) -> Report {
    let contract: Contract =
        serde_json::from_str(schema::CONTRACT).expect("compiled contract is valid");
    let mut report = Report {
        verdict: Verdict::Pass,
        findings: Vec::new(),
    };
    report.require(
        contract.schema == "rr-stability-contract/v1"
            && contract.resource_sampling == "active-ceilings-recovery-ownership",
        Verdict::Invalid,
        "contract",
        "unknown contract",
    );
    report.require(
        evidence.schema == "rr-stability-evidence/v1",
        Verdict::Invalid,
        "evidence",
        "unknown evidence schema",
    );
    let identity = &evidence.identity;
    report.require(
        digest(&identity.source_commit, 40),
        Verdict::Invalid,
        "identity",
        "missing source commit",
    );
    report.require(
        identity.contract.sha256 == contract_sha256,
        Verdict::Invalid,
        "identity",
        "contract differs from the frozen evaluator contract",
    );
    for artifact in [
        &identity.source_archive,
        &identity.candidate,
        &identity.evaluator,
        &identity.contract,
        &identity.environment,
        &identity.workload,
    ] {
        report.require(
            digest(&artifact.sha256, 64) && !artifact.path.is_empty(),
            Verdict::Invalid,
            "identity",
            "incomplete artifact binding",
        );
    }
    let mut check_names = BTreeSet::new();
    for check in &evidence.checks {
        report.require(
            check_names.insert(check.name.as_str())
                && contract.required_checks.contains(&check.name),
            Verdict::Invalid,
            &check.name,
            "duplicate or unknown required check",
        );
        report.require(
            check.source_commit == identity.source_commit
                && check.candidate_sha256 == identity.candidate.sha256,
            Verdict::Invalid,
            &check.name,
            "check belongs to another candidate",
        );
        report.require(
            !check.argv.is_empty()
                && !check.output.path.is_empty()
                && digest(&check.output.sha256, 64),
            Verdict::Invalid,
            &check.name,
            "missing command or raw receipt",
        );
        report.require(
            check.completed && check.executed_cases > 0,
            Verdict::Invalid,
            &check.name,
            "incomplete or empty check",
        );
        report.require(
            check.exit_code == Some(0) && check.failed_cases == 0,
            Verdict::Fail,
            &check.name,
            "command failed",
        );
    }
    for required in &contract.required_checks {
        if !check_names.contains(required.as_str()) {
            report.reject(Verdict::NotRun, required, "required check not run");
        }
    }
    let mut cells = BTreeSet::new();
    // Receipt identity must be globally unique, including both fault and stress
    // cases; a stale upload cannot be reused under a different cycle label.
    let mut receipts = BTreeSet::new();
    let mut upload_paths = BTreeSet::new();
    for cell in &evidence.cells {
        report.require(
            cells.insert(cell.name.as_str()) && contract.cells.contains(&cell.name),
            Verdict::Invalid,
            &cell.name,
            "duplicate or unknown cell",
        );
        if !cell.started {
            report.reject(Verdict::NotRun, &cell.name, "cell not run");
            report.require(
                cell.cycles.is_empty() && cell.faults.is_empty() && cell.integrity.is_empty(),
                Verdict::Invalid,
                &cell.name,
                "unstarted cell contains observations",
            );
            continue;
        }
        report.require(
            cell.completed && cell.started_unix_ms > 0,
            Verdict::Invalid,
            &cell.name,
            "cell did not finalize",
        );
        report.require(
            digest(&cell.terminal.sha256, 64),
            Verdict::Invalid,
            &cell.name,
            "missing terminal receipt",
        );
        report.require(
            cell.unexpected_exits == 0
                && cell.panics == 0
                && cell.oom_kills == 0
                && cell.unexpected_rejections == 0,
            Verdict::Fail,
            &cell.name,
            "unexpected exit, panic, OOM, or protocol/authentication rejection",
        );
        evaluate_cell(&mut report, evidence, &contract, cell);
        for transfer in cell
            .cycles
            .iter()
            .flat_map(|cycle| &cycle.transfers)
            .chain(&cell.integrity)
            .chain(cell.faults.iter().flat_map(|fault| {
                fault
                    .recovery_transfers
                    .iter()
                    .chain(&fault.during_transfers)
                    .chain(std::iter::once(&fault.affected_prefix))
            }))
        {
            evaluate_transfer(
                &mut report,
                &contract,
                &cell.name,
                transfer,
                &mut receipts,
                &mut upload_paths,
            );
        }
    }
    for required in &contract.cells {
        if !cells.contains(required.as_str()) {
            report.reject(
                Verdict::NotRun,
                required,
                "required topology/profile not run",
            );
        }
    }
    report
}

pub(super) fn same_names<'a>(actual: impl Iterator<Item = &'a str>, required: &[String]) -> bool {
    let actual: Vec<_> = actual.collect();
    actual.len() == required.len()
        && actual.into_iter().collect::<BTreeSet<_>>()
            == required.iter().map(String::as_str).collect()
}

#[allow(clippy::too_many_lines)]
fn evaluate_cell(report: &mut Report, evidence: &Evidence, contract: &Contract, cell: &Cell) {
    let scope = cell.name.as_str();
    let mut observations = BTreeSet::new();
    for sample in cell
        .cycles
        .iter()
        .flat_map(|cycle| &cycle.checkpoints)
        .chain(cell.faults.iter().flat_map(|fault| &fault.checkpoints))
        .chain(&cell.integrity_checkpoints)
        .flat_map(|checkpoint| &checkpoint.samples)
    {
        report.require(
            digest(&sample.observation.sha256, 64)
                && observations.insert(&sample.observation.sha256),
            Verdict::Invalid,
            scope,
            "missing or reused raw observation",
        );
    }
    report.require(
        same_names(
            cell.roles.iter().map(|role| role.name.as_str()),
            &contract.roles,
        ),
        Verdict::Invalid,
        scope,
        "role coverage is incomplete or duplicated",
    );
    report.require(
        cell.roles
            .iter()
            .map(|role| &role.process.boot_id)
            .collect::<BTreeSet<_>>()
            .len()
            == 3,
        Verdict::Invalid,
        scope,
        "three distinct system VM boot identities are required",
    );
    for role in &cell.roles {
        let process = &role.process;
        report.require(
            process.pid > 0
                && process.start_ticks > 0
                && !process.boot_id.is_empty()
                && process.executable_sha256 == evidence.identity.candidate.sha256,
            Verdict::Invalid,
            scope,
            "invalid initial process or executable identity",
        );
        report.require(
            role.vcpus > 0
                && role.memory_limit_bytes > 0
                && role.swap_limit_bytes == 0
                && digest(&role.startup.sha256, 64),
            Verdict::Invalid,
            scope,
            "missing startup policy or machine limits",
        );
        if cell.name.ends_with("/constrained") && role.name == "landing" {
            report.require(
                role.vcpus == 1 && role.memory_limit_bytes == 1_073_741_824,
                Verdict::Invalid,
                scope,
                "constrained LANDING is not 1 vCPU / 1 GiB",
            );
        }
        if cell.name.ends_with("/ordinary") && role.name == "landing" {
            report.require(
                role.vcpus >= 2,
                Verdict::Invalid,
                scope,
                "ordinary LANDING must exercise multiple workers",
            );
        }
        let policy = &role.policy;
        let recovered_at = *contract
            .checkpoint_offsets_ms
            .last()
            .expect("recovery checkpoint");
        report.require(
            policy.dynamic_fd_budget > 0
                && policy.soft_fd_limit > 0
                && policy.replay_expiry_ms > 0
                && policy.replay_expiry_ms <= recovered_at
                && policy.retirement_deadline_ms > 0
                && policy.retirement_deadline_ms <= recovered_at,
            Verdict::Invalid,
            scope,
            "startup policy does not fit the frozen recovery schedule",
        );
    }
    report.require(
        cell.cycles.len() == contract.cycles,
        Verdict::Invalid,
        scope,
        "omitted or extra stress cycles",
    );
    for (index, cycle) in cell.cycles.iter().enumerate() {
        let scheduled_start = u64::try_from(index)
            .ok()
            .and_then(|index| index.checked_mul(contract.cycle_interval_ms));
        report.require(
            cycle.index == index
                && Some(cycle.started_ms) == scheduled_start
                && contract.concurrency.get(index) == Some(&cycle.concurrency),
            Verdict::Invalid,
            scope,
            "cycle ordering, schedule or concurrency was substituted",
        );
        report.require(
            cycle.checkpoints.len() == contract.checkpoint_offsets_ms.len(),
            Verdict::Invalid,
            scope,
            "missing phase checkpoint",
        );
        for line in ["line-a", "line-b"] {
            report.require(
                cycle
                    .transfers
                    .iter()
                    .filter(|transfer| transfer.line == line)
                    .count()
                    >= usize::try_from(contract.transfers_per_line).unwrap_or(usize::MAX),
                Verdict::Invalid,
                scope,
                "insufficient transfers per LINE per cycle",
            );
            report.require(
                peak_concurrency(
                    cycle
                        .transfers
                        .iter()
                        .filter(|transfer| transfer.line == line),
                ) == Some(cycle.concurrency),
                Verdict::Invalid,
                scope,
                "transfer intervals did not exercise the prescribed concurrency",
            );
        }
        for transfer in &cycle.transfers {
            let load_end = cycle
                .started_ms
                .checked_add(contract.checkpoint_offsets_ms[4]);
            report.require(
                cycle
                    .started_ms
                    .checked_add(contract.load_start_ms)
                    .is_some_and(|start| transfer.started_ms >= start)
                    && load_end.is_some_and(|end| transfer.completed_ms <= end),
                Verdict::Invalid,
                scope,
                "transfer lies outside its predefined load window",
            );
        }
        for (checkpoint_index, checkpoint) in cycle.checkpoints.iter().enumerate() {
            let scheduled = cycle.started_ms.checked_add(checkpoint.offset_ms);
            report.require(
                contract.checkpoint_offsets_ms.get(checkpoint_index) == Some(&checkpoint.offset_ms)
                    && scheduled.is_some_and(|time| {
                        checkpoint.observed_ms >= time
                            && checkpoint.observed_ms - time <= contract.checkpoint_tolerance_ms
                    }),
                Verdict::Invalid,
                scope,
                "sample missed or substituted its fixed observation window",
            );
            report.require(
                same_names(
                    checkpoint.samples.iter().map(|sample| sample.role.as_str()),
                    &contract.roles,
                ),
                Verdict::Invalid,
                scope,
                "checkpoint has missing or duplicated roles",
            );
            for sample in &checkpoint.samples {
                let Some(role) = cell.roles.iter().find(|role| role.name == sample.role) else {
                    continue;
                };
                report.require(
                    sample.process == role.process,
                    Verdict::Fail,
                    scope,
                    "unexpected restart or changed executable during uninterrupted stress",
                );
                let recovered = checkpoint.offset_ms
                    == *contract
                        .checkpoint_offsets_ms
                        .last()
                        .expect("recovery checkpoint");
                evaluate_sample(report, contract, cell, role, sample, recovered);
            }
        }
    }
    report.require(
        same_names(
            cell.faults.iter().map(|fault| fault.name.as_str()),
            &contract.faults,
        ),
        Verdict::Invalid,
        scope,
        "fault coverage is incomplete or duplicated",
    );
    let mut expected_processes: BTreeMap<_, _> = cell
        .roles
        .iter()
        .map(|role| (role.name.clone(), role.process.clone()))
        .collect();
    let first_fault = contract
        .cycle_interval_ms
        .saturating_mul(contract.cycles as u64);
    for (index, fault) in cell.faults.iter().enumerate() {
        report.require(
            fault.actions.len() == contract.roles.len() * 2
                && fault
                    .actions
                    .iter()
                    .all(|artifact| digest(&artifact.sha256, 64)),
            Verdict::Invalid,
            scope,
            "missing fault action evidence",
        );
        report.require(
            u64::try_from(index)
                .ok()
                .and_then(|index| index.checked_mul(contract.fault_interval_ms))
                .and_then(|offset| first_fault.checked_add(offset))
                == Some(fault.started_ms)
                && contract.faults.get(index) == Some(&fault.name)
                && fault.restored_ms.checked_sub(fault.started_ms)
                    == Some(contract.fault_duration(&fault.name)),
            Verdict::Invalid,
            scope,
            "fault order, start or duration differs from the frozen schedule",
        );
        for (bindings, before) in [
            (&fault.before_processes, true),
            (&fault.after_processes, false),
        ] {
            report.require(
                same_names(
                    bindings.iter().map(|binding| binding.role.as_str()),
                    &contract.roles,
                ),
                Verdict::Invalid,
                scope,
                "missing fault process bindings",
            );
            for binding in bindings {
                let Some(expected) = expected_processes.get(&binding.role) else {
                    continue;
                };
                if !before && fault.name == "landing-restart" && binding.role == "landing" {
                    report.require(binding.identity.pid > 0 && binding.identity.start_ticks > expected.start_ticks && binding.identity.boot_id == expected.boot_id && binding.identity.executable_sha256 == expected.executable_sha256, Verdict::Fail, scope, "controlled restart changed guest or binary, or failed to replace the process");
                } else {
                    report.require(
                        binding.identity == *expected,
                        Verdict::Fail,
                        scope,
                        "unplanned process replacement around a fault",
                    );
                }
            }
        }
        expected_processes = fault
            .after_processes
            .iter()
            .map(|binding| (binding.role.clone(), binding.identity.clone()))
            .collect();

        report.require(
            fault.checkpoints.len() == contract.fault_checkpoint_offsets_ms.len(),
            Verdict::Invalid,
            scope,
            "missing post-fault ownership checkpoints",
        );
        for (index, checkpoint) in fault.checkpoints.iter().enumerate() {
            let scheduled = fault.started_ms.checked_add(checkpoint.offset_ms);
            report.require(
                contract.fault_checkpoint_offsets_ms.get(index) == Some(&checkpoint.offset_ms)
                    && scheduled.is_some_and(|time| {
                        checkpoint.observed_ms >= time
                            && checkpoint.observed_ms - time <= contract.checkpoint_tolerance_ms
                    })
                    && same_names(
                        checkpoint.samples.iter().map(|sample| sample.role.as_str()),
                        &contract.roles,
                    ),
                Verdict::Invalid,
                scope,
                "missing, late or substituted post-fault checkpoint",
            );
            for sample in &checkpoint.samples {
                report.require(
                    expected_processes.get(&sample.role) == Some(&sample.process),
                    Verdict::Fail,
                    scope,
                    "post-fault sample changed process identity",
                );
                if let Some(role) = cell.roles.iter().find(|role| role.name == sample.role) {
                    let recovered =
                        Some(&checkpoint.offset_ms) == contract.fault_checkpoint_offsets_ms.last();
                    evaluate_sample(report, contract, cell, role, sample, recovered);
                }
            }
        }

        report.require(
            fault.restored_ms >= fault.started_ms
                && fault.first_admission_ms >= fault.restored_ms
                && fault.first_admission_ms - fault.restored_ms <= contract.recovery_deadline_ms,
            Verdict::Fail,
            scope,
            "fault recovery deadline exceeded",
        );
        report.require(
            fault.unexpected_failures == 0
                && fault
                    .expected_failures
                    .iter()
                    .all(|time| *time >= fault.started_ms && *time <= fault.restored_ms),
            Verdict::Fail,
            scope,
            "failure outside declared fault interval",
        );
        report.require(
            fault.recovery_transfers.len() >= 100
                && fault.recovery_transfers.iter().all(|transfer| {
                    transfer.started_ms >= fault.restored_ms
                        && fault
                            .restored_ms
                            .checked_add(contract.recovery_deadline_ms)
                            .is_some_and(|end| transfer.completed_ms <= end)
                }),
            Verdict::Invalid,
            scope,
            "missing fresh post-fault recovery transfers",
        );
        if fault.name == "line-a-partition" {
            report.require(
                fault
                    .during_transfers
                    .iter()
                    .any(|transfer| transfer.line == "line-b" && transfer.received_bytes > 0)
                    && fault.restored_ms.checked_sub(fault.started_ms) == Some(10_000),
                Verdict::Fail,
                scope,
                "LINE-B made no progress or partition duration changed",
            );
        }
        report.require(
            fault.during_transfers.iter().all(|transfer| {
                transfer.started_ms >= fault.started_ms
                    && transfer.completed_ms <= fault.restored_ms
            }),
            Verdict::Invalid,
            scope,
            "during-fault receipt lies outside its fixed interval",
        );
        evaluate_fault_workload(report, contract, cell, fault);
    }
    report.require(
        same_names(
            cell.final_processes
                .iter()
                .map(|binding| binding.role.as_str()),
            &contract.roles,
        ),
        Verdict::Invalid,
        scope,
        "missing final process identity verification",
    );
    for binding in &cell.final_processes {
        report.require(
            expected_processes.get(&binding.role) == Some(&binding.identity),
            Verdict::Fail,
            scope,
            "final process identity differs from the last verified process",
        );
    }
    evaluate_integrity_checkpoints(report, contract, cell, &expected_processes);
    for line in ["line-a", "line-b"] {
        for size in &contract.payload_bytes {
            for direction in &contract.directions {
                report.require(
                    cell.integrity.iter().any(|transfer| {
                        transfer.line == line
                            && transfer.direction == *direction
                            && transfer.expected_bytes == *size
                            && transfer.started_ms >= contract.integrity_start()
                            && transfer.completed_ms
                                <= contract
                                    .integrity_start()
                                    .saturating_add(contract.integrity_duration_ms)
                    }),
                    Verdict::Invalid,
                    scope,
                    "missing fresh 1/4 MiB directional integrity cell",
                );
            }
        }
    }
}

fn evaluate_fault_workload(
    report: &mut Report,
    contract: &Contract,
    cell: &Cell,
    fault: &schema::Fault,
) {
    let prefix = &fault.affected_prefix;
    report.require(
        prefix.line == "line-a"
            && prefix.direction == "download"
            && prefix.started_ms < fault.started_ms
            && prefix.completed_ms >= fault.started_ms
            && (fault.name == "landing-restart"
                || fault.name.starts_with("rtt-")
                || prefix.completed_ms > fault.restored_ms)
            && fault.expected_failures.len() == usize::from(fault.name == "landing-restart"),
        Verdict::Invalid,
        &cell.name,
        "continuity probe did not span its fault or failure was misclassified",
    );
    for line in ["line-a", "line-b"] {
        let during: Vec<_> = fault
            .during_transfers
            .iter()
            .filter(|transfer| transfer.line == line)
            .collect();
        let recovery: Vec<_> = fault
            .recovery_transfers
            .iter()
            .filter(|transfer| transfer.line == line)
            .collect();
        let impaired = fault.name != "landing-restart"
            && (fault.name != "line-a-partition" || line == "line-b");
        report.require(
            if impaired {
                during.len() >= usize::try_from(contract.transfers_per_line).unwrap_or(usize::MAX)
                    && peak_concurrency(during.into_iter())
                        == Some(contract.fault_concurrency(&fault.name))
            } else {
                during.is_empty()
            },
            Verdict::Invalid,
            &cell.name,
            "during-fault LINE coverage or concurrency was substituted",
        );
        report.require(
            recovery.len() >= usize::try_from(contract.transfers_per_line).unwrap_or(usize::MAX)
                && peak_concurrency(recovery.into_iter())
                    == Some(contract.fault_concurrency_per_line),
            Verdict::Invalid,
            &cell.name,
            "post-fault LINE coverage or concurrency was substituted",
        );
    }
    if fault.name.starts_with("rtt-") {
        report.require(
            peak_concurrency(fault.during_transfers.iter())
                == contract.rtt_concurrency_per_line.checked_mul(2),
            Verdict::Invalid,
            &cell.name,
            "RTT matrix did not exercise the contracted concurrent transfers across both LINEs",
        );
    }
}

fn evaluate_integrity_checkpoints(
    report: &mut Report,
    contract: &Contract,
    cell: &Cell,
    expected_processes: &BTreeMap<String, schema::ProcessIdentity>,
) {
    let offsets = contract.integrity_offsets();
    report.require(
        cell.integrity_checkpoints.len() == offsets.len(),
        Verdict::Invalid,
        &cell.name,
        "missing integrity recovery checkpoints",
    );
    for (index, checkpoint) in cell.integrity_checkpoints.iter().enumerate() {
        let scheduled = contract.integrity_start().checked_add(checkpoint.offset_ms);
        report.require(
            offsets.get(index) == Some(&checkpoint.offset_ms)
                && scheduled.is_some_and(|time| {
                    checkpoint.observed_ms >= time
                        && checkpoint.observed_ms - time <= contract.checkpoint_tolerance_ms
                })
                && same_names(
                    checkpoint.samples.iter().map(|sample| sample.role.as_str()),
                    &contract.roles,
                ),
            Verdict::Invalid,
            &cell.name,
            "integrity observation window or roles substituted",
        );
        for sample in &checkpoint.samples {
            report.require(
                expected_processes.get(&sample.role) == Some(&sample.process),
                Verdict::Fail,
                &cell.name,
                "unexpected process change during integrity recovery",
            );
            if let Some(role) = cell.roles.iter().find(|role| role.name == sample.role) {
                evaluate_sample(
                    report,
                    contract,
                    cell,
                    role,
                    sample,
                    Some(&checkpoint.offset_ms) == offsets.last(),
                );
            }
        }
    }
}

fn peak_concurrency<'a>(transfers: impl Iterator<Item = &'a Transfer>) -> Option<u64> {
    let mut events = Vec::new();
    for transfer in transfers {
        if transfer.started_ms >= transfer.completed_ms {
            return None;
        }
        events.push((transfer.started_ms, 1_i64));
        events.push((transfer.completed_ms, -1_i64));
    }
    events.sort_unstable();
    let mut active = 0_i64;
    let mut peak = 0_i64;
    for (_, change) in events {
        active = active.checked_add(change)?;
        peak = peak.max(active);
    }
    u64::try_from(peak).ok()
}


/// Scale VM RSS growth envelopes by role memory limit relative to 1 GiB.
///
/// Ordinary LANDING is provisioned at 2 GiB / 2 vCPU; constrained LANDING and
/// every LINE stay at 1 GiB. The contract's recovered/peak KiB budgets are the
/// 1 GiB unit; larger roles receive a proportional budget (ADR 0051).
pub(super) fn role_rss_growth_scale(memory_limit_bytes: u64) -> u64 {
    const GIB: u64 = 1_073_741_824;
    memory_limit_bytes.max(GIB) / GIB
}

fn evaluate_sample(
    report: &mut Report,
    contract: &Contract,
    cell: &Cell,
    role: &schema::Role,
    sample: &Sample,
    recovered: bool,
) {
    let scope = cell.name.as_str();
    evaluate_owners(report, scope, &role.policy, sample, recovered);
    let fd_ceiling = if role.name == "landing" {
        contract.peak_landing_fds
    } else if recovered {
        contract.recovered_line_fds
    } else {
        contract.peak_line_fds
    };
    report.require(
        sample.descriptors.total <= fd_ceiling,
        Verdict::Fail,
        scope,
        "unchanged peak/LINE descriptor envelope exceeded",
    );

    let baseline = cell
        .cycles
        .first()
        .and_then(|cycle| cycle.checkpoints.first())
        .and_then(|checkpoint| {
            checkpoint
                .samples
                .iter()
                .find(|baseline| baseline.role == sample.role)
        });
    if let Some(baseline) = baseline {
        // Ordinary LANDING is intentionally 2 GiB / 2 vCPU; constrained is 1 GiB.
        // A single KiB recovered/peak growth budget calibrated on 1 GiB falsely
        // fails the larger ordinary footprint (ADR 0051). Scale by role GiB.
        let scale = role_rss_growth_scale(role.memory_limit_bytes);
        let rss_limit = if recovered {
            contract.recovered_rss_growth_kib
        } else {
            contract.peak_rss_growth_kib
        }
        .saturating_mul(scale);
        let peak_hwm_limit = contract.peak_rss_growth_kib.saturating_mul(scale);
        let thread_limit = if recovered {
            contract.recovered_thread_growth
        } else {
            contract.peak_thread_growth
        };
        report.require(
            sample.rss_kib.saturating_sub(baseline.rss_kib) <= rss_limit
                && sample.hwm_kib.saturating_sub(baseline.hwm_kib) <= peak_hwm_limit
                && sample.threads.saturating_sub(baseline.threads) <= thread_limit,
            Verdict::Fail,
            scope,
            "absolute memory/thread envelope exceeded",
        );
    } else {
        report.reject(Verdict::Invalid, scope, "missing process baseline");
    }
    report.require(
        sample.rss_kib > 0
            && sample.hwm_kib >= sample.rss_kib
            && sample.hwm_kib <= role.memory_limit_bytes / 1024
            && sample.rss_kib <= role.memory_limit_bytes / 1024
            && sample.pss_kib > 0
            && sample.pss_kib <= sample.rss_kib
            && sample.anonymous_kib <= sample.rss_kib
            && sample.threads > 0,
        Verdict::Invalid,
        scope,
        "invalid or missing memory/thread observation",
    );
}

fn evaluate_owners(
    report: &mut Report,
    scope: &str,
    policy: &Policy,
    sample: &Sample,
    recovered: bool,
) {
    let fd = &sample.descriptors;
    // Kernel census and periodic owner counters have independent timestamps.
    // Active checkpoints enforce each authority's bounds without inventing a
    // same-instant subtraction between the two.
    let dynamic = fd
        .observed_tcp_sockets
        .checked_sub(fd.listener_sockets)
        .and_then(|sockets| sockets.checked_add(fd.observed_pipe_fds));
    let total = fd
        .observed_tcp_sockets
        .checked_add(fd.observed_pipe_fds)
        .and_then(|total| total.checked_add(fd.fixed))
        .and_then(|total| total.checked_add(fd.runtime_unix_sockets));
    report.require(
        total == Some(fd.total) && fd.unexplained == 0,
        Verdict::Fail,
        scope,
        "unexplained descriptors or overflow in descriptor accounting",
    );
    report.require(
        fd.fixed == policy.fixed_fds
            && fd.runtime_unix_sockets == policy.runtime_unix_sockets
            && u64::try_from(policy.fixed_descriptor_targets.len()).ok() == Some(policy.fixed_fds)
            && fd.listener_sockets == policy.listener_sockets
            && fd.total <= policy.soft_fd_limit
            && dynamic.is_some_and(|value| value <= policy.dynamic_fd_budget)
            && fd.held_dynamic_permits <= policy.dynamic_fd_budget,
        Verdict::Fail,
        scope,
        "descriptor census or recorded permits exceed startup policy",
    );
    report.require(
        fd.retained_pipe_pairs <= policy.pipe_pair_capacity
            && fd.dirty_retained_pipe_bytes == 0
            && fd.warm_sockets <= policy.warm_socket_capacity
            && policy
                .pipe_pair_capacity
                .checked_mul(2)
                .and_then(|retained| retained.checked_add(policy.relay_fd_capacity))
                .is_some_and(|ceiling| fd.observed_pipe_fds <= ceiling)
            && policy
                .listener_sockets
                .checked_add(policy.warm_socket_capacity)
                .and_then(|count| count.checked_add(policy.idle_inbound_capacity))
                .and_then(|count| count.checked_add(policy.active_socket_capacity))
                .is_some_and(|ceiling| fd.observed_tcp_sockets <= ceiling),
        Verdict::Fail,
        scope,
        "dirty or excessive retained pool, socket, or relay descriptors",
    );
    let owners = &sample.owners;
    report.require(
        owners.replay_entries <= policy.replay_capacity
            && owners.pre_auth_idle_connections <= policy.idle_inbound_capacity
            && sample.descriptors.idle_inbound_sockets == owners.pre_auth_idle_connections,
        Verdict::Fail,
        scope,
        "replay or pre-auth ownership exceeded its fixed capacity or lost its socket binding",
    );
    if recovered {
        let Some(reconciliation) = &fd.reconciliation else {
            report.reject(
                Verdict::Invalid,
                scope,
                "recovery checkpoint lacks ownership reconciliation",
            );
            return;
        };
        report.require(
            dynamic.and_then(|owned| owned.checked_add(reconciliation.reserved_dynamic_permits))
                == Some(fd.held_dynamic_permits),
            Verdict::Invalid,
            scope,
            "recovery ownership evidence is not coherent",
        );
        report.require(
            reconciliation.active_sockets == 0
                && reconciliation.active_relay_fds == 0
                && reconciliation.reserved_dynamic_permits == policy.listener_sockets
                && owners.admitted_connections == owners.pre_auth_idle_connections
                && owners.tracked_connection_tasks == owners.pre_auth_idle_connections
                && owners.retired_generations == 0
                && owners.handshakes == 0
                && owners.fallbacks == 0
                && owners.crypto_operations == 0
                && owners.dns_lookups == 0
                && owners.replay_entries == 0,
            Verdict::Fail,
            scope,
            "transient ownership survived its recovery deadline",
        );
    }
}

/// Native qualification shares the same owner/accounting rules while retaining
/// its existing, stricter memory and thread envelopes.
pub fn evaluate_native_resources(
    policy: &Policy,
    baseline: &Sample,
    sample: &Sample,
    recovered: bool,
) -> Report {
    let contract: Contract = serde_json::from_str(schema::CONTRACT).expect("compiled contract");
    let mut report = Report {
        verdict: Verdict::Pass,
        findings: Vec::new(),
    };
    let scope = sample.role.as_str();
    report.require(
        sample.process == baseline.process,
        Verdict::Fail,
        scope,
        "native process changed identity",
    );
    evaluate_owners(&mut report, scope, policy, sample, recovered);
    report.require(
        sample.hwm_kib >= sample.rss_kib
            && sample.rss_kib > 0
            && sample.pss_kib > 0
            && sample.pss_kib <= sample.rss_kib
            && sample.anonymous_kib <= sample.rss_kib
            && sample.threads > 0,
        Verdict::Invalid,
        scope,
        "invalid native memory observation",
    );
    report.require(
        sample.hwm_kib.saturating_sub(baseline.hwm_kib) <= contract.native_peak_hwm_growth_kib
            && sample.threads.saturating_sub(baseline.threads) <= contract.native_thread_growth
            && (!recovered
                || sample.rss_kib.saturating_sub(baseline.rss_kib)
                    <= contract.native_recovered_rss_growth_kib),
        Verdict::Fail,
        scope,
        "native absolute memory/thread envelope exceeded",
    );
    report
}

fn evaluate_transfer(
    report: &mut Report,
    contract: &Contract,
    scope: &str,
    transfer: &Transfer,
    receipts: &mut BTreeSet<String>,
    paths: &mut BTreeSet<String>,
) {
    report.require(
        !transfer.id.is_empty()
            && receipts.insert(transfer.id.clone())
            && ["line-a", "line-b"].contains(&transfer.line.as_str())
            && contract.directions.contains(&transfer.direction),
        Verdict::Invalid,
        scope,
        "duplicate receipt or invalid transfer identity",
    );
    report.require(
        transfer.completed_ms >= transfer.started_ms
            && transfer.completed_ms - transfer.started_ms <= contract.transfer_deadline_ms,
        Verdict::Fail,
        scope,
        "transfer deadline exceeded",
    );
    report.require(
        transfer.expected_bytes > 0
            && transfer.received_bytes == transfer.expected_bytes
            && digest(&transfer.expected_sha256, 64)
            && transfer.received_sha256 == transfer.expected_sha256,
        Verdict::Fail,
        scope,
        "payload or received prefix mismatch",
    );
    if transfer.direction == "download" {
        report.require(
            transfer.upload.is_none(),
            Verdict::Invalid,
            scope,
            "download carries an unrelated upload receipt",
        );
    } else if let Some(upload) = &transfer.upload {
        report.require(
            !upload.path.is_empty()
                && paths.insert(upload.path.clone())
                && upload.receipt_offset >= upload.log_boundary
                && upload.appended_matches == 1
                && upload.bytes == transfer.expected_bytes
                && upload.sha256 == transfer.expected_sha256,
            Verdict::Fail,
            scope,
            "stale, duplicate, missing or corrupt upload receipt",
        );
    } else {
        report.reject(Verdict::Invalid, scope, "upload lacks an origin receipt");
    }
}
