//! Pure verification of a native resource receipt within stability evidence.

use std::collections::BTreeSet;

use super::{
    evaluate::{self, Report, Verdict},
    schema::{self, NativeEvidence, Sample},
};

/// Verify native coverage and ownership without trusting its recorded verdicts.
#[allow(clippy::too_many_lines)]
pub fn evaluate(
    receipt: &NativeEvidence,
    source: &str,
    candidate: &str,
    evaluator: &str,
    contract_sha256: &str,
) -> Report {
    let contract: schema::Contract =
        serde_json::from_str(schema::CONTRACT).expect("compiled contract");
    let mut report = Report {
        verdict: Verdict::Pass,
        findings: Vec::new(),
    };
    let scope = "native-resources";
    report.require(
        receipt.source_commit == source
            && receipt.candidate_sha256 == candidate
            && receipt.evaluator_sha256 == evaluator
            && receipt.contract_sha256 == contract_sha256,
        Verdict::Invalid,
        scope,
        "native receipt belongs to another source, executable, harness or contract",
    );
    report.require(
        receipt.primary_error.is_none() && receipt.finalization_errors.is_empty(),
        Verdict::Fail,
        scope,
        "native workload or final identity verification failed",
    );
    report.require(
        evaluate::same_names(
            receipt.policies.iter().map(|policy| policy.role.as_str()),
            &contract.native_roles,
        ),
        Verdict::Invalid,
        scope,
        "missing or duplicated native process policy",
    );
    let rounds = receipt
        .checkpoints
        .iter()
        .filter(|checkpoint| checkpoint.phase.starts_with("round-"))
        .count();
    report.require(
        rounds >= contract.native_minimum_rounds
            && receipt.duration_ms >= contract.native_duration_ms,
        Verdict::Invalid,
        scope,
        "native workload does not cover its required duration and rounds",
    );
    let mut phases = vec!["baseline".to_owned()];
    phases.extend((1..=rounds).map(|round| format!("round-{round}")));
    phases.extend(
        contract
            .native_recovery_offsets_ms
            .iter()
            .map(|offset| format!("recovery-{offset}")),
    );
    phases.push("terminal".to_owned());
    report.require(
        receipt
            .checkpoints
            .iter()
            .map(|checkpoint| &checkpoint.phase)
            .eq(phases.iter()),
        Verdict::Invalid,
        scope,
        "native phase sequence is missing, duplicated or substituted",
    );
    let (Some(workload), Some(recovery)) = (
        receipt.workload_started_unix_ms,
        receipt.recovery_started_unix_ms,
    ) else {
        report.reject(
            Verdict::Invalid,
            scope,
            "native workload/recovery epochs are missing",
        );
        return report;
    };
    report.require(
        workload > 0
            && recovery
                .checked_sub(workload)
                .is_some_and(|elapsed| elapsed >= receipt.duration_ms),
        Verdict::Invalid,
        scope,
        "native workload ended before its bound duration",
    );
    let last_offset = *contract
        .native_recovery_offsets_ms
        .last()
        .expect("native recovery");
    let mut hashes = BTreeSet::new();
    let mut previous = 0;
    let baseline = receipt.checkpoints.first();
    report.require(
        baseline.is_some_and(|baseline| {
            baseline
                .samples
                .iter()
                .map(|sample| sample.process.pid)
                .collect::<BTreeSet<_>>()
                .len()
                == contract.native_roles.len()
                && baseline
                    .samples
                    .iter()
                    .map(|sample| &sample.process.boot_id)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == 1
        }),
        Verdict::Invalid,
        scope,
        "native topology requires distinct processes on one kernel boot",
    );
    for checkpoint in &receipt.checkpoints {
        report.require(
            checkpoint.started_unix_ms >= previous,
            Verdict::Invalid,
            scope,
            "native checkpoint time moved backwards",
        );
        previous = checkpoint.started_unix_ms;
        let recovered =
            checkpoint.phase == "terminal" || checkpoint.phase == format!("recovery-{last_offset}");
        if checkpoint.phase == "baseline" {
            report.require(
                checkpoint.started_unix_ms < workload,
                Verdict::Invalid,
                scope,
                "native baseline overlaps workload",
            );
        } else if checkpoint.phase.starts_with("round-") {
            report.require(
                checkpoint.started_unix_ms >= workload && checkpoint.started_unix_ms <= recovery,
                Verdict::Invalid,
                scope,
                "native round is outside the workload interval",
            );
        } else if checkpoint.phase == "terminal" {
            report.require(
                recovery
                    .checked_add(last_offset)
                    .is_some_and(|time| checkpoint.started_unix_ms >= time),
                Verdict::Invalid,
                scope,
                "native terminal observation precedes recovery",
            );
        } else if let Some(offset) = checkpoint
            .phase
            .strip_prefix("recovery-")
            .and_then(|offset| offset.parse::<u64>().ok())
        {
            report.require(
                contract.native_recovery_offsets_ms.contains(&offset)
                    && recovery.checked_add(offset).is_some_and(|time| {
                        checkpoint.started_unix_ms >= time
                            && checkpoint.started_unix_ms - time <= contract.checkpoint_tolerance_ms
                    }),
                Verdict::Invalid,
                scope,
                "native recovery checkpoint missed its fixed window",
            );
        }
        report.require(
            checkpoint.errors.is_empty(),
            Verdict::Fail,
            scope,
            "native collection or resource check failed",
        );
        report.require(
            evaluate::same_names(
                checkpoint.samples.iter().map(|sample| sample.role.as_str()),
                &contract.native_roles,
            ) && checkpoint.observations.len() == contract.native_roles.len(),
            Verdict::Invalid,
            scope,
            "native checkpoint lacks complete process observations",
        );
        for artifact in &checkpoint.observations {
            report.require(
                evaluate::digest(&artifact.sha256, 64) && hashes.insert(&artifact.sha256),
                Verdict::Invalid,
                scope,
                "missing or reused native raw observation",
            );
        }
        for sample in &checkpoint.samples {
            report.require(
                checkpoint
                    .observations
                    .iter()
                    .filter(|artifact| **artifact == sample.observation)
                    .count()
                    == 1
                    && sample.process.executable_sha256 == candidate
                    && sample.process.pid > 0
                    && sample.process.start_ticks > 0
                    && !sample.process.boot_id.is_empty(),
                Verdict::Invalid,
                scope,
                "unbound native sample or executable identity",
            );
            let policy = receipt
                .policies
                .iter()
                .find(|policy| policy.role == sample.role);
            let initial = baseline.and_then(|checkpoint| {
                checkpoint
                    .samples
                    .iter()
                    .find(|initial| initial.role == sample.role)
            });
            if let (Some(policy), Some(initial)) = (policy, initial) {
                report.require(
                    policy.policy.dynamic_fd_budget > 0
                        && policy.policy.soft_fd_limit > 0
                        && policy.policy.replay_expiry_ms > 0
                        && policy.policy.replay_expiry_ms <= last_offset
                        && policy.policy.retirement_deadline_ms > 0
                        && policy.policy.retirement_deadline_ms <= last_offset,
                    Verdict::Invalid,
                    scope,
                    "native startup policy exceeds the fixed recovery schedule",
                );
                report.extend(evaluate::evaluate_native_resources(
                    &policy.policy,
                    initial,
                    sample,
                    recovered,
                ));
            } else {
                report.reject(
                    Verdict::Invalid,
                    scope,
                    "native sample lacks startup authority",
                );
            }
        }
        if let Some(baseline) = baseline {
            aggregate(
                &mut report,
                &contract,
                &baseline.samples,
                &checkpoint.samples,
                recovered,
            );
        }
    }
    report
}

fn aggregate(
    report: &mut Report,
    contract: &schema::Contract,
    baseline: &[Sample],
    samples: &[Sample],
    recovered: bool,
) {
    let totals = |samples: &[Sample]| {
        samples.iter().try_fold([0_u64; 3], |total, sample| {
            Some([
                total[0].checked_add(sample.rss_kib)?,
                total[1].checked_add(sample.hwm_kib)?,
                total[2].checked_add(sample.threads)?,
            ])
        })
    };
    if let (Some(before), Some(after)) = (totals(baseline), totals(samples)) {
        report.require(
            after[1].saturating_sub(before[1]) <= contract.native_peak_hwm_growth_kib
                && after[2].saturating_sub(before[2]) <= contract.native_thread_growth
                && (!recovered
                    || after[0].saturating_sub(before[0])
                        <= contract.native_recovered_rss_growth_kib),
            Verdict::Fail,
            "native-resources",
            "native aggregate memory/thread envelope exceeded",
        );
    } else {
        report.reject(
            Verdict::Invalid,
            "native-resources",
            "native resource aggregate overflow",
        );
    }
}
