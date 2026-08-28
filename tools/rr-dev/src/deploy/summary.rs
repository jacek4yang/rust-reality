//! Pure deployment-characterization summary policy.
//!
//! The legacy deployment driver mixed evidence aggregation with the formal gate.
//! This module owns the gate as typed data: exact setup labels and dimensions,
//! throughput cells, routing/long-flow correctness, netem cardinality, and netem
//! performance propagation. File loading remains with the deployment benchmark
//! migration; policy can already be tested without Python or filesystem fixtures.

use std::collections::{BTreeMap, BTreeSet};

use super::netem::LEGS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Pass,
    Fail,
}

#[derive(Debug, Clone)]
pub(crate) struct FormalPlan {
    pub samples: usize,
    pub connections: i64,
    pub concurrencies: Vec<i64>,
    pub rtt_samples: usize,
    pub rtt_connections: i64,
    pub rtt_concurrencies: Vec<i64>,
    pub throughput_samples: usize,
    pub throughput_cells: Vec<(i64, i64)>,
    pub longflow_mib: i64,
    pub rtts: Vec<i64>,
    pub loss_tokens: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct SetupCell {
    pub samples: usize,
    pub failed_connections: i64,
    pub has_connections_per_second: bool,
    pub has_p99: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct SetupEvidence {
    pub by_concurrency: BTreeMap<i64, SetupCell>,
    pub total_connections: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct ThroughputCell {
    pub samples: usize,
    pub errors: usize,
    pub has_rate: bool,
    pub integrity_pass: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct RoutingEvidence {
    pub cases: usize,
    pub passed: usize,
    pub failed: usize,
    pub verdict: Verdict,
}

#[derive(Debug, Clone)]
pub(crate) struct NetemEvidence {
    pub data_quality_verdict: Verdict,
    pub performance_verdict: Verdict,
    pub expected_profile_count: usize,
    pub actual_profile_count: usize,
    pub expected_raw_record_count: usize,
    pub actual_raw_record_count: usize,
    pub legs: Vec<String>,
    pub concurrencies: Vec<i64>,
    pub samples_per_concurrency: usize,
    pub connections_per_sample: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct SummaryEvidence {
    pub setup: BTreeMap<String, SetupEvidence>,
    pub throughput: BTreeMap<(String, i64, i64), ThroughputCell>,
    pub routing: Option<RoutingEvidence>,
    pub longflow_verdict: Option<Verdict>,
    pub netem: Option<NetemEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SummaryReport {
    pub setup_count: usize,
    pub correctness_verdict: Verdict,
    pub data_quality_verdict: Verdict,
    pub performance_verdict: Verdict,
    pub gate_verdict: Verdict,
    pub overall_verdict: Verdict,
    pub data_quality_failures: Vec<String>,
}

impl FormalPlan {
    pub(crate) fn current() -> Self {
        Self {
            samples: 3,
            connections: 96,
            concurrencies: vec![8, 32],
            rtt_samples: 6,
            rtt_connections: 512,
            rtt_concurrencies: vec![1, 8, 32, 128, 512],
            throughput_samples: 3,
            throughput_cells: vec![(32, 1), (32, 32), (512, 32)],
            longflow_mib: 512,
            rtts: vec![1, 10, 50, 100, 200],
            loss_tokens: vec!["0".to_owned(), "0.1".to_owned(), "1".to_owned()],
        }
    }
}

/// Evaluates the current formal deployment characterization plan.
pub(crate) fn evaluate(plan: &FormalPlan, evidence: &SummaryEvidence) -> SummaryReport {
    let mut correctness_failures = BTreeSet::new();
    let mut quality_failures = BTreeSet::new();

    evaluate_required_verdicts(
        plan,
        evidence,
        &mut correctness_failures,
        &mut quality_failures,
    );
    evaluate_setup(plan, evidence, &mut quality_failures);
    evaluate_throughput(
        plan,
        evidence,
        &mut correctness_failures,
        &mut quality_failures,
    );

    let performance_verdict = evidence
        .netem
        .as_ref()
        .map_or(Verdict::Fail, |netem| netem.performance_verdict);
    let correctness_verdict = verdict(correctness_failures.is_empty());
    let data_quality_verdict = verdict(quality_failures.is_empty());
    let gate_verdict = verdict(
        correctness_verdict == Verdict::Pass
            && data_quality_verdict == Verdict::Pass
            && performance_verdict == Verdict::Pass,
    );

    SummaryReport {
        setup_count: evidence.setup.len(),
        correctness_verdict,
        data_quality_verdict,
        performance_verdict,
        gate_verdict,
        overall_verdict: gate_verdict,
        data_quality_failures: quality_failures.into_iter().collect(),
    }
}

fn verdict(pass: bool) -> Verdict {
    if pass { Verdict::Pass } else { Verdict::Fail }
}

fn evaluate_required_verdicts(
    plan: &FormalPlan,
    evidence: &SummaryEvidence,
    correctness: &mut BTreeSet<String>,
    quality: &mut BTreeSet<String>,
) {
    match &evidence.routing {
        Some(routing)
            if routing.cases == 26
                && routing.passed == 26
                && routing.failed == 0
                && routing.verdict == Verdict::Pass => {}
        Some(_) => {
            quality.insert("formal:routing-cardinality".to_owned());
        }
        None => {
            correctness.insert("routingCorrectness".to_owned());
            quality.insert("missing:routingCorrectness".to_owned());
        }
    }
    if evidence.longflow_verdict != Some(Verdict::Pass) {
        correctness.insert("longFlowRelay".to_owned());
        if evidence.longflow_verdict.is_none() {
            quality.insert("missing:longFlowRelay".to_owned());
        }
    }

    let Some(netem) = &evidence.netem else {
        correctness.insert("netemProfiles".to_owned());
        quality.insert("missing:netemProfiles".to_owned());
        return;
    };
    if netem.data_quality_verdict != Verdict::Pass {
        correctness.insert("netemProfiles".to_owned());
    }
    let expected_profiles = plan.rtts.len() * plan.loss_tokens.len();
    let expected_raw =
        expected_profiles * LEGS.len() * plan.rtt_concurrencies.len() * plan.rtt_samples;
    let expected_legs: Vec<String> = LEGS.iter().map(|leg| (*leg).to_owned()).collect();
    if netem.data_quality_verdict != Verdict::Pass
        || netem.expected_profile_count != expected_profiles
        || netem.actual_profile_count != expected_profiles
        || netem.expected_raw_record_count != expected_raw
        || netem.actual_raw_record_count != expected_raw
        || netem.legs != expected_legs
        || netem.connections_per_sample != plan.rtt_connections
        || netem.samples_per_concurrency != plan.rtt_samples
        || netem.concurrencies != plan.rtt_concurrencies
    {
        quality.insert("formal:netem-cardinality".to_owned());
    }
}

fn evaluate_setup(plan: &FormalPlan, evidence: &SummaryEvidence, quality: &mut BTreeSet<String>) {
    let base = base_setup_labels();
    let rtt = rtt_setup_labels(plan);
    let expected: BTreeSet<String> = base.union(&rtt).cloned().collect();
    let actual: BTreeSet<String> = evidence.setup.keys().cloned().collect();
    if actual != expected {
        quality.insert("formal:setup-label-set".to_owned());
    }

    for label in expected.intersection(&actual) {
        let entry = &evidence.setup[label];
        let (concurrencies, samples, connections) = if rtt.contains(label) {
            (
                &plan.rtt_concurrencies,
                plan.rtt_samples,
                plan.rtt_connections,
            )
        } else {
            (&plan.concurrencies, plan.samples, plan.connections)
        };
        let expected_keys: BTreeSet<i64> = concurrencies.iter().copied().collect();
        let actual_keys: BTreeSet<i64> = entry.by_concurrency.keys().copied().collect();
        if actual_keys != expected_keys {
            quality.insert(format!("formal:setup-concurrencies:{label}"));
        }
        let expected_connections =
            i64::try_from(concurrencies.len() * samples).unwrap_or(i64::MAX) * connections;
        if entry.total_connections != expected_connections {
            quality.insert(format!("formal:setup-connections:{label}"));
        }
        for concurrency in expected_keys.intersection(&actual_keys) {
            let cell = &entry.by_concurrency[concurrency];
            if cell.samples != samples {
                quality.insert(format!("formal:setup-samples:{label}:c{concurrency}"));
            }
            if cell.samples == 0
                || cell.failed_connections != 0
                || !cell.has_connections_per_second
                || !cell.has_p99
            {
                quality.insert(format!("setup:{label}:c{concurrency}"));
            }
        }
    }
}

fn evaluate_throughput(
    plan: &FormalPlan,
    evidence: &SummaryEvidence,
    correctness: &mut BTreeSet<String>,
    quality: &mut BTreeSet<String>,
) {
    let expected_topology: BTreeSet<(String, i64, i64)> = ['a', 'b', 'c', 'd']
        .into_iter()
        .flat_map(|topology| {
            plan.throughput_cells
                .iter()
                .map(move |(mib, concurrency)| (format!("topo-{topology}"), *mib, *concurrency))
        })
        .collect();
    let longflow = ("longflow".to_owned(), plan.longflow_mib, 1);
    let mut expected = expected_topology.clone();
    expected.insert(longflow.clone());
    let actual: BTreeSet<(String, i64, i64)> = evidence.throughput.keys().cloned().collect();
    if actual != expected {
        quality.insert("formal:throughput-cell-set".to_owned());
    }

    for key in expected_topology.intersection(&actual) {
        let cell = &evidence.throughput[key];
        if cell.samples != plan.throughput_samples || cell.errors != 0 || !cell.integrity_pass {
            quality.insert(format!(
                "formal:throughput-samples:{}:{}mib:c{}",
                key.0, key.1, key.2
            ));
        }
        evaluate_throughput_cell(key, cell, correctness, quality);
    }
    if let Some(cell) = evidence.throughput.get(&longflow) {
        if cell.samples != 1 || cell.errors != 0 || !cell.integrity_pass {
            quality.insert("formal:longflow-throughput".to_owned());
        }
        evaluate_throughput_cell(&longflow, cell, correctness, quality);
    }
}

fn evaluate_throughput_cell(
    key: &(String, i64, i64),
    cell: &ThroughputCell,
    correctness: &mut BTreeSet<String>,
    quality: &mut BTreeSet<String>,
) {
    if !cell.integrity_pass {
        correctness.insert("byteIntegrity".to_owned());
    }
    if cell.samples == 0 || cell.errors != 0 || !cell.has_rate || !cell.integrity_pass {
        quality.insert(format!("throughput:{}:{}mib:c{}", key.0, key.1, key.2));
    }
}

fn base_setup_labels() -> BTreeSet<String> {
    [
        "cost-simple",
        "cost-medium",
        "cost-complex",
        "cost-complex-ipifnonmatch",
        "cost-complex-ipondemand",
        "topo-a",
        "topo-b",
        "topo-c",
        "topo-d",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn rtt_setup_labels(plan: &FormalPlan) -> BTreeSet<String> {
    plan.rtts
        .iter()
        .flat_map(|rtt| {
            plan.loss_tokens.iter().flat_map(move |loss| {
                LEGS.iter()
                    .map(move |leg| format!("rtt{rtt}-loss{}-{leg}", loss.replace('.', "p")))
            })
        })
        .collect()
}

fn complete_evidence(plan: &FormalPlan) -> SummaryEvidence {
    let base = base_setup_labels();
    let rtt = rtt_setup_labels(plan);
    let mut setup = BTreeMap::new();
    for label in base.union(&rtt) {
        let (concurrencies, samples, connections) = if rtt.contains(label) {
            (
                &plan.rtt_concurrencies,
                plan.rtt_samples,
                plan.rtt_connections,
            )
        } else {
            (&plan.concurrencies, plan.samples, plan.connections)
        };
        setup.insert(
            label.clone(),
            SetupEvidence {
                by_concurrency: concurrencies
                    .iter()
                    .map(|concurrency| {
                        (
                            *concurrency,
                            SetupCell {
                                samples,
                                failed_connections: 0,
                                has_connections_per_second: true,
                                has_p99: true,
                            },
                        )
                    })
                    .collect(),
                total_connections: i64::try_from(concurrencies.len() * samples).unwrap_or(i64::MAX)
                    * connections,
            },
        );
    }

    let mut throughput = BTreeMap::new();
    for topology in ['a', 'b', 'c', 'd'] {
        for (mib, concurrency) in &plan.throughput_cells {
            throughput.insert(
                (format!("topo-{topology}"), *mib, *concurrency),
                ThroughputCell {
                    samples: plan.throughput_samples,
                    errors: 0,
                    has_rate: true,
                    integrity_pass: true,
                },
            );
        }
    }
    throughput.insert(
        ("longflow".to_owned(), plan.longflow_mib, 1),
        ThroughputCell {
            samples: 1,
            errors: 0,
            has_rate: true,
            integrity_pass: true,
        },
    );
    let profiles = plan.rtts.len() * plan.loss_tokens.len();
    let raw = profiles * LEGS.len() * plan.rtt_concurrencies.len() * plan.rtt_samples;
    SummaryEvidence {
        setup,
        throughput,
        routing: Some(RoutingEvidence {
            cases: 26,
            passed: 26,
            failed: 0,
            verdict: Verdict::Pass,
        }),
        longflow_verdict: Some(Verdict::Pass),
        netem: Some(NetemEvidence {
            data_quality_verdict: Verdict::Pass,
            performance_verdict: Verdict::Pass,
            expected_profile_count: profiles,
            actual_profile_count: profiles,
            expected_raw_record_count: raw,
            actual_raw_record_count: raw,
            legs: LEGS.iter().map(|leg| (*leg).to_owned()).collect(),
            concurrencies: plan.rtt_concurrencies.clone(),
            samples_per_concurrency: plan.rtt_samples,
            connections_per_sample: plan.rtt_connections,
        }),
    }
}

/// Runs the synthetic deployment-summary contracts formerly owned by Python.
///
/// # Errors
///
/// Returns the exact failed contract instead of accepting an incomplete policy
/// migration.
pub(crate) fn check_contract() -> Result<String, String> {
    let plan = FormalPlan::current();
    let complete = complete_evidence(&plan);
    let happy = evaluate(&plan, &complete);
    if happy.setup_count != 99
        || happy.correctness_verdict != Verdict::Pass
        || happy.data_quality_verdict != Verdict::Pass
        || happy.performance_verdict != Verdict::Pass
        || happy.gate_verdict != Verdict::Pass
        || happy.overall_verdict != Verdict::Pass
    {
        return Err("deployment summary happy-path contract failed".to_owned());
    }

    let mut performance_failure = complete.clone();
    let Some(netem) = performance_failure.netem.as_mut() else {
        return Err("deployment summary fixture omitted netem evidence".to_owned());
    };
    netem.performance_verdict = Verdict::Fail;
    let failed = evaluate(&plan, &performance_failure);
    if failed.correctness_verdict != Verdict::Pass
        || failed.data_quality_verdict != Verdict::Pass
        || failed.performance_verdict != Verdict::Fail
        || failed.gate_verdict != Verdict::Fail
    {
        return Err("deployment summary netem performance propagation failed".to_owned());
    }

    let mut missing_label = complete;
    missing_label.setup.remove("topo-d");
    let missing = evaluate(&plan, &missing_label);
    if missing.data_quality_verdict != Verdict::Fail
        || !missing
            .data_quality_failures
            .iter()
            .any(|failure| failure == "formal:setup-label-set")
    {
        return Err("deployment summary missing-label contract failed".to_owned());
    }

    Ok("deployment summary contract: PASS (99 setup labels)".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_formal_plan_happy_path_has_99_setup_summaries() {
        let plan = FormalPlan::current();
        let report = evaluate(&plan, &complete_evidence(&plan));
        assert_eq!(report.setup_count, 99);
        assert_eq!(report.correctness_verdict, Verdict::Pass);
        assert_eq!(report.data_quality_verdict, Verdict::Pass);
        assert_eq!(report.performance_verdict, Verdict::Pass);
        assert_eq!(report.gate_verdict, Verdict::Pass);
        assert_eq!(report.overall_verdict, Verdict::Pass);
        assert!(report.data_quality_failures.is_empty());
    }

    #[test]
    fn netem_performance_failure_propagates_without_corrupting_data_quality() {
        let plan = FormalPlan::current();
        let mut evidence = complete_evidence(&plan);
        evidence.netem.as_mut().unwrap().performance_verdict = Verdict::Fail;
        let report = evaluate(&plan, &evidence);
        assert_eq!(report.correctness_verdict, Verdict::Pass);
        assert_eq!(report.data_quality_verdict, Verdict::Pass);
        assert_eq!(report.performance_verdict, Verdict::Fail);
        assert_eq!(report.gate_verdict, Verdict::Fail);
        assert_eq!(report.overall_verdict, Verdict::Fail);
    }

    #[test]
    fn a_missing_setup_label_is_a_data_quality_failure() {
        let plan = FormalPlan::current();
        let mut evidence = complete_evidence(&plan);
        evidence.setup.remove("topo-d");
        let report = evaluate(&plan, &evidence);
        assert_eq!(report.data_quality_verdict, Verdict::Fail);
        assert!(
            report
                .data_quality_failures
                .iter()
                .any(|failure| failure == "formal:setup-label-set")
        );
    }

    #[test]
    fn the_native_check_executes_all_three_contracts() {
        assert_eq!(
            check_contract().as_deref(),
            Ok("deployment summary contract: PASS (99 setup labels)")
        );
    }
}
