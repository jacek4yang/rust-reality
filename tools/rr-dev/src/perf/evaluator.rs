//! Evaluation: deterministic verdict, then reporting statistics, then the report.
//!
//! # The structural invariant
//!
//! The audit established that bootstrap intervals are reporting-only. This module
//! encodes that as a type property rather than leaving it as convention:
//!
//! - [`DeterministicMetric`] is built by [`DeterministicMetric::evaluate`], whose
//!   parameters are block ratios and a direction. There is no seed, no iteration
//!   count and no random source in scope, so a verdict **cannot** be constructed
//!   from RNG-dependent data.
//! - [`ReportingStatistics`] holds the bootstrap interval and nothing else. It has
//!   no method that returns a verdict, a p-value or a classification, so reporting
//!   cannot feed back into classification.
//! - [`MetricEvaluation`] joins them for serialisation only.
//!
//! The invariant is not "the bootstrap usually does not matter". It is that the
//! verdict type has no constructor capable of consuming the reporting type.
//!
//! # Global verdict, transcribed
//!
//! From `evaluate` in the Python original, and deliberately not reinterpreted:
//!
//! ```text
//! regressions  = metrics where pass == false
//! improvements = metrics classified KEEP_IMPROVEMENT or SMALL_IMPROVEMENT
//! overall      = FAIL if regressions is non-empty else PASS
//! ```
//!
//! Note that `improvements` includes the immaterial `SMALL_IMPROVEMENT` class. That
//! reads oddly next to the classification's careful distinction between material and
//! immaterial improvement, but it is what the current evaluator does and the list is
//! informational rather than verdict-bearing.

use super::{
    bootstrap,
    contract::ContractError,
    stats::{self, Classification, Direction, StatsError},
};

/// Lowest bootstrap resample count the manifest may request.
pub const MIN_BOOTSTRAP_ITERATIONS: usize = 20_000;

/// Highest bootstrap resample count the manifest may request.
pub const MAX_BOOTSTRAP_ITERATIONS: usize = bootstrap::MAX_ITERATIONS;

/// CPU tiers the evaluator recognises.
pub const SUPPORTED_TIERS: [&str; 2] = ["portable", "x86-64-v3"];

/// The overall outcome of one evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverallVerdict {
    /// No metric regressed.
    Pass,
    /// At least one metric regressed.
    Fail,
    /// Evidence was not admissible, so no comparison was performed.
    Invalid,
}

impl OverallVerdict {
    /// The wire spelling used by the report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Invalid => "INVALID",
        }
    }

    /// The process exit status, matching the Python original exactly.
    ///
    /// Zero for a pass, one for a regression, two for inadmissible evidence. The
    /// distinction between one and two matters to callers: a failing gate and a
    /// broken gate need different responses.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Pass => 0,
            Self::Fail => 1,
            Self::Invalid => 2,
        }
    }
}

/// Everything about one metric that a verdict may depend on.
///
/// Constructed only by [`DeterministicMetric::evaluate`]. Every field here is a pure
/// function of the block ratios and the metric's direction.
#[derive(Debug, Clone, PartialEq)]
pub struct DeterministicMetric {
    /// Stable metric identifier, used as the Holm hypothesis key.
    pub id: String,
    /// Workload the metric came from.
    pub workload: String,
    /// Measured quantity, for example `throughput`.
    pub measure: String,
    /// Unit the measurement was recorded in.
    pub unit: String,
    /// Which way this metric improves.
    pub direction: Direction,
    /// One ratio per completed block, candidate over baseline.
    pub blocks: Vec<f64>,
    /// Median block ratio: the point effect estimate.
    pub median_ratio: f64,
    /// Mean oriented log ratio: the test statistic, positive meaning better.
    pub mean_log_benefit: f64,
    /// One-sided regression p-value before correction.
    pub raw_p_value: f64,
    /// One-sided improvement p-value before correction.
    pub improvement_raw_p_value: f64,
    /// Regression p-value after global Holm correction.
    pub adjusted_p_value: Option<f64>,
    /// Improvement p-value after global Holm correction.
    pub improvement_adjusted_p_value: Option<f64>,
    /// Final classification, available once correction has been applied.
    pub classification: Option<Classification>,
}

impl DeterministicMetric {
    /// Evaluates one metric from its block ratios.
    ///
    /// Deliberately takes no seed and no iteration count: the signature is the
    /// enforcement mechanism for the module's central invariant. Correction fields
    /// are left unset because Holm operates over the whole family, not one metric.
    ///
    /// # Errors
    ///
    /// Returns [`StatsError`] if the block count is outside the exact gate's range,
    /// a ratio is not positive and finite, or a log ratio is not finite.
    pub fn evaluate(
        id: impl Into<String>,
        workload: impl Into<String>,
        measure: impl Into<String>,
        unit: impl Into<String>,
        direction: Direction,
        ratios: &[f64],
    ) -> Result<Self, StatsError> {
        let id = id.into();
        let oriented = stats::oriented_log_ratios(&id, direction, ratios)?;
        let (raw_p_value, improvement_raw_p_value) =
            stats::exact_sign_flip_pvalues(&id, &oriented)?;
        #[expect(
            clippy::cast_precision_loss,
            reason = "block counts are bounded by MAX_EXACT_BLOCKS"
        )]
        let mean_log_benefit = stats::fsum(&oriented) / oriented.len() as f64;
        Ok(Self {
            id,
            workload: workload.into(),
            measure: measure.into(),
            unit: unit.into(),
            direction,
            blocks: ratios.to_vec(),
            median_ratio: stats::median(ratios)?,
            mean_log_benefit,
            raw_p_value,
            improvement_raw_p_value,
            adjusted_p_value: None,
            improvement_adjusted_p_value: None,
            classification: None,
        })
    }
}

/// Statistics that exist for the report and never for the verdict.
///
/// The type carries no p-value, no classification and no verdict, so there is no
/// way for a caller to route it into a decision.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReportingStatistics {
    /// Deterministic 95% block-bootstrap interval on the median ratio.
    pub bootstrap95: [f64; 2],
}

impl ReportingStatistics {
    /// Computes the reporting interval for one metric.
    ///
    /// Seeded from the metric identifier so the interval is reproducible, which is
    /// what makes a regenerated report comparable with one recorded at release time.
    /// See [`super::bootstrap`] for why the CPython-compatible generator exists: it
    /// is required for **report** reproducibility, not for verdict correctness.
    ///
    /// # Errors
    ///
    /// Returns a statistical error when the ratios or resample count are outside
    /// the bounded reporting contract.
    pub fn compute(metric_id: &str, ratios: &[f64], iterations: usize) -> Result<Self, StatsError> {
        Ok(Self {
            bootstrap95: bootstrap::interval(metric_id, ratios, iterations)?,
        })
    }
}

/// Why an evaluation could not produce a verdict.
#[derive(Debug, Clone, PartialEq)]
pub enum EvaluationError {
    /// The manifest declared an unsupported CPU tier.
    UnsupportedTier {
        /// What the manifest said.
        found: String,
    },
    /// The bootstrap iteration count was outside the permitted range.
    BootstrapIterations {
        /// The requested count.
        found: usize,
    },
    /// No protected metric survived to be evaluated.
    NoProtectedMetrics,
    /// A statistical precondition failed.
    Stats(StatsError),
    /// A contract precondition failed.
    Contract(ContractError),
}

impl From<StatsError> for EvaluationError {
    fn from(error: StatsError) -> Self {
        Self::Stats(error)
    }
}

impl From<ContractError> for EvaluationError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

impl std::fmt::Display for EvaluationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedTier { found } => write!(formatter, "invalid CPU tier: {found}"),
            Self::BootstrapIterations { found } => write!(
                formatter,
                "bootstrapIterations must be in {MIN_BOOTSTRAP_ITERATIONS}..{MAX_BOOTSTRAP_ITERATIONS}, found {found}"
            ),
            Self::NoProtectedMetrics => {
                write!(formatter, "no protected metrics were produced")
            }
            Self::Stats(error) => write!(formatter, "{error}"),
            Self::Contract(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for EvaluationError {}

/// Validates a requested bootstrap iteration count.
///
/// # Errors
///
/// Returns [`EvaluationError::BootstrapIterations`] outside the permitted range.
pub fn validate_bootstrap_iterations(found: usize) -> Result<usize, EvaluationError> {
    if !(MIN_BOOTSTRAP_ITERATIONS..=MAX_BOOTSTRAP_ITERATIONS).contains(&found) {
        return Err(EvaluationError::BootstrapIterations { found });
    }
    Ok(found)
}

/// Validates a declared CPU tier.
///
/// # Errors
///
/// Returns [`EvaluationError::UnsupportedTier`] for anything unrecognised.
pub fn validate_tier(tier: &str) -> Result<(), EvaluationError> {
    if SUPPORTED_TIERS.contains(&tier) {
        return Ok(());
    }
    Err(EvaluationError::UnsupportedTier {
        found: tier.to_owned(),
    })
}

/// Applies the two global Holm families and classifies every metric.
///
/// Two independent families, one over regression p-values and one over improvement
/// p-values, each spanning every protected metric in the run. Correcting them
/// jointly would be a different and stricter test than the recorded methodology.
///
/// # Errors
///
/// Returns [`EvaluationError::NoProtectedMetrics`] for an empty family, or the
/// underlying [`StatsError`] if correction or classification rejects the input.
pub fn apply_global_holm(metrics: &mut [DeterministicMetric]) -> Result<(), EvaluationError> {
    if metrics.is_empty() {
        return Err(EvaluationError::NoProtectedMetrics);
    }
    let regression_family: Vec<(String, f64)> = metrics
        .iter()
        .map(|metric| (metric.id.clone(), metric.raw_p_value))
        .collect();
    let improvement_family: Vec<(String, f64)> = metrics
        .iter()
        .map(|metric| (metric.id.clone(), metric.improvement_raw_p_value))
        .collect();
    let regression_adjusted = stats::holm_adjusted_pvalues(&regression_family)?;
    let improvement_adjusted = stats::holm_adjusted_pvalues(&improvement_family)?;

    for (index, metric) in metrics.iter_mut().enumerate() {
        let regression = regression_adjusted[index];
        let improvement = improvement_adjusted[index];
        let classification = stats::classify(
            &metric.id,
            metric.direction,
            metric.median_ratio,
            regression,
            improvement,
        )?;
        metric.adjusted_p_value = Some(regression);
        metric.improvement_adjusted_p_value = Some(improvement);
        metric.classification = Some(classification);
    }
    Ok(())
}

/// The global outcome derived from corrected metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalOutcome {
    /// Identifiers of every metric that failed.
    pub regressions: Vec<String>,
    /// Identifiers of every metric classified as an improvement of either size.
    pub improvements: Vec<String>,
    /// The overall verdict.
    pub verdict: OverallVerdict,
}

/// Derives the global outcome, transcribed from the Python original.
///
/// `improvements` deliberately includes `SMALL_IMPROVEMENT` alongside
/// `KEEP_IMPROVEMENT`. The list is informational; only `regressions` decides the
/// verdict.
///
/// # Errors
///
/// Returns [`EvaluationError::NoProtectedMetrics`] if any metric is uncorrected,
/// since a verdict over partially corrected metrics would be meaningless.
pub fn global_outcome(metrics: &[DeterministicMetric]) -> Result<GlobalOutcome, EvaluationError> {
    if metrics.is_empty() {
        return Err(EvaluationError::NoProtectedMetrics);
    }
    let mut regressions = Vec::new();
    let mut improvements = Vec::new();
    for metric in metrics {
        let Some(classification) = metric.classification else {
            return Err(EvaluationError::NoProtectedMetrics);
        };
        if !classification.passes() {
            regressions.push(metric.id.clone());
        }
        if matches!(
            classification,
            Classification::KeepImprovement | Classification::SmallImprovement
        ) {
            improvements.push(metric.id.clone());
        }
    }
    let verdict = if regressions.is_empty() {
        OverallVerdict::Pass
    } else {
        OverallVerdict::Fail
    };
    Ok(GlobalOutcome {
        regressions,
        improvements,
        verdict,
    })
}

#[cfg(test)]
#[expect(
    clippy::float_cmp,
    reason = "parity tests compare against recorded evidence exactly; an epsilon \
              would defeat their purpose"
)]
mod tests {
    use super::*;

    /// Recorded blocks for `matrix-c1:direct-upload_32_1:p99-latency`, v1.8.0 gate.
    const P99_BLOCKS: [f64; 12] = [
        1.010_752_480_599_204_8,
        1.002_100_273_887_067_7,
        1.295_504_478_004_131_2,
        0.840_590_560_783_179_4,
        1.144_003_999_294_242_1,
        0.997_321_357_707_876,
        0.988_555_785_791_684_9,
        1.095_088_664_311_070_4,
        1.009_385_513_414_038,
        1.140_572_764_312_578_3,
        1.046_156_422_709_764,
        1.229_912_065_504_826_8,
    ];

    fn metric(id: &str, direction: Direction, ratios: &[f64]) -> DeterministicMetric {
        DeterministicMetric::evaluate(id, "w", "throughput", "unit", direction, ratios)
            .expect("valid blocks")
    }

    /// Twelve ratios centred on `centre`, deterministic and positive.
    fn ratios_around(centre: f64) -> Vec<f64> {
        (0..12)
            .map(|index| {
                let wobble = f64::from(index % 3) * 0.001 - 0.001;
                centre + wobble
            })
            .collect()
    }

    #[test]
    fn a_recorded_metric_reproduces_every_deterministic_field() {
        let evaluated = metric("p99", Direction::LowerIsBetter, &P99_BLOCKS);
        assert_eq!(evaluated.median_ratio, 1.028_454_451_654_484_5);
        assert_eq!(evaluated.mean_log_benefit, -0.058_513_158_852_144_67);
        assert_eq!(evaluated.raw_p_value, 0.052_734_375);
        assert_eq!(evaluated.improvement_raw_p_value, 0.947_509_765_625);
        assert_eq!(evaluated.blocks.len(), 12);
        assert_eq!(
            evaluated.classification, None,
            "classification is unavailable before global correction"
        );
    }

    #[test]
    fn the_verdict_path_is_independent_of_the_reporting_seed() {
        // The invariant this whole module exists to protect. Reporting statistics are
        // recomputed under several different labels, which changes the derived seed
        // and therefore the entire resample stream. Nothing verdict-bearing may move.
        let mut metrics = vec![metric("p99", Direction::LowerIsBetter, &P99_BLOCKS)];
        apply_global_holm(&mut metrics).expect("correction succeeds");
        let outcome = global_outcome(&metrics).expect("outcome");

        let baseline_fields = (
            metrics[0].median_ratio,
            metrics[0].mean_log_benefit,
            metrics[0].raw_p_value,
            metrics[0].improvement_raw_p_value,
            metrics[0].adjusted_p_value,
            metrics[0].improvement_adjusted_p_value,
            metrics[0].classification,
            outcome.verdict,
        );

        let mut intervals = Vec::new();
        for seed_label in ["p99", "different-seed", "another", "zzz", ""] {
            let reporting =
                ReportingStatistics::compute(seed_label, &P99_BLOCKS, MIN_BOOTSTRAP_ITERATIONS)
                    .expect("twelve blocks is enough");
            intervals.push(reporting.bootstrap95);

            // Re-derive the deterministic side from scratch and confirm nothing moved.
            let mut again = vec![metric("p99", Direction::LowerIsBetter, &P99_BLOCKS)];
            apply_global_holm(&mut again).expect("correction succeeds");
            let again_outcome = global_outcome(&again).expect("outcome");
            let observed = (
                again[0].median_ratio,
                again[0].mean_log_benefit,
                again[0].raw_p_value,
                again[0].improvement_raw_p_value,
                again[0].adjusted_p_value,
                again[0].improvement_adjusted_p_value,
                again[0].classification,
                again_outcome.verdict,
            );
            assert_eq!(
                observed, baseline_fields,
                "seed {seed_label:?} must not disturb any verdict-bearing field"
            );
        }

        // The seeds must genuinely have taken effect, otherwise this test is
        // vacuous. That is asserted on the random *stream* rather than on the
        // interval, because of a property measured while writing this test and
        // confirmed against the Python implementation: at twelve blocks with twenty
        // thousand resamples the reported percentile bounds are identical for every
        // seed. The median of a twelve-element resample can only take a small set of
        // values, so twenty thousand draws saturate that distribution and the 2.5th
        // and 97.5th percentiles converge regardless of seed. That makes the
        // reporting interval even more clearly non-decisive than the schema claims,
        // but it also means the interval cannot be used as evidence that a seed
        // changed anything.
        let mut streams = Vec::new();
        for label in ["p99", "different-seed", "another", "zzz", ""] {
            let seed = bootstrap::seed_from_label(label);
            let mut generator = bootstrap::PythonRandom::seeded(seed);
            streams.push((
                seed,
                (0..4).map(|_| generator.random()).collect::<Vec<f64>>(),
            ));
        }
        for window in streams.windows(2) {
            assert_ne!(
                window[0].0, window[1].0,
                "labels must derive distinct seeds"
            );
            assert_ne!(
                window[0].1, window[1].1,
                "distinct seeds must drive distinct random streams"
            );
        }
        assert_eq!(
            intervals.len(),
            5,
            "every seed produced a reporting interval"
        );
    }

    #[test]
    fn reporting_statistics_expose_nothing_verdict_bearing() {
        // A structural assertion, kept as a test so it is visible: the reporting type
        // carries exactly one field, the interval. If a p-value or classification is
        // ever added here, this test is the place that should be reconsidered.
        let reporting = ReportingStatistics::compute("m", &P99_BLOCKS, MIN_BOOTSTRAP_ITERATIONS)
            .expect("valid");
        let ReportingStatistics { bootstrap95 } = reporting;
        assert!(bootstrap95[0] <= bootstrap95[1]);
    }

    #[test]
    fn the_recorded_gate_family_corrects_to_a_pass() {
        // Three of the recorded metrics, smallest raw p-values in the v1.8.0 family.
        // With 32 hypotheses every adjusted value clamped to 1.0 and the gate passed;
        // with three the smallest is 0.052734375 * 3, still far above alpha.
        let mut metrics = vec![
            metric("a", Direction::LowerIsBetter, &P99_BLOCKS),
            metric("b", Direction::HigherIsBetter, &ratios_around(1.0)),
            metric("c", Direction::LowerIsBetter, &ratios_around(1.0)),
        ];
        apply_global_holm(&mut metrics).expect("correction succeeds");
        let outcome = global_outcome(&metrics).expect("outcome");
        assert_eq!(outcome.verdict, OverallVerdict::Pass);
        assert!(outcome.regressions.is_empty());
        for evaluated in &metrics {
            assert!(evaluated.adjusted_p_value.is_some());
            assert!(evaluated.improvement_adjusted_p_value.is_some());
        }
    }

    #[test]
    fn one_regression_fails_the_whole_gate() {
        // A large one-sided loss on a lower-is-better metric: every block worse.
        let regressing: Vec<f64> = (0..12).map(|index| 2.0 + f64::from(index) * 0.01).collect();
        let mut metrics = vec![metric("bad", Direction::LowerIsBetter, &regressing)];
        apply_global_holm(&mut metrics).expect("correction succeeds");
        let outcome = global_outcome(&metrics).expect("outcome");
        assert_eq!(outcome.verdict, OverallVerdict::Fail);
        assert_eq!(outcome.regressions, vec!["bad".to_owned()]);
        assert_eq!(outcome.verdict.exit_code(), 1);
    }

    #[test]
    fn multiple_simultaneous_regressions_are_all_reported() {
        let regressing: Vec<f64> = (0..12).map(|index| 2.0 + f64::from(index) * 0.01).collect();
        let mut metrics = vec![
            metric("bad-a", Direction::LowerIsBetter, &regressing),
            metric("bad-b", Direction::LowerIsBetter, &regressing),
        ];
        apply_global_holm(&mut metrics).expect("correction succeeds");
        let outcome = global_outcome(&metrics).expect("outcome");
        assert_eq!(outcome.verdict, OverallVerdict::Fail);
        assert_eq!(
            outcome.regressions,
            vec!["bad-a".to_owned(), "bad-b".to_owned()],
            "every failing metric must be named, not just the first"
        );
    }

    #[test]
    fn improvements_include_both_material_and_immaterial_classes() {
        // Transcribed behaviour: the improvements list does not filter by size, even
        // though the classification distinguishes KEEP from SMALL.
        let improving: Vec<f64> = (0..12).map(|index| 1.5 + f64::from(index) * 0.01).collect();
        let barely: Vec<f64> = (0..12)
            .map(|index| 1.001 + f64::from(index) * 0.000_01)
            .collect();
        let mut metrics = vec![
            metric("material", Direction::HigherIsBetter, &improving),
            metric("immaterial", Direction::HigherIsBetter, &barely),
        ];
        apply_global_holm(&mut metrics).expect("correction succeeds");
        assert_eq!(
            metrics[0].classification,
            Some(Classification::KeepImprovement)
        );
        assert_eq!(
            metrics[1].classification,
            Some(Classification::SmallImprovement)
        );
        let outcome = global_outcome(&metrics).expect("outcome");
        assert_eq!(
            outcome.improvements,
            vec!["material".to_owned(), "immaterial".to_owned()],
            "both improvement classes are listed"
        );
        assert_eq!(outcome.verdict, OverallVerdict::Pass);
    }

    #[test]
    fn a_mixed_outcome_still_fails_because_regression_takes_precedence() {
        let improving: Vec<f64> = (0..12).map(|index| 1.5 + f64::from(index) * 0.01).collect();
        let regressing: Vec<f64> = (0..12).map(|index| 2.0 + f64::from(index) * 0.01).collect();
        let mut metrics = vec![
            metric("good", Direction::HigherIsBetter, &improving),
            metric("bad", Direction::LowerIsBetter, &regressing),
        ];
        apply_global_holm(&mut metrics).expect("correction succeeds");
        let outcome = global_outcome(&metrics).expect("outcome");
        assert_eq!(outcome.verdict, OverallVerdict::Fail);
        assert!(
            !outcome.improvements.is_empty(),
            "the improvement is still reported"
        );
        assert_eq!(outcome.regressions, vec!["bad".to_owned()]);
    }

    #[test]
    fn an_uncorrected_metric_cannot_produce_a_global_outcome() {
        let metrics = vec![metric("m", Direction::HigherIsBetter, &ratios_around(1.0))];
        assert_eq!(
            global_outcome(&metrics),
            Err(EvaluationError::NoProtectedMetrics),
            "a verdict over uncorrected metrics would be meaningless"
        );
    }

    #[test]
    fn an_empty_family_is_refused_by_both_stages() {
        assert_eq!(
            apply_global_holm(&mut []),
            Err(EvaluationError::NoProtectedMetrics)
        );
        assert_eq!(
            global_outcome(&[]),
            Err(EvaluationError::NoProtectedMetrics)
        );
    }

    #[test]
    fn exit_codes_match_the_python_contract() {
        assert_eq!(OverallVerdict::Pass.exit_code(), 0);
        assert_eq!(OverallVerdict::Fail.exit_code(), 1);
        assert_eq!(OverallVerdict::Invalid.exit_code(), 2);
        assert_eq!(OverallVerdict::Pass.as_str(), "PASS");
        assert_eq!(OverallVerdict::Fail.as_str(), "FAIL");
        assert_eq!(OverallVerdict::Invalid.as_str(), "INVALID");
    }

    #[test]
    fn tiers_and_iteration_bounds_match_the_manifest_contract() {
        for tier in SUPPORTED_TIERS {
            assert!(validate_tier(tier).is_ok());
        }
        assert!(matches!(
            validate_tier("x86-64-v4"),
            Err(EvaluationError::UnsupportedTier { .. })
        ));

        assert_eq!(validate_bootstrap_iterations(20_000), Ok(20_000));
        assert_eq!(validate_bootstrap_iterations(100_000), Ok(100_000));
        for bad in [19_999, 100_001, 0] {
            assert!(
                matches!(
                    validate_bootstrap_iterations(bad),
                    Err(EvaluationError::BootstrapIterations { .. })
                ),
                "{bad} iterations must be refused"
            );
        }
    }

    #[test]
    fn block_counts_outside_the_exact_range_are_refused_at_construction() {
        let short = vec![1.0_f64; stats::MIN_EXACT_BLOCKS - 1];
        let long = vec![1.0_f64; stats::MAX_EXACT_BLOCKS + 1];
        for ratios in [short, long] {
            assert!(
                DeterministicMetric::evaluate(
                    "m",
                    "w",
                    "throughput",
                    "unit",
                    Direction::HigherIsBetter,
                    &ratios
                )
                .is_err(),
                "{} blocks must be refused",
                ratios.len()
            );
        }
    }

    #[test]
    fn holm_families_are_separate_so_one_direction_cannot_mask_the_other() {
        // The methodology runs two independent global Holm families, one per
        // direction. Merging them into a single family of twice the size would be a
        // stricter and different test, and could withdraw a real regression.
        //
        // The block pattern below is calibrated so the distinction is observable
        // rather than incidental: ten blocks 5% worse and two 5% better give a raw
        // one-sided regression p-value of 0.019287. Multiplied by a family of two
        // that is 0.0386, still significant at alpha 0.05; multiplied by a merged
        // family of four it is 0.0771, no longer significant. A more extreme
        // regression would survive either family size and prove nothing.
        let mut regressing = vec![1.05_f64; 10];
        regressing.extend([0.95_f64; 2]);
        let neutral = ratios_around(1.0);
        let mut metrics = vec![
            metric("down", Direction::LowerIsBetter, &regressing),
            metric("flat", Direction::HigherIsBetter, &neutral),
        ];
        assert_eq!(
            metrics[0].raw_p_value, 0.019_287_109_375,
            "the calibration this test depends on has drifted"
        );

        apply_global_holm(&mut metrics).expect("correction succeeds");
        let adjusted = metrics[0].adjusted_p_value.expect("corrected");
        assert!(
            adjusted <= stats::FAMILY_WISE_ALPHA,
            "with two hypotheses per direction the regression must remain \
             significant, found {adjusted}"
        );
        assert_eq!(metrics[0].classification, Some(Classification::Regression));
        let outcome = global_outcome(&metrics).expect("outcome");
        assert_eq!(outcome.verdict, OverallVerdict::Fail);
    }
}
