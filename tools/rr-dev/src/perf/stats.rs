//! Pure statistics for the release performance gate.
//!
//! This module is the frozen methodology of `scripts/evaluate-release-performance.py`,
//! reimplemented in Rust with no behavioural change. It reads no files, spawns no
//! processes and holds no state: every function is a pure transformation, which is
//! what makes the gate's decisions independently testable.
//!
//! # Why exact summation matters
//!
//! The sign-flip test compares a permuted sum against the observed sum. With
//! ordinary `f64` addition those two sums can differ in the last bit purely
//! through summation order, and a `<=` comparison on the boundary then flips a
//! count — which changes a p-value, which can change a verdict. The Python
//! original uses `math.fsum`, so [`fsum`] reproduces the same exactly-rounded
//! result rather than approximating it.
//!
//! # What is decision-bearing and what is not
//!
//! Established from the recorded evidence and preserved deliberately:
//!
//! - **Decision-bearing, fully deterministic:** block ratios, log ratios,
//!   orientation, the exact sign-flip enumeration, Holm correction, and
//!   classification. No random number generator participates.
//! - **Reporting only:** the block-bootstrap interval. The evidence schema labels
//!   it `"deterministic 95% block bootstrap (reporting only)"` and no verdict
//!   consults it.
//!
//! That split is the reason this migration is lower-risk than it first appears:
//! verdict parity needs no RNG reproduction at all. The interval is still
//! reproduced bit-for-bit in [`super::bootstrap`] so recorded reports stay
//! comparable.

/// The family-wise error rate the gate is held to.
pub const FAMILY_WISE_ALPHA: f64 = 0.05;

/// Fewest complete ABBA blocks the exact gate accepts.
pub const MIN_EXACT_BLOCKS: usize = 12;

/// Most complete ABBA blocks the exact gate accepts.
///
/// The enumeration is `2^n`, so this bound is what keeps the exact test tractable
/// rather than a statistical preference.
pub const MAX_EXACT_BLOCKS: usize = 16;

/// Smallest median ratio that counts as a *material* improvement.
///
/// A statistically significant improvement below this size is reported as
/// `SMALL_IMPROVEMENT` rather than `KEEP_IMPROVEMENT`, so a one-percent effect is
/// never presented as a reason to keep a change.
pub const MATERIAL_IMPROVEMENT_RATIO: f64 = 1.01;

/// Whether a larger measurement is better for a metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Throughput-like: larger is better.
    HigherIsBetter,
    /// Latency-like: smaller is better.
    LowerIsBetter,
}

impl Direction {
    /// Parses the wire spelling used by the evidence schema.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "higher-is-better" => Some(Self::HigherIsBetter),
            "lower-is-better" => Some(Self::LowerIsBetter),
            _ => None,
        }
    }

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HigherIsBetter => "higher-is-better",
            Self::LowerIsBetter => "lower-is-better",
        }
    }

    /// The multiplier that turns a log ratio into "candidate benefit".
    ///
    /// After orientation, positive always means the candidate is better,
    /// regardless of which way the raw metric points.
    #[must_use]
    pub const fn orientation(self) -> f64 {
        match self {
            Self::HigherIsBetter => 1.0,
            Self::LowerIsBetter => -1.0,
        }
    }
}

/// How one metric came out after correction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    /// A significant regression. The gate fails.
    Regression,
    /// A significant and materially sized improvement.
    KeepImprovement,
    /// A significant but immaterial improvement.
    SmallImprovement,
    /// Neither direction is significant.
    NoSignificantChange,
}

impl Classification {
    /// The wire spelling used by the evidence schema.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Regression => "REGRESSION",
            Self::KeepImprovement => "KEEP_IMPROVEMENT",
            Self::SmallImprovement => "SMALL_IMPROVEMENT",
            Self::NoSignificantChange => "NO_SIGNIFICANT_CHANGE",
        }
    }

    /// Whether this classification lets the gate pass.
    #[must_use]
    pub const fn passes(self) -> bool {
        !matches!(self, Self::Regression)
    }
}

/// Why an evaluation could not be performed.
///
/// Every variant is a fail-closed condition: the gate refuses to produce a verdict
/// rather than producing one from evidence it cannot trust.
///
/// `Eq` is deliberately not derived: [`StatsError::InvalidPValue`] carries the
/// offending `f64`, which may be NaN, and an equality that claims two NaN-carrying
/// errors are identical would be wrong.
#[derive(Debug, Clone, PartialEq)]
pub enum StatsError {
    /// A block count outside the exact gate's supported range.
    BlockCount {
        /// The metric that failed.
        metric: String,
        /// How many blocks were supplied.
        found: usize,
    },
    /// A ratio that was not a positive finite number.
    NonPositiveRatio {
        /// The metric that failed.
        metric: String,
        /// Which block.
        index: usize,
    },
    /// A log ratio that was not finite.
    NonFiniteLogRatio {
        /// The metric that failed.
        metric: String,
    },
    /// A correction family with no hypotheses in it.
    EmptyFamily,
    /// Two hypotheses sharing one identifier.
    DuplicateHypothesis {
        /// The repeated identifier.
        id: String,
    },
    /// A raw p-value outside `[0, 1]` or not finite.
    InvalidPValue {
        /// The hypothesis that failed.
        id: String,
        /// The offending value.
        value: f64,
    },
    /// Both directional hypotheses came out significant, which is contradictory.
    ContradictoryDirections {
        /// The metric that failed.
        metric: String,
    },
    /// Too few blocks for a bootstrap interval.
    BootstrapSample {
        /// The metric that failed.
        metric: String,
        /// How many blocks were supplied.
        found: usize,
    },
    /// An empty sample list handed to a rank statistic.
    EmptySample,
}

impl std::fmt::Display for StatsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BlockCount { metric, found } => write!(
                formatter,
                "{metric}: exact gate requires {MIN_EXACT_BLOCKS}..{MAX_EXACT_BLOCKS} complete ABBA blocks, found {found}"
            ),
            Self::NonPositiveRatio { metric, index } => {
                write!(
                    formatter,
                    "{metric} block ratio {index} is not a positive number"
                )
            }
            Self::NonFiniteLogRatio { metric } => {
                write!(
                    formatter,
                    "{metric}: exact sign-flip test received a non-finite log ratio"
                )
            }
            Self::EmptyFamily => write!(formatter, "Holm correction family is empty"),
            Self::DuplicateHypothesis { id } => {
                write!(
                    formatter,
                    "Holm correction hypothesis IDs are not unique: {id}"
                )
            }
            Self::InvalidPValue { id, value } => {
                write!(formatter, "{id}: invalid raw p-value {value}")
            }
            Self::ContradictoryDirections { metric } => {
                write!(
                    formatter,
                    "{metric}: both directional hypotheses are significant"
                )
            }
            Self::BootstrapSample { metric, found } => write!(
                formatter,
                "{metric}: fewer than three complete ABBA blocks ({found})"
            ),
            Self::EmptySample => write!(formatter, "tail-latency sample list is empty"),
        }
    }
}

impl std::error::Error for StatsError {}

/// Exactly-rounded summation, matching Python's `math.fsum`.
///
/// Shewchuk's algorithm keeps a list of mutually non-overlapping partial sums, so
/// no information is lost as values accumulate. The sign-flip test depends on this:
/// it compares two sums over the same magnitudes in different orders, and ordinary
/// accumulation can make them differ in the last bit, which flips a boundary
/// comparison and therefore a p-value.
///
/// The final reduction is not a plain reverse sum. `CPython` walks the partials from
/// the largest down, stopping at the first inexact addition, and then applies a
/// half-even correction when the residual and the next partial share a sign. That
/// step is what makes `fsum([1e-16, 1.0, 1e16])` round up rather than down.
/// Omitting it reproduces Shewchuk's *value* but not Python's *rounding*, which was
/// measured here as a one-ULP disagreement against recorded gate evidence — small,
/// but the whole point of this migration is that the numbers do not move.
#[expect(
    clippy::float_cmp,
    reason = "an exact-zero residual is the stopping condition; an epsilon would change the rounding"
)]
#[must_use]
pub fn fsum(values: &[f64]) -> f64 {
    let mut partials: Vec<f64> = Vec::new();
    for &value in values {
        let mut x = value;
        let mut index = 0;
        for position in 0..partials.len() {
            let mut y = partials[position];
            if x.abs() < y.abs() {
                std::mem::swap(&mut x, &mut y);
            }
            let high = x + y;
            let low = y - (high - x);
            if low != 0.0 {
                partials[index] = low;
                index += 1;
            }
            x = high;
        }
        partials.truncate(index);
        partials.push(x);
    }

    // Reduce from the top, stopping at the first inexact addition.
    let mut count = partials.len();
    if count == 0 {
        return 0.0;
    }
    count -= 1;
    let mut high = partials[count];
    let mut low = 0.0_f64;
    while count > 0 {
        let x = high;
        count -= 1;
        let y = partials[count];
        high = x + y;
        let y_rounded = high - x;
        low = y - y_rounded;
        // Exact zero is the intended test, not an approximate one: a residual of
        // exactly zero means the addition was exact, which is the loop's stopping
        // condition in `CPython`. An epsilon here would stop early and change the
        // rounding.
        if low != 0.0 {
            break;
        }
    }

    // Half-even correction across multiple partials: only applies when the
    // residual agrees in sign with the next partial down.
    if count > 0
        && ((low < 0.0 && partials[count - 1] < 0.0) || (low > 0.0 && partials[count - 1] > 0.0))
    {
        let y = low * 2.0;
        let x = high + y;
        if y == x - high {
            high = x;
        }
    }
    high
}

/// The median, matching Python's `statistics.median`.
///
/// An even-length sample averages the two central order statistics.
///
/// # Errors
///
/// Returns [`StatsError::EmptySample`] for an empty sample.
#[expect(
    clippy::manual_midpoint,
    reason = "must match the (a + b) / 2 arithmetic that produced the recorded evidence"
)]
pub fn median(values: &[f64]) -> Result<f64, StatsError> {
    if values.is_empty() {
        return Err(StatsError::EmptySample);
    }
    let mut ordered = values.to_vec();
    ordered.sort_unstable_by(f64::total_cmp);
    let count = ordered.len();
    let middle = count / 2;
    if count % 2 == 1 {
        Ok(ordered[middle])
    } else {
        // Written as the original does rather than with `midpoint`, because the
        // recorded evidence was produced by `(a + b) / 2` and the two can differ in
        // the last bit. `f64::midpoint` cannot overflow here either way, since these
        // are ratios near one.
        Ok((ordered[middle - 1] + ordered[middle]) / 2.0)
    }
}

/// The nearest-rank quantile, matching the evaluator's `nearest_rank`.
///
/// Index is `ceil(len * fraction) - 1`, floored at zero.
///
/// # Errors
///
/// Returns [`StatsError::EmptySample`] for an empty sample.
pub fn nearest_rank(values: &[f64], fraction: f64) -> Result<f64, StatsError> {
    if values.is_empty() {
        return Err(StatsError::EmptySample);
    }
    let mut ordered = values.to_vec();
    ordered.sort_unstable_by(f64::total_cmp);
    #[expect(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "sample counts here are at most a few hundred, well inside f64 and usize"
    )]
    let rank = (ordered.len() as f64 * fraction).ceil() as usize;
    Ok(ordered[rank.saturating_sub(1)])
}

/// One-sided exact p-values from the paired sign-flip test.
///
/// Under the sharp null, candidate and baseline labels are exchangeable within
/// each completed ABBA block. Swapping a block's labels negates its log ratio, so
/// all `2^n` sign assignments are equally likely and the null distribution can be
/// enumerated rather than approximated.
///
/// Returns `(regression_p, improvement_p)`. The statistic is the oriented sum, so
/// `permuted <= observed` counts toward regression and `permuted >= observed`
/// toward improvement. Both tails include the observed value, which is why the two
/// p-values sum to slightly more than one.
///
/// # Errors
///
/// Returns [`StatsError::BlockCount`] outside `1..=MAX_EXACT_BLOCKS` and
/// [`StatsError::NonFiniteLogRatio`] if any input is not finite.
pub fn exact_sign_flip_pvalues(
    metric: &str,
    oriented_log_ratios: &[f64],
) -> Result<(f64, f64), StatsError> {
    let count = oriented_log_ratios.len();
    if count == 0 || count > MAX_EXACT_BLOCKS {
        return Err(StatsError::BlockCount {
            metric: metric.to_owned(),
            found: count,
        });
    }
    if oriented_log_ratios.iter().any(|value| !value.is_finite()) {
        return Err(StatsError::NonFiniteLogRatio {
            metric: metric.to_owned(),
        });
    }

    let observed = fsum(oriented_log_ratios);
    let denominator = 1_u32 << count;
    let mut regression_count = 0_u32;
    let mut improvement_count = 0_u32;
    let mut buffer = vec![0.0_f64; count];

    for assignment in 0..denominator {
        for (index, value) in oriented_log_ratios.iter().enumerate() {
            buffer[index] = if assignment & (1 << index) == 0 {
                -*value
            } else {
                *value
            };
        }
        let permuted = fsum(&buffer);
        if permuted <= observed {
            regression_count += 1;
        }
        if permuted >= observed {
            improvement_count += 1;
        }
    }

    Ok((
        f64::from(regression_count) / f64::from(denominator),
        f64::from(improvement_count) / f64::from(denominator),
    ))
}

/// Holm step-down adjustment over one global hypothesis family.
///
/// Hypotheses are ordered by raw p-value, ties broken by identifier so the result
/// is deterministic. The adjusted value at rank `i` is
/// `min(1, (family_size - i) * p_i)`, made monotonically non-decreasing by
/// carrying a running maximum — without that carry an adjusted value could fall
/// below an earlier one and a rejected hypothesis could appear acceptable.
///
/// Returns adjusted values in the input order.
///
/// # Errors
///
/// Returns [`StatsError::EmptyFamily`], [`StatsError::DuplicateHypothesis`] or
/// [`StatsError::InvalidPValue`].
pub fn holm_adjusted_pvalues(family: &[(String, f64)]) -> Result<Vec<f64>, StatsError> {
    if family.is_empty() {
        return Err(StatsError::EmptyFamily);
    }
    let mut seen = std::collections::BTreeSet::new();
    for (id, value) in family {
        if !seen.insert(id.as_str()) {
            return Err(StatsError::DuplicateHypothesis { id: id.clone() });
        }
        if !value.is_finite() || *value < 0.0 || *value > 1.0 {
            return Err(StatsError::InvalidPValue {
                id: id.clone(),
                value: *value,
            });
        }
    }

    let mut order: Vec<usize> = (0..family.len()).collect();
    order.sort_by(|&left, &right| {
        family[left]
            .1
            .total_cmp(&family[right].1)
            .then_with(|| family[left].0.cmp(&family[right].0))
    });

    #[expect(
        clippy::cast_precision_loss,
        reason = "family sizes are tens of hypotheses, exactly representable"
    )]
    let family_size = family.len() as f64;
    let mut adjusted = vec![0.0_f64; family.len()];
    let mut running_max = 0.0_f64;
    for (rank, &position) in order.iter().enumerate() {
        #[expect(
            clippy::cast_precision_loss,
            reason = "rank is bounded by the family size"
        )]
        let factor = family_size - rank as f64;
        running_max = running_max.max((factor * family[position].1).min(1.0));
        adjusted[position] = running_max;
    }
    Ok(adjusted)
}

/// Classifies one metric from its corrected p-values and effect size.
///
/// Precedence is regression first: a metric that is a significant regression is
/// never reported as anything else. A significant improvement is only reported as
/// `KEEP_IMPROVEMENT` when the median ratio is materially better than parity in the
/// metric's own direction.
///
/// # Errors
///
/// Returns [`StatsError::ContradictoryDirections`] if both directions are
/// significant, which indicates broken evidence rather than an unusual result.
pub fn classify(
    metric: &str,
    direction: Direction,
    median_ratio: f64,
    regression_adjusted: f64,
    improvement_adjusted: f64,
) -> Result<Classification, StatsError> {
    let regression = regression_adjusted <= FAMILY_WISE_ALPHA;
    let improvement = improvement_adjusted <= FAMILY_WISE_ALPHA;
    if regression && improvement {
        return Err(StatsError::ContradictoryDirections {
            metric: metric.to_owned(),
        });
    }
    if regression {
        return Ok(Classification::Regression);
    }
    if !improvement {
        return Ok(Classification::NoSignificantChange);
    }
    let material = match direction {
        Direction::HigherIsBetter => median_ratio >= MATERIAL_IMPROVEMENT_RATIO,
        Direction::LowerIsBetter => median_ratio <= 1.0 / MATERIAL_IMPROVEMENT_RATIO,
    };
    Ok(if material {
        Classification::KeepImprovement
    } else {
        Classification::SmallImprovement
    })
}

/// Validates block ratios and produces the oriented log ratios the test consumes.
///
/// # Errors
///
/// Returns [`StatsError::BlockCount`] if the block count is outside the exact
/// gate's range, and [`StatsError::NonPositiveRatio`] for a ratio that is not a
/// positive finite number.
pub fn oriented_log_ratios(
    metric: &str,
    direction: Direction,
    ratios: &[f64],
) -> Result<Vec<f64>, StatsError> {
    if ratios.len() < MIN_EXACT_BLOCKS || ratios.len() > MAX_EXACT_BLOCKS {
        return Err(StatsError::BlockCount {
            metric: metric.to_owned(),
            found: ratios.len(),
        });
    }
    for (index, ratio) in ratios.iter().enumerate() {
        if !ratio.is_finite() || *ratio <= 0.0 {
            return Err(StatsError::NonPositiveRatio {
                metric: metric.to_owned(),
                index,
            });
        }
    }
    let orientation = direction.orientation();
    Ok(ratios
        .iter()
        .map(|ratio| orientation * ratio.ln())
        .collect())
}

#[cfg(test)]
#[expect(
    clippy::float_cmp,
    reason = "these are golden-parity tests: bit-exact comparison against recorded \
              evidence is the property under test, so an epsilon would defeat them"
)]
mod tests {
    use super::*;

    /// A recorded protected metric from `artifacts/v180-release-gate`.
    ///
    /// Golden data: these blocks and every derived value were produced by the
    /// Python evaluator during the v1.8.0 release gate and are reproduced here
    /// verbatim, so the Rust implementation is checked against real evidence
    /// rather than against a synthetic example that shares its assumptions.
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

    const THROUGHPUT_BLOCKS: [f64; 12] = [
        1.001_371_102_206_451_5,
        1.010_131_489_657_956,
        0.997_111_791_611_569_3,
        0.988_921_135_220_374_5,
        1.029_454_590_052_914_4,
        0.994_169_358_765_256_3,
        1.018_523_189_018_883_5,
        0.996_070_946_748_784_5,
        1.005_016_217_892_342,
        1.018_928_378_543_756_6,
        1.007_902_668_143_456_9,
        1.024_463_711_107_134_9,
    ];

    #[test]
    fn fsum_is_order_independent_where_naive_addition_is_not() {
        // The classic case: a large value swamps small ones under naive addition.
        let values = [1e100, 1.0, -1e100, 1.0];
        assert_eq!(fsum(&values), 2.0, "fsum must recover the exact total");
        let naive: f64 = values.iter().sum();
        assert_ne!(naive, 2.0, "this test is pointless if naive addition works");

        let forward = [0.1, 0.2, 0.3, 0.4, 0.5];
        let mut backward = forward;
        backward.reverse();
        assert_eq!(
            fsum(&forward),
            fsum(&backward),
            "fsum must not depend on summation order"
        );
    }

    #[test]
    fn fsum_applies_the_half_even_correction() {
        // CPython's documented motivating case. Without the half-even step the
        // result rounds down to 1.0000000000000002e16 instead of up.
        assert_eq!(
            fsum(&[1e-16, 1.0, 1e16]),
            1.000_000_000_000_000_2e16,
            "the half-even correction across partials must be applied"
        );
        assert_eq!(fsum(&[]), 0.0, "an empty sum is zero, not NaN");
        assert_eq!(fsum(&[2.5]), 2.5, "a single value passes through");
    }

    #[test]
    fn fsum_matches_python_on_the_golden_log_ratios() {
        // Python: math.fsum(-log(r) for r in P99_BLOCKS) / 12
        let oriented =
            oriented_log_ratios("p99", Direction::LowerIsBetter, &P99_BLOCKS).expect("valid");
        let mean = fsum(&oriented) / 12.0;
        assert_eq!(
            mean, -0.058_513_158_852_144_67,
            "meanLogCandidateBenefit must reproduce the recorded value bit for bit"
        );
    }

    #[test]
    fn the_golden_p99_metric_reproduces_its_recorded_p_values() {
        let oriented =
            oriented_log_ratios("p99", Direction::LowerIsBetter, &P99_BLOCKS).expect("valid");
        let (regression, improvement) =
            exact_sign_flip_pvalues("p99", &oriented).expect("the exact test must run");
        assert_eq!(regression, 0.052_734_375, "recorded rawPValue");
        assert_eq!(
            improvement, 0.947_509_765_625,
            "recorded improvementRawPValue"
        );
    }

    #[test]
    fn the_golden_throughput_metric_reproduces_its_recorded_p_values() {
        let oriented = oriented_log_ratios("thr", Direction::HigherIsBetter, &THROUGHPUT_BLOCKS)
            .expect("valid");
        let (regression, improvement) =
            exact_sign_flip_pvalues("thr", &oriented).expect("the exact test must run");
        assert_eq!(regression, 0.966_552_734_375, "recorded rawPValue");
        assert_eq!(
            improvement, 0.033_691_406_25,
            "recorded improvementRawPValue"
        );
    }

    #[test]
    fn the_golden_medians_reproduce_exactly() {
        assert_eq!(
            median(&P99_BLOCKS).expect("non-empty"),
            1.028_454_451_654_484_5
        );
        assert_eq!(
            median(&THROUGHPUT_BLOCKS).expect("non-empty"),
            1.006_459_443_017_899_5
        );
    }

    #[test]
    fn p_values_are_dyadic_with_the_enumerated_denominator() {
        // Exact enumeration over 2^12 assignments can only produce multiples of
        // 1/4096. A sampled approximation could not, so this pins the method.
        let oriented =
            oriented_log_ratios("p99", Direction::LowerIsBetter, &P99_BLOCKS).expect("valid");
        let (regression, improvement) = exact_sign_flip_pvalues("p99", &oriented).expect("runs");
        for value in [regression, improvement] {
            let scaled = value * 4096.0;
            assert_eq!(
                scaled.fract(),
                0.0,
                "{value} is not an exact multiple of 1/4096"
            );
        }
    }

    #[test]
    fn both_tails_include_the_observed_statistic() {
        let oriented = oriented_log_ratios("thr", Direction::HigherIsBetter, &THROUGHPUT_BLOCKS)
            .expect("valid");
        let (regression, improvement) = exact_sign_flip_pvalues("thr", &oriented).expect("runs");
        assert!(
            regression + improvement > 1.0,
            "each tail is inclusive, so the two p-values must overshoot one: \
             {regression} + {improvement}"
        );
    }

    #[test]
    fn orientation_reverses_the_two_tails() {
        let higher =
            oriented_log_ratios("m", Direction::HigherIsBetter, &THROUGHPUT_BLOCKS).expect("ok");
        let lower =
            oriented_log_ratios("m", Direction::LowerIsBetter, &THROUGHPUT_BLOCKS).expect("ok");
        let (high_reg, high_imp) = exact_sign_flip_pvalues("m", &higher).expect("runs");
        let (low_reg, low_imp) = exact_sign_flip_pvalues("m", &lower).expect("runs");
        assert_eq!(high_reg, low_imp);
        assert_eq!(high_imp, low_reg);
    }

    #[test]
    fn holm_reproduces_the_recorded_family_verdict() {
        // The recorded v1.8.0 gate: 32 metrics, smallest raw p-value 0.052734375,
        // every adjusted value 1.0. With a family of 32 the smallest raw value is
        // multiplied by 32, which exceeds one, so the whole family clamps.
        let family: Vec<(String, f64)> = vec![
            ("a".to_owned(), 0.052_734_375),
            ("b".to_owned(), 0.053_955_078_125),
            ("c".to_owned(), 0.122_802_734_375),
        ];
        let adjusted = holm_adjusted_pvalues(&family).expect("valid family");
        assert_eq!(adjusted[0], (0.052_734_375_f64 * 3.0).min(1.0));
        assert!(
            adjusted.iter().all(|value| *value <= 1.0),
            "adjusted values must never exceed one"
        );
    }

    #[test]
    fn holm_steps_the_factor_down_rather_than_applying_bonferroni() {
        // The distinguishing case. Holm multiplies rank i by (n - i):
        //   0.01*3 = 0.03,  0.02*2 = 0.04,  0.03*1 = 0.03 -> carried to 0.04
        // Bonferroni would multiply every value by 3, giving 0.03, 0.06, 0.09.
        // Asserting only the first element cannot tell the two apart, so the later
        // ranks are what pin the method.
        let family: Vec<(String, f64)> = vec![
            ("a".to_owned(), 0.01),
            ("b".to_owned(), 0.02),
            ("c".to_owned(), 0.03),
        ];
        let adjusted = holm_adjusted_pvalues(&family).expect("valid");
        assert_eq!(adjusted[0], 0.03, "rank 0 uses factor 3");
        assert_eq!(adjusted[1], 0.04, "rank 1 uses factor 2, not 3");
        assert_eq!(
            adjusted[2], 0.04,
            "rank 2 uses factor 1 and inherits the carry"
        );
    }

    #[test]
    fn holm_carries_a_running_maximum_forward() {
        // Without the carry the second value would be reported as 0.021, which is
        // below the first and would let a hypothesis look acceptable after a
        // stronger one was already rejected.
        let family: Vec<(String, f64)> =
            vec![("first".to_owned(), 0.02), ("second".to_owned(), 0.021)];
        let adjusted = holm_adjusted_pvalues(&family).expect("valid");
        assert_eq!(adjusted[0], 0.04, "0.02 * 2");
        assert_eq!(
            adjusted[1], 0.04,
            "0.021 * 1 = 0.021 must be raised to the running maximum"
        );
    }

    #[test]
    fn holm_clamps_each_step_to_one_before_carrying() {
        // 0.6 * 2 = 1.2, which is not a probability. The clamp must apply at each
        // step, not only to the final answer.
        let family: Vec<(String, f64)> = vec![("a".to_owned(), 0.6), ("b".to_owned(), 0.9)];
        let adjusted = holm_adjusted_pvalues(&family).expect("valid");
        assert_eq!(adjusted[0], 1.0, "1.2 must clamp to 1.0");
        assert_eq!(adjusted[1], 1.0);
        assert!(
            adjusted.iter().all(|value| *value <= 1.0),
            "no adjusted value may exceed one: {adjusted:?}"
        );
    }

    #[test]
    fn holm_is_monotonically_non_decreasing_in_rank() {
        let family: Vec<(String, f64)> = vec![
            ("a".to_owned(), 0.01),
            ("b".to_owned(), 0.2),
            ("c".to_owned(), 0.02),
            ("d".to_owned(), 0.9),
        ];
        let adjusted = holm_adjusted_pvalues(&family).expect("valid");
        // Re-sort into rank order and confirm the sequence never decreases.
        let mut paired: Vec<(f64, f64)> = family
            .iter()
            .zip(&adjusted)
            .map(|((_, raw), adj)| (*raw, *adj))
            .collect();
        paired.sort_by(|left, right| left.0.total_cmp(&right.0));
        assert!(
            paired.windows(2).all(|pair| pair[0].1 <= pair[1].1),
            "Holm adjusted values must not decrease with rank: {paired:?}"
        );
    }

    #[test]
    fn a_single_hypothesis_family_leaves_the_p_value_unchanged() {
        let adjusted = holm_adjusted_pvalues(&[("only".to_owned(), 0.03)]).expect("valid");
        assert_eq!(adjusted, vec![0.03]);
    }

    #[test]
    fn holm_handles_the_boundary_values_zero_and_one() {
        let adjusted = holm_adjusted_pvalues(&[("zero".to_owned(), 0.0), ("one".to_owned(), 1.0)])
            .expect("valid");
        assert_eq!(adjusted[0], 0.0, "zero stays significant");
        assert_eq!(adjusted[1], 1.0, "one stays fully clamped");
    }

    #[test]
    fn equal_p_values_are_ordered_by_identifier_for_determinism() {
        let forward = holm_adjusted_pvalues(&[
            ("alpha".to_owned(), 0.04),
            ("beta".to_owned(), 0.04),
            ("gamma".to_owned(), 0.04),
        ])
        .expect("valid");
        let reversed = holm_adjusted_pvalues(&[
            ("gamma".to_owned(), 0.04),
            ("beta".to_owned(), 0.04),
            ("alpha".to_owned(), 0.04),
        ])
        .expect("valid");
        // Same identifiers, same values, different input order: the adjusted value
        // attached to each identifier must not move.
        assert_eq!(forward[0], reversed[2], "alpha");
        assert_eq!(forward[1], reversed[1], "beta");
        assert_eq!(forward[2], reversed[0], "gamma");
    }

    #[test]
    fn correction_can_turn_a_significant_raw_value_non_significant() {
        // 0.02 alone is significant at 0.05; inside a family of ten it is not.
        let alone = holm_adjusted_pvalues(&[("m".to_owned(), 0.02)]).expect("valid");
        assert!(alone[0] <= FAMILY_WISE_ALPHA);

        let mut family = vec![("m".to_owned(), 0.02)];
        for index in 0..9 {
            family.push((format!("other{index}"), 0.9));
        }
        let corrected = holm_adjusted_pvalues(&family).expect("valid");
        assert!(
            corrected[0] > FAMILY_WISE_ALPHA,
            "family-wise correction must be able to withdraw significance: {}",
            corrected[0]
        );
    }

    #[test]
    fn multiple_simultaneous_regressions_stay_significant_when_small_enough() {
        let family: Vec<(String, f64)> = (0..4).map(|index| (format!("m{index}"), 0.001)).collect();
        let adjusted = holm_adjusted_pvalues(&family).expect("valid");
        assert!(
            adjusted.iter().all(|value| *value <= FAMILY_WISE_ALPHA),
            "four strong regressions must all survive correction: {adjusted:?}"
        );
    }

    #[test]
    fn an_empty_or_duplicated_or_invalid_family_fails_closed() {
        assert_eq!(holm_adjusted_pvalues(&[]), Err(StatsError::EmptyFamily));
        assert!(matches!(
            holm_adjusted_pvalues(&[("a".to_owned(), 0.1), ("a".to_owned(), 0.2)]),
            Err(StatsError::DuplicateHypothesis { .. })
        ));
        for bad in [-0.1, 1.1, f64::NAN, f64::INFINITY] {
            assert!(
                matches!(
                    holm_adjusted_pvalues(&[("a".to_owned(), bad)]),
                    Err(StatsError::InvalidPValue { .. })
                ),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn block_counts_outside_the_exact_range_fail_closed() {
        let eleven = vec![1.0_f64; 11];
        let seventeen = vec![1.0_f64; 17];
        for sample in [eleven, seventeen] {
            assert!(matches!(
                oriented_log_ratios("m", Direction::HigherIsBetter, &sample),
                Err(StatsError::BlockCount { .. })
            ));
        }
        assert!(oriented_log_ratios("m", Direction::HigherIsBetter, &[1.0; 12]).is_ok());
        assert!(oriented_log_ratios("m", Direction::HigherIsBetter, &[1.0; 16]).is_ok());
    }

    #[test]
    fn non_positive_and_non_finite_ratios_fail_closed() {
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let mut ratios = vec![1.0_f64; 12];
            ratios[5] = bad;
            assert!(
                matches!(
                    oriented_log_ratios("m", Direction::HigherIsBetter, &ratios),
                    Err(StatsError::NonPositiveRatio { index: 5, .. })
                ),
                "{bad} must be rejected at its own index"
            );
        }
    }

    #[test]
    fn classification_puts_regression_ahead_of_everything() {
        assert_eq!(
            classify("m", Direction::HigherIsBetter, 0.5, 0.001, 0.9).expect("ok"),
            Classification::Regression
        );
        assert!(!Classification::Regression.passes());
    }

    #[test]
    fn a_material_improvement_is_distinguished_from_a_small_one() {
        // Higher-is-better needs a median at or above 1.01 to count as material.
        assert_eq!(
            classify("m", Direction::HigherIsBetter, 1.02, 0.9, 0.001).expect("ok"),
            Classification::KeepImprovement
        );
        assert_eq!(
            classify("m", Direction::HigherIsBetter, 1.005, 0.9, 0.001).expect("ok"),
            Classification::SmallImprovement
        );
        // Lower-is-better mirrors the threshold.
        assert_eq!(
            classify("m", Direction::LowerIsBetter, 1.0 / 1.02, 0.9, 0.001).expect("ok"),
            Classification::KeepImprovement
        );
        assert_eq!(
            classify("m", Direction::LowerIsBetter, 0.999, 0.9, 0.001).expect("ok"),
            Classification::SmallImprovement
        );
    }

    #[test]
    fn a_neutral_result_passes_without_claiming_an_improvement() {
        let classification = classify("m", Direction::HigherIsBetter, 1.0, 0.9, 0.9).expect("ok");
        assert_eq!(classification, Classification::NoSignificantChange);
        assert!(classification.passes());
    }

    #[test]
    fn both_directions_significant_is_rejected_as_broken_evidence() {
        assert!(matches!(
            classify("m", Direction::HigherIsBetter, 1.0, 0.001, 0.001),
            Err(StatsError::ContradictoryDirections { .. })
        ));
    }

    #[test]
    fn the_alpha_boundary_is_inclusive() {
        // Exactly alpha counts as significant, matching `<=` in the original.
        assert_eq!(
            classify("m", Direction::HigherIsBetter, 1.0, FAMILY_WISE_ALPHA, 0.9).expect("ok"),
            Classification::Regression
        );
    }

    #[test]
    fn nearest_rank_matches_the_documented_index() {
        let values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        // ceil(10 * 0.99) - 1 = 9
        assert_eq!(nearest_rank(&values, 0.99).expect("non-empty"), 10.0);
        // ceil(10 * 0.5) - 1 = 4
        assert_eq!(nearest_rank(&values, 0.5).expect("non-empty"), 5.0);
        // A fraction of zero floors at index zero rather than underflowing.
        assert_eq!(nearest_rank(&values, 0.0).expect("non-empty"), 1.0);
        assert_eq!(nearest_rank(&[], 0.5), Err(StatsError::EmptySample));
    }

    #[test]
    fn median_rejects_an_empty_sample_rather_than_returning_zero() {
        assert_eq!(median(&[]), Err(StatsError::EmptySample));
    }

    #[test]
    fn direction_round_trips_through_its_wire_spelling() {
        for direction in [Direction::HigherIsBetter, Direction::LowerIsBetter] {
            assert_eq!(Direction::parse(direction.as_str()), Some(direction));
        }
        assert_eq!(Direction::parse("sideways"), None);
    }
}
