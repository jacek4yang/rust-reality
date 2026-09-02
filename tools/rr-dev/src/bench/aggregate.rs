//! Turning slot samples into the summary each formal harness recorded.
//!
//! Two aggregation shapes appear across the family, and they are not
//! interchangeable:
//!
//! * **Paired block ratio** — `benchmark-fallback-ab.sh` and
//!   `benchmark-setup-rate.sh` compare two builds of the *same* implementation.
//!   Each block contributes one median per side, their ratio is the block's
//!   statistic, and the cell reports the median ratio with a seeded block
//!   bootstrap. Blocking is the point: it is what makes the comparison robust to
//!   drift over a long run, so an unbalanced block is an error rather than
//!   something to average over.
//! * **Pooled per-implementation** — `benchmark-setup-rate-xray.sh` compares two
//!   *different* implementations serving the same shape. It pools every row per
//!   side, reports medians and latency percentiles, and takes ratios of those. It
//!   records no bootstrap at all.
//!
//! ## The percentile is not [`crate::perf::stats::nearest_rank`]
//!
//! This family indexes with `min(len - 1, int(len * fraction))` — a *floor* rank.
//! The evaluator's `nearest_rank` uses `ceil(len * fraction) - 1`. They agree on
//! some lengths and disagree on others: at twenty samples and p95, floor gives
//! element 19 and nearest-rank gives element 18. Reusing the wrong one would move
//! recorded percentiles silently, so [`floor_percentile`] is separate and tested
//! against the disagreement.

use crate::perf::{bootstrap, json_out::Json, stats};

/// Resamples per bootstrap interval, as every harness recorded.
pub const BOOTSTRAP_ITERATIONS: usize = 20_000;

/// `benchmark-fallback-ab.sh` seeds throughput cells with `0x464200 + concurrency`.
pub const FALLBACK_CELL_SEED_BASE: u64 = 0x0046_4200;

/// `benchmark-fallback-ab.sh` seeds its CPU-per-GiB summary with `0x4642C0`.
pub const FALLBACK_CPU_SEED: u64 = 0x0046_42C0;

/// `benchmark-setup-rate.sh` seeds rate cells with `0x525200 + concurrency`.
pub const SETUP_RATE_CELL_SEED_BASE: u64 = 0x0052_5200;

/// `benchmark-setup-rate.sh` seeds its CPU-per-connection summary with `0x5252C0`.
pub const SETUP_RATE_CPU_SEED: u64 = 0x0052_52C0;

/// The `method` string the two paired harnesses record.
pub const PAIRED_METHOD: &str = "alternating balanced ABBA blocks; block bootstrap";

/// The `method` string the Xray comparator records.
pub const COMPARATOR_METHOD: &str = "alternating balanced ABBA blocks; Xray serves one leg";

/// One block's observations for both sides of a paired comparison.
#[derive(Debug, Clone, Default)]
pub struct BlockObservations {
    /// Every baseline value measured in this block.
    pub baseline: Vec<f64>,
    /// Every candidate value measured in this block.
    pub candidate: Vec<f64>,
}

/// One block's medians and the candidate-versus-baseline ratio.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockRatio {
    /// Median of the block's baseline observations.
    pub baseline: f64,
    /// Median of the block's candidate observations.
    pub candidate: f64,
    /// `candidate / baseline`.
    pub ratio: f64,
}

/// A paired cell: per-block ratios, their median, and the bootstrap interval.
#[derive(Debug, Clone, PartialEq)]
pub struct PairedCell {
    /// The per-block statistics, in block order.
    pub blocks: Vec<BlockRatio>,
    /// Median of the per-block ratios.
    pub median_ratio: f64,
    /// The deterministic 95% block-bootstrap interval, for reporting only.
    pub bootstrap95: [f64; 2],
}

/// Aggregates one paired cell.
///
/// Every block must contribute exactly `expected_per_block` observations on each
/// side; anything else is the `unbalanced block` failure the originals raised.
///
/// # Errors
///
/// Returns a message when a block is unbalanced, an observation is not positive
/// and finite, a ratio is not positive and finite, or the bootstrap cannot
/// estimate a bounded interval.
pub fn paired_cell(
    blocks: &[BlockObservations],
    expected_per_block: usize,
    seed: u64,
    label: &str,
) -> Result<PairedCell, String> {
    let mut rows = Vec::with_capacity(blocks.len());
    let mut ratios = Vec::with_capacity(blocks.len());
    for (index, block) in blocks.iter().enumerate() {
        if block.baseline.len() != expected_per_block || block.candidate.len() != expected_per_block
        {
            return Err(format!(
                "unbalanced block {}: expected {expected_per_block} observations per side, \
                 found {} baseline and {} candidate",
                index + 1,
                block.baseline.len(),
                block.candidate.len()
            ));
        }
        for (side, observations) in [
            ("baseline", block.baseline.as_slice()),
            ("candidate", block.candidate.as_slice()),
        ] {
            if let Some((sample, _)) = observations
                .iter()
                .enumerate()
                .find(|(_, value)| !value.is_finite() || **value <= 0.0)
            {
                return Err(format!(
                    "block {} {side} observation {} is not positive and finite",
                    index + 1,
                    sample + 1
                ));
            }
        }
        let baseline = stats::median(&block.baseline).map_err(|error| error.to_string())?;
        let candidate = stats::median(&block.candidate).map_err(|error| error.to_string())?;
        let ratio = candidate / baseline;
        if !ratio.is_finite() || ratio <= 0.0 {
            return Err(format!(
                "block {} candidate/baseline ratio is not positive and finite",
                index + 1
            ));
        }
        ratios.push(ratio);
        rows.push(BlockRatio {
            baseline,
            candidate,
            ratio,
        });
    }
    let median_ratio = stats::median(&ratios).map_err(|error| error.to_string())?;
    let bootstrap95 = bootstrap::interval_with_seed(seed, label, &ratios, BOOTSTRAP_ITERATIONS)
        .map_err(|error| error.to_string())?;
    Ok(PairedCell {
        blocks: rows,
        median_ratio,
        bootstrap95,
    })
}

/// Renders a paired cell, optionally carrying the `unit` a CPU summary records.
#[must_use]
pub fn paired_cell_json(cell: &PairedCell, unit: Option<&str>) -> Json {
    let blocks: Vec<Json> = cell
        .blocks
        .iter()
        .map(|block| {
            Json::object([
                ("baseline", Json::Float(block.baseline)),
                ("candidate", Json::Float(block.candidate)),
                ("candidateVsBaseline", Json::Float(block.ratio)),
            ])
        })
        .collect();
    let mut fields: Vec<(String, Json)> = vec![
        ("blocks".to_owned(), Json::Array(blocks)),
        (
            "medianCandidateVsBaseline".to_owned(),
            Json::Float(cell.median_ratio),
        ),
        (
            "bootstrap95".to_owned(),
            Json::Array(vec![
                Json::Float(cell.bootstrap95[0]),
                Json::Float(cell.bootstrap95[1]),
            ]),
        ),
    ];
    if let Some(unit) = unit {
        fields.push(("unit".to_owned(), Json::string(unit)));
    }
    Json::object(fields)
}

/// One implementation's pooled statistics in the Xray comparator.
#[derive(Debug, Clone, PartialEq)]
pub struct PooledImplementation {
    /// Number of sample rows pooled.
    pub samples: usize,
    /// Number of individual connection latencies pooled.
    pub connections: usize,
    /// Median of the per-row connection rates.
    pub connections_per_second_median: f64,
    /// 50th percentile setup latency.
    pub p50_seconds: f64,
    /// 95th percentile setup latency.
    pub p95_seconds: f64,
    /// 99th percentile setup latency.
    pub p99_seconds: f64,
}

impl PooledImplementation {
    /// Renders the per-implementation object the comparator records.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            (
                "samples",
                Json::Int(i64::try_from(self.samples).unwrap_or(i64::MAX)),
            ),
            (
                "connections",
                Json::Int(i64::try_from(self.connections).unwrap_or(i64::MAX)),
            ),
            (
                "connectionsPerSecondMedian",
                Json::Float(self.connections_per_second_median),
            ),
            ("p50Seconds", Json::Float(self.p50_seconds)),
            ("p95Seconds", Json::Float(self.p95_seconds)),
            ("p99Seconds", Json::Float(self.p99_seconds)),
        ])
    }
}

/// Pools one implementation's rows for the Xray comparator.
///
/// # Errors
///
/// Returns a message when there are no rows or no latencies to summarise, or when
/// any rate or latency is not positive and finite.
pub fn pooled_implementation(
    rates: &[f64],
    latencies: &[f64],
) -> Result<PooledImplementation, String> {
    if rates.is_empty() {
        return Err("no sample rows to pool for this implementation".to_owned());
    }
    if latencies.is_empty() {
        return Err("no connection latencies to pool for this implementation".to_owned());
    }
    if let Some(index) = rates
        .iter()
        .position(|value| !value.is_finite() || *value <= 0.0)
    {
        return Err(format!(
            "connection-rate observation {} is not positive and finite",
            index + 1
        ));
    }
    if let Some(index) = latencies
        .iter()
        .position(|value| !value.is_finite() || *value <= 0.0)
    {
        return Err(format!(
            "latency observation {} is not positive and finite",
            index + 1
        ));
    }
    Ok(PooledImplementation {
        samples: rates.len(),
        connections: latencies.len(),
        connections_per_second_median: stats::median(rates).map_err(|error| error.to_string())?,
        p50_seconds: floor_percentile(latencies, 0.50)?,
        p95_seconds: floor_percentile(latencies, 0.95)?,
        p99_seconds: floor_percentile(latencies, 0.99)?,
    })
}

/// The floor-rank percentile this family uses: `min(len - 1, int(len * fraction))`.
///
/// Deliberately **not** [`crate::perf::stats::nearest_rank`], which is
/// `ceil(len * fraction) - 1` and disagrees on many lengths.
///
/// # Errors
///
/// Returns a message for an empty sample, a non-finite observation, or a fraction
/// outside the closed unit interval.
pub fn floor_percentile(values: &[f64], fraction: f64) -> Result<f64, String> {
    if values.is_empty() {
        return Err("cannot take a percentile of an empty sample".to_owned());
    }
    if !fraction.is_finite() || !(0.0..=1.0).contains(&fraction) {
        return Err(format!("percentile fraction {fraction} is outside 0..=1"));
    }
    if let Some(index) = values.iter().position(|value| !value.is_finite()) {
        return Err(format!(
            "percentile observation {} is not finite",
            index + 1
        ));
    }
    let mut ordered = values.to_vec();
    ordered.sort_unstable_by(f64::total_cmp);
    #[expect(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "sample counts are at most a few thousand, well inside f64 and usize"
    )]
    let rank = (ordered.len() as f64 * fraction) as usize;
    Ok(ordered[rank.min(ordered.len() - 1)])
}

/// Builds the summary envelope every harness shares, with `extra` merged in.
///
/// `status`, `performanceVerdict` and `failures` are constants in all three
/// originals: the harness proves completeness and refuses to publish otherwise, and
/// the verdict is assigned later by the evaluator, never here.
#[must_use]
pub fn summary_document(
    schema_version: i64,
    method: &str,
    slot_count: usize,
    raw_sample_count: usize,
    extra: impl IntoIterator<Item = (String, Json)>,
) -> Json {
    let mut fields: Vec<(String, Json)> = vec![
        ("schemaVersion".to_owned(), Json::Int(schema_version)),
        ("status".to_owned(), Json::string("COMPLETE")),
        (
            "performanceVerdict".to_owned(),
            Json::string("NOT_EVALUATED"),
        ),
        ("method".to_owned(), Json::string(method)),
        (
            "slotCount".to_owned(),
            Json::Int(i64::try_from(slot_count).unwrap_or(i64::MAX)),
        ),
        (
            "rawSampleCount".to_owned(),
            Json::Int(i64::try_from(raw_sample_count).unwrap_or(i64::MAX)),
        ),
        ("failures".to_owned(), Json::Int(0)),
    ];
    fields.extend(extra);
    Json::object(fields)
}

#[cfg(test)]
#[expect(
    clippy::float_cmp,
    reason = "golden-parity tests: exact reproduction of recorded statistics is the \
              property under test, so an epsilon would defeat them"
)]
mod tests {
    use super::*;

    fn blocks(pairs: &[(&[f64], &[f64])]) -> Vec<BlockObservations> {
        pairs
            .iter()
            .map(|(baseline, candidate)| BlockObservations {
                baseline: baseline.to_vec(),
                candidate: candidate.to_vec(),
            })
            .collect()
    }

    #[test]
    fn a_paired_cell_takes_block_medians_then_their_ratio() {
        let data = blocks(&[
            (&[10.0, 12.0], &[11.0, 13.0]),
            (&[20.0, 22.0], &[21.0, 25.0]),
            (&[10.0, 10.0], &[9.0, 11.0]),
        ]);
        let cell = paired_cell(&data, 2, FALLBACK_CPU_SEED, "fallback:cpu").unwrap();
        // Medians: 11 vs 12, 21 vs 23, 10 vs 10.
        assert_eq!(cell.blocks[0].baseline, 11.0);
        assert_eq!(cell.blocks[0].candidate, 12.0);
        assert_eq!(cell.blocks[0].ratio, 12.0 / 11.0);
        assert_eq!(cell.blocks[1].ratio, 23.0 / 21.0);
        assert_eq!(cell.blocks[2].ratio, 1.0);
        // Ratios sort to [1.0, 12/11, 23/21], so the median is the first block's.
        assert_eq!(cell.median_ratio, 12.0 / 11.0);
        assert!(cell.bootstrap95[0] <= cell.median_ratio);
        assert!(cell.bootstrap95[1] >= cell.median_ratio);
    }

    /// The blocking design is the robustness claim, so a short block is an error.
    #[test]
    fn an_unbalanced_block_is_rejected() {
        let data = blocks(&[
            (&[1.0, 1.0], &[1.0, 1.0]),
            (&[1.0], &[1.0, 1.0]),
            (&[1.0, 1.0], &[1.0, 1.0]),
        ]);
        let error = paired_cell(&data, 2, FALLBACK_CPU_SEED, "x").unwrap_err();
        assert!(error.starts_with("unbalanced block 2:"), "{error}");
    }

    #[test]
    fn a_zero_baseline_observation_is_rejected_rather_than_producing_infinity() {
        let data = blocks(&[
            (&[1.0, 1.0], &[1.0, 1.0]),
            (&[0.0, 0.0], &[1.0, 1.0]),
            (&[1.0, 1.0], &[1.0, 1.0]),
        ]);
        let error = paired_cell(&data, 2, FALLBACK_CPU_SEED, "x").unwrap_err();
        assert!(error.contains("baseline observation 1"), "{error}");
    }

    #[test]
    fn paired_cells_reject_non_finite_negative_and_overflowing_values() {
        for bad in [-1.0, f64::NAN, f64::INFINITY] {
            let data = blocks(&[(&[1.0], &[1.0]), (&[1.0], &[bad]), (&[1.0], &[1.0])]);
            let error = paired_cell(&data, 1, FALLBACK_CPU_SEED, "x").unwrap_err();
            assert!(error.contains("candidate observation 1"), "{bad}: {error}");
        }

        let data = blocks(&[
            (&[f64::MIN_POSITIVE], &[f64::MAX]),
            (&[1.0], &[1.0]),
            (&[1.0], &[1.0]),
        ]);
        let error = paired_cell(&data, 1, FALLBACK_CPU_SEED, "x").unwrap_err();
        assert!(
            error.contains("ratio is not positive and finite"),
            "{error}"
        );
    }

    /// The bootstrap refuses to interval-estimate from fewer than three blocks,
    /// and the harnesses required `BLOCKS` in 3..20 for exactly that reason.
    #[test]
    fn fewer_than_three_blocks_cannot_be_bootstrapped() {
        let data = blocks(&[(&[1.0], &[1.0]), (&[1.0], &[1.0])]);
        assert!(paired_cell(&data, 1, FALLBACK_CPU_SEED, "x").is_err());
    }

    /// Each harness seeds its own cells; the same ratios under different seeds must
    /// not silently share an interval.
    #[test]
    fn the_cell_seed_is_derived_from_the_harness_and_concurrency() {
        assert_eq!(FALLBACK_CELL_SEED_BASE + 32, 0x0046_4220);
        assert_eq!(SETUP_RATE_CELL_SEED_BASE + 8, 0x0052_5208);
        assert_eq!(FALLBACK_CPU_SEED, 0x0046_42C0);
        assert_eq!(SETUP_RATE_CPU_SEED, 0x0052_52C0);
    }

    #[test]
    fn the_paired_cell_document_matches_the_legacy_shape() {
        let data = blocks(&[(&[10.0], &[11.0]), (&[10.0], &[12.0]), (&[10.0], &[13.0])]);
        let cell = paired_cell(&data, 1, SETUP_RATE_CPU_SEED, "setup:cpu").unwrap();
        let rendered = paired_cell_json(&cell, None).to_python_json();
        assert!(rendered.contains("\"blocks\""));
        assert!(rendered.contains("\"candidateVsBaseline\""));
        assert!(rendered.contains("\"medianCandidateVsBaseline\": 1.2"));
        assert!(rendered.contains("\"bootstrap95\""));
        assert!(!rendered.contains("\"unit\""));

        // A CPU summary is the same object plus the unit.
        let rendered = paired_cell_json(&cell, Some("secondsPerGiB")).to_python_json();
        assert!(rendered.contains("\"unit\": \"secondsPerGiB\""));
    }

    /// The floor rank and the evaluator's nearest rank genuinely disagree; picking
    /// the wrong one would move every recorded percentile.
    #[test]
    fn the_floor_percentile_is_not_the_evaluator_nearest_rank() {
        let values: Vec<f64> = (0..20).map(f64::from).collect();
        assert_eq!(floor_percentile(&values, 0.95).unwrap(), 19.0);
        assert_eq!(stats::nearest_rank(&values, 0.95).unwrap(), 18.0);
        assert_eq!(floor_percentile(&values, 0.50).unwrap(), 10.0);
        assert_eq!(stats::nearest_rank(&values, 0.50).unwrap(), 9.0);
        // The top fraction is clamped to the last element, as `min(len - 1, ...)` does.
        assert_eq!(floor_percentile(&values, 1.0).unwrap(), 19.0);
        assert!(floor_percentile(&[], 0.5).is_err());
    }

    #[test]
    fn floor_percentile_rejects_invalid_inputs_instead_of_panicking() {
        for fraction in [-0.1, 1.1, f64::NAN, f64::INFINITY] {
            assert!(floor_percentile(&[1.0, 2.0], fraction).is_err());
        }
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(floor_percentile(&[1.0, bad, 2.0], 0.5).is_err());
        }
    }

    /// A ten-element sample is a length where the two agree, which is why the
    /// disagreement is easy to miss.
    #[test]
    fn the_two_percentile_rules_agree_at_some_lengths() {
        let values: Vec<f64> = (0..10).map(f64::from).collect();
        assert_eq!(
            floor_percentile(&values, 0.95).unwrap(),
            stats::nearest_rank(&values, 0.95).unwrap()
        );
    }

    #[test]
    fn a_pooled_implementation_matches_the_comparator_shape() {
        let rates = [100.0, 120.0, 110.0];
        let latencies: Vec<f64> = (1..=100).map(|n| f64::from(n) / 1000.0).collect();
        let pooled = pooled_implementation(&rates, &latencies).unwrap();
        assert_eq!(pooled.samples, 3);
        assert_eq!(pooled.connections, 100);
        assert_eq!(pooled.connections_per_second_median, 110.0);
        // int(100 * 0.5) = 50 -> the 51st smallest, 0.051.
        assert_eq!(pooled.p50_seconds, 0.051);
        assert_eq!(pooled.p95_seconds, 0.096);
        assert_eq!(pooled.p99_seconds, 0.1);

        let rendered = pooled.to_json().to_python_json();
        assert!(rendered.contains("\"connectionsPerSecondMedian\": 110.0"));
        assert!(rendered.contains("\"p95Seconds\": 0.096"));
        assert!(rendered.contains("\"samples\": 3"));

        assert!(pooled_implementation(&[], &latencies).is_err());
        assert!(pooled_implementation(&rates, &[]).is_err());
    }

    #[test]
    fn pooled_statistics_reject_non_positive_and_non_finite_measurements() {
        for bad in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert!(pooled_implementation(&[100.0, bad], &[0.01, 0.02]).is_err());
            assert!(pooled_implementation(&[100.0, 110.0], &[0.01, bad]).is_err());
        }
    }

    #[test]
    fn the_summary_envelope_is_shared_across_the_family() {
        let rendered = summary_document(
            3,
            PAIRED_METHOD,
            12,
            108,
            [("cells".to_owned(), Json::object([] as [(&str, Json); 0]))],
        )
        .to_python_json();
        assert!(rendered.contains("\"schemaVersion\": 3"));
        assert!(rendered.contains("\"status\": \"COMPLETE\""));
        assert!(rendered.contains("\"performanceVerdict\": \"NOT_EVALUATED\""));
        assert!(
            rendered.contains("\"method\": \"alternating balanced ABBA blocks; block bootstrap\"")
        );
        assert!(rendered.contains("\"slotCount\": 12"));
        assert!(rendered.contains("\"rawSampleCount\": 108"));
        assert!(rendered.contains("\"failures\": 0"));
        assert!(rendered.contains("\"cells\": {}"));

        // The comparator records a different schema version and method.
        let rendered = summary_document(1, COMPARATOR_METHOD, 4, 36, []).to_python_json();
        assert!(rendered.contains("\"schemaVersion\": 1"));
        assert!(rendered.contains("Xray serves one leg"));
    }
}
