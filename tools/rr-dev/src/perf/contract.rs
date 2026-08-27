//! The protected-metric contract.
//!
//! What is protected, which way each metric points, and what shape a formal matrix
//! cell must have. Kept as one typed layer so these rules are not scattered as
//! string comparisons through CLI or reporting code — a metric silently losing its
//! protected status would weaken the gate without failing anything.
//!
//! Rules are transcribed from `benchmarks/contracts/protected-metrics-v1.json` and
//! from `evaluate_matrix` in the Python evaluator, and are golden-tested against
//! both the real contract file and recorded matrix evidence.
//!
//! # Two role vocabularies
//!
//! The evidence uses different words for the same thing depending on the workload,
//! and this is preserved rather than normalised away:
//!
//! - paired setup and fallback runs label the two sides `baseline` and `candidate`;
//! - the formal matrix labels them `baseline` and **`final`**, and carries a third
//!   `xray` arm that is excluded from pairing.
//!
//! Collapsing these would either break the matrix or silently pair the wrong arm, so
//! [`MatrixRole`] is a separate type from
//! [`ImplementationRole`](super::evidence::ImplementationRole).

use super::{
    evidence::EvidenceError,
    stats::{MAX_EXACT_BLOCKS, MIN_EXACT_BLOCKS},
};

#[cfg(test)]
use super::stats::Direction;

/// An arm of the formal matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MatrixRole {
    /// The reference build.
    Baseline,
    /// The candidate build. Spelled `final` in matrix evidence.
    Final,
    /// The external Xray control, measured but never paired.
    Xray,
}

impl MatrixRole {
    /// Parses the wire spelling used in matrix evidence.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "baseline" => Some(Self::Baseline),
            "final" => Some(Self::Final),
            "xray" => Some(Self::Xray),
            _ => None,
        }
    }

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Final => "final",
            Self::Xray => "xray",
        }
    }

    /// Whether this arm participates in the paired comparison.
    ///
    /// The Xray arm is an external control: it is recorded for context and appears
    /// in the interleave so it competes for the same resources, but including it in
    /// the pairing would compare against a different implementation entirely.
    #[must_use]
    pub const fn is_paired(self) -> bool {
        matches!(self, Self::Baseline | Self::Final)
    }

    /// Every arm the matrix interleave must contain.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Baseline, Self::Final, Self::Xray]
    }
}

/// Which direction a measured quantity improves in, per the contract file.
///
/// Deliberately test-only. The evaluator does not consult this map: each metric's
/// direction is fixed where the metric is constructed, exactly as the Python original
/// fixes it at the `metric()` call. The map is therefore *documentation* that the
/// contract file and the implementation agree, and the golden test below is what keeps
/// them from drifting apart. Wiring it into the pipeline would be a methodology change,
/// not a refactor.
#[cfg(test)]
///
/// Transcribed from the `direction` object of the contract. A measure absent from
/// both lists is not protected, and asking for its direction returns `None` rather
/// than defaulting — defaulting would silently assign a direction and could invert a
/// verdict.
#[must_use]
pub fn direction_of(measure: &str) -> Option<Direction> {
    const HIGHER_IS_BETTER: &[&str] =
        &["throughput", "connectionsPerSecond", "handshakesPerSecond"];
    const LOWER_IS_BETTER: &[&str] = &[
        "cpuTime",
        "cycles",
        "instructions",
        "syscalls",
        "allocations",
        "copies",
        "latency",
        "rss",
        "memory",
        "descriptors",
        "threads",
        "leakedResources",
    ];
    if HIGHER_IS_BETTER.contains(&measure) {
        return Some(Direction::HigherIsBetter);
    }
    if LOWER_IS_BETTER.contains(&measure) {
        return Some(Direction::LowerIsBetter);
    }
    None
}

/// Identifies one protected matrix cell.
///
/// Rendered as `scenario:payloadMiB:concurrency`, which is the key the summary uses
/// and which the evaluator requires to exactly cover the raw samples.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CellKey {
    /// Traffic scenario, for example `bidi` or `direct-download`.
    pub scenario: String,
    /// Payload size in whole mebibytes.
    pub payload_mib: u64,
    /// Concurrency level.
    pub concurrency: u32,
}

impl CellKey {
    /// Builds a key from raw-sample fields.
    ///
    /// Payload is recorded in bytes on raw rows and in mebibytes in the summary, so
    /// the conversion is integer division exactly as the original performs it.
    #[must_use]
    pub const fn from_bytes(scenario: String, payload_bytes: u64, concurrency: u32) -> Self {
        Self {
            scenario,
            payload_mib: payload_bytes / (1024 * 1024),
            concurrency,
        }
    }

    /// Parses a summary cell key.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = text.rsplitn(3, ':');
        let concurrency = parts.next()?.parse().ok()?;
        let payload_mib = parts.next()?.parse().ok()?;
        let scenario = parts.next()?.to_owned();
        Some(Self {
            scenario,
            payload_mib,
            concurrency,
        })
    }
}

impl std::fmt::Display for CellKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}:{}:{}",
            self.scenario, self.payload_mib, self.concurrency
        )
    }
}

/// The scenario name whose rows are excluded from cell coverage.
///
/// Integrity rows verify payload correctness rather than measuring performance, so
/// they are not part of any protected cell.
pub const INTEGRITY_SCENARIO: &str = "integrity";

/// Why a matrix cell was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    /// The sample count is outside the exact gate's range or is odd.
    SampleCount {
        /// The offending cell.
        cell: String,
        /// The count found.
        found: usize,
    },
    /// The interleave length did not equal three times the sample count.
    InterleaveLength {
        /// The offending cell.
        cell: String,
        /// The length found.
        found: usize,
        /// The length required.
        expected: usize,
    },
    /// The interleave did not contain exactly the three expected arms.
    InterleaveArms {
        /// The offending cell.
        cell: String,
    },
    /// One arm did not appear exactly `samplesPerImplementation` times.
    InterleaveCardinality {
        /// The offending cell.
        cell: String,
        /// The arm that was miscounted.
        arm: &'static str,
        /// How many times it appeared.
        found: usize,
        /// How many times it should appear.
        expected: usize,
    },
    /// A paired block was neither ABBA nor BAAB, or repeated its predecessor.
    PairedOrder {
        /// The offending cell.
        cell: String,
        /// Which block, one-based.
        block: usize,
    },
    /// Summary cells and raw samples did not describe the same set of cells.
    CoverageMismatch {
        /// Cells present in the summary but absent from raw samples.
        summary_only: Vec<String>,
        /// Cells present in raw samples but absent from the summary.
        samples_only: Vec<String>,
    },
    /// Underlying evidence admissibility failure.
    Evidence(EvidenceError),
}

impl From<EvidenceError> for ContractError {
    fn from(error: EvidenceError) -> Self {
        Self::Evidence(error)
    }
}

impl std::fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SampleCount { cell, found } => write!(
                formatter,
                "matrix cell {cell}: formal gate requires {MIN_EXACT_BLOCKS}..{MAX_EXACT_BLOCKS} complete ABBA blocks, found {found} samples per implementation"
            ),
            Self::InterleaveLength {
                cell,
                found,
                expected,
            } => write!(
                formatter,
                "matrix cell {cell}: interleave has {found} entries, expected {expected}"
            ),
            Self::InterleaveArms { cell } => write!(
                formatter,
                "matrix cell {cell}: interleave implementations invalid"
            ),
            Self::InterleaveCardinality {
                cell,
                arm,
                found,
                expected,
            } => write!(
                formatter,
                "matrix cell {cell}: {arm} appears {found} times, expected {expected}"
            ),
            Self::PairedOrder { cell, block } => write!(
                formatter,
                "matrix cell {cell}: paired block {block} is not ABBA/BAAB or did not alternate"
            ),
            Self::CoverageMismatch {
                summary_only,
                samples_only,
            } => write!(
                formatter,
                "matrix: summary cells do not exactly cover raw samples (summary only: {summary_only:?}, samples only: {samples_only:?})"
            ),
            Self::Evidence(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ContractError {}

/// Validates the sample count of one protected cell.
///
/// The gate needs whole ABBA blocks, so the count must be even and must land in
/// `2 * MIN_EXACT_BLOCKS ..= 2 * MAX_EXACT_BLOCKS`. An odd count means a block was
/// left half-measured.
///
/// # Errors
///
/// Returns [`ContractError::SampleCount`].
pub fn validate_sample_count(cell: &str, count: usize) -> Result<usize, ContractError> {
    let blocks = count / 2;
    if !count.is_multiple_of(2) || !(MIN_EXACT_BLOCKS..=MAX_EXACT_BLOCKS).contains(&blocks) {
        return Err(ContractError::SampleCount {
            cell: cell.to_owned(),
            found: count,
        });
    }
    Ok(blocks)
}

/// Validates a cell's interleave order.
///
/// Four independent properties, all transcribed from `evaluate_matrix`:
///
/// 1. length is exactly `3 * count`, one entry per arm per sample;
/// 2. exactly the three known arms appear, no more and no fewer;
/// 3. each arm appears exactly `count` times, so no arm is over-sampled;
/// 4. the paired subset, with the Xray arm removed, forms ABBA/BAAB blocks that
///    alternate between consecutive blocks.
///
/// Property four is why the Xray arm cannot simply be ignored earlier: it must be
/// present for the cardinality check and absent for the ordering check.
///
/// # Errors
///
/// Returns the specific structural failure.
pub fn validate_interleave(
    cell: &str,
    interleave: &[MatrixRole],
    count: usize,
) -> Result<(), ContractError> {
    const ABBA: [MatrixRole; 4] = [
        MatrixRole::Baseline,
        MatrixRole::Final,
        MatrixRole::Final,
        MatrixRole::Baseline,
    ];
    const BAAB: [MatrixRole; 4] = [
        MatrixRole::Final,
        MatrixRole::Baseline,
        MatrixRole::Baseline,
        MatrixRole::Final,
    ];

    let expected_length = count * 3;
    if interleave.len() != expected_length {
        return Err(ContractError::InterleaveLength {
            cell: cell.to_owned(),
            found: interleave.len(),
            expected: expected_length,
        });
    }
    for arm in MatrixRole::all() {
        let seen = interleave.iter().filter(|entry| **entry == arm).count();
        if seen == 0 {
            return Err(ContractError::InterleaveArms {
                cell: cell.to_owned(),
            });
        }
        if seen != count {
            return Err(ContractError::InterleaveCardinality {
                cell: cell.to_owned(),
                arm: arm.as_str(),
                found: seen,
                expected: count,
            });
        }
    }

    let paired: Vec<MatrixRole> = interleave
        .iter()
        .copied()
        .filter(|role| role.is_paired())
        .collect();
    let mut previous: Option<[MatrixRole; 4]> = None;
    for (index, window) in paired.chunks(4).enumerate() {
        let block = index + 1;
        let Ok(sequence) = <[MatrixRole; 4]>::try_from(window) else {
            return Err(ContractError::PairedOrder {
                cell: cell.to_owned(),
                block,
            });
        };
        if sequence != ABBA && sequence != BAAB {
            return Err(ContractError::PairedOrder {
                cell: cell.to_owned(),
                block,
            });
        }
        if previous == Some(sequence) {
            return Err(ContractError::PairedOrder {
                cell: cell.to_owned(),
                block,
            });
        }
        previous = Some(sequence);
    }
    Ok(())
}

/// Requires that summary cells and raw samples describe exactly the same cells.
///
/// Neither direction is tolerated. A summary cell with no raw samples would be
/// evaluated from nothing; a raw cell absent from the summary would be measured and
/// then silently dropped from the gate.
///
/// # Errors
///
/// Returns [`ContractError::CoverageMismatch`] listing both directions.
pub fn validate_coverage(
    summary_cells: &[CellKey],
    sample_cells: &[CellKey],
) -> Result<(), ContractError> {
    let summary: std::collections::BTreeSet<&CellKey> = summary_cells.iter().collect();
    let samples: std::collections::BTreeSet<&CellKey> = sample_cells.iter().collect();
    if summary == samples {
        return Ok(());
    }
    Err(ContractError::CoverageMismatch {
        summary_only: summary
            .difference(&samples)
            .map(ToString::to_string)
            .collect(),
        samples_only: samples
            .difference(&summary)
            .map(ToString::to_string)
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The recorded interleave prefix from
    /// `artifacts/v180-release-gate/gates/matrix-formal-r01/summary.json`, cell
    /// `bidi:1:1`. Used to confirm the paired subset of real evidence is ABBA.
    const RECORDED_PREFIX: [&str; 8] = [
        "baseline", "final", "xray", "final", "baseline", "xray", "final", "baseline",
    ];

    fn roles(names: &[&str]) -> Vec<MatrixRole> {
        names
            .iter()
            .map(|name| MatrixRole::parse(name).expect("known arm"))
            .collect()
    }

    /// Builds a valid interleave for `blocks` blocks by repeating an alternating
    /// paired pattern and inserting one Xray entry per sample.
    fn valid_interleave(blocks: usize) -> Vec<MatrixRole> {
        let mut paired = Vec::new();
        for block in 0..blocks {
            let sequence = if block.is_multiple_of(2) {
                [
                    MatrixRole::Baseline,
                    MatrixRole::Final,
                    MatrixRole::Final,
                    MatrixRole::Baseline,
                ]
            } else {
                [
                    MatrixRole::Final,
                    MatrixRole::Baseline,
                    MatrixRole::Baseline,
                    MatrixRole::Final,
                ]
            };
            paired.extend_from_slice(&sequence);
        }
        // `samplesPerImplementation` is `blocks * 2`, and the paired subset holds
        // `blocks * 4` entries (two per arm per block). One xray entry per two paired
        // entries therefore lands every arm on the same cardinality.
        let mut interleave = Vec::new();
        for (index, role) in paired.iter().enumerate() {
            interleave.push(*role);
            if !index.is_multiple_of(2) {
                interleave.push(MatrixRole::Xray);
            }
        }
        interleave
    }

    #[test]
    fn the_recorded_contract_direction_map_is_reproduced() {
        let raw = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .ancestors()
                .nth(2)
                .expect("repository root")
                .join("benchmarks/contracts/protected-metrics-v1.json"),
        )
        .expect("the contract file must be readable");

        // Every measure the contract lists must resolve, and to the right direction.
        for measure in ["throughput", "connectionsPerSecond", "handshakesPerSecond"] {
            assert!(
                raw.contains(measure),
                "this test is stale: {measure} is no longer in the contract"
            );
            assert_eq!(direction_of(measure), Some(Direction::HigherIsBetter));
        }
        for measure in [
            "cpuTime",
            "cycles",
            "instructions",
            "syscalls",
            "allocations",
            "copies",
            "latency",
            "rss",
            "memory",
            "descriptors",
            "threads",
            "leakedResources",
        ] {
            assert!(
                raw.contains(measure),
                "this test is stale: {measure} is no longer in the contract"
            );
            assert_eq!(direction_of(measure), Some(Direction::LowerIsBetter));
        }
    }

    #[test]
    fn an_unlisted_measure_has_no_direction_rather_than_a_default() {
        // Defaulting would silently assign a direction and could invert a verdict.
        assert_eq!(direction_of("wallClock"), None);
        assert_eq!(direction_of(""), None);
        assert_eq!(direction_of("Throughput"), None, "matching is case-exact");
    }

    #[test]
    fn matrix_roles_use_the_final_spelling_and_exclude_xray_from_pairing() {
        assert_eq!(MatrixRole::parse("final"), Some(MatrixRole::Final));
        assert_eq!(
            MatrixRole::parse("candidate"),
            None,
            "matrix evidence spells the candidate `final`; accepting `candidate` \
             here would mask a schema mismatch"
        );
        assert!(MatrixRole::Baseline.is_paired());
        assert!(MatrixRole::Final.is_paired());
        assert!(
            !MatrixRole::Xray.is_paired(),
            "the external control must never enter the paired comparison"
        );
    }

    #[test]
    fn the_recorded_interleave_prefix_pairs_as_abba() {
        let prefix = roles(&RECORDED_PREFIX);
        let paired: Vec<MatrixRole> = prefix
            .iter()
            .copied()
            .filter(|role| role.is_paired())
            .collect();
        assert_eq!(
            &paired[..4],
            [
                MatrixRole::Baseline,
                MatrixRole::Final,
                MatrixRole::Final,
                MatrixRole::Baseline
            ],
            "removing the xray arm from real evidence must leave an ABBA block"
        );
    }

    #[test]
    fn cell_keys_round_trip_and_convert_bytes_to_mebibytes() {
        let key = CellKey::from_bytes("bidi".to_owned(), 1024 * 1024, 1);
        assert_eq!(key.to_string(), "bidi:1:1");
        assert_eq!(CellKey::parse("bidi:1:1"), Some(key));

        // 32 MiB at concurrency 1, matching a recorded cell shape.
        let large = CellKey::from_bytes("direct-upload".to_owned(), 32 * 1024 * 1024, 1);
        assert_eq!(large.to_string(), "direct-upload:32:1");

        // Integer division, exactly as the original performs it.
        let partial = CellKey::from_bytes("bidi".to_owned(), 1024 * 1024 + 5, 8);
        assert_eq!(partial.payload_mib, 1);
    }

    #[test]
    fn a_scenario_containing_a_colon_still_parses_from_the_right() {
        // rsplitn keeps the scenario intact even if it contains a separator, which
        // matters because scenario names are free-form.
        let key = CellKey::parse("odd:name:4:32").expect("parses");
        assert_eq!(key.scenario, "odd:name");
        assert_eq!(key.payload_mib, 4);
        assert_eq!(key.concurrency, 32);
    }

    #[test]
    fn sample_counts_must_be_even_and_inside_the_exact_range() {
        assert_eq!(validate_sample_count("c", 24), Ok(12));
        assert_eq!(validate_sample_count("c", 32), Ok(16));
        for bad in [22, 34, 23, 0, 1] {
            assert!(
                matches!(
                    validate_sample_count("c", bad),
                    Err(ContractError::SampleCount { .. })
                ),
                "{bad} samples per implementation must be refused"
            );
        }
    }

    #[test]
    fn an_odd_sample_count_is_refused_as_a_half_measured_block() {
        assert!(matches!(
            validate_sample_count("c", 25),
            Err(ContractError::SampleCount { found: 25, .. })
        ));
    }

    #[test]
    fn a_well_formed_interleave_validates_at_both_range_ends() {
        for blocks in [MIN_EXACT_BLOCKS, MAX_EXACT_BLOCKS] {
            let interleave = valid_interleave(blocks);
            let count = blocks * 2;
            assert_eq!(interleave.len(), count * 3);
            assert!(
                validate_interleave("c", &interleave, count).is_ok(),
                "{blocks} blocks must validate"
            );
        }
    }

    #[test]
    fn an_interleave_of_the_wrong_length_is_refused() {
        let mut interleave = valid_interleave(12);
        interleave.pop();
        assert!(matches!(
            validate_interleave("c", &interleave, 24),
            Err(ContractError::InterleaveLength { .. })
        ));
    }

    #[test]
    fn a_missing_arm_is_refused() {
        // Replace every xray entry with final: length is right, arms are not.
        let interleave: Vec<MatrixRole> = valid_interleave(12)
            .into_iter()
            .map(|role| {
                if role == MatrixRole::Xray {
                    MatrixRole::Final
                } else {
                    role
                }
            })
            .collect();
        assert!(matches!(
            validate_interleave("c", &interleave, 24),
            Err(ContractError::InterleaveArms { .. } | ContractError::InterleaveCardinality { .. })
        ));
    }

    #[test]
    fn an_over_sampled_arm_is_refused() {
        let mut interleave = valid_interleave(12);
        // Swap one baseline for a final: cardinality now 23 / 25 / 24.
        let position = interleave
            .iter()
            .position(|role| *role == MatrixRole::Baseline)
            .expect("a baseline exists");
        interleave[position] = MatrixRole::Final;
        assert!(matches!(
            validate_interleave("c", &interleave, 24),
            Err(ContractError::InterleaveCardinality { .. })
        ));
    }

    #[test]
    fn a_paired_subset_that_is_not_abba_is_refused() {
        // ABAB in the paired subset: each block contains both arms but the candidate
        // is always second, so ordering bias is never balanced.
        let mut interleave = Vec::new();
        for _ in 0..12 {
            interleave.extend_from_slice(&[
                MatrixRole::Baseline,
                MatrixRole::Final,
                MatrixRole::Xray,
                MatrixRole::Baseline,
                MatrixRole::Final,
                MatrixRole::Xray,
            ]);
        }
        assert!(matches!(
            validate_interleave("c", &interleave, 24),
            Err(ContractError::PairedOrder { .. })
        ));
    }

    #[test]
    fn an_invalid_sequence_is_refused_even_when_it_alternates() {
        // The previous test is masked: ABAB repeated also trips the alternation
        // check, so removing the ABBA/BAAB test alone would not fail it. Here two
        // *different* invalid sequences alternate, so only the sequence check can
        // reject them. Mutation testing found this gap.
        let mut interleave = Vec::new();
        for block in 0_usize..12 {
            let paired = if block.is_multiple_of(2) {
                // ABAB: both arms present, candidate always second.
                [
                    MatrixRole::Baseline,
                    MatrixRole::Final,
                    MatrixRole::Baseline,
                    MatrixRole::Final,
                ]
            } else {
                // BABA: the mirror, also unbalanced.
                [
                    MatrixRole::Final,
                    MatrixRole::Baseline,
                    MatrixRole::Final,
                    MatrixRole::Baseline,
                ]
            };
            for (index, role) in paired.iter().enumerate() {
                interleave.push(*role);
                if !index.is_multiple_of(2) {
                    interleave.push(MatrixRole::Xray);
                }
            }
        }
        // Sanity: the design alternates, so alternation cannot be what rejects it.
        let sequences: Vec<Vec<MatrixRole>> = interleave
            .iter()
            .copied()
            .filter(|role| role.is_paired())
            .collect::<Vec<_>>()
            .chunks(4)
            .map(<[MatrixRole]>::to_vec)
            .collect();
        assert!(
            sequences.windows(2).all(|pair| pair[0] != pair[1]),
            "this test is only meaningful if consecutive blocks differ"
        );

        assert!(matches!(
            validate_interleave("c", &interleave, 24),
            Err(ContractError::PairedOrder { block: 1, .. })
        ));
    }

    #[test]
    fn coverage_must_match_in_both_directions() {
        let a = CellKey::parse("bidi:1:1").expect("parses");
        let b = CellKey::parse("bidi:32:1").expect("parses");
        assert!(validate_coverage(&[a.clone(), b.clone()], &[b.clone(), a.clone()]).is_ok());

        // A summary cell with no raw samples would be evaluated from nothing.
        let error = validate_coverage(&[a.clone(), b.clone()], std::slice::from_ref(&a))
            .expect_err("must refuse");
        assert!(matches!(
            error,
            ContractError::CoverageMismatch { ref summary_only, .. } if summary_only == &["bidi:32:1"]
        ));

        // A raw cell absent from the summary would be measured then dropped.
        let error =
            validate_coverage(std::slice::from_ref(&a), &[a.clone(), b]).expect_err("must refuse");
        assert!(matches!(
            error,
            ContractError::CoverageMismatch { ref samples_only, .. } if samples_only == &["bidi:32:1"]
        ));
    }

    #[test]
    fn every_recorded_matrix_cell_satisfies_the_contract() {
        // The strongest available check: run the real rules over the real recorded
        // evidence rather than over synthetic data that shares this module's
        // assumptions. All twelve v1.8.0 gate cells must validate.
        // Evidence archives live beside the checkout, not inside it, so the path is
        // searched upward rather than assumed at one fixed depth.
        let summary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .map(|ancestor| {
                ancestor.join("artifacts/v180-release-gate/gates/matrix-formal-r01/summary.json")
            })
            .find(|candidate| candidate.is_file());
        let Some(raw) = summary.and_then(|path| std::fs::read_to_string(path).ok()) else {
            // Evidence archives are not part of the git checkout, so CI legitimately
            // has nothing to read here. The synthetic tests cover the rules; this one
            // adds real-evidence confirmation on hosts that retain the archive.
            eprintln!("recorded matrix evidence unavailable; skipping real-evidence check");
            return;
        };

        let mut checked = 0_usize;
        for (key, interleave, count) in recorded_cells(&raw) {
            let blocks =
                validate_sample_count(&key, count).unwrap_or_else(|error| panic!("{key}: {error}"));
            assert!(
                (MIN_EXACT_BLOCKS..=MAX_EXACT_BLOCKS).contains(&blocks),
                "{key}: {blocks} blocks"
            );
            validate_interleave(&key, &interleave, count)
                .unwrap_or_else(|error| panic!("{key}: {error}"));
            assert!(
                CellKey::parse(&key).is_some(),
                "{key}: recorded cell key must parse"
            );
            checked += 1;
        }
        assert_eq!(checked, 12, "the recorded gate has twelve protected cells");
    }

    /// Extracts `(cell key, interleave, samplesPerImplementation)` from a recorded
    /// matrix summary without pulling in a JSON dependency.
    fn recorded_cells(raw: &str) -> Vec<(String, Vec<MatrixRole>, usize)> {
        let mut cells = Vec::new();
        // Cell objects appear as `"scenario:mib:conc": { ... }` inside `"cells"`.
        let body = raw.split_once("\"cells\"").map_or(raw, |(_, rest)| rest);
        let mut cursor = body;
        while let Some(start) = cursor.find("\"interleaveOrder\"") {
            // The nearest preceding quoted key that parses as a cell key is the owner.
            let head = &cursor[..start];
            let key = head
                .rmatch_indices('"')
                .find_map(|(index, _)| {
                    let candidate = head[index + 1..].split('"').next()?;
                    CellKey::parse(candidate).map(|_| candidate.to_owned())
                })
                .expect("every interleave belongs to a cell");
            let list_start = cursor[start..].find('[').expect("array opens") + start;
            let list_end = cursor[list_start..].find(']').expect("array closes") + list_start;
            let interleave: Vec<MatrixRole> = cursor[list_start + 1..list_end]
                .split(',')
                .filter_map(|entry| MatrixRole::parse(entry.trim().trim_matches('"')))
                .collect();
            let count_key = "\"samplesPerImplementation\"";
            let count = cursor[..start]
                .rfind(count_key)
                .or_else(|| cursor[start..].find(count_key).map(|offset| offset + start))
                .and_then(|index| {
                    let tail = &cursor[index + count_key.len()..];
                    let digits: String = tail
                        .chars()
                        .skip_while(|character| !character.is_ascii_digit())
                        .take_while(char::is_ascii_digit)
                        .collect();
                    digits.parse().ok()
                })
                .expect("every cell records a sample count");
            cells.push((key, interleave, count));
            cursor = &cursor[list_end..];
        }
        cells
    }

    #[test]
    fn the_integrity_scenario_name_is_what_the_original_excludes() {
        assert_eq!(INTEGRITY_SCENARIO, "integrity");
    }
}
