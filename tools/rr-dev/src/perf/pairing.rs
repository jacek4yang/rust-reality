//! Pair and block reconstruction.
//!
//! Separate from statistics on purpose. A pairing mistake does not produce an
//! obvious error — it produces a *plausible* p-value computed over the wrong
//! comparison. Pairing baseline samples against baseline samples, or ignoring
//! concurrency so a c1 measurement is divided by a c32 measurement, both yield
//! numbers that pass every statistical check and mean nothing. So this module is
//! tested and mutation-tested independently of the statistics it feeds.
//!
//! # The pairing key, transcribed
//!
//! From `ratios_for_rows` in the Python evaluator, a sample belongs to a cell
//! identified by exactly three things:
//!
//! ```text
//! (block, implementation, concurrency)
//! ```
//!
//! Within a cell, samples are aggregated by **median**, not mean. One ratio is then
//! produced per block as `median(candidate) / median(baseline)`. A cell with no
//! samples is a fail-closed error, never a skipped block — skipping would quietly
//! shrink the block count and change the exact test's denominator.
//!
//! No additional constraint is imposed here. The temptation to also require, say,
//! matching sample counts between the two sides was resisted: the original does not,
//! and this migration must accept exactly what the original accepts.

use std::collections::BTreeMap;

use super::{
    evidence::{EvidenceError, ImplementationRole, positive_number},
    stats::median,
};

/// One measurement drawn from an evidence row.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    /// Which ABBA block produced it, one-based.
    pub block: u32,
    /// Which side of the comparison produced it.
    pub implementation: ImplementationRole,
    /// Concurrency level the row was measured at.
    pub concurrency: u32,
    /// The measured value for the field under evaluation.
    pub value: f64,
}

/// Why pairing failed.
#[derive(Debug, Clone, PartialEq)]
pub enum PairingError {
    /// A block/implementation/concurrency cell had no samples at all.
    EmptyCell {
        /// The block that was incomplete.
        block: u32,
        /// The side that was missing.
        implementation: &'static str,
        /// The field being paired.
        field: String,
    },
    /// The order manifest did not carry four slots for every block.
    SlotCount {
        /// How many slots were found.
        found: usize,
        /// How many were required.
        expected: usize,
    },
    /// A block's slot positions were not exactly 1, 2, 3, 4.
    Positions {
        /// The offending block.
        block: u32,
    },
    /// A block's implementation sequence was neither ABBA nor BAAB.
    NotAlternating {
        /// The offending block.
        block: u32,
    },
    /// Two consecutive blocks used the same sequence.
    DirectionDidNotAlternate {
        /// The block that repeated its predecessor.
        block: u32,
    },
    /// A measurement failed admissibility before pairing.
    Evidence(EvidenceError),
}

impl From<EvidenceError> for PairingError {
    fn from(error: EvidenceError) -> Self {
        Self::Evidence(error)
    }
}

impl std::fmt::Display for PairingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyCell {
                block,
                implementation,
                field,
            } => write!(
                formatter,
                "block {block} {implementation} {field}: no samples"
            ),
            Self::SlotCount { found, expected } => write!(
                formatter,
                "order manifest does not contain exactly four slots per block: found {found}, expected {expected}"
            ),
            Self::Positions { block } => {
                write!(formatter, "block {block}: positions are incomplete")
            }
            Self::NotAlternating { block } => write!(formatter, "block {block}: not ABBA/BAAB"),
            Self::DirectionDidNotAlternate { block } => {
                write!(formatter, "block {block}: direction did not alternate")
            }
            Self::Evidence(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for PairingError {}

/// One slot in an order manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderSlot {
    /// Which block the slot belongs to, one-based.
    pub block: u32,
    /// Position within the block, 1 through 4.
    pub position: u32,
    /// Which side runs in this slot.
    pub implementation: ImplementationRole,
}

/// The two admissible within-block sequences.
///
/// ABBA and its mirror BAAB. Both balance order effects within a block; requiring
/// one specific sequence would bias every block the same way.
const ABBA: [ImplementationRole; 4] = [
    ImplementationRole::Baseline,
    ImplementationRole::Candidate,
    ImplementationRole::Candidate,
    ImplementationRole::Baseline,
];
const BAAB: [ImplementationRole; 4] = [
    ImplementationRole::Candidate,
    ImplementationRole::Baseline,
    ImplementationRole::Baseline,
    ImplementationRole::Candidate,
];

/// Validates an order manifest against an expected block count.
///
/// Three independent properties, each transcribed from `verify_order`:
///
/// 1. exactly four slots per block, so no block is short or padded;
/// 2. positions exactly `1, 2, 3, 4` within each block;
/// 3. the sequence is ABBA or BAAB, **and** differs from the previous block's.
///
/// The third is the one worth spelling out. Alternating the sequence between blocks
/// is what prevents a systematic ordering bias — if every block ran baseline first,
/// any warm-up or thermal drift would land on the candidate consistently and the
/// design would no longer be balanced.
///
/// # Errors
///
/// Returns the specific structural failure; nothing is repaired or skipped.
pub fn verify_order(slots: &[OrderSlot], blocks: u32) -> Result<(), PairingError> {
    let expected = (blocks as usize) * 4;
    if slots.len() != expected {
        return Err(PairingError::SlotCount {
            found: slots.len(),
            expected,
        });
    }

    let mut previous: Option<[ImplementationRole; 4]> = None;
    for block in 1..=blocks {
        let mut rows: Vec<&OrderSlot> = slots.iter().filter(|slot| slot.block == block).collect();
        rows.sort_by_key(|slot| slot.position);
        let positions: Vec<u32> = rows.iter().map(|slot| slot.position).collect();
        if positions != vec![1, 2, 3, 4] {
            return Err(PairingError::Positions { block });
        }
        let sequence: [ImplementationRole; 4] = [
            rows[0].implementation,
            rows[1].implementation,
            rows[2].implementation,
            rows[3].implementation,
        ];
        if sequence != ABBA && sequence != BAAB {
            return Err(PairingError::NotAlternating { block });
        }
        if previous == Some(sequence) {
            return Err(PairingError::DirectionDidNotAlternate { block });
        }
        previous = Some(sequence);
    }
    Ok(())
}

/// Reconstructs one ratio per block from validated samples.
///
/// For each block, samples are selected by the full key — block, implementation and
/// concurrency — then reduced by median, and the block's ratio is
/// `median(candidate) / median(baseline)`.
///
/// # Errors
///
/// Returns [`PairingError::EmptyCell`] if either side of any block has no matching
/// sample. This is deliberately fatal: silently dropping the block would change the
/// number of blocks the exact test enumerates over, and therefore the p-value.
pub fn block_ratios(
    samples: &[Sample],
    blocks: u32,
    concurrency: u32,
    field: &str,
) -> Result<Vec<f64>, PairingError> {
    let mut ratios = Vec::with_capacity(blocks as usize);
    for block in 1..=blocks {
        let mut sides: BTreeMap<ImplementationRole, Vec<f64>> = BTreeMap::new();
        for sample in samples {
            if sample.block == block && sample.concurrency == concurrency {
                let value = positive_number(Some(sample.value), &format!("{field} row"))?;
                sides.entry(sample.implementation).or_default().push(value);
            }
        }
        let mut medians = BTreeMap::new();
        for role in [ImplementationRole::Baseline, ImplementationRole::Candidate] {
            let values = sides.get(&role).filter(|values| !values.is_empty());
            let Some(values) = values else {
                return Err(PairingError::EmptyCell {
                    block,
                    implementation: role.as_str(),
                    field: field.to_owned(),
                });
            };
            medians.insert(
                role,
                median(values).map_err(|_| PairingError::EmptyCell {
                    block,
                    implementation: role.as_str(),
                    field: field.to_owned(),
                })?,
            );
        }
        ratios
            .push(medians[&ImplementationRole::Candidate] / medians[&ImplementationRole::Baseline]);
    }
    Ok(ratios)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(block: u32, position: u32, implementation: ImplementationRole) -> OrderSlot {
        OrderSlot {
            block,
            position,
            implementation,
        }
    }

    /// Builds `blocks` well-formed blocks, alternating ABBA and BAAB.
    fn valid_order(blocks: u32) -> Vec<OrderSlot> {
        let mut slots = Vec::new();
        for block in 1..=blocks {
            let sequence = if block % 2 == 1 { ABBA } else { BAAB };
            for (index, implementation) in sequence.iter().enumerate() {
                #[expect(clippy::cast_possible_truncation, reason = "index is 0..4")]
                slots.push(slot(block, index as u32 + 1, *implementation));
            }
        }
        slots
    }

    fn sample(block: u32, role: ImplementationRole, concurrency: u32, value: f64) -> Sample {
        Sample {
            block,
            implementation: role,
            concurrency,
            value,
        }
    }

    /// One block per entry, baseline then candidate, all at one concurrency.
    fn paired_samples(values: &[(f64, f64)], concurrency: u32) -> Vec<Sample> {
        let mut samples = Vec::new();
        for (index, (baseline, candidate)) in values.iter().enumerate() {
            #[expect(clippy::cast_possible_truncation, reason = "test data is tiny")]
            let block = index as u32 + 1;
            samples.push(sample(
                block,
                ImplementationRole::Baseline,
                concurrency,
                *baseline,
            ));
            samples.push(sample(
                block,
                ImplementationRole::Candidate,
                concurrency,
                *candidate,
            ));
        }
        samples
    }

    #[test]
    fn a_single_valid_pair_produces_one_ratio() {
        let samples = paired_samples(&[(100.0, 110.0)], 1);
        let ratios = block_ratios(&samples, 1, 1, "throughput").expect("valid");
        assert_eq!(ratios, vec![1.1]);
    }

    #[test]
    fn multiple_valid_pairs_produce_one_ratio_each_in_block_order() {
        let samples = paired_samples(&[(100.0, 110.0), (200.0, 190.0), (50.0, 50.0)], 1);
        let ratios = block_ratios(&samples, 3, 1, "throughput").expect("valid");
        assert_eq!(ratios, vec![1.1, 0.95, 1.0]);
    }

    #[test]
    fn input_order_does_not_change_the_result() {
        let mut forward = paired_samples(&[(100.0, 110.0), (200.0, 190.0)], 1);
        let expected = block_ratios(&forward, 2, 1, "throughput").expect("valid");
        forward.reverse();
        let reversed = block_ratios(&forward, 2, 1, "throughput").expect("valid");
        assert_eq!(
            expected, reversed,
            "pairing is by identity, so input order must be irrelevant"
        );
    }

    #[test]
    fn samples_within_a_cell_are_reduced_by_median_not_mean() {
        // Median of [10, 20, 300] is 20; the mean would be 110. Choosing the wrong
        // reducer would change every ratio in a way no later check would catch.
        let samples = vec![
            sample(1, ImplementationRole::Baseline, 1, 10.0),
            sample(1, ImplementationRole::Baseline, 1, 20.0),
            sample(1, ImplementationRole::Baseline, 1, 300.0),
            sample(1, ImplementationRole::Candidate, 1, 40.0),
        ];
        let ratios = block_ratios(&samples, 1, 1, "throughput").expect("valid");
        assert_eq!(ratios, vec![2.0], "40 / median(10,20,300) = 40 / 20");
    }

    #[test]
    fn concurrency_is_part_of_the_pairing_key() {
        // A c1 sample must never be divided by a c32 sample. Both cells exist here;
        // asking for c1 must use only c1.
        let samples = vec![
            sample(1, ImplementationRole::Baseline, 1, 100.0),
            sample(1, ImplementationRole::Candidate, 1, 110.0),
            sample(1, ImplementationRole::Baseline, 32, 400.0),
            sample(1, ImplementationRole::Candidate, 32, 200.0),
        ];
        assert_eq!(
            block_ratios(&samples, 1, 1, "throughput").expect("valid"),
            vec![1.1]
        );
        assert_eq!(
            block_ratios(&samples, 1, 32, "throughput").expect("valid"),
            vec![0.5]
        );
    }

    #[test]
    fn a_missing_baseline_fails_closed() {
        let samples = vec![sample(1, ImplementationRole::Candidate, 1, 110.0)];
        assert!(matches!(
            block_ratios(&samples, 1, 1, "throughput"),
            Err(PairingError::EmptyCell {
                block: 1,
                implementation: "baseline",
                ..
            })
        ));
    }

    #[test]
    fn a_missing_candidate_fails_closed() {
        let samples = vec![sample(1, ImplementationRole::Baseline, 1, 100.0)];
        assert!(matches!(
            block_ratios(&samples, 1, 1, "throughput"),
            Err(PairingError::EmptyCell {
                block: 1,
                implementation: "candidate",
                ..
            })
        ));
    }

    #[test]
    fn an_incomplete_final_block_fails_closed_rather_than_shrinking_the_test() {
        // Two complete blocks then a third with only a baseline. Dropping block 3
        // would hand the exact test 2 blocks instead of 3 and change its denominator,
        // so it must be an error.
        let mut samples = paired_samples(&[(100.0, 110.0), (100.0, 105.0)], 1);
        samples.push(sample(3, ImplementationRole::Baseline, 1, 100.0));
        assert!(matches!(
            block_ratios(&samples, 3, 1, "throughput"),
            Err(PairingError::EmptyCell { block: 3, .. })
        ));
    }

    #[test]
    fn a_concurrency_mismatch_leaves_the_cell_empty_and_fails_closed() {
        let samples = vec![
            sample(1, ImplementationRole::Baseline, 1, 100.0),
            sample(1, ImplementationRole::Candidate, 32, 110.0),
        ];
        assert!(matches!(
            block_ratios(&samples, 1, 1, "throughput"),
            Err(PairingError::EmptyCell { .. })
        ));
    }

    #[test]
    fn a_non_positive_measurement_is_refused_before_pairing() {
        for bad in [0.0, -5.0, f64::NAN, f64::INFINITY] {
            let samples = vec![
                sample(1, ImplementationRole::Baseline, 1, bad),
                sample(1, ImplementationRole::Candidate, 1, 110.0),
            ];
            assert!(
                matches!(
                    block_ratios(&samples, 1, 1, "throughput"),
                    Err(PairingError::Evidence(_))
                ),
                "{bad} must be refused"
            );
        }
    }

    #[test]
    fn a_well_formed_order_manifest_validates() {
        assert!(verify_order(&valid_order(12), 12).is_ok());
        assert!(verify_order(&valid_order(16), 16).is_ok());
    }

    #[test]
    fn an_order_manifest_must_carry_four_slots_per_block() {
        let mut slots = valid_order(3);
        slots.pop();
        assert!(matches!(
            verify_order(&slots, 3),
            Err(PairingError::SlotCount {
                found: 11,
                expected: 12
            })
        ));
    }

    #[test]
    fn duplicated_positions_are_rejected() {
        let mut slots = valid_order(1);
        slots[3].position = 1;
        assert!(matches!(
            verify_order(&slots, 1),
            Err(PairingError::Positions { block: 1 })
        ));
    }

    #[test]
    fn a_sequence_that_is_neither_abba_nor_baab_is_rejected() {
        // ABAB balances nothing: the candidate is always second.
        let slots = vec![
            slot(1, 1, ImplementationRole::Baseline),
            slot(1, 2, ImplementationRole::Candidate),
            slot(1, 3, ImplementationRole::Baseline),
            slot(1, 4, ImplementationRole::Candidate),
        ];
        assert!(matches!(
            verify_order(&slots, 1),
            Err(PairingError::NotAlternating { block: 1 })
        ));
    }

    #[test]
    fn all_baseline_or_all_candidate_blocks_are_rejected() {
        for role in [ImplementationRole::Baseline, ImplementationRole::Candidate] {
            let slots: Vec<OrderSlot> = (1..=4).map(|position| slot(1, position, role)).collect();
            assert!(matches!(
                verify_order(&slots, 1),
                Err(PairingError::NotAlternating { block: 1 })
            ));
        }
    }

    #[test]
    fn consecutive_blocks_must_not_repeat_the_same_sequence() {
        // Both blocks ABBA: legal individually, but the design requires the
        // direction to flip so ordering bias does not accumulate on one side.
        let mut slots = Vec::new();
        for block in 1..=2 {
            for (index, implementation) in ABBA.iter().enumerate() {
                #[expect(clippy::cast_possible_truncation, reason = "index is 0..4")]
                slots.push(slot(block, index as u32 + 1, *implementation));
            }
        }
        assert!(matches!(
            verify_order(&slots, 2),
            Err(PairingError::DirectionDidNotAlternate { block: 2 })
        ));
    }

    #[test]
    fn slot_order_within_the_manifest_is_irrelevant() {
        let mut slots = valid_order(4);
        slots.reverse();
        assert!(
            verify_order(&slots, 4).is_ok(),
            "validation sorts by position, so manifest order must not matter"
        );
    }

    #[test]
    fn extra_samples_outside_the_requested_block_range_are_ignored() {
        // Asking for 2 blocks must not be affected by a stray block 3, matching the
        // original's explicit `for block in range(1, blocks + 1)` loop.
        let mut samples = paired_samples(&[(100.0, 110.0), (100.0, 120.0)], 1);
        samples.push(sample(3, ImplementationRole::Baseline, 1, 1.0));
        samples.push(sample(3, ImplementationRole::Candidate, 1, 1000.0));
        let ratios = block_ratios(&samples, 2, 1, "throughput").expect("valid");
        assert_eq!(ratios, vec![1.1, 1.2]);
    }
}
