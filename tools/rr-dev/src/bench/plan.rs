//! Balanced ABBA measurement ordering — the plan every formal A/B harness shares.
//!
//! Four legacy scripts each re-derived the same experiment design in a different
//! language: `benchmark-fallback-ab.sh` and `benchmark-setup-rate.sh` in Bash plus
//! an embedded Python order generator, `benchmark-setup-rate-xray.sh` with the same
//! generator under different labels, and `benchmark-matrix.sh` with a per-cell
//! variant that interleaves a third comparator. They agree on one rule:
//!
//! ```text
//! block ordinal even -> [start, other, other, start]
//! block ordinal odd  -> [other, start, start, other]
//! ```
//!
//! The scripts *look* like they disagree, because three of them number blocks from
//! one (`(block % 2 == 1) == (start == "baseline")`) and the matrix numbers them
//! from zero (`(block % 2 == 0) == (abba_start == "baseline")`). Those are the same
//! predicate over different bases. This module states the rule once over a
//! zero-based ordinal so a future reader cannot mistake the indexing for a
//! behavioural difference.
//!
//! What genuinely varies is declarative and lives in [`PortLayout`] and the choice
//! between [`abba_slots`] (blocks of four measurement slots, each owning fresh
//! processes) and [`interleaved_order`] (a flat per-cell sample order with a
//! comparator sample after every pair).
//!
//! ## Evidence compatibility
//!
//! [`order_json`] reproduces the legacy `order.json` contract: `schemaVersion` 1,
//! the exact `method` string, and per-slot `block` / `position` / `implementation`
//! with `serverPort` and `socksPort` present only when that harness recorded them.
//! Keys render sorted, as every native evidence writer in this crate does; JSON
//! object order carries no meaning and no consumer (`jq`, `json.load`) observes it.

use crate::perf::json_out::Json;

/// The `method` string every ABBA harness records in `order.json`.
pub const ABBA_METHOD: &str = "alternating balanced ABBA blocks";

/// How a harness assigns loopback ports to slots in the order manifest.
///
/// The port arithmetic is part of the recorded evidence, so it is owned and tested
/// here rather than open-coded per suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortLayout {
    /// No ports in the manifest; the suite allocates them per slot at run time.
    ///
    /// `benchmark-setup-rate-xray.sh` draws each slot's ports from the contract's
    /// reserved block as the slot starts, so its manifest records order only.
    Deferred,
    /// One server port per slot, after a single origin port at `base`.
    ///
    /// `benchmark-fallback-ab.sh`: `serverPort = base + 1 + ordinal`.
    ServerAfterOneOrigin {
        /// The first port of the reserved block.
        base: u16,
    },
    /// A server and a SOCKS port per slot, after two origin ports at `base`.
    ///
    /// `benchmark-setup-rate.sh`: `serverPort = base + 2 + ordinal * 2` and
    /// `socksPort = base + 3 + ordinal * 2`.
    ServerAndSocksAfterTwoOrigins {
        /// The first port of the reserved block.
        base: u16,
    },
}

/// One measurement slot: a block, a position within it, and what runs there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    /// One-based block number, as the manifest records it.
    pub block: usize,
    /// One-based position within the block, 1..=4.
    pub position: usize,
    /// The implementation label measured in this slot.
    pub implementation: String,
    /// The server port, when the harness fixes ports up front.
    pub server_port: Option<u16>,
    /// The SOCKS client port, when the harness fixes ports up front.
    pub socks_port: Option<u16>,
}

impl Slot {
    /// The evidence directory name, e.g. `block-01-slot-03-candidate`.
    ///
    /// Zero-padded so a lexicographic directory listing is measurement order, which
    /// is how every legacy aggregator read the slots back.
    #[must_use]
    pub fn directory_name(&self) -> String {
        format!(
            "block-{:02}-slot-{:02}-{}",
            self.block, self.position, self.implementation
        )
    }
}

/// Whether the block at zero-based `ordinal` leads with the starting implementation.
#[must_use]
const fn leads_with_start(ordinal: usize) -> bool {
    ordinal.is_multiple_of(2)
}

/// The four labels of one block, in measurement order.
fn block_order<'a>(implementations: [&'a str; 2], start: &str, ordinal: usize) -> [&'a str; 4] {
    let start_is_first = start == implementations[0];
    let (first, second) = if leads_with_start(ordinal) == start_is_first {
        (implementations[0], implementations[1])
    } else {
        (implementations[1], implementations[0])
    };
    [first, second, second, first]
}

/// Plans `blocks` balanced ABBA blocks of four slots each.
///
/// Reproduces the order generator shared by `benchmark-fallback-ab.sh`,
/// `benchmark-setup-rate.sh` and `benchmark-setup-rate-xray.sh`; only the labels
/// and [`PortLayout`] differ between them.
///
/// # Errors
///
/// Returns a message when `start` is not one of `implementations`, when the two
/// labels are equal, when `blocks` is zero, or when a computed port exceeds the
/// 16-bit range.
pub fn abba_slots(
    implementations: [&str; 2],
    start: &str,
    blocks: usize,
    ports: PortLayout,
) -> Result<Vec<Slot>, String> {
    if implementations[0] == implementations[1] {
        return Err(format!(
            "the two implementations must differ: both are {}",
            implementations[0]
        ));
    }
    if start != implementations[0] && start != implementations[1] {
        return Err(format!(
            "start must be {} or {}, got {start}",
            implementations[0], implementations[1]
        ));
    }
    if blocks == 0 {
        return Err("an ABBA plan needs at least one block".to_owned());
    }

    let mut slots = Vec::with_capacity(blocks * 4);
    for block in 1..=blocks {
        let order = block_order(implementations, start, block - 1);
        for (index, implementation) in order.into_iter().enumerate() {
            let position = index + 1;
            let ordinal = (block - 1) * 4 + index;
            let (server_port, socks_port) = assign_ports(ports, ordinal)?;
            slots.push(Slot {
                block,
                position,
                implementation: implementation.to_owned(),
                server_port,
                socks_port,
            });
        }
    }
    Ok(slots)
}

/// Applies a [`PortLayout`] to a zero-based slot ordinal.
fn assign_ports(ports: PortLayout, ordinal: usize) -> Result<(Option<u16>, Option<u16>), String> {
    let offset = |from_base: usize| -> Result<u16, String> {
        u16::try_from(from_base)
            .map_err(|_| format!("slot port {from_base} does not fit in the port range"))
    };
    match ports {
        PortLayout::Deferred => Ok((None, None)),
        PortLayout::ServerAfterOneOrigin { base } => {
            let server = offset(usize::from(base) + 1 + ordinal)?;
            Ok((Some(server), None))
        }
        PortLayout::ServerAndSocksAfterTwoOrigins { base } => {
            let server = offset(usize::from(base) + 2 + ordinal * 2)?;
            let socks = offset(usize::from(base) + 3 + ordinal * 2)?;
            Ok((Some(server), Some(socks)))
        }
    }
}

/// The per-cell sample order the matrix harness uses: balanced ABBA over two
/// implementations with a comparator sample appended after every pair.
///
/// `samples` is the number of samples *per implementation* for the pair, so the
/// returned order has `samples` entries for each of the three labels. An odd
/// `samples` contributes a half block, exactly as the original does.
///
/// # Errors
///
/// Returns a message when `start` is not one of `implementations`, when any two
/// labels collide, or when `samples` is zero.
pub fn interleaved_order(
    implementations: [&str; 2],
    start: &str,
    comparator: &str,
    samples: usize,
) -> Result<Vec<String>, String> {
    if implementations[0] == implementations[1] {
        return Err(format!(
            "the two implementations must differ: both are {}",
            implementations[0]
        ));
    }
    if start != implementations[0] && start != implementations[1] {
        return Err(format!(
            "start must be {} or {}, got {start}",
            implementations[0], implementations[1]
        ));
    }
    if implementations.contains(&comparator) {
        return Err(format!(
            "the comparator {comparator} must differ from both implementations"
        ));
    }
    if samples == 0 {
        return Err("an interleaved cell needs at least one sample".to_owned());
    }

    // Reuse the block rule; only the flattening differs. An odd sample count
    // contributes the leading half of one more block, as the original does.
    let mut paired: Vec<&str> = Vec::with_capacity(samples * 2);
    for ordinal in 0..samples / 2 {
        paired.extend(block_order(implementations, start, ordinal));
    }
    if samples % 2 == 1 {
        paired.extend(&block_order(implementations, start, samples / 2)[..2]);
    }

    let mut order = Vec::with_capacity(samples * 3);
    for pair in paired.chunks(2) {
        order.extend(pair.iter().map(|label| (*label).to_owned()));
        order.push(comparator.to_owned());
    }
    Ok(order)
}

/// Renders the legacy `order.json` manifest for a slot plan.
#[must_use]
pub fn order_json(slots: &[Slot]) -> Json {
    let entries: Vec<Json> = slots
        .iter()
        .map(|slot| {
            let mut fields: Vec<(String, Json)> = vec![
                (
                    "block".to_owned(),
                    Json::Int(i64::try_from(slot.block).unwrap_or(i64::MAX)),
                ),
                (
                    "position".to_owned(),
                    Json::Int(i64::try_from(slot.position).unwrap_or(i64::MAX)),
                ),
                (
                    "implementation".to_owned(),
                    Json::string(slot.implementation.clone()),
                ),
            ];
            if let Some(port) = slot.server_port {
                fields.push(("serverPort".to_owned(), Json::Int(i64::from(port))));
            }
            if let Some(port) = slot.socks_port {
                fields.push(("socksPort".to_owned(), Json::Int(i64::from(port))));
            }
            Json::object(fields)
        })
        .collect();
    Json::object([
        ("schemaVersion", Json::Int(1)),
        ("method", Json::string(ABBA_METHOD)),
        ("slots", Json::Array(entries)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(slots: &[Slot], first: &str) -> String {
        slots
            .iter()
            .map(|slot| {
                if slot.implementation == first {
                    'A'
                } else {
                    'B'
                }
            })
            .collect()
    }

    /// The self-test cases embedded in `benchmark-setup-rate.sh`:
    ///   blocks=3 start=baseline -> ABBA, BAAB, ABBA
    ///   blocks=4 start=candidate -> BAAB, ABBA, ...
    #[test]
    fn the_script_self_test_orderings_are_reproduced() {
        let slots = abba_slots(
            ["baseline", "candidate"],
            "baseline",
            3,
            PortLayout::Deferred,
        )
        .unwrap();
        assert_eq!(pattern(&slots, "baseline"), "ABBABAABABBA");

        let slots = abba_slots(
            ["baseline", "candidate"],
            "candidate",
            4,
            PortLayout::Deferred,
        )
        .unwrap();
        assert_eq!(pattern(&slots, "baseline"), "BAABABBABAABABBA");
    }

    /// `benchmark-setup-rate-xray.sh` uses the same rule under `rust`/`xray`.
    #[test]
    fn the_xray_comparator_labels_follow_the_same_rule() {
        let slots = abba_slots(["rust", "xray"], "rust", 2, PortLayout::Deferred).unwrap();
        let labels: Vec<&str> = slots
            .iter()
            .map(|slot| slot.implementation.as_str())
            .collect();
        assert_eq!(
            labels,
            [
                "rust", "xray", "xray", "rust", // block 1
                "xray", "rust", "rust", "xray", // block 2
            ]
        );
    }

    /// Every block is balanced and the plan is balanced overall — the property the
    /// whole design exists for.
    #[test]
    fn every_block_is_balanced_for_both_starts_and_all_block_counts() {
        for start in ["baseline", "candidate"] {
            for blocks in 1..=20 {
                let slots = abba_slots(
                    ["baseline", "candidate"],
                    start,
                    blocks,
                    PortLayout::Deferred,
                )
                .unwrap();
                assert_eq!(slots.len(), blocks * 4);
                for block in 1..=blocks {
                    let in_block: Vec<&Slot> =
                        slots.iter().filter(|slot| slot.block == block).collect();
                    assert_eq!(in_block.len(), 4);
                    assert_eq!(
                        in_block
                            .iter()
                            .filter(|slot| slot.implementation == "baseline")
                            .count(),
                        2,
                        "block {block} must measure each side twice"
                    );
                    // ABBA or BAAB: the first and last agree, the middle two agree.
                    assert_eq!(in_block[0].implementation, in_block[3].implementation);
                    assert_eq!(in_block[1].implementation, in_block[2].implementation);
                    assert_ne!(in_block[0].implementation, in_block[1].implementation);
                }
            }
        }
    }

    /// The one- and zero-based predicates in the scripts are the same rule.
    #[test]
    fn the_matrix_zero_based_predicate_agrees_with_the_one_based_one() {
        for ordinal in 0..8_usize {
            let one_based_block = ordinal + 1;
            // The three ABBA scripts: (block % 2 == 1) == (start == first).
            let script_leads = one_based_block % 2 == 1;
            // benchmark-matrix.sh: (block % 2 == 0) == (start == first), block from 0.
            assert_eq!(script_leads, leads_with_start(ordinal));
        }
    }

    /// `benchmark-fallback-ab.sh`: `serverPort = base + 1 + (block-1)*4 + position-1`.
    #[test]
    fn the_fallback_port_layout_matches_the_script_formula() {
        let base = 20_000;
        let slots = abba_slots(
            ["baseline", "candidate"],
            "baseline",
            3,
            PortLayout::ServerAfterOneOrigin { base },
        )
        .unwrap();
        for slot in &slots {
            let expected =
                base + 1 + u16::try_from((slot.block - 1) * 4 + slot.position - 1).unwrap();
            assert_eq!(slot.server_port, Some(expected));
            assert_eq!(slot.socks_port, None);
        }
        assert_eq!(slots[0].server_port, Some(20_001));
        assert_eq!(slots[11].server_port, Some(20_012));
    }

    /// `benchmark-setup-rate.sh`: two origins, then a server/SOCKS pair per slot.
    #[test]
    fn the_setup_rate_port_layout_matches_the_script_formula() {
        let base = 20_000;
        let slots = abba_slots(
            ["baseline", "candidate"],
            "baseline",
            3,
            PortLayout::ServerAndSocksAfterTwoOrigins { base },
        )
        .unwrap();
        for slot in &slots {
            let ordinal = u16::try_from((slot.block - 1) * 4 + slot.position - 1).unwrap();
            assert_eq!(slot.server_port, Some(base + 2 + ordinal * 2));
            assert_eq!(slot.socks_port, Some(base + 3 + ordinal * 2));
        }
        assert_eq!(slots[0].server_port, Some(20_002));
        assert_eq!(slots[0].socks_port, Some(20_003));
        // The block spans 2 + slot_count * 2 ports, matching the script's port_count.
        assert_eq!(slots[11].socks_port, Some(20_025));
    }

    /// The matrix cell order for the default `SAMPLES=5`, traced from the script.
    #[test]
    fn the_matrix_interleave_matches_the_script_for_five_samples() {
        let order = interleaved_order(["baseline", "final"], "baseline", "xray", 5).unwrap();
        assert_eq!(
            order,
            [
                "baseline", "final", "xray", //
                "final", "baseline", "xray", //
                "final", "baseline", "xray", //
                "baseline", "final", "xray", //
                "baseline", "final", "xray",
            ]
        );
        assert_eq!(order.len(), 15);
    }

    /// Whatever the sample count, each of the three labels appears exactly
    /// `samples` times — the invariant the aggregation depends on.
    #[test]
    fn the_interleaved_order_gives_every_label_the_same_sample_count() {
        for start in ["baseline", "final"] {
            for samples in 1..=9_usize {
                let order = interleaved_order(["baseline", "final"], start, "xray", samples)
                    .unwrap_or_else(|error| panic!("{samples} samples: {error}"));
                for label in ["baseline", "final", "xray"] {
                    assert_eq!(
                        order.iter().filter(|entry| *entry == label).count(),
                        samples,
                        "{label} at samples={samples} start={start}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_slot_directory_name_is_zero_padded_measurement_order() {
        let slots = abba_slots(
            ["baseline", "candidate"],
            "baseline",
            3,
            PortLayout::Deferred,
        )
        .unwrap();
        assert_eq!(slots[0].directory_name(), "block-01-slot-01-baseline");
        // Block 3 leads with the start again, so its last slot is the baseline.
        assert_eq!(slots[11].directory_name(), "block-03-slot-04-baseline");
        // A lexicographic sort of the directory names is measurement order.
        let mut names: Vec<String> = slots.iter().map(Slot::directory_name).collect();
        let ordered = names.clone();
        names.sort();
        assert_eq!(names, ordered);
    }

    #[test]
    fn the_order_manifest_matches_the_legacy_contract() {
        let slots = abba_slots(
            ["rust", "xray"],
            "rust",
            1,
            PortLayout::ServerAndSocksAfterTwoOrigins { base: 61_000 },
        )
        .unwrap();
        let rendered = order_json(&slots).to_python_json();
        assert!(rendered.contains("\"schemaVersion\": 1"));
        assert!(rendered.contains("\"method\": \"alternating balanced ABBA blocks\""));
        assert!(rendered.contains("\"implementation\": \"rust\""));
        assert!(rendered.contains("\"serverPort\": 61002"));
        assert!(rendered.contains("\"socksPort\": 61003"));

        // A deferred layout records order only, as setup-rate-xray does.
        let deferred = abba_slots(["rust", "xray"], "rust", 1, PortLayout::Deferred).unwrap();
        let rendered = order_json(&deferred).to_python_json();
        assert!(!rendered.contains("serverPort"));
        assert!(!rendered.contains("socksPort"));
    }

    #[test]
    fn invalid_plans_fail_closed() {
        assert!(abba_slots(["a", "a"], "a", 3, PortLayout::Deferred).is_err());
        assert!(abba_slots(["a", "b"], "c", 3, PortLayout::Deferred).is_err());
        assert!(abba_slots(["a", "b"], "a", 0, PortLayout::Deferred).is_err());
        // 12 slots need 2 + 24 ports, so a base of 65530 runs past 65535.
        assert!(
            abba_slots(
                ["a", "b"],
                "a",
                3,
                PortLayout::ServerAndSocksAfterTwoOrigins { base: 65_530 },
            )
            .is_err(),
            "a port block running past 65535 must be rejected, not wrapped"
        );
        assert!(interleaved_order(["a", "b"], "a", "a", 4).is_err());
        assert!(interleaved_order(["a", "b"], "a", "x", 0).is_err());
        assert!(interleaved_order(["a", "b"], "c", "x", 4).is_err());
    }
}
