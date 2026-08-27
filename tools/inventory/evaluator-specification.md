# Frozen specification: release performance evaluator

Captured from `scripts/evaluate-release-performance.py` before any Rust was written.
The Python implementation is treated as **executable specification**: this document
records what it does, not what it should do. Methodology changes are out of scope for
the migration and belong in a separate reviewed PR.

## CLI and callers

```text
python3 scripts/evaluate-release-performance.py --manifest PATH --output PATH
exit 0 = evaluation completed;  exit non-zero = fail closed
```

No production code calls it. Callers are the gate harnesses under
`scripts/v150-release-gates/` and `scripts/v16-release-gates/`, plus documentation
references in `docs/performance.md`, its Chinese translation and `CHANGELOG.md`.

## Constants

```text
FAMILY_WISE_ALPHA      0.05
MIN_EXACT_BLOCKS       12
MAX_EXACT_BLOCKS       16
REQUIRED_KINDS         setup-abba, fallback-abba, matrix
bootstrapIterations    20000   (recorded in the output method block)
material improvement   median ratio >= 1.01, or <= 1/1.01 for lower-is-better
```

## Decision-bearing pipeline

```text
block ratios (candidate/baseline, one per completed ABBA block)
  -> validate: 12..=16 blocks, each positive and finite
  -> natural log of each ratio
  -> orient: x1 for higher-is-better, x-1 for lower-is-better
  -> exact sign-flip enumeration over all 2^n assignments
  -> two global Holm families, one per direction
  -> classification and pass/fail
```

**Exact sign-flip.** The statistic is the oriented **sum** (`math.fsum`), not the
mean; the two are monotonically related so the test is identical, but the recorded
`meanLogCandidateBenefit` is the sum divided by the block count. All `2^n`
assignments are enumerated — nothing is sampled, so there is no seed and no
approximation. Both tails are inclusive: `permuted <= observed` counts toward
regression and `permuted >= observed` toward improvement, which is why the two
p-values sum to slightly more than one. With 12 blocks every p-value is an exact
multiple of 1/4096, which the recorded evidence confirms.

**Holm.** Two independent global families, one over regression p-values and one over
improvement p-values, each covering every metric in the run. Ordering is by raw
p-value with ties broken by metric id, so the result is deterministic. Adjusted value
at rank `i` is `min(1, (n - i) * p_i)`, carried forward as a running maximum to keep
the sequence non-decreasing. Significance is `adjusted <= 0.05`, inclusive.

**Classification precedence.** `REGRESSION` > `KEEP_IMPROVEMENT` >
`SMALL_IMPROVEMENT` > `NO_SIGNIFICANT_CHANGE`. `pass = not regression`. A metric
significant in both directions is a fail-closed error, not a classification.

## Reporting-only, not decision-bearing

The block bootstrap. The output method block labels it
`"deterministic 95% block bootstrap (reporting only)"` and no verdict consults it.
Procedure: seed from the first eight bytes of `sha256(metric_id)` read big-endian,
`random.Random(seed)`, then `iterations` resample medians via
`random.choices(ratios, k=len(ratios))`; sort and report elements
`iterations / 40` and `(iterations * 39) / 40 - 1`. Requires at least three blocks.

This split is the key risk finding of the inventory: **verdict parity requires no RNG
reproduction at all.** The RNG only affects a reported interval.

## Fail-closed conditions

```text
block count outside 12..=16
ratio not positive or not finite
non-finite log ratio
empty Holm family
duplicate hypothesis id
raw p-value outside [0,1] or not finite
both directions significant for one metric
fewer than three blocks for the bootstrap
empty sample handed to a rank statistic
```

## Numerical parity

`math.fsum` is not ordinary summation. CPython reduces Shewchuk partials from the
largest down, stops at the first inexact addition, and then applies a half-even
correction when the residual and the next partial share a sign. Reproducing
Shewchuk's value without that final step was measured here as a **one-ULP**
disagreement against recorded gate evidence, so the correction is implemented.

`f64::ln` was verified bit-identical to Python's `math.log` across all twelve golden
block ratios, so no tolerance is needed there.

**Allowed non-byte-identical differences: none.** Every compared quantity —
oriented log ratios, mean log benefit, median, raw and adjusted p-values,
classification, and the bootstrap interval — reproduces exactly.

## Golden fixtures

`artifacts/v180-release-gate/gates/` preserves both `evaluator-manifest-r01.json` and
`evaluation-r01.json` (32 protected metrics, verdict `PASS`), with the evidence
directories intact, so the run is replayable. Two metrics are embedded as unit-test
vectors: the smallest raw p-value in the family
(`matrix-c1:direct-upload_32_1:p99-latency`, lower-is-better) and the largest
(`matrix-c1:framed-upload_32_1:throughput`, higher-is-better).
