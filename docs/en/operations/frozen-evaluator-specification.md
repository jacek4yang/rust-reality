# Frozen evaluator specification

This document records the methodology contract of the release performance
evaluator (`cargo dev perf evaluate`) as implemented in `tools/rr-dev` and as
transcribed from the original Python evaluator that it replaced. It is the
durable, human-readable record of what the evaluator computes and which legacy
semantics are reproduced exactly rather than tidied.

## Statistical core

```text
FAMILY_WISE_ALPHA      0.05
MIN_EXACT_BLOCKS       12
MAX_EXACT_BLOCKS       16
REQUIRED_KINDS         setup-abba, fallback-abba, matrix
bootstrapIterations    20000   (recorded in the output method block)
material improvement   median ratio >= 1.01, or <= 1/1.01 for lower-is-better
```

Decision-bearing pipeline:

```text
block ratios (candidate/baseline, one per completed ABBA block)
  -> validate: 12..=16 blocks, each positive and finite
  -> natural log of each ratio
  -> orient: x1 for higher-is-better, x-1 for lower-is-better
  -> exact sign-flip enumeration over all 2^n assignments
  -> two global Holm families, one per direction
  -> classification and pass/fail
```

**Exact sign-flip.** The statistic is the oriented **sum** (extended-precision
`fsum` semantics), not the mean; the two are monotonically related so the test
is identical, but the recorded `meanLogCandidateBenefit` is the sum divided by
the block count. All `2^n` assignments are enumerated — nothing is sampled, so
there is no seed and no approximation. Both tails are inclusive: `permuted <=
observed` counts toward regression and `permuted >= observed` toward
improvement, which is why the two p-values sum to slightly more than one. With
12 blocks every p-value is an exact multiple of 1/4096.

**Holm.** Two independent global families, one over regression p-values and one
over improvement p-values, each covering every metric in the run. Ordering is
by raw p-value with ties broken by metric id, so the result is deterministic.
Adjusted value at rank `i` is `min(1, (n - i) * p_i)`, carried forward as a
running maximum to keep the sequence non-decreasing. Significance is
`adjusted <= 0.05`, inclusive.

**Classification precedence.** `REGRESSION` > `KEEP_IMPROVEMENT` >
`SMALL_IMPROVEMENT` > `NO_SIGNIFICANT_CHANGE`. `pass = not regression`. A
metric significant in both directions is a fail-closed error, not a
classification.

## Reporting-only, not decision-bearing

The block bootstrap. The output method block labels it
`"deterministic 95% block bootstrap (reporting only)"` and no verdict consults
it. Procedure: seed from the first eight bytes of the SHA-256 of `metric_id`
read big-endian, then resample medians over the recorded iteration count; sort
and report the 2.5% and 97.5% elements. Requires at least three blocks.

This split is the key parity finding: **verdict parity requires no RNG
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

Extended-precision summation reproduces CPython's `math.fsum` exactly,
including the final half-even correction when the residual and the next partial
share a sign; reproducing Shewchuk's value without that final step was measured
as a one-ULP disagreement against recorded gate evidence.

`f64::ln` was verified bit-identical to Python's `math.log` across all twelve
golden block ratios, so no tolerance is needed there.

**Allowed non-byte-identical differences: none** for metric values. For the
evaluator self-description block, exactly two fields are provenance and MAY
differ between checkouts: `evaluator.path` and `evaluator.sha256`. The
parity-baseline measurement that established this set (recorded v1.8.0 gate
replayed byte-exactly except for those two fields) is a durable acceptance
fact: byte-level verdict parity is achievable and stays the acceptance gate
(`historical_verdict_changes = 0`). The exception list MUST NOT be widened
without a recorded measurement.

## Legacy evidence-loader semantics that must not be unified

The evidence loader (`tools/rr-dev/src/perf/loader.rs`) validates recorded
files into typed evidence. Each of these looks like an opportunity to share
code and is not:

1. `summary.failures` is the integer `0` in paired evidence and an empty
   **array** in matrix evidence.
2. The paired success marker is verified against `environment.json`; the matrix
   marker against `run-contract.json`.
3. Matrix blocks are consecutive `sampleIndex` pairs. The interleave governs raw
   execution order only; pairing is index arithmetic.
4. Raw sample order is compared as an exact sequence, never as a set and never
   after sorting.
5. Setup p99 reads a precomputed field; fallback p99 pools every
   `perRequestSeconds` value across the cell and then takes a nearest-rank
   quantile.
6. Metric identifiers sanitise the cell key, so `bidi:1:1` becomes `bidi_1_1`.

## Evidence identity

The evaluator re-verifies several external inputs against the live filesystem
when it replays recorded evidence (host-exclusive-lock contract and keeper
identity). ADR 0009 records why that makes archived evidence fragile and the
content-addressed archival resolution that answers it.
