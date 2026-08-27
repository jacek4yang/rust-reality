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

No production code calls it. Callers are the historical gate harnesses under
`notes/history/release-gates/v150-release-gates/` and
`notes/history/release-gates/v16-release-gates/` (inert evidence), plus
documentation references in `docs/performance.md`, its Chinese translation and
`CHANGELOG.md`.

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

---

# Part II: the evidence loader, transcribed in full

Added after the statistical core landed. Everything below is read out of
`scripts/evaluate-release-performance.py` rather than inferred, so the remaining
implementation is a transcription task against a written specification instead of a
re-reading of dense Python.

## `verify_files(entry, kind)`

```text
runDir            must be a string starting with "/"; must be a directory; must not be a symlink
files             must be an object whose key set EXACTLY equals FILES_BY_KIND[kind]
per file, sorted  expected digest must be a 64-char lowercase hex string
                  runDir/<name> must be a file and not a symlink
                  path.resolve().parent must equal runDir.resolve()   <- escape guard
                  computed SHA-256 must equal the expected digest
returns           (runDir, {name: digest}) with the OBSERVED digests
```

## Host-lock verification

`verify_host_lock_metadata(value, context)` re-verifies against the live filesystem:

```text
protocolVersion   == 1
required          is True                    mode == "dedicatedKeeper"
path              absolute; is_file; not symlink; resolve() == path
deviceInode       matches /^[1-9][0-9]*:[1-9][0-9]*$/ AND equals f"{st_dev}:{st_ino}"
keeperPid         int > 1                    parentPid    int > 1
keeperStarttime   decimal string > 0         parentStarttime  decimal string > 0
keeperExe         absolute; is_file; resolve() == keeperExe
keeperHelper      {path, sha256}: absolute, hex64, is_file, not symlink,
                  resolve() == path, and re-hashed SHA-256 must match
returns           a normalised dict of exactly those fields plus required: True
```

`verify_pair_host_lock(environment, context)`:

```text
current    = verify_host_lock_metadata(environment.hostExclusiveLock)
preflight  = verify_host_lock_metadata(...preflight)
postflight = verify_host_lock_metadata(...postflight)
require    current == preflight == postflight     <- identity unchanged during collection
harness    must be an object
contract   = verify_contract_identity(harness.contract)
require    harness.keeperHelper == current.keeperHelper
result     current with contract attached
```

`verify_contract_identity(value, context)`: absolute path, hex64 digest, is_file, not
symlink, `resolve() == path`, re-hashed digest matches. **This is the check whose
durability limit ADR 0009 records.**

`coordination_identity(value)` projects exactly seven fields, and all three workloads
must agree on it:

```text
protocolVersion, path, deviceInode, mode, keeperExe,
keeperHelperSha256 (= keeperHelper.sha256), contractSha256 (= contract.sha256)
```

## `verify_success_marker(marker, evidence_path, run_id, collector, context)`

```text
schemaVersion == 1 and status == "COMPLETE"
exitCode is an int (not bool) and == 0
run_id is a non-empty string and marker.runId == run_id
marker.collector == collector
marker.evidence.path   == str(evidence_path.resolve())
marker.evidence.sha256 == sha256_file(evidence_path)
```

Collector names: `benchmark-setup-rate` for `setup-abba`, `benchmark-fallback-ab` for
`fallback-abba`, `benchmark-matrix` for `matrix`.

## `evaluate_pair_run(entry, kind, candidate, baseline, iterations)`

Loads `summary.json`, `environment.json`, `completion.json`, `order.json` and
`raw-samples.jsonl`. The success marker is verified against **`environment.json`** with
`environment.runId`.

```text
summary.status             == "COMPLETE"
summary.performanceVerdict == "NOT_EVALUATED"      <- collector must not claim a verdict
summary.failures           == 0
environment.blocks         int in 12..=16
environment.samplesPerSlot int >= 1
environment.concurrencies  string (whitespace-split to ints) OR list of ints;
                           non-empty, no duplicates, every value a positive int
order                      verify_order(order, blocks)
```

Row validation, keyed by `(block, position)` against the order manifest:

```text
(block, position) must exist in the order manifest
row.implementation must equal the order's implementation for that slot
row.concurrency must be one of the declared concurrencies
row.failed == 0
setup-abba:   environment.connectionsPerSample int > 0
              row.connections == connectionsPerSample
fallback:     environment.payloadMiB int, expected = payloadMiB * 1024 * 1024 > 0
              row.requests == concurrency
              row.bytesObserved is a list of length concurrency, every value == expected
              row.perRequestSeconds is a list of length concurrency
grouping:     (block, position, concurrency) -> rows
completeness: every (block, position) x concurrency cell has exactly samplesPerSlot rows
              and their sampleIndex values are exactly 0..samplesPerSlot-1
```

Metrics produced, per concurrency:

```text
{workload}:c{c}:throughput
    field  connectionsPerSecond (setup) | throughputMiBPerSecond (fallback)
    unit   connectionsPerSecond         | MiBPerSecond
    higher-is-better, ratios from ratios_for_rows(rows, blocks, c, field)

{workload}:c{c}:p99-latency   unit seconds, lower-is-better
    setup     ratios_for_rows(rows, blocks, c, "p99Seconds")
    fallback  per block, pool EVERY perRequestSeconds value across the cell's rows
              for each implementation, take nearest_rank(pooled, 0.99),
              ratio = candidate / baseline
```

Then one CPU metric via `cpu_metrics(summary, field, blocks, workload, unit, iterations)`:

```text
id     {workload}:server-cpu, measure serverCpu, lower-is-better
field  serverCpuPerConnection (setup) | serverCpuPerGiB (fallback)
unit   microsecondsPerConnection      | secondsPerGiB
rows   summary[field].blocks must be a list of exactly `blocks` objects
per    baseline and candidate positive; ratio = candidate / baseline;
       recorded candidateVsBaseline must satisfy isclose(ratio, recorded, rel_tol=1e-9)
```

## `evaluate_matrix(entry, candidate, baseline, iterations)`

Loads `summary.json`, `run-contract.json`, `run-completion.json`, `samples.jsonl`.
Marker is verified against **`run-contract.json`** with `contract.runId`.

`verify_matrix_identity(summary, contract, candidate, baseline)`:

```text
summary.status == "COMPLETE"; performanceVerdict == "NOT_EVALUATED"
summary.failures == []                     <- an empty LIST here, not 0
summary.totals.invalidSamples == 0
summary.identity.candidateCommit == candidate.commit
summary.identity.baselineCommit  == baseline.commit
summary.identity.binaries.final.sha256    == candidate.sha256      <- "final"
summary.identity.binaries.baseline.sha256 == baseline.sha256
summary.identity.binariesPinned is True
contract.phase == "complete" and contract.exploratory is False
contract.script.harnessCommit == candidate.commit
contract.binaries, keyed by label: "candidate" and "baseline" rows must carry
    matching sha256, matching sourceCommit, and a hex buildId
host lock from contract.hostExclusiveLock, contract identity from contract.contract
```

Cell coverage and per-cell checks are already implemented in `perf::contract`. The
remaining per-cell dataflow:

```text
selected = rows where scenario, direction, payloadBytes == payloadMiB*1024*1024,
           and concurrency all equal the cell's values
expected_raw_order = walk interleaveOrder assigning each implementation the next
           sequential sampleIndex, producing [(impl, index), ...]
require    [(row.implementation, row.sampleIndex) for row in selected]
           == expected_raw_order          <- exact order, not a set comparison
per impl in (baseline, final):
           exactly `count` rows; sampleIndex values exactly 0..count-1
           every row: invalid is False, bytesVerified is True,
                      throughputMiBPerSecond positive,
                      perRequestSeconds a non-empty list of positive numbers
xray:      exactly `count` rows with sampleIndex exactly 0..count-1
```

Block construction is **consecutive sampleIndex pairs**, not interleave chunks:

```text
for block in 0..count/2:
    indexes = {2*block, 2*block+1}
    per implementation: exactly 2 rows with those indexes
        throughput = median of the two throughputMiBPerSecond values
        tail       = nearest_rank(all perRequestSeconds from both rows, 0.99)
    throughput_ratio = final / baseline
    latency_ratio    = final_tail / baseline_tail
```

Metric ids use a sanitised cell key, `re.sub(r"[^A-Za-z0-9._-]+", "_", key)`, so
`bidi:1:1` becomes `bidi_1_1`:

```text
{workload}:{safe_key}:throughput    measure throughput, MiBPerSecond, higher-is-better
{workload}:{safe_key}:p99-latency   measure p99Latency, seconds, lower-is-better
```

## The `inputs` entry, identical in shape for both loaders

```text
name, kind, runDir (string), files (observed digests),
status (from summary), dataQualityVerdict: "PASS" (constant),
collectorPerformanceVerdict (from summary.performanceVerdict),
hostExclusiveLock (the verified, normalised lock identity including contract)
```

It is derived from the same validation pass, so the report cannot claim inputs that
differ from what the evaluator actually validated.

## Recorded v1.8.0 metric census

Eight paired metrics plus twenty-four matrix metrics is the recorded thirty-two:

```text
setup     c1 and c32 x {throughput, p99-latency} + server-cpu   = 5
fallback  c1 x {throughput, p99-latency} + server-cpu           = 3
matrix    12 cells x {throughput, p99-latency}                  = 24
```
