# v1.6.0 release gates

Wrappers and analysis for the v1.6.0 release-gate evidence runs, mirroring
`scripts/v150-release-gates/`.  Baseline is the published **v1.5.1 release
asset** (gitCommit `149f126`, SHA-256
`49f3246f571b63043dd3fa198c84d6f2c113c64372e6955c1a0282fb0926956b`, extracted
read-only at `artifacts/v1.6.0/baseline/extracted/rust-reality` and bound by
`baseline-identity-149f126.json`).  The candidate is a **prebuilt read-only
binary passed via `RR_CANDIDATE_BIN`** because the v1.6.0 candidate commit is
not merged when this harness lands; its source commit defaults to the HEAD of
`REPOSITORY` (the main checkout).  Xray comparator:
`artifacts/xray-reference-v26.7.28` (SHA-256 `23d228d7…04c5268`).

`env-common.sh` exports everything the workload scripts need, including:

- `GATES=artifacts/v1.6.0/gates`, `TMPDIR=$GATES/tmp` (create it first),
- `RR_HOST_EXCLUSIVE_LOCK=/tmp/v16-bench.lock` — overrides
  `benchmark-contract.sh`'s compiled-in `.coord/v1.5.0/` default **via env
  only**; the contract script itself is unmodified,
- `MANAGE_PIPE_USER_PAGES_SOFT=0`, `GOFLAGS=-buildvcs=false`.

## Lock discipline

`/tmp/v16-bench.lock` serializes ALL benchmark/perf/soak runs on this host
across workers.

- **Formal contract runs** (setup-abba, fallback-abba, matrix-formal, and any
  run without `EXPLORATORY=1`) acquire the lock themselves through the
  contract's dedicated keeper.  Do NOT wrap them in an outer
  `flock -x /tmp/v16-bench.lock` — the keeper opens its own FD on the same
  file and would deadlock.
- **Exploratory runs** (`EXPLORATORY=1`: run-matrix.sh, run-soak.sh,
  cpu-per-gib.sh, and the gap-cell scripts below) take no contract lock, so
  the caller MUST hold the outer lock: queue with
  `flock -x /tmp/v16-bench.lock <cmd>`, hold it as briefly as possible, and
  verify afterwards that no orphan inherited it:
  `fuser -v /tmp/v16-bench.lock; pgrep -af 'bench-origin|rust-reality serve|xray'`.

## Invocations

```bash
source /home/jacek/work/kimi-rust-reality-performance/proxy-env.sh  # crates.io/GitHub only
mkdir -p /home/jacek/work/kimi-rust-reality-performance/artifacts/v1.6.0/gates/tmp
export RR_CANDIDATE_BIN=<read-only v1.6.0 candidate rust-reality ELF>
G=scripts/v16-release-gates

# Formal legs (contract lock via keeper; clean repo at the candidate commit):
$G/run-setup-abba.sh 01
$G/run-fallback-abba.sh 01
$G/run-matrix-formal.sh 01

# Exploratory legs (outer lock required):
flock -x /tmp/v16-bench.lock $G/run-matrix.sh 01
flock -x /tmp/v16-bench.lock env ABBA_START=final $G/run-matrix.sh 02
flock -x /tmp/v16-bench.lock $G/run-soak.sh baseline 01
flock -x /tmp/v16-bench.lock $G/run-soak.sh candidate 01
flock -x /tmp/v16-bench.lock $G/cpu-per-gib.sh \
    artifacts/v1.6.0/baseline/extracted/rust-reality baseline \
    artifacts/v1.6.0/gates/cpu-base-r01 61600
flock -x /tmp/v16-bench.lock $G/cpu-per-gib.sh \
    "$RR_CANDIDATE_BIN" candidate artifacts/v1.6.0/gates/cpu-cand-r01 61610

# Evaluation:
source $G/env-common.sh   # exports RUST_REALITY_COMMIT/SHA256 for the manifest
python3 $G/build-manifest.py
python3 scripts/evaluate-release-performance.py \
    artifacts/v1.6.0/gates/evaluator-manifest.json
python3 $G/analyze-gates.py   # exploratory c32 matrix + cpu-per-gib; exit 1 on regression
```

## README comparison gap cells (G1/G2/G3/G5, notes/v1.6.0/readme-plan.md)

All four are contract-driven, exploratory-capable, and safe on this 4-core
host under the lock.  Exploratory sanity invocations:

```bash
S=$PWD/scripts   # from any checkout at the candidate commit
X=/home/jacek/work/kimi-rust-reality-performance/artifacts/xray-reference-v26.7.28
B=/home/jacek/work/kimi-rust-reality-performance/artifacts/v1.6.0/baseline/extracted/rust-reality

# G1 — setup rate / CPU-per-conn, Xray as SERVER leg vs rust server:
flock -x /tmp/v16-bench.lock env EXPLORATORY=1 \
    RUST_REALITY_BIN=$B XRAY_BIN=$X \
    BLOCKS=2 SAMPLES=2 CONNS=32 CONCURRENCIES="1 8" MEASURE_MODE=wall \
    $S/benchmark-setup-rate-xray.sh
# (MEASURE_MODE=perf adds perf-stat server µs/conn; requires passwordless sudo.)

# G2 — Xray server RSS/FD under the soak load shape:
flock -x /tmp/v16-bench.lock env EXPLORATORY=1 \
    XRAY_BIN=$X DURATION_MIN=1 ROUND_SLEEP=2 \
    $S/sampling-xray-resources.sh

# G3 — DNS cold/warm/burst vs Xray with a counted loopback fake DNS:
flock -x /tmp/v16-bench.lock env EXPLORATORY=1 \
    RUST_REALITY_BIN=$B XRAY_BIN=$X \
    SAMPLES=2 WARM_SAMPLES=1 CONNS=8 CONCURRENCY=8 BURST_CONNS=16 \
    $S/benchmark-dns-comparison.sh

# G5 — routing-rule scaling 10/100/1000/10000 vs Xray (explicit domain rules):
flock -x /tmp/v16-bench.lock env EXPLORATORY=1 \
    RUST_REALITY_BIN=$B XRAY_BIN=$X \
    RULE_SCALES="10 100" BLOCKS=2 SAMPLES=2 CONNS=32 CONCURRENCY=8 \
    $S/benchmark-routing-comparison.sh
```

Formal (non-exploratory) invocations of the gap scripts additionally require
`RUN_ID OUT_DIR TMPDIR PORT_BASE`, SHA-256 pins (`RUST_REALITY_SHA256`,
`XRAY_SHA256`), `EXPECTED_SOURCE_COMMIT` for the rust binary, read-only
binary paths, and a clean repository; the contract lock keeper then owns
`/tmp/v16-bench.lock` and no outer `flock` may be used.
