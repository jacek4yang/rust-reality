# Benchmark policy and baseline

English | [简体中文](benchmarks.zh-CN.md)

## Built-in protocol measurements

Run an optimized binary on an otherwise idle host:

```shell
./scripts/build-release.sh
target/release/rust-reality benchmark \
  --duration-ms 5000 \
  --warmup-ms 1000 \
  > benchmark.json
```

The JSON records build mode, embedded commit, target OS and architecture,
visible CPU count, requested timings, operation counts, aggregate mean, and
per-sample p50/p95. Each case uses nine independent windows. Reported MiB/s is
logical input throughput for the named in-process operation; it is not socket,
proxy, or Internet throughput.

Criterion remains the tool for regression analysis with baselines and plots:

```shell
cargo bench --bench vless_decode
cargo bench --bench vision
```

## Recorded development-host sample

This sample is evidence that the command runs and produces stable bounded data,
not a release performance promise:

- Date: 2026-08-03 (Asia/Shanghai)
- Host: Intel Core i3-8100, 4 logical CPUs
- Kernel: Linux 6.12.94+deb13-amd64
- Rust: 1.96.0
- Measured time: 900 ms per case, 100 ms warm-up
- `vless.decode.ipv4`: 26.99 ns/op, 37.06 million ops/s
- `vision.decode.8k`: 164.93 ns/op, 6.06 million ops/s
- `nxr.auth.encode.domain`: 1237.62 ns/op, 0.808 million ops/s

For a comparison, preserve the complete JSON and repeat runs in randomized
implementation order on the same host, CPU governor, kernel, target, payload,
concurrency, and network impairment. Report every sample and confidence
interval; do not select the fastest run.

## Xray compatibility versus performance

`scripts/test-xray-interop.sh` is a compatibility gate: an unmodified Xray
26.7.28 client transfers a verified payload through the real public VLESS +
REALITY + Vision stack. Its one Internet request is not a benchmark.

Any future Xray performance comparison must separate:

- loopback protocol CPU cost;
- same-host relay throughput at fixed concurrency;
- controlled delay/loss/rate tests with `tc netem`;
- real-web samples whose DNS, origin, and Internet variance are disclosed.

No result may claim resistance to upstream volumetric DDoS or generalize one VPS
measurement to other CPUs and networks.

## Recorded Xray 26.7.28 loopback comparison

`scripts/benchmark-xray.sh` runs the same unmodified Xray SOCKS5 client against
both servers through VLESS + REALITY + Vision. It randomizes implementation
order with a recorded seed, verifies every response length, retains every
sample, and emits machine-readable JSON. The Xray server's new default rule that
blocks private destinations is explicitly overridden only so both servers can
reach the same loopback origin.

Recorded on 2026-08-03 using Linux 6.12.94, rustc 1.96.0, Xray 26.7.28, an
Intel Core i3-8100 with four cores, `dl.google.com:443` as the REALITY target,
nine samples per implementation, and 64 MiB per request:

| Concurrency | Implementation | Mean MiB/s | p50 MiB/s | Minimum MiB/s | Mean request seconds |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 | rust-reality | 266.56 | 259.34 | 231.38 | 0.2339 |
| 1 | Xray | 252.34 | 245.58 | 220.31 | 0.2481 |
| 4 | rust-reality | 762.57 | 799.18 | 616.96 | 0.3159 |
| 4 | Xray | 701.17 | 708.35 | 429.75 | 0.3390 |

The rust-reality/Xray p50 throughput ratios were 1.056 at concurrency one and
1.128 at concurrency four. On this host that is a modest measured lead, not a
multi-fold improvement. The shared Xray client and Python origin remain part of
both measurements, so this comparison isolates neither server CPU time nor
maximum NIC capacity.

No `tc netem` or equivalent privileged network impairment facility was
available on this host. Consequently these results make no weak-network claim;
latency, loss, reordering, and rate-limited testing must be collected separately
on a controlled interface rather than simulated and mislabeled as network data.

Reproduce either profile with:

```shell
SAMPLES=9 CONCURRENCY=1 PAYLOAD_MIB=64 \
  XRAY_BIN=/home/jacek/src/Xray-core/xray \
  ./scripts/benchmark-xray.sh > xray-c1.json

SAMPLES=9 CONCURRENCY=4 PAYLOAD_MIB=64 \
  XRAY_BIN=/home/jacek/src/Xray-core/xray \
  ./scripts/benchmark-xray.sh > xray-c4.json
```

## Adaptive relay backend measurements

`benches/relay_backends.rs` measures the relay engine itself over loopback. It
emits one JSON object per sample to standard output and retains every sample:

```shell
RR_BENCH_COMMIT="$(git rev-parse HEAD)" RR_BENCH_HOST="$(hostname)" \
  cargo bench --bench relay_backends -- --samples 5 --seed 20260804 \
  > benchmarks/relay-after.jsonl
```

Each sample records commit, timestamp, host, CPU, kernel, configuration, seed,
sample index, direction, payload size, concurrency, requested backend, selected
backend, duration, throughput, bytes moved, peak RSS, backend hit rate, and a
verification hash.

### Method

- Implementation order is shuffled per repetition from the recorded seed, so
  ordering cannot favour one backend.
- Every sample is kept. No fastest run is selected and nothing is averaged away
  before the raw file is written.
- Directions cover uplink-only, downlink-only and simultaneous bidirectional.
- Backends cover `buffered`, `splice` and `automatic`.

### Limitations that must be stated with any number

- These are **loopback** measurements on a single host. They measure relay
  engine cost, not Internet throughput, and must never be presented as a general
  speed promise.
- The implementation host for this branch was a 2-vCPU virtual machine. The
  512 MiB payload and 32-way concurrency rows of the full specification matrix
  were not executed there; the retained matrix covers 1 MiB and 32 MiB payloads
  at concurrency 1 and 4.
- `cpuUserNs`, `cpuSystemNs`, `contextSwitches`, `syscallCounts` and
  `allocations` are recorded as `null` rather than estimated. Steady-state
  allocation behaviour is proven separately and exactly by the allocation gate.
- io_uring and sockhash rows are absent because those backends declined on the
  implementation host. A decline is recorded, never a fabricated number.

### Baseline

`benchmarks/relay-baseline.jsonl` is produced from the unmodified baseline
commit `14ed098505b5cd9c3f5cc0d00c393c45428b0e42` in a separate worktree, using
the same scenario matrix, the same seed and the same shuffling, adapted only
where the baseline API differs (the baseline has no backend enum and no owned
relay entry point). Compare the two files by scenario tuple, never by row order.
