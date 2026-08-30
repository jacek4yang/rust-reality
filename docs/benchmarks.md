# Benchmark policy and canonical samples

English | [简体中文](benchmarks.zh-CN.md)

This document states how rust-reality is measured, which samples are canonical
for v1.0.0, and the limits on interpreting any number here. The final frozen
v1.0.0 release comparison matrix is produced at release time from the same
harnesses; the design-level evidence behind the numbers lives in
[performance.md](performance.md).

## Measurement policy

- Every sample is retained; no fastest run is selected and nothing is averaged
  away before the raw file is written.
- Implementation order is shuffled per repetition from a recorded seed, so
  ordering cannot favour one side.
- Both sides run the same origin, concurrency, and payload, and comparative
  claims require symmetric conditions wherever possible. Where instrumentation
  forces an asymmetry — the matrix harness needs rust-reality's debug-level
  per-connection events for its tunnel-bypass guard while Xray logs at
  warning — the asymmetry is disclosed with the numbers and sensitive
  headline cells (fallback, setup rate) are re-measured in symmetric
  warn-level harnesses.
- Loopback numbers describe implementation cost, not Internet throughput. No
  result may claim resistance to upstream volumetric DDoS or generalize one
  host's measurement to other CPUs, kernels, and networks.
- Declined backends and failed cells are recorded as declines/failures, never
  as fabricated numbers.

### Active-probe regression contract

`tools/fixtures/active-probe-cases.json` is the canonical deterministic case
inventory. `cargo dev check` validates the manifest and proves every named test
still exists, rejecting a missing or renamed case. The inventory covers
authentication success
and rejection, replay, ClientHello fragmentation, ClientFinished failure and
absence, cover timeout/refusal/malformed flight, exact fallback prefixes, and
resource pressure.

`cargo dev bench run --suite tls-shape` compares an identical captured
stock-Xray ClientHello against rust-reality, the pinned Xray server where
applicable, and the direct local cover. It retains TLS record sequence,
deterministically observable process-write segmentation, packet captures when
available, exact prefixes, and repeated first-byte/flight timings, and drives
the real candidate through a deterministic delayed-record cover matrix
(already-buffered and absent-would-block fifth-record classifications at
0/20/50/100/200 ms delays) with a production reader gate. Deterministic
wire and closure differences fail; timing is reported as a distribution rather
than fragile microsecond equality. Packetization remains network-dependent.
These measurements do not establish indistinguishability.

## Harnesses

The machine-readable protected-cell contract is
`benchmarks/contracts/protected-metrics-v1.json`. The immutable v1.6.1
measurement foundation in `benchmarks/baselines/v1.6.1-cache-foundation.json`
records the clean-main binary/compiler/host identity, important structure sizes,
and the existing zero-allocation record-path assertions. `cargo dev perf environment --tool stat` and `--tool c2c` verify the measured binary hash and emit atomic JSON;
when kernel or VPS policy denies an event, they record `UNAVAILABLE` with the
exact diagnostic instead of manufacturing a measurement.

| Harness | Purpose |
|---|---|
| `rust-reality benchmark` (built-in) | Bounded, machine-readable in-process protocol measurements (VLESS decode, Vision framing, NXR auth). |
| `cargo bench` (criterion) | Regression analysis for VLESS decoding, Vision framing, relay backends, dual-stack planning/setup/fallback, adaptive short-ID/identity/tag lookup, REALITY digest hashing, replay expiry/reservation, and direct admission contention, with baselines and plots. |
| `cargo dev bench run --suite matrix` | Full A/B/C loopback matrix (baseline/final/Xray) over direction × payload × concurrency, with per-cell origin-saturation, upload-accounting and tunnel-bypass guards and an end-to-end integrity run. `--cells`/`--skip` trim the plan. |
| `cargo dev bench run --suite fallback` | Clean fallback A/B between a pinned baseline ELF and the candidate: warn-level logging both sides, direct-to-listener, with the relay splice/pipe-pool/buffer policy pinned identically on both sides and per-slot payload integrity verified before timing. |
| `cargo dev bench run --suite setup-rate` | Balanced setup-rate A/B (accept → first Vision transition) between a pinned baseline ELF and the candidate. `--cover-netem-rtt-ms` moves only the TLS cover behind a veth/netns and applies a recorded one-leg delay, retaining pool hit/miss summaries. `--measure-mode perf` attributes task-clock/instructions/context switches after warmup; `strace` records the bounded read/receive syscall set and gracefully stops the tracee so summaries cannot be silently empty. |
| `cargo dev bench run --suite vision-direct`, `cargo dev bench run --suite xray` | Focused Vision-Direct and Xray comparisons. |
| `cargo dev bench run --suite deployment` | Deployment characterization: routing correctness proof, routing decision cost (incl. DNS strategies), NXR topologies (direct/NXR/SOCKS5/Xray), long-flow relay evidence, and a formal one-leg netem matrix. The RTT section retains production-build ABBA cold/warm samples for Handoff/NXR/SOCKS5 at 1/10/50/100/200 ms, c1/8/32/128/512, plus secret-free pool retirement summaries. `--deployment-plan` selects `full`, `mechanism`, `robustness`, or the non-formal `smoke`. |
| `cargo dev bench run --suite soak` | Optional long-horizon loopback evidence with standalone mixed traffic plus Handoff, NXR, and TCP-only SOCKS5, midpoint reload, exact per-process RSS identities, aggregate PSS, and hash-bound start/interval/reload/end integrity attempts. `--soak-implementation xray` selects the retained comparator. The default native run is scheduled/non-blocking; an exact 12-hour run with a 5–30 minute distributed interval records whether it meets the strict long-horizon qualification. |
| `cargo dev bench profiles` | Fail-closed machine-profile validation under exact cgroup-v2 CPU, memory and zero-swap boundaries. It owns candidate/Xray identity, scoped process cleanup, churn and 512 MiB downloads, default/tuned idle-session ladders, RSS/FD/cgroup/OOM samples, absolute log counters with per-ladder baselines, class summaries, and aggregate publication. |
| `cargo dev perf hotspot` | Identity-bound `perf record` capture for either the built-in benchmark or an existing server PID. Rust owns argument bounds, exact PID/start-time/executable identity, read-only binary archival, report/build-ID checks, checksums, publication, and cleanup; `perf`, `readelf`, and `sudo` remain typed external mechanisms. |
| `cargo dev deploy canary` | Fail-closed evaluator for the approximately ten-minute exact-candidate dual-VPS active canary: deployment, real-WAN Handoff, stock Xray, integrity, churn, reload, LANDING restart/recovery, bounded pools, and recovering resource envelopes. |
| `cargo dev bench run --suite real-path` | Real-Internet A/B against Xray: crash and protocol-error gates on a real path; throughput is capped by the slowest link, so it does not discriminate bandwidth. |
| `cargo dev bench run --suite vless-encryption` | Xray v26.7.28 A/B for `encryption:none` versus VLESS Encryption inside the same REALITY + Vision stack; measures throughput, server CPU/GiB, and warmed setup in a seeded, recorded random order. |
| `scripts/test-xray-interop.sh` | Compatibility gate (below), not a benchmark. |

## v1.7 LINE-to-LANDING evidence contract

The v1.7 transport claim is accepted only from a formal deployment run with
`REQUIRE_NETEM=1`. `DEPLOYMENT_PLAN=mechanism` is the focused foreground gate:
it runs zero-loss concurrency-one 50/100/200 ms cells with six balanced samples
per leg. `DEPLOYMENT_PLAN=robustness` runs the complete RTT/loss/concurrency
Cartesian product as an asynchronous evidence campaign, while the default
`DEPLOYMENT_PLAN=full` additionally retains routing, topology, throughput, and
long-flow evidence. The focused mechanism program is the release claim gate.
A robustness run is a PASS only when its complete fail-closed inventory and
completion marker exist. If an external wall-clock budget stops it, the
preflight/incomplete contract and an artifact note identify the missing cells;
the partial run is diagnostic evidence only. The split prevents a multi-hour
robustness campaign from blocking unrelated review and engineering work. All
plans' warm and cold processes use the same release binary,
peer, origin, client, shaped veth pair, and configuration identity; only the
outbound `warmTcp` switch differs. Each protocol/mode cell retains balanced
ABBA blocks, p50/p90/p95/p99, setup rate, exact environment and binary hashes,
and raw failures. The profile inventory is fail-closed: all Handoff, NXR, and
SOCKS5 cold/warm legs must exist for every RTT, loss, and concurrency.

The formal run emits a fail-closed performance verdict. For each transport it
uses the zero-loss concurrency-one 50/100/200 ms profiles, preserves complete
ABBA blocks, and evaluates `median(cold p50) - median(warm p50)` against the
measured shaped-link RTT. The median effect must be 0.65--1.35 RTT; at 100 and
200 ms its deterministic block-bootstrap lower bound must exceed 0.5 RTT.
This checks only the expected mechanism: the warm hit removes one TCP handshake
from the user path. Loss and higher-concurrency cells are robustness evidence,
not clean RTT-mechanism estimates, and do not delay the focused mechanism
verdict.
Pool logs supply startup-aware checkout, hit/miss, cold fallback, stale,
ready/connecting/target, EWMA, growth, and shrink counters. Debug/instrumented
runs may explain phases but cannot supply headline numbers. Idle-age, burst,
combined prebuilt-cover plus warm-LANDING, protected-path, and soak evidence
remain separate retained release artifacts; no missing artifact is inferred
from this focused matrix.

Release evidence has three tiers. Tier A is the mandatory focused mechanism
gate above and is budgeted for approximately 10–20 minutes. Tier B is the
mandatory approximately ten-minute dual-VPS active canary evaluated by
`cargo dev deploy canary`. Tier C is an optional hours-long or overnight
soak. Tier C may find long-horizon retention defects, but it no longer blocks
publication or the next development worktree. The Tier B memory gate compares
baseline, burst peak, and post-recovery FD/thread/RSS envelopes; it does not
extrapolate a precise MiB/hour slope from ten minutes or claim equivalence to
long-duration evidence.

## Canonical v1.0.0 samples

The final v1.0.0 evidence sets are retained in the repository:
`benchmarks/final/v1-matrix/` + `v1-matrix-512/` (the 36-cell release
matrix), `v1-fallback-ab/`, and `v1-setup-rate/` are the canonical release
samples; `d9-framed-ab/` (ring provider A/B) and `d11-ab/` (record-batching
A/B) are the mechanism evidence behind two shipped design decisions. Larger
historical matrices were archived outside the repo in the release evidence
archive.

### Framed AEAD provider A/B — `benchmarks/final/d9-framed-ab/`

Ring (default) vs RustCrypto (`baseline`) vs Xray 26.7.28, framed cells, 219
valid samples, 0 invalid, 2 GiB sha256 integrity matched for all three
implementations. Environment: Intel Core i3-8100 (4C/4T), Linux
6.12.94+deb13-amd64, rustc 1.96.0, Xray 26.7.28 (`5ca6f4b`, Go 1.26.0),
loopback with a compiled Go origin, REALITY cover `dl.google.com:443`, seed
`0x5252`.

512 MiB cells, p50 MiB/s:

| cell | RustCrypto | ring (default) | Xray | ring/RustCrypto | ring/Xray |
|---|---:|---:|---:|---:|---:|
| download, c1 | 682.3 | 736.5 | 655.1 | 1.079 | 1.124 |
| download, c32 | 1277.0 | 1481.4 | 1391.6 | 1.160 | 1.065 |
| upload, c1 | 635.6 | 670.8 | 611.2 | 1.055 | 1.097 |
| upload, c32 | 1331.3 | 1429.3 | 1375.0 | 1.074 | 1.040 |

All 16 framed cells are ≥1.00 ring-vs-RustCrypto. Server cost per GiB of
framed download (perf stat, 3 reps each): task-clock 631 vs 940 ms/GiB
(−33%), instructions −30%, context switches −39%; RSS +3% (noise).

### Fallback A/B — `benchmarks/final/v1-fallback-ab/`

Final v1.0.0 clean same-origin fallback comparison (splice backend vs Xray,
warn-level logging both sides), medians of 7:

| concurrency | rust-reality (splice) | Xray | ratio |
|---|---:|---:|---:|
| c1 | 1631 MiB/s | 1631 MiB/s | 1.00× |
| c4 | 3075 MiB/s | 2999 MiB/s | 1.03× |
| c32 | 3279 MiB/s | 3194 MiB/s | 1.03× |

## Canonical v1.3 structure and encryption samples

- `benchmarks/final/v1.3-hot-structures/summary.json` records the Criterion
  short-ID/UUID/tag crossover evidence, zero-copy VLESS gate, REALITY digest
  hashing, lock-free direct admission, and replay heap/selected-shard A/B. The
  benchmark sources are `benches/short_id_lookup.rs`,
  `benches/identity_lookup.rs`, `benches/tag_lookup.rs`, and
  `benches/replay_expiry.rs`, `benches/vless_decode.rs`, and
  `benches/admission.rs`. The admission benchmark keeps the replaced mutex
  token bucket as an executable reference, so the contention claim remains
  reproducible.
- `benchmarks/final/v1.3-setup-refactor/` records the composed setup-path
  rerun after the allocation/lookup refactor: raw samples and perf counters
  plus `summary.json`. It is same-host loopback evidence, not a WAN claim.
- `benchmarks/final/v1.3-vless-encryption/summary.json` records the same-host
  Xray v26.7.28 nested-stack A/B. It applies only to VLESS Encryption inside
  REALITY + Vision, not raw VLESS Encryption; complete interpretation and
  revisit gates are in ADR 0003.

## Dual-stack change validation (2026-08-18)

The dual-stack correction was measured on an Intel Core i3-8100, Linux
6.12.100+deb13-amd64, rustc 1.96.0, using default-feature release builds pinned
to `main` (`ed8fea0`), the original PR head (`b322024`), and the corrected code
snapshot (binary SHA-256 prefix `1ffe66c8`). The original head includes an
unrelated unpublished v1.5 ancestor chain, so it is used only for the connector
mechanism comparison, not as the relay baseline.

Criterion connector medians (100 samples) were 42.54 us for numeric IPv4,
45.03 us for numeric IPv6, 51.37 us for healthy mixed-family setup, and
48.26 us when an immediate IPv6 refusal fell through to IPv4. Versus the
original PR head, numeric IPv4 changed -0.06%, numeric IPv6 +1.12%, planning
+0.44%, and immediate-error fallback improved 30.9% (69.82 to 48.26 us). The
immediate-error case therefore does not wait for the configured 250 ms delay.
In a 101-iteration connector-path timing test with injected, deterministic
family outcomes, simulated `ENETUNREACH` under a 250 ms policy measured
P50/P95/P99 50.17/53.86/185.61 us; a stalled preferred attempt under a 5 ms
policy measured 6.26/6.43/6.43 ms. These injected cases validate scheduler and
fallback overhead without sending probes or relying on a public IPv6 route.

The established-relay benchmark used 32 MiB flows, seven retained samples per
run, and an A-B-A order around `main`; the corrected result is the geometric
mean of the two bracketing run medians. MiB/s:

| direction | c1 main | c1 corrected | delta | c32 main | c32 corrected | delta |
|---|---:|---:|---:|---:|---:|---:|
| upload | 2720.0 | 2725.8 | +0.21% | 2657.2 | 2672.1 | +0.56% |
| download | 2604.5 | 2591.2 | -0.51% | 2574.3 | 2581.8 | +0.29% |
| full duplex | 2536.5 | 2499.4 | -1.46% | 2510.2 | 2505.6 | -0.18% |

The end-to-end setup harness retained five 128-connection samples per cell
with zero failures. Corrected versus `main`: c1 was 268.35 versus 269.38
connections/s with median P50/P95/P99 3.68/3.91/4.23 ms versus
3.67/3.94/4.24 ms; c32 was 878.24 versus 880.96 connections/s with
29.65/53.43/76.98 ms versus 30.59/56.10/65.13 ms. The c32 P99 varied between
runs while P50/P95 improved. `perf stat` over the same 1,280 successful
connections measured 0.666 versus 0.663 ms task-clock per connection (+0.55%)
and +0.15% instructions per connection. Family planning, health, and refresh
remain outside established relay read/write loops.

The robustness evidence is intentionally separate from throughput numbers.
At the time of this historical dual-stack measurement six bounded parser
targets ran 20,000 cases each. The current attack-surface program declares 14
targets in `fuzz/Cargo.toml`, including structured REALITY authentication; every
target runs in bounded, time-based CI shards, with a deeper scheduled budget.
The parser property gate still covers
every maximum-request prefix plus three byte mutations at every position.
Local restricted-shell runs disable only LSan's ptrace-unsupported leak
detector; CI retains leak detection, while TSan covers the replay duplicate
race.

## Methodology rules (and the traps that invalidated earlier numbers)

1. **Symmetric log levels for any A/B claim.** rust-reality's debug level
   serializes per-connection JSON events on the stderr lock; Xray's warning
   level does not. An asymmetric comparison once fabricated a ~25% fallback
   deficit. Matrix harnesses run rust servers at debug only for
   per-connection backend statistics, and any cell sensitive to logging cost
   is re-measured with the clean warn-level harness before a claim is made.
2. **Strip the proxy environment.** A `NO_PROXY` entry covering `127.0.0.1`
   makes curl bypass even an explicit `--socks5-hostname` for loopback URLs.
   Every harness strips proxy variables and verifies tunnel usage via
   server-side connection logs; numbers produced without this guard measure
   direct connections, not the proxy.
3. **Interleave with a recorded seed** and keep every sample; report per-cell
   medians and the invalid-sample count.
4. **Mind the filesystem.** Multi-GiB integrity transfers fail spuriously on
   a small tmpfs (`curl` rc=23, disk full); harness working directories
   belong on disk-backed storage.
5. **Guard the origin.** Origins are compiled (Go), streamed, and report
   their own errors; cells whose origin reports errors are marked invalid
   rather than read as proxy results.

## v1.5.1 release comparison evidence

All v1.5.1 numbers were measured on the release host (Intel i3-8100 4C/4T,
Linux 6.12.100+deb13-amd64, rustc 1.96.0) with every run serialized under
the host-exclusive lock `/tmp/v151-bench.lock`. Identities: candidate
`a6d6363` (binary SHA-256 `b3bff3f7…`), baseline the published v1.5.0
release binary (`eda773b`, SHA-256 `344a9d8f…`), comparator Xray-core
26.7.28 (`5ca6f4b`, go1.26.0, SHA-256 `23d228d7…04c5268`). Both servers
ran at warn-level logging (rust-reality performs no per-connection log
work at warn), the same unmodified Xray SOCKS5 client fronted both
servers, the REALITY cover was TLS 1.3, origins were loopback, every
transfer was byte-verified, and comparative runs used balanced ABBA
interleaving. Evidence root: `artifacts/v1.5.1/` (`gates/` for the release
gates, `readme-comparison/` for the Xray comparison legs).

Release gates (`artifacts/v1.5.1/gates/evaluator-report.json`): the formal
evaluator passed all 40 protected metrics with zero regressions and
classified two statistically significant improvements —
`setup:c1:throughput` (median 1.013, raw p = 0.0005) and
`setup:server-cpu` (median ratio 0.933, bootstrap95 [0.930, 0.934]; 602 µs
vs 646 µs aggregate task-clock per connection — the incremental
transcript-hash change). The formal concurrency-1 matrix (867 samples,
0 invalid) reported no significant protected-path change; 10-minute soaks
showed flat descriptors, threads, and RSS with zero transfer failures.

### Setup rate and latency vs Xray — `readme-comparison/g1-setup-xray/`

288-sample balanced ABBA (accept → first Vision transition), Xray serving
one leg:

| concurrency | rust-reality conn/s | Xray conn/s | ratio | p50 rust | p50 Xray | p99 rust | p99 Xray |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 266.6 | 262.5 | 1.016× | 3.7 ms | 3.7 ms | 4.4 ms | 16.0 ms |
| 8 | 756.3 | 710.0 | 1.065× | 9.6 ms | 10.2 ms | 18.6 ms | 32.5 ms |
| 32 | 850.8 | 806.4 | 1.055× | 27.6 ms | 29.7 ms | 59.4 ms | 64.5 ms |

Server CPU per setup connection (perf task-clock attribution, same
benchmark): rust-reality 609 µs, Xray 988 µs (Xray/rust ratio 1.62×).
(The v1.5.1-vs-v1.5.0 CPU/conn figure above comes from the rust-only
setup ABBA.)

### Throughput vs Xray — `gates/matrix-formal-r01/`, `gates/matrix-r01/`, `gates/matrix-r02/`

Candidate vs Xray p50 throughput ratio per cell. The concurrency-1 matrix
is the formal gate; the two concurrency-32 rounds are exploratory.

| path | bulk 512 MiB ×32 (r01, r02) | c1 cells (formal) |
|---|---:|---:|
| bidirectional | 1.29×, 1.33× | 1.01–1.03× |
| Direct download | 1.59×, 1.48× | 1.00–1.01× |
| Direct upload | 1.11×, 1.07× | 1.01× |
| framed download | 1.13×, 1.15× | 1.00–1.04× |
| framed upload | 1.02×, 1.04× | 1.02–1.05× |
| fallback | 0.94×, 1.02× | 1.00–1.01× |

Honest exception: in the 32 MiB × c1 Direct upload cell Xray is faster —
223 MiB/s vs 197 MiB/s in the formal matrix, with the same ordering in
both exploratory rounds (214 vs 169; 242 vs 212 MiB/s). Small-payload c1
cells are latency-dominated and some are bimodal on this host.

### DNS vs Xray — `readme-comparison/g3-dns/`

Loopback fake resolver (TTL 300 s, ~0 ms RTT), identical Xray client,
domain destinations resolved server-side; 8 rounds × 32 connections per
phase:

| phase | rust-reality | Xray |
|---|---:|---:|
| cold p50 (fresh unique names) | 10.95 ms | 11.16 ms |
| warm p50 (cached names) | 9.21 ms | 10.18 ms |
| burst, 64 identical names, wall | 73.8 ms | 107.2 ms |
| burst upstream queries | 2 | 1 |

Warm phases issued zero upstream queries on both sides. Configuration
difference: rust-reality issued A and AAAA upstream queries in the cold
phase (512 upstream queries for 256 names) while the Xray configuration
issued A-only (256) — the cold numbers are not an efficiency claim.
Upstream latency is ~0 (loopback UDP), so cold/warm numbers isolate
resolver and cache plumbing, not network latency.

### Routing rule scaling vs Xray — `readme-comparison/g5-routing/`

Explicit first-match domain rules, all to a direct outbound; the target
matches the LAST rule (worst-case full walk); DNS answer cached after
warm-up so latency isolates rule evaluation; balanced ABBA per scale
point, 320 connections per side:

| rules | rust-reality conn/s | Xray conn/s | ratio | p50 rust | p50 Xray |
|---:|---:|---:|---:|---:|---:|
| 10 | 699 | 646 | 1.08× | 10.0 ms | 10.0 ms |
| 100 | 703 | 659 | 1.07× | 9.8 ms | 10.8 ms |
| 1,000 | 683 | 598 | 1.14× | 9.8 ms | 11.3 ms |
| 10,000 | 690 | 321 | 2.15× | 9.7 ms | 22.3 ms |

Operational difference: Xray's server needed ~50 s to start with 10,000
explicit domain rules on this host (matcher construction; server log
15:10:09 config read → 15:11:01 first accept), while rust-reality starts
in ~1 s because its routing indices are compiled at config load.

### Memory under soak — `gates/soak-candidate-r01/`, `readme-comparison/g2-xray-rss/`

After the 10-minute mixed-workload soak the standalone rust-reality
server's VmRSS was 7,840 KiB (7.7 MiB; 7.9 MiB sampled peak, HWM
7.8 MiB). Under the equivalent load shape the Xray server's VmRSS was
38,888 KiB (38.0 MiB; HWM 38.1 MiB). Both showed flat descriptor, thread,
and RSS growth over the soak with zero transfer failures.

### Limitations of the v1.5.1 measurements

- One host (4-core i3-8100), one kernel, loopback only; concurrency-32
  cells on four cores measure scheduler contention as much as proxy cost.
- The concurrency-32 matrix rounds used exploratory sample sizes; only the
  concurrency-1 matrix is a formal release gate.
- Small-payload c1 cells are latency-dominated, and some are bimodal.
- The DNS phases used a loopback upstream (~0 ms RTT).
- Results are measurements of this host and are not a universal
  performance claim.

## v1.8.0 release comparison evidence

v1.8.0 introduced no new comparison table. It is an architecture release whose
performance claim is neutrality against v1.7.0, established by four independent
formal gates rather than by a new headline measurement campaign. The gate
inputs, verdicts, and stated limits are recorded in
[performance.md](performance.md#v180-release-evidence).

The stock Xray compatibility gate ran unchanged: the pinned
`artifacts/xray-reference-v26.7.28` client drove every matrix cell of every gate
with zero invalid samples and passing SHA-256 payload-integrity cells.

The v1.7.0 and earlier headline tables below remain the measurement foundation
and are unchanged.

## v1.7.0 release comparison evidence

The v1.7.0 protected Xray-comparison headline retains the v1.6.1 measurement
foundation: the v1.6.0 numbers measured on the release host (Intel i3-8100
4C/4T,
Linux 6.12.100+deb13-amd64, rustc 1.96.0) with every run serialized under
the host-exclusive lock `/tmp/v16-bench.lock`. Identities: candidate
`c182829` (binary SHA-256 `cc53c1f4…`, built by
`scripts/build-release.sh linux-x86_64-generic`), baseline the published
v1.5.1 release binary (`149f126`, SHA-256 `49f3246f…`), comparator
Xray-core 26.7.28 (`5ca6f4b`, go1.26.0, SHA-256 `23d228d7…04c5268`).
Same methodology as v1.5.1: warn-level logging on both servers, the same
unmodified Xray SOCKS5 client, TLS 1.3 REALITY cover, loopback origins,
byte-verified transfers, balanced ABBA interleaving. Evidence root:
`artifacts/v1.6.0/` (`gates/` for the release gates, `readme-comparison/`
for the Xray comparison legs).

Release gates (`artifacts/v1.6.0/gates/evaluator-report.json`): the formal
evaluator passed all 40 protected metrics with zero regressions against
the v1.5.1 release binary. The two retained v1.6.0 data-path changes were
measured separately: 512 KiB splice pipes (fallback cpuPerGiB 0.953,
bootstrap95 [0.925, 0.974], splice syscalls halved; 1 MiB variant measured
and rejected) and Vision framed-uplink batching (framed-upload:32MiB:c32
1.055–1.057 across two flipped-order ABBA rounds, origin write syscalls
3.5× fewer; framed download and c1 unchanged). Compiler experiments were
run and rejected with numbers: FatLTO, PGO, and BOLT each showed parity on
protected throughput cells (BOLT's ~3% setup CPU/conn did not convert to
rate and cost +63% binary size).

### Setup rate and latency vs Xray — `readme-comparison/setup-xray/`

144-sample balanced ABBA (accept → first Vision transition), Xray serving
one leg:

| concurrency | rust-reality conn/s | Xray conn/s | ratio | p50 rust | p50 Xray | p99 rust | p99 Xray |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 268.5 | 251.4 | 1.068× | 3.7 ms | 3.6 ms | 4.5 ms | 17.7 ms |
| 8 | 767.5 | 716.9 | 1.071× | 9.6 ms | 10.3 ms | 18.8 ms | 30.8 ms |
| 32 | 853.2 | 784.5 | 1.088× | 28.0 ms | 29.9 ms | 59.3 ms | 73.3 ms |

Server CPU per setup connection (perf task-clock attribution,
`readme-comparison/setup-xray-perf/`): rust-reality 571 µs, Xray 925 µs
(Xray/rust ratio 1.62×).

### Throughput vs Xray — `gates/matrix-r01/`, `gates/matrix-r02/`

32 MiB × concurrency 32, p50 of medians across two flipped-order rounds:

| path | rust-reality MiB/s | Xray MiB/s | ratio |
|---|---:|---:|---:|
| bidirectional | 752.5 | 587.7 | 1.28× |
| Direct download | 1023.3 | 634.6 | 1.61× |
| framed download | 1369.4 | 1212.1 | 1.13× |
| Direct upload | 603.9 | 570.6 | 1.06× |
| framed upload | 1335.8 | 1209.8 | 1.10× |
| fallback | 2686.5 | 2750.7 | 0.98× |

The fallback row's exploratory full-matrix context can also exhibit a
kernel pipe-page clamp (`fs.pipe-user-pages-soft`, default 64 MiB): pipes
created while the host is over the soft limit are clamped to one page, and
the affected server's splice chunks collapse to ~2 KiB (~0.7× on that
cell). This was bisected, straced (38 failed `F_SETPIPE_SZ` grows), and
causally proven (raising the limit restores 1647–1662 MiB/s parity); it
is an external kernel constraint, not a code regression — the formal
fallback ABBA gate shows 1.00× with the cpuPerGiB win. Analysis:
`notes/v1.6.0/fallback-exploratory-cell-pipeclamp.md`.

### DNS vs Xray — `readme-comparison/dns/`

Loopback fake DNS, 8 rounds × 32 connections per phase: cold p50 29.2 ms
vs 30.4 ms; warm p50 23.1 ms vs 25.0 ms with zero upstream queries on both
sides; a 64-connection same-name burst finished in 80.2 ms vs 100.2 ms
wall (2 vs 1 upstream queries).

### Routing rule scaling vs Xray — `readme-comparison/routing2/`

| rules | rust-reality conn/s | Xray conn/s | ratio | p50 rust | p50 Xray |
|---:|---:|---:|---:|---:|---:|
| 10 | 795 | 787 | 1.01× | 29.3 ms | 32.3 ms |
| 100 | 803 | 753 | 1.07× | 28.1 ms | 32.1 ms |
| 1,000 | 813 | 685 | 1.19× | 29.9 ms | 34.9 ms |
| 10,000 | 794 | 324 | 2.45× | 29.8 ms | 81.1 ms |

### Memory under soak — `gates/soak-candidate-r01/`, `readme-comparison/xray-resources/`

After the 10-minute mixed-workload soak the standalone rust-reality
server's VmRSS was 8.3 MiB (HWM 8.3 MiB, 17 fds). Under the equivalent
load shape the Xray server's VmRSS was 39.5 MiB (HWM 40.9 MiB). Both flat
across the soak with zero transfer failures.

### Limitations of the v1.6.0 measurements

- One host (4-core i3-8100), one kernel, loopback only; concurrency-32
  cells on four cores measure scheduler contention as much as proxy cost.
- The concurrency-32 matrix rounds used exploratory sample sizes; only the
  concurrency-1 matrix is a formal release gate.
- Small-payload c1 cells are latency-dominated, and some are bimodal.
- The DNS phases used a loopback upstream (~0 ms RTT).
- The exploratory fallback c1 cell is sensitive to the kernel pipe-page
  soft limit in saturated harness contexts (see above).
- Results are measurements of this host and are not a universal
  performance claim.

## Historical README headline tables

The tables below previously headed the README performance section. They
are kept here as per-release historical evidence; the current README
carries the v1.6.0 comparison above. Superseded numbers must not be read
as current behavior.

### v1.0.0 headline table (frozen at v1.0.0)

Comparator: Xray-core 26.7.28 (commit `5ca6f4b`, go1.26.0). Host: Intel
i3-8100 (4C/4T), Linux 6.12.94, loopback, Go origin, 5 samples per cell;
every cell byte-verified, plus 2 GiB SHA-256 integrity runs per
implementation. Matrix cells ran rust-reality at debug log level (required
by the harness's tunnel-bypass guard) against Xray at warning — a handicap
for rust-reality; the fallback and setup rows came from symmetric
warn-level harnesses.

| Workload | rust-reality 1.0.0 | Xray-core | Ratio |
|---|---:|---:|---:|
| Direct download, 512 MiB ×32 | 1386 MiB/s | 516 MiB/s | **2.69×** |
| Direct upload, 512 MiB ×32 | 1155 MiB/s | 1031 MiB/s | 1.12× |
| Framed download, 512 MiB ×32 | 1580 MiB/s | 1388 MiB/s | 1.14× |
| Framed upload, 512 MiB ×32 | 1442 MiB/s | 1383 MiB/s | 1.04× |
| Bidirectional, 512 MiB ×32 | 1017 MiB/s | 633 MiB/s | 1.61× |
| Fallback, 32 MiB ×32 (clean harness) | 3279 MiB/s | 3194 MiB/s | 1.03× |
| Connection setup, c32 | 895 conn/s | 812 conn/s | 1.10× |

Setup cost per connection was well under half of Xray's (0.65 ms vs
1.53 ms server CPU over the measured 864-connection window).
Single-stream loopback cells were latency-bound and sat at parity
(0.94–1.04×). The full 36-cell matrix is detailed under
[performance.md](performance.md) §"Final release matrix (v1.0.0)".

### v1.5.0 summary (frozen at v1.5.0)

For v1.5, a balanced same-host ABBA comparison against v1.4 found no
statistically significant setup or protected-path throughput/latency
change: all reported 95% intervals in two complete matrix rounds crossed
no difference. The candidate did remove 4.0013 cover `recvfrom` calls per
setup connection in a separate syscall trace. These are bounded
implementation-cost observations, not a claimed throughput win; the exact
intervals are in
[performance.md](performance.md#v15-cover-flight-and-release-evidence).
The v1.5.0 shared-DNS coalescing results, the ≥64-rule routing index
measurements, and the real-IPv6 validation scope are recorded in the same
document.

## v1.5 balanced ABBA evidence

The v1.5 release comparison uses immutable candidate and v1.4 binaries. Every
authoritative setup or data-path comparison is arranged in balanced ABBA
blocks after reproducible warmup; raw samples, failures, binary SHA-256,
frequency and temperature metadata are retained. Perf attribution and syscall
tracing run in separate rounds and never lend their instrumented elapsed time
to an uninstrumented performance claim.

The final release evaluator does not use bootstrap intervals as significance
tests. For each protected metric it takes the mean of the paired block log
ratios (oriented so positive is better) and enumerates every within-block
candidate/baseline sign flip under the sharp label-exchangeability null. The
one-sided regression hypotheses across all protected metrics form one global
family, and the improvement hypotheses form a separate global family. Holm
adjustment at family-wise alpha 0.05 within each family decides every
regression or improvement classification; release failure depends only on the
regression family. The deterministic 95% block bootstrap remains only an
effect interval. Every formal metric must contain 12 through 16 complete ABBA
blocks or the evidence is invalid. Three blocks all in one direction have a
smallest possible raw one-sided p-value of 1/8, but are rejected before formal
evaluation because they have insufficient power.

The matrix also controls Linux's per-user pipe-page soft limit. All six
resident data-plane endpoints retain splice pipes across cells, so ordinary
ABBA traffic ordering alone cannot balance a process that filled its pipe
pool first. On the 4-core release host, the default 16,384-page limit made
the first Rust implementation keep 256 KiB pipes while the second received
downgraded pipes; reversing `ABBA_START` reversed an apparent 20–25% Direct
regression. Raising the soft limit to the harness-calculated 49,152 pages
made both implementations retain full-size pipes and converge. Formal runs
therefore compute a bound from maximum concurrency, apply it with non-
interactive privilege, record original/effective values, and restore the
exact original value on success, failure, or signal. A mismatched external
change or failed restoration invalidates the run.

Three warmed setup blocks measured candidate/baseline medians of -0.38% at c1
(95% bootstrap interval -0.465% to +0.170%), +0.26% at c8 (-3.368% to
+2.497%), and +0.53% at c32 (-1.257% to +1.557%). Normalized task-clock and
instructions changed by -0.768% and -0.190%; context switches changed by
+1.042%, approximately +0.058 per connection. A separate current syscall
trace measured 4.0013 fewer candidate `recvfrom` calls per connection.

Two six-path matrix rounds exercised bidirectional, Direct download/upload,
fallback, and framed download/upload with exact payload hashes. Each retained
219 samples with zero invalid samples. Every workload's throughput and latency
95% block-bootstrap interval crossed no difference. Direct upload's median
ratio reversed from 0.9511 to 1.1390 between rounds, confirming order/host
noise. These results are retained as no-difference evidence: they neither
establish a protected-path regression nor justify a performance-win headline.

The formal tier comparison is
`20260812T130000Z-matrix-v3-04285e63-r01`: x86-64-v3 (`final`) versus portable
(`baseline`) from the same source/features, with six balanced ABBA blocks. It
retained 219 samples, zero invalid samples, and three matching 64 MiB integrity
hashes (portable, v3, and Xray guard).

| path | v3/portable throughput median (95% CI) | v3/portable worst latency median (95% CI) |
|---|---:|---:|
| bidirectional | 1.0306 (0.9240–1.1118) | 0.9935 (0.8477–1.0862) |
| Direct download | 1.0145 (0.9820–1.0498) | 0.9906 (0.9417–1.0372) |
| Direct upload | 0.9682 (0.8462–1.1066) | 0.9970 (0.8829–1.1871) |
| fallback | 0.9981 (0.9280–1.0613) | 0.9795 (0.8752–1.0169) |
| framed download | 1.0091 (0.9826–1.0278) | 1.0150 (0.9996–1.0162) |
| framed upload | 1.0058 (0.9865–1.0229) | 0.9751 (0.9556–1.0074) |

All twelve intervals contain 1, so this run supplies no statistically reliable
v3 advantage. The portable tier remains independently protected: v3 evidence
cannot cancel or mask a portable regression.

The v1.5 interoperability matrix also exercised Xray 26.7.28 against
Microsoft, Google, and Fastly public covers plus local OpenSSL 3.5.6 without
CCS. Each case passed exact 1 MiB SHA-256 and ML-DSA-65 compatibility. It is a
protocol gate and carries no timing claim.

### v1.5.0 DNS, routing, and IPv6 evidence

Same host class and caveats as the rest of this document (i3-8100, Linux
6.12, loopback/same-host; implementation cost only).

- **DNS coalescing (shared resolver, upstream-server mode):** 128 concurrent
  identical lookups produced 2 upstream queries instead of 315; warm p50 fell
  from 12.9 ms to sub-microsecond; the cold path cost +2.1%. System mode
  coalesces and governs identically but caches no dynamic answers (no TTLs
  from getaddrinfo).
- **Routing indices:** at the measured 64-rule crossover the compiled
  candidate index costs ≈53 bytes per rule and preserves exact ordered
  first-match semantics. P95 decision latency fell 31–57% at 1,000 rules and
  31–55% at 10,000 rules; lists below the threshold keep the linear path.
- **IPv6:** the native `cargo dev bench run --suite ipv6` gate over real global IPv6 and real
  IPv6 Internet egress finished 29 pass / 0 fail / 1 skip; the skip is the
  external-ingress case (no outside IPv6 source on the validation host), so
  public-Internet inbound IPv6 is not externally attested. Covered: listener
  modes, all client/server family combinations, byte-exact 64 MiB
  up/down/full-duplex, 100 ms/1% netem, route loss/recovery, and 0.086 s
  family-refusal fallback.

## v1.2.0 distributed and WAN-emulation evidence (LAB-NETEM)

The v1.2 cycle characterized the distributed topologies on a namespace/veth
rig with `tc netem` (LAB-NETEM; **not** real-WAN evidence — real multi-host,
real WAN, ≥8-core, and NUMA remain unverified):

- **RTT sweep** (client↔line delayed 0–200 ms): all topologies — standalone,
  NXR, Handoff, and the Xray comparator — are within run-level noise of each
  other at every RTT (e.g. ~15 MiB/s at 100 ms for all four), and Handoff
  adds at most ~0.5 internal-link RTT of setup vs NXR, matching its
  one-sealed-flight design. Single-stream numbers are host TCP-autotuning
  dependent.
- **Loss** (0.5% at 50 ms): NXR and Handoff are statistically
  indistinguishable; both show the rig's bistable slow mode (see below).
- **Bistability warning**: single-stream large transfers on this rig fall
  into a ~70–150 MiB/s slow mode in ~15–25% of samples regardless of
  topology or relay backend (a TCP receive-window autotuning equilibrium,
  root-caused with `ss -ti` to a bogus initial RTT under churn). Any
  single-stream cell therefore needs n≥15 and medians; n=3 spikes are not
  evidence.
- **Multi-peer Handoff**: 1 LINE→2 LANDINGs, 2 LINEs→1 LANDING, and a 2×2
  mesh all transfer byte-exactly with per-UUID routing; only the intended
  landing can open its pair's sealed transfer.
- **Rolling upgrade**: mixed v1.1.0↔v1.2.0 LINE/LANDING pairs (Handoff and
  NXR) transfer byte-exactly in both directions; either node may be
  upgraded first.
- **Failure semantics**: landing down or wrong key fails the client in
  ~12–13 ms; a landing killed mid-transfer truncates the client's stream
  (never a false clean EOF); SIGTERM during an active transfer drains for
  up to 30 s, then force-aborts.
- **Backpressure**: a 1 MiB/s client through a Handoff chain leaves both
  nodes' RSS/FDs flat for a full 512 MiB transfer.
- **Soak**: 6-hour mixed distributed soak (Handoff + NXR + churn + periodic
  line reloads + landing restarts): zero transfer failures, bounded RSS/FD
  growth on both nodes.

## Xray 26.7.28 compatibility gate

`scripts/test-xray-interop.sh` proves that an unmodified Xray client can
drive the production public stack end to end:

```text
curl -> Xray SOCKS5 inbound -> VLESS + REALITY + xtls-rprx-vision
     -> rust-reality -> direct -> destination
```

```shell
XRAY_BIN=/path/to/xray ./scripts/test-xray-interop.sh
```

The script builds a release binary, creates fresh ephemeral UUID, X25519, and
short-ID material, starts both processes on loopback, transfers a
deterministic 1 MiB object through Xray, verifies its SHA-256 digest, checks
ML-DSA-65 verification-key generation against Xray for a fixed seed, and
optionally requests one real HTTPS URL. All generated configuration and keys
remain in a bounded temporary directory that is removed on exit.

Recorded 2026-08-03 on the validation host (Linux 6.12.94+deb13-amd64, rustc
1.96.0, Xray 26.7.28 `5ca6f4b`, cover `www.microsoft.com:443`, uTLS
fingerprint `chrome`): the 1 MiB digest matched, the ML-DSA-65 verification
key was byte-identical to Xray's, a real HTTPS request returned HTTP 302,
and Xray's debug log showed successful Vision padding/unpadding and
authenticated Direct-boundary detection for both transfers.

This is a compatibility gate, not a benchmark: its one Internet request
carries no throughput signal.

### Low descriptor-limit recovery gate

`cargo dev bench run --suite descriptor-pressure` is the fail-closed regression
gate for descriptor exhaustion. It runs an existing binary through direct
`prlimit` argv with equal low soft and hard `RLIMIT_NOFILE` values, then holds real
Xray -> REALITY -> Vision -> local-echo sessions until the server's derived FD
budget is exhausted. The gate requires all of the following evidence:

- the running executable hashes, exact child identities, and both inherited
  limits match the requested test identity;
- `descriptor_budget_report` reflects the low limit and
  `descriptor_pressure_changed` reaches `high`;
- the exact server process survives and a connection established before
  pressure continues to pass an echo integrity check;
- at least one new connection in the bounded storm is refused or stalls; and
- after held sessions close, pressure returns to `normal` and a fresh 64 KiB
  echo flow matches its SHA-256.

The native gate never builds or downloads the tested binaries, owns every child
through PID/start-time RAII, passes external-tool arguments without a shell, and
refuses to overwrite its evidence directory:

```shell
cargo dev bench run --suite descriptor-pressure \
  --rust-bin /absolute/path/to/rust-reality \
  --xray-bin /absolute/path/to/xray \
  --run-id descriptor-pressure-run-01 \
  --out-dir diagnostics/final/descriptor-pressure-run-01
```

## Limitations

- **Real-path bandwidth gates are unverifiable from the validation host.**
  Its NIC negotiates 100 Mb/s, so real-Internet runs cap at ~94 Mbps for
  both implementations equally. Real-path runs (20 alternating, 5 MiB each,
  zero crashes or protocol errors) are correctness evidence only. Loopback
  tunneled Direct-path measurements stand in for the downlink comparison.
- **Single-stream TLS-origin cells are origin-bound** (~400–500 MiB/s per Go
  TLS connection); ratios there swing 0.8–1.1 between runs on all
  implementations and are not reported as proxy performance.
- **Loopback p99** is dominated by client/origin process startup; interpret
  with care.
- **Miri cannot exercise `crates/rr-linux`** (raw syscalls unsupported); that
  crate is covered by ABI/layout tests and privileged suites instead.
- **NXR has no protocol-identical Xray baseline** (Xray implements no NXR),
  but NXR *does* have a controlled protocol comparison: the deployment
  characterization (`cargo dev bench run --suite deployment`) measures the same
  line/landing/origin topology over NXR vs SOCKS5 — setup rate, throughput,
  CPU/connection, and a netem RTT sweep — plus a clearly-labeled system-level
  rust+NXR vs Xray+SOCKS5 comparison. Final numbers are in
  [performance.md](performance.md#deployment-characterization-v100).

Earlier development-host samples (a 2026-08-03 Xray loopback table and a
2-vCPU relay baseline whose own conclusion was "indistinguishable from
noise") are superseded by the canonical samples above and were removed from
the repository.
