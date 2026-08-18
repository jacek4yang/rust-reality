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

## Harnesses

| Harness | Purpose |
|---|---|
| `rust-reality benchmark` (built-in) | Bounded, machine-readable in-process protocol measurements (VLESS decode, Vision framing, NXR auth). |
| `cargo bench` (criterion) | Regression analysis for VLESS decoding, Vision framing, relay backends, dual-stack planning/setup/fallback, adaptive short-ID/identity/tag lookup, REALITY digest hashing, replay expiry/reservation, and direct admission contention, with baselines and plots. |
| `scripts/benchmark-matrix.sh` | Full A/B/C loopback matrix (baseline/final/Xray) over direction × payload × concurrency. |
| `scripts/benchmark-fallback-ab.sh` | Clean fallback A/B against Xray: warn-level logging both sides, direct-to-listener. |
| `scripts/benchmark-setup-rate.sh` | Connection setup-rate model (accept → first Vision transition). |
| `scripts/benchmark-vision-direct.sh`, `scripts/benchmark-xray.sh` | Focused Vision-Direct and Xray comparisons. |
| `scripts/benchmark-deployment.sh` | Deployment characterization: routing correctness proof, routing decision cost (incl. DNS strategies), NXR topologies (direct/NXR/SOCKS5/Xray), optional netem RTT sweep, and long-flow relay evidence. |
| `scripts/soak-test.sh` | Loopback mixed-workload soak (tunnel traffic + connection churn) with `/proc`-based leak bounding; env: `DURATION_MIN`, `ROUND_SLEEP`, `RUST_REALITY_BIN`, `XRAY_BIN`, `OUT_DIR`. |
| `scripts/benchmark-real-path.sh` | Real-Internet A/B against Xray: crash and protocol-error gates on a real path; throughput is capped by the slowest link, so it does not discriminate bandwidth. |
| `scripts/benchmark-vless-encryption.sh` | Xray v26.7.28 A/B for `encryption:none` versus VLESS Encryption inside the same REALITY + Vision stack; measures throughput, server CPU/GiB, and warmed setup. |
| `scripts/test-xray-interop.sh` | Compatibility gate (below), not a benchmark. |

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

The robustness evidence is intentionally separate from throughput numbers:
each of the six bounded fuzz targets runs 20,000 cases, and the parser
property gate covers every maximum-request prefix plus three byte mutations at
every position. Local restricted-shell runs disable only LSan's ptrace-
unsupported leak detector; CI's scheduled sanitizer jobs retain leak detection
and run the full suite, while TSan covers the replay duplicate race.

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
- **IPv6:** `scripts/validate-ipv6-e2e.sh` over real global IPv6 and real
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

`scripts/test-descriptor-pressure.sh` is the fail-closed regression gate for
descriptor exhaustion. It runs an existing binary in a user systemd scope with
equal low soft and hard `RLIMIT_NOFILE` values, then holds real
Xray -> REALITY -> Vision -> local-echo sessions until the server's derived FD
budget is exhausted. The gate requires all of the following evidence:

- the running executable hash, PID, PID start time, cgroup membership, and both
  inherited limits match the requested test identity;
- `descriptor_budget_report` reflects the low limit and
  `descriptor_pressure_changed` reaches `high`;
- the exact server process survives and a connection established before
  pressure continues to pass an echo integrity check;
- at least one new connection in the bounded storm is refused or stalls; and
- after held sessions close, pressure returns to `normal` and a fresh 64 KiB
  echo flow matches its SHA-256.

The script never builds or downloads binaries, never uses process-name cleanup,
and refuses to overwrite its evidence directory:

```shell
RUST_REALITY_BIN=/absolute/path/to/rust-reality \
XRAY_BIN=/absolute/path/to/xray \
OUT_DIR=diagnostics/final/descriptor-pressure-run-01 \
scripts/test-descriptor-pressure.sh
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
  characterization (`scripts/benchmark-deployment.sh`) measures the same
  line/landing/origin topology over NXR vs SOCKS5 — setup rate, throughput,
  CPU/connection, and a netem RTT sweep — plus a clearly-labeled system-level
  rust+NXR vs Xray+SOCKS5 comparison. Final numbers are in
  [performance.md](performance.md#deployment-characterization-v100).

Earlier development-host samples (a 2026-08-03 Xray loopback table and a
2-vCPU relay baseline whose own conclusion was "indistinguishable from
noise") are superseded by the canonical samples above and were removed from
the repository.
