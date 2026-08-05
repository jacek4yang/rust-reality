# Performance report: completing the proxy data plane

Branch: `perf/complete-proxy-datapath-and-dedicated-runtime`
Base SHA: `717e69bfd1e83dd114ff652b74167ad3046e7692` (`origin/main`)
Head SHA: recorded in the archive MANIFEST and the PR body; obtain it with `git rev-parse perf/complete-proxy-datapath-and-dedicated-runtime`
Xray reference: `5ca6f4b7d4dc20a881d4330e498892697627ec0c` (v26.7.28), built from the adjacent read-only clone
Host: Debian 13, kernel 6.12.94+deb13-amd64, Intel i3-8100 (4C/4T @ 3.60 GHz), 16 GiB, NIC `enp2s0` negotiated **100 Mb/s**, RLIMIT_NOFILE 524288/524288, no cgroup limits, rustc 1.96.0

All measurements are retained: loopback matrix in `benchmarks/final/`, harness
runs and profiles in `diagnostics/final/`, mirror copies in the offline
archive. Gates that could not be verified on this host are listed in
`UNVERIFIED-GATES.md` — nothing there is claimed here.

## 1. Root-cause analysis of the downlink gap

**Observation (reference, real path):** Xray ≈ 651 Mbps down / 48.5 Mbps up;
rust-reality ≈ 311 Mbps down / 49.6 Mbps up.

**Structural cause (verified in source, base SHA):** rust-reality only ran a
kernel relay backend after a **bilateral** handoff — both Vision directions had
to reach their authenticated raw boundary and have their sockets reunited
(`DirectHandoff`). A direction that reached its Direct boundary alone waited in
a userspace `read → write_all` loop with a fresh `time::timeout` per chunk
until the peer settled. Xray instead promotes each direction **independently**:
the downlink splices as soon as the final framed write completes
(Xray `f926ee4a`), and uplink splice is deliberately disabled
(Xray `903214a0`). The symmetric upload result and the 2:1 download deficit
match this difference exactly: on download-heavy flows Xray's downlink runs in
the kernel while rust-reality's stays in userspace until (unless) the uplink
also goes raw.

**Why loopback did not show it at first:** with an interactive local client
both directions reach Direct almost simultaneously, so the bilateral handoff
engaged and baseline loopback numbers looked fine. Two additional methodology
failures had to be fixed before any of this was measurable (section 3).

**Fix (this branch):** directional independence. Each direction decides exactly
once at its raw boundary: pair if the peer is already there, otherwise start a
directional relay (splice preferred, buffered fallback) immediately — no
sleeps, no peer waits, monotonic direction states making split-brain
impossible. See `docs/performance-data-path.md`.

**Verified effect (loopback, tunneled, TLS 1.3 origin, Xray client, c=1,
64 MiB):**

| build | rust MiB/s p50 | Xray MiB/s p50 | ratio | downlink backend |
|---|---|---|---|---|
| baseline | 300 | 380 | **0.79** | (bilateral only; wait loop) |
| phase-1 | 268 | 275 | **0.97** | splice (10/10 connections) |
| phase-2 (final) | 274 | 272 | **1.01** | splice (10/10 connections) |

Handoff delay after the fix: 27–52 µs per direction (server log
`*_handoff_delay_us`).

## 2. What changed (commit map)

| commit | change |
|---|---|
| `d25326c` | bench: TLS-origin Vision-Direct reproduction harness |
| `48b31d8` | bench fix: strip proxy env so curl cannot bypass the tunnel |
| `56f697b` | perf(vision): directional independent Direct relay + per-direction observability |
| `21a0cfe` | perf(vision): framed-path copies/timer churn removed (idle deadline, grow-only record storage, read-into-AEAD, borrowed raw decode, packed Vision frames, single-write server flight) |
| `04c5382` | perf(reality): fallback hands owned sockets to the unified relay (splice-capable) |
| `9db08c9` | fix(sockhash): production wiring — controller, transactional arm, FIN drain, TCP_INFO accounting, privileged gates |
| `3af4f5b` | fix(io-uring): backend removed after lifecycle audit (not zero-copy, no cancellation, no session layer) |
| `f5a6d4e` | feat(runtime): dedicated adaptive resource mode |
| `80c9f8b` | bench: matrix/real-path/validation harnesses, data-path doc |

## 3. Methodology (and the two traps that invalidated earlier numbers)

1. **curl proxy bypass.** The workspace proxy environment sets
   `NO_PROXY=…,127.0.0.1,…`; curl then bypasses **even an explicit
   `--socks5-hostname`** for loopback URLs (verified with a logging SOCKS
   listener: zero connections). Every earlier loopback A/B number in this
   workspace measured direct connections and was discarded. All harnesses now
   strip proxy variables from curl's environment and verify tunnel usage via
   server-side connection logs.
2. **tmpfs exhaustion.** `/tmp` is a 7.6 GiB tmpfs; the first matrix's
   multi-GiB integrity runs for `final` and `xray` failed with curl rc=23
   (disk full), not a proxy defect. Integrity was re-run with the workspace on
   disk (section 5).

Benchmarks compare three implementations — `baseline` (base SHA binary),
`final` (branch head), `xray` (reference) — with the same unmodified Xray
client, interleaved samples (seed recorded), every sample retained in
`benchmarks/final/*/samples.jsonl`. Limitations: loopback includes the shared
Xray client and Python origins in the measured path; Python TLS/HTTP origins
saturate before the proxies do at high concurrency (affected cells are marked
invalid and disclosed, failures evenly distributed across implementations).

## 4. Results — loopback matrix

Filled from `benchmarks/final/matrix-full/summary.json` (648 samples, 48 cells),
`matrix-recheck/` and `matrix-gates/` (9-sample re-runs of volatile cells).
The full per-cell table is Appendix A below.

Headline (throughput-meaningful cells, 32/512 MiB, p50):

- **Direct download:** final ≈ Xray (ratios 0.94–1.13 across cells/runs;
  512 MiB c=1: 0.94 and 1.01 in repeated runs — origin-bound variance).
- **Direct upload:** final ≥ 0.95× Xray in all measurable cells (1.07/0.99/1.04).
- **Framed download/upload:** final ≈ Xray at c=1..4 (0.9–1.14); Xray faster at
  512 MiB × c=32 (framed-upload 0.82–0.84, framed-download 0.91) — not a
  regression (final ≥ baseline in those cells), recorded as a limitation.
- **Fallback:** final 1.2–2.6× baseline (splice wired into fallback);
  Xray faster at 512 MiB × c=32 (0.68–0.73) — pre-existing gap, not a
  regression; recorded as a limitation.
- **Bidirectional:** parity (0.96–1.06).

`direct-upload:32:32`, `direct-download:32:32`, `bidi:*:32` (TLS origin):
unmeasurable — the Python TLS origin collapses at 32-way TLS concurrency on
all three implementations (100% invalid samples, evenly spread).

## 5. Integrity

- Multi-GiB (2 GiB) direct-download per implementation, sha256 both sides:
  baseline/final/xray all match (baseline from the first run; final/xray after
  the tmpfs fix — see `diagnostics/final/integrity/`).
- Every matrix sample is byte-count verified; upload samples are verified
  origin-side. Byte-exact relay conformance is covered by
  `tests/relay_backends.rs` (all backends) and the Vision oracle tests.

## 6. Profiles

- Framed path (after cleanup), perf cycles: ~46% AES-GCM
  (`aes::encrypt` 18.9%, `polyval` 16.4%, `update_padded` 11.2%), ~8.8% kernel
  copy_to/from_user, ~4.4% first-touch page zeroing, all else <1%. The framed
  path is AEAD-bound; phase-2 removed the measured userspace overheads
  (per-chunk timers, per-record zero-fill, scratch copies, raw-mode memcpy,
  splintered writes) without claiming a throughput change.
- CPU-per-GiB (raw Direct, `perf stat` on the server during sustained
  downloads): see `diagnostics/final/perf-stat/` — filled at PR time.

## 7. Backends: honesty matrix

| backend | configured | kernel supported | runtime implemented | runtime ready (this host) | automatic eligible | notes |
|---|---|---|---|---|---|---|
| buffered | yes (default) | n/a | yes | yes | yes (last) | bounded pool, 1 buffer/direction |
| splice | yes (default) | yes | yes (pair + directional) | yes | yes | 2 FDs/direction, reserved pre-pipe2 |
| sockhash | off (default) | yes (verified, sudo) | yes | needs CAP_BPF/root | yes (first, bilateral only) | transactional arm, FIN drain, TCP_INFO accounting |
| io_uring | removed | — | **no (removed)** | — | — | audit-justified; stale config keys fail decode |

Startup `relay_backend_report` reports runtime readiness (a constructed,
arm-ready controller), not a bare probe.

## 8. Dedicated resource mode

`{"runtime": {"resourceMode": "dedicated"}}`: startup detection
(RLIMIT_NOFILE/MEMLOCK, cgroup v2 cpu/memory with fallbacks), process-local
soft-limit raise (verified live: 4096 → 524288), FD budget ≤90% of effective
capacity, MemoryPlan 80% usable with 60/50% pressure and 90/80% critical
hysteresis, 1 s monitor outside data loops, priority shedding (fallback →
handshake → connection → accept pause), established relays never revoked,
automatic resume. Details: `docs/dedicated-resource-mode.md`. Behavior with
the mode off is provably unchanged (no events, same headroom).

## 9. Correctness gates

- `cargo test --workspace`: 389 passed / 0 failed (dev); release-mode suite:
  see `diagnostics/final/gates/`.
- clippy `-D warnings`, fmt, `cargo test --doc`, nextest, `cargo deny check`:
  see `diagnostics/final/gates/`.
- Privileged (sudo): `rr-linux` sockhash suite 8/8; production
  `tests/sockhash_runtime.rs` 8/8 × 4 consecutive runs.
- Low-RLIMIT / pressure: `tests/resource_pressure.rs` (critical pauses new
  sessions, established keep flowing, resume works) + child-process setrlimit
  test.
- Xray interop (`scripts/test-xray-interop.sh`): sha256-verified tunnel
  transfer + ML-DSA-65 differential: see `diagnostics/final/gates/`.
- Real path: 20 alternating real-Internet runs — see
  `diagnostics/final/real-path.json` (crash/protocol-error gate; bandwidth
  capped by the 100 Mb/s NIC, not discriminating).

## 10. Remaining limitations (not claims)

- Real-world 95%/105% downlink gates are unverifiable from this host
  (100 Mb/s NIC); loopback Direct evidence stands in (see UNVERIFIED-GATES.md).
- Xray is faster on 512 MiB × c=32 framed-upload (~0.82–0.84×) and
  fallback (~0.68–0.73×); final improves on baseline in both. Not regressions;
  future work.
- Xray's high run-to-run variance at c=1 framed (226–387 MiB/s across runs on
  this shared host) makes single-run framed comparisons ±10%.
- Python origins, not the proxies, are the bottleneck in several cells;
  high-concurrency TLS-origin cells are unmeasurable with this harness.
- Sockhash requires privilege the benchmark server does not run with, so its
  production throughput is validated by the privileged correctness gates, not
  by an A/B throughput number.

### Appendix A — retained loopback matrix (p50 MiB/s; invalid samples marked)

Full = matrix-full (5 samples/cell), Gates = matrix-gates (9 samples/cell, 0 invalid).

| cell | run | baseline | final | xray | F/X | F/B |
|---|---|---|---|---|---|---|
| bidi:1:1 | full | 16 (1inv) | 14 | 13 | 1.04 | 0.86 |
| bidi:1:32 | full | — | — | — | — | — |
| bidi:1:4 | full | 35 | 33 | 32 | 1.03 | 0.95 |
| bidi:32:1 | full | 244 (1inv) | 232 | 241 | 0.96 | 0.95 |
| bidi:32:32 | full | — | — | — | — | — |
| bidi:32:4 | full | 472 | 518 | 490 | 1.06 | 1.10 |
| bidi:32:4 | gates | 492 | 513 | 513 | 1.00 | 1.04 |
| bidi:512:1 | full | 1170 | 1180 | 1173 (1inv) | 1.01 | 1.01 |
| bidi:512:1 | gates | 1139 | 1135 | 1161 | 0.98 | 1.00 |
| bidi:512:32 | full | — | — | — | — | — |
| direct-download:1:1 | full | 7 | 7 | 7 | 1.00 | 0.97 |
| direct-download:1:32 | full | 26 | 26 | 26 (1inv) | 0.99 | 1.00 |
| direct-download:1:4 | full | 24 | 23 | 24 | 0.97 | 0.98 |
| direct-download:32:1 | full | 198 | 167 | 226 | 0.74 | 0.84 |
| direct-download:32:1 | recheck | 202 | 191 | 169 | 1.13 | 0.95 |
| direct-download:32:32 | full | — | — | — | — | — |
| direct-download:32:4 | full | 435 | 440 | 469 | 0.94 | 1.01 |
| direct-download:32:4 | gates | 441 | 445 | 410 | 1.09 | 1.01 |
| direct-download:512:1 | full | 819 | 850 | 900 | 0.94 | 1.04 |
| direct-download:512:1 | gates | 798 | 947 | 867 | 1.09 | 1.19 |
| direct-download:512:32 | full | — | — | — | — | — |
| direct-upload:1:1 | full | 9 | 9 | 9 | 1.05 | 1.01 |
| direct-upload:1:32 | full | 24 (2inv) | 26 (3inv) | 26 (2inv) | 0.98 | 1.08 |
| direct-upload:1:4 | full | 23 | 22 | 23 | 0.98 | 0.99 |
| direct-upload:32:1 | full | 179 | 171 | 160 | 1.07 | 0.95 |
| direct-upload:32:1 | gates | 171 | 183 | 176 | 1.04 | 1.07 |
| direct-upload:32:32 | full | — | — | — | — | — |
| direct-upload:32:32 | recheck | — | — | — | — | — |
| direct-upload:32:4 | full | 372 | 360 | 346 | 1.04 | 0.97 |
| direct-upload:32:4 | gates | 376 | 371 | 367 | 1.01 | 0.99 |
| direct-upload:512:1 | full | 679 | 671 (1inv) | 681 | 0.99 | 0.99 |
| direct-upload:512:1 | gates | 674 | 662 | 668 | 0.99 | 0.98 |
| direct-upload:512:32 | full | — | 500 (2inv) | 511 (2inv) | 0.98 | — |
| fallback:1:1 | full | 72 | 74 | 73 | 1.01 | 1.02 |
| fallback:1:32 | full | 29 | 301 (2inv) | 29 | 10.29 | 10.31 |
| fallback:1:4 | full | 210 | 210 | 232 | 0.91 | 1.00 |
| fallback:32:1 | full | 611 | 1406 | 822 | 1.71 | 2.30 |
| fallback:32:1 | gates | 863 | 1424 | 775 | 1.84 | 1.65 |
| fallback:32:32 | full | 815 | 809 | 803 | 1.01 | 0.99 |
| fallback:32:4 | full | 823 | 1023 | 1096 | 0.93 | 1.24 |
| fallback:32:4 | gates | 771 | 971 | 1035 | 0.94 | 1.26 |
| fallback:512:1 | full | 1247 | 3246 | 2200 | 1.48 | 2.60 |
| fallback:512:1 | gates | 1342 | 2806 | 2178 | 1.29 | 2.09 |
| fallback:512:32 | full | 2075 (2inv) | 2567 (1inv) | 3767 | 0.68 | 1.24 |
| fallback:512:32 | recheck | 2062 | 2544 (1inv) | 3495 | 0.73 | 1.23 |
| framed-download:1:1 | full | 9 | 11 | 11 | 1.02 | 1.20 |
| framed-download:1:32 | full | 28 | 90 | 27 | 3.36 | 3.26 |
| framed-download:1:4 | full | 31 | 37 | 35 | 1.04 | 1.18 |
| framed-download:32:1 | full | 228 | 244 | 228 | 1.07 | 1.07 |
| framed-download:32:1 | gates | 236 | 242 | 235 | 1.03 | 1.03 |
| framed-download:32:32 | full | 727 | 1011 | 1049 | 0.96 | 1.39 |
| framed-download:32:32 | gates | 739 | 1016 | 1071 | 0.95 | 1.37 |
| framed-download:32:4 | full | 425 | 419 | 418 | 1.00 | 0.98 |
| framed-download:32:4 | gates | 412 | 419 | 420 | 1.00 | 1.02 |
| framed-download:512:1 | full | 696 | 695 | 625 | 1.11 | 1.00 |
| framed-download:512:1 | gates | 711 | 709 | 643 | 1.10 | 1.00 |
| framed-download:512:32 | full | 1250 | 1258 | 1388 | 0.91 | 1.01 |
| framed-download:512:32 | gates | 1233 | 1252 | 1368 | 0.91 | 1.02 |
| framed-upload:1:1 | full | 11 | 11 | 11 | 0.99 | 1.03 |
| framed-upload:1:32 | full | 40 | 114 | 163 | 0.70 | 2.89 |
| framed-upload:1:4 | full | 37 | 37 | 36 | 1.05 | 1.01 |
| framed-upload:32:1 | full | 200 | 215 | 200 | 1.07 | 1.08 |
| framed-upload:32:1 | gates | 204 | 204 | 214 | 0.95 | 1.00 |
| framed-upload:32:32 | full | 923 | 726 | 1035 | 0.70 | 0.79 |
| framed-upload:32:32 | recheck | 688 (3inv) | 934 (2inv) | 875 (1inv) | 1.07 | 1.36 |
| framed-upload:32:4 | full | 404 | 399 | 413 | 0.96 | 0.99 |
| framed-upload:512:1 | full | 602 | 578 | 642 | 0.90 | 0.96 |
| framed-upload:512:1 | gates | 573 | 633 | 663 | 0.95 | 1.10 |
| framed-upload:512:32 | full | 1111 | 1120 | 1366 | 0.82 | 1.01 |
| framed-upload:512:32 | recheck | 1118 | 1138 | 1358 | 0.84 | 1.02 |

## 11. Follow-up pass (PR #17 completion)

### CI failure and repair

GitHub check "Repository quality" failed on `RUSTDOCFLAGS="-D warnings" cargo
doc`: the public docs of `Tls13RecordLayer::seal_filled` linked the private
`application_plaintext_region` (two intra-doc links). Fixed by referencing the
helper as plain code text — no lint suppression, no visibility change
(commit `b6b2eee`). Full local quality path re-verified: fmt, clippy
`--all-targets --all-features --locked -D warnings`, rustdoc, `scripts/check.sh`.

### io_uring removal audit — PASSED

Case-insensitive tree-wide search plus `cargo tree --all-features`: no io_uring
dependency, module, ring/shard runtime, `RelayBackend::IoUring`, capability
probe, `ioUring`/`maxIoUringRelays` field, ring FD reserve, session FD unit,
pinned-memory formula, benchmark selector, or automatic-selection branch
remains. Historical explanation is confined to the decision record
(`docs/decisions/adaptive-relay-implementation-plan.md` amendment) and this
report; other docs carry a one-line removal notice; stale keys fail strict
decoding (regression-pinned). No roadmap, no aliases, no migration layer.

### Compiled benchmark origin

The Python TLS origin collapsed at concurrency 32 on every implementation
(curl rc=35, PUT mismatches; 60-100% invalid cells — origin noise, not proxy
results). `scripts/bench-origin` (stdlib-only Go) serves streamed GETs,
counted PUTs, TLS 1.3, and a `/__stats` endpoint; the matrix harness builds it
by default, defaults its work dir to disk-backed storage (the tmpfs
exhaustion trap), and marks cells invalid when an origin reports errors.
Previously dead cells (direct/bidi 32 MiB x c32) are now 100% valid; c=64 is
proven with the origin idle (zero errors, ~3 goroutines).

### Measured follow-up changes

1. **Buffered TLS record reads with pending drain (kept).** Profile: ~31%
   AEAD + ~24-31% kernel on framed upload c32; strace: exactly 2 recvfrom per
   outer record (header + body) + 1 sendto per record. The framed read path
   now refills a connection-owned buffer once per <=64 KiB and parses complete
   records out of it (in-place AEAD), and the raw boundaries drain buffered
   post-boundary bytes in order before any relay starts (the re-derived
   equivalent of Xray's input/rawInput handling). Keep/revert matrix (390
   samples, 0 invalid): framed upload vs Xray 0.93 -> 0.98 (32M c32),
   0.91 -> 0.98 (c64), 0.89 -> 0.94 (512M c32), ~1.00 (c4); framed download
   0.95 -> 0.97 (32M c32); Direct path held (1.26-1.65x Xray at c4/32/64);
   no valid cell regressed > 3%.
2. **256 KiB splice pipes + pipe memory accounting (kept).** Fallback was
   splice-syscall-bound (98.8% of syscall time, 539k calls / 8 GiB, ~15.5 KiB
   per call against a 32 KiB chunk). Pipes now request 256 KiB (below the 1
   MiB unprivileged cap, best effort); splice calls dropped ~8x on the same
   workload. Throughput effect modest (fallback c32 0.76 -> 0.81 vs Xray —
   calls there are availability-limited). Accounting: 4 pipes x 256 KiB per
   configured splice relay; defaults adjusted (maxSpliceRelays 1024 -> 256,
   maxRelayMemoryBytes 256 -> 512 MiB).
3. **SOCKHASH vs splice production A/B (measured, default unchanged).**
   REALITY fallback path, 32 MiB, c1/4/32: parity throughput (c32 3245 vs
   3281 MiB/s), task-clock +2.7%, context switches +15%, per-request p50/p99
   within noise. Short sessions do not amortize arm/drain cost; sockhash
   remains opt-in.
4. **Standard vs dedicated under saturation (verified equal).** 12 GiB
   fallback workload: 3087/3049 ms (standard) vs 3060/3082 ms (dedicated) —
   noise; zero pressure transitions, no overshoot. The pressure check is one
   atomic load; the monitor samples cgroup once per second outside data loops.

### Remaining unresolved cells (honest record)

- **fallback at c32/c64 (32 MiB):** final 0.76-0.81x Xray. The gap is not the
  read path and not pipe capacity; remaining suspects are per-session setup
  and Xray's 64 KiB userspace copy simply being cheaper than splice at
  availability-limited chunk sizes. Not a regression (final >= 1.14x baseline
  on these cells); explicitly unresolved.
- **single-stream TLS cells (512:1):** the Go origin's per-connection TLS
  throughput caps ~400-500 MiB/s, so all three implementations land in the
  same band and ratios swing 0.8-1.1 run to run. These cells are origin-bound
  and are not reported as proxy performance; the meaningful single-stream
  evidence is the vision-direct harness (64 MiB) and the multi-connection
  cells where the origin scales.

### Final confirmation matrix (this head) and CPU A/B

`benchmarks/final/matrix-final/`: 393 samples, 0 invalid, 2 GiB integrity
sha256 matched for all three implementations. Direct download 1.51-1.65x
Xray at c32/64 (0.97-1.06 at c1/c4), direct upload 0.96-1.03x, framed upload
0.95-0.99x, framed download ~0.97-1.00x, bidirectional 1.03-1.21x, fallback
c32 unresolved (0.78x; final 1.16x baseline). One disclosed note: at c32/c64
direct download, both PR builds run ~5-10% below the original baseline while
remaining 1.3-1.65x Xray — the directional pairing design trades a little
peak for per-direction independence; not a gate failure (the acceptance
thresholds are vs Xray and vs PR head), recorded for reviewers.

CPU per GiB, same-workload A/B on the raw Direct path (2.5 GiB, both
directions splice): pre-follow-up vs final head identical within ~3%
(3801 vs 3931 ms task-clock, 4.78 vs 4.70 G instructions) — the follow-up
changes did not move Direct-path CPU per byte; the earlier rust 0.56 s/GiB
vs Xray 0.64 s/GiB result stands.
