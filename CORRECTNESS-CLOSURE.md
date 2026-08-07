# Correctness closure report — fix/pr17-correctness-closure

Stacked on `perf/complete-proxy-datapath-and-dedicated-runtime` (parent
`274cca9d728d2f96d073ccc0d1ed84158740d7bf`, Draft PR #17). This branch closes
the correctness hypotheses scoped for the follow-up: FD accounting, release
ordering, raw-relay liveness, sampler truthfulness, Vision Direct
linearizability, and soak/GitHub validation infrastructure.

Evidence classes: **SOURCE-PROVEN** (code reading), **MODEL-PROVEN**
(exhaustive-interleaving argument + stress test), **LOCALLY-MEASURED**,
**GITHUB-VALIDATED**, **PRIVILEGED-LOCAL** (sudo on this host),
**UNVERIFIED-WITHOUT-TARGET-HOST**.

Host: Debian 13, kernel 6.12.94+deb13-amd64, Intel i3-8100 4C/4T, 16 GiB,
RLIMIT_NOFILE 524288/524288, passwordless sudo (verified at task start).

## Hypothesis classification

### H1 — exact FD ownership/accounting: CONFIRMED GAP, FIXED

- SOURCE-PROVEN: inbound sockets were charged one unit at accept, splice
  pipes 4/2 per relay, the sockhash controller sits in the fixed reserve —
  but outbound sockets were charged nothing; `UNITS_OUTBOUND_SOCKET` and
  `UNITS_CONNECTOR_CANDIDATE` existed unused. Under pressure the budget could
  show headroom while real usage approached the limit.
- Fix: every outbound connect (direct/SOCKS5/NXR outbounds, fallback cover,
  NXR landing upstream) reserves exactly one unit before `connect(2)`, fails
  fast with `DescriptorBudget` (mapped to `RejectionReason::ResourceLimit`),
  and releases the unit after the socket closes. Commit `c61162e`.
- LOCALLY-MEASURED: unit tests pin the exact one-unit charge and the denial
  path; `theoretical_fd_peak` (2/connection) now matches runtime accounting.

### H2 — close-before-budget-release ordering: CONFIRMED, FIXED

- SOURCE-PROVEN: in `SplicePool::try_relay_direction` the rebound `_fd_permit`
  local dropped before the pipe pair (reverse local drop order), releasing
  two budget units while the pipe descriptors were still open — a transient
  over-admission window. Bilateral `SplicePipes` and the buffer-pool leases
  already drop in the correct order; the listener/connection paths in
  production.rs close streams before releasing permits.
- Fix: permit binds before pipe creation, so the pipe closes first. Commit
  `fe8cee6`.

### H3 — raw-relay progress-based liveness: CONFIRMED GAP, FIXED

- SOURCE-PROVEN: buffered/splice/sockhash raw relays had no timeout; a
  stalled peer parked a session indefinitely, pinning descriptors, pipes,
  map entries and permits (documented but unbounded).
- Fix: `RelayContext.liveness` (None default; compatibility entry points and
  tests unchanged). Production raw relays (Vision pair and directional, NXR
  landing) run with the session idle timeout; one reusable idle window per
  chunk — progress resets, never a session cap. Sockhash teardown samples
  TCP_INFO counters on existing poll ticks and ends a session whose counters
  stop advancing. Vision maps a raw-stage idle timeout to a clean close with
  accumulated stats. The REALITY fallback needs none — its absolute session
  deadline subsumes it. Commit `f23b1ae`.
- PRIVILEGED-LOCAL: new stall test (session ends with TimedOut; map entries
  and admission return to baseline; re-arm works) — 9/9 suite under sudo.
- LOCALLY-MEASURED: stalled directional buffered+splice relays terminate and
  return every unit; an active relay runs 4× the window unaffected.

### H4 — truthful cgroup/sampler fallback: CONFIRMED, FIXED

- SOURCE-PROVEN: a cgroup `memory.current` read that starts failing at
  runtime froze the memory-pressure state forever (samples returned None and
  the monitor holds prior state by design).
- Fix: the sampler falls back to process RSS (a different, documented
  quantity) before yielding None; only a double failure keeps prior state —
  a monitoring gap still never raises or clears an alarm. Commit `17f5970`.
- LOCALLY-MEASURED: test proves a missing cgroup file yields a live RSS
  sample.

### H5 — Vision Direct pair-decision linearizability: CONFIRMED RACE, FIXED

- MODEL-PROVEN (pre-fix): the decision was check-then-act on two separate
  atomics. The interleaving B.RawReady < B.read(A=DirectPending) < A.RawReady
  < A.read(B=RawReady) < B.commit(Relaying) lets A commit to the pair while B
  commits to a directional relay — A's deposited halves sit unclaimed for the
  rest of the session and the pair relay never runs. Rare (requires a
  mid-decision preemption) but real.
- Fix: `DirectHandoff::decide` reads the peer state and commits the own state
  under the slots mutex, totally ordering decisions; the bounded pair window
  (two scheduler yields) is retained before the atomic commit. Commit
  `c1ec2cf`.
- MODEL-PROVEN (post-fix): decisions are serialized; the second decider
  always observes the first decider's committed state, so Pair ⟺ both pair.
  Exhaustive-interleaving argument recorded in the code comment; a 256-round
  multi-thread racing-decisions stress test asserts agreement.

### H6 — soak and validation infrastructure: ADDED

- `scripts/soak-test.sh`: bounded loopback soak (direct/framed/fallback +
  connect-drop churn) with /proc FD/RSS/thread snapshots and a leak verdict.
- GitHub: the Security workflow's sanitizer jobs are schedule/dispatch-only;
  manual dispatch against this branch works (`gh workflow run security.yml
  --ref fix/pr17-correctness-closure`, run 31080903908). No self-hosted
  privileged runner assumed; none created.

## Results

- LOCALLY-MEASURED gates: fmt, clippy `-D warnings`, cargo test --workspace
  (411 passed), release suite, doc tests, nextest — see diagnostics/final/gates/.
- PRIVILEGED-LOCAL: rr-linux sockhash 8/8 + production sockhash_runtime 9/9
  (sudo), including the new stall-liveness test.
- LOCALLY-MEASURED soak (30 min, 173 rounds, mixed direct/framed/fallback +
  churn): 0 transfer failures, FD growth 0, thread growth 0, RSS +0.8 MiB —
  diagnostics/final/soak/soak-summary.json.
- LOCALLY-MEASURED parent-vs-candidate (matrix-closure, 309 samples, 0
  invalid): every discriminating cell within ±3.5% of parent (most ~1.0x);
  candidate vs Xray unchanged from the parent's profile (direct download
  1.8x Xray at c32, framed within 0.92-1.13x, fallback c32 0.80x Xray —
  the pre-existing documented gap). fallback:32:1 read C/P=0.59-0.62 in two
  runs and was investigated: the raw samples show ALL THREE implementations
  bouncing bimodally between ~700 and ~1300-1670 MiB/s within a single run —
  the cell is latency-dominated noise on this host and cannot discriminate;
  it is reported as non-discriminating, not as a regression or a win.
  Integrity: 2 GiB sha256 matched for parent, candidate, and Xray.
- GITHUB-VALIDATED: PR #18 required checks pass (Repository quality,
  Dependency policy, Parser fuzz smoke). Manually dispatched Security
  workflow on this branch (run 31080903908): ASan/LSan PASS, TSan
  (replay-cache race) PASS, fuzz smoke PASS, dependency policy PASS.
- UNVERIFIED-WITHOUT-TARGET-HOST: real-server/WAN bandwidth gates (no target
  host exists); reproducible commands preserved: scripts/benchmark-matrix.sh,
  benchmark-real-path.sh, benchmark-sockhash-ab.sh, soak-test.sh,
  run-target-host-validation.sh.
