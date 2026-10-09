# ADR 0041: ACK-driven LANDING restart census

Status: Accepted

## Context

Frozen QEMU runs on `c84e16c` / `5e882bb` retained INVALID evidence for
`handoff/ordinary` landing-restart: LINE-A's co-scheduled `ss` census of the
prefix ingress on `:9444` raced LANDING's abort. A later wall-clock hold
(`RESTART_CENSUS_HOLD_MS`, commit `5111bc1`) made the census win under one
observed latency profile but tied correctness to sleep under interference —
rejected by the owner mandate for development gates.

Historical INVALID verdicts (`37886641986`, `37895293382`, and earlier) remain
immutable. The empty-census failure string stays a Class B harness signal.

## Decision

Replace the hold with an explicit LINE-A → LANDING census ACK handshake:

1. At begin, LINE-A records the single established loopback ingress on `:9444`.
2. LINE-A publishes that peer (and its boot id) to LANDING on
   `192.0.2.2:19501` with magic `rr-restart-census-ack/v1`.
3. LANDING listens on `0.0.0.0:19501`, accepts exactly one well-formed ACK, then
   aborts. Missing, duplicate, malformed, wrong-peer, or late ACK fails closed
   inside `checkpoint_tolerance_ms`.
4. Offline evaluation requires census completion ≤ ACK completion, matching
   peers, and attributes the Handoff EPIPE only after that ACK barrier.

`cargo dev bench stability-repro --fault landing-restart --output DIR` exercises
the receipt contract and loopback wire handshake in minutes without four-cell
QEMU, and classifies empty-census / ordering defects as Class B.

Four-cell execution stays sequential under the process-global benchmark
`HostLock` and fixed fixture SSH/SOCKS ports. Campaign aggregation now retains
per-cell `cell-diagnosis.json` and `cells-summary.json` so a fail-closed run
names the failing cell/fault immediately. Parallel port pools remain future
work and must not weaken identity binding.

## Consequences and limits

Correctness no longer depends on amplifying sleeps. Product defects still cannot
pass: expected restart EPIPE still needs the witnessed peer and ACK-ordered
kill. Harness races surface as explicit ACK/census errors instead of multi-hour
vague INVALID. This does not claim the data path is bug-free and does not
reintroduce TSan.
