# Historical throughput investigation: v1.4.0 baseline and two rejected mechanisms

Status: **no rust-reality regression mechanism found between v1.4.0 and current.**
Two candidate mechanisms were proposed and both rejected on measurement. The
decisive four-way comparison the brief asks for **cannot be run from this host**
and requires the original high-bandwidth client.

Nothing here claims the historical observation was wrong. It claims that the
regression, if real, has not been located in the datapath, and names exactly what
is needed to settle it.

## Baseline strategy corrected

v1.7.0 is no longer the primary historical comparator. The operator's known-good
observations are approximately: stock Xray ~800 Mbps, rust-reality v1.4.0
~800 Mbps, current deployment observed once near ~670 Mbps. So the question is
whether a sustained regression appeared anywhere between v1.4.0 and current.

## v1.4.0 official baseline identity

Downloaded and verified against the release `SHA256SUMS`; both published assets
report `OK`.

```text
tag            v1.4.0
commit         ed8fea0a5efae480a559691c738e6927ed85fa5c
artifact       rust-reality-v1.4.0-x86_64-unknown-linux-gnu.tar.gz
binary sha256  38ba5cd5e02edbb039b13751220b91b60cb005a22d2241e6c3026d84ce643c57
GNU Build ID   d1de46ed1deddb0dfe66434a09896589c0794e32
target         x86_64-unknown-linux-gnu
self-reports   rust-reality 1.4.0, gitCommit ed8fea0a…
```

v1.4.0 supports the `benchmark` subcommand and emits a valid
`environment.gitCommit`, so it is registrable as a formal-harness baseline.

**Configuration compatibility.** v1.4.0 rejects the current daily configuration
outright (`invalid JSON configuration … at line 66`), because the schema changed
across releases. A semantically equivalent v1.4.0-shaped configuration already
exists at `private/v17-90539d3/v1.4.0-config.json`; it validates under the v1.4.0
binary and preserves identity exactly — REALITY `privateKey`, `target`,
`serverNames`, the client UUIDs, and port all hash-identical to the daily
configuration. That satisfies the "semantically equivalent, same identity"
requirement without rotating or exposing any secret.

**Formal harness limitation.** `scripts/benchmark-matrix.sh` generates one
configuration shape via `make_rust_config` for every rust implementation under
test, so it cannot currently drive a v1.4.0 baseline. A historical sweep needs
per-version configuration generation. This is a harness gap, not a v1.4.0 problem.

## Mechanism triage: what actually changed in the datapath

Diffing `ed8fea0a..main` over `src/transport` and `src/runtime`:

```text
src/runtime/plan.rs        +1725     (new)
src/runtime/adaptive.rs    +1131     (new)
src/runtime/admission.rs    +450
src/runtime/ceiling.rs      +295     (new)
src/transport/tcp.rs         +71
src/transport/backend.rs     +52
src/transport/tcp_relay.rs   +47
src/transport/relay.rs         0     (unchanged)
```

The splice datapath barely moved. `relay.rs` is byte-identical, and the entire
`tcp_relay.rs` change is the PR #104 policy-type rename plus one constant. The
runtime resource/admission/derivation layer grew by roughly 3,600 lines.

This sharpens the search prior the brief suggested: if a regression exists, the
runtime/admission/resource layer introduced across v1.5 and v1.6 is a far more
likely location than the splice loop. It remains a prior, not a conclusion.

## Rejected mechanism 1: splice pipe capacity and page budget

The one substantive datapath constant did change:

```text
v1.4.0   const SPLICE_PIPE_CAPACITY: usize = 256 * 1024;
main     const SPLICE_PIPE_CAPACITY: usize = 512 * 1024;
```

The change is documented as a measured improvement — 512 KiB halves the splice
syscall rate and server CPU per GiB against 256 KiB on the loopback reference
workload. But it doubles pipe-page consumption, and the relay explicitly detects
and records `pipe_capacity_downgraded` when the kernel grants a smaller pipe than
requested.

On the live LINE node:

```text
fs.pipe-max-size          1048576
fs.pipe-user-pages-soft      16384   (= 64 MiB at 4 KiB pages)
fs.pipe-user-pages-hard          0
```

512 KiB is 128 pages; a bidirectional splice relay holds two pipes. So the soft
budget covers roughly **64 concurrent 512 KiB relays**, against roughly **128** for
v1.4.0's 256 KiB pipes. That is a real halving of concurrent splice headroom, on a
change validated where pipe pages were not the binding constraint.

**Prediction:** under multi-stream load, `pipe_capacity_downgraded` becomes true and
the splice syscall rate rises.

**Result: rejected.** 80 concurrent 4 MiB HTTPS streams through the live node, read
from its own `connection_completed` events:

```text
sessions                          80
bulk sessions (>1 MB)             79
downlink reached Direct        80/80
backends (downlink, uplink)   splice/splice for 79, none for 1 (a non-bulk session)
PIPE CAPACITY DOWNGRADED        0 of 80
```

Zero downgrades at a concurrency above the calculated threshold, so the pipe-page
budget was not reached in practice. The bounded pool (`maxPooledPipes` 256,
`maxSpliceRelays` 256) and the fact that streams ramp and retire rather than all
peaking together keep live pipe count under budget.

The mechanism is **not disproved in principle** — it would still bite at higher
sustained simultaneity — but it is not active at 80 concurrent streams on this node
and therefore does not explain the observation. Revisit condition: a workload that
holds more than roughly 64 simultaneous splice relays, or a node with a lower
`fs.pipe-user-pages-soft`.

## Rejected mechanism 2: userspace relay buffer

Already rejected on mechanism in
`datapath-measurement-rejects-buffer-hypothesis.md` and unchanged by this work.
`relay.bufferBytes` feeds only the buffered backend; production bulk download is
Direct + splice after roughly 4 KiB.

## What the 80-stream run also establishes

Two independent live measurements now agree on the production datapath:

- single 32 MiB stream: Direct at 3942 bytes, splice both directions, no downgrade;
- 80 concurrent 4 MiB streams: 80/80 reached Direct, 79/79 bulk sessions on splice
  both directions, no downgrade.

Aggregate observed throughput was about 12.6 MB/s (~101 Mbps), above this host's
single-stream ceiling of 62–71 Mbps and still clearly bounded by the client link
rather than the server.

## What is required to settle the question

This host cannot produce the measurement. The four-way comparison must run from the
original high-bandwidth client that produced the ~800 Mbps result, against the same
VPS and the same target, in one short time window, with ABBA ordering:

```text
A  stock Xray Core, pinned exact version and binary
B  official rust-reality v1.4.0     (38ba5cd5…, config already prepared)
C  official rust-reality v1.8.0     (450392cc…)
D  current main candidate
```

For each run capture, from `connection_completed` at debug level: whether Vision
reached Direct, the Direct byte offset, downlink and uplink backend, any
`pipe_capacity_downgraded`, session count, plus server CPU and TCP retransmission
deltas.

Decision rule, stated in advance so the result cannot be rationalised afterwards:

- if Xray and v1.4.0 both reproduce ~800 Mbps while C and D sit near ~670, that is
  strong evidence of a rust-reality regression and the coarse version sweep
  (v1.5.0, v1.5.1, v1.6.0, v1.6.1, v1.7.0) then bisects the interval;
- if A, B, C and D all perform similarly in that controlled window, the historical
  difference was environmental or WAN variance, and **no rust-reality regression
  should be invented**.

Prerequisite work item: teach the sweep harness to generate per-version
configurations so v1.4.0 through current can be driven from one runner.

## Epistemic status

```text
measured   production bulk download is Direct + splice, single- and multi-stream
measured   no pipe capacity downgrade at 80 concurrent streams
measured   splice datapath is nearly unchanged since v1.4.0; relay.rs untouched
measured   SPLICE_PIPE_CAPACITY doubled, halving concurrent splice headroom
rejected   relay.bufferBytes as the download mechanism
rejected   pipe-page exhaustion at observed concurrency
inferred   runtime/admission layer is the more likely location if a regression exists
not reproduced   the ~670 versus ~800 Mbps difference itself
```
