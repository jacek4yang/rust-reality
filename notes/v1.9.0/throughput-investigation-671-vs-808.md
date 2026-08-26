# Investigation: real-WAN download ~671 Mbps vs ~808 Mbps

Status: **leading cause identified as runtime-policy configuration, not a v1.8
dataplane regression.** Not yet closed — the decisive confirmation must be
measured from the reporting client's vantage point, and one BDP experiment
remains. No performance-sensitive code has been changed.

## What was asked

Determine whether the reported drop — approximately 671 Mbps download on the
current deployment versus approximately 808 Mbps on the earlier Xray/old
rust-reality setup, with upload nearly unchanged — is WAN noise, runtime-policy
configuration, or a genuine v1.8 dataplane regression. Do not mask a real
regression by raising limits or buffers.

## Finding 1: the absolute numbers cannot be reproduced from the build host

Measured from the development host through the live daily node, 50 MiB downloads:

```text
through daily node   8 944 809 B/s   ≈ 71 Mbps
                     8 803 193 B/s   ≈ 70 Mbps
                     8 816 268 B/s   ≈ 71 Mbps

same endpoint, no proxy at all
                     1 286 928 B/s   ≈ 10 Mbps
                       882 311 B/s   ≈  7 Mbps
```

The unproxied reference is *slower than the proxied path*, so the development
host's own uplink — not the server — is the binding constraint here. A ceiling
near 70 Mbps makes it impossible to observe a difference between 671 and
808 Mbps from this vantage point.

Consequence: the 671/808 comparison has to be re-measured from whatever client
and link produced it. Any number this host reports about that regime would be
fabricated.

## Finding 2: v1.8 is throughput-neutral against v1.7.0 on the formal gate

The v1.8.0 release gate compared the published v1.7.0 asset
(`7765a65f…c2e23c03`) against the exact v1.8.0 candidate
(`989d4536…c332a7bd9`) using the repository's evaluator — exact one-sided paired
sign-flip permutation on the mean oriented block log ratio, global Holm
correction, 12 complete ABBA blocks per metric:

```text
framed-download_32_1 : throughput 1.0002 [0.9900, 1.0208]   p99 1.0016 [0.9829, 1.0196]
direct-download_32_1 : throughput 0.9970 [0.9894, 1.0052]   p99 0.9926 [0.9891, 1.0086]
setup:server-cpu     : 1.0029 [0.9987, 1.0061]
```

32/32 protected metrics `NO_SIGNIFICANT_CHANGE`, 0 regressions. Evidence:
`artifacts/v180-release-gate/gates/evaluation-r01.json`.

This does not by itself exonerate v1.8 in the high-bandwidth-delay-product
regime, because those cells are loopback with near-zero RTT. It does mean there
is no CPU-side or per-record throughput regression to find at 32 MiB.

## Finding 3: the live node has machine-derived tuning switched off

The node's own `runtime_plan_report`, read from its journal:

```json
{
  "event": "runtime_plan_report",
  "resource_mode": "dedicated",
  "tuning_mode": "fixed",
  "objective": "balanced",
  "worker_threads": 1,
  "max_blocking_threads": 64,
  "policy_derived": false
}
```

`tuning_mode: "fixed"` is documented in `src/config/model.rs` as *"Numbers come
from `advanced.limits` (or the built-in defaults) and never move. v1.5
behavior."* and `policy_derived: false` confirms no machine derivation ran. The
default mode is `startup`, and `adaptive` adds a controller within
startup-derived bounds — the node uses neither.

Every relay limit therefore comes from the pinned block in the daily
configuration:

```json
"relay": {
  "bufferBytes": 32768,
  "maxPooledBuffers": 4096,
  "maxSpliceRelays": 256,
  "maxRelayMemoryBytes": 536870912,
  "splice": true,
  "pipePool": true,
  "maxPooledPipes": 256
}
```

Both backends are available on the node (`relay_backend_report`: buffered
available, splice available), so splice is usable and is preferred by the
automatic policy.

## Finding 4: the derived policy is measurably wider, and `bufferBytes` is exactly 2x

`rust-reality runtime explain` resolves the effective numeric policy offline. Run
on the **same v1.8.0 binary**, changing only the tuning policy — A is the live
daily policy, B is the single-node-first target (`dedicated` +
`adaptive`/`throughput`, pinned `relay` block removed):

| field | A live (fixed/balanced) | B adaptive/throughput | ratio |
| --- | ---: | ---: | ---: |
| `relay.bufferBytes` | 32768 (default) | **65536 (derived x2)** | **2.00** |
| `relay.maxPooledBuffers` | 4096 (default) | 30929 (derived x2) | 7.55 |
| `relay.maxPooledPipes` | 256 (default) | 1928 (derived x2) | 7.53 |
| `relay.maxRelayMemoryBytes` | 536870912 (default) | 4048659456 (derived x1.5) | 7.54 |
| `relay.maxSpliceRelays` | 256 (default) | 964 (derived x2) | 3.77 |
| `resourceGovernor.maxConnections` | 16384 (default) | 185332 (derived x1.5) | 11.31 |
| `resourceGovernor.maxReplayEntries` | 65536 (default) | 741328 (derived x1.5) | 11.31 |
| `directBarrier.maxPerSecond` | 4096 (default) | 16384 (derived x2) | 4.00 |
| `directBarrier.maxConcurrent` | 2048 (default) | 3072 (derived x1.5) | 1.50 |
| `resourceGovernor.maxHandshakes` | 1024 (default) | 512 (derived x1) | 0.50 |
| `resourceGovernor.maxPreAuthIdleConnections` | 1024 (default) | 512 (derived x1) | 0.50 |
| `resourceGovernor.maxDnsLookups` | 64 (default) | 128 (derived x1) | 2.00 |

Nine further fields are identical. Full output in `plan-a-fixed-balanced.txt` and
`plan-b-adaptive-throughput.txt`.

Two things stand out.

**`relay.bufferBytes` is 32768 on the live node and its permitted range is
`[16384..65536]`.** The throughput objective derives 65536, the maximum of the
range. The userspace relay buffer in production is therefore exactly **half** of
what a throughput-oriented derivation would choose, on the one path that cannot
use splice. That is a concrete, quantified mechanism consistent with a download
shortfall that leaves upload nearly unchanged.

**Every value in column A is reported as `default`, not `operator`.** The daily
configuration pins a block of numbers that happen to equal the built-in defaults,
and pinning them selects `tuning_mode: fixed`, which switches off derivation
entirely. The operator gained nothing from writing those numbers and lost all
machine-aware sizing — which is exactly the configuration-experience problem the
single-node-first work is meant to remove.

Note that derivation is not uniformly "bigger": `maxHandshakes` and
`maxPreAuthIdleConnections` come out *lower* (512 versus 1024) because they are
derived from the detected machine. This is sizing, not inflation, which is why the
correct fix is to let derivation run rather than to hand-raise the buffer.



## Leading hypothesis

The pinned `relay.bufferBytes` of 32 KiB combined with `tuning_mode: fixed`
limits the **userspace** relay path at high bandwidth-delay product, while the
splice path is unaffected.

This fits the reported asymmetry. Vision Direct bulk transfer crosses the raw
relay boundary and uses splice, which moves page references and is insensitive to
`bufferBytes`. The Vision **framed** path stays in userspace through the TLS
record layer. On an 800 Mbps path at, say, 50 ms the in-flight product is roughly
5 MB; a 32 KiB userspace buffer bounds how much can be outstanding per cycle in
that direction. Download is the direction carrying bulk data toward the client,
which is why upload would move far less.

It also matches the operator-facing problem in the current brief: a node that
pins dozens of numeric limits gets none of the machine-derived or adaptive
tuning, which is precisely the configuration mode being deprecated for the common
single-node case.

## Why this is not being "fixed" by raising the buffer

Enlarging `bufferBytes` would very likely raise the number and would also hide
whatever the real mechanism is. The mechanism has to be demonstrated first, and
the correct product change is the one already scoped — make
`profile=dedicated` plus adaptive throughput-oriented derivation the common-case
default so the limit is derived from the machine rather than pinned by hand, with
numeric controls demoted to expert overrides.

## Exact next experiments

1. **BDP experiment, controlled.** `scripts/benchmark-deployment.sh` has an `rtt`
   mode that moves a hop onto a veth pair across a network namespace and shapes it
   with `tc netem` at 1/10/50/100/200 ms. Use it to measure framed download
   against `relay.bufferBytes` at 32 KiB versus a machine-derived value, holding
   the binary constant at v1.8.0. If throughput is flat in `bufferBytes` at
   100 ms, the hypothesis is wrong and the search moves to TCP window and
   congestion state.
2. **Configuration A/B on the same binary.** v1.8.0 with the current pinned
   `fixed`/`balanced` configuration versus v1.8.0 with `dedicated` plus
   `adaptive`/`throughput` and no pinned relay block, judged by
   `evaluate-release-performance.py`. This separates configuration from code
   without touching either.
3. **Client-side reproduction.** Re-measure 671 versus 808 from the client and
   link that produced those figures, capturing in parallel on the server: CPU,
   cycles, instructions, branch misses, context switches, CPU migrations, chosen
   relay backend per session, and TCP retransmission deltas from
   `/proc/net/netstat`.
4. **Only if 1–3 implicate code:** bisect the v1.8 PR sequence
   (#100 → #101 → #102 → #103 → #104) with the framed-download cell at the RTT
   that shows the effect.

## What is already ruled out

- Not a CPU-side or per-record regression at 32 MiB loopback — 32/32 protected
  metrics neutral against the published v1.8.0 baseline.
- Not a missing splice backend — both backends report available on the node.
- Not measurable from the build host — its own link caps near 70 Mbps proxied.
