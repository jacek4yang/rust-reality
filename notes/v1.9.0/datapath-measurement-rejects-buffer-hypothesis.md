# Datapath measurement: the relay-buffer hypothesis is rejected on mechanism

Status: **the `relay.bufferBytes` 32K→64K hypothesis is REJECTED.** It cannot
affect bulk download on this deployment. Established by reading the code and then
confirmed by measuring the live node with real traffic, not by benchmarking a
number into place.

This supersedes the leading hypothesis recorded in
`throughput-investigation-671-vs-808.md`. That document's Findings 1–4 remain
correct as written; its *interpretation* — that the pinned 32 KiB relay buffer
plausibly constrains the download path — is now disproved.

## Why it was worth checking before benchmarking

The planned experiment was a netem sweep at 1/10/50/100/200 ms varying only
`relay.bufferBytes`. Before spending that, two cheaper questions had to be
answered: does the framed path even read that field, and does bulk download even
use the framed path? Both answers turned out to be no.

## Mechanism 1: `relay.bufferBytes` is not on the framed path at all

`relay.bufferBytes` is consumed in exactly one place:

```text
src/transport/tcp_relay.rs:58
    let buffers = BufferPool::new(policy.buffer_bytes, policy.max_pooled_buffers)?;
```

That is `TcpRelay`'s buffer pool, which serves the **buffered raw-relay backend**.
`RelayBackend::automatic_preference()` is `[Splice, Buffered]`, so the buffered
backend runs only when splice declines.

The Vision **framed** path does not read it. Every `RelayPolicy` and
`buffer_bytes` occurrence in `src/server/vision.rs` (lines 2131, 3627, 3660, 3699)
lies inside `mod tests`, which begins at line 2116. The production framed socket
buffer is a compile-time constant:

```text
src/protocol/reality/tls13/application_io.rs:23
    const SOCKET_BUFFER_CAPACITY: usize = 4 * MAX_TLS_RECORD_WIRE_LEN;
```

So no configuration value — derived, pinned, or adaptive — changes the framed
buffer. Raising `relay.bufferBytes` from 32768 to 65536 cannot move the framed
download path, because that path never touches the field.

## Mechanism 2: bulk download does not use the buffered backend either

Measured on the live daily node with a debug-logging generation that differed from
the daily configuration in **only** the `log` key — REALITY identity, clients,
routing, and outbounds were verified hash-identical, so existing client links were
untouched. Real 32 MiB HTTPS download through the node, from its own
`connection_completed` event:

```text
duration_ms              4333
uplink_bytes             1835
downlink_bytes       33608221
uplink_direct            true
downlink_direct          true
uplink_backend         splice
downlink_backend       splice
downlink_direct_at_bytes 3942
pipe_capacity_downgraded  absent (false)
```

A control request over plain HTTP, which carries no inner TLS, stayed framed in
both directions as expected (`uplink_direct: false`, `downlink_direct: false`, no
backend).

The bulk session therefore:

- reached the authenticated Vision **Direct** boundary after only **3942 bytes**,
  so 99.99% of the 32 MiB never crossed the framed TLS path;
- ran **splice in both directions**, which moves page references through a pipe
  pair and performs no userspace copy at all;
- was not degraded by kernel pipe-page limits.

`maxSpliceRelays` (256 pinned) and `maxPooledPipes` (256 pinned) were not
exhausted — splice was selected and succeeded, and no decline or downgrade was
recorded. So the pinned splice capacities are also not implicated for this
workload.

## Consequence for the netem experiment

The planned 32K-versus-64K netem sweep is **not worth running for the download
case**, and running it anyway would be the failure mode the brief warns about:
searching for a benchmark that makes a preferred answer look good. There is direct
evidence that the field under test is not in the path.

The sweep retains a narrower purpose, recorded for later: it would characterise
the **buffered fallback** backend, which is what serves traffic when splice is
unavailable — non-Linux targets, `relay.splice: false`, or splice resource
exhaustion under high concurrency. That is a real path with real users, but it is
not the path that produced the reported download figure.

## What this leaves as candidate mechanisms

Bulk download on this deployment is kernel splice after a ~4 KB framed preamble.
That is version-insensitive by construction: no v1.8 PR altered the splice
implementation (PR #104 changed only the directional policy *type*, with identical
behaviour), and the formal gate already reported v1.8 neutral against v1.7.0 with
`direct-download_32_1` throughput 0.9970. A v1.8 bulk-download dataplane
regression is therefore implausible, and no evidence for one exists.

Remaining candidates for a 671 versus 808 Mbps difference, in rough order of
plausibility:

1. **Path and peering variance**, including Speedtest server selection. A splice
   datapath contributes almost no per-byte CPU, so the number is dominated by the
   network path.
2. **Single-vCPU host limits.** LINE is 1 vCPU. Even with splice, ~800 Mbps means
   substantial softirq and syscall work on one core, and hypervisor steal is
   invisible to the application.
3. **Connection-setup effects on ramp** rather than steady state: cover-profile
   hit or miss, warm-pool state, and the ~4 KB framed preamble all affect how
   quickly a short Speedtest stream ramps.
4. **The comparison baseline itself.** If the earlier figure came from Xray rather
   than an older rust-reality, stream count and congestion behaviour differ, and
   that is not a like-for-like server comparison.

Note also that this host still cannot measure the regime: the same 32 MiB download
recorded 7 743 202 B/s (about 62 Mbps), consistent with the ~70 Mbps ceiling
already documented. Reproduction requires the original client and link.

## What is now known, and what is still assumption

Known, measured:

- bulk HTTPS download reaches Vision Direct after ~4 KB and runs on splice both
  directions on the live node;
- `relay.bufferBytes` is confined to the buffered backend, and the framed buffer is
  a compile-time constant;
- splice capacity and pipe pages were not exhausted for this workload;
- v1.8 is neutral against v1.7.0 on the low-RTT formal gate.

Still assumption, not established:

- that runtime policy explains the reported download difference **at all**. The
  strongest remaining configuration-side candidate is no longer the relay buffer;
- that the reported figures are like-for-like between the two setups.

The honest current position is that the reported download difference has **no
demonstrated mechanism in rust-reality's datapath**, and the burden of the next
experiment falls on reproduction from the original vantage point rather than on
further local tuning.

## Correction to the record

`throughput-investigation-671-vs-808.md` should be read together with this file.
Specifically, its "Leading hypothesis" section — the pinned 32 KiB buffer bounding
the userspace path — is disproved for the download case, because the download case
is not a userspace path.

The single-node-first configuration work remains fully justified on its own
merits: an operator pinning a block of defaults and thereby silently disabling
machine-aware derivation is a real usability defect, and `policy_derived: false`
on the live node is a real finding. It is simply **not** the explanation for the
download figure, and it must not be released as if it were.
