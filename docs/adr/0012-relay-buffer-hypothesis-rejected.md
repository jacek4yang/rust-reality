# ADR 0012: The relay-buffer throughput hypothesis is rejected on mechanism

## Status

Rejected on mechanism (code reading) and confirmed by live measurement. The
`relay.bufferBytes` 32K→64K hypothesis cannot affect bulk download on the
production deployment shape.

## Context

A reported real-WAN download difference (≈671 Mbps vs ≈808 Mbps) produced the
leading hypothesis that the pinned 32 KiB relay buffer constrained the download
path, with a planned netem sweep at 1/10/50/100/200 ms varying only
`relay.bufferBytes`. Before spending that, two cheaper questions were asked:
does the framed path read that field, and does bulk download even use the
buffered path? Both answers were no.

## Findings

1. **`relay.bufferBytes` is not on the framed path at all.** It is consumed in
   exactly one place — `TcpRelay`'s buffer pool in `src/transport/tcp_relay.rs`
   — which serves the buffered raw-relay backend.
   `RelayBackend::automatic_preference()` is `[Splice, Buffered]`, so the
   buffered backend runs only when splice declines. The Vision framed path's
   socket buffer is the compile-time constant
   `SOCKET_BUFFER_CAPACITY = 4 * MAX_TLS_RECORD_WIRE_LEN`
   (`src/protocol/reality/tls13/application_io.rs`); no configuration value
   changes it (see ADR 0011).

2. **Bulk download does not use the buffered backend either.** Measured on the
   live daily node with a debug-logging generation differing from the daily
   configuration in only the `log` key (REALITY identity, clients, routing,
   outbounds hash-identical, existing client links untouched). A real 32 MiB
   HTTPS download through the node reached the authenticated Vision Direct
   boundary after only 3 942 bytes — 99.99% of the transfer never crossed the
   framed TLS path — and ran **splice in both directions** with no
   pipe-capacity downgrade. A control request over plain HTTP stayed framed in
   both directions, as expected.

3. **A v1.8 bulk-download dataplane regression is implausible.** The splice
   datapath is version-insensitive across the v1.8 change sequence, and the
   formal gate already reported v1.8 neutral against v1.7.0 on
   `direct-download_32_1` (0.9970).

## Decision

1. **Do not run the 32K-vs-64K netem sweep for the download case.** There is
   direct evidence the field under test is not in the path; running it anyway
   would be searching for a benchmark that makes a preferred answer look good.

2. **Do not "fix" the throughput observation by raising `bufferBytes`.**
   Enlarging it would likely raise the number while hiding the real mechanism.
   The correct product change is the one already scoped: make
   `profile: dedicated` plus adaptive throughput-oriented derivation the
   common-case default so limits derive from the machine rather than being
   pinned by hand, with numeric controls demoted to expert overrides.

3. **The sweep retains a narrower purpose:** characterising the buffered
   fallback backend, which serves traffic when splice is unavailable
   (non-Linux targets, `relay.splice: false`, or splice resource exhaustion
   under high concurrency). That is a real path with real users, but it is not
   the path that produced the reported download figure.

## What remains as candidate mechanisms

For the ≈671 vs ≈808 Mbps difference, in rough order of plausibility: path and
peering variance (including Speedtest server selection; a splice datapath
contributes almost no per-byte CPU, so the number is dominated by the network
path); single-vCPU host limits (softirq/syscall work and hypervisor steal are
invisible to the application); connection-setup ramp effects (cover-profile
hit/miss, warm-pool state, the ~4 KB framed preamble); and the comparison
baseline itself (if the earlier figure came from Xray rather than an older
rust-reality, stream count and congestion behaviour differ and it is not
like-for-like). The decisive confirmation must be measured from the reporting
client's vantage point; nothing here claims the historical observation was
wrong — only that no mechanism for it exists in the dataplane.

## Evidence

- `src/transport/tcp_relay.rs` buffer-pool consumption site (sole reader of
  `relay.bufferBytes`).
- Live-node `connection_completed` event for a real 32 MiB download:
  `downlink_bytes 33608221`, `downlink_direct true`,
  `downlink_backend splice`, `downlink_direct_at_bytes 3942`, no downgrade.
- Formal v1.8.0 gate: `direct-download_32_1` throughput 0.9970 vs v1.7.0.
