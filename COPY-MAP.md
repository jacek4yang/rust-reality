# COPY-MAP — payload copy topology of the production data paths

Base: `d28c5f0` (perf/1.0-pipe-pool). Every claim below is either
SOURCE-PROVEN (file:line) or MEASURED-LOCAL (profile artifact cited).

## 1. Framed uplink (client → server, REALITY TLS decrypt side)

```
client socket
  → [C1, mandatory] read(2) into TlsApplicationReader.socket_buffer
      src/protocol/reality/tls13/application_io.rs:472 (refill)
  → [0 copies] AEAD open_in_place on the record slice inside socket_buffer
      application_io.rs:443-449 (cursor advances past the record first)
  → [0 copies] Vision decode borrowed from the opened plaintext
      (decode_borrowed path; plaintext never leaves socket_buffer)
  → [C2, mandatory] write(2) from the plaintext region to the destination
      socket
```

- Steady-state user-space copies: **zero** besides the two syscall-boundary
  copies, which are irreducible for a decrypting proxy.
- Amortized exception: `refill` compacts the buffer with `copy_within` only
  when the free tail cannot hold one maximum record
  (application_io.rs:477-483). Rare in steady state; not visible in the
  profile (libc memcpy ≈ 0.15%).
- MEASURED-LOCAL: in the steady-state framed download profile
  (`benchmarks/final/framed-prof/perf-download.txt`) no userspace copy
  function exceeds 0.2%.

## 2. Framed downlink (server → client, REALITY TLS encrypt side)

```
destination socket
  → [C1, mandatory] read(2) straight into the plaintext region of the
      connection's reusable write_record buffer
      application_io.rs:605 (write_application_read_from) — the old scratch
      buffer + per-chunk copy is gone by design
  → [0 copies] AEAD seal in place inside write_record
  → [C2, mandatory] write(2) of the sealed record to the client socket
```

- Steady-state user-space copies: **zero** besides the syscall boundary.
- Vision frames are packed multiple-per-record by the assembler, so the
  per-record AEAD/header cost is amortized over up to 16 KiB of payload.

## 3. Raw / Direct directions

- Splice backend: socket → pipe → socket entirely in-kernel; **zero**
  user-space copies, zero userspace bytes touched. PipePool (90eb08c)
  removes per-session pipe2/fcntl/close churn; pooled pipes are never
  reused with unread data.
- Buffered backend (decline/fallback path): read(2) → 32 KiB connection
  buffer → write(2): two syscall-boundary copies per chunk, no extra
  user-space copies.

## 4. REALITY fallback (camouflage relay to the cover server)

- Same relay backends as §3; splice preferred everywhere per the D8
  decision surface (`benchmarks/final/relay-surface*.jsonl`).

## 5. Connection setup (one-time, not steady-state)

- REALITY handshake: handshake bytes buffered once per connection;
  VLESS request parsed from a borrowed slice (no payload copy).
- These costs are per-connection, not per-byte; they are measured in the
  setup-rate model (CONNECTION-SETUP-PERFORMANCE.md), not here.

## Summary

| path | userspace copies per byte (steady state) | avoidable? |
|---|---|---|
| framed uplink | 0 (2 syscall-boundary) | no |
| framed downlink | 0 (2 syscall-boundary) | no |
| raw/direct splice | 0 total | — |
| raw/direct buffered | 0 (2 syscall-boundary) | no |

VERDICT (PROVEN by source + profile): there is no avoidable payload copy
left in the framed hot path. Copy elimination is NOT a framed-throughput
opportunity; the remaining copy cost is the kernel boundary itself
(`copy_to/from_user` ≈ 13.3% of download CPU, inside the kernel share).
The framed bottleneck is AEAD + kernel boundary — see
FRAMED-AMDAHL-REPORT.md.
