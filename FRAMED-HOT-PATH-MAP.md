# FRAMED-HOT-PATH-MAP — steady-state framed path, function-level attribution

Base commit: `d28c5f0`. Same profile and labels as
FRAMED-AMDAHL-REPORT.md (`benchmarks/final/framed-prof/perf-*.txt`).

## Path map

```
read_application (application_io.rs:412)
  refill (application_io.rs:472)            socket read(2) — kernel share
  open_in_place (tls13/record)              AEAD open — aes/polyval symbols
Vision decode (borrowed)                    <1% — no steady-state cost
destination write(2)                        kernel share

write_application_read_from (application_io.rs:605)
  destination read(2) into plaintext region kernel share
  seal in place (tls13/record)              AEAD seal — aes/polyval symbols
  client write(2)                           kernel share
```

## Attribution table (self time, download profile)

| symbol | share | category |
|---|---|---|
| `aes::backends::x86_aes::Aes<_>::encrypt` | 22.10% (+0.16 tail) | AEAD |
| `polyval … proc_par_blocks` | 17.09% (+0.15) | AEAD (GHASH) |
| kernel `copy_user` (rep_movs) | 13.27% | kernel boundary |
| `universal_hash::UniversalHash::update_padded` | 11.20% | AEAD (GHASH driver) |
| kernel `clear_page` | 3.90% | kernel boundary (page faults on buffers/socket memory) |
| `relay_outer_downlink` closure | 0.40% | Vision/TLS glue |
| `IdleDeadline::write_all` closure | 0.29% | write glue |
| `tokio::time::sleep::Sleep::reset` | 0.24% | timers |
| `aes_gcm::…::compute_tag` | 0.12% | AEAD |
| libc memcpy | 0.15% | userspace copy (negligible) |

Upload profile has the same shape with `open_in_place` visible at 0.71%
(record-layer framing — cheap) and AEAD at 38.7% total.

## Vision workload split (per directive)

The production steady state is one of two shapes, both mapped above:

- stable framed: covered by the profile — AEAD-dominated;
- stable Raw/Direct: leaves this path entirely for the relay backends
  (splice) — not a framed cost.

First-frame costs (first Direct frame, first Raw/End frame, fragmented
headers) are **per-connection**, not steady-state; they live in the
Criterion suite (`vision/decode/8k_single_fragment`,
`vision/decode/8k_fragmented_64b`, `vision/raw_decode/16k_staged`,
`vision/raw_decode/16k_borrowed`) and in the setup model
(CONNECTION-SETUP-PERFORMANCE.md). Earlier finding stands: the built-in
equal-wall-time benchmark that reconstructs `VisionDecoder` every
iteration measures first-frame parsing, not steady state, and must not
be used to infer framed throughput.

## Consequences

1. No framed refactor is justified outside AEAD: every non-AEAD,
   non-kernel category is ≤1% self time.
2. The kernel-boundary share (47–57%) caps total achievable gain; an
   infinitely fast AEAD yields at most 2.04× (download) / 1.63×
   (upload).
3. The only evidence-backed framed lever is the AEAD provider; see
   FRAMED-AMDAHL-REPORT.md §3 for the isolated OpenSSL comparison
   (SUPPORTED, ≈2.0× at 16 KiB records, ceiling 1.35×/1.25×
   end-to-end).
