# v1.8 memory audit: ownership map, copy ledger, allocation ledger, future sizes

This document is the v1.8 record required by the performance programme. It states
what is **measured**, by which tool, and — deliberately — what is not measured, so
no line here can be mistaken for an unverified claim.

Source commit for every measurement in this document: the v1.8 release candidate.
Host for the size and allocation measurements: Intel i3-8100, kernel
`6.12.100+deb13-amd64`, rustc 1.96.0, `--release` tier
`linux-x86_64-generic` (`-C target-cpu=x86-64`).

Tools:

| tool | what it establishes | where |
| --- | --- | --- |
| `allocation-counter` | exact allocation counts inside a closure, per thread | `src/protocol/reality/tls13/allocation_gate.rs`, `src/protocol/vless/decode.rs`, `src/server/routing.rs` |
| `size_of` guardrails | hot-state struct sizes | `tests/layout_baseline.rs` |
| `rustc -Zprint-type-sizes` | async coroutine layout, including which locals are retained across `.await` | this document |
| `size_of_val` guardrail | the connection task carries one copy of the connection future | `src/runtime/connection.rs` |

## 1. Ownership map

For each item: who allocates it, who owns it, whether it is mutated in place,
whether it is copied, where ownership moves, when it drops, and whether it is
zeroized.

| item | allocation | owner | mutation | copy | move | drop | zeroization |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ClientHello | inline, no heap; 168 B struct pinned by `layout_baseline` | REALITY accept path | parsed in place from the read buffer | none for classification | into the cover-flight decision | end of accept | not secret material; no zeroization required |
| TLS transcript | bounded inline hash state | REALITY handshake | incremental update in place | none | none | end of handshake | hash state is not key material |
| TLS records | the retained ciphertext buffer inside `TlsApplicationIo` (328 B struct, buffer owned) | `TlsApplicationIo` | decrypted in place; plaintext region reserved inside the retained buffer | **none per record** (see copy ledger C1) | none | with the session | AEAD keys zeroized by the crypto crates (`zeroize` features enabled) |
| VLESS request | borrowed from the decrypted record; `decode_request_ref` | protocol decoder | none | none per request (C2) | destination/user id copied out as small `Copy` values | with the record | not secret |
| Vision buffers | `VisionEncoder` 424 B / `VisionDecoder` 64 B, both inline | Vision codec | frames assembled in place inside the writer's plaintext region | **none per frame** (C1) | none | with the session | padding seed is not long-term key material |
| Handoff continuation | one `Vec<u8>` per transfer attempt, built by `seal_fresh` | the Handoff line | built once, then written | one write from the vector to the socket (C4) | consumed by the counted write | after the attempt; a failed attempt's bytes are discarded, never resumed | continuation keys held by the protocol layer with `zeroize` |
| NXR request | one `Vec<u8>` per attempt, built by `fresh_nxr_request` | the NXR outbound | built once, then written | one write (C4) | consumed by the counted write | after the attempt | HMAC key held with `zeroize` |
| routing state | compiled once at startup / reload; sorted array below 4 entries, hash map above | `ConnectionRuntime`, shared by `Arc` | immutable after compilation | **zero allocations per decision**, measured | `Arc` clone per generation, not per connection | at reload generation retirement | not secret |
| relay buffers | pooled; bounded userspace buffers and bounded splice pipe pairs | `TcpRelay` pools | reused in place | splice path performs **no userspace copy**; buffered path is one bounded copy (C3) | pool checkout/return | pool shrink or process exit | payload, not key material |
| cover profile state | validated and prebuilt at startup | cover profile store, shared | immutable after validation | none per connection | shared reference | at reload | contains no client secret |
| warm pool state | one prepaid socket plus its descriptor permit | `AdaptiveTcpPool` | counters updated atomically | none | checkout moves the socket to the session, permanently | retirement, or session end | warm sockets carry **no** authentication authority; each attempt builds fresh authenticated bytes |

Two ownership rules from ADR 0008 are now type-enforced rather than documented:
`CommittedWrite` is a one-shot, non-`Clone` witness that a transport accepted a
complete authenticated message, and `RawRelayGrant` is a one-shot, non-`Clone`
authority to move socket ownership across the raw boundary.

## 2. Copy ledger

Classification per §40. "Required" means the copy is inherent to the operation;
"removed" means it existed in an earlier version and no longer does.

| id | copy | path | classification |
| --- | --- | --- | --- |
| C1 | TLS record plaintext ↔ Vision frame | Vision framed uplink and downlink | **removed.** The record layer reserves the plaintext region inside the writer's retained ciphertext buffer and the encoder assembles UUID, header, content and padding in place. There is no intermediate frame buffer. Verified by the zero-allocation gates below. |
| C2 | VLESS request parse | authenticated setup | **removed.** `decode_request_ref` borrows from the decrypted record; nothing is copied to inspect it. |
| C3 | userspace relay copy | raw relay, buffered backend only | **required for that backend.** One bounded pooled buffer per direction. The splice backend performs no userspace copy at all and is preferred by the automatic policy; the buffered copy occurs only when splice is disabled by configuration or declines before the first byte. |
| C4 | sealed Handoff/NXR message → socket | one authenticated write per attempt | **security-required.** The message must be constructed in owned memory before it is authenticated and written, and a permitted retry must construct entirely fresh bytes rather than resending. `RetryableProgress` deliberately exposes only `bytes_discarded()` and no offset, so resuming is not expressible. |
| C5 | cover-flight retained prefix digest | debug logging only | **currently justified.** Occurs only when debug logging is enabled; not on the authoritative warn-level path. |
| C6 | kernel socket→pipe→socket | splice relay | **required, but not a userspace copy.** Page references move; no bytes are copied into this process. |

No line here claims "zero copy" for the whole data path. The framed path is
zero-copy *between the record layer and the Vision codec*; the raw path is
zero-copy in userspace *when splice is admitted*.

## 3. Allocation ledger

Measured with `allocation-counter`, which counts allocations on the calling
thread, driven by a current-thread runtime so the counts are attributable.

| workload | allocations | source |
| --- | --- | --- |
| framed read, per record | **0** | `protocol::reality::tls13::allocation_gate` |
| framed write, per record | **0** | same |
| Vision decode, per record | **0** | same |
| raw borrowed decode, per record | **0** | same |
| outer downlink, per batch | **0** | same |
| routing decision | **0** | `server::routing` allocation test |

Per-connection allocation is **not** claimed as a single number here, and that is
deliberate: setup allocates a bounded number of times (record buffers, the sealed
Handoff/NXR message when those paths are used, and pool structures on a cold
miss), and the exact count depends on which path a connection takes. What the
gates establish is the property that matters for steady state: **the per-record
and per-chunk steady-state paths allocate nothing**, so allocation does not scale
with transferred bytes.

Steady-state retention per connection is dominated by the task future, quantified
in the next section, plus the retained record buffers inside `TlsApplicationIo`.

## 4. Future sizes

Measured with `rustc -Zprint-type-sizes` over the release build, 2 324 async
coroutines. This section produced the one actionable finding of the audit — and
the fix for it was measured and **rejected**.

### Finding: the connection task stores the connection future twice

`ConnectionTasks::spawn` takes the connection future **by value** and awaits it
inside a spawned async block. rustc keeps the captured upvar slot alive for the
whole coroutine alongside the separate awaitee slot, so the task's state machine is
sized for two copies:

```text
{async block@src/runtime/connection.rs}: 21224 bytes
    variant `Suspend0`: 21216 bytes
        upvar  `.future`:    10592 bytes
        local  `.__awaitee`: 10592 bytes   <-- the same future, second slot
```

At a `maxConnections` of 4 096 the duplicated half is roughly 42 MiB of task state,
which is material on the 1 GiB / 1 vCPU VPS profile the project targets.

### The fix was implemented, measured, and rejected

Passing a factory instead of a future removes the duplication exactly as predicted:
connection task future 21 224 B → 10 768 B (−49.3%), largest async future in the
crate 21 376 B → 11 008 B, coroutines ≥ 16 KiB 11 → 0, at a cost of 1 408 B of
added `.text`.

It was rejected because two independent formal rounds against the pinned v1.7.0
release asset both failed the protected `framed-download` 32 MiB c1 cell — round 1
on p99 latency (1.0244 [1.0116, 1.0428]), round 2 on throughput
(0.9850 [0.9790, 0.9934]) — with the same sign in both rounds and the throughput
interval entirely below 1.0 both times. Per the project's first principle, measured
runtime efficiency is not traded for a memory reduction that was not a
demonstrated production constraint.

Full hypothesis, implementation, evidence, candidate mechanism, and the three
revisit conditions are recorded in
`notes/v1.8.0/rejected-connection-future-factory.md`. The duplication therefore
**remains present in v1.8** and is documented here rather than silently fixed or
silently ignored.

### Remaining large futures

43 coroutines are ≥ 8 KiB, led by `run_connection` at 10 432 B. These are *not*
duplications: `run_connection`'s `Unresumed` variant is 112 B and its `Suspend0`
variant is dominated by a single `__awaitee` of 10 144 B, i.e. one copy of the
session state machine it drives. Shrinking them means reducing what the session
genuinely holds across an await, which is a v1.10 deep-performance task and is not
attempted here.

## 5. What this audit does not establish

- No claim about long-horizon leak behaviour. Retention is a static layout and
  allocation-count property here, not a soak result.
- No PMU-derived cache or branch data. Unprivileged hardware PMU access is denied
  by kernel policy on this host (`perf_event_paranoid = 3`), recorded as
  `UNAVAILABLE_WITH_HARNESS` in the cache-foundation baseline rather than
  fabricated.
- No syscalls-per-connection or syscalls-per-GiB ledger. That is a v1.10
  deliverable and needs a counted harness rather than an estimate.
- The allocation gates measure the protocol and routing paths, not the whole
  process. Startup, configuration, and logging allocate and are not on a
  per-connection path.
