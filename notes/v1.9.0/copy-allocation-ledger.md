# Copy and allocation ledger: Vision framed and the setup prefix

Scope: the production userspace dataplane. Steady-state Vision Direct payload is
excluded on purpose — it is already measured as kernel `splice`, so there is no
userspace copy to account for after its setup prefix.

Headline: **the Vision framed record loop has no avoidable copy and no allocation at
all, and this is already measured and CI-enforced rather than asserted by
inspection.** `AVOIDABLE = 0` on that path today. The optimization target named for
this campaign turns out to be already closed.

## The framed buffer constant, answered

`src/protocol/reality/tls13/application_io.rs`:

```rust
const SOCKET_BUFFER_CAPACITY: usize = 4 * MAX_TLS_RECORD_WIRE_LEN;
```

| question | answer |
| --- | --- |
| why does it exist | batching: one refill moves up to four maximum-sized records per socket read, so a pipelined peer costs one syscall per refill instead of a header read plus a body read per record |
| why this size | matches the 64 KiB read window of the reference implementation |
| stack or heap | heap, connection-owned, behind the split reader |
| lifetime | allocated and zero-filled **once** per connection |
| reused | yes — only the start/end cursors move afterwards |
| retained across await | yes, deliberately: it is connection state, which is what allows a partial record to survive a `Poll::Pending` |
| duplicated | no |
| larger than necessary | no — it is the batching mechanism, not slack |

So it is a syscall-amortisation buffer, not an oversized copy staging area.
Shrinking it would trade allocation it does not perform for syscalls it currently
avoids. **KEEP.** This is the mechanism §14 asked to establish before touching the
constant, and it argues against touching it.

## Copy classification, framed path

| site | copy? | classification |
| --- | --- | --- |
| socket → socket buffer | yes, by the kernel | KERNEL_REQUIRED |
| record decrypt | **none** — `open_in_place` | CRYPTO_REQUIRED, satisfied in place |
| record encrypt | **none** — `seal_in_place_separate_tag` | CRYPTO_REQUIRED, satisfied in place |
| plaintext → application | **none** — `ApplicationRecord<'record>` borrows | — |
| Vision decode | **none** — borrowed-plaintext decode | — |

The borrow is the load-bearing design decision, and the code says so:

```rust
/// The borrow keeps the connection's socket buffer immutable until the caller
/// finishes with the plaintext, which is what makes the successful record loop
/// allocation-free: no owned `Vec` is produced per record.
pub struct ApplicationRecord<'record> { plaintext: &'record [u8] }
```

AEAD runs in place in both directions, so the only unavoidable data movement per
record is the kernel's own socket copy. There is no userspace copy to remove.

## Allocation ledger: measured, not inspected

`src/protocol/reality/tls13/allocation_gate.rs` drives the **real** reader, writer,
Vision decoder and Vision encoder against an instrumented global allocator and
asserts the delta is exactly zero:

```rust
assert_eq!(
    measured.count_total, 0,
    "steady-state framed reads must not allocate, saw {measured:?} over {MEASURED_RECORDS} records"
);
```

Seven gates cover the path:

```text
framed_read_path_allocates_nothing_per_record_after_warm_up
framed_write_path_allocates_nothing_per_record_after_warm_up
assembled_frames_match_the_reference_encoder_on_the_wire
vision_decode_of_borrowed_plaintext_allocates_nothing_per_record
raw_mode_borrowed_decode_allocates_nothing_per_record
outer_downlink_read_into_record_allocates_nothing_per_chunk_after_warm_up
outer_downlink_batched_allocates_nothing_per_batch_after_warm_up
```

Further allocation gates exist in `src/server/routing.rs` and
`src/protocol/vless/decode.rs`.

Resulting figures for the framed steady state:

```text
allocations / record          0   (measured)
allocations / GiB             0   (measured, follows from per-record zero)
bytes allocated / record      0   (measured)
userspace copies / record     0   beyond the kernel socket copy
```

The per-connection figures are dominated by one-time setup — the socket buffer, the
boxed connection future, the key schedule — and per §11 those one-time small
allocations are explicitly the lower priority.

## Consequence for the campaign

The instruction was to make Vision framed the first userspace dataplane
optimization target and to map copies, allocations and buffer ownership before
changing code. Doing that mapping shows there is nothing left to remove at the
record level:

- copies: only KERNEL_REQUIRED and in-place CRYPTO_REQUIRED. **AVOIDABLE = 0.**
- allocations: measured zero per record, enforced by seven gates.
- buffer ownership: single connection-owned buffer, allocated once, cursors only.

**Conclusion: NO CHANGE REQUIRED on the framed record loop.** Attempting a copy or
allocation optimization here would be manufacturing an improvement against a path
already measured at zero.

Remaining framed cost is therefore syscalls and AEAD compute. Syscalls are already
amortised four records per refill by the buffer above. AEAD compute is
CRYPTO_REQUIRED and would only move with a different cipher or hardware path, which
is not a copy-ledger question.

## What stays open

- **Setup prefix.** The pre-Direct bytes, REALITY ClientHello processing, ServerFlight
  construction, VLESS request parse and SOCKS5 negotiation are not covered by the
  seven record-loop gates. These run once per connection, so by the §11 priority they
  rank below steady state, but they are the honest remaining gap in this ledger.
- **Handoff/NXR encode/decode.** Not yet audited for staging copies.
- **Buffered relay fallback.** The only path that consumes `relay.bufferBytes`; still
  uncharacterised, and the reason that field was retained rather than removed.
- **Connection future size.** Still the highest-value unexplained result: shrinking
  21,224 B → 10,768 B *lost* framed-download throughput. Not a copy or allocation
  question, and unresolved.

## Epistemic status

```text
measured    framed read/write/decode allocate exactly zero per record (7 CI gates)
measured    AEAD is in place both directions: open_in_place, seal_in_place_separate_tag
measured    application plaintext is borrowed, never copied into an owned Vec
measured    socket buffer is allocated once per connection; only cursors move
established AVOIDABLE copies on the framed record loop = 0
decision    KEEP 4 * MAX_TLS_RECORD_WIRE_LEN; it buys syscall amortisation
decision    NO CHANGE REQUIRED on the framed record loop
open        setup prefix, Handoff/NXR, buffered fallback
open        connection-future size mechanism
```
