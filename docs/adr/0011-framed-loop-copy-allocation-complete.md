# ADR 0011: The framed record loop is copy- and allocation-complete; keep the 4-record batching buffer

## Status

Accepted as a negative result: no change required. The finding is recorded so
the framed record loop is not re-audited from scratch and the batching constant
is not "optimized" into a regression.

## Context

Before touching any framed-path constant, the copy/allocation accounting was
established by reading the code and, for allocations, by measurement. The
Vision framed record loop (`src/protocol/reality/tls13/application_io.rs`) is
the production userspace dataplane; steady-state Vision Direct payload is
excluded on purpose because it is kernel `splice` with no userspace copy after
its setup prefix.

Copy classification on the framed path:

| site | copy? | classification |
| --- | --- | --- |
| socket → socket buffer | yes, by the kernel | KERNEL_REQUIRED |
| record decrypt | none — `open_in_place` | CRYPTO_REQUIRED, in place |
| record encrypt | none — `seal_in_place_separate_tag` | CRYPTO_REQUIRED, in place |
| plaintext → application | none — `ApplicationRecord<'record>` borrows | — |
| Vision decode | none — borrowed-plaintext decode | — |

Allocations are measured, not asserted: the instrumented-allocator gates in
`src/protocol/reality/tls13/allocation_gate.rs` drive the real reader, writer,
and Vision codec and assert an exactly zero allocation delta per record across
seven gates (framed read, framed write, assembled-frame wire equality, borrowed
Vision decode, raw-mode borrowed decode, and both outer-downlink shapes).

## Decision

1. **`AVOIDABLE = 0` on the framed record loop.** The only unavoidable data
   movement per record is the kernel's own socket copy. There is no userspace
   copy or allocation left to remove; attempting one would manufacture an
   improvement against a path already measured at zero.

2. **Keep `SOCKET_BUFFER_CAPACITY = 4 * MAX_TLS_RECORD_WIRE_LEN`.** The
   constant is the syscall-amortisation mechanism, not slack: one refill moves
   up to four maximum-sized records per socket read (one syscall per refill
   instead of two per record), matching the 64 KiB read window of the reference
   implementation. It is heap, connection-owned, allocated and zero-filled once
   per connection, and deliberately retained across `.await` — it is connection
   state, which is what lets a partial record survive `Poll::Pending`. It is
   not duplicated and not oversized. Shrinking it would trade allocations it
   does not perform for syscalls it currently avoids.

3. **Do not re-audit the framed record loop for copies or allocations** unless
   the mechanism itself changes. Remaining framed cost is syscalls (already
   amortised) and AEAD compute (CRYPTO_REQUIRED; moves only with a different
   cipher or hardware path).

## Revisit conditions

- **Setup prefix** (REALITY ClientHello processing, ServerFlight construction,
  VLESS request parse, SOCKS5 negotiation): runs once per connection and is not
  covered by the record-loop gates. Audit only if per-connection setup cost
  becomes a measured constraint.
- **Handoff/NXR encode/decode**: not audited for staging copies; audit before
  optimizing either.
- **Buffered relay fallback**: the only path that consumes
  `relay.bufferBytes`; see ADR 0012 before touching that field.
- **Connection-future size**: the rejected factory experiment (ADR 0010)
  remains the highest-value unresolved mechanism in this area.

## Evidence

- Seven allocation gates in `src/protocol/reality/tls13/allocation_gate.rs`
  (CI-enforced).
- The borrow-based `ApplicationRecord<'record>` design, which keeps the socket
  buffer immutable until the caller finishes with the plaintext.
- `docs/en/operations/memory-audit-v1.8.md` records the ownership, copy, and
  allocation ledgers with their tools and hosts.
