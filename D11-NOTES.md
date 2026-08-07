# D11 — Downlink multi-record batching

Branch: `perf/d11-record-batching` (base: main `48daa1c`).

## Hypothesis

Framed downlink steady state on main issues exactly one `recvfrom` + one
`sendto` per ≤16 KiB TLS record (64+64 syscalls/MiB). Syscall entry/exit is
≈9% of server CPU. Batching K=4 records per read+write pair targets only the
syscall count; per-byte costs (copy_user, page zeroing) are untouched.

## Design

- `TlsApplicationWriter::write_application_read_from_batched`
  (`src/protocol/reality/tls13/application_io.rs`) is the batched variant of
  `write_application_read_from`, used only by the framed outer-downlink relay
  (`relay_outer_downlink` in `src/server/vision.rs`).
- Buffer layout (`src/protocol/reality/tls13/record.rs`): one grow-only `Vec`
  holding K=4 consecutive record slots of 16 406 B each (5-byte header +
  16 385 B inner plaintext+type + 16 B tag) = 65 624 B total.
- One `readv` fills up to K disjoint plaintext regions (`IoSliceMut` per slot);
  each filled slot is sealed in place with the existing
  `Tls13RecordLayer::seal_filled` — no record-formatting logic is duplicated,
  one sequence increment per sealed record, nonce/AAD semantics unchanged.
  The sealed records form one contiguous prefix of the buffer, so a single
  `write_all` covers the whole batch. Full batch: 1 read + 1 write syscall
  for 4 records (16+16 syscalls/MiB instead of 64+64).
- Wire format unchanged: maximal 16 384 B plaintext records except possibly
  the last of a batch — exactly today's variable-length behavior. Record
  boundaries may differ from the unbatched path; both are legal TLS.
- **Lazy growth**: connections start on the existing single-record buffer.
  Only a completely-full (16 384 B) record read — evidence of a bulk flow —
  grows the buffer to the K-slot layout, once, with the same
  reserve-then-zero-fill discipline as the single-record path. The buffer
  never shrinks; idle and small-flow connections gain no RSS. Mode selection
  keys on buffer *capacity* (not length) because framed writes
  (`seal_into`/`seal_assembled`) clear the shared buffer's length.
- EOF mid-batch: a short `readv` seals and writes whatever was filled; the
  following call observes the 0-byte read and returns `Ok(0)`, which is
  exactly today's EOF path in `relay_outer_downlink` (shutdown +
  `close_notify`). Cancellation safety and the SO_LINGER abort path are
  untouched (no changes outside the relay read/write step).

## Vectored reads through the relay stack

tokio's generic `AsyncRead` exposes only a single-buffer poll, so a
crate-internal trait `VectoredRead` (in `application_io.rs`) carries the
vectored read. `NestedRecordReader` implements it: rare post-classification
buffered bytes fill only the first iovec (correct, just unbatched for that
one call); the steady state forwards to one `OwnedReadHalf::try_read_vectored`
under `readable()` readiness. The relay bound changed from
`R: AsyncRead + Unpin` to `R: VectoredRead`; the only production reader is
`NestedRecordReader`.

## Tests

- `application_io.rs`: exactly-K full records with one read + one write
  (syscall counts asserted, sequence advances K times, plaintext byte-exact),
  partial last record, 1-byte short read, EOF before any byte (nothing
  written), EOF after a full record (tail flushed, then clean `Ok(0)`), lazy
  growth only after a completely-full read and never-shrink.
- `allocation_gate.rs`:
  `outer_downlink_batched_allocates_nothing_per_batch_after_warm_up` — zero
  heap allocations per measured batch and a stable storage address.

## Deviations from the brief

None. `write_application_read_from` (single-record) is kept unchanged: it is
the batched method's pre-growth path and is still covered by the existing
allocation gate. Xray interoperability is for the coordinator's matrix; the
wire format is unchanged.
