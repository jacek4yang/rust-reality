# 0002. io_uring relay backend removed

- Status: accepted
- Date: v1.0.0 development cycle

## Context

An io_uring relay backend was planned and partially built as part of the
adaptive relay work. Before it could ship, the driver underwent a lifecycle
audit.

## Decision

Remove the io_uring backend entirely: the module, the `io-uring` dependency,
the `RelayBackend::IoUring` variant, the `ioUring`/`maxIoUringRelays`
configuration keys, the ring descriptor reserve, the session FD unit, and the
pinned-memory formula. Stale configuration keys fail strict decoding as
unknown fields (regression-pinned in `src/config/io.rs`).

The audit found:

- it was recv/send only — not zero-copy: a cross-thread channel round trip
  and a heap box per operation made it strictly worse than the buffered
  backend;
- it had no operation cancellation, so shard `Drop` could join forever behind
  a quiet peer;
- its `SessionFds` fd-safety duplication was never wired into any caller;
- it had no session layer (no partial-I/O resubmit, no half-close assembly);
- production never drove it — the relay declined it unconditionally and
  automatic backend selection omitted it.

Completing it would have been a rewrite for dubious gain over the working
splice backend.

## Consequences

The automatic backend order is splice → buffered. The server needs no
io_uring-related kernel capability, and the configuration surface rejects the
historical keys rather than silently ignoring them.
