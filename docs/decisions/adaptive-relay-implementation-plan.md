# Adaptive Bounded Relay — Implementation Plan and Design Record

Status: accepted for `perf/adaptive-relay-backends`
Baseline: `main@14ed098505b5cd9c3f5cc0d00c393c45428b0e42`

This record captures the audit performed before any hot-path edit, the ownership
model the branch adopts, the resource formulas that bound every new structure,
and the mapping from requirement to test. It is deliberately written so that a
reviewer can check the implementation against measured repository facts rather
than against intent.

## 1. Audited baseline facts

All statements below were read out of the baseline tree, not assumed.

### 1.1 Relay implementations present at baseline

The baseline contains **three unrelated relay implementations**:

| Implementation | Location | Governed by `policy.relay` | Used by |
| --- | --- | --- | --- |
| `TcpRelay` (pooled buffered + Linux `splice`) | `src/transport/tcp_relay.rs` | yes | NXR landing only (`src/server/nxr.rs`) |
| `relay_bidirectional` (`tokio::io::copy_bidirectional`) | `src/transport/relay.rs` | no | plain VLESS handler, REALITY cover fallback |
| hand-written Vision loops | `src/server/vision.rs` | no | public VLESS + REALITY + Vision |

Consequence: at baseline, tuning `policy.relay` has **no effect** on the public
Vision path or on REALITY fallback. Unifying these three is the precondition for
any backend work, and is why Phase 3 lands before Phase 4/5.

### 1.2 Steady-state allocations on the framed path

Measured by reading the per-record loops:

| Site | Baseline behaviour | Bytes per record |
| --- | --- | --- |
| `record_read.rs:143` | `Vec::with_capacity(512)` per TLS record, grown through a 4 KiB stack scratch and `extend_from_slice` | 1 allocation + up to 5 reallocations |
| `vision.rs:322` | `record.plaintext().to_vec()` per uplink record | 1 allocation ≤ 8 KiB |
| `vision.rs:558` | `Vec::new()` + `try_reserve_exact(record_length)` per nested downlink record | 1 allocation ≤ 18 432 B |
| `vision.rs:469/481` | `Vec::with_capacity(VISION_FRAME_SIZE)` per `write_vision_content` call | 1 allocation of 8 KiB |
| `vision.rs:322` (indirect) | `VisionEncoder::encode` builds a complete intermediate frame that is then copied into the AEAD plaintext | 1 full frame copy |

So the baseline framed path performs **four heap allocations and one avoidable
full-frame copy per record pair**. Phase 1 removes all of them.

### 1.3 Ownership at baseline

`VisionHandler::handle` splits the client socket with `TlsApplicationIo::into_split`,
which calls `tokio::io::split` (`application_io.rs:215`). `tokio::io::split`
produces `ReadHalf<S>`/`WriteHalf<S>` that **cannot be recombined into the
original `TcpStream`**, and the destination socket is split the same way at
`vision.rs:196`. Once Vision reaches a Direct boundary the code therefore only
has half-streams (`vision.rs:348`, `vision.rs:442`) and can never hand a whole
socket to a kernel backend.

`bind_application_halves` (`application_io.rs:166`) already exists and has zero
call sites. It is the intended seam for binding independently owned halves to
the two TLS directions.

### 1.4 One-way versus two-way Direct at baseline

Uplink Direct is driven by the authenticated Vision command (`VisionDecoder`).
Downlink Direct is driven by passive TLS-1.3 classification of the destination
stream (`NestedTlsDetector`). The two run as independent futures joined only by
`tokio::try_join!`; `VisionRelayStats` already carries separate `uplink_direct`
and `downlink_direct` booleans (`vision.rs:47-48`). One-way Direct is therefore a
reachable state today and **must not** be treated as a whole-pair raw handoff.

### 1.5 Logging

`src/logging/sink.rs` uses a closed `LogEvent` enum with intrinsic levels and a
single emission point in `src/server/production.rs`. `RotatingFile::write` calls
`prune_total()` on **every** record (`sink.rs:298`), performing up to
`max_files - 1` `fs::metadata` calls under a process-wide mutex per log line.

### 1.6 Configuration

`RelayPolicy` (`config/model.rs:667`) already carries `splice`, `ioUring` and
`sockhash`, but `validate.rs:732-743` rejects `ioUring: true` and
`sockhash: true` unconditionally as "reserved". `policy.relay` is already cold
configuration: `ensure_hot_compatible` rejects reloads that change it
(`production.rs:440`).

## 2. Reference material disposition

`reference/change/` was audited line by line. Decisions:

| Recovered artefact | Decision | Reason |
| --- | --- | --- |
| `src/transport/backend/uring.rs` | **rejected** | `mpsc::UnboundedSender<Request>` violates the boundedness invariant |
| `crates/src/uring/raw.rs` | **rejected** | hand-written io_uring UAPI; the audited `io-uring` crate is required |
| `crates/src/bpf/insn.rs`, `program.rs` | **ideas only** | instruction encoding re-derived from the kernel ABI and covered by ABI tests |
| `crates/src/sock.rs` | **ideas only** | flow identity re-derived; the recovered version keys on the listener port |
| `crates/tests/sockhash_verdict.rs` | **test ideas harvested** | scenario list reused, assertions re-derived |
| benchmark claims in comments | **discarded** | not evidence for this branch |

No file from `reference/change/` is copied verbatim into the branch.

## 3. Corrected data-path matrix

The specification matrix was checked against real call sites. Two corrections:

* **SOCKS5 post-negotiation stream.** `src/server/outbound.rs` performs SOCKS5
  negotiation on an owned `TcpStream` and returns the owned stream, so full FDs
  *are* recoverable; the row stands.
* **REALITY fallback.** `RealityFallback::relay` is generic over
  `I: AsyncRead + AsyncWrite + ?Sized` and is invoked with the still-unsplit
  client `TcpStream` from `reality.rs`. The concrete owned socket is available at
  the call site, so the fallback row becomes eligible once the call site passes
  the owned stream instead of a borrow.

| Path | Semantic phase | Kernel backend eligible | Outcome on this branch |
| --- | --- | ---: | --- |
| REALITY handshake | TLS/REALITY authentication | No | userspace |
| Consumed fallback prefix | parsed handshake bytes | No | written in order first |
| Remaining REALITY fallback stream | raw TCP↔TCP | Yes | owned `TcpRelay` |
| VLESS request parsing | header + payload prefix | No | borrowed range in retained buffer |
| Vision framed uplink | TLS open + Vision decode | No | zero steady-state allocations |
| Vision framed downlink | Vision encode + TLS seal | No | assembled in final AEAD storage |
| One-way Vision Direct | one raw, one framed | **No whole-pair handoff** | bounded mixed userspace relay |
| Two-way Vision Direct | both at exact boundaries | Yes | reunite sockets → `TcpRelay` |
| SOCKS5 negotiation | SOCKS5 | No | userspace |
| SOCKS5 post-negotiation | raw | Yes | owned `TcpRelay` |
| NXR inbound authentication | NXR request/HMAC/replay | No | userspace |
| NXR landing after authentication | raw TCP↔TCP | Yes | owned `TcpRelay` |
| NXR outbound after request write | raw TCP↔TCP | Yes | owned `TcpRelay` |
| Blackhole | none | No | unchanged |

## 4. Ownership model

The branch replaces `tokio::io::split` with `tokio::net::TcpStream::into_split`
on both the client and the destination socket. `OwnedReadHalf::reunite` restores
the original `TcpStream`, which makes "recover the complete socket" a checked
operation rather than an impossible one.

```text
TcpStream --into_split--> (OwnedReadHalf, OwnedWriteHalf)
                              |               |
                bind_application_halves(reader, writer, tls)
                              |               |
                 TlsApplicationReader   TlsApplicationWriter
                              |               |
                        into_inner()     into_inner()
                              |               |
                              +--reunite()----+
                                     |
                                 TcpStream
```

`reunite` returns `ReuniteError` when the halves do not belong to the same
socket, so descriptor aliasing is impossible by construction.

### 4.1 Direction state machine

```text
Framed -> DirectPending -> RawReady -> Closed
   |            |             |
   |            +-> Closed    +-> Failed
   +-> Outer -> Closed
   +-> Closed
   +-> Failed
```

`Outer -> RawReady`, `RawReady -> Framed`, and any transition out of `Closed` or
`Failed` are rejected by `DirectionState::advance` and covered by unit tests.

### 4.2 Bilateral handoff preconditions

All ten specification preconditions are encoded in
`DirectHandoff::try_complete`. The implementation makes the dangerous cases
unrepresentable rather than merely checked:

1. Both directions report `RawReady` through an `AtomicU8` per direction.
2. The pending block is a single `Option<PendingBlock>` per direction, bounded
   by `bufferBytes`, and `try_complete` refuses while it is `Some`.
3. Socket recovery consumes the `TlsApplicationReader`/`TlsApplicationWriter`,
   which drops the record layers and therefore all socket borrows.
4. `reunite` is fallible and its error terminates the session rather than
   falling back.

### 4.3 One-way Direct

If only one direction reaches `RawReady`, the pair is **never** handed to
splice, io_uring or sockhash. The raw direction is relayed with one pooled
bounded buffer while the framed direction keeps running the TLS/Vision codec.
Half-close, End, alert, timeout, cancellation, reset and EOF semantics are
preserved unchanged.

## 5. Backend model

```rust
pub enum RelayBackend { Buffered, Splice, IoUring, Sockhash }
pub enum BackendDeclineReason { Disabled, UnsupportedOperatingSystem, UnsupportedKernel,
    MissingOperation, MissingCapability, BlockedBySeccomp, BlockedByLsm, ResourceLimit,
    QueueUnavailable, MapUnavailable, UnsafeToArm, ExistingQueuedBytes, InitializationFailure }
```

### 5.1 Zero-byte fallback rule, structurally enforced

A backend never returns a bare `io::Result`. It returns
`Result<BackendRun, BackendError>` where

```rust
enum BackendRun { Declined(BackendDeclineReason), Completed(RelayOutcome) }
struct BackendError { transferred: Transferred, source: io::Error }
```

`Transferred` is produced only by the shared `TransferLedger`, whose counters are
atomic and monotonic. The selection loop can only continue to the next backend
when it holds a `Declined`, and `Declined` cannot be constructed after the
ledger has observed a nonzero count — the constructor takes `&TransferLedger`
and returns `Err` if it is nonzero. There is no code path that turns a
post-transfer error back into a retry.

### 5.2 Automatic preference

`sockhash -> splice -> buffered`.

io_uring is implemented, probed, reported and selectable, but is **excluded from
automatic selection** on this branch. Justification: no retained measurement on a
target host proved it is not materially slower for this workload class, and the
specification forbids adding a speculative classifier purely to claim
adaptivity. `relayBackend: "ioUring"` selects it explicitly.

## 6. Resource formulas

Every formula uses `checked_*` arithmetic and is validated before any listener
binds.

```text
buffered_memory        = active_buffer_pairs * 2 * bufferBytes
io_uring_registered    = maxIoUringRelays * 2 * slotsPerDirection * bufferBytes
io_uring_metadata      = shards * (sqEntries + cqEntries + fdSlots + requestSlots) * entryBytes
sockhash_capacity      = flowSlots * (flowKeyBytes + socketEntryBytes + statsEntryBytes + overhead)
total_pinned           = io_uring_registered + sockhash_capacity  <= maxPinnedMemoryBytes
total_relay            = buffered_memory + io_uring_registered    <= maxRelayMemoryBytes
```

Constraints: `maxIoUringRelays <= maxConnections`,
`maxSockhashRelays <= maxConnections`, and an enabled backend must have a
nonzero relay limit. `maxPooledBuffers` remains a **count**, never a byte budget.

## 7. Requirement → test mapping

| Requirement | Test |
| --- | --- |
| zero steady-state allocations per record | `tests/allocation_gate.rs` (counting global allocator) |
| stable record storage address | `record_read.rs` unit test `reused_storage_address_is_stable` |
| header/body fragmentation, min/max record, timeout prefix | `record_read.rs` unit tests |
| Vision encoder equivalence | `tests/vision_encoder_oracle.rs` differential vs retained reference encoder |
| direction state machine transitions | `vision/direct.rs` unit tests |
| bilateral handoff preconditions | `tests/vision_direct_handoff.rs` |
| one-way Direct stays userspace | `tests/vision_direct_handoff.rs` |
| shared backend conformance | `tests/relay_backends.rs` (matrix over available backends) |
| zero-byte fallback rule | `transport/relay/ledger.rs` unit tests |
| io_uring ABI/lifecycle | `crates/rr-linux/tests/uring_abi.rs`, `uring_conformance.rs` |
| sockhash ABI/flow identity | `crates/rr-linux/tests/bpf_abi.rs`, `sockhash_flow.rs` |
| sockhash privileged behaviour | `crates/rr-linux/tests/sockhash_privileged.rs` (ignored without capability) |
| resource formulas reject overflow | `config/validate.rs` unit tests |
| padding distribution | `vision.rs` unit tests with deterministic seeding |

## 8. Phase plan

| Phase | Commit | Independently buildable |
| --- | --- | --- |
| 0 | design record | yes |
| 1 | `perf(tls): reuse record buffers and remove steady-state copies` | yes |
| 2 | `refactor(vision): preserve socket ownership across direct transitions` | yes |
| 3 | `feat(relay): introduce bounded adaptive relay abstraction` | yes |
| 4 | `feat(linux): add bounded io_uring relay backend` | yes |
| 5 | `feat(linux): add bounded sockhash relay backend` | yes |
| 6 | `feat(relay): select bounded backends with explicit capability fallback` | yes |
| 7 | tests, benchmarks, documentation | yes |

## 9. Environment limitations recorded up front

The implementation environment is an unprivileged container. Capability probes
are written to *report* rather than assume, and the gates that cannot execute
here are listed in the handoff `UNVERIFIED-GATES.md` with the exact command the
operator must run. No skipped gate is reported as a pass anywhere in this branch.
