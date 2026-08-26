# ADR 0008: Session Engine, Runtime Adapter, and Transport Boundaries

## Status

Accepted for incremental implementation in v1.8. No wire-format change is
authorized by this decision.

## Context

rust-reality's v1.7 data plane is deliberately direct: Tokio owns readiness and
task lifetime, protocol code drives the authenticated handshake, and the
existing transport layer takes over the raw relay. This has strong measured
performance, but some pure session decisions still live in modules that also
name Tokio timers, `TcpStream`, descriptor permits, and Linux relay types.

That coupling makes semantic event-sequence fuzzing, deterministic transition
tests, future runtime experiments, and `core`/`alloc` reuse harder than they
need to be. It is not permission to replace the working Tokio/splice path or to
insert an abstraction into every relay operation.

The protected v1.7 baseline includes REALITY authentication and fallback,
VLESS and Vision, Handoff/NXR authentication and replay protection, warm TCP
ownership, generation isolation, FD governance, half-close behavior, stock
Xray interoperability, and the raw relay performance matrix.

## Decision

The service evolves incrementally toward four compiler-visible layers:

```text
Application
    -> Session Engine
    -> Runtime Adapter
    -> Transport
    -> Linux
```

There is one canonical semantic model. Logic moves into the Session Engine,
callers switch to it, equivalence is tested, and the old definition is deleted.
Re-exporting a moved type during a bounded migration is acceptable; maintaining
two independent state machines is not.

### Session Engine

The internal `rr-session` crate owns synchronous data-only decisions such as:

- authenticated-message write progress and the irreversible retry boundary;
- Vision direction phases and permitted transitions;
- session authority and transport-ownership states;
- later, pure REALITY/VLESS/Handoff/NXR orchestration decisions;
- terminal-state and generation-isolation invariants expressed as values.

`rr-session` is `no_std` by default and may use `alloc` only when a moved
algorithm requires bounded owned storage. It must not depend on Tokio, socket
types, file descriptors, DNS implementations, filesystem APIs, process-global
logging, or OS clocks/randomness.

Time, random bytes, DNS/connect results, byte-precise I/O progress, timer
expiration, cancellation, and pressure events enter as explicit inputs. The
engine returns decisions and bounded outputs; it does not perform OS work.

### Runtime Adapter

The Tokio adapter owns:

- accept/connect/DNS execution and readiness;
- timers, spawning, cancellation, reload, and task lifetime;
- conversion of partial I/O into exact semantic progress;
- descriptor/resource permits and generation-owned cancellation;
- construction of fresh cryptographic attempts when semantics permit retry.

The adapter uses static dispatch and ordinary synchronous calls into
`rr-session`. It must not add a channel, boxed future, heap allocation, or
dynamic dispatch per protocol transition.

### Transport

Transport continues to own concrete TCP streams, buffered relay, Linux splice,
vectored I/O, half-close, cancellation, and descriptor lifetime. Once an
authenticated session reaches the exact raw boundary, the runtime transfers
both stream owners to the existing relay backend. The Session Engine does not
observe relay chunks and no semantic abstraction is invoked per byte or per
buffer.

A one-shot `RawRelayGrant` makes that transition compiler-visible. The pure
Session Engine plans the legal `RawReady` successor, the runtime adapter first
commits that state atomically, and only then consumes the non-`Clone`,
non-`Copy` grant while transferring socket ownership. The grant is gone before
the steady-state relay starts and never wraps a relay buffer or syscall.

## Ownership and side-effect rules

- A transport has exactly one owner at a time.
- Warm sockets are protocol-unprivileged until fresh authentication succeeds.
- `CompleteWrite` is irreversible: the peer may authenticate and perform a
  destination side effect, so another transport cannot retry that session.
- A permitted retry constructs entirely fresh Handoff or NXR authentication
  state; the old byte vector is never reused.
- Terminal session/direction states never revive.
- Raw relay consumes socket ownership once; the pool and Session Engine cannot
  reclaim a checked-out session socket.
- Secrets remain zeroized according to the existing protocol ownership; moving
  a type does not justify cloning secret material.

## Performance constraints

The boundary is accepted only if protected exact-binary comparisons remain
neutral or better within justified noise. In particular it must not introduce:

- a message or actor hop per record/chunk;
- `Box<dyn Future>` or trait-object dispatch in the authenticated hot path;
- a heap allocation or `Arc` clone per transition;
- a global lock or additional atomic per relay buffer;
- a copy of ClientHello, TLS record, continuation state, or relay payload solely
  to satisfy the boundary.

Each staged PR records the relevant structure sizes, allocations, copies,
syscalls, CPU/connection, latency, and throughput relative to the frozen v1.7
binary. Pure transition benchmarks supplement but never replace the system and
stock-Xray gates.

## Incremental sequence

1. Extract byte-exact authenticated write progress.
2. Extract Vision direction states and the legal transition table while leaving
   atomic coordination and socket halves in the Tokio module.
3. Express retry/ownership and one-shot relay eligibility as pure values. The
   first `RawRelayGrant` extraction covers Vision Direct; later protocol grants
   must reuse the same one-shot ownership principle rather than creating a
   parallel session model.
4. Move eligible codec/orchestration decisions without changing wire bytes.
5. Make the Tokio driver consume semantic inputs/outputs explicitly.
6. Delete transitional re-exports and duplicate definitions.
7. Prove the raw relay still bypasses the semantic layer.

Every step must compile and test independently. A losing step is redesigned or
reverted rather than subsidized by an architectural performance budget.

## Validation

At minimum each extraction runs:

- `cargo fmt --all --check`;
- workspace all-feature clippy with warnings denied;
- `rr-session` tests with no default features;
- deterministic transition and ownership tests;
- affected integration and half-close tests;
- the protected performance cells appropriate to the changed path.

Before v1.8, the complete v1.7 security, active-probe, sanitizer, fuzz, stock
Xray, package, resource, reload, and short dual-VPS canary gates run against the
exact release candidate.

## Consequences

Pure semantic code becomes independently testable and fuzzable, and runtime or
transport experiments can be compared without cloning protocol logic. The
Linux executable remains a normal `std` program. Tokio and splice remain the
production baseline until evidence supports a better adapter or backend.

The incremental approach temporarily creates more module boundaries and some
type re-exports, but it avoids a flag-day rewrite and preserves bisectability.

## Rejected alternatives

- A full async-trait abstraction over every I/O operation: it taxes the hot path
  and obscures ownership.
- Per-record actors/channels: they add scheduling, allocation, and queue state.
- A second session implementation alongside the current one: equivalence would
  drift and double the security surface.
- Replacing Tokio or splice as part of v1.8: runtime/transport experiments need
  separate evidence and must beat the established baseline.
- Forcing the Linux service to `no_std`: OS integration legitimately belongs at
  the edge; only pure logic benefits from `core`/`alloc` isolation.

## Revisit criteria

Revisit the boundary only if measurements show unavoidable overhead, a protocol
invariant cannot be represented without OS state, or a proven transport backend
needs a different one-shot ownership grant. Public wire changes require a
separate ADR and compatibility/security decision.
