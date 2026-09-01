# ADR 0016: The protocol core is `no_std`-ready and stays in the main crate

## Status

Accepted (positive finding, deferred action). The `no_std + alloc` boundary
inside `src/protocol` is real and is now enforced by a test. Extracting it into
a separate crate is deliberately **not** done, and the conditions that would
change that are recorded below.

## Context

[ADR 0015](0015-rr-linux-is-a-no-std-linux-abi-boundary.md) made the Linux ABI
boundary a genuine `no_std` crate. The obvious next question, and the one
issue #191 asks, is whether the protocol semantics above it are also a coherent
layer that does not depend on `std` or a runtime — the VLESS codec, Vision
framing, the NXR wire, and the REALITY-adjacent pure transformations.

The question is *not* how much code can be moved into another crate. It is
whether a reusable canonical semantic layer exists that naturally has no
runtime dependency, and whether making it a crate is worth what that costs.

## What the audit found

`src/protocol` is 19,436 lines. Classifying every module by what it actually
depends on:

| classification | modules |
| --- | --- |
| **`core` + `alloc` only** | `vless/{types,addons,decode,padding,vision}`, `reality/client_hello`, `reality/tls13/{keys,record,messages,server_hello,cover_profile}`, `nxr` |
| **`core` + `alloc`, plus one application type** | `vless/validate` (`AdaptiveUserMap`), `reality/auth` (`RealityConfig`, `VlessInboundConfig`, `server_name`) |
| **mixed; needs splitting** | `handoff` — a pure continuation-blob codec sharing a file with a sharded, `Instant`-driven nonce replay cache |
| **inherently runtime-bound** | `reality/replay` (concurrent cache + clock + `ResourceGovernor`), and every `*_read` module, `application_io`, `idle`, `allocation_gate`, `handshake` |

The first row is ~4,400 production lines containing **zero** Tokio references,
**zero** `async`/`await`, and **zero** `std`-only facilities. Every `std` path
it uses — `error::Error`, `fmt`, `str`, `net::{Ipv4Addr, Ipv6Addr}`,
`ops::Range`, `iter::repeat_n`, `sync::Arc` — is a re-export of the `core` or
`alloc` item of the same name.

This is not an accident. The tree already separates readers from codecs by
module (`vless/read.rs` beside `vless/decode.rs`,
`tls13/record_read.rs` beside `tls13/record.rs`), and that discipline has held.

### The finding is compile-verified, not inferred

Two slices were compiled as `#![no_std]` + `extern crate alloc` crates: the
VLESS and Vision codec with its user map, and the TLS 1.3 record layer and key
schedule. Both compile **with no logic changes** — only import rewrites
(`std::` → `core::`/`alloc::`) and `hashbrown` for `std::collections::HashMap`.

`cargo tree -e normal -f "{p}|{f}"` over both closures shows **no crate with a
`std` feature enabled**, including `ring`, which resolves without `alloc` or
`std`. The concern that the fastest AEAD backend would force `std` — and so
force a choice between ADR 0015's architecture and §39's "crypto performance
outranks purity" — does not exist.

### What extraction would cost

- **52 `pub(crate)`/`pub(super)` items become public API.** Sixteen in
  `client_hello`, eight in `cover_profile`, nine in `decode`, seven in
  `record`. These are deliberately internal: cover-probe templates, record
  layer internals, `ClientHello` parsing internals. Publishing them to gain a
  property that already holds is a poor trade on security-critical code.
- **One new dependency, on a measured path.** `std::collections::HashMap`
  becomes `hashbrown`. The identity lookup it serves has a documented measured
  crossover, so swapping the hasher is a hot-path change that would need its
  own before/after measurement — for an architectural reason, not a
  performance one.
- **Two real decouplings.** `reality/auth` would have to compile from
  primitives instead of `RealityConfig`, and `handoff` would have to be split
  into codec and replay cache.
- **No consumer.** Nothing outside this binary would depend on the crate. The
  repository has one product and one binary.

## Decision

**Record the boundary as real, enforce it with a test, and do not extract it.**

1. `tests/protocol_core_boundary.rs` asserts, over the listed core modules,
   that they name no async runtime, no clock, no configuration, no transport,
   no server, no socket type, and no `std` facility that lacks a `core`/`alloc`
   equivalent. This is the property a crate boundary would have enforced.
2. The module list is written out rather than discovered, and a vacuity test
   fails if a listed module disappears or empties — so a rename cannot silently
   retire the rule.
3. `reality/auth`, `reality/replay`, `handoff` and every reader module stay
   outside the enforced set, with their reasons recorded above. They are not
   failures of the layering; they are where the layering correctly puts
   configuration, concurrency, and I/O.

The rule that decides this is §11's: a new crate exists for a real dependency,
platform, `no_std`, reusable-API, or isolation requirement. The `no_std`
property is real, but it is already true and now mechanically enforced; the
reusable-API requirement has no consumer. A crate today would publish 52
internal items and change a measured lookup to buy an invariant this ADR just
demonstrated is held.

## Consequences

- The canonical semantics stay in one place. There is no second implementation
  and no representation adapter, so the "one canonical model" invariant is
  untouched.
- Regression is now mechanical rather than a matter of reviewer attention. A
  future change that reaches for `tokio::time` inside `vless/vision.rs` fails a
  test with the module and the token named.
- The extraction, if it happens, starts from a layer already proven to compile
  against `core` and `alloc`, with the blocker list above already inventoried.
- `no_std + alloc` is **not** heap-free. This layer uses `Vec`, `String`, `Box`
  and `Arc` freely, and this ADR makes no allocation claim whatsoever.
  Allocation behaviour remains a separate, independently measured problem.

## Rejected alternatives

- **Extract `crates/rr-protocol` now.** Rejected on the cost inventory above:
  no consumer, 52 items published, a measured lookup path disturbed, for an
  invariant already held.
- **Extract only the VLESS codec.** Rejected as a micro-crate: it would split
  the protocol semantics across two homes without completing the boundary, and
  §11 forbids crates created for directory symmetry.
- **Assert the property by freezing today's import list.** Rejected as brittle:
  it would fail on a legitimate `core::cmp::Ordering` and teach contributors to
  edit the test rather than think. The test forbids the facilities that have no
  `core`/`alloc` equivalent instead.
- **Force `core::error::Error` spellings now.** Rejected as churn: `std`'s is a
  re-export of the same trait, so the spelling costs a rename at extraction
  time and nothing else. The test documents this explicitly so a future reader
  does not mistake the omission for an oversight.
- **Move `reality/replay` down by injecting the clock.** Rejected: it is a
  sharded concurrent cache whose entire job is bounded shared mutable state
  under a real clock. Making it runtime-free would mean handing the shard array
  and every expiry decision to a caller — more conversions than it removes.

## Revisit conditions

Extract when any of these becomes true, and not before:

- a second consumer appears — a client implementation, a separate binary, a
  fuzzing or conformance harness that must link the semantics without the
  runtime;
- `reality/auth` is decoupled from `RealityConfig` for its own reasons, and
  `handoff` is split for its own reasons, so the extraction stops carrying
  those costs;
- the enforced boundary is repeatedly violated in review, showing that a test
  is insufficient where a compiler error would not be;
- a measured reason appears to replace `std::collections::HashMap` on the
  identity path anyway, removing the hasher objection.

Do not revisit this ADR to raise the `no_std` line count. That number is a
consequence, not a goal.

## Evidence

- Issue #191, Transaction 2 audit comment: the per-module classification, the
  two `no_std` compile probes with their resolved feature graphs, the 52-item
  encapsulation count, and the ~40-identifier cross-boundary API measurement.
- `tests/protocol_core_boundary.rs`, including its negative controls.
- [ADR 0015](0015-rr-linux-is-a-no-std-linux-abi-boundary.md) for the layer
  below, and [ADR 0008](0008-session-engine-runtime-and-transport-boundaries.md)
  for the layering this refines.
