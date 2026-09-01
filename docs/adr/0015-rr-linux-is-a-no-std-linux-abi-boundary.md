# ADR 0015: `rr-linux` is a `no_std` Linux ABI boundary

## Status

Accepted. This decision changes the shape of one crate boundary and the types
that cross it. It does not change observable server behavior, does not make the
daemon libc-free, and does not authorize any further `no_std` work.

## Context

[ADR 0008](0008-session-engine-runtime-and-transport-boundaries.md) placed
`crates/rr-linux` at the bottom of the layering as the only place raw-syscall
`unsafe` may live, so the protocol crate can keep `#![deny(unsafe_code)]`. That
boundary existed, but it was not the boundary it claimed to be.

The crate was `std`, depended on `libc` with the `std` feature, and reached the
kernel through 15 hand-written `unsafe` blocks: `socket`/`bind`/`listen` with a
hand-built `sockaddr_in6`, four `setsockopt` shapes, two `getsockopt` shapes,
`ioctl(FIONREAD)`, `getrlimit`/`setrlimit` over a `mem::zeroed()`
`struct rlimit`, and `sysconf(_SC_PAGESIZE)`. It returned `std::io::Error`,
`std::net::TcpListener` and `std::fs::File`, took `RawFd` at most entry points,
and read `/proc/self/statm` with `read_to_string` and `String` parsing on a
process-lifetime timer. It already used `rustix` for pipes, `splice`, `fcntl`
and `shutdown`, so two mechanisms for reaching the kernel coexisted in one file.

The consequence was not a performance problem. It was that the one crate whose
entire purpose is to be auditable required `std` to express itself, hand-wrote
ABI that a reviewed dependency already provides, and handed descriptor numbers
upward where ownership should have travelled.

A dependency audit recorded on issue #191 established the constraint that
frames this decision: removing the `rr-linux -> libc` edge **cannot** remove
glibc from the daemon. Tokio/mio/socket2, signal handling, getrandom/ring,
parking-lot platform code and other std runtime paths retain `libc`
independently. Any decision that justified itself by ELF purity would have been
justified by a false premise.

## Decision

**`crates/rr-linux` is `#![no_std]`, reaches the kernel only through reviewed
`rustix` APIs, reports `Errno`, and transfers descriptors by ownership.**

### Kernel access

All mechanisms go through `rustix` with `default-features = false` and the
`fs`, `net`, `param`, `pipe`, `process` features. `rustix/use-libc` is not
enabled, so on Linux rustix resolves its `linux_raw` backend over
`linux-raw-sys` and issues syscalls directly rather than through a C library.
No syscall number, ioctl opcode, `sockaddr` layout, or architecture trampoline
is written here.

This is an ownership and auditability decision, not a performance one. rustix
was already issuing the relay's `splice` calls the same way; the syscalls the
kernel sees are unchanged.

### Error model

Mechanisms return `rustix::io::Errno`. The Runtime Adapter converts to
`std::io::Error` at the call sites that need one, which preserves the raw errno
that accept classification already depends on. No error is stringified in the
mechanism layer, and no error hierarchy is invented: the single non-kernel
failure — a `/proc/self/statm` that is not the documented shape — is a
two-variant, non-allocating `MemoryError`.

### Descriptor ownership

Creation returns `OwnedFd`; observation takes `impl AsFd`. `RawFd` does not
appear in the public API, and the `fd()` accessors in the TLS layer return
`BorrowedFd<'_>` instead of a number.

`bind_tcp_listener_v6only` returns the created, configured, bound and listening
descriptor rather than a `TcpListener`. Transport moves it into
`std::net::TcpListener` and then Tokio, by value, once. Taking `SocketAddrV6`
rather than `SocketAddr` also removes an error case that could not occur.

One exception is deliberate. The Vision `DirectionAbortGuard` is armed while a
socket is live and fires on unwind, by which time the owner may already have
closed it, so it can only hold a descriptor number — this is unchanged from the
previous design, which stored `[RawFd; 2]`. `socket::AbortMark` makes that
explicit: `capture` takes an `impl AsFd`, so arming is safe and typed, and
`apply` contains the crate's only `unsafe` block. Applying a stale mark reports
`EBADF`, which callers ignore; applying a *reused* number would mark an
unrelated socket, which is why every path that hands a descriptor onward
disarms its guard first. Containing that hazard here is the whole point of the
crate: the alternative was `unsafe` in the protocol crate.

### The `std` feature

`std` is a default feature that forwards `rustix/std` and nothing else. It
makes `rustix::fd::OwnedFd` *the same type* as `std::os::fd::OwnedFd`, which is
what lets the descriptor transfer above happen without `unsafe` anywhere above
this crate. It enables no mechanism and no alternate code path: the source is
identical in both compositions, and
`cargo check -p rr-linux --no-default-features` compiles the complete
implementation.

The root manifest states the requirement explicitly
(`default-features = false, features = ["std"]`) rather than inheriting it, so
the interop dependency is visible where the composition is chosen.

### `SOMAXCONN`

The listen backlog stays `libc::SOMAXCONN` — the crate's only remaining `libc`
reference, on a `default-features = false` (`no_std`) dependency, resolved at
compile time, mediating no syscall.

It is a C library policy constant, not a kernel ABI number: the kernel clamps
the requested backlog to `net.core.somaxconn` regardless, and the two release
targets deliberately disagree — **4096 on glibc, 128 on musl**. Neither
`linux-raw-sys` nor rustix exposes it. Copying a kernel header value or picking
one universal number would have silently changed the accept queue of one
release tier to remove a dependency name from a crate that still compiles
without `std`. Behavioral compatibility outranks that. A test asserts both
numbers per `target_env`, so a dependency bump that changes either fails the
build.

### `/proc/self/statm`

The resident-set fallback stays in the Linux layer and no longer allocates: a
rustix `open`, a bounded read into a fixed 128-byte stack buffer, and an
explicit ASCII scanner with checked arithmetic. It rejects empty input, a
missing field, a non-decimal, signed or prefixed field, overflow, and — the
case a naive parser gets wrong — a field that runs to the end of a bounded read
and could be a prefix of the real number. It is not a general `/proc` library;
it answers one question.

## Consequences

### Measured

Candidate `e42c2a1de98e0a8caea3d253d2bcd9963a9e7731`, SHA-256
`b9868162e81231938004f7d716b7020f0250695a6986e8cfe846ddc59e0784ea`, Build ID
`39a3a4d367dccd801c8bd9958d3247304b691503`, against the governed baseline
`25bf1f558d846d66c907f78d5b0341354ab1a977`, SHA-256
`4724e5d41da501df9e258ec592a3dfe1809a5358f9d8750178bab89a8dc30c05`, Build ID
`8de6d615b54843eafcc934164a9235216b1ec296`. Every run is a balanced ABBA
transaction over 12 slots and 324 samples with zero failures.

| measurement | result |
| --- | --- |
| setup rate, concurrency 1 / 8 / 32 | median candidate/baseline 0.9982 / 0.9994 / 1.0108; every bootstrap interval spans 1.0 |
| setup server CPU per connection | median 0.9987, bootstrap95 [0.9959, 1.0067] |
| setup receive syscalls per session | 14.6752 baseline vs 14.6537 candidate; the same baseline binary measured 14.6571 in the earlier A/A, so the delta is below the run-to-run spread of one binary |
| relay throughput, concurrency 1 / 8 / 32 | median 0.9873 / 0.9940 / 1.0013, against an A/A control of 1.0058 / 1.0044 / 0.9951 |
| relay server CPU per GiB | A/B +0.33%, bootstrap95 [+0.14%, +0.73%] — but the **identical-binary A/A control** on the same suite gave −0.54%, bootstrap95 [−1.10%, −0.39%] |
| Vision Direct engagement | identical: 22 accepted, 20 measured, 20 downlink Direct, 20 uplink Direct, 23 splice observations, no tunnel bypass |
| Vision Direct throughput | p50 1.038, mean 1.012, p95 0.997, minimum 0.999, while the Xray comparator in the same two runs moved 1.018 p50 / 1.137 mean |

The relay CPU/GiB line is the one that needs stating plainly rather than
rounding off. A three-block bootstrap on this suite produced an interval
excluding 1.0 *for a binary compared against itself*, and that A/A deviation
(0.54%) is larger than the candidate's (0.33%). The harness cannot resolve
differences of this size, so no relay CPU change is claimed in either
direction.

**Verdict: `ARCHITECTURE_IMPROVED_PERFORMANCE_NEUTRAL`.**

### Structural

| property | before | after |
| --- | --- | --- |
| `unsafe` blocks in `rr-linux` | 15 | 1 |
| `libc::` references in `rr-linux` | 77 | 1 (`SOMAXCONN`) |
| `RawFd` in the public API | most entry points | none |
| mechanism crate needs `std` | yes | no |
| `unsafe` above `rr-linux` | none | none |

### ELF

The GNU release is unchanged in kind, as the audit predicted. `DT_NEEDED`
remains `libgcc_s.so.1`, `libm.so.6`, `libc.so.6`, `ld-linux-x86-64.so.2`;
undefined dynamic symbols fall 120 → 118 and GLIBC-versioned imports 107 → 105,
losing exactly `getrlimit@GLIBC_2.2.5` and `setrlimit@GLIBC_2.2.5`. The other
mechanisms this crate stopped calling — `socket`, `bind`, `listen`,
`setsockopt`, `getsockopt`, `ioctl`, `sysconf` — remain imported because Tokio,
mio and std still call them. `.text` grows 6,091,559 → 6,092,519 bytes
(+0.016%) and the file 8,263,760 → 8,264,920 bytes.

**The daemon still links glibc and is still a std/Tokio application.** That was
never in question and is not a defect: this ADR is about where the Linux ABI
lives, not about what the loader maps. The musl tier remains fully static
(`static-pie`, no dynamic section).

## Rejected alternatives

- **Make the daemon libc-free.** Rejected on evidence, before implementation:
  the resolved dependency graph retains `libc` through Tokio/mio/socket2,
  signal handling, getrandom/ring and other std runtime paths. Pursuing it
  would mean replacing the async runtime, which no measurement supports.
- **Hardcode one `SOMAXCONN`.** Rejected: it changes the accept queue of one
  release tier to delete a dependency name. See above.
- **Copy the kernel header backlog value.** Rejected: hand-copied ABI is the
  thing this ADR removes.
- **Return `RawFd` and let the runtime rebuild owned handles.** Rejected: it
  moves `from_raw_fd` `unsafe` into a crate that denies `unsafe_code`, and
  turns a compiler-checked ownership transfer into a convention.
- **Duplicate the listener as an `OwnedFd` for the abort guard.** Rejected: a
  second owning handle changes reset semantics, because `SO_LINGER` fires when
  the last reference closes.
- **Keep the tests `no_std` too.** Rejected as dishonest framing: the tests
  exercise the `std` interoperability boundary, so they are gated on the `std`
  feature and the `no_std` claim is made about the library, where it is real.
- **Enable `rustix/use-libc-auxv` for the page size.** Rejected: it reintroduces
  a libc call into the mechanism path to avoid a `prctl(PR_GET_AUXV)` that is
  read once and cached, on a path only reached after `/proc` was already read
  successfully.

## Revisit conditions

- Revisit the `libc` `SOMAXCONN` dependency if rustix or `linux-raw-sys` grows a
  target-correct backlog constant, or if the project decides to own the backlog
  as an explicit configuration value rather than inheriting C library policy.
- Revisit the `std` interop feature if `rustix` and `std` descriptor types stop
  being unifiable, which would force a different transfer mechanism.
- Revisit the `AbortMark` exception if the Vision abort guard is restructured so
  the abort happens while the socket is provably live; that would remove the
  crate's last `unsafe` block, and it is a correctness question worth its own
  transaction — the current guard can fire after its descriptors are closed.
- Do not revisit this ADR to pursue a lower `DT_NEEDED` or GLIBC symbol count.
  Those are consequences, not goals.

## Evidence

- Issue #191, "Transaction 1 audit — `rr-linux` no-std feasibility ACCEPTED",
  for the dependency inventory, ELF baseline and profile baselines.
- `crates/rr-linux/` and its 30 focused tests, including the owned-descriptor
  transfer into std, the per-target backlog assertion, and 16 rejected `statm`
  shapes.
- `cargo tree -p rr-linux --no-default-features -e normal`: no crate in the
  closure has a `std` feature enabled, and rustix's optional `libc` dependency
  is absent, which is what proves the `linux_raw` backend selection.
