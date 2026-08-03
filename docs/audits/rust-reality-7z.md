# `rust-reality.7z` reuse audit

## Provenance and handling

- Archive: `rust-reality.7z`
- SHA-256: `20611ae6e5dc5de4748777e929d4a085faa3a3cdb84c441b201595eef8e15ec1`
- Physical size: 553,087,331 bytes
- Listed entries: 13,249
- Listed unpacked bytes: 887,768,726
- Audited Rust source: 115 files, 1,249,503 bytes

The archive is untrusted migration input, not a source tree to merge. It contains
an embedded Git repository, compiled third-party binaries, local deployment
artifacts, and `local/secrets/**`. Only source, manifests, public test fixtures,
scripts, and documentation were extracted into an isolated audit directory.
Secret-looking files and all deployment material were excluded without reading
their contents.

The archive must never be committed, copied into a build context, or used as a
Cargo source directory. The production repository remains the sole source of
truth.

## Executive decision

The archive contains substantial protocol research worth preserving, but its
root crate is too coupled to migrate as a unit. Reuse is therefore permitted
only by small, reviewed ports that introduce their own invariants, tests, and
atomic commits in the production repository.

The migration order is:

1. bounded wire parsing and raw-byte preservation;
2. cryptographic primitives and RFC vectors;
3. TLS 1.3 record and key schedule state machines;
4. two-phase REALITY authentication and replay admission;
5. target compatibility probing and presentation snapshots;
6. Vision framing and TLS-boundary switching;
7. bounded relay and Linux-only acceleration;
8. Geo assets, routing, outbounds, and NXR.

No later layer may be imported before the lower layer has independent tests.

## Findings

### Critical: replay state is committed before ClientFinished

The archived REALITY server verifies ClientFinished before returning an
established session, which is correct. However, it records the authenticated
ClientHello in the global replay state before sending the forged server flight
and before ClientFinished is verified.

This allows a captured ClientHello that arrives first to reserve the replay
identity even when the sender cannot complete the handshake. A legitimate
client using that ClientHello can then be diverted to fallback.

The production design must use a two-phase replay transaction:

- `reserve`: install a bounded pending entry and return an RAII reservation;
- `commit`: convert the pending entry to accepted only after the exact expected
  ClientFinished is verified in constant time;
- `Drop`: remove an uncommitted pending entry on error, timeout, cancellation,
  or peer close.

Concurrent duplicate pending or accepted entries are rejected or sent to the
bounded cover fallback. Pending entries have a short absolute deadline and are
charged to the pre-authentication resource governor.

### Critical: the archive contains secret and deployment material

`local/secrets/**`, deployment binaries, private-looking keys, and full upstream
reference trees are present. Their presence makes whole-archive extraction,
vendoring, or history import unacceptable. A repository secret scan is required
before every future import commit.

### High: custom TLS code requires proof, not trust

The archive implements a dedicated TLS 1.3 record layer, key schedule,
handshake messages, ClientHello parsing, target presentation synthesis, and
Finished verification. The separation is promising and gives explicit buffer
ownership, but correctness cannot be inferred from code volume or internal
tests.

Before reuse, each component requires:

- RFC 8446 key schedule, transcript, nonce, record, and Finished vectors;
- RFC 5869 HKDF vectors and AEAD vectors from the selected mature libraries;
- differential ClientHello parsing against rustls and captured Xray traffic;
- differential TLS behavior against OpenSSL/nginx cover targets;
- end-to-end interoperability with Xray-core 26.7.28;
- fuzzing of all public parsers and state transitions;
- cancellation, truncation, fragmentation, and oversized-record tests.

Cryptographic algorithms remain library-owned. The project may own protocol
state and buffers, but not AES-GCM, ChaCha20-Poly1305, HKDF, SHA-2, X25519,
Ed25519, ML-KEM, ML-DSA, or operating-system randomness.

### High: unsafe code is not isolated

Unsafe code appears in runtime, networking, geodata fetching, record handling,
socket options, batched relay, and splice implementations. This violates the
target architecture in which protocol crates deny unsafe code.

Only a small Linux I/O crate may contain unsafe code. Every unsafe block must
state its safety invariants and have a safe API. Protocol, configuration,
routing, TLS state, REALITY, Vision, and NXR framing crates deny unsafe code.

### High: resource controls are coupled to observability

The archived server obtains admission, crypto, fallback, and pipe permits from
a `metrics` module. Metrics and health surfaces are outside the product scope,
but the resource limits are mandatory security controls.

They must be extracted into a standalone `ResourceGovernor` with bounded RAII
permits. It must not expose an HTTP endpoint or require counters on the data
path.

### Medium: panic and unbounded-operation debt

A lexical audit found 736 `unwrap` calls, 142 `expect` calls, 12 explicit
`panic!` calls, 37 uses or mentions of unbounded behavior, and 98 task-spawn
sites across source and tests. Many are test-only, but the archive does not make
the production boundary easy to prove.

Migrated data-path code must contain no `unwrap`, `expect`, or panic path. Queue,
buffer, task, replay, fallback, probe, DNS, route, and NXR pool bounds are
explicit configuration values with validated ceilings.

### Medium: source text contains encoding damage

Several comments and manifest descriptions contain mojibake. Source code may be
ported, but documentation and error text must be rewritten rather than copied.

## Component disposition

| Archived component | Decision | Required work before production |
|---|---|---|
| `reality/client_hello.rs` | Port early | Replace owned fields where possible, preserve exact raw bytes, add fragmentation/size/fuzz/differential tests |
| `reality/auth.rs` | Conditional port | Verify Xray 26.7.28 derivation and session-id layout; constant-time comparison; mature X25519/HKDF/AEAD only |
| `reality/tls13/*` | Conditional port | Remove unsafe from protocol layer; add RFC vectors and OpenSSL/rustls differential tests |
| `reality/handshake.rs` | Rewrite around proven pieces | Explicit state enum, transcript ownership, no hidden globals, commit only after ClientFinished |
| `reality/server.rs` | Do not copy wholesale | Split admission, fallback, presentation, handshake, and established-session phases |
| `reality/fallback.rs` | Port early | Byte-for-byte prefix ownership tests, bounded lifetime and concurrency, no synthetic pre-auth response |
| `reality/replay.rs` | Redesign | Two-phase reservation/commit with RAII rollback and bounded shards |
| `reality/profile.rs` / `probe.rs` | Conditional port | Immutable target snapshots, strict compatibility verdicts, atomic publication, bounded refresh |
| `vless/vision.rs` | Conditional port | Xray differential vectors, fragmentation/fuzz tests, TLS-boundary proof |
| `vless/request.rs` | Compare and selectively port | Reconcile with the smaller production decoder and retain allocation budgets |
| `relay/buffers.rs` / `copy.rs` | Port | ResourceGovernor integration, bounded pool, cancellation and half-close tests |
| `relay/splice.rs` | Port into Linux I/O crate | Safe wrapper, nonblocking readiness, pipe budget, never cross encrypted TLS boundary |
| `relay/sockopt.rs` | Rewrite minimally | Keep only measured options; document kernel/version behavior |
| `geo/*` and `rr-geodata` | Conditional port | Xray DAT compatibility, ext assets, atomic last-good snapshots, corruption tests |
| `rr-routing` | Port concepts | Replace flat profiles with `routing.users` groups plus small `globalRules` |
| `outbound/direct.rs` | Conditional port | Preserve DirectBarrier and DNS strategy semantics; remove metrics coupling |
| `outbound/socks5.rs` | Port | Bounded handshake and authentication, no credential logging |
| TOML compiler / embedded config | Reject | Product configuration is strict JSON with one runtime model |
| `metrics.rs` / `telemetry.rs` | Reject | Outside product scope |
| x86 assembly helpers | Defer | Reintroduce only after portable baselines prove a material benefit |
| archived binaries and secrets | Reject permanently | Never extract into or reference from the repository |

## Security and performance boundaries

- The server can be hardened against scanning, active probing, replay, protocol
  identification, and local resource exhaustion. It cannot claim application-
  layer protection from upstream volumetric DDoS.
- Kernel zero-copy is permitted only for plaintext socket-to-socket regions.
  TLS and REALITY records retain explicit userspace ownership until authenticated
  decryption or encryption is complete.
- Performance claims require measurements on the same host with recorded kernel,
  CPU, toolchain, commit, configuration, and test order. Microbenchmarks are not
  Internet throughput claims.
- The same-city NXR design should optimize connection establishment and queueing
  delay first; multiplexing is retained for short flows, while sustained large
  flows switch to dedicated connections to avoid head-of-line blocking.

## Acceptance gate for a migrated module

A port is accepted only when all of the following are true:

1. its public invariants and failure behavior are documented;
2. protocol code denies unsafe code;
3. hostile input cannot panic or allocate without a configured bound;
4. unit, property, fuzz, and relevant differential tests exist;
5. `fmt`, strict Clippy, workspace tests, doc tests, audit, and deny checks pass;
6. any claimed optimization has a reproducible baseline and preserves the
   security boundary;
7. the commit contains no archive history, secret, deployment artifact, or
   unrelated component.
