# ADR 0031: A local control interface that publishes whole generations

Status: Accepted

## Context

rust-reality is configured by one JSON file and changed by editing it and
sending `SIGHUP`. Every external program that wants to manage users — an
operator script, a provisioning tool, a panel built by someone else — must
therefore rewrite the administrator's configuration file, serialize its own
edits against every other writer, and infer from the journal whether the
reload it triggered was accepted. There is no machine-readable way to ask the
running process what it is serving.

The production server already has the property a control plane needs. A
`RuntimeStore` holds one immutable `RuntimeSnapshot` in an `ArcSwap`; an
update compiles a complete candidate from a configuration, rejects cold
changes (`ensure_hot_compatible`), and atomically publishes it under one
update mutex. Connections take an `Arc` of the snapshot at accept time and
never observe a later one. Process-lifetime authorities (admission, replay,
descriptor budget) are borrowed, so publications cannot multiply a ceiling.

The question is what interface to put in front of that machinery, and what it
may and may not change.

## Decision

### Boundary

An entry node may declare `control.socket`, an absolute path. Absent means no
control interface exists. When present, the server first takes an exclusive
`flock` on `<socket>.lock` (held for the process lifetime, never removed), so
a second instance configured with the same path fails instead of unlinking a
live socket. Holding the lock, it removes a stale socket, creates one Unix
domain socket there after every data listener has bound, sets it to mode
`0600`, records its owning uid and inode, and additionally refuses a
connection whose `SO_PEERCRED` uid is neither that owner nor root. Shutdown
unlinks the path only while it still names that inode. A connect probe was
rejected for exclusion: probing and then unlinking is itself a check/unlink
race. There is no TCP listener,
no configuration field that could create one, and no default path. The path is
cold: rebinding it on reload would race connected controllers.

The interface lives in two places, by lifetime:

- `src/control/` is pure: the wire protocol and its strict decoder, the user
  handle derivation, and the translation of one operation into one candidate
  configuration. It performs no I/O and holds no lock.
- `src/server/production/control.rs` serves it: the socket, the connection
  bound, the line framing, and the store transaction.

### Protocol

Version 1 is one JSON object per line in each direction, at most 64 KiB per
request. Every request states `v`; a version the build does not speak is
answered with `unsupportedVersion` and the supported list, never
reinterpreted. Operations are a closed set reported by `system.status`;
errors are a closed code vocabulary. The protocol is documented in
[the control API reference](../en/operations/control-api.md).

### Mutation semantics

A mutation never edits a live structure. Under the store's existing update
mutex, the server takes the generation that is current *after* the lock is
acquired, clones its configuration, applies exactly one change, and holds the
result to the same gates a file must pass: the `MAX_CONFIG_BYTES` size bound,
full semantic validation, and the hot/cold comparison. A candidate that passes
is compiled and published by the code path `SIGHUP` uses. Consequently:

- concurrent controllers are linearised by the lock and none can derive from a
  generation another has already replaced, so no update is silently lost;
- a request may carry `expectedGeneration`, turning the transaction into
  compare-and-publish: if it is not the current generation, nothing changes
  and the caller receives `generationConflict` with the current number;
- a refused candidate leaves the last good generation live and the generation
  counter untouched;
- sessions established under an earlier generation keep it, exactly as across
  a reload. Disabling or deleting a user denies new connections only.

The compile runs on the blocking pool, as `SIGHUP` reloads already do, because
it may read cached assets from disk.

### Publication cost

A control candidate equal to the live configuration publishes nothing and
answers with the current generation (`changed: false`). A candidate that
differs only in `users` is compiled narrowly: the authenticator, its short-ID
index, and the UUID-grouped routing table are rebuilt; the loaded assets,
outbound registry and its pools, cover fallback and its pool, cover profiles,
certificate identity, and logger are carried over. None of the carried-over
components holds per-user state, and the replay cache and admission
authorities were already process-lifetime, so authentication, replay safety,
and existing-session ownership are unchanged: a session still keeps the
generation it was accepted under, and a new generation still denies a removed
or disabled user immediately. Every other difference, and every file reload
or asset refresh, takes the full compile. Pool reuse is limited to this case
deliberately — a full compile may change a cover, an outbound, or a dial
policy, and a pool built for the old one must not serve the new one.

An asset refresh derives its candidate inside the transaction, from the
generation current under the update lock, so it can never republish a
configuration a concurrent control change already replaced.

### Lifecycle

Publication has a commit boundary separate from the update lock: a small
mutex held only while the compiled candidate is swapped in and while a
generation's pools are activated. Shutdown closes that boundary before
retiring the final generation's pools, without waiting for a compile. A
transaction still compiling — a reload, a refresh, or a control mutation on
the blocking pool, which dropping its waiter cannot cancel — then fails with
`ShuttingDown` at commit, and activation after close is a no-op. Pool
activation after a control publication runs on the publishing thread, so a
cancelled waiter cannot leave a published generation without its pools.

### Read bounds

Listings are paged (at most 1000 entries and 256 KiB of entries per page,
always at least one entry) with generation-bound cursors; a cursor from a
replaced generation is refused rather than stitched across generations.
Handles are derived once per generation and cached in it. Every operation
other than `system.status` and `generation.get` runs on the blocking pool,
at most two at a time across all connections, so control work never occupies
a Tokio worker that serves proxy traffic.

### Identity

A VLESS UUID is a credential. It is accepted on `users.create` (or generated
from the OS CSPRNG), returned exactly once in that response, and never listed,
logged, or used as a resource name. Users are addressed by a handle:
`u_` + the first 128 bits of `HMAC-SHA256(k, uuid-bytes)`, with `k` derived by
HKDF-SHA256 from the node's REALITY private key. The handle is stable across
reloads and restarts, unforgeable and non-reversible without the private key
even for a low-entropy UUID, and recomputed from the configuration so it
cannot drift. Replacing the REALITY private key — which already invalidates
every client — changes every handle.

### Lifecycle state

`users[].enabled` (absent means `true`) is part of the one configuration
schema rather than control-only state, so a disabled user is expressible in a
file, survives an asset refresh, and is visible to `check`. A disabled user's
short IDs remain reserved by validation but are excluded when the REALITY
authenticator index is compiled; presenting one is indistinguishable from an
unknown short ID and falls back to the cover. At least one user must remain
enabled, which keeps the authenticator's non-empty invariant untouched.

### Ownership of state

The running daemon never writes the administrator's configuration file.
Control changes live only in the published generation. Each generation records
its origin (`startup`, `configuration`, `assets`, `control`) and whether it
carries control changes the file does not; an asset refresh inherits that flag
and a file reload (`SIGHUP` or `config.reload`) clears it by replacing the
changes. Durable control-managed state is deferred to a separate state
boundary (for example `/var/lib/rust-reality`) in a later decision.

## Consequences

- No relay, record, handshake, or accept path changes. The data plane reads the
  same immutable snapshot it did before; the compile-time differences are the
  `enabled` filter when the short-ID index is built and the narrower
  identity-only compile, which builds the same authenticator and routing
  table a full compile would.
- The locks the control plane shares with the rest of the process are the
  existing update mutex, held for a compile exactly as a reload holds it, and
  the commit boundary, held for a pointer swap or a pool activation.
- Resource use is bounded: at most 8 concurrent control connections, one
  request in flight per connection, at most 2 requests doing work at once, a
  64 KiB request line, a 60 s idle timeout, a 10 s write-stall timeout, paged
  listings, and at most one refusal log event per minute.
- A file reload discards control changes. This is deliberate and observable
  (`controlChanges`), but an operator mixing both workflows must know it.
- Two new structured events (`control_started`, `control_change_published`)
  and one warning (`control_connection_refused`) carry only fixed names, the
  socket path, and generation numbers.

## Rejected alternatives

- **HTTP/JSON over the Unix socket.** The production graph contains no HTTP
  server. Adding one (`hyper` and its stack) grows the supply-chain and audit
  surface of the shipped binary for request routing a closed operation set
  does not need; hand-writing an HTTP/1.1 parser would add a second untrusted
  parser that must be fuzzed and kept correct. Line-delimited JSON needs only
  `serde_json`, already a dependency, is testable with `socat` or any
  language's socket library, and keeps one strict decoder (`control_request`
  fuzz target). If a later phase needs streaming events, they fit the same
  framing as additional response lines on a dedicated subscription
  connection.
- **A TCP or Internet-facing listener.** Rejected outright: remote management
  belongs to external programs that reach the socket through their own
  authenticated transport (for example SSH).
- **Mutable runtime user maps patched in place.** Would create a second source
  of truth beside the configuration, require locks or RCU on the
  authentication path, and break the "a connection sees one generation"
  invariant. Whole-generation publication already exists and costs one compile
  per change.
- **Rewriting `/etc/rust-reality/config.json` from the daemon.** Conflates the
  administrator's input with runtime state, races manual edits, and requires
  write access the service sandbox deliberately does not grant.
- **Using the UUID, or a plain hash of it, as the resource identifier.** The
  first exposes credentials in every listing; the second exposes guessable
  operator-chosen UUIDs to a dictionary search.
- **Control-only enable/disable state.** Would be lost on every asset refresh
  unless duplicated beside the configuration, and could not be expressed in a
  file.

## Compatibility with later phases

- **Telemetry** belongs in process-lifetime authorities beside the store
  (fixed or indexed atomic counters, bounded heavy-hitter tables), never in the
  snapshot, so publication does not reset it. Per-user counters can be indexed
  by the position a generation assigns each enabled user, with the handle as
  the external name. New read operations (`stats.*`) and a subscription
  operation can be added to the version-1 operation set without changing the
  envelope; capabilities advertise them.
- **Guard** primitives that change who may connect (bans, suspension,
  quotas that disable a user) publish generations through the same
  transaction. Counters that trip thresholds remain atomics read off the hot
  path; enforcement on established sessions, if adopted, needs its own
  decision because generations deliberately do not reach live sessions.
- **Persistence** adds a state file under a separate directory, loaded at
  startup and layered deterministically over the configuration; it does not
  change the protocol.

## Revisit conditions

- A required control operation needs request routing, streaming bodies, or
  content negotiation that line framing cannot express cleanly.
- Generation compile cost becomes material for controllers that change users
  at high frequency.
- Persistence is introduced, which must define how control state and file
  reloads compose.
