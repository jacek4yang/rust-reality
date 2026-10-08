# Control API

English | [简体中文](../../zh-CN/operations/control-api.md)

An entry node can expose a local control socket that other programs on the
same host use to inspect the running generation and to manage users and short
IDs without editing the configuration file. This page is the protocol
contract. Why it is shaped this way is recorded in
[ADR 0031](../../adr/0031-local-control-interface.md).

rust-reality provides only this generic interface. Dashboards, bots, billing,
account systems, and remote administration are external programs built on it;
none of them belong in this repository.

## Enabling it

```json
{ "control": { "socket": "/run/rust-reality/control.sock" } }
```

`control` is an entry-node section and is cold: changing or removing it
requires a restart. Absent means no control interface exists. The shipped
systemd units create `/run/rust-reality` (mode `0750`, owned by the service
account) for this path. See the [configuration reference](../configuration/reference.md#control).

At startup, after every data listener has bound, the server:

1. opens `<socket>.lock` beside the socket (created with mode `0600` when
   absent, never truncated or removed) and takes an exclusive, non-blocking
   `flock` on it for the life of the process; if another process holds it,
   startup fails and the existing socket is left untouched;
2. holding that lock, removes a stale *socket* left at the path by a previous
   process, and refuses to start if any other kind of file is there;
3. creates the socket and sets it to mode `0600`;
4. accepts only peers whose `SO_PEERCRED` uid owns the socket or is root.

At shutdown the socket is removed only if the path still names the socket
this process created (same device and inode); a file someone else put there
is left alone. The lock file stays, so two instances can never race over
deleting and recreating it. There is no TCP listener and no setting
that creates one; reach the socket remotely through your own authenticated
transport, such as SSH.

## Framing

One JSON object per line in each direction, UTF-8, terminated by `\n`
(`\r\n` is accepted). A connection may send any number of requests; each gets
exactly one response line, in order. Blank lines are ignored.

```shell
printf '%s\n' '{"v":1,"op":"system.status"}' \
  | sudo -u rust-reality socat - UNIX-CONNECT:/run/rust-reality/control.sock
```

### Request

| field | type | required | meaning |
| --- | --- | --- | --- |
| `v` | integer | yes | Protocol version. This build speaks `1`. |
| `op` | string | yes | Operation name, from the table below. |
| `id` | string ≤ 128 bytes | no | Opaque, echoed in the response. |
| `args` | object | no | The operation's arguments. Unknown fields are rejected. |
| `expectedGeneration` | integer | no | Mutations only: apply only if this is still the current generation. |

Unknown envelope fields are rejected. A version this build does not speak is
answered with `unsupportedVersion` and never reinterpreted.

### Response

```text
{"v":1,"id":"r1","ok":true,"generation":8,"result":{ }}
{"v":1,"id":"r1","ok":false,"generation":7,"error":{"code":"notFound","message":"no user has this handle"}}
```

`generation` is the generation current when the response was produced: the
newly published one after a successful mutation. A validation error may carry
`error.path`, the configuration path that failed (`users[2].shortIds[0]`).
Branch on `error.code`; the message is for people and may change.

## Users and handles

A user is addressed by its **handle**, `u_` followed by 32 lowercase
hexadecimal characters. The handle is derived from the user's UUID with a key
derived from the node's REALITY private key: it is stable across reloads and
restarts, reveals nothing about the UUID, and changes for every user if the
REALITY private key is replaced.

UUIDs are credentials. The control interface accepts one on `users.create` (or
generates one) and returns it exactly once, in that response. No listing,
error, or log line contains a UUID.

A user summary, as `users.list` and `users.get` return it, is:

```json
{"handle":"u_…","label":"phone","policy":"split","enabled":true,"shortIdCount":1}
```

A mutation's `user` result is the full view, with `shortIds` in place of
`shortIdCount`. `label` and `policy` are omitted when unset.

## Listings

`users.list` and `shortIds.list` are paged. They accept `limit` (1–1000,
default 100) and `cursor`, and return `total` and, while entries remain,
`nextCursor`. Pass `nextCursor` back as `cursor` to read the next page. A page
holds whole entries and stops growing at 256 KiB of encoded entries, so it may
hold fewer than `limit`; it always holds at least one entry when any remain.

A cursor belongs to the generation that issued it. Presenting it after
another generation was published is refused with `cursorExpired`: restart the
listing without a cursor. A listing is therefore never stitched together from
two generations.

## Operations

| operation | arguments | result |
| --- | --- | --- |
| `system.status` | — | `server` (`name`, `version`, `commit`), `protocol` (`version`, `supported`), `role`, `generation`, `capabilities` (operation names), `limits` |
| `generation.get` | — | `generation`, `origin`, `controlChanges` |
| `config.reload` | — | as `generation.get`, for the published generation |
| `users.list` | `cursor`?, `limit`? | `users`: user summaries, `total`, `nextCursor`? |
| `users.get` | `user` | `user`: a user summary |
| `users.create` | `id`?, `shortIds`?, `label`?, `policy`?, `enabled`? | `user`, `id` (the UUID, once) |
| `users.setEnabled` | `user`, `enabled` | `user` |
| `users.delete` | `user` | `handle` |
| `shortIds.list` | `user`?, `cursor`?, `limit`? | `shortIds`: `shortId`, `user`, `enabled`; `total`, `nextCursor`? |
| `shortIds.add` | `user`, `shortId` | `user` |
| `shortIds.remove` | `user`, `shortId` | `user` |
| `shortIds.rotate` | `user`, `retire`?, `bytes`? | `shortId` (the new one), `user` |

- `users.create` without `id` generates a UUID from the operating-system
  CSPRNG; without `shortIds` it generates one 8-byte short ID. `label` is at
  most 128 bytes without control characters.
- `users.setEnabled` with `false` writes `enabled: false`; with `true` it
  removes the field, because enabled is the default.
- `shortIds.rotate` draws a fresh short ID of `bytes` bytes (1–8, default 8)
  that no user owns and that is not being retired, adds it, and removes every
  short ID in `retire` (at most 16, each owned by this user) in the same
  generation. With no `retire`, old short IDs keep working: distribute the new
  one to clients, then remove the old ones in a second call.
- Short IDs are compared case-insensitively and stored in lowercase.
- Every mutation result carries `changed`. A mutation whose result equals the
  live configuration (for example `users.setEnabled` to the state the user
  already has) publishes nothing: `changed` is `false` and `generation` is the
  current one.

### Generation origin

`origin` names what produced the live generation: `startup`, `configuration`
(a file reload by `SIGHUP` or `config.reload`), `assets` (a scheduled asset
refresh of the live configuration), or `control`. `controlChanges` is `true`
while the live generation carries control changes the configuration file does
not have.

## Generation semantics

A mutation is one transaction:

1. take the store's update lock;
2. if `expectedGeneration` is present and not current, stop with
   `generationConflict`;
3. derive a candidate from the *current* configuration with exactly one change;
4. hold it to the configuration size limit and full semantic validation, and
   reject cold changes, exactly as for a configuration file;
5. compile it and publish it atomically, as a `SIGHUP` reload does.

A candidate that differs from the live configuration only in `users` takes a
narrower compile: the REALITY authenticator, its short-ID index, and the
UUID-grouped routing table are rebuilt from the new users, while the loaded
geo assets, the outbounds and their line-to-landing pools, the cover fallback
and its pool, and the cover profiles are carried over from the live generation.
User administration therefore never reads or downloads an asset and never
cools a warm pool. Any other difference takes the full compile.

An asset refresh is the same kind of transaction: it recompiles the
configuration that is current under the lock, so it never reverts a control
change published while it waited.

When the server begins shutting down it closes the store before retiring the
last generation's pools. A transaction still compiling at that moment fails
with `unavailable` and publishes nothing.

Consequences:

- Concurrent controllers never silently overwrite each other: each change is
  applied to the result of the previous one. Use `expectedGeneration` when a
  change is only correct relative to state you read (compare-and-publish), and
  to make a retried request safe.
- A refused change leaves the live generation and the generation counter
  untouched.
- Sessions established earlier keep their generation. Disabling or deleting a
  user, or removing a short ID, denies **new** connections only.
- A disabled user's short IDs stay reserved; presenting one is treated exactly
  like an unknown short ID. At least one user must stay enabled, and every user
  keeps at least one short ID.

## Control changes and the configuration file

The server never writes its configuration file. Control changes live only in
the running generation:

- an asset refresh keeps them;
- a file reload (`SIGHUP` or `config.reload`) **replaces them** with the file's
  content, and `controlChanges` becomes `false`;
- a restart loses them.

An external controller that owns users should therefore either be the only
writer and re-apply its state after a restart, or write the file itself and use
`config.reload`. A durable state boundary for control-managed state is planned
separately.

## Error codes

| code | meaning |
| --- | --- |
| `invalidRequest` | The line is not a valid request envelope. |
| `unsupportedVersion` | `v` names a version this build does not speak. |
| `unknownOperation` | `op` is not an operation. |
| `invalidArgument` | Arguments are malformed, unknown, or out of range. |
| `notFound` | No user has the handle, or the user does not own the short ID. |
| `conflict` | The identity already exists, or the short ID is owned by a user. |
| `generationConflict` | `expectedGeneration` is not current. |
| `validationFailed` | The resulting configuration fails validation; see `error.path`. |
| `updateFailed` | Compile or publication failed, or a file reload was rejected. |
| `unavailable` | The operation needs something this process lacks, such as a configuration file for `config.reload`, or the server is shutting down. |
| `requestTooLarge` | The request line exceeds 64 KiB; the connection is closed. |
| `busy` | All control connections are in use; the connection is closed. |
| `cursorExpired` | A listing `cursor` belongs to a replaced generation; restart the listing. |
| `internal` | An internal invariant failed; nothing changed. |

## Limits

| limit | value |
| --- | --- |
| request line | 64 KiB |
| request `id` | 128 bytes |
| concurrent connections | 8 |
| requests in flight per connection | 1 |
| requests doing work at once, all connections | 2 |
| listing page | 1000 entries, 256 KiB of entries |
| idle time between requests | 60 s |
| stalled response write | 10 s |
| error message | 4 KiB |
| resulting configuration | 4 MiB, the limit for any configuration file |

Every operation except `system.status` and `generation.get` runs on the
blocking pool, never on a thread that serves proxy traffic, and at most two
run at once across all connections; the rest wait their turn. Handles are
derived once per generation and reused by every read of it.

`system.status` reports the request, connection, work, page, and idle limits
under `limits`.

## Events

| event | level | fields |
| --- | --- | --- |
| `control_started` | info | `socket` |
| `control_change_published` | info | `operation`, `generation` |
| `control_connection_refused` | warn | `reason` (`capacity` or `peerCredentials`), at most once a minute |

Every publication also emits the existing `configuration_published`. No event
carries a UUID, handle, short ID, or argument.
