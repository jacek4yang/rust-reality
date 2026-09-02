# How configuration works

English | [简体中文](../../zh-CN/configuration/index.md)

One file, strict JSON, no comments. This page explains the rules that hold
across the whole file, so the topic pages can get straight to their subject.

If you have not written a configuration yet, start with
[getting started](../getting-started.md) and come back.

## The file is the whole interface

There is no configuration directory, no include, no environment variable that
overrides a field, and no command that writes the file for you. The server
reads exactly one file, and what you can read in it is what it will do.

That has a consequence worth stating plainly: **everything the server decides
that is not in the file was derived from this machine.** Nothing is hidden in
a second file or a compiled-in profile. `rust-reality explain` prints the
derived values whenever you want to see them.

## Strict, and what that costs

The parser rejects what it does not understand rather than ignoring it:

- An unknown field is an error, not a warning. A typo cannot silently
  disable a setting.
- An unknown enum value is an error, and the message lists the values that
  exist.
- A duplicate key is an error. JSON permits it, and every parser silently
  keeps one of the two; here it is refused, because the reader of the file
  and the parser must agree.
- A reference to a name that is not declared is an error, and the message
  lists the names that are.

The cost is that JSON has no comments, and this project accepts that cost
rather than adding a second syntax. To annotate a deployment, keep notes
beside the file, or use `label` on a user — the one field that exists purely
for humans.

## Role first

The first field decides the shape of everything after it:

```json
{ "role": "entry" }
```

- **`entry`** — a public node. It terminates VLESS over REALITY with the
  Vision flow, authenticates users, and routes their traffic.
- **`landing`** — a hidden node. It accepts one internal protocol from an
  entry node and dials the destination. It has no users, no REALITY identity,
  and no routing, because it makes none of those decisions.

A field belonging to the other role is rejected by name. There is no
configuration that is both, on purpose: the whole point of splitting them is
to keep a burnable public IP away from a clean egress IP, and one process
holding both defeats it.

## Names, and where they come from

Two shapes appear throughout, and which one is used says something:

**Objects keyed by name**, where the name *is* the identity:

```json
{
  "outbounds": {
    "landing-1": { "type": "nxr", "address": "10.0.0.2", "port": 7443, "psk": "..." }
  }
}
```

There is no `tag` or `name` field inside, because the key is the name. Two
outbounds cannot collide, and a reference to `landing-2` fails immediately
with `landing-1` offered as the alternative.

**Arrays**, where order or multiplicity is real:

```json
{ "routing": { "rules": [] }, "listeners": [], "users": [] }
```

Routing rules are first-match, so their order is a decision you are making.
Listeners and users are lists of things, not one thing named several ways.

## `direct` and `block` always exist

Every configuration can route to two outbounds that are never declared:

- **`direct`** — dial the destination from this machine.
- **`block`** — refuse the connection.

Declaring either is an error. They are not protocols and there is nothing to
configure about them, so a `{"protocol": "blackhole", "tag": "block"}` line in
every file would be pure ceremony. `rust-reality explain` lists them among the
available outbounds so they are never invisible.

## What you write, and what is derived

Every field with a sensible machine-dependent default is optional, and
**omitting it means "derive it"**, not "use a fixed constant".

Writing a value means you are pinning it. That holds even when the value you
write happens to equal what would have been derived — presence is the signal,
not difference. This matters for `runtime.limits`, where `explain` reports
each value as `operator-pinned` or `startup-derived`, and a value you wrote is
reported as pinned regardless of what it says.

The corollary: a decision that must stay visible is a **required** field, not
a defaulted one. `reality.cover`, `reality.privateKey`, `routing.default`,
and each user's `id` and `shortIds` are required for exactly that reason — a
file that does not state them is not a file you should be deploying.

## Secrets live in the file

Private keys and pre-shared keys are written inline. There is no keystore, no
secret reference syntax, and no external provider, because one file keeps
reload, backup, and permissions simple, and a secret indirection layer would
have to be operated too.

So the file is a secret:

```shell
sudo chown root:root /etc/rust-reality/config.json
sudo chmod 0600 /etc/rust-reality/config.json
```

Secrets never appear in logs, in `explain`, or in an error message. A
diagnostic about a malformed key shows `[REDACTED]` and describes the rule it
broke.

## Canonical form

`rust-reality format` rewrites a file in the canonical form: validated,
consistently indented, and with keys in the order the reference documents
them — outbounds before the routing that refers to them, required fields
before optional ones.

```shell
rust-reality format -c config.json          # print it
rust-reality format -c config.json --write  # rewrite in place
```

It is not `jq`. It parses and validates first, so its output is always a file
this binary accepts; `jq .` will happily pretty-print something the server
rejects, and `jq -S` sorts keys alphabetically, which scatters related fields
apart.

It never editorialises. A field you wrote survives even when it equals its
default, and a field you omitted is never expanded into the file. Formatting
is idempotent and preserves meaning exactly.

Every JSON example in this documentation is in canonical form, and CI checks
that by running the real parser and formatter over every one of them.

## Reload: what is hot and what is cold

`SIGHUP` reloads the file. Most of it is hot:

| hot — reload applies it | cold — needs a restart |
| --- | --- |
| `users` | `role` |
| `routing` and `outbounds` | `listeners` |
| `dns` servers | `network` |
| `log` level and destination | `runtime` (profile, tuning, limits, statusFile) |
| `assets` | `dns` (resolver policy) |
| landing keys, including rotation | |

The line is structural rather than a list someone maintains: cold settings are
the ones every pool, ceiling, and socket was sized against before the first
connection was accepted. A reload that changes one is refused with a message
naming it, and the running configuration keeps serving.

Live connections always finish on the generation they started with. A reload
never moves an established session onto a new routing table.

## Where to next

| you want to | page |
| --- | --- |
| build a single-node config field by field | [standalone](standalone.md) |
| add users, rotate keys, know what to share | [users and credentials](users-and-credentials.md) |
| pick or validate a cover target | [cover targets](cover-targets.md) |
| send traffic somewhere other than out | [outbounds](outbounds.md) |
| decide what goes where | [routing](routing.md) |
| hide your egress behind a second machine | [line and landing](line-landing.md) |
| carry only ciphertext to the landing | [handoff](handoff.md) |
| IPv4-only, IPv6-only, custom DNS | [DNS and network](dns-and-network.md) |
| tune a shared or dedicated machine | [runtime and resources](runtime-and-resources.md) |
| look up one field | [reference](reference.md) |
