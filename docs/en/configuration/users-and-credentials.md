# Users and credentials

English | [简体中文](../../zh-CN/configuration/users-and-credentials.md)

Which values to generate, which half goes where, and how to change them
without dropping anybody.

## The four kinds of material

| generate with | goes in | shared with |
| --- | --- | --- |
| `generate x25519` | `reality.privateKey` (private half) | the **public** half goes to every client |
| `generate uuid` | `users[].id` | the client that identity belongs to |
| `generate short-id` | `users[].shortIds` | the same client |
| `generate psk` | an outbound's and a landing's `psk` | the paired node, nothing else |

Everything else in the file is policy. These four are secrets or identities,
and none of them should be typed by hand or reused between deployments.

```shell
rust-reality generate x25519
rust-reality generate uuid 3          # three at once
rust-reality generate short-id 3      # three at once
rust-reality generate psk
```

Add `--json` to any of them when a script is consuming the output:

```shell
rust-reality generate x25519 --json
```

```json
{
  "privateKey": "005oawzDIFyUCdSjXtgGaP7UgGF7zFEzay4kL_nq9ww",
  "publicKey": "UWesja3AOowUwLohp5LcPtmE0gZmBSsn8I6623QczzY"
}
```

There is no command that assembles a configuration, a client profile, or a
subscription link. `generate` emits exactly the value you asked for.

## The X25519 pair, and which half goes where

This is the one that goes wrong. `generate x25519` prints two values:

```
private key (keep secret): bkuHF6dZ2Elt_dkFKZoXkSUZ6gnLITrUZbRmDggVfuQ
public key  (give to peers): CyrxYetA0RSs9IxcGpb7vNfQ3GoKm6xTUL5qWdbjUAY
```

- The **private** half goes in `reality.privateKey`, on the server, in a file
  mode `0600`. It never leaves that machine.
- The **public** half goes in the client's `publicKey` / `pbk` field. It is
  not secret — every client has it — but it must be the matching half.

A client configured with the private key, or a server configured with the
public one, fails at the handshake with nothing useful in the log, because
from the server's point of view the client simply did not authenticate.

**Generate one pair per purpose.** A Handoff landing needs its own pair
(`landing.privateKey`), separate from the REALITY identity. Reusing one pair
for both collapses two independent secrets into one, and the validator
refuses it when it can see both in the same file.

## Short IDs

A short ID is 2 to 16 hexadecimal characters, and the count must be even
because it is a byte string on the wire:

```json
{
  "users": [
    {
      "id": "11111111-1111-4111-8111-111111111111",
      "shortIds": ["0123456789abcdef", "aabb"],
      "label": "alice"
    }
  ]
}
```

A client presents exactly one of them. Listing several lets one identity's
devices carry different short IDs without needing different UUIDs, which is
useful when you want to retire one device's credential later.

Short IDs are not secrets in the way the private key is, but they are
identifiers: they must be unique across the node, and the validator enforces
that.

`rust-reality generate short-id --bytes N` produces a shorter one when you
have a reason to; the default of 8 bytes is 16 hex characters.

## What the client needs

Six values, gathered from three places:

| client field | where it comes from |
| --- | --- |
| address | your server's public IP or hostname |
| port | `listeners[].port` |
| id / UUID | `users[].id` |
| public key / `pbk` | the **public** half — not in the server file |
| short id / `sid` | one entry from that user's `shortIds` |
| server name / SNI | an entry from `reality.serverNames`, or the cover host if it is omitted |
| flow | `xtls-rprx-vision`, always |

The flow is fixed. This server speaks Vision and nothing else, which is why
the configuration has no field for it — there was never a second value to
choose.

Note that the public key is the only value a client needs that is **not** in
the server's configuration file. Record it when you generate the pair; you
cannot recover it from the file later without deriving it.

## Adding a user

Append to `users` and reload:

```shell
rust-reality check -c /etc/rust-reality/config.json
sudo systemctl reload rust-reality
```

Users are hot. Established connections keep running on the generation they
started with; the new identity works on the next connection.

Always `check` before reloading. A reload that fails validation is refused and
the running configuration keeps serving — but you find out from the journal
rather than from your terminal, which is a worse place to find out.

## Removing a user

Delete the entry and reload. Connections that identity already has are **not**
torn down: they finish on the generation that admitted them. If you need them
gone immediately, restart the service.

## Rotating the REALITY key

Changing `reality.privateKey` invalidates every client at once — there is no
overlap window, because a REALITY identity is a single key.

So rotate it deliberately: generate the new pair, update the server file,
distribute the new public key, and reload. Every client must be updated. If
that is too disruptive, the thing you probably want is to rotate *users*
instead, which can be done one at a time.

## Rotating a landing's keys without dropping traffic

Landing credentials *do* have an overlap window, because the two nodes are
under your control and can be updated one at a time.

A Handoff landing accepts its current key pair plus a bounded list of retired
ones:

```json
{
  "landing": {
    "protocol": "handoff",
    "psk": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
    "privateKey": "REREREREREREREREREREREREREREREREREREREREREQ",
    "previousPsks": ["MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM"],
    "previousPrivateKeys": ["ERERERERERERERERERERERERERERERERERERERERERE"]
  }
}
```

The sequence:

1. On the **landing**, make the new pair active and list the old one in
   `previousPsks` / `previousPrivateKeys`. Reload. It now accepts both.
2. On the **entry**, switch the outbound to the new `psk` and
   `landingPublicKey`. Reload. It now sends only the new one.
3. On the **landing**, remove the retired entries. Reload. The window closes.

Do not skip step 3. While the window is open, a retired key still opens a
sealed transfer, so the forward-secrecy property the rotation exists to
restore is not restored until the old key is gone. The server logs
`handoff_rotation_window_open` once per generation for as long as the list is
non-empty, so an unfinished rotation is visible rather than forgotten.

The active key may not also appear in the retired list, and the validator
rejects that — it would mean the rotation had not actually happened.

## Keeping the file safe

The configuration contains private keys, so it is a secret:

```shell
sudo chown root:root /etc/rust-reality/config.json
sudo chmod 0600 /etc/rust-reality/config.json
```

Nothing this binary prints will leak them. Log events never contain key
material, `explain` never prints it, and a diagnostic about a malformed key
shows `[REDACTED]` and describes the rule that was broken:

```
error: invalid value for `reality.privateKey`
 --> config.json:6:19
  |
6 |     "privateKey": "[REDACTED]"
  |                   ^^^^^^^^^^^^ must be URL-safe unpadded base64 decoding to exactly 32 bytes
```

Back the file up somewhere that is also encrypted, and remember that a backup
of a rotated file is a backup of a live secret until you rotate again.
