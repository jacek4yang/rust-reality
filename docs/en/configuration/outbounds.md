# Outbounds

English | [简体中文](../../zh-CN/configuration/outbounds.md)

An outbound is a way of leaving this node. Two exist without being declared,
and three can be declared.

## The two you never declare

| name | what it does |
| --- | --- |
| `direct` | dial the destination from this machine |
| `block` | refuse the connection |

They are always available and declaring either is an error. They are not
protocols and have nothing to configure, so a line for each in every file
would be pure ceremony. `rust-reality explain` lists them so they are never
invisible:

```
outbounds: direct, block, landing-1
```

A standalone node needs nothing else — `{"routing": {"default": "direct"}}` is
a complete routing configuration.

## Declaring one

`outbounds` is an object keyed by name. The key *is* the name, so there is no
`tag` field and two outbounds cannot collide:

```json
{
  "role": "entry",
  "listeners": [
    {
      "port": 443
    }
  ],
  "reality": {
    "cover": "www.microsoft.com:443",
    "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE"
  },
  "users": [
    {
      "id": "11111111-1111-4111-8111-111111111111",
      "shortIds": [
        "0123456789abcdef"
      ]
    }
  ],
  "outbounds": {
    "upstream": {
      "type": "socks5",
      "address": "127.0.0.1",
      "port": 1080
    }
  },
  "routing": {
    "default": "upstream"
  }
}
```

Every outbound has a `type`. `type` rather than `protocol` because `direct`
and `block` are not protocols, and one word for the discriminator across the
whole file is worth more than a familiar one for three of five cases.

## `socks5`

Forward to a SOCKS5 server — a local privacy tool, a corporate egress, or
another proxy:

| field | required | meaning |
| --- | --- | --- |
| `address` | yes | SOCKS5 server host |
| `port` | yes | SOCKS5 server port |
| `username` | no | required if and only if `password` is set |
| `password` | no | required if and only if `username` is set |
| `warmTcp` | no | pre-establish connections; defaults to on |

Credentials come as a pair. Setting one without the other is an error rather
than a half-configured authentication that fails at the first connection.

## `nxr` and `handoff`

Both send traffic to a **landing node** — a second machine whose IP does the
actual dialling, so your public entry IP never appears as the source to any
destination. They differ in what crosses the hop between them:

| | `nxr` | `handoff` |
| --- | --- | --- |
| what crosses the hop | the destination and the plaintext stream, re-authenticated | the client's TLS session, still sealed |
| the landing can read the traffic | yes | no |
| entry-side state after transfer | relays for the connection's life | none — the session is handed over |

Choose `nxr` when the landing is yours and simplicity matters. Choose
`handoff` when the landing should not be able to read what it forwards.
[Line and landing nodes](line-landing.md) and [Handoff](handoff.md) cover each
in full; this page covers the fields.

```json
{
  "role": "entry",
  "listeners": [
    {
      "port": 443
    }
  ],
  "reality": {
    "cover": "www.microsoft.com:443",
    "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE"
  },
  "users": [
    {
      "id": "11111111-1111-4111-8111-111111111111",
      "shortIds": [
        "0123456789abcdef"
      ]
    }
  ],
  "outbounds": {
    "landing-handoff": {
      "type": "handoff",
      "address": "10.0.0.3",
      "port": 7443,
      "psk": "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU",
      "landingPublicKey": "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM"
    },
    "landing-nxr": {
      "type": "nxr",
      "address": "10.0.0.2",
      "port": 7443,
      "psk": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"
    },
    "upstream": {
      "type": "socks5",
      "address": "127.0.0.1",
      "port": 1080,
      "username": "proxyuser",
      "password": "proxypass",
      "warmTcp": false
    }
  },
  "routing": {
    "default": "landing-nxr"
  }
}
```

**`nxr`**

| field | required | meaning |
| --- | --- | --- |
| `address` | yes | landing node address |
| `port` | yes | the port the landing listens on |
| `psk` | yes | 32-byte pre-shared key, matching the landing's |
| `warmTcp` | no | pre-establish connections; defaults to on |

**`handoff`** takes the same fields plus:

| field | required | meaning |
| --- | --- | --- |
| `landingPublicKey` | yes | the **public** half of the landing's key pair |
| `connectTimeoutMs` | no | dial deadline for the landing; default 10000 |
| `firstByteTimeoutMs` | no | deadline for the landing's first byte; default 15000 |

The entry node holds the landing's *public* key. The landing holds the
private half. Nothing in an entry node's file should be a landing's private
key, and a value appearing in both files that is not the shared `psk` is a
mistake.

## Warm connections

`warmTcp` defaults to on, which means the node keeps a small pool of
established TCP connections to that outbound ready before anyone asks. It
removes a round trip from the start of a session that uses it.

The pool's size is derived from the machine — how many to keep ready, how
many may be connecting at once, how fast to grow and shrink — and there is
no field for any of it. Turn the whole thing off for an outbound where a
persistent connection is unwelcome:

```json
{ "outbounds": { "upstream": { "type": "socks5", "address": "127.0.0.1", "port": 1080, "warmTcp": false } } }
```

Reasons to: a metered upstream, a SOCKS5 server that logs connections, or a
peer that closes idle sockets aggressively enough that the pool churns.

## Names, and what refers to them

An outbound is used by name, from three places:

- `routing.default`
- a rule's `outbound`
- a policy's `default`, or a rule inside a policy

A reference to a name that is not declared is refused, and the message lists
what is available:

```
error: invalid value for `routing.default`
 --> config.json:24:16
  |
24 |     "default": "landing-2"
  |                ^^^^^^^^^^^ unknown outbound; declared: landing-1; built in: direct, block
```

Declaring an outbound nothing refers to is allowed. It costs a warm pool if
`warmTcp` is on, so remove ones you no longer route to.

## Reload

`outbounds` is hot. Adding, removing, or re-keying one applies on SIGHUP, and
connections already established keep using the table they started with — a
reload never moves a live session onto a new outbound.

Removing an outbound that a live connection is using does not tear that
connection down. It finishes on its own generation.
