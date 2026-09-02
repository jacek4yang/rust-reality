# Building a standalone node

English | [简体中文](../../zh-CN/configuration/standalone.md)

One machine that accepts clients and dials destinations itself. It is the
simplest deployment and the right place to learn the file, because every
other topology is this plus something.

This page builds the configuration one decision at a time. If you only want a
working node quickly, [getting started](../getting-started.md) is the short
path; this one explains why each field is there.

> Every key, UUID, and short ID on this page is a placeholder. They are
> structurally valid so the examples can be machine-checked, which means
> `check` accepts them. Replace them with `rust-reality generate` output.

## The smallest file that runs

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
  "routing": {
    "default": "direct"
  }
}
```

That is the complete list of things this project will not decide for you.
Everything else — thread counts, connection ceilings, buffer sizes, timeouts,
DNS caching, relay strategy — is derived from the machine at startup.

Check it, and see what was derived:

```shell
rust-reality check -c config.json
rust-reality explain -c config.json
```

## `role`

```json
{ "role": "entry" }
```

`entry` is a public node: it terminates VLESS over REALITY with the Vision
flow, authenticates users, and decides where their traffic goes. It must come
first in your thinking because it decides which other fields are legal —
a `landing` node has no `users`, no `reality`, and no `routing`, and stating
one is an error rather than a field quietly ignored.

## `listeners`

```json
{ "listeners": [{ "port": 443 }] }
```

A bare `port` means "bind this port on every address family that works". On a
dual-stack host that is two sockets, `0.0.0.0:443` and `[::]:443`; on an
IPv4-only host it is one, and the node still starts. That last part is the
reason `auto` is the default: a node that refuses to start because the host
has no IPv6 is failing for no reason.

To pin the behaviour instead:

| `ip` | binds |
| --- | --- |
| `auto` (default) | both families, starts if at least one works |
| `dualStack` | both families, **both must succeed** |
| `ipv4Only` | IPv4 only |
| `ipv6Only` | IPv6 only |

To bind a specific address rather than the wildcard, name it:

```json
{ "listeners": [{ "port": 443, "ip": "ipv4Only", "ipv4": "203.0.113.10" }] }
```

Several listeners share one REALITY identity and one user list. That is
useful when a second port is reachable where 443 is not — the node is the
same node on both.

Listeners are cold: changing them needs a restart, because the sockets are
bound before anything else exists.

## `reality`

```json
{
  "reality": {
    "cover": "www.microsoft.com:443",
    "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE"
  }
}
```

**`cover`** is the real TLS 1.3 host this node impersonates, with its port.
An unauthenticated connection is proxied to it, which is what makes probing
the node look like probing that host. Choosing it well is its own decision:
see [cover targets](cover-targets.md).

**`privateKey`** is the private half of an X25519 pair from
`rust-reality generate x25519`. Its public half goes in every client. If your
server file contains the value the client also has, they are swapped.

**`serverNames`** is optional and defaults to the cover's own hostname, which
is almost always what you want. Set it only to accept a name that differs from
the cover host, and note that an authenticated client's SNI must match an
entry here — a mismatch is the second most common first-deployment failure.

A cover named by IP address has no hostname to default to, so `serverNames`
becomes required there.

## `users`

```json
{
  "users": [
    {
      "id": "11111111-1111-4111-8111-111111111111",
      "shortIds": ["0123456789abcdef"],
      "label": "alice"
    }
  ]
}
```

**`id`** is the UUID the client presents. **`shortIds`** are the REALITY short
IDs that identity may use: 2 to 16 hexadecimal characters, an even number of
them. Give a user more than one when you want to hand different devices
different short IDs without giving them different UUIDs.

**`label`** is for you. It appears in `explain` and in reports, and has no
effect on the protocol — it exists so that a routing summary can say
`alice` instead of a UUID.

Identities and short IDs must be unique across the whole node.

Users are hot: adding, removing, or re-keying one takes effect on SIGHUP,
and connections already established keep running.

## `routing`

```json
{ "routing": { "default": "direct" } }
```

`default` is required. It is where traffic goes when nothing else matched, and
making it required means no file can be ambiguous about its own fallback.

`direct` dials the destination from this machine. `block` refuses. Both always
exist and are never declared.

That is the whole routing configuration for a standalone node. When you want
some destinations treated differently, [routing](routing.md) covers rules,
matchers, and per-user policies.

## A fuller example

Two listeners, two users, a rule that refuses private address space, and
explicit logging:

```json
{
  "role": "entry",
  "listeners": [
    {
      "port": 443,
      "ip": "ipv4Only",
      "ipv4": "203.0.113.10"
    },
    {
      "port": 8443
    }
  ],
  "reality": {
    "cover": "www.microsoft.com:443",
    "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE",
    "serverNames": [
      "www.microsoft.com"
    ]
  },
  "users": [
    {
      "id": "11111111-1111-4111-8111-111111111111",
      "shortIds": [
        "0123456789abcdef",
        "aabb"
      ],
      "label": "alice"
    },
    {
      "id": "22222222-2222-4222-8222-222222222222",
      "shortIds": [
        "fedcba9876543210"
      ],
      "label": "bob"
    }
  ],
  "routing": {
    "default": "direct",
    "rules": [
      {
        "name": "block-private",
        "ip": [
          "geoip:private"
        ],
        "outbound": "block"
      }
    ]
  },
  "log": {
    "level": "info",
    "output": "stderr"
  }
}
```

`geoip:private` needs no downloaded data — it is built in. Rules that name
other `geoip:` or `geosite:` labels need geo files; see
[routing](routing.md#geo-data).

## What you did not have to write

Run `explain` against the file above and every remaining decision is listed:

```
posture: profile auto -> standard, tuning startup, objective balanced
runtime: 4 worker threads, 512 blocking threads (tokio-default)
limits: 25 values, all derived from the machine (--json for the table)
```

Twenty-five admission ceilings, buffer sizes, and pool bounds, all derived
from the CPU count, memory, and descriptor limit this machine actually has.
You can pin any of them, and on most machines you should not — see
[runtime and resources](runtime-and-resources.md) for the cases where it is
justified and how to tell.

## Next

- [Users and credentials](users-and-credentials.md) — what to generate, what
  to share, and how to rotate it.
- [Cover targets](cover-targets.md) — choosing one that holds up.
- [Routing](routing.md) — when `direct` stops being enough.
- [Deployment](../operations/deployment.md) — systemd, permissions, firewall.
