# Routing

English | [简体中文](../../zh-CN/configuration/routing.md)

Deciding where each connection goes. A default is required; rules and
per-user policies are optional and most nodes need neither.

## The default

```json
{ "routing": { "default": "direct" } }
```

`default` is required so that no configuration can be ambiguous about its own
fallback. Everything else on this page narrows it.

## Rules

`routing.rules` applies to every user. It is an array because order matters:
**first match wins**, and evaluation stops there.

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
    "default": "direct",
    "strategy": "resolveIfNoMatch",
    "rules": [
      {
        "name": "block-private",
        "ip": [
          "geoip:private"
        ],
        "outbound": "block"
      },
      {
        "name": "block-ads",
        "domain": [
          "geosite:category-ads-all"
        ],
        "outbound": "block"
      },
      {
        "name": "no-smtp",
        "port": [
          "25",
          "465",
          "587"
        ],
        "outbound": "block"
      }
    ]
  }
}
```

A rule has a name, at least one condition, and an outbound. The `name` is
optional but worth writing — it is what `explain --route` reports when the
rule fires, and "the third rule" is a poor thing to read at three in the
morning.

A rule with no condition is refused. An empty condition list would match
everything, which is what `default` is for, and a rule that silently swallows
all traffic because a field was left empty is exactly the failure this
project refuses to have.

## Conditions

A rule may carry any combination of three:

| condition | matches |
| --- | --- |
| `domain` | the destination hostname |
| `ip` | the destination address |
| `port` | the destination port |

Within one condition, entries are alternatives — any entry matching is enough.
Across conditions they are requirements: a rule with both `domain` and `port`
needs both to match.

### Domain matchers

| form | matches |
| --- | --- |
| `example.com` | that exact name |
| `full:example.com` | that exact name, stated explicitly |
| `domain:example.com` | that name and any subdomain of it |
| `keyword:example` | any name containing the substring |
| `regexp:^ad[0-9]+\\.` | any name the expression matches |
| `geosite:cn` | any name in that geo list |
| `ext:file.dat:tag` | a tag from an external data file |

Prefer `domain:` over `keyword:`. `keyword:ads` also matches
`downloads.example.com`.

### IP matchers

A plain address, a CIDR block, or a `geoip:` label:

```json
{ "ip": ["10.0.0.0/8", "192.168.0.0/16", "203.0.113.7", "geoip:private"] }
```

`geoip:private` is built in and needs no downloaded data. Every other
`geoip:` label needs a geo file.

### Port matchers

A single port, or a range:

```json
{ "port": ["25", "465", "587", "6000-6010"] }
```

## `strategy`

```json
{ "routing": { "default": "direct", "strategy": "resolveIfNoMatch" } }
```

An `ip` condition needs an address, and a destination often arrives as a name.
The strategy decides when to resolve it:

| value | behaviour |
| --- | --- |
| `resolveIfNoMatch` (default) | try the domain rules first; resolve only if none matched and an `ip` rule exists |
| `asIs` | never resolve for routing; `ip` rules only match a destination that was already an address |
| `resolveOnDemand` | resolve whenever an `ip` rule could apply |

The default is a deliberate compromise: a rule set that decides everything by
domain never pays for a lookup, and one that needs an address gets one.

Use `asIs` when DNS is slow or untrusted and you accept that `ip` rules will
not see domain destinations. Use `resolveOnDemand` when an `ip` rule is a
security boundary that must apply even to a name — a `block` rule for private
address space, for instance, where `resolveIfNoMatch` would let a hostname
resolving into your LAN slip past a domain rule that matched first.

## Per-user policies

When users need different treatment, give a user a policy:

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
      ],
      "label": "alice"
    },
    {
      "id": "22222222-2222-4222-8222-222222222222",
      "shortIds": [
        "fedcba9876543210"
      ],
      "label": "bob",
      "policy": "split"
    }
  ],
  "outbounds": {
    "landing-1": {
      "type": "nxr",
      "address": "10.0.0.2",
      "port": 7443,
      "psk": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"
    }
  },
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
    ],
    "policies": {
      "split": {
        "default": "landing-1",
        "rules": [
          {
            "name": "home-direct",
            "domain": [
              "geosite:cn"
            ],
            "outbound": "direct"
          }
        ]
      }
    }
  }
}
```

A policy is a `default` plus optional `rules`, and a user opts into one by
name. A user with no `policy` follows the global default.

Evaluation order for one connection:

1. `routing.rules` — the global rules, in order. First match wins.
2. If none matched and the user has a policy, that policy's `rules`, in order.
3. Otherwise the policy's `default`, or `routing.default` if the user has no
   policy.

Global rules run first and are therefore not overridable by a policy. That is
what makes them the right place for a rule that must hold for everyone —
blocking private address space, for example.

Policies are name-keyed, so a user naming one that does not exist is refused
with the available names listed.

## Checking a decision

Reading a rule list to work out where one destination goes is error-prone.
Ask instead:

```shell
rust-reality explain -c config.json --route example.com
```

```
example.com for alice -> direct (routing, default outbound)
```

The answer names the outbound, the list that decided, and how. `global rule`
means `routing.rules`; `policy rule` means a rule inside the user's policy;
`default outbound` means nothing matched and the named list's `default`
applied.

It accepts `host` or `host:port`, including bracketed and bare IPv6 literals,
and defaults to port 443.

It is offline, like the rest of `explain`, and that bounds what it can say. A
`geoip:` or `geosite:` condition is evaluated against no data, so it never
matches, and the answer says so rather than reporting a route the running
server would not choose:

```
note: geo conditions were not evaluated: `explain` is offline, so a rule
naming geoip: or geosite: was treated as not matching. Use `doctor` to load
the data.
```

## Geo data

Rules naming `geoip:` or `geosite:` labels other than `geoip:private` need
data files. Point at them and they are downloaded and cached:

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
    "default": "direct",
    "rules": [
      {
        "name": "cn-direct",
        "domain": [
          "geosite:cn"
        ],
        "outbound": "direct"
      }
    ]
  },
  "assets": {
    "geoip": "https://example.com/geoip.dat",
    "geosite": "https://example.com/geosite.dat",
    "cacheDirectory": "/var/lib/rust-reality/assets",
    "reloadIntervalSeconds": 86400
  }
}
```

| field | meaning |
| --- | --- |
| `geoip` | HTTPS URL of the GeoIP data file |
| `geosite` | HTTPS URL of the GeoSite data file |
| `cacheDirectory` | where snapshots are kept |
| `reloadIntervalSeconds` | how often to re-fetch |

Sources must be `https://`, and a URL carrying embedded credentials is
refused. A failed refresh keeps the last good snapshot serving; it does not
take the node down.

`check` never fetches them — it is offline. `doctor` does, which makes it the
command that tells you whether the labels your rules name actually exist in
the data you are pointing at.

## Reload

`routing` is hot. Rules, policies, the default, and the strategy all apply on
SIGHUP. Connections already established keep the table they started with, so
a reload cannot re-route a live session.
