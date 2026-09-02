# Multiple landings

English | [简体中文](../../zh-CN/configuration/multi-landing.md)

One line node, several exits, chosen per user or per destination.

## When this is worth it

Three reasons, in roughly the order they come up:

- **Different exit locations.** Users who need a European exit and users who
  need an American one, from one entry point.
- **Blast radius.** One landing burned takes its users with it, not everyone.
- **Capacity.** Two landings share what one would carry alone.

If none of those applies, one landing is simpler and simpler is better.

## The shape

```
                        ┌─▶ landing-eu ──▶ destination
client ──▶ LINE node ───┤
                        └─▶ landing-us ──▶ destination
```

Each landing is an ordinary landing node — the file from
[line and landing](line-landing.md), unchanged. The work is all on the line
node, and it is routing.

## Assigning users to landings

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
      "label": "alice",
      "policy": "via-eu"
    },
    {
      "id": "22222222-2222-4222-8222-222222222222",
      "shortIds": [
        "fedcba9876543210"
      ],
      "label": "bob",
      "policy": "via-us"
    }
  ],
  "outbounds": {
    "landing-eu": {
      "type": "nxr",
      "address": "10.0.0.2",
      "port": 7443,
      "psk": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"
    },
    "landing-us": {
      "type": "nxr",
      "address": "10.0.0.3",
      "port": 7443,
      "psk": "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU"
    }
  },
  "routing": {
    "default": "landing-eu",
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
      "via-eu": {
        "default": "landing-eu"
      },
      "via-us": {
        "default": "landing-us",
        "rules": [
          {
            "name": "eu-sites-stay-eu",
            "domain": [
              "geosite:category-eu"
            ],
            "outbound": "landing-eu"
          }
        ]
      }
    }
  }
}
```

Each landing is one outbound. Each policy names its default landing. Each user
names its policy. A user with no `policy` follows `routing.default`.

`via-us` also carries a rule: users on the US exit still reach European sites
through the European landing. That is the general shape — a policy is a
default plus whatever exceptions that group needs.

Check the assignment rather than reading it back:

```shell
rust-reality explain -c config.json
```

```
routing:
  default: landing-eu (1 rule, strategy resolveIfNoMatch)
  policy via-eu: default landing-eu (0 rules, 1 user)
  policy via-us: default landing-us (1 rule, 1 user)
  outbounds: direct, block, landing-eu, landing-us
```

The user counts are the useful part. A policy with zero users is either a
mistake or a leftover.

## Every landing needs its own keys

Each landing gets its own pre-shared key, and for Handoff, its own key pair:

```shell
rust-reality generate psk    # once per landing
```

Sharing one key across landings means a key recovered from one opens all of
them. The validator refuses two outbounds carrying identical key material in
the same file, so this particular mistake is caught — but only because both
values happen to be visible in one place.

## Mixing NXR and Handoff

Nothing requires the landings to use the same protocol. A trusted landing on
NXR and a less-trusted one on Handoff is a legitimate configuration, and the
line node's file simply carries two outbounds with different `type` values.

## Failure is per-connection

There is no health checking, no failover, and no load balancing between
landings. A connection routed to a landing that is down fails, and the next
connection tries again.

That is deliberate. Automatic failover would silently move a user's traffic to
a different exit IP, which is exactly the property they chose a specific
landing to control. If a landing is down, the operator decides — by editing
the policy default and reloading, which takes effect immediately and affects
no established connection.

```json
{ "routing": { "policies": { "via-us": { "default": "landing-eu" } } } }
```

## Adding one

1. Bring up the new landing node and firewall it to the line node.
2. Generate its key material.
3. Add the outbound and a policy to the line node.
4. `check`, then reload.
5. Move users to the new policy as you want them moved.

Steps 3 to 5 are all hot. No restart, and no established connection is
affected.

## Removing one

Point its policy's default elsewhere, reload, and wait for existing
connections to finish — they keep running on the generation that admitted
them. Then remove the outbound and the policy, reload again, and shut the
landing down.

Removing the outbound while connections still use it does not break them, but
it does mean a reload cannot be undone by re-adding it: the connections are
already on their own generation either way.
