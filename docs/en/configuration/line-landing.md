# Line and landing nodes

English | [简体中文](../../zh-CN/configuration/line-landing.md)

Two machines instead of one, so that the IP your clients connect to is not the
IP your traffic comes out of.

## Why split them

A single node's public IP does two jobs at once. Clients connect to it, and
destinations see it. That means anything that burns the first — a scanner, a
block list, an enumeration of your port 443 — also burns the second, and
anything that identifies the second identifies the first.

Splitting them separates the risks:

```
client ──REALITY──▶ LINE node ──NXR──▶ LANDING node ──▶ destination
                    public IP           clean IP
                    expendable          hidden, firewalled
```

The **line node** faces the public internet. It is exposed by design, and if
it is burned you replace it: it holds no unique egress reputation.

The **landing node** is reachable only from the line node. It has no public
listener, no REALITY identity, and no users. Its IP is what destinations see,
and it stays clean because nothing on the public internet can reach it.

This is why a single process cannot be both. Co-hosting the two roles puts the
burnable IP and the clean IP on the same machine, which is the exact thing the
topology exists to prevent.

## NXR, in one paragraph

NXR is the internal protocol between the two. The line node authenticates to
the landing with a pre-shared key, sends the destination, and relays the
stream. The landing checks the key, refuses replays, dials the destination,
and forwards. It is not designed to survive a hostile network — it is designed
for a hop between two machines you control, so it is cheap.

If the landing must not be able to read what it forwards, use
[Handoff](handoff.md) instead.

## Before you start

- Two machines. The landing needs no public IP, and is better off without one.
- A private path between them — a private network, a VPC, a WireGuard tunnel,
  or a firewall rule that admits only the line node's address.
- One pre-shared key, generated once and used in both files:

```shell
rust-reality generate psk
```

## The landing node

```json
{
  "role": "landing",
  "listeners": [
    {
      "port": 7443,
      "ip": "ipv4Only",
      "ipv4": "10.0.0.2"
    }
  ],
  "landing": {
    "protocol": "nxr",
    "psk": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"
  }
}
```

That is the entire file. A landing has no `reality`, no `users`, and no
`routing`, because it makes none of those decisions — it forwards what the
line node authenticated. Stating any of them is an error naming the field.

Note the explicit `ipv4` bind. A landing should listen on its private address,
not the wildcard, so a misconfigured firewall cannot expose it.

Traffic leaves a landing via `direct` unless you point `egress` at a declared
outbound; see [multiple landings](multi-landing.md) for when that is useful.

## The line node

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
    "default": "landing-1",
    "rules": [
      {
        "name": "block-private",
        "ip": [
          "geoip:private"
        ],
        "outbound": "block"
      }
    ]
  }
}
```

It is a standalone entry node with one addition: an `nxr` outbound naming the
landing, and `routing.default` pointing at it instead of `direct`.

The `block-private` rule matters more here than on a standalone node. Without
it, a client can ask the line node for `10.0.0.2` and reach your landing's
management interface through your own proxy. Block private address space on
any node that has a private network worth reaching.

## The three values that must agree

`check` reads one file, so it cannot verify any of these. Confirm them
yourself:

| line node | landing node | must |
| --- | --- | --- |
| `outbounds.landing-1.port` | `listeners[].port` | be equal |
| `outbounds.landing-1.psk` | `landing.psk` | be equal |
| `outbounds.landing-1.address` | the landing's bound address | be reachable |

A mismatch is not a configuration error — both files are individually valid.
It is a deployment error, and it shows up as connections failing at the first
transfer.

## Bring it up

Landing first, so the line node has something to reach:

```shell
# on the landing
rust-reality check -c /etc/rust-reality/config.json
rust-reality run -c /etc/rust-reality/config.json

# on the line node
rust-reality check -c /etc/rust-reality/config.json
rust-reality doctor -c /etc/rust-reality/config.json
rust-reality run -c /etc/rust-reality/config.json
```

Confirm the route before pointing a client at it:

```shell
rust-reality explain -c /etc/rust-reality/config.json --route example.com
```

```
example.com for alice -> landing-1 (routing, default outbound)
```

## Firewall the landing

The landing's protection is that nothing else can reach it. Make that true:

```shell
# on the landing — allow only the line node
sudo iptables -A INPUT -p tcp --dport 7443 -s <line-node-private-ip> -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 7443 -j DROP
```

A landing reachable from the internet is a landing whose IP can be discovered,
which is the whole thing you were avoiding.

## What each node can see

Worth being precise about, because it decides which machine you can afford to
lose:

| | line node | landing node |
| --- | --- | --- |
| client identities | yes | no |
| destination hostnames | yes | yes |
| plaintext stream | yes | yes |
| your egress IP | no | it *is* the egress |

The landing sees traffic in the clear. It is a machine you control and trust;
NXR is not protecting the traffic from the landing, it is protecting your
egress IP from the public internet. When you need the landing itself to be
unable to read the stream, that is [Handoff](handoff.md).

## Next

- [Handoff](handoff.md) — the same topology, but the hop carries only
  ciphertext.
- [Multiple landings](multi-landing.md) — several exits, chosen per user.
- [Routing](routing.md) — sending only some traffic through the landing.
