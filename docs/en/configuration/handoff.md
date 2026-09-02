# Handoff

English | [简体中文](../../zh-CN/configuration/handoff.md)

The same two-machine topology as [line and landing](line-landing.md), with one
difference: the landing cannot read what it forwards.

## What it changes

With NXR, the line node terminates the client's session, then relays plaintext
to the landing. The landing sees everything.

With Handoff, the line node terminates the client's *handshake*, then hands the
whole live TLS session to the landing — sealed. The landing forwards ciphertext
it holds no key for, and the line node drops out of the path entirely.

| | NXR | Handoff |
| --- | --- | --- |
| landing can read the stream | yes | **no** |
| line node after transfer | relays for the connection's life | nothing |
| entry-side memory per connection | a relay | none once transferred |
| landing must be trusted with content | yes | no |

Two consequences follow, and both are worth having:

**The landing is no longer a place traffic can be read.** If the landing is
seized, hosted somewhere you do not fully trust, or shared, it forwards bytes
it cannot interpret.

**The line node stops being a bottleneck.** After the transfer it holds no
buffers and no relay task for that connection, so its memory and CPU do not
scale with how much data flows.

## What it costs

The transfer is a cryptographic operation per connection rather than per byte,
so the cost is at setup, not throughput. The landing must run the same version
family as the line node, because the sealed transfer is an internal wire
contract between them.

## The keys

Handoff needs two independent secrets, and they play different roles:

| value | on the line node | on the landing |
| --- | --- | --- |
| `psk` | `outbounds.<name>.psk` | `landing.psk` — the same value |
| the landing's key pair | `landingPublicKey` — public half | `privateKey` — private half |

Generate them separately:

```shell
rust-reality generate psk       # the shared pre-shared key
rust-reality generate x25519    # the landing's own pair
```

The `psk` authenticates the line node to the landing. The key pair is what
seals the transfer, and only the landing's private half opens it.

Do not reuse the REALITY key pair for the landing. They protect different
things, and the validator refuses the reuse whenever it can see both values in
one file.

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
    "protocol": "handoff",
    "psk": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
    "privateKey": "REREREREREREREREREREREREREREREREREREREREREQ"
  }
}
```

`privateKey` here is the private half. The line node gets the public half, and
if the value in this file also appears in the line node's file, they are
swapped.

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
      "type": "handoff",
      "address": "10.0.0.2",
      "port": 7443,
      "psk": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
      "landingPublicKey": "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM"
    }
  },
  "routing": {
    "default": "landing-1"
  }
}
```

Two optional deadlines are available when the path between the nodes is slow
or unreliable:

| field | default | meaning |
| --- | --- | --- |
| `connectTimeoutMs` | 10000 | dialling the landing |
| `firstByteTimeoutMs` | 15000 | waiting for the landing's first byte |

Leave them alone unless a measured problem says otherwise.

## What must agree

| line node | landing node | must |
| --- | --- | --- |
| `outbounds.landing-1.psk` | `landing.psk` | be equal |
| `outbounds.landing-1.landingPublicKey` | public half of `landing.privateKey` | be a pair |
| `outbounds.landing-1.port` | `listeners[].port` | be equal |

`check` reads one file and cannot verify a key *pair* across two machines. A
mismatched pair produces a transfer the landing cannot open, which is a
connection that fails after authentication rather than a validation error.

## Rotating without dropping traffic

Because both machines are yours, Handoff credentials can be rotated with an
overlap window. The landing accepts its current pair plus a bounded list of
retired ones:

```json
{
  "landing": {
    "protocol": "handoff",
    "psk": "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU",
    "privateKey": "REREREREREREREREREREREREREREREREREREREREREQ",
    "previousPsks": ["IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"],
    "previousPrivateKeys": ["ERERERERERERERERERERERERERERERERERERERERERE"]
  }
}
```

1. **Landing**: new pair active, old pair listed as previous. Reload. It now
   accepts both.
2. **Line node**: switch to the new `psk` and `landingPublicKey`. Reload. It
   now sends only the new one.
3. **Landing**: delete the retired entries. Reload. The window closes.

Step 3 is not optional. A retired key still opens a sealed transfer while it
is listed, so the forward-secrecy property this rotation exists to restore is
not restored until it is gone. The landing logs
`handoff_rotation_window_open` once per generation while the list is
non-empty, so an unfinished rotation stays visible.

Landing keys are hot, so each of those three reloads is a SIGHUP, and no
connection is dropped by any of them.

## Choosing between NXR and Handoff

Use **NXR** when the landing is a machine you control as fully as the line
node, and you would rather have the simpler thing.

Use **Handoff** when any of these is true:

- the landing is hosted somewhere you do not fully trust,
- the line node is small and you do not want its memory scaling with traffic,
- you want the property that a seized landing yields nothing readable.

Both topologies are otherwise identical to operate, and the entry node's
configuration differs by one outbound `type` and one extra key.
