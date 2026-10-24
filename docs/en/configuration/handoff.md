# Handoff

English | [简体中文](../../zh-CN/configuration/handoff.md)

The same two-machine topology as [line and landing](line-landing.md), with a
different ownership of the live TLS session after the transfer.

## What it changes

With NXR, the line node terminates the client's session, then relays the
authenticated flow as plaintext to the landing. The landing sees everything
and dials the destination. Session keys never leave the line node.

With Handoff, the line node terminates the client's *handshake*, finishes
VLESS decode and routing, then transfers the whole live TLS session to the
landing in one sealed message: current traffic secrets, record sequences, cipher
suite, an owed KeyUpdate response, routing decision, and pending buffers. After a
successful transfer:

- the **landing** reconstructs the TLS 1.3 record layers, holds the session
  keys, dials the destination, and runs the standard Vision relay;
- the **line node** becomes a thin raw relay: it splices client TLS ciphertext
  against the handoff socket in both directions and never touches TLS or Vision
  state for that session again.

| | NXR | Handoff |
| --- | --- | --- |
| landing can read the stream | yes | **yes** (holds transferred session keys) |
| line node after transfer | relays plaintext for the connection's life | thin raw ciphertext splice (no TLS/Vision) |
| LINE↔LANDING hop content | plaintext of the authenticated flow | client TLS ciphertext |
| where session keys live after setup | line node only | **landing** (its memory is part of the secrecy boundary) |
| landing must be trusted with content | yes | yes |

Two consequences follow, and both are worth having:

**Per-byte TLS/Vision work moves to the landing.** After the one-time transfer
the line node's steady state is a splice pump, not AEAD or Vision. That is
edge-compute migration: the public line node sheds crypto CPU when a stronger
private landing is available. Measured evidence lives in
[performance.md](../performance.md#handoff-line-node-offload-measured-single-host).

**The private hop carries ciphertext, not NXR plaintext.** Observers of the
LINE↔LANDING link see TLS record sizes and timing, not payload. That does
*not* mean the landing cannot read the stream — it holds the live session
keys and is inside the session's secrecy boundary. See
[architecture.md](../architecture.md#handoff-session-transfer),
[protocol.md](../protocol.md#handoff-the-internal-session-transfer-hop), and
[threat-model.md](../threat-model.md#handoff-boundary).

## What it costs

The transfer is a cryptographic operation per connection rather than per byte,
so the cost is at setup, not throughput. LINE and LANDING must implement the
same continuation-state contract. A shared release family or unchanged
configuration is not proof of wire compatibility.

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

## Deploying and rolling back the current contract

The current transfer uses `HND1` framing, protocol version **1**, and
continuation-state version **3**. The framing version does not imply acceptance
of older state versions. Version 3 transfers each direction's current traffic
secret and next record sequence, plus any pending KeyUpdate response, and adds
an explicit session kind (TCP Vision or XUDP), an inbound tag, and a sealed
Handoff policy snapshot so LANDING can authorize UDP destinations without
LINE-side UDP ownership. LANDING can then answer KeyUpdate requests and derive
later traffic generations.

Older sealed blobs are rejected by this build, not converted:

- Version 1 contained only derived keys and IVs and cannot retain KeyUpdate
  state.
- Version 2 transferred KeyUpdate-capable TCP secrets without session kind or
  policy snapshot; this build does not silently reinterpret it as XUDP.

There is one current parser, with no negotiation, downgrade, or conversion.
A LINE and LANDING with mismatched continuation-state versions reject the
transfer. The receiving side rejects a mismatched header before reading the
body or connecting the destination. It closes without response bytes, so the
affected client connection fails. Retired PSKs or private keys permit
credential rotation only, not mixed state versions.

For a contract-changing upgrade:

1. Validate both configurations with `rust-reality check --config config.json`.
   This checks each file, not the remote binary contract.
2. Stop admitting new sessions to the affected LINE/LANDING pairs. Drain their
   active sessions and retire their unused warm TCP connections before replacing
   either process. A forced shutdown terminates remaining sessions.
3. Deploy both ends with the same current contract before reopening admission.
   In a multi-node topology, every selectable LINE→LANDING pair must agree.
   Separate cohorts are safe only when routing cannot cross their contracts.
4. Qualify the exact binaries together, including requested and later KeyUpdate,
   before returning the cohort to service.

Rollback crosses the same drain boundary. Stop new version-3 sessions and drain
or terminate them, then restore a matching earlier binary pair before reopening
admission. An earlier binary cannot import version-3 state or take over a live
LANDING-owned session. Existing sessions continue only while their original
owners remain running. Do not roll back one reachable endpoint independently.

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

Use **NXR** when any of these is true:

- the landing is a machine you control as fully as the line node, and you
  would rather have the simpler hop;
- session keys must never leave the line node (NXR transfers no key material;
  the private hop then carries plaintext after its one-time authentication).

Use **Handoff** when any of these is true:

- the public line node is CPU-constrained and a stronger private landing can
  absorb per-byte TLS/Vision work;
- you want the LINE↔LANDING hop to carry client TLS ciphertext rather than
  NXR plaintext.

Do **not** choose Handoff because you distrust the landing's ability to read
content. After a successful transfer the landing holds the live session keys
and can read the stream; a seized landing is inside the secrecy boundary.
Both topologies still require a firewall-restricted landing listener and a
landing you trust with the destinations it dials.

Both topologies are otherwise identical to operate, and the entry node's
configuration differs by one outbound `type` and one extra key.
