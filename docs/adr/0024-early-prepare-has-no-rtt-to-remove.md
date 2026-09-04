# ADR 0024: Early Prepare has no RTT to remove

Status: Rejected on measurement

Date: 2026-09-04

## Context

A latency program proposed a REALITY-native "Early Prepare" message: after the
client authenticates but before it sends its VLESS request, LINE would tell
LANDING to begin preparing the session, so that LANDING's own work overlaps the
remaining client round trip instead of following it.

The proposal came with a hard constraint, and the constraint is the whole
argument: **TLS ClientFinished remains the irreversible-side-effect
authorization barrier**. LANDING may not connect to a destination, resolve a
name, or take any other externally visible action before the commit that
follows ClientFinished.

That constraint bounds the mechanism before any code is written. If LANDING may
not act until it receives a commit, and LINE may not send that commit until it
has verified ClientFinished, then the earliest possible commit is the message
LINE already sends today — the Handoff continuation transfer. Early Prepare
could therefore only remove a round trip if one of two things were true:

1. the client's VLESS request arrives a full round trip *after* ClientFinished,
   leaving LINE idle in between; or
2. LANDING's post-commit local work is itself large enough to matter.

Neither could be settled by reading the source. Both were measured.

## Evidence

Class: LOCAL_SYNTHETIC. Nothing in this ADR was measured against a live
deployment.

- rust-reality `a8dbc2acd1523a524c0ffff3a69e4ac7e7175fa2` (v1.9.0), release
  profile.
- Xray-core 26.7.28, commit `5ca6f4b`, `go1.26.5 linux/amd64`, unmodified. The
  release archive digest matches the published `.dgst`
  (`8195d909…e5dd2a40`); the extracted binary is `64d46afb…d1affb1d`. That
  differs from the `23d228d7…` recorded elsewhere in these docs because this is
  a `go1.26.5` rebuild of the same upstream commit, not a different Xray.
- Topology: one network namespace joined by a veth pair, `10.204.0.1/30` on the
  host and `10.204.0.2/30` in the namespace, `netem delay 25ms` on each
  direction. Only the client-to-LINE leg is shaped; the REALITY cover and
  origin legs are unshaped. Measured RTT 50.14 ms (`ping`, min).
- The client runs in the namespace, LINE on the host. Capture is on the host
  veth, so inbound timestamps are arrival at LINE and outbound timestamps are
  the moment the packet left after shaping.

The client's last handshake flight, as LINE saw it:

```text
t+0.000 ms   client -> LINE    64 bytes   ChangeCipherSpec (6) + ClientFinished (58)
t+0.628 ms   client -> LINE   420 bytes   first VLESS + Vision application record
```

No LINE-to-client packet of any kind falls between them. The client does not
wait for the server; it writes its request straight after Finished in the same
flight.

The same measurement on unshaped loopback produced a 0.647 ms gap. A separation
that does not grow when the link RTT grows from ~0.05 ms to 50 ms is local write
scheduling inside the client, not a network round trip.

## Decision

Early Prepare is rejected. It is not implemented, and no wire format, parser,
replay state, cryptographic binding or fingerprint surface is added for it.

The reasoning:

- The request already arrives coalesced with ClientFinished, so LINE learns the
  destination at the same instant it is allowed to act on it. Condition 1 is
  false.
- With ClientFinished retained as the barrier, the commit LINE may send is the
  transfer it already sends. Early Prepare cannot move it earlier without
  moving the barrier, which is a different decision with a different threat
  model.
- What remains is LANDING's local authenticate-and-allocate work, which is
  microseconds. Condition 2 is false at any RTT this product operates on.

Buying microseconds with a new public protocol message is the wrong trade. The
cost is not the implementation; it is the permanent compatibility surface, a
new attacker-reachable parser, new replay state, and a new distinguishable
behaviour, all justified by an effect below measurement noise.

## Consequences

- The LINE-to-LANDING critical path stays as
  [ADR 0007](0007-adaptive-line-to-landing-warm-connections.md) leaves it: the
  TCP handshake is prepaid by the warm pool, and the transfer is the commit.
- The latency program redirected to the defect the same measurements exposed:
  the reusable cover-profile path never activated, so every authenticated
  handshake paid a live cover round trip. See
  [ADR 0025](0025-cover-profiles-observe-but-do-not-reproduce-encrypted-extensions.md).
- This ADR does not claim Early Prepare is unsound, only that it is unmotivated
  here and now.

## Revisit conditions

Any one of these makes the measurement above stale and the decision worth
re-opening:

- A client in the compatibility set stops coalescing its first application
  record with ClientFinished, so a real round trip appears between them.
- The barrier moves. If a future design admits a *bounded, replay-safe,
  reversible* pre-Finished action at LANDING, the cost model changes and the
  question is no longer whether an RTT exists but whether that action is safe.
- LANDING's post-commit preparation becomes material — for example a landing
  whose outbound requires work measured in milliseconds rather than
  microseconds. The measurement to repeat is LANDING-local, not network.

## Evidence retention

The topology, the capture procedure and the two timings above are the whole of
the evidence. They reproduce with a veth pair and `netem`; no stored artifact is
required, and no packet capture is committed.
