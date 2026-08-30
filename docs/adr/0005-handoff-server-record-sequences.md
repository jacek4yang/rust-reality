# ADR 0005: Restore Handoff at server record sequence 0 or 1

- Status: accepted for v1.5
- Date: 2026-08-12

## Context

Handoff transfers an established REALITY connection from a LINE to a LANDING.
Its continuation state contains the TLS 1.3 application traffic keys, IVs, and
record sequences, so accepting an invalid sequence could reuse an AEAD nonce.

Before v1.5, LINE always transferred before any server application record and
LANDING therefore accepted only server sequence 0. The v1.5 cover-flight model
can emit one empty cover-shaped ApplicationData fake NST after Finished. That
record correctly consumes server sequence 0 even though no Vision response has
been sent. Such a session must transfer with server sequence 1.

Changing the `HND1` framing or continuation-state version would make all mixed
deployments incompatible despite the state encoding itself remaining adequate.

## Decision

Keep `HND1`, protocol version 1, continuation-state version 1, and the existing
wire encoding. A v1.5 LANDING accepts server application sequence 0 or 1 and
restores the record layer at exactly that value. It rejects sequence 2 or
greater before restoration. The client sequence remains governed by its own
transferred state.

The two accepted values have narrow meanings:

- sequence 0: no server application record was emitted before transfer;
- sequence 1: exactly one empty fake NST shape record was emitted at sequence 0.

No generic “future sequence” range is accepted. A later protocol change that
legitimately transfers at sequence 2 or greater must define and validate that
boundary explicitly instead of weakening this gate.

## Consequences

A v1.4 LINE remains compatible with a v1.5 LANDING. A v1.5 LINE is compatible
with a v1.4 LANDING only for sequence-0 sessions; a sequence-1 transfer fails
closed at the old landing. Therefore rolling upgrade order is LANDING first,
then LINE.

Rollback order is LINE first. After all LINE nodes can no longer create new
sequence-1 transfers, stop admitting Handoff sessions, drain active sessions,
and only then downgrade LANDING. A LANDING must never be restarted or
downgraded underneath transferred sessions.

The sequence bound, exact restoration tests, and a resumed sequence-1 record
test protect nonce uniqueness and byte continuity. This decision adds no
runtime switch and no new wire field.
