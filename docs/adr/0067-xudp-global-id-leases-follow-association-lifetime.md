# ADR 0067: XUDP GlobalID leases follow association lifetime

Status: Accepted

## Context

GlobalID registration before fallible socket creation, followed by explicit
normal-path cleanup, leaves active entries on failed creation or cancellation.
An active entry is deliberately exempt from expiry, so a timeout on the entry
alone cannot recover it. Also, one same-user association closing must not make
another live association's GlobalID available to a different user. The
regressions in `tests/xudp_adversarial_lifecycle.rs` cover these distinct cases.

## Decision

Acquisition returns one non-cloneable lease borrowed from the process-wide
GlobalID map. The lease is owned first by the pending open future, then by its
Direct or NXR association. Error returns and cancellation drop it. Explicit
orderly close consumes the same lease; it cannot release ownership twice.
Handoff uses the same Direct association ownership on LANDING.

Each entry counts active leases belonging to its authenticated user. The
existing grace period starts only after the last lease is released. Purge
cannot remove an entry with an active lease, and neither active ownership nor
the grace period permits a different user to acquire that ID. Counter overflow
fails admission before changing the entry. Capacity and grace duration are
unchanged.

The map remains the sole representation of GlobalID ownership. Remove manual
activate/expire pairing rather than preserving it beside the lease API. The
lease introduces no allocation, background cleanup task, or per-datagram map
operation. Borrowed lifetimes prevent the map from disappearing before its
owners; the runtime adapter supplies time for orderly close and drop cleanup.

This implements the cancellation and ownership requirements of
[ADR 0034](0034-qualify-resource-ownership-and-lifetime.md) without changing
XUDP framing, routing authorization, or the stock ingress contract. Explicit
time tests cover grace and concurrent owners; dropping a polled pending future
covers cancellation without a scheduler timing assumption.
