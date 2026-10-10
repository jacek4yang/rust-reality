# ADR 0047: Restart ordering uses census command time

Status: Accepted

## Context

Frozen run `38023074176` on `796f557` fail-closed both handoff cells with
Class B `landing abort ACK predates LINE-A census` while nxr cells PASS and
CI/Security/Candidate/Native PASS. Retained receipts show a correct ACK-driven
handshake (ADR 0041):

| Event | unix_ms (handoff/ordinary) |
|---|---|
| LINE-A `ss` census completed | 6524 |
| LANDING ACK receive completed | 6527 |
| LINE-A ACK send / action completed | 6565 |

LANDING abort is authorized only after accepting the census ACK. LINE-A's
action `completed_unix_ms` includes waiting for LANDING's accept reply, so it
always post-dates the ACK. Offline evaluation compared ACK completion to that
action timestamp and falsely rejected every well-ordered handoff restart.

## Decision

1. `restart_ingress` returns `(peer, census_completed_unix_ms)` where the time
   is the `ss` command completion, not the LINE-A action completion.
2. `product_logs` requires `ack_completed >= census_completed` using that census
   command time (ADR 0041 semantics unchanged).
3. No sleep, hold, or wall-clock amplification. Runtime handshake unchanged.

## Consequences

Harness Class B from this false barrier is removed without loosening product
checks: empty census, peer mismatch, ACK-before-census on the wire, and
missing ACK still fail closed. Historical INVALID evidence stays immutable.
