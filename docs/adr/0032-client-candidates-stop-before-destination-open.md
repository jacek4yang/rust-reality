# ADR 0032: Client candidates stop before destination open

## Status

Accepted for incremental client integration.

## Context

A general-purpose multi-LINE client cannot interpret a VLESS response as an
application delivery acknowledgement. Its Addons length is not an error code,
and its bytes do not prove destination reachability. Racing complete requests
can open multiple destinations or duplicate application side effects.

## Decision

One logical connection owns one `rr-session::ClientRace`. There are exactly two
non-reusable candidate slots and one non-cloneable adoption grant. Candidates
may race only through authenticated transport setup. A loser is dropped before
the selected transport receives a VLESS request or any application data. Late
or duplicate outcomes cannot grant ownership or affect this establishment.

The Tokio adapter owns a single overall deadline and an optional delayed
alternate. A primary failure starts that alternate immediately. Cancelling the
owning future drops both owned futures; no task is detached. Passed-in futures
must themselves obey cancellation and pre-request isolation. The adapter does
not implement authentication or infer node health from untyped errors.

After adoption, request failure is reported rather than silently replayed.
This sacrifices destination-stage transparent retry to preserve side-effect
safety. User-visible retry belongs above the transport, with application
knowledge. Global health, per-inbound LINE groups and authenticated-client
wiring remain separate responsibilities; a codec or scheduling primitive alone
does not constitute an operational client role.

## Validation

Deterministic event-sequence tests and `session_semantics` fuzzing enforce at
most one alternate start and one adoption, and permanent terminal states.
Paused-time adapter tests cover hedge timing, overall deadlines, failure order,
loser cleanup and caller cancellation without network timing assumptions.
