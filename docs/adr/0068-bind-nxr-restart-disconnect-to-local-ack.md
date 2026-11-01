# ADR 0068: Bind NXR restart disconnect to the local ACK

Status: Accepted

## Context

An injected LANDING kill can make the witnessed NXR prefix connection report
`session_relay` / `io` / EPIPE. The existing restart attribution recognized only
Handoff's `handoff_relay` stage. Treating that expected NXR disconnect as an
unexplained protocol rejection rejects otherwise complete fault evidence.

Frozen run `41299700110`, attempt 2, at `ba0313c5` retained this case. Its
original aggregate remains FAIL. Artifact `13084716020` has SHA-256
`b3a540b8e6a114cf3d0d1f2f44cd956a68e7e493404554158847eda19f898d78`.
The bounded regression fixture in `tools/fixtures/stability/nxr-restart/`
retains the original census/ACK actions and exact prefix bytes, with a
documented reduction of unrelated observations and the product log.

The NXR event occurs 41 ms after LINE-A completes its ACK exchange. Adding the
350 ms cross-guest clock guard to LANDING's ACK timestamp cannot classify this
fast local event. A fixed delay would change the test to accommodate its
evaluator rather than establish causality.

## Decision

Keep the existing Handoff attribution unchanged. For NXR, admit exactly one
expected restart disconnect only when all of these checks succeed:

- The established LINE-A ingress census, its guest identity and its ACK match
  the LANDING kill action. Preserve the existing cross-guest census/ACK check.
- The prefix began before injection, contains exact verified bytes, and its
  single observed failure is inside the declared fault interval.
- The product event names that same peer, is `connection_rejected` with reason
  `outbound`, and reports `session_relay` / `io` / errno 32.
- Its timestamp is no earlier than LINE-A's ACK-exchange completion, measured
  on the same guest clock as the product event. The existing upper bound at
  prefix completion plus the clock guard remains unchanged.
- The proof is consumed once across all process logs. Another event, another
  stage, a different peer, an authentication rejection, or missing evidence
  remains a failure.

The ACK is the causal authorization barrier for the injected kill, not a claim
that independent guest clocks establish the exact instant of the remote syscall.
This same-guest lower bound does not widen a global fault window or ignore all
errors during a restart. No product logging, protocol behavior, authentication,
resource ceiling, timeout, transfer count or performance threshold changes.

## Validation and limits

Require captured-evidence reconstruction and negative tests for missing actions,
identity drift, corrupt prefix bytes, wrong stage/peer/time/error, and duplicate
events. Requalify the corrected evaluator on fresh exact-source evidence; do not
rewrite the old FAIL or use the reduced unit fixture as a release verdict.
An ACK exchange without the verified kill and intact prefix is insufficient.
