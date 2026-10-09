# ADR 0039: Separate active census from recovery ownership

Status: Accepted

## Context

A kernel descriptor census and a periodic resource-owner log are observations
from different instants. Consecutive matching descriptor maps do not synchronize
them. Under legitimate connection churn, the newer census can exceed an older
permit count even when admission correctly reserves permits before allocating
resources. Subtracting these observations cannot establish a product leak.
Increasing freshness tolerance, selecting the largest counter, retrying until
accounting passes, or adding a production-wide lock would not repair that claim.

## Decision

The owner approved this division of validation on 2026-10-08:

- During active workload, retain and independently verify the raw socket/pipe
  census and the fresh owner counters. Enforce unchanged process/resource
  ceilings and each authority's capacity. Do not derive active resource
  ownership by subtracting asynchronous counters from the census.
- At the existing fixed recovered checkpoints, require ownership
  reconciliation, empty retained pipe contents, permitted pool capacities,
  retired generation completion, and absence of transient work. A recovered
  sample cannot substitute active-only evidence. Incoherent observations are
  INVALID evidence, not proof of a product defect and never a PASS.
- Keep deterministic permit lifetime, cancellation and concurrency tests, plus
  the real native pressure/recovery and byte-integrity gates. Observation
  methodology does not change production admission, wire behavior, resource
  limits, timers, or packet-path locking.

The evidence schema retains observed TCP socket and pipe counts separately from
an optional derived reconciliation. The evaluator determines whether ownership
is required from the frozen workload checkpoint schedule, not a caller-supplied
success flag. Raw verification reconstructs every retained number and rejects
unknown descriptors, substituted identities, stale logs and inconsistent reads.

The contract marker is `active-ceilings-recovery-ownership`. Existing numeric
limits, recovery deadlines, workload sizes and sampling windows are unchanged.
Normal bounded pool retention is allowed; resources are not required to become
zero. Known incoherence cannot be fixed by discarding the offending record or
labeling a recovery sample as active.

## Consequences and limits

This supersedes ADR 0034 only where it would infer instantaneous ownership from
active asynchronous observations. It does not claim atomic snapshots or prove
the absence of every short-lived leak between samples. Recovered accounting and
independent lifecycle tests remain necessary. New evidence binds the updated
contract and evaluator. Historical failures retain their original contract and
verdict; replaying them diagnostically does not qualify a new candidate.

Regression tests cover ordinary census growth after a counter record, bounded
retained pools and pre-auth idle tasks, missing recovery reconciliation, real
capacity excess, dirty retained contents, unknown descriptors and fabricated
normalized counts. Future changes must preserve this distinction rather than
rejecting normal workload behavior to satisfy an impossible snapshot claim.
