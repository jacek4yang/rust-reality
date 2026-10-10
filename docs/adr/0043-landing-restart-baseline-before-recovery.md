# ADR 0043: LANDING restart baseline census before recovery admissions

Status: Accepted

## Context

Frozen QEMU on candidate `9b90036` (Actions run `37940381711`) fail-closed in
both ordinary cells after `landing-restart` harness races:

1. `nxr/ordinary` at checkpoint offset `15000`:
   `descriptor census had no consecutive complete matching reads within its fixed bound`
2. `handoff/ordinary` at finalization (last fault `rtt-100-loss-1`):
   `restart disconnect lacks its bounded intact prefix`

LINE-A's ACK-driven abort barrier ([ADR 0041](0041-ack-driven-landing-restart-census.md))
had already succeeded: the prefix was witnessed, LANDING aborted after the ACK,
and the controller replaced the process. The failure was the guest collector's
six back-to-back `/proc/<pid>/fd` sweeps on the **new** LANDING while the
controller was already admitting the fixed recovery batch (`restored + 1000`,
concurrency 4 per LINE).

[ADR 0037](0037-bound-descriptor-census-acquisition.md) correctly refuses to
manufacture stability under continuous churn: consecutive complete equal maps
are required, and exhausting the fixed read bound is INVALID, never PASS.
[ADR 0039](0039-separate-active-census-from-recovery-ownership.md) separates
active ceilings from recovered ownership, but still needs a coherent sample.
Pumping intentional recovery admissions through a cold post-restart LANDING at
the same instant as the first ownership census makes a stable pair improbable
without proving a product leak. Sleep holds were already rejected.

Historical INVALID evidence for `9b90036` / `37940381711` remains immutable.

## Decision

Keep the six-sweep census bound and fail-closed semantics unchanged.

For `landing-restart` only, delay recovery admissions until the first fault
checkpoint window has closed:

`recovery_ready = start + fault_checkpoint_offsets_ms[0] + checkpoint_tolerance_ms`

(and never earlier than the ordinary `restored + 1000` edge). Other faults keep
immediate post-restore recovery. The first post-restart checkpoint therefore
observes an idle replaced LANDING; later checkpoints (`60000` and beyond)
continue to cover recovered ownership under and after recovery traffic.

Triage labels the consecutive-matching-reads acquisition miss and the intact
prefix attribution miss as Class B (harness schedule / evidence acquisition).
When the echo prefix ends on an expected disconnect, `completed_ms` MUST equal
the recorded failure instant — a second `elapsed()` call must not invent a
1ms mismatch that fails `completed_ms != expected_failures[0]`.

Cell evidence staging in the Actions matrix MUST run after fail-closed
`stability-run` so merge does not cascade into Class B `missing cell artifacts`.

Product defects at recovered checkpoints, ceiling breaches, and unexpected
transfer failures remain Class A.

`cargo dev bench stability-repro --fault landing-restart` continues to cover the
ACK wire contract in minutes. Hosted four-cell QEMU remains the only full proof
of this schedule against real guest `/proc` churn.

## Consequences and limits

Workload and assertions are coherent without sleep inflation. Coverage of
mid-recovery ceilings for `landing-restart` moves to checkpoints after recovery
begins; the idle post-restart baseline is newly reliable. This does not claim
bug-free software, does not weaken fail-closed INVALID on true continuous churn,
and does not reintroduce TSan.
