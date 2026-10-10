# ADR 0046: Short-fault baseline census before recovery admissions

Status: Accepted

## Context

Frozen QEMU on Exact-head `26c6e1c` (Actions run `38016570647`) fail-closed in
`nxr/ordinary` at `fault-warm-15000` with:

`descriptor census had no consecutive complete matching reads within its fixed bound`

Landing retained `descriptors closed during census: [117]`. Warm does not restart
LANDING; LINE roles only reload. Recovery admissions still begin at
`restored + 1000` (ADR 0043 left non-restart faults on the immediate edge), so the
first shared fault checkpoint (`+15000`) lands ~4s into the intentional recovery
blast (`transfers_per_line` at `fault_concurrency_per_line`). Under QEMU guest
`/proc` latency, six back-to-back sweeps cannot manufacture a consecutive equal
complete pair. That is INVALID acquisition evidence, not a product leak
([ADR 0037](0037-bound-descriptor-census-acquisition.md)).

[ADR 0043](0043-landing-restart-baseline-before-recovery.md) already delayed
recovery for `landing-restart` only. Native Exact-head on the same SHA passed
after [ADR 0045](0045-collector-inherited-pipes-are-fixed-inventory.md); collector
pipe inventory does not quiet QEMU recovery churn. Sleep holds remain rejected.

A secondary Class B appeared when the Actions cell job, after `sudo`-owned
`stability-run`, tried to write `cell-matrix.json` with unprivileged Python and
hit `PermissionError`, cascading merge into "missing cell artifacts".

Historical INVALID for `26c6e1c` / `38016570647` remains immutable.

## Decision

1. Generalize `recovery_ready_ms`: every **non-RTT** fault waits until
   `start + fault_checkpoint_offsets_ms[0] + checkpoint_tolerance_ms` (and never
   earlier than `restored + 1000`). RTT/loss faults keep immediate post-restore
   recovery; their first checkpoint is still inside the long fault window.
2. Keep the six-sweep census bound and fail-closed INVALID on true continuous
   churn. Product defects at later recovered checkpoints stay Class A.
3. `stability-run --cell` writes `cell-matrix.json` under the same privileges as
   the rest of the cell output. Staging copies use shell/`sudo`, not Python.
4. `stability-merge-cells --cells-root DIR` discovers `cell-matrix.json` markers
   in Rust so merge no longer depends on an inline Python helper.

`cargo dev bench stability-repro --fault landing-restart` remains the fast ACK
contract check. Hosted four-cell QEMU remains the only full proof of this
schedule against guest `/proc` churn.

## Consequences and limits

Coverage of mid-recovery ceilings for short faults moves to checkpoints after
recovery begins (`60000` and beyond); the idle post-restore baseline at `15000`
becomes reliable on QEMU. This does not claim bug-free software, does not weaken
fail-closed INVALID, and does not reintroduce TSan.

## References

- [Bound descriptor census acquisition](0037-bound-descriptor-census-acquisition.md)
- [Separate active census from recovery ownership](0039-separate-active-census-from-recovery-ownership.md)
- [LANDING restart baseline before recovery](0043-landing-restart-baseline-before-recovery.md)
- Frozen failure: https://github.com/jacek4yang/rust-reality/actions/runs/38016570647
