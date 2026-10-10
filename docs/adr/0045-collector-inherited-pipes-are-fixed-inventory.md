# ADR 0045: Collector-inherited pipes are fixed inventory

Status: Accepted

## Context

Native Exact-head soak on PR #278 head `c58eae50` (Actions run
38012283433) failed at the pre-workload baseline for every role with
`ownership evidence is not coherent: census exceeds recorded permits`, then
cascaded to `missing native ownership baseline`. Workload had not started.
`resources.jsonl` was empty.

Evidence shows each candidate still held two pipe ends (`pipe:[12740]` and
`pipe:[12741]`) also open in the collector. Product `fd_units_in_use` and
`retained_pipe_pairs` correctly omit them. Reconciling the full kernel pipe
census against product permits therefore rejects quiet, correct startups.
Lengthening the baseline settle sleep cannot remove inherited descriptors.

`spawn_isolated` clears the environment and redirects stdio, but Linux still
inherits non-CLOEXEC descriptors. `rr-dev` forbids `unsafe_code`, so a
`pre_exec` close of arbitrary FDs is not available in this package.

## Decision

1. Each raw observation records `collector_pipe_targets`: the collector's open
   `pipe:[...]` targets for file descriptors greater than 2 at observe time.
2. `startup_policy` promotes matching child pipe targets into
   `fixed_descriptor_targets` (multiset match). Later checkpoints keep that
   inventory; they never refit it from a later census.
3. Dynamic pipe accounting (normalize, reconcile, verify) excludes those fixed
   pipes. Product retained pairs and other non-matching pipes remain dynamic
   and must still be covered by permits.
4. Missing or empty `collector_pipe_targets` preserves prior fail-closed
   behaviour for historical receipts. A product pipe whose inode is absent from
   the collector inventory cannot be excused as harness inheritance.

No production admission, wire behaviour, resource limits, or timers change.
Acceptance still fails closed on incoherent permits, unknown descriptors, dirty
retained pipes, and capacity excess.

## Consequences and limits

Native baseline on ordinary hosted runners becomes coherent when the only
extra pipes are inherited collector inventory. Genuine descriptor leaks keep
failing. QEMU guest collectors record their own pipe set; host-only leakage
does not rewrite guest evidence. Closing inherited FDs at spawn remains a
desirable hardening and may land later behind a safe ABI boundary; this ADR
does not depend on it.

## References

- [Qualify resource ownership and lifetime](0034-qualify-resource-ownership-and-lifetime.md)
- [Separate active census from recovery ownership](0039-separate-active-census-from-recovery-ownership.md)
- Native soak failure: https://github.com/jacek4yang/rust-reality/actions/runs/38012283433
