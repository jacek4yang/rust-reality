# Historical release-gate harnesses (inert evidence)

These directories preserve the release-gate harnesses used to produce the
performance-gate evidence for past releases:

- `v150-release-gates/` — v1.5.0
- `v151-release-gates/` — v1.5.1
- `v16-release-gates/` — v1.6.0

They are **inert historical evidence**, not runnable tooling. Each harness
drives the retired `scripts/evaluate-release-performance.py` evaluator (deleted
after its migration to `cargo dev perf evaluate`) and the pre-migration
`scripts/benchmark-*.sh` family, against baselines and worktrees that no longer
exist. They are retained unmodified so a reader can reconstruct exactly how a
past release was gated; they are not part of any current CI, release or gate
path.

The authoritative evaluator is now `cargo dev perf evaluate`. Current
benchmark tooling lives under `tools/rr-dev`. Do not resurrect these harnesses
as active commands; treat them as a frozen record.
