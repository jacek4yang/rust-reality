# ADR 0036: Separate native and QEMU qualification

Status: Accepted

## Context

One workflow previously mixed native interoperability, connection lifetime,
resource recovery, and a multi-hour independent-kernel campaign. Every draft
push restarted both. A native success appeared beside unrelated VM work, while
sampling failures obscured which evidence layer had failed. VM timing also
cannot establish precise production performance on a shared hosted runner.

## Decision

Use separate execution lanes with explicit coverage:

- Ordinary CI owns fast deterministic state, timeout, ownership, cancellation,
  parser and regression tests. Security owns the declared sanitizer, fuzz and
  dependency checks. Neither claims exhaustive concurrency exploration.
- Native qualification owns real Linux processes and owned network namespaces:
  stock-Xray interoperability, cold/warm mechanisms, descriptor pressure and
  recovery, mixed topology operation, and the 600-second connection matrix.
- Candidate packages own native execution of the actual four packaged Linux
  tiers and the combined checksums/manifest, without creating a release.
- QEMU specialist qualification owns separate kernels and constrained guest
  CPU/RAM profiles. Its existing fault, integrity and resource campaign remains
  intact. It is not the place for fine-grained throughput comparisons or the
  first reproducer of a pure state-machine defect.

The QEMU workflow runs when a PR becomes ready for review, or on explicit
workflow dispatch. Dispatch uses the selected branch's exact commit; PR runs
use the PR head. It does not run for every draft edit. An in-progress campaign
is preserved rather than cancelled by a later requested campaign. Its result
only qualifies its recorded source, not a newer commit. Native and QEMU
concurrency groups are independent.

This scheduling separation does not relax the existing Tier B acceptance
contract or treat skipped/missing checks as success. Until a separately
reviewed replacement provides the required fault coverage, the frozen release
candidate still needs the declared QEMU evidence. A changed candidate needs
new exact-candidate qualification, including an explicit QEMU dispatch when
the PR is already ready. No automatic merge follows a green subset of checks.

Raw sampling failures remain evidence errors, distinct from demonstrated
product resource failures. Preserve the original reads and failures; never
derive a leak diagnosis from a census already known to have raced, or retry
acceptance until a favorable resource number appears.

## Consequences

Draft development receives fast feedback without continuously restarting
multi-hour guest campaigns. Review/release preparation must explicitly verify
all declared exact-source evidence. GitHub workflow dispatch requires the
workflow to exist on the default branch; the ready-for-review PR event permits
the initial pre-merge qualification. None of these tests guarantees zero bugs
or proves independent physical-host/WAN behavior. No production host access is
required or authorized by this workflow.

## References

- [GitHub workflow events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
- [Resource ownership acceptance](0034-qualify-resource-ownership-and-lifetime.md)
- [Testing layers](../en/development/testing.md)
