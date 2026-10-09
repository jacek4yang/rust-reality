# ADR 0042: Four-cell QEMU parallelism via Actions matrix

Status: Accepted

## Context

Frozen QEMU qualification requires four contract cells (`handoff`/`nxr` ×
`ordinary`/`constrained`). Sequential execution on one hosted runner stretched
failures into multi-hour vague INVALID triage. True same-host parallelism is
blocked by three coupled constraints:

1. process-global benchmark `HostLock`;
2. fixed fixture SSH/SOCKS and data-socket ports in `guests.json`;
3. ordinary `ubuntu-24.04` runners expose four cores — exactly one cell's
   non-overlapping guest vCPU affinity budget (LANDING 2 + LINE-A 1 + LINE-B 1).

Oversubscribing those cores would weaken the constrained LANDING profile the
cells exist to exercise. Paid larger runners are out of scope.

## Decision

1. Keep one cell per host under `HostLock` and the fixed fixture ports.
2. Parallelize across GitHub Actions jobs with a four-entry matrix. Each job
   provisions its own ephemeral guests and runs
   `bench stability-run ... --cell NAME`.
3. Aggregate with `bench stability-merge-cells`, which fail-closes on identity
   drift, duplicate/missing cells, and retained cell failures, then runs the
   existing offline evaluator. The merged artifact name remains
   `hosted-qemu-campaign-<sha>` for frozen acceptance.
4. Shared Class A/B/C labels (`diagnosis`) make cell and merge receipts name
   harness vs infrastructure vs product defects without rewriting historical
   INVALID evidence.
5. Reject same-host multi-cell execution on ordinary runners. Port-pool remaps
   remain future work only where a host honestly has independent capacity.

Identity `environment.json` binds only pinned Xray/OpenSSL digests.
Per-runner `uname` goes to non-identity `controller-host.json` so matrix cells
can merge without false identity drift.

## Consequences

Wall-clock four-cell qualification drops toward one cell's duration plus merge.
A single cell defect no longer waits behind siblings for triage, while fail-closed
acceptance is preserved. Prep binaries and the cloud base image are shared once
per SHA. This does not claim the data path is bug-free and does not reintroduce
TSan.

## References

- [ADR 0041](0041-ack-driven-landing-restart-census.md)
- [ADR 0036](0036-separate-native-and-qemu-qualification.md)
- [ADR 0038](0038-hosted-actions-are-primary-quality-gates.md)
