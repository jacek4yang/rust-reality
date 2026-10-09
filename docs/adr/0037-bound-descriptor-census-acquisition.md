# ADR 0037: Bound descriptor census acquisition

Status: Accepted

## Context

Linux descriptor-directory enumeration and `readlink` are separate operations.
An owned process may close a descriptor between them. That ENOENT establishes
an incomplete census, not a leaked descriptor or missing resource permit.
A single such sweep should not be mistaken for an atomic kernel snapshot.

## Decision

Within the existing checkpoint interval, collect at most six descriptor
sweeps and retain every map, disappeared entry and read error. Select the first
pair of consecutive complete, equal descriptor-number/target maps. Stop further
sweeps after any non-ENOENT read error. Selection never reads an acceptance
threshold, ownership counter, RSS value or previous resource verdict.

The offline verifier checks the full retained history, the six-sweep bound,
the selected map, and that no earlier complete equal pair was bypassed.
No matching pair produces INVALID evidence. The last partial map is retained
for diagnosis only. Permission errors are not retried or ignored. Existing
process/executable identities, the two-second observation bound, clock guards,
resource capacities and ownership checks remain unchanged.

Earlier incomplete sweeps remain visible in the observation. Their descriptor
numbers are never added to the selected census or treated as additional live
resources. Historical failed observations are not rewritten or retrospectively
reacquired; they keep their original collector/evaluator identities.

## Limitations

Two matching reads mean two matching observations, not atomicity or future
quiescence. Open/close activity between reads, descriptor-number reuse and
asynchronous ownership-log timing remain possible. They are not solved by this
acquisition rule. Existing ownership inconsistencies still reject the sample;
no tolerance is added to make mismatched counters pass. Continuous churn can
exhaust the fixed read bound and produce INVALID, which must not become PASS.

The extra reads are tooling-only and bounded. No production lock, instrumentation
endpoint, signal, allocator behavior or transport deadline changes. New evidence
contains the required sweep history; old evidence remains bound to the old
evaluator instead of being silently upgraded to this representation.

## References

- [Resource acceptance](0034-qualify-resource-ownership-and-lifetime.md)
- [Qualification responsibilities](0036-separate-native-and-qemu-qualification.md)
