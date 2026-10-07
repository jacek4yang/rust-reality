# Phase 1 replay and historical memory evidence

These measurements do not establish the cause of historical PSS growth.
No production memory change is justified by this checkpoint.

## Historical artifact audit

[manifest.json](manifest.json) records the original GitHub artifact metadata,
ZIP identities and byte-exact retained member identities.
[artifact-audit.json](artifact-audit.json) records independently verified
member checksums, completion-to-evidence bindings, frozen source/binary
identities, stable PID/starttime pairs, reload timestamps and per-role slopes.
All five ZIP digests match the GitHub API digest. All 229 original member
checksums match. The frozen binary in the latest archive is
`d7d32f53e73bc0dcc8565a287165e9ecf3188e2ee0ae19c1c7f6e3de30902e34`.

| Source | Native run | Artifact | Aggregate tail MiB/hour |
| --- | --- | --- | ---: |
| `ff2977a` | 37331344170 | 11358675348 | 2.623952748 |
| `3b581bd` | 37351315930 | 11365897422 | 3.596465581 |
| `3b581bd` | 37358417218 | 11368625773 | 0.432756491 |
| `c3bda40` | 37459735433 | 11415921286 | 2.634096777 |
| `ec0d0a3` | 37492205352 | 11429711879 | 1.389721739 |

Recomputation uses the original second half of samples, starting at
`max(1, sample_count / 2)` with integer division. For each role, regress
`vmPssKiB / 1024` against `monotonicSeconds` and multiply by 3600.
Aggregate PSS sums the six roles at each timestamp before regression.
No time window, warmup, sample or threshold is changed. The limit remains
2.0 MiB/hour. Missing terminal completion/environment records in failed
runs remain missing; checksum verification is not terminal live-image binding.
The two `3b581bd` runs have identical frozen executable hashes. A passing
repeat does not supersede a failure or explain its cause.

The earlier allocation diagnostic and rejected pointer-accounting evidence
remain at immutable commit
[`baa1a9fc3bdc0037957a3a376d9e3cdbdcc11a5b`](https://github.com/jacek4yang/rust-reality/tree/baa1a9fc3bdc0037957a3a376d9e3cdbdcc11a5b/benchmarks/evidence/issue-261).
Their source baseline is not silently integrated into this candidate.

## Replay lifecycle regression

`committed_entries_expire_and_refill_across_shards` uses explicit monotonic
instants, 300 unique keys across all 16 shards and two full admission cycles.
It verifies saturation, rejection of a committed duplicate one nanosecond
before expiry, exact-expiry cleanup of entries/expiration records/permits,
and successful refill. The existing replay module passes all nine tests.
This is an expected-pass lifecycle regression, not a leak reproduction or
proof of historical allocator retention. Container capacities are deliberately
not asserted. REALITY replay ownership alone cannot explain LANDING replay
or allocator state.
