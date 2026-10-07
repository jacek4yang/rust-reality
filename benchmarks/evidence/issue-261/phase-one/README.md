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

## Replay allocation discriminator

[replay-retention.json](replay-retention.json) records 384 measured cycles from
the diagnostic source in [replay-diagnostic.tar.xz](replay-diagnostic.tar.xz).
Rust 1.96.0 x86_64 layouts are: key 32 bytes, entry 64, admission permit 32
(already included in entry), expiration record 56, shard 56. The counter
measures requested allocation bytes, not allocator usable bytes or PSS.
Cache/governor construction occurs before measurement.

| Synthetic limit | Workload | Retained container bytes after 64 cycles |
| ---: | --- | ---: |
| 300 | Balanced committed entries | 107264 |
| 300 | Successive hot shards | 2507008 |
| 300 | Dropped pending churn | 465216 |
| 65536 | Balanced committed entries | 20054272 |
| 65536 | Successive hot shards | 320864512 |
| 65536 | Dropped pending churn | 1841472 |

All cycles explicitly purge and recover zero live entries/permits. All six
cases have zero new allocation bytes over their final 16 cycles. Hot-shard
occupancy is sequential, not simultaneously multiplied by 16; retained
capacity nevertheless accumulates across shards. Sequential synthetic hash
words intentionally do not model uniform SHA-256 wire keys. Tombstones can
reduce reported `HashMap::capacity()` without releasing the table; it is not
an allocation-byte counter. The 300-entry hot-shard case needs a second
table growth before rehashing can reuse it.

A conservative container bound must use per-shard historical high water.
For this compiler's hashbrown 0.16.1, growth caused by tombstones stops once
full table capacity is at least twice the maximum shard occupancy; subsequent
reservation rehashes in place. For occupancy bound C >= 15, a conservative
bucket bound is `next_power_of_two(floor(16*C/7))`. Table allocation is
`97*buckets + 16` bytes for the measured key/entry layout. Pending-drop
compaction bounds stale records; allowing two transient appended records,
use `2*C + 1026` heap records, rounded up to the next power of two, at
56 bytes each. Multiply both by 16, not by one global live-entry count.
For synthetic C=65536 this conservative bound is 641728768 container bytes,
not a claim that the workload allocated that amount. Allocator metadata,
cache construction and transient resize overlap are separate.

These finite synthetic bounds do not quantitatively explain the historical
role trajectories. Actual service policy is machine-derived, not necessarily
65536 entries; actual occupancy and allocator residency must be measured.
The shared REALITY authority survives reload, and expiry is lazy: waiting
120 seconds without a cache operation does not itself free entries.
