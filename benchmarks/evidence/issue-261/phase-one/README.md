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

## Fixed-work allocator discriminator

[fixed-work-manifest.json](fixed-work-manifest.json) binds the source and 711
members of [fixed-work-diagnostic.tar.xz](fixed-work-diagnostic.tar.xz).
Both sequential host runs use the unchanged frozen `ec0d0a3` executable
identified above: four batches of 100 hash-checked 4 MiB transfers per public
topology, concurrency four, six process roles, and generation-one reload after
batch two. Both complete 1600 transfers without failures. Checkpoints add
approximately five seconds of observation overhead; the final observations are
at 920.402 and 916.923 seconds, not a nominal ten-minute qualification.
No native threshold or acceptance window is changed.

The control has no preload. The observer adds one sampling thread and one log
descriptor per process, reads `malloc_info` every ten seconds, and changes no
allocator settings. These runs use host glibc 2.43, not the hosted qualification
environment. Smaps mapping geometry and numeric fields are retained; file
pathnames are redacted and original private-file hashes recorded.

| Role | Control final anonymous KiB | Observer final anonymous KiB | Observer arena system bytes | Observer free bytes | Non-free upper bound bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Handoff LANDING | 4444 | 4620 | 5410816 | 4934635 | 1266709 |
| Handoff LINE | 2628 | 2516 | 3522560 | 3035225 | 1277863 |
| NXR LANDING | 1292 | 1488 | 3010560 | 2655384 | 1145704 |
| NXR LINE | 4604 | 6136 | 6885376 | 6406639 | 1269265 |
| SOCKS LINE | 3960 | 4044 | 4751360 | 4284249 | 1257639 |
| Standalone | 3644 | 4368 | 5103616 | 4638172 | 1255972 |

Allocator totals use XML root totals once, not the sum of root and per-heap
copies. The upper bound is `system.current - fast - rest + mmap`; all six final
`mmap` totals are 790528 bytes. It includes unreported free/tcache space and
allocator overhead: it is **not** an exact live-object count. Arena system
space is not resident space either.

All roles retain stable PID/starttime pairs through reload. The final ten
allocator snapshots have unchanged arena counts/system/mmap totals; non-free
upper bounds vary by at most 50 bytes per role. Final control thread counts are
17; observer counts are 18. The 32 retained pipe descriptors in Handoff LINE
and NXR LANDING are separately classified, not called live connections.

The control's fourth batch adds 724 KiB to Handoff LANDING residency without
later quiet growth; the observer instead has late increases of 188 KiB in NXR
LINE and 388 KiB in standalone. In the observer's late plateaus, standalone
arena system growth is 397312 bytes and free growth 386378 bytes, while the
non-free upper bound changes by 10934 bytes. NXR LINE residency grows with
unchanged arena system size and approximately 15 KiB non-free growth. These
observations demonstrate that resident growth cannot be equated to matching
live-object growth.

This checkpoint supports allocator high-water retention as a substantial
contributor, but does not establish a universal bound or retrospectively assign
every historical failed sample to a stack. Historical failures remain failed.
These measurements do not quantify how many resident pages an explicit
allocator trim would return; no production trimming change is justified here.

## Candidate native failure at `63c3523`

Native run 37574005711 failed the unchanged aggregate PSS tail gate:
2.351475833 MiB/hour exceeds 2.0. The
[artifact manifest](11463444612/manifest.json) and
[independent audit](11463444612/audit.json) retain artifact 11463444612,
ZIP SHA-256
`f478518fe579e14affd0bf6890809764d7503944ea1e27834b551295c2aef7c5`.
All 45 original member hashes match. Artifact workflow head/run identity,
publication source/run identity and frozen source identity agree.
The frozen executable is
`43ed02c8aeb5b1007940306a3206847270df9841d05a45613f36fc79e5aa17d6`.

| Role | Tail MiB/hour |
| --- | ---: |
| Handoff LANDING | 0.025719885 |
| Handoff LINE | 0.344840078 |
| NXR LANDING | 0.090880509 |
| NXR LINE | 0.396356651 |
| SOCKS LINE | 0.229012553 |
| Standalone | 1.264666158 |

FD growth is -6 and thread growth -1. Interoperability, mechanism and
descriptor-pressure completion/evidence bindings pass; the failed soak has no
retained terminal completion binding. Its resource samples remain a failure,
not a successful candidate qualification. This source changes the replay
regression and evidence, not production memory behavior.

## Allocator counterfactual and mixed standalone discriminator

[Manifest](allocator-counterfactual-manifest.json) binds the 1,223-member
`allocator-counterfactual.tar.xz` archive, SHA-256
`0f61ce6ff63fe7bf630ea50ad440ed511263b225db8fc3dcbbf985e1a4504e48`.
It contains raw numeric smaps observations with file paths redacted, root-only
allocator accounting, analysis scripts, diagnostic driver sources and the
observer source. Configuration secrets are not included.

The Ubuntu 24.04/glibc 2.39 guest control and observer each complete the same
1,600 hash-checked transfers with zero failures. A final diagnostic-only
`malloc_trim(0)` probe runs after work and idle recovery, not during traffic.
PID/starttime, FD and thread counts remain unchanged across the probe:

| Role | Released anonymous/PSS KiB | Non-free upper-bound delta, bytes |
| --- | ---: | ---: |
| Handoff LANDING | 1,140 | -13 |
| Handoff LINE | 272 | -1 |
| NXR LANDING | 32 | -10 |
| NXR LINE | 1,516 | +1 |
| SOCKS LINE | 924 | -3 |
| Standalone | 1,280 | -2 |

The released 5,164 KiB were allocator-owned free pages, not live objects
destroyed by the probe. `system - free + mmap` remains an upper bound including
tcache/overhead, not a precise count of live Rust objects. Guest and host differ
in libc, CPU count and automatically derived resource policy; their absolute
totals are not a controlled worker-count comparison.

The standalone discriminator uses the native mixed round: TLS/Vision, framed
cleartext, direct TLS fallback and range churn. Control and observer each
complete 200 rounds, 600 hash-checked full 4 MiB transfers and 3,200 range
requests, with zero failures and a generation reload after round 100.
Range requests retain the native success checks, not an added payload hash.
During the last four batches, control anonymous residency is 1,816–1,820 KiB;
observer residency is 1,988 KiB throughout, including the final quiet interval.
The diagnostic trim releases another 484 KiB from standalone with exactly zero
change in its non-free upper bound. Other roles are idle controls in this
experiment, not distributed workload coverage.

The archived historical owner ledger uses only the five previously validated
distributed Heaptrack traces. Between approximately 880 and 1,780 seconds,
their live requested bytes increase by 1,336–4,296 bytes per role while arena
system bytes increase by 53,248–647,168 bytes. The invalid historical standalone
pointer trace remains excluded. Allocation-origin grouping is not complete Rust
ownership attribution; observer and native clocks are not conflated.

Together with the replay expiry/capacity experiment, these observations support
bounded container capacity and allocator high-water retention in the exercised
workloads. They do not establish a universal resident-memory ceiling or justify
production trimming, allocator replacement, or a changed acceptance threshold.

## Native qualification at `240ea59`

Run 37579723782 passes the full authoritative gate, interoperability, mechanism,
descriptor pressure and the unchanged 30-minute soak. The
[artifact audit](11466264441/audit.json) verifies all 47 members and terminal
bindings. [Artifact manifest](11466264441/manifest.json) records ZIP SHA-256
`4c5a79f4e6dbb6fb1f5adefd2cbe7c00977ddca75c1f34b19c9ed3f8dc94fcea`.
Aggregate PSS tail is 1.821038584 MiB/hour against the unchanged 2.0 limit.
This pass neither erases the preceding failure nor qualifies a subsequent head.

## Frozen candidate `583ffed`

The executable candidate remains
`583ffed78f3a943b8a2235d158060a537ec284b2`; subsequent evidence-only commits do
not change that identity. Local `cargo dev check --all` passes all 19 stages in
750.3 seconds. CI 37586749887 and Security 37586749683 pass.

Native run 37586749806 passes with aggregate PSS tail
0.617346461 MiB/hour against the unchanged 2.0 limit.
[Audit](11469499077/audit.json) verifies all 47 checksum entries and all four
completion/evidence bindings. [Manifest](11469499077/manifest.json) retains the
public-safe textual evidence; the frozen binary remains in the original
artifact. ZIP SHA-256:
`0b8b475df7178c42ee8682840991f18bc0f57de2a09fc6dbd974d18dc82ecfd0`.
Hosted ELF:
`c8bbb90090ee51d34071c8ff1a3849c8bf2ebe9438730c9ba99d855671aaa675`.
Locally frozen ELF:
`b261d4a25a88d057ceb7c5f50c06f3a8041ec95b609c3d1349785264f20a830f`.
They have the same source identity, not byte-identical build environments.

The [checkpoint manifest](candidate-checkpoint-583ffed-manifest.json) binds
`candidate-checkpoint-583ffed.tar.xz`, SHA-256
`dd6dc9b9a37b00268f0bceab020df8fc936bbd0ed3c31b47144e5881248a00af`.
Its 53 members include local gate/freeze receipts, native ARM package bindings,
and failed/passed disposable-driver diagnostics. ARM artifact 11466936938
comes from the native Ubuntu 22.04 ARM CI job; its package SHA-256 is
`45636400901ad61550dfe5ee4e65d5fcfce225d1d05c9ed9466cc9b1ce1cd230`.
The existing version is a package-format label, not a newly created release.

The initial NXR KVM lifecycle is incomplete: its sampler aborted when an
enumerated `/proc/<pid>/fd` entry closed before `readlink`. A short live
reproducer names that exact path; a deterministic closed-descriptor regression
fails before and passes after the diagnostic-only correction. The corrected
sampler retains enumerated descriptors in its count, marks disappearing
targets explicitly, and still fails on process disappearance or other errors.
Its live confirmation completes 1,620 samples in 20 seconds, observing one
close race without aborting. A separate failed smoke detects reused upload
paths in an append-only origin log. The corrected verifier uses the captured
pre-transfer append boundary and requires one new PUT receipt per upload with
the exact length/hash. Neither correction changes production code or turns
the original failed/incomplete runs into passes.

This evidence is not real-WAN Tier B and does not authorize publication.
