# NXR frame single-buffer measurements

Candidate source: `37391f86c8d58ade672c25453a855b69e7d81932` (PR #420).
Baseline: `54c204af0a1c9a8568c530b8d3ffadaded39e25c`; its NXR UDP writer
matches `76dd5448`. Baseline traces and the exact driver are retained separately
in this evidence tree by PR #420. This directory is carried in evidence PR
#417 so measurements do not change the runtime candidate being qualified.

All 15 matched heaptrack cases show zero incremental allocations per encoder
call with preallocated caller storage. Baseline counts are one without an
address, two with an address. This does not establish zero allocations in a
whole UDP association: callers, decode paths, sockets and runtime still exist.

The predeclared 20-block ABBA comparison completes 1200 child processes,
100000 encodes each, on CPU 2 with P-core policies fixed at 2.4 GHz.
`cpu-samples.jsonl` retains every child user+system CPU observation from
`getrusage(RUSAGE_CHILDREN)` and elapsed time; CPU cost includes child startup.
Within each case/block, divide the mean of the two candidate CPU observations
by the mean of the two baseline observations. Resample the 20 block ratios
with replacement 10000 times (seed 325420), take each resample median, and
use interpolated 2.5/97.5 percentiles. All 15 upper intervals meet the unchanged
1.05 diagnostic guard. Median ratios range 0.89585 to 0.98087, approximately
1.9% to 10.4% lower CPU for this encoder-only workload. Full session and
release-package performance qualification remain independent requirements.

CPU policies restore exactly; collector exit is zero. Host snapshots contain
no detected compiler and the declared frequency bounds. Control-plane work
was pinned to CPU 8; this does not prove exclusive physical hardware.
The optional perf command was unavailable on PATH; no PMU-counter result is
claimed. Allocation backtraces and generated code support the mechanism;
CPU observations use the operating-system child accounting API.

The encoder symbol grows from 1348 to 3141 bytes because MAC computation
inlines into it. Total diagnostic ELF text decreases from 359279 to 359103
bytes; neither number describes the full production daemon. Both function
disassemblies and exact diagnostic executable identities are retained.
Assembly presentation has trailing whitespace trimmed; instruction bytes
are unchanged. Rebuild the exact Rust driver using `identity.json` and the
baseline README's compiler instructions. No instrumentation or dependency
enters production. The initial incomplete archival attempt and its correction
are recorded separately; they do not change any measurement outcome.

The exact official GNU package is additionally captured through 64 fresh
production CLI processes: 32 Chrome offers (16 omitted defaults, 16 explicit)
and 32 Firefox offers. Independent structure and freshness comparisons pass
against frozen native Windows browser fixtures. Capture stops before the
server flight; these files do not establish authenticated-session behavior.
All four candidate archives, source-file contents, executable hashes, native
smoke receipts, harness bytes and command-output hashes verify independently.
ARM native execution is attested by its matching hosted runner; local ARM
execution is explicitly not run. These are candidate assets, not a published
release. The full local check passes all 19 stages at the runtime source,
with hosted CI and Security PASS; Native/Frozen qualification remains separate.

The independently downloaded Native artifact from run 41280033428 verifies
3,120 members and its nested checksum manifest; see `native-verification.json`.
`frozen-packages-comparison.json` verifies that all six assets from the separate
Frozen package build match the candidate-package workflow bytes. This package
comparison does not claim the complete Frozen coordinator has passed.
