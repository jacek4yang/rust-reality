# Pinned-source allocation diagnostic

The 1800-second mixed-traffic diagnostic on source
`dbf4773475e7d30a6753f8b90a7db3850cf7f135` failed the unchanged aggregate PSS
tail-slope gate: **3.169552473 MiB/hour**, limit **2.0**. The native observations
contain 247 round samples and all **96 distributed integrity samples passed**.
Final native image binding was **not run**; no successful completion or
qualification is claimed. The failed summary does not serialize mixed-transfer
or churn failure counters. Reaching the resource gate nevertheless establishes
zero counted failures by the pinned source's preceding
[transfer guard](https://github.com/jacek4yang/rust-reality/blob/dbf4773475e7d30a6753f8b90a7db3850cf7f135/tools/rr-dev/src/bench/soak.rs#L1601-L1629).
This is a source-derived result, not a serialized counter. An independent check
also verifies the expected size and SHA256 of all 741 retained full-transfer
bodies.

[manifest.json](manifest.json) records source/build/binary/patch identities and
the SHA256 and size of every retained member. Identity-encoded native files
are byte-exact. XZ members decompress to their original bytes; the manifest
also records their original SHA256. Raw and interpreted allocation traces,
two-second process/mapping observations, and ten-second allocator XML are
retained. The non-executable input archive contains the diagnostic Rust patch,
observer C source, sampler, and analysis sources; it installs no repository
tool or policy.

The product ELF was an optimized, symbolized release with frame pointers, SHA256
`b8ab364ca79c9debe18b2f96eed02dc9b7d80847e71475e08991f3aa63c99ace`.
The explicitly identified harness injected Heaptrack 1.5 and `malloc_info`
only into its isolated rust-reality children and retained scratch files. It
changed no timing, threshold, warmup, allocator knob, or round-output cleanup.
All service identities stayed stable. Five distributed services published
generation 1; standalone stayed on generation 0 as the workload specifies.

The five distributed raw traces passed the duplicate-live-pointer check.
Corrected allocation-stack grouping gives zero exit bytes for connection
tasks, warm pools, relay pools, and replay caches. NXR line's 128-byte
cover-profile-origin remainder has an ArcSwap debt-node stack, rather than a
cover-profile payload stack. Grouping describes allocation origin, not a
complete ownership proof. Earlier broad task grouping remains under
`superseded-attribution/`; the corrected reports and inputs retain provenance.

Standalone's raw trace has conflicting live-pointer records. Its checked
timeline failed and is preserved under `rejected-standalone-timeline.stderr`
and `receipts/profile-final-analysis/`. No repaired standalone attribution is
published. Heaptrack's own report is retained with this limitation.

The first conflict has a 533-byte Vision request buffer and a new 512-byte
target-flight buffer recorded at the same address before the old free. That
free is immediately followed by the Vision buffer's moved 1186-byte
reallocation. The exact preload disassembly calls real `realloc` before its
recording callback, matching the
[upstream hook order](https://github.com/KDE/heaptrack/blob/v1.5.0/src/track/heaptrack_preload.cpp#L220-L233).
These records explain the diagnostic ordering failure; they do not identify
the unprofiled historical memory failure's cause.

The workstation used Ubuntu 26.04, glibc 2.43, and 16 worker CPUs. Profiling and
the observer add threads, allocations, and resident memory; allocator XML
includes their effects. These data support retention as a local hypothesis,
but neither prove the historical root cause nor justify a product change.
They provide no long-horizon qualification or historical same-host comparison.
