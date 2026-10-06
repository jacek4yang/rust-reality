# Pinned-source uninstrumented control

The 1800-second native mixed workload on source
`dbf4773475e7d30a6753f8b90a7db3850cf7f135` passed the unchanged aggregate PSS
tail-slope gate at **1.919933042 MiB/hour**, limit **2.0**. It completed 250
rounds with zero counted transfer failures, all 96 distributed integrity
samples passed, and terminal image binding and completion are present.
`longHorizonQualified` remains false.

[manifest.json](manifest.json) records byte identities and retained member
checksums. The product ELF, fixture binaries, diagnostic harness and sampler
are identical to the [profiled run](../pinned-profile/README.md). The parent
instrumentation marker was unset; child environments and process mappings
independently confirm absence of Heaptrack and the allocator observer. No
allocator knob was set. Scratch retention remained enabled in the explicitly
identified diagnostic harness; this is not an unmodified release qualification.

All six service PID/start-time identities remained stable. Five distributed
services published generation 1, while standalone stayed at generation 0.
Two-second observations retain PSS, anonymous memory, threads, file
descriptors, CPU ticks and grouped mappings. The elapsed process observations
include terminal-binding idle time beyond the native workload; CPU totals are
not a calibrated performance comparison.

This single pass does not supersede the instrumented or historical failures.
The same workstation's profiler and observer change memory and thread counts;
ordinary run variation also remains possible. No product root cause or fix is
claimed. All original scratch and raw captures remain retained locally;
generated fixture secrets and payload files are not published.
