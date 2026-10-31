# ADR 0065: Reject full-read upload window growth

Status: Rejected

## Context

The client reads local upload bytes into a connection-owned buffer before
assembling bounded Vision frames in the canonical TLS writer. A full local read
does not establish that larger reads improve every traffic shape.

The experiment at `ef8d1171d73846cc9778c87036afef52f10236e1` grows this buffer
once from 16,374 to 32,748 bytes after its first full read. It preserves initial
idle capacity and immediate short-read flushing. The hypothesis was to reduce
receive calls without adding a second serializer or steady-state allocations.

The [matched diagnostic](../../benchmarks/evidence/releases/v2.3.0/client-upload-window-rejected-ef8d117/archive-manifest.json)
compares this experiment with `1c1930f` using three ABBA blocks, three samples,
concurrencies 1 and 64, five 16-MiB workloads, and identical fixed CPU policies.
All 14,040 data requests succeed. Direct upload at concurrency 1 uses 5.34-8.27%
more CPU in every block, with median throughput ratio 0.9886. Concurrency-64
Direct-upload CPU improves, with median ratio 0.9254, and framed-upload CPU at
concurrency 1 improves, with median ratio 0.9398. These three-block observations
are diagnostics, not confidence bounds or release qualification.

## Decision

Reject growth based solely on the first full upload read. Retain the existing
one-record payload window and canonical writer. High-concurrency savings cannot
compensate for a repeatable low-concurrency regression. Keep the multi-record
writer boundary test independently of this rejected buffer policy.

No memory benefit is claimed: the optional post-upload residency experiment
was not run after the performance rejection. Existing performance failures
remain unresolved; reverting this experiment does not qualify the baseline.

## Revisit conditions

Revisit only with profiling of the affected low-concurrency upload path and a
bounded ownership strategy that passes the unchanged per-cell performance and
resource contracts. Do not select behavior by benchmark concurrency or weaken
socket, timeout, authentication, or byte-integrity requirements.
