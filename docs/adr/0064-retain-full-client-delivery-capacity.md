# ADR 0064: Retain full client delivery capacity

Status: Accepted

## Context

The unified client's delivery Vec is both authenticated plaintext storage and,
after Vision Direct, the raw socket read destination. Reducing its initial
capacity from one 16-KiB TLS plaintext record to one 8-KiB Vision frame saves
idle residency, but also changes allocation and socket-read behavior.

The [initial 8-KiB experiment](../../benchmarks/evidence/releases/v2.3.0/client-data-ab-d72-119b37d/archive-manifest.json)
fails seven data assessments and leaves two unresolved. Small retained capacity
persists into Direct and increases high-concurrency download CPU by 25-30%.
Promoting capacity once at Direct corrects that mechanism, but the
[follow-up comparison](../../benchmarks/evidence/releases/v2.3.0/client-data-ab-d72-6455589/archive-manifest.json)
still fails concurrency-64 bidirectional throughput: candidate/baseline ratio
0.9754, with 95% block-bootstrap interval [0.9592, 0.9885], below the
predeclared 0.99 lower limit. The other 39 assessments pass. These are matched
same-Chrome comparisons against d72abc2, not browser-profile cost comparisons.
The follow-up does not isolate which consequence of the smaller initial
allocation causes the remaining throughput difference.

The later [full-capacity comparison](../../benchmarks/evidence/releases/v2.3.0/client-data-ab-d72-7e4d89d/archive-manifest.json)
also fails concurrency-64 bidirectional throughput: 0.9732 [0.9659, 0.9872].
Its executable text matches the earlier `2fb3076` implementation. This prevents
attributing the remaining regression to reduced initial capacity alone; restoring
capacity is not a substitute for complete data-path qualification.

The [original-client comparison](../../benchmarks/evidence/releases/v2.3.0/client-original-setup-2fb3076/archive-manifest.json)
already shows lower absolute held anonymous residency with full delivery
capacity: 9,790 versus 10,012 KiB at 128 held connections. Its larger increment
above the post-churn baseline is not a total-memory regression or a leak.

## Decision

Retain one full TLS plaintext record of delivery capacity at client connection
construction. Remove the experimental Direct-specific capacity promotion.
Keep the canonical cancellation-safe TLS reader, bounded buffered-record batches,
and direct reads into retained delivery storage. No timeout, security check,
resource ceiling, or performance threshold changes.

Reject both smaller-initial-capacity variants rather than accepting a protected
throughput regression for idle-memory savings. Preserve all failed measurements.
This decision restores the earlier capacity policy; it does not substitute
historical measurements for qualification of a new release binary.

## Revisit conditions

Revisit only with allocation or syscall evidence identifying a different bounded
ownership strategy, followed by matched setup, residency, Direct, framed and
bidirectional measurements that satisfy the unchanged performance contracts.
Do not infer an allocation leak from incremental RSS or anonymous residency.
