# ADR 0066: Reject duplicated upload storage

Status: Rejected

## Context

Coalescing already available TLS records can reduce upload CPU cost without
waiting for more application bytes. The experiment at `b436d294` retains both
an enlarged local plaintext buffer and an enlarged TLS write buffer.

The [three-block diagnostic](../../benchmarks/evidence/releases/v2.3.0/client-paired-upload-b436d29/archive-manifest.json)
compares this candidate with `1c1930f` at concurrencies 1 and 64, using five
16-MiB workloads and identical fixed CPU policies. All 14,040 requests succeed.
Direct-upload CPU at concurrency 1 decreases in every block, with median ratio
0.9715; framed-upload CPU at concurrency 1 has median ratio 0.8145. These are
observations, not resolving confidence bounds or release acceptance.

The [rotated residency diagnostic](../../benchmarks/evidence/releases/v2.3.0/client-paired-upload-memory-b436d29/assessment.json)
completes 3,456 verified HTTPS transfers. After upload on 128 held connections,
anonymous memory is 15,648-15,724 KiB, versus 10,328-10,480 KiB for `1c1930f`
and 10,448-11,048 KiB for `d72abc2`. All nine runs recover descriptors after
closure. This is not a long-term leak verdict, but the duplicate retained
storage is a clear resource cost.

## Decision

Reject retaining separate enlarged plaintext and ciphertext upload buffers.
Passing functional tests and lower CPU cost do not override protected resource
contracts. Preserve the raw diagnostic results, including the CPU benefit and
memory failure; do not relabel this experiment as release-qualified.

## Revisit conditions

Reuse one connection-owned allocation for local input and final AEAD record
slots. Keep the existing record protection, KeyUpdate, deadlines and cancellation
guard. Any in-place framing must match the canonical encoder byte for byte,
with fuzz coverage and boundary tests. Requalify residency and every protected
performance cell; source-level allocation bounds alone are insufficient.
