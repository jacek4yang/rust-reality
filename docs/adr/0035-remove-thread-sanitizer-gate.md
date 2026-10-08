# ADR 0035: Remove the ThreadSanitizer gate

Status: Accepted

## Context

ThreadSanitizer repeatedly reports a Tokio I/O registration/readiness race,
including in a standalone Tokio-only reproducer. This does not establish
whether the report is a dependency defect or an instrumentation limitation.
Safe Rust excludes data races only when its unsafe dependencies uphold their
contracts; it is not proof that this dependency report is impossible.

## Decision

At the operator's explicit request, remove the ThreadSanitizer workflow job
and active invocation rather than modifying production architecture to satisfy
this detector. This is a deliberate reduction in dynamic race-detection
coverage, not a fix or a passing result for the historical reports.

Keep ordinary replay, Handoff, NXR, outbound, pre-authentication, warm-pool and
Vision tests, ASan/LSan, fuzzing, dependency checks, resource qualification and
protocol interoperability. Do not introduce suppression files or rename a
failed TSan result as success. Retain historical reports and investigation
receipts on the PR. New exact-head Security results describe the revised suite.

## Consequences

ASan/LSan and ordinary tests do not replace TSan's race detection. Loom and
Miri can strengthen focused concurrency/unsafe tests but are not claimed as
implemented replacements in this decision. Known issues must be disclosed;
passing the declared release suite never guarantees absence of all bugs.
The independent QEMU observation-consistency defect remains unresolved and
is not waived by this decision.

## References

- [Rust data races and race conditions](https://doc.rust-lang.org/nomicon/races.html)
- [Tokio Loom workflow](https://github.com/tokio-rs/tokio/blob/master/.github/workflows/loom.yml)
- [Tokio Valgrind stress workflow](https://github.com/tokio-rs/tokio/blob/master/.github/workflows/stress-test.yml)
- [Quinn CI and focused Miri checks](https://github.com/quinn-rs/quinn/blob/main/.github/workflows/rust.yml)
