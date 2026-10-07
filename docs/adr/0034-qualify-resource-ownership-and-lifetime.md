# ADR 0034: Qualify resource ownership and lifetime

Status: Accepted

## Context

[ADR 0033](0033-stress-and-virtual-machines-qualify-releases.md) preserved the
historical resource proxies while changing the qualification environment.
[The retained candidate verdict](../../benchmarks/evidence/issue-261/phase-one/candidate-1da34e3-qualification-verdict.json)
contains two failures: a native PSS tail slope above 2 MiB/hour, and recovered
LANDING descriptors above 256. Those results remain failures under their
original contracts. Neither changing the contract nor subsequently passing a
new campaign changes their meaning.

The descriptor census attributes 244 descriptors to 122 empty retained pipes,
within the startup-derived pool capacity. The memory experiments distinguish
expired replay occupancy, retained container capacity, and allocator-free
resident pages. These observations expose limits of the proxies: a fixed FD
ceiling can reject intended bounded capacity, and a short residency slope does
not establish whether live ownership is accumulating. Merely labelling a
resource as pooled, or observing a flat slope, also cannot establish safety.

## Decision

This decision supersedes only ADR 0033's preservation of recovered LANDING
`FD <= 256` and slope-based memory acceptance. Its system-VM environment,
correctness, isolation, exact-candidate, fault, package, and authorization
requirements remain in force.

The executable acceptance contract is
[`benchmarks/contracts/stability.json`](../../benchmarks/contracts/stability.json).
Freeze it, the source, evaluator, workload, environment and executables before
qualification. Evidence parsing is strict and offline evaluation distinguishes
PASS, FAIL, NOT RUN and INVALID. Missing observations never establish PASS.
Predetermined cycle indices, concurrency, observation offsets, tolerance and
deadlines prevent omitted cycles or retrospective window selection.

Reconcile the external descriptor census with actual startup policy: fixed
non-socket descriptors, listener sockets, warm sockets, active session sockets,
active relay descriptors and retained pipe pairs have separate owners. Count
reserved permits separately from descriptors already opened: admission reserves
before creating a descriptor. Retained pipes must be empty, within configured
capacity, and backed by held permits. Unexplained descriptors fail. The existing
LINE recovery and role-specific peak FD ceilings remain additional bounds.

Memory acceptance combines deterministic owner/lifetime regressions with
fixed-work resource qualification. Completed connections, cancelled work,
retired generations and expired replay entries release their resources within
existing deadlines; idle expiry reclamation runs on the one-second resource
maintenance cadence without changing authentication windows. Debug ownership
observations use that cadence and generation/listener lifecycle boundaries,
with no allocator census or management endpoint. Saturated-container reuse tests must demonstrate stable
retained storage and permit ownership. Persistent pools retain only documented
bounded capacity. Unattributed cumulative retention blocks qualification;
allocator-free bytes are not a substitute for owner evidence. Preserve absolute
RSS/thread envelopes, pressure recovery and OOM rejection. RSS/PSS slopes are
diagnostics, with no acceptance threshold.

Every predefined cycle retains baseline, load and recovered observations for
each exact process. Payloads and received prefixes are byte-exact; upload
receipts must be fresh and unique. Process replacement, missing case coverage,
changed binaries, panics, OOMs and unexpected protocol/authentication rejection
cannot pass. Execution, collection and verdict calculation remain separate
within the tooling workspace. Failed attempts retain available raw evidence,
terminal status and final identity-check outcomes; finalization errors do not
replace the original failure.

## Consequences

The replacement is a new qualification transaction, not a waiver for the two
historical failures. Full local gates, exact-head CI/Security, native
interoperability/mechanism/pressure qualification and the complete multi-node
campaign still apply to the frozen candidate. Deterministic source-level tests
complement executable observations; they do not manufacture missing runtime
measurements or justify invented zero counts.

No public management API, production allocator instrumentation, generic VM
framework, compatibility parser or live deployment authority follows from this
decision. Real-WAN evidence and its existing evaluator stay separate. Revisit
this contract when a demonstrated defect escapes its ownership, temporal or
fault coverage, adding a discriminating test and retaining the failed receipt.
