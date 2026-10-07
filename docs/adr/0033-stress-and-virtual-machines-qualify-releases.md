# ADR 0033: Stress and virtual machines qualify releases

Status: Accepted

## Context

Requiring operator-owned dual-VPS infrastructure for every publication couples
product qualification to access to a particular deployment. WAN behavior is
important deployment evidence, but its uncontrolled latency and background
traffic are not a reproducible test of ownership, resource reclamation, or
protocol state transitions. Long elapsed time alone is also not a causal test:
a one-day run neither proves a month of correctness nor identifies the owner
of retained memory.

The [Phase 1 memory experiments](../../benchmarks/evidence/issue-261/phase-one/README.md)
separate live occupancy, retained container capacity, allocator-free memory and
resident pages using repeated finite workloads and explicit expiry inputs.
A [source-bound KVM fault experiment](https://github.com/jacek4yang/rust-reality/blob/19c625645b3fa2cf1f897bd63e670da515529fc7/benchmarks/evidence/issue-261/phase-one/established-io-classification-manifest.json)
exposes a concrete production error-classification defect by killing LANDING
under established NXR traffic; a short repeat discriminates the correction.
These results favor deliberate state transitions over blind time extension.
They do not establish equivalence between a virtual network and a real WAN.

## Decision

The mandatory multi-node release qualification may run in isolated QEMU system
VMs. It combines exact-candidate interoperability, repeated stress/recovery
cycles, resource-pressure tests, deterministic tests of time-based boundaries,
and an explicit multi-node fault matrix. Its canonical acceptance contract is
in the [release process](../en/release-process.md#tier-b--stress-and-isolated-multi-node-qualification).
Passing that contract permits publication without dual-VPS access or an
additional hours-long, overnight, or multi-day soak.

The engineering constitution, full local gate, exact-head CI and Security,
applicable native qualification, integrity and resource thresholds, provenance,
review, and all-or-nothing release packaging remain required. A failed required
check is not made optional by calling it a soak. This decision changes the
required environment and the evidence model, not those gates or their limits.

Stress accelerates operation counts, contention and occupancy transitions;
it does not accelerate wall clocks, external key expiry, kernel timers or rare
calendar-dependent events. Relevant expiry, reload/generation, inactivity,
write-stall and cancellation boundaries need deterministic tests where time is
an explicit input or the test runtime supports controlled time. Production
clocks and deadlines must not be shortened to manufacture coverage. Neither
stress volume nor a VM pass may be described as a simulated month of uptime.

Real-WAN canaries remain separately labelled deployment validation. They are
not prerequisites for publishing a product artifact. A local qualification
does not authorize production access or mutation, waive rollback safeguards,
or establish a deployed service's health. The existing dual-VPS runner and
its fail-closed contract retain their WAN-specific identity; VM evidence must
not be relabelled to satisfy that evaluator.

## Consequences and limits

A release can be qualified reproducibly without renting or mutating live
infrastructure. Retained raw samples, fixture/evaluator source identities,
complete case results, and causal explanations of retained resources make the
claim reviewable. QEMU user-mode execution alone is not a multi-kernel test.
Single-host VMs share hardware and cannot establish real-WAN routing, cloud
firewall, NAT, MTU, host-failure independence, or long-horizon reliability.
Those untested properties remain explicit deployment risks.

Extended soaks remain useful scheduled, post-release, or hypothesis-driven
experiments. Extend a run because a named time-dependent mechanism requires
it, not to convert elapsed time into a blanket reliability claim. Revisit this
decision if incidents identify a failure class the specified stress, temporal
and fault tests cannot expose; add a discriminating test rather than an
arbitrary longer waiting period.
