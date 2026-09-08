# ADR 0029: Retain automatic runtime worker selection

## Status

Accepted. A separate worker-count or runtime-topology setting is post-v2 work.

## Context

[Issue #219](https://github.com/jacek4yang/rust-reality/issues/219) characterizes
small Debian KVM guests on a locally pinned Intel i5-1240P. The completed T3c
comparison found 445.8 microseconds of server CPU per connection at one vCPU,
608.7 at two vCPUs/1 GiB, and 579.7 at two vCPUs/2 GiB. Restricting the same
two-vCPU workload to one CPU measured 440.1 microseconds. The second automatic
Tokio worker costs CPU per connection, but buys 16–27% setup throughput at
concurrency eight while losing at concurrency one.

This is LOCAL_KVM characterization. CPU affinity changes the client and harness
placement as well as the daemon's visible CPU count; it is not an isolated
before/after test of a new production worker setting. Intel measurements do not
establish AMD Zen performance. The production LINE has one vCPU already;
LANDING's useful worker count also depends on concurrent relay traffic.

## Decision

Keep automatic worker selection in v2. Do not add an unvalidated topology knob,
change production affinity, or change systemd semantics for this release. The
existing result demonstrates a throughput/CPU tradeoff, not a universally better
runtime policy. Resource recovery and bounded operation on one- and two-vCPU
guests remain release correctness gates.

## Consequences

There is no new configuration surface or deployment migration. The two-worker
CPU cost remains a known workload-dependent limitation. A future change must
isolate daemon worker count with client/origin placement held constant, retain
an A/A floor, and demonstrate useful CPU/session and CPU/GiB results without a
protected throughput or latency regression on the intended deployment envelope.

NUMA, a large thread-pool redesign, io_uring, AF_XDP, and send-zc are outside
this decision and remain outside v2 finalization.

## Evidence

Issue #219 T3c retains the four guest shapes, variance, steal observations,
CPU/session, and setup-throughput tradeoff. These checkpoints need no new run
to justify retaining the current policy; a future implementation needs its own
controlled comparison.
