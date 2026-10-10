# Roadmap

[简体中文](../../zh-CN/development/roadmap.md) | English

rust-reality will evolve in three qualified stages. Each stage establishes a stable baseline before the next begins.

The project keeps one public compatibility boundary: VLESS + REALITY behavior must remain compatible with current Xray-core clients. Internal implementation may evolve aggressively as long as correctness, interoperability, traffic behavior, and protected performance do not regress.

## Configuration compatibility

Existing valid rust-reality server JSON remains valid across this roadmap and should not require deployment rewrites.

New capabilities may introduce optional configuration where new information is genuinely required, but existing deployments keep their current meaning. Runtime tuning should remain derived automatically where practical.

## Phase 1 — LINE → LANDING reliability

Tracking: [#253](https://github.com/jacek4yang/rust-reality/issues/253)

First establish a production-grade reliability baseline for the existing LINE → LANDING path.

The phase focuses on current NXR/Handoff stability, long-lived connection survival, multi-LINE pressure, overload behavior, observability, and non-regression. It deliberately avoids broader protocol or client expansion.

Phase 2 starts only after this baseline passes correctness, interoperability, fault, soak, resource, and performance qualification.

## Phase 2 — unified rust-reality client

Tracking: [#254](https://github.com/jacek4yang/rust-reality/issues/254)

Absorb rust-reality-client into this repository and make client operation a first-class role of the shared rust-reality core.

Support both single-LINE and flexible multi-LINE use, including independent local inbounds that may select different LINEs or LINE groups. The public connection to each LINE remains standard VLESS + REALITY; the client does not need to know whether the selected LINE later uses direct, NXR, Handoff, or a landing.

Phase 3 starts only after both single-LINE and multi-LINE client operation are stable, interoperable, fault-tolerant, and performance-qualified against the Phase 1 baseline.

## Phase 3 — unified high-performance transport core

Tracking: [#255](https://github.com/jacek4yang/rust-reality/issues/255)

Complete the transition to a general high-performance core for client, LINE, LANDING, direct, NXR, and Handoff deployments.

This stage owns the larger transport evolution: TCP and UDP flow support, optimized LINE → LANDING transport, multi-LINE/multi-LANDING operation, long-lived flow resilience, connection reuse, adaptive transport behavior, resource efficiency, and measured kernel/data-path optimization.

The exact implementation remains open to evidence gathered during Phases 1 and 2 rather than being fixed in advance.

## Qualification and deployment

Every phase must pass its own automated tests, interoperability checks, fault testing, soak testing, resource-pressure testing, and protected performance gates before it becomes the baseline for the next phase.

After Phase 3 is qualified, production rollout remains staged rather than all-at-once:

1. qualified LANDING deployment;
2. one LINE canary;
3. wider LINE rollout;
4. rust-reality client in single-LINE mode;
5. multi-LINE client operation;
6. broader production adoption.

Any stage may stop or roll back independently without requiring configuration rewrites.
