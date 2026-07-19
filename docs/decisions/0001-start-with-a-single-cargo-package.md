# ADR 0001: Start with a single Cargo package

- Status: Accepted
- Date: 2026-07-19

## Context

The project will eventually contain several substantail protocol and runtime
components, including VLESS, VLESS Encryption, TLS 1.3, REALITY, Vision,
routing, outbound transports, configuration, and observability.

These boundaries are not yet proven by implementation. Splitting the project
into multiple crates before the interfaces stabilize would introduce public
APIs, dependency relationships, feature coordination, and longer refactoring
cycles without providing an immediate correctness benefit.

The initial implementation also needs to remain easy to inspect while the
networking and Rust concepts are learned through production code.

## Decision

Start with one Cargo package containing:

- a library target in `src/lib.rs`;
- a binary target in `src/main.rs`;
- private modules grouped by protocol and runtime responsibility;
- unit tests next to implementation code;
- integration tests under `tests/`;
- long-lived diagnostic programs under `examples/`.

Core protocol and runtime logic must live in the library target. The binary
target should remain responsible only for process-level concerns such as
configuration loading, runtime initialization, signal handling, and startup.

A module may be extracted into a separate crate only after at least one of
these conditions is demonstrated:

1. it has a stable and independently testable API boundary;
2. it requires dependencies that should not be inherited by the rest of the
   project;
3. it has a mterially different release, fuzzing, or compilation lifecycle;
4. it is reusable outside the server binary;
5. extraction measurably improves build isolation or maintenance.

## Consequences

### Positive

- Refactoring remains inexpensive while protocol boundaries are evolving.
- The complete implementtation is easier to navigate and debug.
- Tests can access internal implementation details without premature public
  APIs.
- Cargo configuration and feature management remain simple.

### Negative

- Compilation units may become larger as the project grows.
- Internal modules can become coupled if boundaries are not enforced.
- A later crate extraction may require deliberate API design and migration.

## Revisit criteria

Revisit this decision when module boundaries are supported by working code,
tests, dependency graphs, and measured build or maintenance costs.
