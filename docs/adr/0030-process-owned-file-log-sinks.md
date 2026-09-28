# ADR 0030: Process-owned file log sinks

Status: Accepted

## Context

Connections retain their configuration generation across reloads. Creating a
new file logger for each generation gave the same pathname independent file
handles, byte counters and rotation locks. Old and new sessions could exceed
the configured file limit and race each other's rotation.

## Decision

The process authorities own a registry of weak references to file sinks, keyed
by canonical path. All live generations using that path share one file handle,
rotation lock and retention counter. Weak references allow unused destinations
to close; returning to a path still used by an older session reuses its writer.

Log filtering remains generation-local. Preparing a candidate logger does not
change a shared writer's limits. Only after the complete runtime candidate has
compiled does publication apply retention to the shared writer. Old loggers
cannot restore an earlier policy.

Startup, publication and rotation reconcile the active file and rotated-file
sizes. Successful ordinary writes update the cached sizes and enforce the total
bound without filesystem scans or temporary path allocations. A partial write
failure refreshes the active byte count before reporting the error.

## Consequences

The configured file bounds apply across reload generations. File logging keeps
its synchronous error contract and does not introduce an unbounded work queue.
External file changes are reconciled at the documented lifecycle boundaries.
The tests cover interleaved generations, changed retention, path aliases,
returning to an older destination and allocation-free rotation accounting on
ordinary writes.
