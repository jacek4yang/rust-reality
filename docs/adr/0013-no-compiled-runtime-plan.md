# ADR 0013: No compiled-runtime-plan construct; the runtime snapshot already is the compiled plan

## Status

Accepted as a negative result reached by reading the code. It prevents a
speculative rewrite of the control plane.

## Context

The question was whether the runtime needed a `CompiledRuntimePlan` construct —
an explicit compiled representation of the configuration before serving. The
audit mapped the requested pipeline to what already exists under
repository-native names:

```text
requested                        actual
---------------------------------------------------------------------------
JSON config / parse              serde Config
schema + semantic validation     validate_config, incl. override conflict rejection
legacy/new override resolution   resolve_policy(limits, overrides, …)
machine detection                MachineReport / MachineCapabilities
runtime policy derivation        StartupPlan::derive -> PolicyResolution
routing compilation              RoutingTable::compile -> CompiledRule/CompiledUserPolicy
user compilation                 AdaptiveUserMap
outbound compilation             OutboundRegistry / OutboundIndex -> CompiledOutbound
CompiledRuntimePlan              RuntimeSnapshot::compile(...)
immutable generation publication ArcSwap<RuntimeSnapshot>, generation: u64
```

## Findings

Every invariant a compiled plan would provide is already satisfied by
construction:

| invariant | evidence |
| --- | --- |
| immutable after publication | `current: ArcSwap<RuntimeSnapshot>`; snapshots are replaced, never mutated |
| generation-scoped | `RuntimeSnapshot { generation: u64, … }` |
| fully validated before publication | `validate_config` then `RuntimeSnapshot::compile`; publication is the final step |
| safe for concurrent reads | `ArcSwap` load, no lock on the read path |
| cheap to share | per-connection state is one `Arc<ConnectionRuntime>` clone |
| compact enough for hot-path use | no `Config` on the per-connection path |
| independent from serde representation | compiled tables, not serde structs |

The per-connection path receives no user-facing configuration:
`ConnectionRuntime` holds a tag, the resource governor, and the compiled
handler; `VisionHandler` holds only compiled tables and scalars. User and
outbound lookups are compiled with documented measured crossover points
(sorted structures up to 4 entries, hashing beyond), and routing selection
returns borrowed views and allocates nothing — every `format!`/`to_string()`
in the routing path is test-only.

## Decision

**Introduce no new `CompiledRuntimePlan` construct.** Doing so would add a
boundary without reducing hidden coupling. The architecture task as framed is
complete.

Two known residuals are recorded deliberately:

1. One per-accept `HashMap` lookup keyed by the listener address (production
   cardinality 1–2, once per accept, not per record) is below what the formal
   evaluator can resolve; changing it would manufacture an improvement rather
   than measure one.
2. Generation-isolation invariants are satisfied by construction but not
   mutation-tested; a test that fails if generation isolation is broken is a
   real gap and a good future contribution.

## Revisit conditions

- Revisit only if a measured control-plane constraint appears that the current
  `RuntimeSnapshot` shape cannot express — not for aesthetic symmetry with the
  benchmark configuration compiler.

## Evidence

- `src/runtime/` snapshot compilation and publication path.
- Routing/user/outbound compiled structures with their measured crossovers.
- The per-accept lookup at `src/server/` (listener-address keyed
  `HashMap<SocketAddr, Arc<ConnectionRuntime>>`).
