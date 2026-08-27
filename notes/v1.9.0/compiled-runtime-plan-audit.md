# CompiledRuntimePlan audit: the construct already exists

Status: **NO NEW CONSTRUCT REQUIRED.** The compiled-plan architecture is already
implemented under repository-native names. Introducing a `CompiledRuntimePlan` type
would add a boundary without reducing hidden coupling, which the project's own rule
forbids.

This is a negative result reached by reading the code, and it is worth as much as a
refactor: it prevents a large speculative rewrite of the control plane.

## The requested pipeline, mapped to what exists

```text
requested                        actual
---------------------------------------------------------------------------
JSON config / parse              serde Config
schema + semantic validation     validate_config, incl. #111 conflict rejection
legacy/new override resolution   resolve_policy(limits, overrides, …)  (#109/#111)
machine detection                MachineReport / MachineCapabilities
runtime policy derivation        StartupPlan::derive -> PolicyResolution
routing compilation              RoutingTable::compile -> CompiledRule/CompiledUserPolicy
user compilation                 AdaptiveUserMap
outbound compilation             OutboundRegistry / OutboundIndex -> CompiledOutbound
transport capability compilation TcpRelay + BackendReport (BackendCapability)
CompiledRuntimePlan              RuntimeSnapshot::compile(...)
immutable generation publication ArcSwap<RuntimeSnapshot>, generation: u64
```

## Every stated invariant is already satisfied

| invariant | evidence |
| --- | --- |
| immutable after publication | `current: ArcSwap<RuntimeSnapshot>`; snapshots are replaced, never mutated |
| generation-scoped | `RuntimeSnapshot { generation: u64, … }` |
| fully validated before publication | `validate_config` then `RuntimeSnapshot::compile`; publication is the final step |
| safe for concurrent reads | `ArcSwap` load, no lock on the read path |
| cheap to share | per-connection state is one `Arc<ConnectionRuntime>` clone |
| compact enough for hot-path use | see below — no `Config` on the per-connection path |
| independent from serde representation | see below |

## The per-connection path already sees no user-facing configuration

`run_connection` receives exactly:

```rust
async fn run_connection(
    state: Arc<ConnectionRuntime>,
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    connection_permit: AdmissionPermit,
    logger: &Logger,
) -> io::Result<()>
```

and `ConnectionRuntime` is:

```rust
struct ConnectionRuntime {
    tag: Arc<str>,
    governor: ResourceGovernor,
    handler: ConnectionHandler,   // compiled RealityAcceptor + VisionHandler, or NXR/Handoff
}
```

No `Config`, no serde struct, no `HashMap<String, _>`.

`VisionHandler` — the per-session handler — holds only compiled tables and scalars:

```rust
pub struct VisionHandler {
    outbounds: OutboundRegistry,
    routing: RoutingTable,
    relay: TcpRelay,
    request_timeout: Duration,
    io_timeout: Duration,
    dns_strategy: DnsStrategy,
    dns_timeout: Duration,
}
```

Every `snapshot.config` read in `production.rs` is startup reporting (lines 434,
482, 483), startup construction (696, 709), a background asset-reload interval
(829, 838), or the reload compatibility comparison in `ensure_hot_compatible`
(1146–1192). **None is on the per-connection path.** The snapshot retains `Config`
because reload must compare candidate against current — a legitimate control-plane
use, not a hot-path one.

## Compact identifiers and cardinality-aware structures already exist, with measured crossovers

The brief lists compact IDs and cardinality-aware lookup as opportunities. Both are
already implemented, and — more importantly — already **measured**:

```rust
// src/user_map.rs
/// Measured crossover on the supported release build: a sorted, contiguous
/// lookup wins both hit and miss at 64 UUIDs; SipHash wins legitimate hits at
/// 128. Use the lower measured boundary rather than extrapolating between them.
const SORTED_USER_LIMIT: usize = 64;
pub(crate) enum AdaptiveUserMap<V> { Sorted(Box<[(UserId, V)]>), Hashed(HashMap<UserId, V>) }
```

```rust
// src/server/outbound.rs
/// Benchmarked crossover for immutable outbound tags: sorted lookup is faster
/// at one and four entries; hashing wins by sixteen entries.
const SORTED_OUTBOUND_LIMIT: usize = 4;
enum OutboundIndex { Sorted(Box<[(Box<str>, CompiledOutbound)]>), Hashed(HashMap<Box<str>, CompiledOutbound>) }
```

Routing selection returns borrowed views (`outbound(&self) -> &str`,
`rule_name(&self) -> &str`) and allocates nothing. Every `format!` and
`to_string()` in `routing.rs` sits at line 1675 or later, inside the test module
that synthesises random rules.

So the answer to "does compact ID compilation matter here" is: it was already
done, against measured crossover points, and re-deriving it would repeat work.

## Residual candidate, recorded and deliberately not taken

One per-accept lookup remains:

```rust
let Some(state) = snapshot.connections.get(&address).cloned() else { … };  // line 1705
```

`connections` is `HashMap<SocketAddr, Arc<ConnectionRuntime>>` keyed by the
**listener** address. Production cardinality is 1–2 entries (dual-stack `443`), and
the lookup runs once per accept — not per record and not per relay chunk.

By the repository's own measured convention (`SORTED_OUTBOUND_LIMIT = 4`), a sorted
or linear structure would be faster at that cardinality. But at one lookup per
accepted connection on a 1–2 entry map, the effect is far below what the formal
evaluator can resolve, so changing it would be manufacturing an improvement rather
than measuring one. Recorded as a candidate, not implemented.

## What this means for the program

The architecture task as framed is complete. The remaining genuine work in this area
is not "build a compiled plan" but:

1. **Generation-isolation mutation tests.** The invariants are satisfied by
   construction, but the brief asks for them to be mutation-tested. There is no test
   that fails if generation isolation is broken — the existing layering gates cover
   module dependencies, not generation crossing. This is a real gap and a good next
   PR.
2. **Runtime report provenance.** `runtime explain` already prints per-field
   `derived`/`override`/`default`. After #109 it should also name *which channel*
   supplied an override, since there are now two input languages.
3. **Recommended-configuration simplification.** Independent of any code change:
   documentation should lead with `profile: dedicated` plus objective, not a full
   numeric block.

## Epistemic status

```text
measured    per-connection path receives no Config and no serde struct
measured    user and outbound lookups are compiled with documented measured crossovers
measured    routing selection allocates nothing; its string work is test-only
measured    generation publication is ArcSwap over an immutable generation-scoped snapshot
established no new CompiledRuntimePlan construct is required
open        generation-isolation invariants are not mutation-tested
open        override provenance is not reported per channel
not taken   per-accept 1-2 entry HashMap, below measurable threshold
```
