# Dedicated-machine resource mode

This document describes `runtime.resourceMode`, what the dedicated mode
detects and changes at startup, the exact budget arithmetic, and the pressure
model that keeps the process below the kernel and cgroup limits it derives
from.

## 1. What the mode is

```json
{ "runtime": { "resourceMode": "dedicated" } }
```

Two values, no other fields:

| Value | Meaning |
|---|---|
| `standard` | Default. Every budget derives from the inherited process limits; the process assumes nothing about what else runs on the machine. Behavior is exactly the historical one. |
| `dedicated` | The process declares that it owns the machine — or, under a container runtime, its cgroup. It budgets against measured machine resources and supervises its own memory pressure. |

The mode is a **cold setting**. It shapes the process-lifetime descriptor
budget, the soft-limit raise and the memory monitor, so a SIGHUP reload that
changes it is rejected (`the runtime resource mode requires a process
restart`); the last good generation keeps running.

## 2. Startup detection

In dedicated mode the process detects, once, before any listener is bound:

* soft and hard `RLIMIT_NOFILE`;
* soft and hard `RLIMIT_MEMLOCK` (the eBPF backends account pinned memory
  against it);
* the cgroup v2 of the current process (`/proc/self/cgroup` +
  `/sys/fs/cgroup`): `cpu.max`, `cpuset.cpus.effective`, `memory.current`,
  `memory.high`, `memory.max` — the literal `max` is treated as unbounded,
  and any absent or unreadable file degrades to "not reported" rather than
  to a fabricated value;
* fallbacks when the cgroup files are absent: `MemTotal` from
  `/proc/meminfo` and the CPUs visible to the process;
* the kernel relay backend capability summary, already emitted as
  `relay_backend_report`.

Everything is reported in one structured `machine_report` event at info
level. No field can carry a target, a peer or a configuration value. A real
startup looks like:

```json
{"event":"machine_report","resource_mode":"dedicated","fd_soft_limit":4096,
 "fd_hard_limit":524288,"fd_effective_soft_limit":524288,
 "fd_soft_raise_attempted":true,"fd_soft_limit_raised":true,
 "memlock_soft_limit":8388608,"memlock_hard_limit":8388608,
 "available_cpus":4,"cpu_period_us":100000,"memory_source":"cgroup_v2",
 "memory_current":9432547328,"memory_total":16192278528}
```

### The soft-limit raise

When the hard `RLIMIT_NOFILE` exceeds the soft limit, the dedicated mode
raises the process's **own soft limit to the hard limit** via `setrlimit(2)`.
This needs no privilege and touches nothing outside the calling process.
The example above is a real run started with `ulimit -Sn 4096`: the raise
took effect and the descriptor budget derived from the effective 524 288.

A failed raise is not fatal. The report records
`fd_soft_raise_attempted: true` with `fd_soft_limit_raised: false`, and the
derivation continues with the effective soft limit, whatever it is.

## 3. Budget derivation

### Descriptors

```text
effective_dynamic_fd_budget = effective_soft_limit - fixed_reserve - headroom
```

The fixed reserve is identical to standard mode (listeners, standard streams
and logger, runtime reactor, eBPF descriptors, uncancellable resolver
descriptors, the emergency reserve). Only the headroom policy differs:

| Mode | Safety headroom | Consequence |
|---|---|---|
| `standard` | `max(limit / 16, 64)` | ~94% of the limit minus reserve is admissible |
| `dedicated` | `max(limit / 10, 64)` | ~90% of the limit minus reserve is admissible |

The dedicated headroom is *larger*, not smaller: the process plans against
the raised limit and keeps a tenth of it for descriptor consumers it cannot
account for — libraries, resolver threads, kernel-side sockets. The
invariant `budget + reserve + headroom <= effective_soft_limit` holds under
both policies and is tested across the full limit range.

Per-resource costs are unchanged and are accounted exactly where the
resource is acquired: one unit per inbound socket, one per outbound socket,
two per directional splice, four per bilateral splice relay, BPF map and
program descriptors inside the fixed reserve. Dedicated mode does not
re-account them.

### Memory

The effective memory total is the finite cgroup `memory.max` when one is
set (capped by `MemTotal`), otherwise `MemTotal`. When neither is readable
the total is zero and the memory dimension is disabled rather than invented.
All watermarks are fractions of that total:

| Boundary | Fraction of total | Rationale |
|---|---|---|
| usable budget | 80% | one fifth held back for the kernel, socket buffers and the runtime, none of which is accounted per allocation |
| pressure enter | 60% | three quarters of the usable budget |
| pressure exit | 50% | a ten-point hysteresis gap |
| critical enter | 90% | below the hard cgroup/machine limit, early enough that refusing new work can still move the number |
| critical exit | 80% | exactly the usable budget: new work resumes only inside the process's own allowance |

Each tier has a separate enter and exit watermark, so a usage value
oscillating around any single threshold produces no transitions. Escalation
and recovery both advance one tier per sample.

## 4. The pressure model

Two dimensions feed one effective state:

* **Descriptors** — the existing `FdBudget` watermarks (high at 15/16 of
  capacity, low at 13/16). Descriptor `High` maps to the `Pressure` tier;
  the budget itself is the hard block, so the descriptor dimension never
  needs the `Critical` tier.
* **Memory** — a monitor task sampling cgroup `memory.current` (fallback:
  the resident set size from `/proc/self/statm`) once per second, advancing
  the watermarks above.

The effective state is the worst of the dimensions, published as one atomic
value. The monitor is the only writer; the read path is one atomic load.
There is no global mutex anywhere near the data path, and nothing is sampled
in a read, write or record loop. An unreadable sample keeps the previous
state — a monitoring gap never raises or clears an alarm by itself.

### Priorities

| State | New fallback | New handshake | New connection accept | New direct outbound dial | Established traffic |
|---|---|---|---|---|---|
| `Normal` | admitted | admitted | admitted | admitted | flows |
| `Pressure` | **refused** | **refused** | admitted | admitted | flows |
| `Critical` | refused | refused | **paused / failed fast** | **failed fast** | flows |

The ordering is deliberate: fallback work is shed first, then new
unauthenticated setup, and only at `Critical` does every new category pause.
Permits already held are never revoked, so established authenticated relays
and ordinary relay traffic continue through both pressure tiers. A
connection that races the `Critical` transition while the listener is parked
inside `accept` is closed immediately and reported once as
`connection_rejected{reason:resource_limit}`; the listener then parks on a
`Notify` wakeup — never a poll loop — and resumes automatically when the
hysteresis exit publishes a lower state. Shutdown stays prompt in every
state.

Calibration and benchmark work is a separate process in this codebase (the
`benchmark` subcommand); it needs no runtime hook and gets none.

## 5. What the mode never does

* It never touches a sysctl, a cgroup file, another process, or the hard
  resource limits. The only mutation anywhere in the dedicated startup path
  is raising the process's own soft `RLIMIT_NOFILE` up to its hard limit.
* It never admits beyond the derived budgets. The dedicated headroom relaxes
  the *default* fraction; the `budget + reserve + headroom <= limit`
  invariant is unchanged.
* It never burns CPU to "use" the machine, never pre-allocates memory it
  does not need, and runs no background "optimization" work. The only
  periodic task is the one-second memory sample.
* It never polls `/proc/self/fd`, never counts descriptors on the accept
  path, and never logs per connection for a sustained pressure condition.

## 6. Operational guidance

Use `dedicated` when the process is the single tenant of a machine, VM or
cgroup — the standard standalone and line/landing deployments. Keep
`standard` when other unpredictable workloads share the same descriptor
limit or memory cgroup.

The mode does not replace the unit file. Keep `LimitNOFILE=` in the systemd
unit: the raise can only reach the *inherited* hard limit, and the hard
limit is set by the service manager. The startup `descriptor_budget_report`
still prints the recommended value, and `machine_report` shows whether the
raise had anything to do.

If `memory_total` is `0` in the report, the host exposes neither a cgroup
v2 memory limit nor `MemTotal`; the descriptor dimension still works, but no
memory watermark exists. Treat that as a monitoring gap worth fixing, not as
headroom.

## 7. Observability

| Event | When |
|---|---|
| `machine_report` | once at startup, dedicated mode only |
| `descriptor_budget_report` | once at startup, both modes |
| `descriptor_pressure_changed` | on a descriptor-pressure transition, never per accept |
| `resource_pressure_changed` | on a combined-state transition, never per sample |
| `connection_rejected{reason:resource_limit}` | per connection refused while paused |
| `admission_limited` | per category refused by a limit or by the pressure state |

A sustained pressure condition costs two `resource_pressure_changed` lines
(enter, exit), regardless of how long it lasts.
