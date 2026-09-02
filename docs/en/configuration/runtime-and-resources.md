# Runtime and resources

English | [简体中文](../../zh-CN/configuration/runtime-and-resources.md)

What this process is allowed to consume. Every value here has a default
derived from the machine, and on most nodes the whole section should be
absent.

## Read this first

Twenty-five ceilings, buffer sizes, and pool bounds are derived at startup
from the CPU count, memory, and descriptor limit this machine actually has.
The derivation runs before the first listener binds, uses no benchmark and no
network, and is deterministic.

That means the honest default advice is: **write nothing here, and look at
what was derived.**

```shell
rust-reality explain -c /etc/rust-reality/config.json
```

```
machine: 4 effective cpus (4 logical), 524288 descriptors, 16194637824 bytes memory (cgroup_v2)
posture: profile auto -> standard, tuning startup, objective balanced
runtime: 4 worker threads, 512 blocking threads (tokio-default)
limits: 25 values, all derived from the machine (--json for the table)
```

`--json` prints every value with its provenance, floor, cap, and the
multiplier the objective applied. That is the table to read before deciding
anything on this page is worth setting.

## `profile`

```json
{ "runtime": { "profile": "dedicated" } }
```

The one field most nodes should consider, because it answers a question the
machine cannot: **does this process own the box?**

| value | meaning |
| --- | --- |
| `auto` (default) | look for a cgroup tenancy boundary and decide |
| `shared` | other things run here; budget conservatively |
| `dedicated` | this process owns the host or cgroup |

Under `dedicated` the process raises its own soft `RLIMIT_NOFILE` toward the
hard limit, plans against relaxed headroom, sizes the Tokio thread pools from
the cgroup-aware CPU view, and starts a memory pressure monitor that refuses
new work before a cgroup OOM kill can arrive.

Under `shared` it does none of that, because a process sharing a host has no
business sizing its own thread pools or claiming descriptors that other
processes need.

`auto` looks for an actual tenancy boundary. It gets it right on a container
with limits set and on a plain VPS; it cannot know that the VPS you are on is
also running your database. If it is, say `shared`.

## `tuning`

```json
{ "runtime": { "tuning": "adaptive", "statusFile": "/run/rust-reality/status.json" } }
```

| value | meaning |
| --- | --- |
| `startup` (default) | derive once at startup, then never move |
| `adaptive` | derive at startup, then adjust selected soft ceilings while running |

`adaptive` lets a controller move a few admission ceilings and the direct-dial
rate gate in response to observed pressure. It never exceeds the startup
derivation — that is a hard ceiling — and it never touches anything sized at
startup, such as buffer sizes.

`statusFile` is only meaningful under `adaptive`, and stating it under
`startup` is refused rather than silently ignored. The controller writes a
snapshot there at startup and on every change:

```shell
jq . /run/rust-reality/status.json
```

There is no command that reads it back. Process status belongs to
`systemctl status`, logs to `journalctl`, and configuration to `explain`; the
status file is a machine-readable artifact for whatever you already use to
collect metrics.

## `objective`

```json
{ "runtime": { "objective": "throughput" } }
```

| value | favours |
| --- | --- |
| `balanced` (default) | neither |
| `latency` | smaller buffers, tighter concurrency |
| `throughput` | larger buffers, more concurrency |

The objective scales the derived values rather than replacing them, and the
caps and floors still apply afterwards — so `throughput` cannot exceed what
the machine supports, and `latency` cannot under-provision below a usable
floor.

The relay buffer moves one tier per step among 16 KiB, 32 KiB, and 64 KiB. It
cannot leave those three.

## `limits`

```json
{
  "role": "entry",
  "listeners": [
    {
      "port": 443
    }
  ],
  "reality": {
    "cover": "www.microsoft.com:443",
    "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE"
  },
  "users": [
    {
      "id": "11111111-1111-4111-8111-111111111111",
      "shortIds": [
        "0123456789abcdef"
      ]
    }
  ],
  "routing": {
    "default": "direct"
  },
  "runtime": {
    "profile": "dedicated",
    "tuning": "adaptive",
    "objective": "throughput",
    "statusFile": "/run/rust-reality/status.json",
    "limits": {
      "maxConnections": 8000
    }
  }
}
```

Eight fields, all optional. **Presence means pinned** — a value you write is
honoured even when it equals what would have been derived, because writing it
down is the signal.

| field | what it bounds |
| --- | --- |
| `maxConnections` | simultaneous connections admitted |
| `maxHandshakes` | simultaneous handshakes in progress |
| `clientHelloTimeoutMs` | waiting for a client's first flight |
| `handshakeTimeoutMs` | completing a handshake |
| `connectTimeoutMs` | dialling a destination |
| `fallbackTimeoutMs` | proxying an unauthenticated connection to the cover |
| `splice` | use the kernel zero-copy relay path |
| `pipePool` | pool the pipes that path needs |

The four timeouts are protocol security parameters rather than machine
budgets, so they are never derived: unpinned, they take their documented
defaults, and `explain` reports them as `default` rather than
`startup-derived`.

`explain` shows exactly what you pinned:

```
limits: 1 pinned, 24 derived (--json for the table)
  governor.maxConnections = 8000
```

### When pinning is justified

- **A measured problem.** You have evidence the derived value is wrong for
  this workload — not a suspicion.
- **A hard external bound.** A ceiling imposed by something outside this
  process that the derivation cannot see.
- **An exotic kernel.** `splice` and `pipePool` exist because a kernel that
  reports the capability and then misbehaves needs an escape hatch. On a
  normal kernel, leave them alone.

Pinning `maxConnections` above what the descriptor budget supports does not
raise the budget; the process still refuses work it has no descriptors for,
and the pin has bought nothing. `explain --json` shows the floor and cap for
every field, which is the check to make before pinning.

### What you cannot pin

Relay buffer sizes, pool bounds, warm connection sizing, the direct-dial
barrier, replay cache capacity, and DNS cache internals are derived and have
no fields. They are implementation detail: their right values follow from the
machine, and an operator who pins them is guessing against a measurement.

That is the line this project draws — meaningful operator policy stays
configurable, implementation detail does not become a knob.

## `runtime` is cold

Every field here is cold. A reload that changes any of them is refused with
`runtime profile, tuning, or resource-mode changes require a process restart`,
and the running configuration keeps serving.

That is a consequence, not a policy: the descriptor budget, the memory
monitor, the thread pools, and every admission ceiling were sized against
these values before the first listener bound. Changing them without rebuilding
all of that would mean a process whose ceilings and pools disagree.

So plan a restart:

```shell
rust-reality check -c /etc/rust-reality/config.json
rust-reality explain -c /etc/rust-reality/config.json
sudo systemctl restart rust-reality
```

`explain` before the restart is the point. It tells you what the new values
resolve to, on this machine, before you take the service down to find out.

## The advisories

`explain` ends with advisories when the host's own settings will limit what
this process can do:

```
advisories:
  kernel tuning is advisory only: the process never writes sysctls, other
  processes' rlimits, or cgroup files
  net.ipv4.tcp_rmem and net.ipv4.tcp_wmem maxima below the 64 KiB relay
  buffer tier can throttle large transfers
```

They are advisory in the strict sense: this process never writes a sysctl,
another process's rlimit, or a cgroup file. It reports what it noticed and
leaves the machine alone. Acting on them is a host administration decision,
not a configuration one.
