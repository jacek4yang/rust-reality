# File-descriptor pressure and kernel relay backends

This document covers the descriptor admission architecture added after a
production `EMFILE` incident, and the current readiness of each kernel relay
backend.

## 1. What happened

A production server terminated with:

```text
error: listener accept failed
```

The syscall trace showed:

```text
pipe2(..., O_NONBLOCK|O_CLOEXEC) = -1 EMFILE (Too many open files)
pipe2(..., O_NONBLOCK|O_CLOEXEC) = -1 EMFILE (Too many open files)
accept4(..., SOCK_CLOEXEC|SOCK_NONBLOCK) = -1 EMFILE (Too many open files)
```

with `Max open files  soft=1024  hard=1048576`.

Three independent defects combined:

1. The listener loop propagated every accept error, so a recoverable `EMFILE`
   became a fatal process error.
2. Nothing in the process read `RLIMIT_NOFILE`. The stock configuration permits
   roughly 24 000 descriptors; the inherited soft limit was 1 024. The
   configuration was satisfiable only when started from the shipped systemd unit
   (`LimitNOFILE=1048576`).
3. Splice relays created two pipe pairs — four descriptors — with no reservation
   of any kind.

## 2. Descriptor budget

### Derivation

At startup, before any listener is bound:

```text
effective_dynamic_fd_budget = soft_rlimit - fixed_fd_reserve - safety_headroom
```

The fixed reserve is deliberately pessimistic:

| Component | Reserved |
|---|---|
| Listening sockets | one per configured inbound |
| Standard streams and logger sink | 4 |
| Runtime epoll, eventfd and wakers | 16 |
| Uncancellable resolver descriptors | 32 |
| Emergency reserve | 1 |

The safety headroom is `max(soft_limit / 16, 64)`.

Resolver descriptors are reserved rather than admitted because a cancelled
`TcpStream::connect` cannot cancel the blocking `getaddrinfo` underneath it;
those descriptors outlive the connection that asked for them.

### Policy

Exactly one policy, chosen and tested:

* **Refuse to start** when the soft limit cannot cover the fixed reserve plus a
  minimum viable dynamic budget of 64 units. The error names the measured limit
  and the required value:

  ```text
  the process file-descriptor soft limit is 64 (hard limit 1048576) but at
  least 182 is required to serve traffic safely; raise it with
  `ulimit -n 182` or `LimitNOFILE=182` in the unit file
  ```

* **Clamp downward and warn once** when the configured peak exceeds what the
  limit permits. The startup `descriptor_budget_report` names both numbers and
  the soft limit that would avoid clamping.

Under no policy does the process start with a configuration it cannot honour and
then discover the problem in `accept4`.

`maxConnections` remains a protocol limit. It is not lowered; the descriptor
budget simply binds first when it is the tighter constraint.

### Admission

`FdBudget` is a strict upper-bound permit counter.

* The fast path is one relaxed load and one `compare_exchange_weak`. There is no
  mutex anywhere in the module.
* The in-use count can never exceed capacity, even transiently, under any
  interleaving.
* `FdPermit` releases in `Drop`, so normal completion, error, `?` propagation,
  timeout, cancellation and task abort all release through one path.
* Release uses a *checked* subtraction. A saturating release would silently
  absorb a double-release bug and leak capacity over time; the checked form
  records the underflow so a test can fail on it.
* Waiting under pressure is a bounded `Notify` wakeup, never a poll loop. The
  waiter registers before the final re-check, so a release landing in between
  cannot be missed.

Conservative unit costs:

| Resource | Units |
|---|---|
| Accepted inbound socket | 1 |
| Connected outbound socket | 1 |
| Live connector candidate | 1 |
| Bidirectional splice relay | 4 |

The count over-reserves rather than modelling kernel-internal objects. It is a
reservation, not a measurement.

### Pressure and hysteresis

Pressure is entered at 15/16 of capacity and left at 13/16. The gap exists so a
burst of releases does not re-enter pressure on the next accept. Pressure
logging is transition-based, so a sustained pressure condition costs two log
lines rather than one per connection.

The process never polls `/proc/self/fd` for admission.

## 3. Listener recovery

Acceptance is three phases with distinct failure semantics:

```text
accept  ->  configure  ->  admit
```

`TcpAcceptor::accept_only` performs only the accept. `configure_accepted`
applies `TCP_NODELAY` separately, so a per-connection socket-option failure
closes that stream, releases its permit, emits one
`connection_rejected{reason:socketConfiguration}` and continues accepting. The
previous implementation combined both into one `io::Result` and could terminate
the listener over a single connection's option failure.

Accept errors are classified from raw `errno`, not `ErrorKind`:

| Class | Errnos | Response |
|---|---|---|
| `wouldBlock` | `EAGAIN` | retry, no log |
| `transient` | `EINTR`, `ECONNABORTED`, `EPROTO`, `ECONNRESET`, `ENETDOWN`, `ENETUNREACH`, `EHOSTDOWN`, `EHOSTUNREACH`, `ENONET`, `ETIMEDOUT`, `EPERM` | retry immediately, bounded log |
| `descriptorPressure` | `EMFILE`, `ENFILE` | emergency-FD recovery, backoff, never terminate |
| `memoryPressure` | `ENOBUFS`, `ENOMEM` | bounded exponential backoff |
| `fatal` | `EBADF`, `ENOTSOCK`, `EOPNOTSUPP`, `EINVAL`, `EFAULT` | terminate this listener only, with errno attached |
| `unknown` | anything else | backoff and retry |

`EINVAL` is classified as fatal deliberately, not blindly. Its only two
documented causes are invalid `accept4` flags and a socket that is not
listening. The flags are fixed by tokio and valid by construction, so the
remaining cause is a listener that can never accept again; retrying would spin.

Backoff starts at 5 ms, doubles, and is capped at 500 ms. It resets on the first
successful accept.

### Emergency reserve descriptor

One descriptor is held open on `/dev/null` for the process lifetime.

Admission bounds only what *this* process accounts for. A descriptor can still
be consumed by a library, a resolver thread, or another process against the
shared `ENFILE` limit. When that happens `accept4` returns `EMFILE` with a full
backlog and no way to drain it.

On an unexpected `EMFILE` the reserve is released, one accept is attempted with
a 1 ms bound, the accepted socket is closed immediately, and the reserve is
reacquired. The peer observes a close rather than a hang and the backlog
advances by one. Failure to reacquire is recoverable: the next pressure event
simply finds no reserve.

This is a last-resort path, not a substitute for correct admission.

## 4. Splice descriptors

A bidirectional splice relay creates two pipe pairs. Four units are acquired
*before* `pipe2`, and the permit is owned by the same object as the pipes.

When units are unavailable the backend declines. Declining is safe because it
happens before any byte is transferred, so the caller falls through to the
buffered backend without replaying the connection — the no-fallback-after-
transfer invariant is preserved.

If the second pipe pair fails, the first is closed and all four units are
released. Releasing units that were never spent is the conservative direction.

## 5. Backend readiness

A probe result does not mean production traffic can use a backend. The current
honest state of each:

| Backend | Kernel supported | Runtime implemented | Automatically eligible |
|---|---|---|---|
| buffered | n/a | yes | yes |
| splice | yes | yes | yes |
| sockhash | — | **removed** (D7) — see below | — |
| io_uring | — | **removed** — see the decision-record amendment | — |

### SOCKHASH

Removed (D7). The backend never armed in any production benchmark matrix, a
privileged A/B showed parity with splice (c1 1642 vs 1637, c4 3086 vs 3109,
c32 3245 vs 3282 MiB/s), and the unprivileged production deployment model
could never arm it, so the privileged complexity was deleted. The retained
evidence lives in `benchmarks/final/sockhash-ab/`. Stale `sockhash`,
`maxSockhashRelays` or `maxPinnedMemoryBytes` configuration keys fail
validation as unknown fields.

### io_uring

Removed, not implemented. The audit and rationale are recorded in
`decisions/adaptive-relay-implementation-plan.md`; stale `ioUring` or
`maxIoUringRelays` configuration keys fail validation as unknown fields.

## 6. Deployment guidance

Set the soft limit from the startup report rather than from
`maxConnections`. The report prints exactly what to configure:

```json
{"event":"descriptor_budget_report","fdSoftLimit":1024,"fdHardLimit":1048576,
 "fdFixedReserve":54,"fdSafetyHeadroom":64,"fdEffectiveBudget":906,
 "fdClamped":true,"fdRecommendedSoftLimit":37494}
```

For systemd:

```ini
[Service]
LimitNOFILE=37494
```

For a shell-launched process, `ulimit -n` must be raised *before* exec; a
process cannot raise its own soft limit above the hard limit without privilege.

`fdClamped: true` is not an error. It means the process will refuse work earlier
than `maxConnections` implies. Either raise the limit or lower the configured
bounds so the two agree.

## 7. Observability

| Event | When |
|---|---|
| `descriptor_budget_report` | once at startup |
| `descriptor_pressure_changed` | on transition only, never per accept |
| `accept_error_recovered` | on a recoverable accept error, with raw errno |
| `connection_rejected{reason:socketConfiguration}` | per-connection socket setup failure |

No event carries a target, an SNI value, a UUID, a key or any payload.
