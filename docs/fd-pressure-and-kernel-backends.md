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
| io_uring ring descriptors | one per shard, when enabled |
| eBPF map, program and link | 3, when enabled |
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
| io_uring session | 2 |

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
| sockhash | yes | yes — armed per relay from `TcpRelay` when the policy enables it and the probe plus controller construction succeed | yes |
| io_uring | probed only | **no** — driver exists but is unreachable from the relay path | no |

### SOCKHASH runtime

With `policy.relay.sockHash` enabled, `TcpRelay::new` runs the kernel probe
and, only when it passes, constructs the process-lifetime controller: one
`SOCKHASH` sized at two entries per `maxSockhashRelays`, the stream-verdict
program loaded with the bounded verifier log, and the attach. The startup
`RelayBackendReport` reports sockhash available *only* when that controller
exists; otherwise it names the exact fixed decline reason (probe failure,
`missingCapability`, `verifierRejected`, …). A failure never stops the relay
from serving — the backend simply declines, before any byte, and the
automatic order (`sockhash`, `splice`, `buffered`) falls through.

Arming requires the privileges the probe measures on the running host
(`CAP_BPF`/`CAP_NET_ADMIN` or root, plus `RLIMIT_MEMLOCK` headroom); the
unprivileged path is not guessed, it is probed. Arming itself is
transactional (both directions installed or neither, with rollback), guarded
against borrowed sockets, a touched transfer ledger and queued input, and
admitted two directions per relay. Because the redirect consumes FINs without
propagating them, the armed session detects each half-close itself, waits for
a `TCP_INFO`-measured drain barrier so no redirected byte is stranded, and
then propagates the half-close with `shutdown(2)`. Byte counts are
kernel-reported `TCP_INFO` deltas snapshotted at teardown. Privileged
conformance gates live in `tests/sockhash_runtime.rs`.

The historical failure analysis follows.

### SOCKHASH

The merged backend created a map, failed `BPF_PROG_LOAD` with `EACCES`, reported
that as `blockedByLsm`, and never attached or updated anything.

`EACCES` from `BPF_PROG_LOAD` is the standard errno for a **verifier
rejection**, not an LSM denial. The loader now requests a bounded 64 KiB
verifier log and classifies `BPF_PROG_LOAD` failures with its own mapping:

| errno | Category |
|---|---|
| `EACCES` | `verifierRejected` |
| `EPERM` | `missingCapability` |
| others | generic mapping |

Three defects were found and fixed, the third by measurement:

1. **Context offsets.** `__bpf_md_ptr` stores each context pointer in eight
   bytes aligned to eight, so `data`/`data_end` occupy 0..16 and every later
   field sits eight bytes beyond where the old constants assumed. Offset 12
   landed inside `data_end`; the verifier said
   `invalid bpf_context access off=12 size=4`.

2. **Key size.** The map used a 40-byte key while the program built a 16-byte
   one, so the helper's `ARG_PTR_TO_MAP_KEY` check read past the frame pointer.
   One constant now feeds the map, the program and userspace serialisation, and
   the program builder no longer takes a key size at all.

3. **Program type.** `SK_MSG` hooks `sendmsg` — what the local application is
   sending. A proxy needs the receive path. An `SK_MSG` program loads and
   attaches cleanly and still redirects nothing for a relayed pair. The backend
   is now `BPF_PROG_TYPE_SK_SKB` with `BPF_SK_SKB_STREAM_VERDICT`, whose context
   is `__sk_buff`. Helper 72, `bpf_sk_redirect_hash`, was correct for the intent
   all along; the program type did not match it.

**Key derivation.** The old program built a *reversed* key, which can only name
the other end of the same connection. A proxy relays two independent
connections, between which no tuple relationship exists. The program now
describes itself and userspace registers the partner under that key:

```text
map[key(inbound)]  = outbound socket
map[key(outbound)] = inbound socket
```

**Key layout**, exactly 40 bytes with no padding:

```text
[ 0..16]  local address, IPv4-mapped for v4 flows
[16..32]  remote address
[32..36]  local port                       (u32, native order)
[36..40]  (family << 16) | remote port     (u32, native order)
```

Ports are 16-bit, so the address family rides in the high half of the last word.
That keeps an IPv4-mapped address distinct from a native IPv6 one without
spending a byte plus three of padding. All forty bytes are zeroed before use, so
no verifier path sees uninitialised stack.

`__sk_buff.local_port` arrives in host byte order. `remote_port` arrives as a
network-order 16-bit port in the high half of a 32-bit word and is shifted down
and byte-swapped.

IPv6 uses an explicit branch reading `local_ip6`/`remote_ip6` four bytes at a
time; the context refuses 8-byte access with `invalid bpf_context access`.

### io_uring

The driver in `crates/rr-linux/src/uring.rs` compiles but is constructed only
from its own tests. `TcpRelay::run_backend` declines io_uring, and
`automatic_preference()` omits it. The startup report must not be read as a
claim that production traffic uses it.

It is excluded from automatic selection because no retained measurement on a
target host justifies it, and the specification forbids a speculative
classifier.

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

No event carries a target, an SNI value, a UUID, a key or any payload. Verifier
logs appear only in explicit diagnostic and test output and are bounded to
64 KiB.
