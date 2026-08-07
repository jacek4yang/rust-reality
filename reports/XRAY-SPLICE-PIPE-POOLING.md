# Mechanism audit: splice pipe pooling — Go stdlib / Xray v26.7.28 vs rust-reality

```json
{
  "verdict": "hypothesis CONFIRMED with one correction: Go pools pipes (sync.Pool), Xray itself creates/resizes/destroys zero pipes per session; rust-reality creates/resizes/destroys pipes per relay. Correction: Xray FALLBACK flows do NOT use ReadFrom/splice at all — they use readv/writev buf.Copy.",
  "go_stdlib": {
    "pool": "internal/poll/splice_linux.go:191 splicePipePool = sync.Pool{New: newPoolPipe}; no fixed capacity, per-P local caches",
    "get": "internal/poll/splice_linux.go:205-211 getPipe -> Pool.Get; nil -> EINVAL -> caller falls back to generic copy",
    "put": "internal/poll/splice_linux.go:213-222 putPipe; if p.data != 0 the pipe is closed+discarded, else returned to pool",
    "create": "internal/poll/splice_linux.go:225-239 newPipe: 1x pipe2(O_CLOEXEC|O_NONBLOCK) + 1x fcntl(F_SETPIPE_SZ, 1MiB) ONCE per new pipe object, never per session",
    "destroy": "internal/poll/splice_linux.go:242-245 destroyPipe (2x close) only on residual data or GC finalizer (finalizer set at :200)",
    "locking": "sync.Pool (sync/pool.go:51-77): per-P private slot + lock-free poolChain; hot-path Get/Put take no mutex",
    "gc_drain": "sync.Pool cleared at GC (1-cycle victim cache); finalizers close fds so no fd leak between GCs",
    "exhaustion": "pool never blocks; empty pool -> New -> newPipe; pipe2 failure (EMFILE) -> getPipe EINVAL -> Splice handled=false -> silent fallback to io.Copy 32KiB userspace copy",
    "per_session_pipe_syscalls_steady_state": {"pipe2": 0, "fcntl": 0, "close": 0}
  },
  "go_call_chain": {
    "readfrom": "net/tcpsock.go:161 (*TCPConn).ReadFrom -> tcpsock_posix.go:47-55 readFrom",
    "order": ["net/splice_linux.go:19 spliceFrom (reader must be *TCPConn / tcpConnWithoutWriteTo / *UnixConn-stream)", "net/sendfile_linux.go:22 sendFile (reader must be *os.File)", "net/net.go:765 genericReadFrom = io.Copy 32KiB"],
    "splice": "net/splice_linux.go:44 pollSplice = internal/poll.Splice (splice_linux.go:34): getPipe once per ReadFrom call, spliceDrain/splicePump loop, defer putPipe",
    "fallback_batching": "genericReadFrom: NO readv/writev batching, plain read/write, 32KiB buffer (net/net.go:765-768)"
  },
  "xray": {
    "entry": "proxy/proxy.go:718 CopyRawConnIfExist -> unwrap both conns (:719-720) -> require *net.TCPConn writer (:725) + CanSpliceCopy==1 on inbound and ALL outbounds (:746-751) -> :760 tc.ReadFrom(readerConn)",
    "pipes_created_per_session": 0,
    "vision_downlink": "vless/inbound/inbound.go:555 CanSpliceCopy=2 -> proxy/proxy.go:398-401 VisionWriter arms CanSpliceCopy=1 after first direct write; freedom outbound freedom.go:257 ob.CanSpliceCopy=1; freedom.go:431-440 responseDone -> CopyRawConnIfExist (gated by useSplice env, freedom.go:35,49,433). ONE ReadFrom per session, whole-downlink splice loop",
    "vision_uplink": "splice DISABLED (TODO at proxy/proxy.go:273-275 and :339-341). Uplink = buffered loop via VisionReader/VisionWriter: readv (up to 8 iovecs x 8KiB = 64KiB/readv, common/buf/readv_reader.go:15-37,75-121) + writev (net.Buffers, common/buf/writer.go:49-63)",
    "fallback_flows": "NO splice, NO ReadFrom. vless/inbound/inbound.go:432-433,491,501: both directions buf.Copy (readv reader + writev writer, 8KiB buffers, common/buf/buffer.go:13)"
  },
  "rust_reality": {
    "pool_is_permits_not_pipes": "src/transport/tcp_relay.rs:890-904 SplicePool = tokio Semaphore(max_splice_relays) + FdBudget; pipes are NOT retained",
    "per_bidirectional_relay_syscalls": {
      "pipe2": 2, "_at": "tcp_relay.rs:1032-1033 -> PipePair::new :1058 pipe_with(CLOEXEC|NONBLOCK)",
      "fcntl_F_SETPIPE_SZ": 2, "_at": "tcp_relay.rs:1064 fcntl_setpipe_size(write, 256KiB); +1 fcntl(F_GETPIPE_SZ) each on failure (:1065)",
      "close": 4, "_at": "OwnedFd drop of 4 fds at relay end (tcp_relay.rs:1040-1044, 1018-1022)"
    },
    "per_directional_relay_syscalls": {"pipe2": 1, "fcntl": 1, "close": 2, "_at": "tcp_relay.rs:972-1004"},
    "exhaustion": "semaphore/fd-budget deny or pipe2 failure -> decline -> buffered backend (tcp_relay.rs:928-936, 353)"
  },
  "per_session_delta_at_N_concurrent_sessions": "rust-reality: 2 pipe2 + 2 fcntl + 4 close per session, every session. Xray/Go: ~0 once pool is warm; pool holds ~one 1MiB pipe per concurrent spliced direction across GC cycles; cold-start/EMFILE/GC-churn cost is 1 pipe2 + 1 fcntl per new pipe object, amortized"
}
```

## Prose mechanism report

### 1. Go's splice pipe pool — yes, it is pooled

`/usr/lib/go-1.24/src/internal/poll/splice_linux.go`:

- `Splice(dst, src *FD, remain int64)` (splice_linux.go:34-75) calls `getPipe()` once per call and `defer putPipe(p)` (splice_linux.go:35-39). One pipe is held for the whole `ReadFrom`, i.e. the entire downlink.
- The pool is a single `sync.Pool` (splice_linux.go:188-191): `var splicePipePool = sync.Pool{New: newPoolPipe}`. No fixed capacity; sizing is emergent (one cached pipe per recent concurrent splice, per-P).
- `newPipe()` (splice_linux.go:225-239) does the only pipe-creation syscalls in the whole model: `Pipe2(O_CLOEXEC|O_NONBLOCK)` then one `F_SETPIPE_SZ` to `maxSpliceSize = 1<<20` (1 MiB, splice_linux.go:22-27). The resize is done **once per pipe object**, best-effort (error ignored, splice_linux.go:231-236). There is no per-session growth policy — the pipe is created at full 1 MiB and reused at that size.
- `getPipe()` (splice_linux.go:205-211): `Pool.Get()`; if `New` returned nil (pipe2 failed, e.g. EMFILE) it returns `EINVAL`, and `Splice` returns `handled=false`, silently degrading the copy to userspace.
- `putPipe()` (splice_linux.go:213-222): if the pipe still holds data (`p.data != 0`, possible on error paths), the finalizer is cleared and the pipe is closed+discarded; otherwise it goes back into the pool.
- Drain/lifetime: `sync.Pool` contents are dropped at GC (with a one-cycle victim cache), and each pipe carries `runtime.SetFinalizer(p, destroyPipe)` (splice_linux.go:200) so fds are closed before GC reclaims the object (destroyPipe, splice_linux.go:242-245, two `close`).
- Locking: `sync.Pool` (`/usr/lib/go-1.24/src/sync/pool.go:51-77,99-145`) — per-P `private` slot plus a `poolChain` with lock-free local `pushHead`/`popHead`; cross-P steal (`popTail`) is the only contended path. Hot-path Get/Put take **no mutex and make no syscalls**.

### 2. Who reaches the pool

`(*net.TCPConn).ReadFrom` (net/tcpsock.go:161) → `readFrom` (net/tcpsock_posix.go:47-55) tries, in order:

1. `spliceFrom` (net/splice_linux.go:19-49): only if the reader is `*TCPConn`, `tcpConnWithoutWriteTo`, or a stream `*UnixConn`. Calls `pollSplice` = `poll.Splice` (net/splice_linux.go:12,44) → the pooled pipe above. A first-splice `EINVAL` (unsupported socket type) marks `handled=false` and falls through with no bytes consumed (splice_linux.go:49-58).
2. `sendFile` (net/sendfile_linux.go:22-55): only for `*os.File` readers → `poll.SendFile` (internal/poll/sendfile_unix.go:30-35 → `syscall.Sendfile`). Irrelevant for TCP→TCP.
3. `genericReadFrom` (net/net.go:765-768): `io.Copy` with a 32 KiB buffer, plain `read`/`write` — **no readv/writev batching** on this path. (Go's writev batching exists only via `net.Buffers`, which this path does not use.)

### 3. Xray side (v26.7.28 @ 5ca6f4b7)

- `CopyRawConnIfExist` (proxy/proxy.go:718-792): unwraps both conns to raw TCP (`UnwrapRawConn`, :719-720, penetrating TLS/REALITY at proxy.go:691-702), requires the writer to be `*net.TCPConn` (:725), then polls `CanSpliceCopy` (:743-751); when armed it calls `tc.ReadFrom(readerConn)` **once per session** (:760) — the Go runtime then splices the entire direction through one pooled pipe.
- Arming for Vision downlink: VLESS inbound sets `inbound.CanSpliceCopy = 2` for XRV (vless/inbound/inbound.go:555); `VisionWriter.WriteMultiBuffer` flips it to 1 only after the first direct write completes (proxy/proxy.go:398-401); freedom outbound sets `ob.CanSpliceCopy = 1` (freedom/freedom.go:257) and its `responseDone` reaches `CopyRawConnIfExist` (freedom.go:431-440), gated by the `useSplice` env flag (freedom.go:35,49,433).
- Uplink: splice is **disabled** — the enabling lines are commented out as `// TODO: enable uplink splice` (proxy/proxy.go:273-275, 339-341). Uplink runs the buffered loop: `ReadVReader` with readv batching of up to 8 iovecs × 8 KiB (`buf.Size = 8192`, common/buf/buffer.go:13; allocStrategy caps at 8, common/buf/readv_reader.go:23-37; readv loop :75-121) into `BufferToBytesWriter` using `net.Buffers.WriteTo` = writev (common/buf/writer.go:49-63).
- **Fallback flows: no splice, no ReadFrom.** The VLESS fallback handler (vless/inbound/inbound.go:432-433, 491, 501) uses `buf.Copy` in both directions (readv reader + writev writer) between the client conn and the fallback target conn. So the premise "Xray's fallback advantage comes from ReadFrom/splice" is wrong on the fallback path specifically — fallback advantage, if any, comes from readv/writev batching and from not touching pipes at all.

### 4. Direct answer

- **Xray creates or resizes zero pipes per session.** All pipe lifecycle is inside the Go runtime's `sync.Pool`; per-session pipe syscalls in steady state are 0. Pipes are created (1×`pipe2` + 1×`fcntl(F_SETPIPE_SZ,1MiB)`) only when the pool is empty (cold start, post-GC, EMFILE-discard), and closed (2×`close`) only when a pipe is discarded with residual data or GC'd.
- **rust-reality creates and destroys pipes per relay.** Its `SplicePool` (src/transport/tcp_relay.rs:890-904) is a semaphore of concurrency permits plus an fd budget — it pools *permission to splice*, not pipes. Every admitted bidirectional relay runs `SplicePipes::new` (tcp_relay.rs:1026-1036) → 2× `PipePair::new` (tcp_relay.rs:1057-1073) → 2× `pipe2(CLOEXEC|NONBLOCK)` + 2× `fcntl(F_SETPIPE_SZ, 256KiB)` (+1 `fcntl(F_GETPIPE_SZ)` each only if the resize fails), and 4× `close` when the `OwnedFd`s drop at relay end (tcp_relay.rs:1040-1044, 1018-1022). Directional relays pay half (tcp_relay.rs:972-1004).

Per-session syscall ledger (pipe management only):

| model | pipe2 | fcntl | close |
|---|---|---|---|
| Xray/Go (warm pool) | 0 | 0 | 0 |
| Xray/Go (cold pool, per new pipe object, amortized) | 1 | 1 (F_SETPIPE_SZ 1MiB) | 2 only on discard/GC |
| rust-reality bidirectional relay | 2 | 2 (F_SETPIPE_SZ 256KiB; +1 GETPIPE_SZ if refused) | 4 |
| rust-reality single direction | 1 | 1 | 2 |

The locking models are not the comparable cost — Go's `sync.Pool` hot path is mutex-free per-P and rust-reality's `Semaphore` `try_acquire` is also cheap. The measurable difference is the raw syscall count: rust-reality pays 8 fixed pipe-management syscalls per session (2 `pipe2` + 2 `fcntl` + 4 `close`) regardless of session length, while Xray pays ~0 amortized. At high connection churn (short-lived sessions), those 8 syscalls/session plus the fd-churn (pipe fds exist only per session, so the fd table cycles at 2× session rate) is a real, mechanism-level cost the Go model avoids — though it is small compared to per-session TLS/crypto work, and quantifying how much of the observed fallback gap it explains needs profiling, not just syscall counting.

### 5. Per-connection pipe-size syscalls

- Go/Xray: `F_SETPIPE_SZ` happens only in `newPipe` (splice_linux.go:236), i.e. per *new pool object*, never per connection. No per-session resizing anywhere in Xray or the Go splice path.
- rust-reality: every relay pays `F_SETPIPE_SZ` per pipe pair (tcp_relay.rs:1064, target 256 KiB, `SPLICE_PIPE_CAPACITY` at tcp_relay.rs:1053), best-effort with a `F_GETPIPE_SZ` fallback read (tcp_relay.rs:1065). This is the only model of the two with per-connection pipe-size syscalls.

One asymmetry worth noting for a fix: Go pools 1 MiB pipes and never recreates them, so it also amortizes the *kernel memory pinning* of pipe buffers; rust-reality pins and unpins 2×256 KiB of pipe buffer per session on top of the syscall cost.