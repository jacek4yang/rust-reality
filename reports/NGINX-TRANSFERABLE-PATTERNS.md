Audit complete. I read the event core, accept path, epoll module, connection/freelist code, process cycle (reload/shutdown), OpenSSL integration, pools/buffers/chains, stub status, and config defaults in the clone at `/home/jacek/work/kimi-rust-reality-performance/nginx`. The clone was not modified. Below is the full report, ready to save as `reports/NGINX-TRANSFERABLE-PATTERNS.md` (I cannot write files in this role).

---

# NGINX Transferable Patterns (audit of fresh clone, read-only)

Scope: rust-reality = one Tokio process, tasks migrate across 4 worker threads. NGINX = master + N single-threaded worker processes, each with a private event loop and preallocated connection table. Governing constraint applied throughout: **NGINX's per-worker hard authority (freelist caps, accept_mutex, connection_n limits) is sound only because each worker is an isolated process with a single thread; in a shared Tokio process with migrating tasks the same authority is unsound — only caches may become worker-local in our design.**

## 1. Worker-process ownership

- Each worker preallocates `cycle->connections` (array of `ngx_connection_t`), plus parallel `read_events`/`write_events` arrays, linked into a process-local freelist `cycle->free_connections` — no locks anywhere on the connection lifecycle (`src/event/ngx_event.c:754-800`, `src/core/ngx_connection.c:1206-1282`).
- Soundness rests on: one thread per process, non-blocking handlers, connection objects never shared across workers. Cross-worker state exists *only* for stats and the accept mutex, in a shared-memory segment with 128-byte cache-line padding per counter (`src/event/ngx_event.c:550-614`).
- The code itself flags the unsoundness of moving to threads: `TODO: MT: - ngx_atomic_fetch_add() or protection by critical section` on `c->number` (`src/event/ngx_event_accept.c:268-275`).
- Verdict: the lock-free connection table is **NOT-TRANSFERABLE** as authority; the *shape* (preallocated slots, generation-tagged reuse) is transferable as a shared slab or worker-local cache.

## 2. Accept distribution

- Listener topology: master creates listen sockets; workers inherit via fork. With `reuseport`, the socket is **cloned per worker** (`ngx_clone_listening`, `src/core/ngx_connection.c:98-131`) and each worker adds only its own fd to its epoll (`src/event/ngx_event.c:807-913`), `SO_REUSEPORT` set in `ngx_open_listening_sockets` (`src/core/ngx_connection.c:572-577`).
- `accept_mutex` (default **off**, `src/event/ngx_event.c:1369`): shared-memory spin mutex; the holder alone registers accept events; load hysteresis via `ngx_accept_disabled = connection_n/8 - free_connection_n` (`src/event/ngx_event_accept.c:139-140`, gate in `src/event/ngx_event.c:219-239`, delay 500ms `src/event/ngx_event.c:1370`).
- `EPOLLEXCLUSIVE` is preferred when available (multi-worker), plus periodic re-registration of the listen fd every 16 accepts so the kernel stops waking the same worker first (`src/event/ngx_event.c:921-937`, `src/event/ngx_event_accept.c:447-493`).
- `multi_accept` default **off** → `ev->available = 0` → exactly one `accept4()` per event, round-robining accepts against established-connection work (`src/event/ngx_event.c:1368`, `src/event/ngx_event_accept.c:47-49,58-336`).
- On `EMFILE`/`ENFILE`: disable accept events, drop the mutex, re-arm via timer (`src/event/ngx_event_accept.c:112-130`).
- Drain: shutdown removes accept events and closes listen fds (`ngx_close_listening_sockets`, `src/core/ngx_connection.c:1140-1203`); old-cycle accept events explicitly deleted on new generation (`src/event/ngx_event.c:834-854`).

## 3. Bounded work and fairness per cycle

- `epoll_wait` batch capped by `epoll_events` (default 512) (`src/event/modules/ngx_epoll_module.c:800`).
- Posted-queue separation: while holding the accept mutex, events are **posted, not run**; then the cycle runs *accepts first*, unlocks the mutex, expires timers, then runs normal posted events (`src/event/ngx_event.c:248-263`, `src/event/ngx_event_posted.c:18-36`, posting in `src/event/modules/ngx_epoll_module.c:894-931`). New connections get priority without starving established ones (accept is 1-per-event by default).
- Long writes bounded: `sendfile_max_chunk` default **2 MB** (`src/http/ngx_http_core_module.c:3903-3904`); write filters return to the event loop between chunks.
- Idle-reclaim during allocation pressure is bounded per call: `n = ngx_max(ngx_min(32, reusable_connections_n / 8), 1)` (`src/core/ngx_connection.c:1427`).
- There is **no time-slice bound** — NGINX relies on handlers being short; Tokio gives us this for free via `tokio::task::coop` budgets, but the *class separation* (accept vs. established) needs an explicit two-lane structure in our runtime.

## 4. Connection freelists and memory pools

- Freelist = preallocated array + intrusive `c->data` next pointer; alloc/free are O(1) pointer swaps (`src/core/ngx_connection.c:1225-1236,1272-1282`).
- **ABA-safe reuse**: `rev->instance` bit toggled on each reuse; epoll userdata packs the bit (`(uintptr_t) c | ev->instance`); stale events from closed fds are detected and skipped (`src/core/ngx_connection.c:1252-1258`, `src/event/modules/ngx_epoll_module.c:621,839-853,909-919`). Direct analogue: slab generation counters.
- Per-connection pool sized small: stream = **256 B** (`src/stream/ngx_stream.c:1004`), HTTP `connection_pool_size` default 512 B, `request_pool_size` default 4 KB (`src/http/ngx_http_core_module.c:3572-3575`); the per-connection log object lives in that pool (`src/event/ngx_event_accept.c:159,177-181`). Everything freed wholesale on close — no per-allocation free.
- Idle memory cap: total slots fixed by `worker_connections`; when free slots drop below 1/16, idle "reusable" connections (keepalive) are force-closed via `ngx_drain_connections` (`src/core/ngx_connection.c:1404-1457`; marking in `1373-1401`).

## 5. Chain/buffer reuse and copy avoidance

- `pool->chain` = freelist of `ngx_chain_t` link structs (`src/core/ngx_palloc.h:61`, `src/core/ngx_buf.c:48-62`); `ngx_chain_get_free_buf` pops cached buf+link (`src/core/ngx_buf.c:156-180`).
- Output chain keeps `ctx->free`/`ctx->busy`; buffers are recycled only when `buf->tag == ctx->tag` (module-tagged ownership prevents cross-module reuse bugs) (`src/core/ngx_output_chain.c:48-55,172-215,242-243`; `ngx_chain_update_chains`, `src/core/ngx_buf.c:185-225`).
- Copy avoidance: chains pass buffers by reference; data is copied into a cached free buf only when the source can't be referenced (`src/core/ngx_output_chain.c:98,172-180`); sendfile path sends file pages in-kernel, chunk-capped at 2 MB; kernel-TLS variant uses `SSL_sendfile` (`src/event/ngx_event_openssl.c:3435-3463`).
- SSL write path **coalesces** the chain into a per-connection 16 KB buffer before `SSL_write` to amortize per-record overhead (`src/event/ngx_event_openssl.c:3012-3019,3065-3081,3222`) — the most directly relevant pattern for a REALITY relay doing AEAD framing.

## 6. Control-plane vs data-plane separation (reload)

- SIGHUP → master builds a *new cycle* (new config), spawns a **new worker generation**, then channels `NGX_CMD_QUIT` to old workers (`src/os/unix/ngx_process_cycle.c:211-242,432-498`; signal handler `src/os/unix/ngx_process.c:319-365`).
- Old workers: stop accepting (`ngx_close_listening_sockets`), force-close only *idle* connections (`ngx_close_idle_connections`, `src/core/ngx_connection.c:1461-1478`), let established connections run to completion, exit when the timer tree empties (`src/os/unix/ngx_process_cycle.c:710-741`); bounded by optional `worker_shutdown_timeout` (`src/core/ngx_cycle.c:1437-1449`, `src/core/nginx.c:128-132`).
- Tokio analogue: `Arc<Config>` swap; existing sessions hold the old `Arc`, listener rebinds in place. The generation concept transfers; the process-fork mechanism does not.

## 7. OpenSSL integration

- Handshake runs **inline inside the read/write event handler**, retried by swapping `c->read->handler`/`c->write->handler` to `ngx_ssl_handshake_handler` on `SSL_ERROR_WANT_READ/WRITE` (`src/event/ngx_event_openssl.c:2201-2342`). Crypto time is event-loop time — acceptable because records are small; no thread offload except optional async-engine.
- Record buffer 16 KB (`NGX_SSL_BUFSIZE`, `src/event/ngx_event_openssl.h:223`, default at `src/event/ngx_event_openssl.c:330`, tunable `ssl_buffer_size`, `src/http/modules/ngx_http_ssl_module.c:169`); early data capped at the same size (`src/event/ngx_event_openssl.c:1861`).
- Read path loops `SSL_read` until it would block, because one readiness event may hide multiple records (`src/event/ngx_event_openssl.c:2660-2674`).
- Classification note: rustls/ring in rust-reality already runs in-task; the transferable item is the *coalesce-then-write* discipline (§5) and matching record-size buffers, not the handler-swap (that's just `Poll::Pending`).

## 8. Logging/metrics placement

- Per-connection: one `ngx_log_t` from the connection pool; debug logging opt-in per CIDR via `debug_connection` (`src/event/ngx_event_accept.c:177-181,533-587`); routine data-path events are debug-compiled, not logged per connection in production.
- Aggregate: exactly 7 atomics (accepted/handled/requests/active/reading/writing/waiting) in shared memory, each on its own 128-byte cache line (`src/event/ngx_event.c:61-78,550-614`); `stub_status` just reads them (`src/http/modules/ngx_http_stub_status_module.c:106-127`).
- **TRANSFERABLE-AS-IS**: padded atomic counters + a scrape endpoint; verbose logging gated per-connection.

## 9. Overload and connection-limit behavior

- Hard per-worker cap `worker_connections` (default 512, `src/event/ngx_event.c:13,1360`). At capacity, `ngx_get_connection` returns NULL → the just-accepted socket is **closed immediately** with an alert (`src/core/ngx_connection.c:1227-1233`, `src/event/ngx_event_accept.c:142-151`) — fail-fast, no queuing.
- Soft throttle: worker stops competing for accepts when free < 1/8 (`ngx_accept_disabled`, §2); reclaims idle keepalives when free < 1/16 (§4). Three-tier response: shed new → reclaim idle → refuse.
- Applying the critical constraint: a per-worker *cap* is unsound under task migration; a **global** `Semaphore`-style limit with the same tiered hysteresis (refuse new, then reclaim idle) is the transferable form.

## 10. Cold/hot code separation

- No `likely`/`unlikely` macros in NGINX core (verified by grep). Conventions are structural: short-path early return when output chain is empty (`src/core/ngx_output_chain.c:48-55`), handler-pointer dispatch instead of branching (`src/event/ngx_event.c:894-902`), error paths tail-placed, per-level compiled-out debug logging, reuseport/EPOLLEXCLUSIVE to keep the hot path lock-free, `ngx_memzero` only of reused headers (`src/core/ngx_connection.c:1245-1255`).
- Verdict: structural fast-path discipline **TRANSFERABLE-AS-IS**; explicit branch-hint layout **NOT-TRANSFERABLE** (stable Rust lacks it) — mark only genuinely cold fns `#[cold]`.

---

## Machine-readable pattern list

```json
[
  {"name": "worker-local-connection-table", "classification": "NOT-TRANSFERABLE",
   "rationale": "Lock-free preallocated table is sound only with one thread per process; migrating Tokio tasks would race it. Only caches may be worker-local.",
   "source": "src/event/ngx_event.c:754-800"},
  {"name": "slab-generation-instance-bit", "classification": "TRANSFERABLE-WITH-TOKIO-ADAPTATION",
   "rationale": "Instance-bit in epoll userdata detects stale events after slot reuse; equals slab generation counters / tokio task IDs.",
   "source": "src/core/ngx_connection.c:1252-1258; src/event/modules/ngx_epoll_module.c:839-853"},
  {"name": "reuseport-per-worker-listener", "classification": "NOT-TRANSFERABLE",
   "rationale": "Per-worker SO_REUSEPORT sockets solve inter-process accept balance; we have one process and one listener per bind.",
   "source": "src/core/ngx_connection.c:98-131,572-577"},
  {"name": "accept-mutex-with-load-hysteresis", "classification": "NOT-TRANSFERABLE",
   "rationale": "Cross-process accept arbitration; the hysteresis formula (cap/8 - free) is reusable, the mutex is not.",
   "source": "src/event/ngx_event.c:219-239; src/event/ngx_event_accept.c:139-140"},
  {"name": "one-accept-per-event (multi_accept off)", "classification": "TRANSFERABLE-WITH-TOKIO-ADAPTATION",
   "rationale": "Bounded accept work per wakeup round-robins accept vs established traffic; map to accept-task yield after N accepts.",
   "source": "src/event/ngx_event.c:1368; src/event/ngx_event_accept.c:47-49"},
  {"name": "accept-vs-established posted-queue split", "classification": "TRANSFERABLE-WITH-TOKIO-ADAPTATION",
   "rationale": "Two-lane scheduling: accepts drained first, then connection events; needs explicit lane structure in our runtime.",
   "source": "src/event/ngx_event.c:255-263; src/event/ngx_event_posted.c:18-36"},
  {"name": "epoll-batch-cap", "classification": "TRANSFERABLE-AS-IS",
   "rationale": "epoll_wait maxevents=512 bounds per-cycle syscall work; mio/Tokio already exposes this.",
   "source": "src/event/modules/ngx_epoll_module.c:800"},
  {"name": "per-connection-write-chunk-cap", "classification": "TRANSFERABLE-AS-IS",
   "rationale": "sendfile_max_chunk=2MB bounds one connection's turn; apply as per-poll flush cap in relay copy loops.",
   "source": "src/http/ngx_http_core_module.c:3903-3904"},
  {"name": "bounded-idle-reclaim", "classification": "TRANSFERABLE-WITH-TOKIO-ADAPTATION",
   "rationale": "min(32, idle/8) per allocation keeps reclaim bounded; threshold must be global, not per-worker.",
   "source": "src/core/ngx_connection.c:1404-1457"},
  {"name": "small-per-connection-pool", "classification": "TRANSFERABLE-WITH-TOKIO-ADAPTATION",
   "rationale": "256B stream connection pool shows how little per-connection state is needed; use arena/slab per session instead of per-alloc.",
   "source": "src/stream/ngx_stream.c:1004; src/http/ngx_http_core_module.c:3572-3575"},
  {"name": "chain-link-freelist (pool->chain)", "classification": "TRANSFERABLE-WITH-TOKIO-ADAPTATION",
   "rationale": "Free-list of link structs avoids allocator churn; in Rust: object pool for BytesMut/IoSlice wrappers, global or worker-cache only.",
   "source": "src/core/ngx_palloc.h:61; src/core/ngx_buf.c:48-62"},
  {"name": "tagged-buffer-recycling (free/busy chains)", "classification": "TRANSFERABLE-WITH-TOKIO-ADAPTATION",
   "rationale": "Tag-matched buffer reuse prevents cross-component aliasing; maps to per-direction buffer ownership in bidirectional relay.",
   "source": "src/core/ngx_output_chain.c:172-243; src/core/ngx_buf.c:185-225"},
  {"name": "ssl-record-coalesce-before-write", "classification": "TRANSFERABLE-AS-IS",
   "rationale": "Accumulate chain into one 16KB buffer before SSL_write to cut per-record overhead; directly applicable to AEAD record framing.",
   "source": "src/event/ngx_event_openssl.c:3012-3081,3222"},
  {"name": "record-size-matched-buffer (NGX_SSL_BUFSIZE 16k)", "classification": "TRANSFERABLE-AS-IS",
   "rationale": "Buffer sized to max TLS record avoids partial-record syscalls.",
   "source": "src/event/ngx_event_openssl.h:223; src/event/ngx_event_openssl.c:330"},
  {"name": "read-until-would-block-per-readiness", "classification": "TRANSFERABLE-AS-IS",
   "rationale": "One readiness event may cover multiple records; loop SSL_read until WANT_READ (Tokio: loop until Poll::Pending).",
   "source": "src/event/ngx_event_openssl.c:2660-2674"},
  {"name": "sendfile/SSL_sendfile zero-copy", "classification": "NOT-TRANSFERABLE",
   "rationale": "File-to-socket path; REALITY relay is socket-to-socket with crypto, no page-cache bypass exists.",
   "source": "src/event/ngx_event_openssl.c:3435-3604"},
  {"name": "config-generation-swap (HUP)", "classification": "TRANSFERABLE-WITH-TOKIO-ADAPTATION",
   "rationale": "New config generation + graceful drain of old; implement as Arc<Config> swap + listener rebind + idle-first shutdown.",
   "source": "src/os/unix/ngx_process_cycle.c:211-242,728-741; src/core/ngx_connection.c:1461-1478"},
  {"name": "graceful-shutdown-with-timeout", "classification": "TRANSFERABLE-WITH-TOKIO-ADAPTATION",
   "rationale": "Close listeners, close idle conns, wait for timers to empty, bounded by worker_shutdown_timeout; map to graceful-stop budget.",
   "source": "src/os/unix/ngx_process_cycle.c:710-741; src/core/ngx_cycle.c:1437-1449"},
  {"name": "inline-handshake-in-event-handler", "classification": "TRANSFERABLE-AS-IS",
   "rationale": "Handshake is just the connection's first read/write state; rustls handshake-in-task matches; watch CPU skew across workers.",
   "source": "src/event/ngx_event_openssl.c:2201-2342"},
  {"name": "aggregate-atomic-metrics + stub endpoint", "classification": "TRANSFERABLE-AS-IS",
   "rationale": "Seven cache-line-padded atomics, no per-connection metric cost, cheap scrape; already matches our diagnostics direction.",
   "source": "src/event/ngx_event.c:550-614; src/http/modules/ngx_http_stub_status_module.c:119-127"},
  {"name": "per-cidr-debug-logging-gate", "classification": "TRANSFERABLE-AS-IS",
   "rationale": "debug_connection enables verbose logs only for chosen peers; zero-cost for production traffic.",
   "source": "src/event/ngx_event_accept.c:533-587"},
  {"name": "hard-connection-cap-fail-fast", "classification": "TRANSFERABLE-WITH-TOKIO-ADAPTATION",
   "rationale": "Close-and-alert at capacity, never queue; but the cap must be a process-global semaphore, not per-worker.",
   "source": "src/core/ngx_connection.c:1227-1233; src/event/ngx_event_accept.c:142-151"},
  {"name": "three-tier-overload (throttle, reclaim, refuse)", "classification": "TRANSFERABLE-WITH-TOKIO-ADAPTATION",
   "rationale": "Stop accepting at 1/8 free, reclaim idle at 1/16, refuse at 0; thresholds need global accounting and measurement on our workload.",
   "source": "src/event/ngx_event_accept.c:139-140; src/core/ngx_connection.c:1411-1427"},
  {"name": "emfile-accept-backoff", "classification": "TRANSFERABLE-AS-IS",
   "rationale": "On EMFILE/ENFILE stop accepting and re-arm on a timer instead of hot-looping errors.",
   "source": "src/event/ngx_event_accept.c:112-130"},
  {"name": "structural-fast-path-discipline", "classification": "TRANSFERABLE-AS-IS",
   "rationale": "Early-return short paths, fn-pointer dispatch, error paths tail-placed; no compiler hints needed.",
   "source": "src/core/ngx_output_chain.c:48-55; src/core/ngx_connection.c:1245-1255"},
  {"name": "explicit-branch-hints", "classification": "NOT-TRANSFERABLE",
   "rationale": "NGINX doesn't use likely/unlikely; stable Rust has no equivalent — limit to #[cold] on rare paths.",
   "source": "(absent; verified by grep over src/core/ngx_config.h)"}
]
```

Notes for the parent agent:

- Highest-value transfers for rust-reality: `ssl-record-coalesce-before-write`, `read-until-would-block-per-readiness`, `per-connection-write-chunk-cap`, `accept-vs-established posted-queue split`, `three-tier-overload` (with global accounting), `aggregate-atomic-metrics`, and `slab-generation-instance-bit` if we adopt a connection slab.
- Items flagged `NEEDS-MEASUREMENT`: none as a separate class — the threshold values in `three-tier-overload` (1/8, 1/16, 32/cycle) and `per-connection-write-chunk-cap` (2 MB) are NGINX-tuned constants; classification rationale notes they must be re-derived against our relay benchmarks before adoption.
- The one-process constraint bites hardest on items 1, 3, 4, 9: every NGINX mechanism that asserts "this worker owns N slots" must become either a global atomic/semaphore or a purely advisory worker-local cache.