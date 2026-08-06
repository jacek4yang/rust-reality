# Evidence checkpoint — DNS ownership (12.3)

Branch: fix/pr17-correctness-closure (stacked on PR #17). Status at writing:
uncommitted diff of 611 lines across 9 files; gates run plainly (no masking
pipes): `cargo fmt --all --check` PASS, `cargo clippy --workspace --all-targets
-- -D warnings` PASS, `cargo test --workspace` PASS (425 incl. rr-linux),
`cargo test --all-features --workspace` PASS (425).

## 1. Exactly one process-lifetime owner

- The DNS admission pool is a semaphore inside `ResourceGovernor`
  (`AdmissionKind::DnsLookup`, src/runtime/admission.rs). The governor itself is
  a field of `ProcessAuthorities`, constructed exactly once in
  `ProductionServer::compile` (src/server/production.rs, startup) and stored in
  `RuntimeStore` beside the replay caches, `TcpRelay`, and `FdBudget`.
- Reload and asset refresh call `RuntimeSnapshot::compile`, which only CLONES
  the shared governor into the new generation's handlers and the
  `RoutingTable` (`dns_governor` field) — no authority is constructed per
  generation (verified by reading `publish`/`compile`; regression-tested by
  `reload_cannot_multiply_the_connection_ceiling` and
  `reload_cannot_reset_the_direct_dial_bucket`).
- `RoutingTable::compile` requires the governor as a parameter, so no routing
  compilation or configuration snapshot can silently own a second pool.
- The worker pool is tokio's process-wide `spawn_blocking` pool, deliberately
  NOT resized (the prompt forbids shrinking it); DNS work is bounded upstream
  by the DNS semaphore, so DNS can occupy at most `maxDnsLookups` (default 64)
  blocking slots — a bounded subset of the pool's 512.
- Test-only and one-shot CLI paths (`run_self_test`, routing test helpers)
  construct their own throwaway governors in separate one-shot contexts; the
  production server never does.

## 2. Permit held until the underlying operation terminates

`resolve_domain_with` (src/server/routing.rs): the `AdmissionPermit` is MOVED
into the `spawn_blocking` closure and dropped only after the resolver closure
returns. The async side awaits a oneshot with `time::timeout`; when the
timeout (or a task abort) drops the receiver, the blocking operation keeps its
slot until it actually finishes and the result is discarded by a failed
`send`. Proven by tests:

- `async_timeout_keeps_the_permit_until_the_operation_terminates` — 20 ms
  timeout on a gated operation; `try_acquire` still fails afterwards while the
  operation is blocked; succeeds only after the gate opens.
- `a_cancelled_future_keeps_the_permit_until_the_operation_terminates` —
  task-driven future aborted mid-wait; identical retention proof.

## 3. Hard bounds

- Active blocking lookups: semaphore `maxDnsLookups` (default 64, must be > 0
  and ≤ maxConnections — src/config/validate.rs).
- Queued requests: none by design — `try_acquire` fails fast with
  `RouteResolutionError::DnsLimit`; there is no request queue to bound
  (`pool_saturation_denies_new_lookups_without_queuing`).
- Worker threads: bounded subset of tokio's blocking pool (≤ 64 of 512 by
  default); the pool itself is untouched.
- Shutdown duration: the runtime never awaits resolver completion
  (`process_shutdown_stays_bounded_with_a_running_lookup` — abort + gate
  release settles deterministically); a stuck getaddrinfo can extend process
  exit only by the kernel resolver's own timeout, not by our tasks.
- Memory retained by queued work: each in-flight lookup retains one
  `(String, u16)` tuple, one oneshot channel, and one permit — bounded by
  64 × O(100) bytes; there is no queue of request objects.

## 4. Focused tests (all in src/server/routing.rs + src/config/io.rs)

- success (`dns_resolution_succeeds_through_the_bounded_pool`);
- NXDOMAIN/error variant (`dns_failure_maps_to_the_dns_error_variant`);
- async timeout while the blocking operation continues (retention test 1);
- permit retention after timeout and after cancellation (tests 1–2);
- queue saturation → fail fast (`pool_saturation_denies_new_lookups_without_queuing`);
- reload/compilation cannot multiply the authority
  (`routing_compilation_shares_one_process_authority`, plus the production
  reload tests from MB1);
- clean process shutdown (`process_shutdown_stays_bounded_with_a_running_lookup`);
- existing configuration compatibility
  (`existing_configuration_without_max_dns_lookups_uses_the_default` — missing
  key decodes to 64; explicit value decodes; zero fails validation).

## 5. Complete diff

611 lines across: src/runtime/admission.rs (kind+pool), src/config/model.rs
(field+default), src/config/validate.rs (nonzero + parent-limit rule),
src/server/routing.rs (bounded resolver + test seam + 9 tests),
src/server/vision.rs (authorities tuple → shared governor into routing),
src/server/production.rs (governor passed to vision; DNS denial maps to
Handshakes resource class; tiny_ceiling_config sets max_dns_lookups),
src/config/io.rs (compat test), src/main.rs + benches/vision.rs (compile
callers). Saved at /tmp/dns-ownership.diff; committed as shown in git log.

## 6. Gates (run plainly, exit codes unmasked)

- cargo fmt --all --check — PASS
- cargo clippy --workspace --all-targets -- -D warnings — PASS
- cargo test --workspace — PASS (425 total, 0 failed)
- cargo test --all-features --workspace — PASS (425 total, 0 failed)

## 7. Sequencing

PipePool and all performance work remain blocked until the closure gate
(12.4 kernel liveness, 12.5 diagnostic truthfulness, full CI/sanitizer/soak
battery) is complete. Next: 12.4.
