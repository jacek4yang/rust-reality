# Engineering handoff — current state

Verify every mutable fact below before relying on it.

## Repository

```text
main                0829ffc   (verify: git log --oneline -1 origin/main)
latest release      v1.8.0    (tag on 6618e9d)
open PRs            none at time of writing
```

Merged v1.8 series: #100 Session Engine extraction, #101 irreversible write
boundary by type, #102 semantic event-sequence fuzzing, #103 Tokio adapter
boundary, #104 transport capability policy, #105 memory audit, #106 release
v1.8.0, #107 supplemental evidence + throughput investigation, #108 relay-buffer
hypothesis rejected on mechanism, #109 partial derived-policy overrides.

## Deployment

```text
rust-reality-vps       (LINE, daily-use, 1 vCPU, 1973 MiB)
    v1.8.0  sha 450392cc…  restarts 0
    CURRENT  v1.8.0-official-daily
    PREVIOUS v1.8.0-daily-rollback     (identical daily config, log level error)
    ports    22, 443 only (v4 + v6)
    config   sha b4042c54f3f8fa9657ddc9d0e951e279ad5b908e06cadd770df170067bdbd504

rust-reality-landing-vps  (LANDING, 2 vCPU, 954 MiB)
    v1.8.0  sha 450392cc…  restarts 0
    CURRENT  v1.8.0-official-handoff
    PREVIOUS v1.8.0-official-nxr
```

Both CURRENT and PREVIOUS on LINE carry the byte-identical daily configuration, so
a rollback cannot change client-visible identity.

## Immutable optimisation baseline

`notes/v1.9.0/v1.8.0-baseline-identity.json`

```text
tag           v1.8.0
commit        6618e9dbe2cbaf8767f7262e8ff5d9dfdbe58f50
binary sha256 450392ccc73fd4dd8441c04dcdcc93f0eb8b0ea2524e17904ca4bb376416ed1c
build id      e6abf487110749c49daff574d0059838c92f2e98
rustc         1.96.0 (ac68faa20 2026-05-25)
target        x86_64-unknown-linux-gnu, target-cpu x86-64, features [default]
profile       codegen-units=1 lto=thin panic=abort strip=symbols
```

Use the published artifact as baseline. Do not rebuild a "similar" one.

## Completed and measured

- **v1.8 dual-VPS gap closed.** Four legs, all PASS, 1063 attempts each at 100.00%
  success, zero authentication/replay/protocol rejections. Warm hits 1059–1062,
  cold fallback observed in every leg, LANDING restart and recovery verified.
  `notes/v1.9.0/v18-supplemental-dual-vps-evidence.md`.
- **v1.8 is neutral against v1.7.0** on the low-RTT formal gate, 32/32 protected
  metrics `NO_SIGNIFICANT_CHANGE`.
  `artifacts/v180-release-gate/gates/evaluation-r01.json`.
- **Relay-buffer hypothesis rejected on mechanism.** See below.

## Rejected experiments — do not repeat blindly

1. **Connection-future factory** (`notes/v1.8.0/rejected-connection-future-factory.md`).
   Removed a real 21 224 → 10 768 byte per-task duplication, then failed the
   protected `framed-download` 32 MiB c1 cell in two independent rounds with the
   same sign. Three revisit conditions recorded. Mechanism still unexplained;
   candidate is 1 408 bytes of added `.text` shifting instruction-cache layout, and
   PMU is unavailable on this host to test it (`perf_event_paranoid = 3`).
2. **`relay.bufferBytes` 32K→64K as the download fix**
   (`artifacts/v190-baseline/datapath-measurement-rejects-buffer-hypothesis.md`).
   Rejected on mechanism *before* benchmarking: the field feeds only
   `TcpRelay`'s buffered backend, the framed path uses a compile-time
   `4 * MAX_TLS_RECORD_WIRE_LEN`, and a measured real 32 MiB HTTPS download on the
   live node reached Vision Direct after 3942 bytes and ran **splice both
   directions**. The netem 32K/64K sweep was therefore not run for the download
   case; it remains useful only to characterise the buffered *fallback* backend.

## Open question — no demonstrated mechanism

The reported 671 versus 808 Mbps download difference has **no demonstrated
mechanism in the datapath**. Bulk download is kernel splice after a ~4 KB framed
preamble, which is version-insensitive by construction. This host cannot measure
the regime: its own link caps near 62–71 Mbps proxied, and the unproxied reference
is slower still.

Next action is reproduction from the original client and link, capturing server
CPU, TCP retransmissions, chosen backend, and Vision mode simultaneously. Local
tuning should not continue until then.

## Corrected diagnosis of the configuration defect — FIXED in #109

An earlier note said "pinning a block of defaults silently disables derivation".
**That was wrong.** Derivation is disabled by `runtime.tuning.mode: fixed` alone.
The live node's `advanced.limits` block is *inert* because every value in it equals
the built-in default — which is exactly why `runtime explain` reported every field
as `default` rather than `operator`.

The real defects, both reproduced and both now fixed by #109:

- **Defect A (loud).** `RelayPolicy::buffer_bytes`, `max_pooled_buffers` and
  `splice` have no serde default, so they are mandatory once the `relay` object
  exists. Overriding one number failed with `missing required field
  maxPooledBuffers`, forcing the operator to restate unrelated siblings.
- **Defect B (silent, worse).** Override-ness was inferred by comparing a value to
  the built-in default, never by whether the field was written. So a field
  deliberately set to a value equal to the default was indistinguishable from an
  absent field and was silently replaced by derivation. A full relay block written
  entirely with default values resolved to `bufferBytes` 65536,
  `maxPooledBuffers` 30929, `maxSpliceRelays` 964 — every explicit number
  discarded with no warning.

#109 adds `advanced.overrides`, which is presence-based: a field present there is
operator-pinned whatever its value, siblings keep deriving, and existing 1.x
configurations resolve byte-identically because the legacy value-inequality path is
retained after it. Mutation-checked.

The policy-difference measurement itself stands: on the same binary, `dedicated` +
`adaptive`/`throughput` derives 2x relay buffer, 3.8x splice relays, 7.5x pooled
buffers/pipes/relay memory, while deriving `maxHandshakes` and
`maxPreAuthIdleConnections` *lower*. Derivation is sizing, not inflation.

None of this is established as the cause of the download figure, and it must not be
released as if it were.

Note the distinction that matters for any claim:
`runtime.tuning.mode = adaptive` adjusts soft admission and direct-dial ceilings at
runtime. `relay.bufferBytes` is **startup-derived** and is not retuned by the
adaptive controller. Do not attribute startup-derivation effects to `adaptive`.

## Next exact actions

1. **Conflict validation for overrides.** Reject a field appearing in both
   `advanced.limits` as a non-default and `advanced.overrides` with a conflicting
   value, naming both JSON paths. `PolicyOverrides::pinned_paths()` already exists
   for this.
2. **Compiled runtime plan.** The hot path should not traverse user-facing
   configuration. Target one immutable generation-scoped plan with compact IDs
   (`OutboundId`, `RouteId`, `UserIndex`) replacing string/hash lookups — but only
   where the formal evaluator shows a win.
3. **Datapath copy ledger** with every copy classified crypto/kernel/security/
   protocol/lifetime-required or measured-justified; target `AVOIDABLE = 0`. Start
   from the measured fact that bulk download is splice with no userspace copy, so
   the ledger's live targets are the framed path, setup, Handoff/NXR encode, and
   the buffered fallback.
4. **Hot-path inventory and profile cards.** PMU is unavailable on this host
   (`perf_event_paranoid = 3`), so cycles and cache figures must come from another
   host or be omitted, never fabricated.
5. **Reproduce 671 vs 808 from the original client.** No local tuning should
   continue until then; the datapath has no demonstrated mechanism for it.

## Environment gotchas

- `perf_event_paranoid = 3`: no unprivileged hardware PMU. Do not fabricate
  cycles/cache numbers.
- Formal runs require a clean worktree (modified tracked files fail; untracked are
  fine), plus `RUN_ID`, absolute non-existent `OUT_DIR`, absolute disk-backed
  `TMPDIR`, and `PORT_BASE`. Binaries must be read-only with
  `RUST_REALITY_GIT_COMMIT` stamped at build time via
  `scripts/build-release.sh linux-x86_64-generic`.
- Launch long jobs detached: `setsid nohup … > log 2>&1 < /dev/null & disown`.
  Plain backgrounding gets killed with the tool shell.
- Never `pkill -f` a pattern that also matches the agent's own shell command line;
  it terminates the tool shell. Use
  `ps -eo pid,args --no-headers | awk '$2 ~ /binary$/ {print $1}'`.
- A second matrix round needs a different `PORT_BASE` because of `TIME_WAIT`.
- `/home` has hit 100% twice. Reclaim with `rm -rf worktrees/*/target` for merged
  branches; pinned evidence binaries live under `artifacts/*/candidate/`.
- Structured log events are snake_case: `runtime_plan_report`,
  `transport_pool_summary`, `relay_backend_report`, `connection_completed`,
  `connection_rejected`.
- `connection_completed` is debug-level and is the authoritative per-session record
  of `uplink_direct`, `downlink_direct`, `uplink_backend`, `downlink_backend`, and
  `downlink_direct_at_bytes`.
- Short IDs are unique per inbound; the validator rejects reuse.
- To observe the live datapath without disturbing the daily node, stage a
  generation that differs from the daily configuration in **only** the `log` key
  and verify identity/clients/routing/outbounds hash-identical first.
