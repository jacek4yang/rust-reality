# Performance investigation record

This page preserves the durable conclusions of the closed performance
investigations: the per-connection control-path accounting, the historical
throughput question, and the mechanisms that were measured and then accepted
or rejected on the evidence. The
[performance reference](../performance.md) holds the measured data-plane
properties and the release evidence; this page holds the *investigation*
record so the same hypotheses are not re-litigated from scratch.

## Per-connection control path (ledger)

Scope: one normal, successful, authenticated Vision Direct session on `main`,
from `accept` to the point where the kernel `splice` loop owns the transfer.
Established by reading the code — no cycle or cache figures are claimed.

**Conclusion first.** A normal connection performs on the order of **15 relaxed
atomic operations, one 1–2 entry map lookup, two to three `Arc` increments, one
task spawn, and zero locks, zero futex waits, zero heap allocations for
admission** before reaching the same `splice` dataplane earlier releases used.
That cost is per connection, not per record or per relay chunk. Amortised over
a multi-gigabyte bulk transfer it is arithmetically incapable of explaining a
15–20% sustained throughput difference. It could matter for a
connection-rate-bound workload; it cannot matter for single-stream bulk
download.

Verified primitives:

- **Admission is a relaxed compare-exchange on one counter** — not a Tokio
  `Semaphore`, so no waker registration, no futex, no task parking.
- **The pressure gauge is one `Acquire` load plus a decode**, and it is
  optional — a configuration without pressure tracking pays a single branch.
- **The permit is a stack value.** RAII release, no box, no registry insertion.
- The admission subsystem contains no `Mutex` or `RwLock` on either the success
  or the rejection path.
- **Soft ceilings are free when unused**: the adaptive knob only moves a
  ceiling when a controller calls it; until then `try_acquire` compares against
  a constant and behaves exactly as a fixed-size pool. Adaptive behaviour never
  runs controller logic on the per-record path.
- Every admission kind that is reported to operators
  (`maxHandshakes` etc.) has a real production acquisition site; the suspicion
  of an unenforced control surface was checked and rejected (the initial greps
  were truncated).

Control-plane growth between releases (the ~3,600 new lines in the runtime
resource/admission/derivation layer) is therefore **not** a plausible cause of
any historical bulk-throughput observation. That is a narrowing of the search
space, not a claim that the observation was wrong.

## Historical throughput question (≈671 vs ≈808 Mbps)

A real-WAN download difference (≈671 Mbps on the current deployment vs ≈808 on
an earlier setup) was investigated; see [ADR 0012](../../adr/0012-relay-buffer-hypothesis-rejected.md)
for the relay-buffer hypothesis rejection. The surviving durable facts:

- **The absolute numbers cannot be reproduced from the build host** — its own
  link caps near 70 Mbps, and the unproxied reference is *slower* than the
  proxied path. The decisive confirmation must be measured from the reporting
  client's vantage point.
- **v1.4.0 baseline identity** (downloaded and verified against the release
  `SHA256SUMS`): tag `v1.4.0`, commit `ed8fea0a5efae480a559691c738e6927ed85fa5c`,
  binary SHA-256 `38ba5cd5e02edbb039b13751220b91b60cb005a22d2241e6c3026d84ce643c57`,
  GNU Build ID `d1de46ed1deddb0dfe66434a09896589c0794e32`.
- **Mechanism triage**: the splice datapath barely moved between v1.4.0 and the
  investigation point (`relay.rs` byte-identical; `tcp_relay.rs` changed only a
  policy-type rename plus one constant); the runtime resource/admission layer
  grew ~3,600 lines — which the control-path ledger above rules out as a bulk
  throughput cause.
- **Rejected mechanism: splice pipe-page exhaustion.** The 256 KiB → 512 KiB
  splice pipe capacity change halved the calculated concurrent splice headroom
  under `fs.pipe-user-pages-soft` (~64 vs ~128 concurrent relays). Measured
  against the live node with 80 concurrent 4 MiB HTTPS streams: **zero
  `pipe_capacity_downgraded` events**, 80/80 sessions reached Direct, splice in
  both directions. The bounded pools and ramp/retire behaviour keep live pipe
  count under budget. Revisit condition: a workload holding more than roughly
  64 simultaneous splice relays, or a node with a lower
  `fs.pipe-user-pages-soft`.
- **Rejected mechanism: `relay.bufferBytes`** — see ADR 0012.
- **What is ruled out**: a CPU-side or per-record regression at 32 MiB loopback
  (32/32 protected metrics neutral against the published v1.8.0 baseline); a
  missing splice backend; measurement from the build host.

**Decision rule for settling the question** (stated in advance so the result
cannot be rationalised afterwards): run the four-way comparison — pinned stock
Xray, official v1.4.0, official v1.8.0, current candidate — from the original
high-bandwidth client, same VPS, same target, one short window, ABBA ordering.
If Xray and v1.4.0 both reproduce ~800 while the others sit near ~670, that is
strong evidence of a rust-reality regression and the version interval is then
bisected. If all four perform similarly in that controlled window, the
historical difference was environmental or WAN variance and **no rust-reality
regression should be invented**.

## Compiled-control-plane audit

The question "does the runtime need a `CompiledRuntimePlan` construct" was
answered negatively by audit; see [ADR 0013](../../adr/0013-no-compiled-runtime-plan.md).

## NXR cached keyed-HMAC template (accepted)

Hypothesis: `NxrKey` stored the raw 32-byte PSK, so every NXR authenticate and
verify rebuilt the keyed HMAC-SHA256 state from scratch. Caching the keyed
template in `NxrKey` and cloning it per operation should remove that
per-request key schedule. The mechanism claim is *not* "fewer allocations" —
HMAC key initialization never allocated.

### Mechanism

HMAC-SHA256 over the benchmark request (`example.com`, 34-byte header + 11-byte
domain = 45 authenticated bytes) costs four SHA-256 block compressions per
operation: the `key ^ ipad` block, the message block, the `key ^ opad` block,
and the outer block over the 32-byte inner digest. Only the two pad blocks
depend on the key alone, so a precomputed template removes exactly half:

| | SHA-256 blocks per NXR operation |
| --- | --- |
| baseline | 4 |
| candidate | 2 |

### Measured, identity-bound

Host: Intel i3-8100 (4 logical CPUs, fixed 3.6 GHz, **no SHA-NI**, so SHA-256
runs in the portable software backend), Linux 6.12.100.

| | baseline | candidate |
| --- | --- | --- |
| source commit | `d6342f255017bf2f742f876f4973a9d2d47c6d96` | `6814243669f202ed8aec81d78d889fabdb51cabd` |
| binary SHA-256 | `02fdada8c76540dfdf6fa5888c77109892cb6811f850a4b10f777c1e8dacd99c` | `260f8b7413c056590a88251b5f6f1aa8bb2c4176c8052c90c44e6d945aaa1f7b` |
| ELF build ID | `a12f3741f7d7f7069dcb1a813ee4c888260db219` | `d0bf5f2f8a99c934a852db78d60551cba009f19d` |
| `.text` | 6,084,903 | 6,087,527 (+2,624, +0.043%) |
| total binary | 8,256,520 | 8,259,208 (+2,688, +0.033%) |

`rust-reality benchmark`, 8 ABBA blocks (A B B A per block, one pinned core),
16 samples per arm, 2,000 ms measured and 500 ms warm-up per case:

| case | baseline ns/op | candidate ns/op | ratio |
| --- | --- | --- | --- |
| `nxr.auth.encode.domain` | 1225.60 | 644.36 | **1.902×** |
| `vless.decode.ipv4` (control) | 23.68 | 23.24 | 1.019× |
| `vision.decode.8k` (control) | 124.12 | 123.16 | 1.008× |

Per-block paired ratios stayed in 1.847–1.968; an independent earlier ABBA
session on the same pair gave 1.915×. Both controls moved slightly in the
candidate's favour, so nothing regressed.

### The gain is removed work, not cheaper work

`perf record -e cycles:u` over the built-in benchmark, with the SHA-256
compression function exported through the identity-bound hotspot bundle
(`sub_6A9420` in the baseline, `sub_6A9E80` in the candidate — the same
10,298-byte fully unrolled function):

| | baseline | candidate | ratio |
| --- | --- | --- | --- |
| function period (cycles) | 36,806,428,841 | 35,179,278,611 | 0.9558 |
| share of application DSO | 46.37% | 44.31% | |
| SHA blocks executed | ~35.90 M | ~34.21 M | 0.9530 (predicted) |
| **cycles per SHA block** | **1025.2** | **1028.2** | **1.0029** |
| SHA cycles per NXR operation | 4100.8 | 2056.4 | 1.9942 |

Cost per compression is unchanged to 0.3%, and compressions per operation
halved to within 0.6% of exactly two. The whole-capture application-DSO period
is identical (ratio 1.0003), and the period outside the SHA function grew only
3.88% while the candidate executed 90.6% more NXR iterations — accounted for by
iteration count alone. Non-SHA cost per NXR operation is ~190 cycles baseline
against ~194 candidate, so cloning the 144-byte template costs on the order of
a few cycles against the ~2,050 cycles of the two compressions it replaces.
**Cloning HMAC state is not assumed cheaper than re-keying; it was measured.**

### Key-derived state lifetime

`Hmac<Sha256>` deliberately carries no `ZeroizeOnDrop` marker: `hmac` builds it
with `digest::buffer_fixed!` under `MacTraits`, and only `FixedHashTraits`
requests that marker. A compile-time `Hmac<Sha256>: ZeroizeOnDrop` bound
therefore fails, and its failure proves nothing about erasure. The erasure
actually happens by field recursion, which the enabled feature graph
(`hmac/zeroize` and `sha2/zeroize`, both to `digest/zeroize`, which enables
`block-buffer/zeroize`) turns on:

```text
Hmac<Sha256>                      generated wrapper, no Drop
├── core: HmacCore<Sha256>        no Drop; fields dropped recursively
│   ├── digest:      CtOutWrapper<Sha256VarCore, U32>   no Drop
│   │   └── Sha256VarCore  Drop -> state.zeroize(), block_len.zeroize()
│   └── opad_digest: CtOutWrapper<Sha256VarCore, U32>   no Drop
│       └── Sha256VarCore  Drop -> state.zeroize(), block_len.zeroize()
└── buffer: BlockBuffer<U64, Eager>  Drop -> zeroize() over block and position
```

Verified empirically against the locked versions (`hmac` 0.13.0, `sha2` 0.11.0,
`digest` 0.11.3, `block-buffer` 0.12.1, `zeroize` 1.9.0) by writing a keyed
instance into owned storage, dropping it in place, and reading the bytes back:
the entire 144-byte footprint is zero afterwards, and the ipad/opad midstates
do not survive. The same holds for the per-operation clone and for a
baseline-style per-operation instance. The production workspace denies
`unsafe_code`, so that check is a local diagnostic and not an in-tree test.

Two properties of the change are security *improvements*:

- `BlockBuffer` holds `MaybeUninit<Array<u8, U64>>`, and `HmacCore::new_from_slice`
  leaves its `key ^ opad` scratch block on the stack un-zeroized. A live keyed
  instance was observed carrying `key ^ opad` — trivially invertible to the raw
  PSK — in that uninitialised region. The baseline produced that residue on
  **every** authenticate and verify; the candidate produces it once per key.
- The resident secret is now the ipad/opad midstates rather than the raw PSK.
  Both forge NXR tags equally, but recovering the PSK itself from midstates
  requires inverting SHA-256 compression.

Cost: `size_of::<NxrKey>()` grows from 32 to 144 bytes. One `NxrKey` exists per
configured NXR inbound (`NxrAuthenticator`) and per configured NXR outbound
(`CompiledNxr`) — never per connection or per session — so the +112 bytes is a
per-configuration constant. `Debug` still prints `NxrKey([REDACTED])`, and the
number of key copies is unchanged.
