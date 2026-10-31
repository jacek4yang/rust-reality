# XUDP and Vision UDP/443

Authority: stock Xray-core v26.7.28 (`5ca6f4b7d4dc20a881d4330e498892697627ec0c`).

## Two different names

| Name | What it is |
| --- | --- |
| `xtls-rprx-vision-udp443` | Client **config policy** that permits UDP/443. Wire Addons still carry `xtls-rprx-vision`. |
| **XUDP** | VLESS Mux command `0x03` to synthetic `v1.mux.cool:666`, plus Mux-shaped datagram framing (`common/xudp`). |

See Issue [#254](https://github.com/jacek4yang/rust-reality/issues/254) for pin line citations.

## Supported routes (server)

| Outbound | UDP via XUDP |
| --- | --- |
| Direct | Supported (local Direct UDP sockets) |
| NXR | **Authorized** as a distinct egress capability ([ADR 0060](../../adr/0060-xudp-over-nxr-and-handoff.md)). Landward carrier: authenticated `FLAG_UDP` open + length-prefixed session-MAC frames over LINE→LANDING TCP (`protocol::nxr_udp`). LANDING owns UDP sockets. Vision→NXR session wiring lands datagrams on LANDING via the framed carrier; Vision fails closed after authorization without opening Direct sockets on LINE. |
| Handoff | **Authorized** as a distinct egress capability ([ADR 0060](../../adr/0060-xudp-over-nxr-and-handoff.md) Option B). Continuation v3 carries `SessionKind::Xudp` + sealed `HandoffPolicySnapshot` v2 (ordered sealable route rules + default-outbound allow). LINE transfers before any client-visible Vision response; LANDING resumes TLS, owns UDP, frames XUDP, and evaluates Keep rewrites against the snapshot. Geosite/GeoIP/regexp/ext matchers fail closed to initial-only. Same no-silent-Direct rule. |
| Block | Rejected by routing / authorization as usual |
| Other (e.g. SOCKS5) | Fail closed (`Unsupported`) |

See Issue [#314](https://github.com/jacek4yang/rust-reality/issues/314).


## Keep destination rewrites

A Keep frame may embed a new UDP destination (multi-address association). Each
rewrite is re-evaluated through the same canonical routing table, DNS strategy,
and capability-aware egress authorization (`authorize_xudp_egress`) as the
opening New frame. A destination that previously routed to Direct does **not**
authorize a later Block or unknown outbound — the session fails closed. NXR and
Handoff authorize as themselves and must never be silently remapped to Direct.

## Carrier

XUDP datagrams ride inside the existing REALITY + Vision stream. This is not a second public wire protocol and not native QUIC transport.

## Client SOCKS5 UDP ASSOCIATE

The unified client accepts loopback SOCKS5 UDP ASSOCIATE and carries datagrams
as XUDP over one committed REALITY + Vision LINE (Mux command `0x03`).

- Multi-address sessions: each SOCKS5 UDP datagram may name a different
  destination; the first opens XUDP (`New`), later packets use `Keep` (with
  destination rewrite when the target changes).
- LINE ownership: selection commits before the ASSOCIATE success reply; the
  association never migrates mid-session.
- UDP/443: permitted only when the LINE sets `allowUdp443: true` (stock
  `xtls-rprx-vision-udp443` policy). Wire flow remains `xtls-rprx-vision`.

## Qualification (unified-client UDP series)

PR4 adds process-level evidence on top of the unit framing/auth/server Direct
tests from earlier PRs:

| Evidence | What it proves |
| --- | --- |
| SOCKS5 UDP ASSOCIATE E2E | Loopback client → REALITY entry → Direct UDP echo with byte-exact payload |
| UDP/443 policy | Without `allowUdp443`, UDP/443 fails closed; with it, XUDP may carry 443 |
| Framing fuzz | `fuzz_decode_xudp_packet` remains in the wire-parser fuzz shard |
| Route fail-closed | Block/unknown reject at authorize; NXR/Handoff are distinct capabilities and must not silently become Direct |
| NXR UDP E2E (PR3) | rust↔rust and stock Xray Client → LINE → NXR LANDING → UDP echo; LANDING source `127.0.0.2` proof; multi-dest Keep; Block → zero packets; genuine Quinn+h3 UDP/443 via NXR; `allowUdp443` policy |
| Handoff XUDP continuation (PR4) | Continuation v3 `SessionKind` + policy snapshot; version mismatch fail-closed; KeyUpdate/seq/prefetch preserved; LANDING owns TLS+UDP; LINE thin splice |
| Multi-dest sealed policy (PR5) | Handoff policy snapshot v2: ordered sealable rules; Block/other deny before default allow; geosite/geoip fail-closed; NXR Keep re-auth on LINE unchanged |
| Handoff UDP E2E (PR6) | rust↔rust and stock Xray → LINE → Handoff LANDING → UDP echo; LANDING source `127.0.0.2` proof; multi-dest Keep + Block zero packets; genuine Quinn+h3 UDP/443; Native gates |

This is **not** native QUIC transport. QUIC/443 traffic, when permitted, is still
UDP datagrams inside Vision/XUDP over the existing REALITY LINE.

Cancellation and association teardown: closing the SOCKS5 TCP control connection
ends the XUDP association; idle associations expire per `XUDP_ASSOCIATION_IDLE`.

## Cross-implementation notes

Directional contract (AGENTS.md §6, ADR 0059):

| Direction | Gate status |
| --- | --- |
| rust-reality Client ↔ rust-reality Server | **Required** (TCP Vision + UDP/XUDP, including `allowUdp443`) |
| Unmodified stock Xray Client → rust-reality Server | **Required** ingress; Exact-head Native exercises it |
| rust-reality Client → stock Xray Server | **Not required**; no guarantee; not a CI/Native/Frozen/release gate |

- **TCP Vision / REALITY** with unmodified Xray-core **clients** continues under
  Exact-head Native qualification.
- **UDP via XUDP — mandatory proven:** unmodified stock Xray SOCKS client
  (`udp: true`, flow `xtls-rprx-vision-udp443`) → rust-reality entry Direct UDP
  echo. Exact-head Native downloads pinned Xray v26.9.9, verifies the zip
  SHA-256, exports `XRAY_BIN`, and runs
  `stock_xray_client_udp_echo_via_rust_reality_entry` with `--ignored --exact`
  (`tests/xudp_stock_xray_interop.rs`). The test panics if `XRAY_BIN` is missing;
  the workflow also fails on skip markers, zero matched cases, or any result
  other than exactly one pass. Local loopback single-datagram RTT samples
  (including fresh association setup) are diagnostic only, not a throughput claim.
- **UDP via XUDP — historical / ignored (not a release blocker):** rust-reality
  unified client → stock Xray VLESS+REALITY server. Past failure evidence
  (Go ClientHello parse, inbound `SetFlushNext` response ordering, freedom
  private-IP default block) is retained for archaeology; the test stays
  `#[ignore]` and MUST NOT block merge or release.
  Exploratory commit messages that mention enabling RR→Xray (e.g. tree history
  around ClientHello fixes) are **not** mandatory acceptance criteria.
- **QUIC/HTTP3 UDP/443 (rust↔rust):** not native QUIC transport on the REALITY
  LINE. XUDP carries UDP datagrams; `allowUdp443` gates destination port 443
  (stock vision-udp443 policy). Exact-head Native grants `CAP_NET_BIND_SERVICE`
  to `tests/quic_h3_udp443_e2e.rs`, sets `RR_REQUIRE_UDP443=1`, and runs:
  (1) positive UDP/443 echo via SOCKS5 UDP ASSOCIATE, (2) negative policy
  without `allowUdp443`, (3) genuine Quinn+h3 client → SOCKS5 UDP ASSOCIATE →
  rust-reality Client → REALITY+Vision+XUDP → rust-reality Server → Direct
  UDP/443 → independent h3 origin (ALPN `h3`, multi request/response, short
  idle, TCP watchdog on `:443` must see zero accepts). Unprivileged bind is
  **FAIL**, never a green skip. Quinn/h3 are **dev-dependencies only**.
- GlobalID affinity is **process-wide** (`process_xudp_global_map`). Payload
  capped at stock `buf.Size - 666` (7526); encode is failure-atomic.
  Association limits: `XUDP_MAX_ASSOCIATIONS`, idle expire, FD budgets;
  control EOF ends SOCKS5 UDP ASSOCIATE.

## Adversarial lifecycle and routing (Q3)

Exact-head Native runs `tests/xudp_adversarial_lifecycle.rs` as a mandatory
gate (`xudp-adversarial` evidence). It proves:

| Gate | Evidence |
| --- | --- |
| Destination rewrite security | Direct→Block/NXR/Handoff rejects; zero datagrams to a forbidden destination when authorization is withheld |
| GlobalID ownership | Active id cannot be claimed by a different VLESS user (`AssociationConflict`); capacity is process-wide (`XUDP_MAX_ASSOCIATIONS`) |
| Incomplete-frame progress | Truncated buffers retain bytes and require another read (no busy-spin) |
| Payload boundaries | Exact `XUDP_MAX_PAYLOAD_LEN` (7526) encodes; oversize fails closed and is failure-atomic |
| Cancel / recovery | `close` → expire → purge frees the GlobalID; same owner may reopen |
| Malformed + pressure | Codec rejects malformed prefixes; association limit under pressure then recovers |
| Fail-detection demos | UnauthorizedRewrite and egress route-class gates must remain present |

Rust Client → stock Xray Server remains **not required** (ADR 0059).

## Quantitative UDP performance (Q4)

`tests/xudp_udp_performance.rs` records loopback single-datagram RTT through
rust↔rust SOCKS5 UDP ASSOCIATE → XUDP, plus an A/A median ratio as noise
characterisation. Each timed call opens a new SOCKS/REALITY/XUDP association;
the initial untimed exchange primes shared caches but does not remove setup
from subsequent samples. This is not persistent-association datagram latency.
Exact-head Native may retain the receipt. These numbers are
**not** Internet throughput, **not** a capacity claim, and **not** a universal
speedup claim. Optional stock Xray Client→RR samples (when `XRAY_BIN` is set in
other suites) remain diagnostic; rust-reality Client→Xray Server is never required.

## PR7 six-cell Native matrix

Exact-head Native aggregates six client×topology UDP cells and fails closed on
a missing receipt or SKIP token:

| Client | Topology | Receipt gate |
| --- | --- | --- |
| rust-reality | Direct | `rust-direct-xudp` |
| rust-reality | NXR | `nxr-xudp-e2e` |
| rust-reality | Handoff | `handoff-xudp-e2e` |
| stock Xray | Direct | `stock-xray-xudp` |
| stock Xray | NXR | `stock-xray-nxr-xudp` |
| stock Xray | Handoff | `stock-xray-handoff-xudp` |

Adversarial lifecycle covers Keep rewrite security, GlobalID capacity,
association cancel/recover, repeated fault-cycle resource recovery, NXR frame
replay/bad-MAC rejection, cross-outbound Keep fences, reload-style retirement
without mid-life authority widening, and the no-silent-Direct fallback fence
for NXR/Handoff. TCP Vision client paths are re-exercised after the XUDP gates
(`tcp-non-regression`).

### QEMU / Frozen UDP acceptance

| Layer | Role |
| --- | --- |
| Exact-head Native | Six client×topology UDP cells, adversarial lifecycle, genuine QUIC/H3, and `ulimit -n 256` NXR+Handoff. Runs on the runner. Not a guest kernel. |
| QEMU guest | Four KVM cells, `nxr`/`handoff` × `ordinary`/`constrained`. Distinct guest kernels. LINE is `line-a` `192.0.2.1`. LANDING is `landing` `192.0.2.2`. The UDP origin lives only in the LANDING netns `198.51.100.2`. Successful datagrams are emitted from the LANDING listener address `192.0.2.2`. LINE cannot bypass LANDING. |
| Frozen aggregate | Fail-closed on the TCP four-cell VM campaign, the guest UDP four-cell receipts, and Exact-head Native six-cell, adversarial, and constrained receipts for the same SHA. |

Host-only tests are not guest qualification. TCP-only QEMU success is not UDP completion.

