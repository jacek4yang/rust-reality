# ADR 0060: XUDP over NXR and Handoff

Status: Accepted. §3 and the Handoff rows of §4 are superseded by
[ADR 0069](0069-native-udp-channel-for-handoff-xudp.md): Handoff XUDP no
longer transfers TLS or a policy snapshot; LINE routes every datagram and
sends it to LANDING over a native UDP channel. The NXR design is unchanged.

## Context

v2.1.0 ships XUDP (VLESS Mux command `0x03`) for UDP ASSOCIATE and
UDP/443 policy on the public REALITY + Vision path, with stock Xray-client
ingress required under [ADR 0059](0059-asymmetric-stock-xray-interop.md).
Server egress is **Direct-only**: `require_direct_xudp_route` in
`src/server/xudp.rs` fails closed for NXR, Handoff, and Block
(`docs/en/development/xudp.md`).

NXR today authenticates one destination over TCP (`NXR1` HMAC request), then
relays **raw bidirectional TCP** with no post-auth framing
(`src/protocol/nxr.rs`, `NxrLandingHandler::handle`). Handoff transfers
KeyUpdate-capable TLS state to LANDING and leaves LINE as a thin ciphertext
splice ([ADR 0031](0031-handoff-transfers-keyupdate-capable-state.md)).
Neither path carries datagram boundaries or UDP sockets.

v2.2.0 must add real application UDP through **both** NXR and Handoff LANDING
egress for rust↔rust and unmodified stock Xray → rust-reality, including
multi-destination Keep rewrites and genuine QUIC/HTTP3 over UDP/443 when
policy allows — without silent Direct fallback, without a new public wire
protocol, and without giving up Handoff TLS offload.

## Decision

### 1. Public wire unchanged

XUDP remains Mux `0x03` to `v1.mux.cool:666` inside REALITY + Vision.
No second public protocol, no duplicate configuration schema, no insecure
downgrade path (AGENTS.md §6 / §8; ADR 0059 preserved).

### 2. NXR UDP carrier — Option A (framed datagrams over existing TCP)

Use the existing LINE→LANDING **TCP** hop. After an authenticated NXR open
that admits a **UDP/XUDP association mode** (flags or request shape distinct
from TCP-connect mode), replace the post-auth raw TCP↔TCP relay with
**length-prefixed datagram frames** carrying destination metadata and UDP
payload in both directions.

Rejected **Option B** (native UDP LINE→LANDING hop): new transport, firewall,
NAT, and warm-pool model without a current necessity; larger attack surface
for replay and association binding.

Post-auth NXR remains plaintext to hop observers (existing threat model).
Because multi-destination frames would otherwise let a hop attacker redirect
UDP, **destination fields in NXR UDP frames MUST be integrity-protected** by a
session MAC derived from the authenticated open (PSK + transcript/nonce).
Payload confidentiality is not added (same as TCP NXR).

### 3. Handoff UDP — preserve TLS ownership; Option B rewrite authorization

- **TLS ownership** stays on LANDING after transfer (ADR 0031). LINE remains a
  thin raw ciphertext splice for the client-facing TLS records.
- **XUDP / Vision framing** is decoded and encoded on LANDING (only place with
  traffic secrets after transfer).
- **UDP sockets** are owned by LANDING.
- **Routing authority for Keep destination rewrites:** transfer a
  **session-bound policy snapshot** (compiled authorization relevant to this
  user/session and UDP egress via this Handoff outbound) sealed with the
  continuation / transfer. LANDING evaluates each rewrite against that snapshot
  and fails closed on deny. In-flight sessions keep the snapshot from transfer
  time; new sessions observe reload generations (mixed-gen documented, not
  live-mutated mid-association).

Rejected **Option A** as a **live** LANDING→LINE authorization RPC or
multiplexed control on the splice socket: it conflicts with the thin splice /
zero TLS steady-state on LINE that is the point of Handoff. Sealed tickets
issued only at transfer time without a policy snapshot cannot authorize
unpredictable multi-destination Keep targets without LINE seeing plaintext
again.

### 4. Answers (security / ownership)

| # | Question | Answer |
| --- | --- | --- |
| 1 | TLS ownership (Handoff) | LANDING after successful transfer; LINE never re-enters TLS/Vision for that session. |
| 2 | XUDP framing owner | Direct/NXR: LINE (Vision path). Handoff: LANDING after resume. |
| 3 | Routing authority | LINE for Direct and NXR (each New/Keep). Handoff: LINE authorizes transfer; LANDING applies sealed policy snapshot for later Keep rewrites. |
| 4 | UDP socket owner | Direct: entry/LINE process. NXR/Handoff: LANDING. |
| 5 | Datagram boundaries | Public: XUDP codec. NXR landward: length-prefixed framed datagrams. Handoff landward: TLS records (splice); UDP only at LANDING egress. |
| 6 | Rewrite authorization | Every Keep destination change re-evaluated; prior allow does not authorize Block/other class; no silent Direct fallback. |
| 7 | Association auth | Bound to authenticated VLESS user + GlobalID rules (existing process-wide map); NXR open / Handoff transfer bind the landward association. |
| 8 | Replay | NXR open nonce cache unchanged; session MAC covers landward dest headers. Handoff transfer nonce/replay unchanged; snapshot is inside AEAD blob. |
| 9 | Failure | Fail closed with explicit errors; zero silent Direct; Handoff auth failures remain silent close (existing contract). |
| 10 | Reload | New sessions see new generation; in-flight NXR/Handoff UDP associations do not silently widen authority mid-life. |
| 11 | Bounds | Preserve/extend `XUDP_MAX_ASSOCIATIONS`, idle expire, FD budgets, payload cap 7526; landward frame caps ADR'd in implementation PRs. |
| 12 | Versioning | Prefer NXR flags/mode and Handoff continuation fields within current protocol families; no version-dispatched dual parsers (AGENTS.md §9 spirit). Mismatched peers fail closed. |
| 13 | Mixed generation | Admission-and-drain for breaking landward contracts (same operator discipline as ADR 0031). |
| 14 | TCP protection | TCP Vision/Direct/NXR/Handoff paths MUST NOT regress; UDP work stays behind explicit route classes and tests. |

### 5. Implementation sequencing (non-normative)

Tracked by Issue #314: foundations → NXR framing/E2E → Handoff UDP →
multi-dest adversarial → QUIC/H3 gates → resources/perf → docs/release.
Direct-only or NXR-only is **not** completion.

## Consequences

- `require_direct_xudp_route` becomes a Direct-only helper; NXR/Handoff gain
  explicit authorized paths rather than removing fail-closed behavior.
- Operator docs (`xudp.md`, architecture, protocol, threat-model) must state
  NXR/Handoff UDP support and the Handoff snapshot/reload rules when code
  lands — not in this ADR alone.
- Warm pools and TcpRelay remain TCP; NXR UDP mode is a distinct post-auth
  handler path on the same listener family.
- Performance claims require measurement (AGENTS.md §16); this ADR asserts
  no speedup.
- Issues #253 and #291 remain independent of v2.2.0 publication.

## References

- Issue #314 — primary v2.2.0 tracking
- [ADR 0031](0031-handoff-transfers-keyupdate-capable-state.md) — Handoff TLS state
- [ADR 0059](0059-asymmetric-stock-xray-interop.md) — asymmetric Xray interop
- `docs/en/development/xudp.md` — current Direct-only contract
- `src/server/xudp.rs`, `src/protocol/nxr.rs`, `src/protocol/handoff.rs`
