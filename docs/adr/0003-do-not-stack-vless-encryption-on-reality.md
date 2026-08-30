# 0003. Do not stack VLESS Encryption on REALITY

- Status: accepted for v1.3
- Date: 2026-08-10

## Context

Xray added VLESS Encryption in 2025 as an outer connection wrapper with
hybrid ML-KEM-768 + X25519 forward secrecy, optional post-quantum static
authentication, reusable anti-replay 0-RTT tickets, and AES-256-GCM or
ChaCha20-Poly1305 records. These are real security improvements for raw VLESS,
CDN termination, and untrusted relay scenarios. The [upstream design][pr-5067]
also recommends XTLS so that nested TLS data can leave the record layer after
its initial handshake.

This project has a different fixed public stack: VLESS is already carried
inside end-to-end REALITY TLS 1.3 and Vision. Plain public VLESS is rejected.
The current Xray security policy accepts either VLESS Encryption or
TLS/REALITY for a public outbound; it does not require both
([upstream policy change][pr-6303]). The Rust REALITY implementation already
supports the X25519MLKEM768 TLS 1.3 group selected by current Xray clients,
authenticates the pinned REALITY server key, and maintains bounded replay
state.

Stacking VLESS Encryption inside REALITY therefore adds a second stateful
cryptographic transport. In Xray v26.7.28, `CommonConn` frames at most 8 KiB
and applies one data AEAD per frame ([implementation][common-conn]). More
importantly, Vision explicitly disables splice when VLESS Encryption wraps
another security connection such as REALITY ([Vision condition][vision-gate]).
That condition is correct: penetrating only one wrapper would bypass the
other wrapper's authentication state.

## Evidence

`cargo dev bench run --suite vless-encryption` compares the two modes with the same
Xray v26.7.28 build, REALITY, Vision, client, loopback TLS 1.3 origin, and
randomized execution order. VLESS Encryption uses `native` and is warmed first,
so connection setup receives its intended best-case 0-RTT ticket path.

On the release host (4-core x86-64, Linux 6.12), five samples per mode at four
concurrent 64 MiB downloads measured:

| Metric | `none` + REALITY | VLESS Encryption + REALITY | Ratio |
| --- | ---: | ---: | ---: |
| p50 throughput | 841.41 MiB/s | 585.64 MiB/s | 0.696x |
| mean server CPU/GiB | 0.288 s | 1.584 s | 5.50x |
| p50 setup rate, warmed 0-RTT | 93.95 conn/s | 90.51 conn/s | 0.963x |
| mean server CPU/connection | 4.94 ms | 5.81 ms | 1.18x |

The result is not a claim about raw VLESS Encryption. It is evidence for the
specific nested stack this server would deploy. The raw report is retained in
the v1.3 analysis artifacts; the checked-in canonical values are in
`benchmarks/evidence/releases/v1.3-vless-encryption/summary.json`.

## Decision

Do not implement or expose VLESS Encryption in the v1.3 public REALITY
inbound. Keep `settings.decryption` fixed to `none`, keep REALITY mandatory,
and do not let automatic tuning enable a wire-protocol or security-mode change.

The incremental security benefit does not justify a 30.4% p50 throughput loss,
5.5x server CPU/GiB, loss of splice, a second replay/ticket lifecycle, and a
substantially larger interoperability and cryptographic audit surface. This is
an architecture decision, not a rejection of VLESS Encryption for the raw or
CDN use cases it was designed to strengthen.

## Revisit criteria

Reconsider as a separate transport profile, rather than silently stacking it
on REALITY, only when all of these conditions hold:

1. a deployment requirement exists where REALITY is not end-to-end (for
   example CDN termination or an untrusted intermediate relay);
2. the wire format has stable test vectors and differential interoperability
   coverage for 1-RTT, 0-RTT, ticket expiry, replay, key rotation, malformed
   frames, and `native`/`xorpub` modes;
3. fuzzing and an independent cryptographic review cover every new state
   transition and failure path;
4. either upstream supports safe nested-REALITY penetration or a raw profile
   preserves Vision direct/splice;
5. the release-host gate reaches at least 90% of the current p50 throughput and
   no more than 1.25x server CPU/GiB; and
6. the mode is explicit manual configuration, never an auto-tuner decision.

[pr-5067]: https://github.com/XTLS/Xray-core/pull/5067
[pr-6303]: https://github.com/XTLS/Xray-core/pull/6303
[common-conn]: https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/proxy/vless/encryption/common.go#L47-L77
[vision-gate]: https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/proxy/vless/inbound/inbound.go#L552-L568
