# Security policy

English | [简体中文](docs/zh-CN/security.md)

## Supported code

Security fixes are applied to the latest 1.x GitHub Release and the current
`main` branch; older 1.x releases are not maintained unless a release notice
says otherwise. Do not deploy an arbitrary development commit.

## Reporting

Use GitHub private vulnerability reporting for findings that could expose
users, keys, traffic, or deployment details. Do not open a public issue with a
working exploit or any real key, UUID, address, packet capture, or config file.

A useful report includes the affected commit, operating system and architecture,
minimal secret-free reproduction, expected invariant, and observed result.

## Cryptographic boundary

The repository owns protocol state, transcripts, framing, buffer ownership, and
admission policy. It does not implement AES-GCM, ChaCha20-Poly1305, HKDF, SHA-2,
X25519, Ed25519, ML-KEM, ML-DSA, HMAC, or random-number generation primitives.
With one documented exception those operations remain in dedicated Rust
libraries and the operating system: TLS 1.3 record protection for the
production cipher suite (TLS_AES_128_GCM_SHA256) is provided by ring 0.17.x,
whose AES-GCM is BoringSSL-derived C and assembly, statically linked into the
release binary. ring is used for this one AEAD primitive only; handshake key
agreement, key schedule, signatures, and the other two cipher suites remain in
the Rust libraries above. Nonce derivation, sequence ownership, AAD
construction, framing, and per-key record limits are implemented by this
repository and are identical under both providers; byte-exact cross-provider
equivalence and the RFC 8448 vectors are enforced by tests that run under both
configurations.

ring was selected on measurement: ≈2.5× faster AES-128-GCM seal/open at
production 16 KiB record sizes, 1.05–1.16× end-to-end framed throughput on
large-transfer cells, −33% server CPU per GiB, zero new dependency crates
(ring already ships in the release graph via ureq/rustls), a fully static
link, and a slightly smaller binary. The measured numbers and their host
context are recorded in [`docs/performance.md`](docs/en/performance.md).

One deliberate tradeoff follows. rust-reality zeroizes every secret it owns
on drop — ECDHE and hybrid shared secrets, all HKDF handshake/master/traffic
secrets, raw traffic keys, Finished verify data, the REALITY authentication
key and private key material — and the RustCrypto AES-256-GCM and
ChaCha20-Poly1305 states zeroize their expanded key schedules as well.
ring's `LessSafeKey` does not: after a connection closes, its expanded
AES-128-GCM key schedule remains in freed heap memory until the allocator
reuses it or the process exits. Because traffic keys are live in memory for
the whole connection anyway, this affects only the post-close residue
window; it is disclosed here rather than hidden. Separately, after a failed
record authentication the ring build leaves the record buffer contents
unspecified; no caller reads that buffer, and the contract is pinned in
code. Deployments that require complete key-schedule zeroization can build
the RustCrypto provider instead:

```sh
cargo build --release --no-default-features
```

(the default feature set is exactly `ring-aead`; disabling defaults selects
the RustCrypto AES-128-GCM provider with no other behavioral change).

Public traffic is accepted only as VLESS over REALITY with
`xtls-rprx-vision`. NXR is a distinct internal, firewall-restricted hop and is
not an Internet-facing replacement for that public protocol.
