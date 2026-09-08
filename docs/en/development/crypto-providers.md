# Production cryptographic providers

English | [简体中文](../../zh-CN/development/crypto-providers.md)

The v2 provider set is final in [ADR 0028](../../adr/0028-finalize-the-v2-crypto-provider-set.md).
Versions are locked in `Cargo.lock`; this table describes ownership, including
paths that intentionally retain more than one AEAD implementation.

| Primitive | Production provider |
| --- | --- |
| X25519 in REALITY, TLS, the client, probes and Handoff | `rr-crypto`, provenance-pinned s2n-bignum assembly; x86_64 and AArch64 runtime dispatch |
| SHA-256/384/512 | RustCrypto `sha2`; x86_64 SHA-NI for SHA-256 and AVX2 for SHA-384/512 |
| HMAC | RustCrypto `hmac` |
| HKDF | RustCrypto `hkdf` |
| AES-128/256-GCM TLS records | ring by default; RustCrypto `aes-gcm` without default features |
| REALITY authentication AES-GCM | RustCrypto `aes-gcm` |
| ChaCha20-Poly1305 TLS records | ring by default; RustCrypto `chacha20poly1305` without default features |
| Handoff ChaCha20-Poly1305 | RustCrypto `chacha20poly1305` |
| Ed25519 | RustCrypto `ed25519-dalek` |
| ML-KEM-768 | RustCrypto `ml-kem` |

Asset HTTPS uses `ureq`/rustls and ring's TLS internals, including its own key
exchange. It is outside rust-reality's X25519 protocol boundary. ring still
requires a C compiler; the production graph no longer requires AWS-LC's CMake
build. `getrandom` supplies operating-system entropy through `crypto::entropy`;
the immutable static-key and consuming ephemeral-key interfaces own secrets.

`aws-lc-rs` and `x25519-dalek` are dev-only independent differential oracles
and benchmark comparators. Their presence in `Cargo.lock` is expected; their
presence in the normal graph is forbidden. No path or Git dependency on
fastcrypto is permitted. Reproduce the production ledger and boundary gate:

```shell
cargo tree --locked --package rust-reality --edges normal
cargo tree --locked --package rust-reality --edges normal --all-features
cargo test --locked --test crypto_boundary
cargo test --locked --test x25519_differential
```

Retain the tree, ELF metadata, target, features, compiler, build command and
binary hash with the exact release artifact. AArch64 QEMU tests demonstrate
correctness; no AArch64 performance result is implied. See
[crypto provenance](crypto-provenance.md) for licenses, pinned input hashes,
assembly reproduction, and the limits of inherited upstream verification.
