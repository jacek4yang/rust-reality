# Security policy

## Supported code

The project is pre-1.0. Security fixes are applied to the latest GitHub Release
and the current `main` branch; older pre-1.0 releases are not maintained unless
a release notice says otherwise. Do not deploy an arbitrary development commit.

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
Those operations remain in dedicated Rust libraries and the operating system.

Public traffic is accepted only as VLESS over REALITY with
`xtls-rprx-vision`. NXR is a distinct internal, firewall-restricted hop and is
not an Internet-facing replacement for that public protocol.
