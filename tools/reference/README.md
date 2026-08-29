# TLS-shape OpenSSL reference

`tls-shape-openssl.c` is the deliberately narrow independent reference boundary
for `cargo dev bench run --suite tls-shape`. It performs one dynamic TLS 1.3
server handshake with the run's exact captured stock-Xray `ClientHello`.

This cannot be replaced by a static fixture: the suite varies cipher suites,
groups, ALPN, middlebox CCS, send/split fragments, record padding, and
`TCP_NODELAY`. It cannot be replaced by the rust-reality TLS implementation
without destroying the cross-implementation proof. The typed Rust runner owns
compilation, argv, identity, hashing, bounds, evidence, and cleanup; this file
contains no orchestration or policy.

