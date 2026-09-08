# 生产密码学实现

[English](../../en/development/crypto-providers.md) | 简体中文

v2 的实现选择已由 [ADR 0028](../../adr/0028-finalize-the-v2-crypto-provider-set.md)
确定。具体版本由 `Cargo.lock` 锁定。下表说明各路径的实现归属；部分 AEAD
路径有意保留两个成熟实现。

| 原语 | 生产实现 |
| --- | --- |
| REALITY、TLS、客户端、探测和 Handoff 的 X25519 | `rr-crypto`，固定来源版本的 s2n-bignum 汇编；x86_64 和 AArch64 运行时分派 |
| SHA-256/384/512 | RustCrypto `sha2`；x86_64 的 SHA-256 使用 SHA-NI，SHA-384/512 使用 AVX2 |
| HMAC | RustCrypto `hmac` |
| HKDF | RustCrypto `hkdf` |
| AES-128/256-GCM TLS 记录 | 默认 ring；关闭默认特性时使用 RustCrypto `aes-gcm` |
| REALITY 认证 AES-GCM | RustCrypto `aes-gcm` |
| ChaCha20-Poly1305 TLS 记录 | 默认 ring；关闭默认特性时使用 RustCrypto `chacha20poly1305` |
| Handoff ChaCha20-Poly1305 | RustCrypto `chacha20poly1305` |
| Ed25519 | RustCrypto `ed25519-dalek` |
| ML-KEM-768 | RustCrypto `ml-kem` |

资源 HTTPS 下载使用 `ureq`/rustls 和 ring 自身的 TLS 内部实现，包括密钥交换。
它不属于 rust-reality 自有协议的 X25519 边界。ring 仍需 C 编译器；生产依赖图
已不再需要 AWS-LC 的 CMake 构建。操作系统熵由 `getrandom` 经
`crypto::entropy` 提供；不可变静态密钥和消费式临时密钥接口负责秘密的生命周期。

`aws-lc-rs` 和 `x25519-dalek` 仅作为开发期独立差分 oracle 和基准比较对象。
它们出现在 `Cargo.lock` 中是正常的，出现在 normal 生产依赖图中则不允许。
不允许对 fastcrypto 建立路径或 Git 依赖。复现依赖清单和边界检查：

```shell
cargo tree --locked --package rust-reality --edges normal
cargo tree --locked --package rust-reality --edges normal --all-features
cargo test --locked --test crypto_boundary
cargo test --locked --test x25519_differential
```

将依赖树、ELF 元数据、目标、特性、编译器、构建命令和二进制哈希与精确发布产物
一起保留。AArch64 QEMU 测试证明正确性，不代表 ARM 性能测量。
许可证、固定输入哈希、汇编复现步骤和上游验证的适用范围见
[密码学来源记录](../../en/development/crypto-provenance.md)。
