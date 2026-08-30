# 安全策略

[English](../../SECURITY.md) | 简体中文

## 支持范围

安全修复应用于最新的 1.x GitHub Release 和当前 `main` 分支；除非发布说明
另有声明，不维护更早的 1.x 版本。不要部署任意开发 commit。

## 漏洞报告

可能暴露用户、密钥、流量或部署信息的问题，请使用 GitHub 私密漏洞报告。不要
通过公开 issue 提交可工作的 exploit，也不要附带真实密钥、UUID、地址、抓包或
配置文件。

有效报告应包含受影响 commit、操作系统与架构、最小且不含秘密的复现、期望不变量
和实际结果。

## 密码学边界

仓库负责协议状态、transcript、framing、缓冲所有权和 admission 策略，但不自行
实现 AES-GCM、ChaCha20-Poly1305、HKDF、SHA-2、X25519、Ed25519、ML-KEM、
ML-DSA、HMAC 或随机数原语。除一处明确记录的例外，这些操作都由专门的 Rust 库
和操作系统提供：生产密码套件（TLS_AES_128_GCM_SHA256）的 TLS 1.3 记录保护由
ring 0.17.x 提供，其 AES-GCM 源自 BoringSSL 的 C 与汇编实现，静态链接进发布
二进制。ring 仅用于这一个 AEAD 原语；握手密钥协商、密钥调度、签名和另外两个
密码套件仍由上述 Rust 库完成。Nonce 推导、序列号所有权、AAD 构造、framing 和
单密钥记录上限由本仓库实现，且在两种提供者下完全一致；逐字节跨提供者等价性和
RFC 8448 测试向量由在两种配置下都会运行的测试保证。

选择 ring 基于实测：在生产 16 KiB 记录尺寸下 AES-128-GCM seal/open 快约 2.5 倍，
大传输场景端到端 framed 吞吐提升 1.05–1.16 倍，服务端每 GiB CPU 降低 33%，
不引入任何新的依赖 crate（ring 已经由 ureq/rustls 存在于发布依赖图中），完全
静态链接，二进制体积还略有缩小。实测数字及其主机环境记录于
[`performance.zh-CN.md`](../en/performance.md)。

随之而来的是一个经过权衡的取舍。rust-reality 会在 drop 时清零它拥有的全部
秘密——ECDHE 与混合共享秘密、所有 HKDF 握手/主/流量秘密、原始流量密钥、
Finished verify data、REALITY 认证密钥和私钥材料——RustCrypto 的
AES-256-GCM 和 ChaCha20-Poly1305 状态也会清零其扩展密钥调度。ring 的
`LessSafeKey` 则不会：连接关闭后，其扩展 AES-128-GCM 密钥调度会残留在已释放的
堆内存中，直到分配器复用或进程退出。由于流量密钥在整个连接期间本来就驻留内存，
这只影响关闭后的残留窗口；本项目在此如实披露而非隐瞒。另外，记录认证失败后，
ring 构建的记录缓冲区内容是不确定的；没有任何调用方会读取该缓冲区，该契约已
在代码中固定。要求完整密钥调度清零的部署可以改用 RustCrypto 提供者构建：

```sh
cargo build --release --no-default-features
```

（默认 feature 集恰好就是 `ring-aead`；关闭默认 feature 即选择 RustCrypto
AES-128-GCM 提供者，没有其他行为差异。）

公网流量只接受 REALITY 上的 VLESS，并强制 `xtls-rprx-vision`。NXR 是独立、
受防火墙限制的内部跳转，不能替代公网协议。
