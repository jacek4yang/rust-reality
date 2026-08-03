# 安全策略

[English](SECURITY.md) | 简体中文

## 支持范围

项目目前处于 1.0 之前。安全修复应用于最新 GitHub Release 和当前 `main`；除非
发布说明另有声明，不维护更早的 1.0 前版本。不要部署任意开发 commit。

## 漏洞报告

可能暴露用户、密钥、流量或部署信息的问题，请使用 GitHub 私密漏洞报告。不要
通过公开 issue 提交可工作的 exploit，也不要附带真实密钥、UUID、地址、抓包或
配置文件。

有效报告应包含受影响 commit、操作系统与架构、最小且不含秘密的复现、期望不变量
和实际结果。

## 密码学边界

仓库负责协议状态、transcript、framing、缓冲所有权和 admission 策略，但不自行
实现 AES-GCM、ChaCha20-Poly1305、HKDF、SHA-2、X25519、Ed25519、ML-KEM、
ML-DSA、HMAC 或随机数原语；这些操作由专门 Rust 库和操作系统提供。

公网流量只接受 REALITY 上的 VLESS，并强制 `xtls-rprx-vision`。NXR 是独立、
受防火墙限制的内部跳转，不能替代公网协议。
