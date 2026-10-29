# 客户端角色

[English](../../en/configuration/client.md) | 简体中文

**client** 节点只在回环上监听。它接受本机 SOCKS5 与/或 HTTP CONNECT，以
VLESS + REALITY + Vision 出站认证到 **entry**，并转发应用字节。它不持有公网
REALITY 身份，也不得绑到非回环地址。

另见 [ADR 0032](../../adr/0032-client-candidates-stop-before-destination-open.md)：
选择只竞赛认证；已提交的会话不会迁移；目标请求不会重放。

完整 JSON 示例与英文章节相同，见
[English client configuration](../../en/configuration/client.md)
（文档校验要求双语示例与 `format` 规范一致；此处不重复粘贴以免漂移）。

## 要点

- 默认入站是 SOCKS5（无认证 CONNECT）：`socks5h://127.0.0.1:10808`。
- `protocol: "http"` 只接受 HTTP/1.x `CONNECT`（`HTTPS_PROXY`）；不做
  absolute-form 正向代理。
- `lineGroups` + `selection`（`hedgeMs` / `timeoutMs`）实现 sticky 主选与 hedge；
  健康跳闸只影响**新**会话。
- Listener 必须绑定回环；每组 1–8 个 LINE tag；`entry` / `landing` 拒绝
  `protocol` 与 `lineGroup`。

## 相关

- [配置如何工作](index.md)
- [用户与凭证](users-and-credentials.md)
- [架构 — 共享客户端线格式边界](../architecture.md#共享的客户端线格式边界)

## SOCKS5 UDP ASSOCIATE（XUDP）

同一 SOCKS5 监听亦接受 **UDP ASSOCIATE**。数据报经 **XUDP**（VLESS Mux `0x03` /
Vision）在一条已提交的 LINE 上承载；不是第二套公网协议，也不是原生 QUIC。
UDP/443 仅在 LINE 设置 `allowUdp443: true` 时允许。服务端 XUDP 出站为
**Direct**、**NXR** 或 **Handoff**（[ADR 0060](../../adr/0060-xudp-over-nxr-and-handoff.md)）；
Block 与不支持的出站失败关闭，且不得静默回退到 Direct。详见英文
[XUDP and Vision UDP/443](../../en/development/xudp.md)。

## 浏览器 ClientHello

每个 LINE 可设置 `"fingerprint": "chrome"`（默认）或 `"fingerprint": "firefox"`。
固定的原生 Windows 版本分别为 Google Chrome Stable 156.0.8078.74 和 Firefox 159.0。
Chrome 提供 GREASE、X25519MLKEM768、X25519；Firefox 提供混合组、X25519 和 P-256。
Firefox 混合组复用独立 X25519 公钥，Chrome 使用独立密钥。所有真实 key share
都保留相应私钥用于协商。LINE 选择和竞速保持各自配置，格式化及生成的 schema 包含此字段。
未知名称、历史版本、Safari/iOS 和随机配置名称在加载时拒绝。

该配置复现无恢复、无真实 ECH 的首次 TCP ClientHello，保留每次握手的随机性、
Chrome 扩展洗牌、GREASE 和 ECH GREASE。生产运行时仅支持 TLS 1.3，并拒绝
HelloRetryRequest；声明的 TLS 1.2 掩护能力不启用 TLS 1.2 会话。
REALITY 的认证 session ID 和证书身份仍遵循协议自身约定。它验证 HMAC 绑定的
Ed25519 身份、Ed25519 CertificateVerify 和 Finished，即使原生浏览器的签名列表
不声明 Ed25519。这是现有 REALITY 证书策略，不是浏览器的 PKI 或签名协商策略；
测量等价范围限于 ClientHello，不代表通用浏览器 TLS 状态机。ClientHello 等价不代表
HTTP、QUIC、操作系统、时序或完整流量行为等价。浏览器与抓包依赖不进入生产二进制。
复现命令和证据见[测试文档](../development/testing.md)。
