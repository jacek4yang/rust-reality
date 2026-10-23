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
