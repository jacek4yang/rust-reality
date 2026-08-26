# 协议概览

[English](protocol.md) | 简体中文

`rust-reality` 只暴露一个公网协议栈和两个内部跳转协议。本页概括各自的含义；
安全属性和信任边界以 [threat-model.zh-CN.md](threat-model.zh-CN.md) 为准。

## 公网栈：VLESS + REALITY + Vision

```text
兼容 Xray 的客户端
  -> VLESS + REALITY + xtls-rprx-vision 公网 listener
  -> 服务端上的 UUID 策略与路由
  -> direct | SOCKS5 | blackhole | NXR | Handoff 出站
  -> 目标地址
```

- **REALITY** 提供伪装与认证外层。服务端伪装成配置的 TLS 1.3 目标；客户端在
  看似普通 TLS 1.3 握手的过程中证明持有每用户密钥材料。配置的 server name
  可以是具体 DNS 名称，也可以是 `*.lmu.edu` 这样的最左单标签模式；
  ClientHello 的 SNI 必须保持具体。只有验证通过预期的 TLS 1.3
  ClientFinished 之后才提交认证状态。每个 VLESS UUID 拥有一个或多个 REALITY
  short ID：ClientHello short ID 先通过不可变、按基数自适应的 owner 索引解析
  出 UUID；VLESS 解码后，头中的 UUID 必须与该 owner 完全相等。因此从两个
  不同客户端条目分别复制 UUID 与 short ID，无法拼成获准会话。
  已认证 setup 有三层 fail-safe cover 路径：精确匹配的 validated profile 在本地
  生成全新 flight；否则用已完成 TCP 建连的 warm socket 取得当前真实目标 flight；
  再否则使用普通 cold cover 路径。prebuilt 模式绝不重放 ServerHello 或密钥材料，
  且认证与重放预留前不可达。
- **Fallback** 是失败模式：未认证连接会按序、逐字节地转发到伪装目标。没有
  任何合成响应会把服务标识为代理，且 fallback 并发独立于已认证流量计数。
- **VLESS** 是 TLS 流内的已认证请求协议：UUID、命令和目标。解密为 `none`——
  机密性与完整性由外层 REALITY TLS 1.3 记录层提供。v1.3 不在 REALITY 内再
  叠加 VLESS Encryption，因为它会禁用 Vision splice 并重复逐字节加密；实测
  与结论见[决策记录](decisions/0003-do-not-stack-vless-encryption-on-reality.md)。
- **`xtls-rprx-vision`** 是唯一接受的 flow。它在 framed 阶段提供 padding 与
  长度混淆，并支持 **Direct** 转换：当某方向完成认证并识别出内层 TLS 1.3
  应用数据后，该方向切换为 raw relay（优先 Linux `splice`），边界不变量见
  [architecture.zh-CN.md](architecture.zh-CN.md)。公网入站不支持纯 VLESS、
  仅 TLS 的 VLESS、WebSocket、QUIC、UDP 代理或非 Vision flow。

公网栈与 Xray-core 客户端线兼容；兼容性门禁见
[benchmarks.zh-CN.md](benchmarks.zh-CN.md)。

## 出站

- **direct**：有界连接，可选域名策略（在有界、快速失败的池中做 DNS 解析）和
  限制未认证拨号速率的 direct barrier。
- **SOCKS5**：指向上游 SOCKS5 服务器的出站，可选用户名/密码认证。可选 warm
  状态只有 TCP；method negotiation、认证与 CONNECT 仍逐流进行。
- **blackhole**：有界丢弃，可选响应延迟。
- **NXR**：把流量转发到落地机（见下）。
- **Handoff**：把整个会话转移到落地机（见下）。

## NXR：内部线路机到落地机跳转

NXR 是未认证 SOCKS 式线路机到落地机访问的内部替代品，不是公网协议。线路机
上每条已认证的用户 TCP 流量独占一条到落地机的 NXR TCP 连接，并恰好发送一个
有界请求：版本、目标、时间戳、随机 nonce，以及在独立 32 字节预共享密钥下的
HMAC。落地机在任何 DNS 解析或目标连接之前检查结构、时间窗、HMAC 和有界
nonce 重放缓存；失败即静默关闭。

这一次性认证请求之后，NXR 永久切换为带 half-close 的裸双向字节流：没有
TLS、REALITY、AEAD、证书、多路复用、持久 framing，也没有认证后的
加密。NXR listener 必须用防火墙限制为只允许线路机固定源 IP，并且整个跳转
必须按明文对待：任何能观测该链路的人都能观测没有端到端保护（例如 HTTPS）
的载荷。

TCP 可以在用户流出现前建立，但仍未获协议权限。LANDING 在有界 pre-auth idle
策略下等待首字节，然后对请求剩余部分应用原有短截止时间；idle 阶段没有重放
状态、DNS 或目标副作用。checkout 的 socket 只使用一次，每次尝试都生成 fresh
timestamp、nonce 与 HMAC；完整请求写入后绝不重试逻辑流。

## Handoff：内部会话转移跳转

Handoff 是内部的会话转移机制，不是公网协议。在 REALITY 认证、VLESS 解码和
路由之后，线路机把整个会话——TLS 记录状态、序列号、Vision 上下文和待发送
字节——用一条密封且防重放的消息转移给落地机；此后线路机只中继该会话的
TLS 密文。

转移消息用落地机静态密钥做一次新的临时 X25519 交换，与独立的配对 PSK 在同一
条 HKDF-SHA256 链上混合，并以一次 ChaCha20-Poly1305 密封；在任何密钥协商
之前先检查时间窗和有界 nonce 缓存，任何失败都静默关闭、零响应字节。成功后
落地机重建会话的 TLS 记录层并连接转移过来的目标——默认直接连接，或经监听器
`egress` 设置指定的出站（`direct`、`socks5`、`nxr` 或 `blackhole`；Handoff
不链式嵌套）——随后恢复会话。在密钥轮换窗口内，落地机还接受最多两个已退役的
配对 PSK 和静态密钥对（`previousPreSharedKeys`/`previousPrivateKeys`），从而
实现不停机轮换；窗口结束后应及时移除退役密钥。落地机不对
转移的目标应用路由策略，且持有活跃会话密钥，因此其内存属于会话保密边界的
一部分。Handoff listener 必须只允许线路机的地址访问。

TCP 同样可以提前建立，且不改变 Handoff wire bytes 或权限。首个 transfer 字节
结束有界零字节 idle 阶段并启动短 transfer 认证截止时间。每次 checkout 都密封
fresh timestamp/nonce/临时密钥/AEAD state。只有完整 transfer 写入前才允许一次
有界替代；越过该界后 LANDING 可能已经恢复会话或连接目标，迟到失败是最终失败。

## 一段话信任边界

公网 listener 抵御未认证的协议识别、主动探测、ClientHello 重放、畸形记录输入
和本地资源耗尽。认证前的一切都有界且日志不含秘密。部署者仍然要负责伪装目标
的选择、防火墙策略（尤其是 NXR 和 Handoff）、VPS 链路（应用无法吸收上游流量型 DDoS）和
端点被控（REALITY 不会让被控端点变得可信）。完整模型与非目标见
[threat-model.zh-CN.md](threat-model.zh-CN.md)。
