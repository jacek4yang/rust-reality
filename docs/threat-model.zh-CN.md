# 威胁模型

[English](threat-model.md) | 简体中文

## 受保护的数据路径

```text
兼容 Xray 的客户端
  -> VLESS + REALITY + xtls-rprx-vision 公网监听
  -> 线路机 UUID 策略
  -> direct | SOCKS5 | blackhole | NXR
  -> 可选、受防火墙限制的 NXR 落地机
  -> 目标地址
```

公网监听始终要求 TCP、REALITY、VLESS decryption `none` 和 Vision flow。尝试纯
VLESS 的配置会在绑定监听端口前被拒绝。`serverNames` 可使用具体 DNS 名或
`*.lmu.edu` 这样的最左侧单标签模式，但 ClientHello SNI 必须是具体名称。

## 安全目标

公网入口针对未认证协议识别、主动探测、已捕获 ClientHello 重放、畸形/碎片化记录
输入和本地资源耗尽进行防护。只有验证期望的 TLS 1.3 ClientFinished 后才提交认证；
更早发生的取消、超时或失败会回滚 pending 重放预留。

认证失败不会收到合成代理响应。程序先把已经从对端读取的每一个字节原样、按顺序
转发到 REALITY 目标，再进入实时 relay。fallback 并发和生命周期与已认证连接分别
设限。

配置、路由资产、用户、REALITY 状态和出站作为一个不可变 generation 发布。
刷新失败保留最后一个完整快照。私钥、UUID、NXR PSK、凭据和完整配置不进入结构化日志。

## NXR 边界

NXR 是内部的 SOCKS 式线路机到落地机访问替代，不是公网协议。每条用户 TCP 流建立
一条 NXR TCP 连接，只发送一次有界请求，其中包含版本、目标、时间戳、随机 nonce
和独立 32 字节 PSK 下的 HMAC。

落地机在 DNS 和目标连接之前验证结构、时间、HMAC 和有界 nonce 重放缓存。失败时
静默关闭；成功后永久切换到支持 half-close 的原始双向字节。NXR 没有 TLS、REALITY、
AEAD、证书、多路复用、连接池、持续 framing 或认证后加密。防火墙应只允许线路机
源 IP 访问该监听。

因为认证后的 NXR 流量是明文，能观察或修改内部链路的人也能观察或修改未被 HTTPS
等端到端协议保护的载荷。存在该威胁时必须使用私网或其他安全传输。

## 资源和内核边界

所有认证前工作、连接、fallback、密码学操作、重放条目、目标拨号、relay 缓冲和
splice pipe 都有明确上限。数据路径没有无界队列或缓存；协议代码禁止 unsafe Rust。

Linux `splice` 只允许在两侧都是明文 TCP socket 后使用，不能跨越 REALITY/TLS
应用边界。如果传输开始前无法获取有界 splice 资源，则使用有界用户态缓冲。

## 非目标

- 应用无法阻止上游流量型 DDoS 填满 VPS 链路；需要服务商清洗和防火墙策略。
- REALITY 不能让已被入侵的端点变可信。
- NXR 的一次认证请求完成后，不提供载荷机密性或完整性。
- 微基准结果不是互联网吞吐或延迟保证。
- GeoIP 和 GeoSite 是策略输入，不是安全权威。

## 内核中继后端

引入内核数据路径会改变攻击者可触及的范围，因此明确说明边界。

**内核后端绝不会看到认证前流量或成帧流量。** 每个方向都有自己精确的已认证裸
边界，后端只在该方向越过其边界之后才接管它：REALITY 认证失败并转为伪装中继
之后、NXR 认证完成之后，或 Vision 的某个方向到达其精确的已认证 Direct 边界
之后。单向 Vision Direct 方向独立中继（方向性 splice），此时对方向仍可在
用户态保持成帧；只有当两个方向各自越过边界且配对安全时，才使用合并套接字的
双向 splice。

**后端不能悄悄吞掉字节。** 只有在共享传输账本两个方向都为零时才可能回退到另一个
后端；否则无法构造 decline 类型。一旦发生传输，错误将结束该连接。

**unsafe 代码被隔离。** 所有 Linux ABI `unsafe` 都位于
`crates/rr-linux`，该 crate 禁止 `unsafe_op_in_unsafe_fn`；协议 crate 保持
`unsafe_code = "deny"`。每个 unsafe 块都有 `SAFETY:` 注释，ABI 布局与描述符生命周期
都有直接测试。服务器不加载任何 eBPF：需要特权的 sockhash 后端已被移除（D7），
因此无需任何内核注入能力。

**日志保持无秘密。** 拒绝原因、阶段和后端名称均来自封闭词表。本工作不会让任何
UUID、密钥、PSK、SNI 值、目标地址、配置内容或负载字节进入日志行。
