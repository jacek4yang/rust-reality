# 威胁模型

[English](../en/threat-model.md) | 简体中文

## 受保护的数据路径

```text
兼容 Xray 的客户端
  -> VLESS + REALITY + xtls-rprx-vision 公网监听
  -> 线路机 UUID 策略
  -> direct | block | SOCKS5 | NXR | Handoff
  -> 可选、受防火墙限制的 NXR 或 Handoff 落地机
  -> 目标地址
```

公网监听始终要求 TCP、REALITY、VLESS decryption `none` 和 Vision flow。尝试纯
VLESS 的配置会在绑定监听端口前被拒绝。`serverNames` 可使用具体 DNS 名或
`*.lmu.edu` 这样的最左侧单标签模式，但 ClientHello SNI 必须是具体名称。
每个配置 UUID 拥有一组非空、全局唯一的 short ID。REALITY 阶段把提交的 short ID
直接解析为其唯一 owner；解出加密的 VLESS 头后，其中 UUID 必须与 owner 完全相等。
这种两阶段绑定阻止跨账户拼接 UUID 与 short ID。

## 安全目标

公网入口针对未认证协议识别、主动探测、已捕获 ClientHello 重放、畸形/碎片化记录
输入和本地资源耗尽进行防护。只有验证期望的 TLS 1.3 ClientFinished 后才提交认证；
更早发生的取消、超时或失败会回滚 pending 重放预留。

认证失败不会收到合成代理响应。程序先把已经从对端读取的每一个字节原样、按顺序
转发到 REALITY 目标，再进入实时 relay。fallback 并发和生命周期与已认证连接分别
设限。

伪装目标 warm pool 不改变该边界。idle 池化 socket 不授予任何权限，也不包含 TLS
状态；只有已经通过认证并完成重放预留的握手才能 checkout。所有失败类别仍像以前
一样新建自己的真实伪装目标连接。ready/connecting socket 均严格有界、计入 FD
预算并按 generation 隔离；资源压力下先丢弃推测性预热资源，避免与活跃流量竞争。

prebuilt profile 保持同一未认证边界。认证与重放预留成功前无法查询 profile。权威
来源是有界 collector，而不是任意用户观测；只有四次受控响应完全一致才发布。
profile 会擦除目标 random、session ID、临时 key exchange 与流量秘密，带抖动过期，
也绝不跨配置 generation。未知 GREASE/ECH 形状、不支持的 PSK、意外的
EncryptedExtensions、profile 分歧、过期状态或本地 flight 尺寸失败都会选择真实
伪装目标，绝不猜测。获授权客户端最多占用 16 个有界提名槽之一，不能发布目标语义，
也不能影响已有的 validated profile。

本项目不声称所有 TLS 流量都具有完全相同的可观测行为。更窄的目标是：对已验证
class 不引入清晰、确定的
语义差异——所选版本、cipher、group、ServerHello 扩展顺序、ALPN、compatibility
CCS 与外层 record plan 均来自受控目标证据，而 random 与秘密字段必须变化。主动未
认证探针和捕获重放始终只得到真实伪装目标行为。

固定对端传输预热保持 Handoff、NXR 和 SOCKS5 原有协议边界。checkout 的 socket
只使用一次，绝不返回 READY，也不携带已认证用户、密钥协商、重放预留、目标或
SOCKS 授权。Handoff/NXR 的防火墙源地址限制仍是额外部署边界，绝不替代逐流 fresh
认证。

**warm TCP 连接只是预付的传输状态。首个协议字节到达前，它是未认证、有界的 idle
状态；首字节到达后，它进入原有的短认证截止时间。仅仅提前建立 TCP 连接，不会
授予任何 Handoff 或 NXR 权限、重放状态、目标副作用或会话所有权。** LANDING 用
自身有限上限准入该 idle 状态，并在压力或 generation 替换时回收。首字节会立即
启动短截止时间，因此 slowloris 无法继承较长的 warm-idle 寿命。

配置、路由资产、用户、REALITY 状态和出站作为一个不可变 generation 发布。
刷新失败保留最后一个完整快照。私钥、UUID、NXR PSK、Handoff PSK 和静态密钥、
凭据和完整配置不进入结构化日志。

强制 REALITY 档位不把 VLESS Encryption 作为额外安全目标。外层 TLS 1.3 记录层
已经提供机密性、完整性与前向保密的流量密钥；再叠一层数据 AEAD 会禁用本项目
支持的 Vision raw/splice 路径。安全/性能结论及重新评估门槛记录在
[ADR 0003](../adr/0003-do-not-stack-vless-encryption-on-reality.md)。

## NXR 边界

NXR 是内部的 SOCKS 式线路机到落地机访问替代，不是公网协议。每条用户 TCP 流独占
一条 NXR TCP 连接，只发送一次有界请求，其中包含版本、目标、时间戳、随机 nonce
和独立 32 字节 PSK 下的 HMAC。

落地机在 DNS 和目标连接之前验证结构、时间、HMAC 和有界 nonce 重放缓存。失败时
静默关闭；成功后永久切换到支持 half-close 的原始双向字节。NXR 没有 TLS、REALITY、
AEAD、证书、多路复用、持续 framing 或认证后加密。防火墙应只允许线路机
源 IP 访问该监听。

因为认证后的 NXR 流量是明文，能观察或修改内部链路的人也能观察或修改未被 HTTPS
等端到端协议保护的载荷。存在该威胁时必须使用私网或其他安全传输。

## Handoff 边界

Handoff 通过一条单程信道把已认证会话的完整 TLS 属主从线路机转移到落地机。
转移消息承载会话的流量密钥，因此信道是密封的：用 fresh ephemeral X25519 对
落地机静态密钥交换，与成对 PSK 在一条 HKDF-SHA256 链中混合，以整个头部为
关联数据做一次 ChaCha20-Poly1305 密封。AEAD 开封成功即双向密钥确认：落地机
证明其静态密钥，线路机证明 PSK。重放防护是时间戳窗口加有界 nonce 缓存，先于
任何密钥协商工作检查。

前向保密以落地机的静态密钥为界：该密钥泄露会追溯暴露它应答过的所有已录制
转移，以及其中转移的会话。轮换静态密钥以收敛该窗口。零停机轮换期间落地机可能
仍接受 `previousPreSharedKeys`/`previousPrivateKeys` 列表中的退役密钥，前向保密界
只有在这些退役静态密钥被移除后才成立。转移之后，链路只承载
会话的 TLS 密文，端点的记录层 AEAD 仍然保护它；链路观察者只能看到记录大小
和时序，看不到载荷。

任何转移失败——结构、时间戳、重放、认证、状态——都以零响应字节静默关闭，
线路机会重置客户端 socket，而不是在本地继续服务该会话。链路上没有两种秘密
材料的攻击者无法解密、伪造或重定向转移，也无法向已转移会话注入内容而不破坏
其记录层 AEAD；但他们仍能切断连接（客户端观察到 reset），并能用结构合法的
伪造消耗有界重放条目——这与 NXR 缓存已接受的暴露相同：限速靠防火墙，而不是
缓存。该监听器必须只允许线路机地址访问。

有两条信任声明需要明确接受：落地机对被转移目标不做任何路由策略——对线路机
的信任是绝对的，线路机被入侵会把落地机变成内网拨号器；落地机为每个已转移
会话持有在线会话密钥，因此其内存属于会话保密边界的一部分。

Handoff 和 NXR 的重试边界是完整认证写入。边界之前最多允许一次替代 transport，
并重新生成 timestamp、nonce、Handoff 临时密钥/AEAD transfer 或 NXR HMAC request。
完整写入之后 LANDING 可能已经预留重放状态、解析或连接目标，或者恢复会话，因此
绝不因迟到的关闭或响应失败而重复逻辑流。

## 资源和内核边界

所有认证前工作、连接、fallback、密码学操作、重放条目、目标拨号、relay 缓冲和
splice pipe 都有明确上限。数据路径没有无界队列或缓存；协议代码禁止 unsafe Rust。

准入和重放时钟使用有界整数域。无法表示的 deadline、已耗尽的重放 generation 计数器、
或细于每 token 一纳秒的速率都会以 unavailable 拒绝；算术绝不能把饱和变成成功准入。
每个临时重放预留都拥有 RAII permit，在解析失败、超时、取消、重复、分配失败或计数器
耗尽时回滚。

鲁棒性由有界协议 fuzz、截断/字段变异等价属性测试，以及定时 ASan/LSan 和 TSan 门禁
持续检查。这些测试不能宣称数学意义上的绝对无缺陷，但会把未处理输入、资源、算术和
竞态状态明确纳入发布条件。

`fuzz/Cargo.toml` 是攻击面的权威清单。当前目标覆盖原始 VLESS/wire parser、
结构化 REALITY 认证与重放状态、Vision 解码与状态转换、Handoff header/blob/open 与
结构化 round trip、NXR round trip、cover flight 解析、TLS 1.3 record round trip、
transcript 哈希、严格 normalized ClientHello 分类、受控 profile compatibility、
profile EncryptedExtensions 解析、ServerHello 重建、严格配置解码、诊断渲染，
以及运行时无关的会话所有权与重试语义。
CI 会拒绝未声明的目标源码并运行每个已声明目标；全 crate 行覆盖率不能
替代这些可达边界的覆盖。

测试模型是分层的，任何一层都不能替代另一层：字节级 wire fuzzing 与 parser
fuzzing 仍然是 wire 行为的权威依据，语义事件序列 fuzzing 覆盖只有事件序列才能
违反的所有权规则，集成测试覆盖组装后的运行时。

语义层就是 `session_semantics` 目标。它用任意事件序列驱动 `rr-session` 会话引擎，
不涉及 socket、时钟或运行时，并断言：每个方向最多只能获得一次传输授权；两个
Vision 方向在任意交错顺序下都不会把双向 pair 拆开；每个方向的状态增长受一个独立
定义的推进阶梯约束；终态方向在序列剩余部分始终保持终态；已认证的单消息传输在越过
不可逆的 `CommittedWrite` 边界之后永不再授权新的尝试。它所依赖的单步关系——合法
状态转换表、严格推进顺序、pair/directional 规则，以及授权只能在何处规划——由
`crates/rr-session/src/vision.rs` 中的单元测试针对一份手写参考模型**穷举**验证，
因此两层都不是对被检查代码的复述。重放双重提交与认证前权限仍由结构化 REALITY 认证
和 Handoff/NXR round trip 目标覆盖，因为这部分状态尚未抽取进会话引擎。

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

**unsafe 代码被隔离。** `crates/rr-linux` 是允许存放 Linux ABI `unsafe` 的位置，
该 crate 禁止 `unsafe_op_in_unsafe_fn`；协议 crate 保持 `unsafe_code = "deny"`。
该 crate 通过经过评审的 `rustix` API 访问内核，而不是手写 ABI；自中止权限改为
绑定所有权之后，其中已不再有任何生产环境 `unsafe` 块。描述符生命周期、套接字
选项、中止语义与 `/proc` 解析器都有直接测试。服务器不加载任何 eBPF：需要特权的
sockhash 后端已被移除（D7），因此无需任何内核注入能力。

**日志保持无秘密。** 拒绝原因、阶段和后端名称均来自封闭词表。本工作不会让任何
UUID、密钥、PSK、SNI 值、目标地址、配置内容或负载字节进入日志行。
