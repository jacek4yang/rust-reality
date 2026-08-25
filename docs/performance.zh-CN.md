# 性能

[English](performance.md) | 简体中文

本文记录 v1.0.0 数据平面的实测性能属性以及每项设计决策背后的证据。除非另有
说明，数字均在验证主机上测得：Intel Core i3-8100（4C/4T @ 3.60 GHz）、
16 GiB 内存、Debian 13、**Linux 6.12.94+deb13-amd64**、rustc 1.96.0、loopback
对编译的 Go 源站、未经修改的 Xray 26.7.28 客户端。loopback 让服务端、客户端
和源站共享主机 CPU；这些数字描述的是实现成本，绝不是互联网吞吐。冻结的
v1.0.0 发布对比矩阵见
[benchmarks.zh-CN.md](benchmarks.zh-CN.md)。v1.6.0、v1.5.1 与 v1.5.0 的证据在下面紧随的
章节中，v1.0.0 表格作为该版本的历史发布测量保持不变。

## v1.7 开发证据：已认证 cover TCP 预热

第一阶段的 cover 时延优化仍以真实 TLS cover 为权威，只把 TCP 三次握手移入有界
后台池。受控单边 veth/netem 运行对 cover 链路施加实测 50 ms RTT，而客户端与
服务端 loopback 路径保持不变。三组平衡 ABBA block 将不可变的功能前 main
二进制（`6cff6b7`，SHA-256 `e92ac308…ffd94`）与候选 `aaf6a25`
（SHA-256 `be02eb84…096e46`）比较，保留 24 个原始样本且零失败。候选/基线
setup-rate 中位比值在 c1 为 1.9297（95% block-bootstrap 1.9288–1.9299），
c8 为 1.8402（1.7676–1.8943）。因此 warm hit 消除一个 cover TCP RTT；当前
cover ClientHello 到 flight 的 RTT 仍然存在。

每个被测连接的服务端 task-clock 为基线的 0.9929×（95% 区间
0.9926–1.0027），指令数中位约低 0.44%。由于 speculative replacement connect
与当前 cover transaction 重叠，context switch 仍约高 5.4%，但已从被否决的
10 Hz controller 约 +18.5% 大幅下降。聚焦 `strace` ABBA 只跟踪 `read`、
`recvfrom`、`recvmsg`，没有发现候选 syscall 数膨胀（每个 slot 约
2,775–2,790 次），因此排除了被动 stale-socket 检查是 CPU 根因的假设。

聚合池计数包含刻意不阻塞启动的 warmup 与 c1 到 c8 的 burst 转换：864 次
checkout 中 834 次命中（96.53%）；每个候选 slot 有 4–7 次 cold fallback，
没有 stale discard 或失败样本。这不是 99.9% 稳态声明。池没有排队用户流并能
恢复，但数学意义上的瞬时负载跃迁仍可超过当前 ready 存量。全部原始证据及失败
controller 实验保存在仓库外的
`artifacts/release-train/v1.7.0/cover-warm-pool/`。本阶段尚未启用 prebuilt
cover profile；已认证 cache miss 仍取得真实 cover TLS flight。

## v1.7 开发证据：已认证 prebuilt cover profile

第二阶段把第一阶段保留为精确回退路径，但允许已经通过 REALITY 认证和 replay
reservation 的连接使用由四次一致的受控 probe 生成的不可变 profile。profile
不含 server random、临时私钥、traffic secret、证书、Finished 消息或 record
sequence。未知、过期、不稳定或无法精确表示的 ClientHello class 均使用真实
cover；未认证流量和 replay 从不查询 cache。

受控本地 Go/OpenSSL cover 位于单边 veth/netem 后，client/server 路径不施加
损伤。每个 cell 保留三组平衡 ABBA block、精确载荷校验、原始样本、二进制身份、
主机独占锁和服务端 `perf stat` 计数。下表在并发一时比较 cold live cover 与已
验证 prebuilt profile：

| cover RTT | cold p50 | prebuilt p50 | cold/prebuilt setup rate | prebuilt/cold 每连接 CPU |
|---:|---:|---:|---:|---:|
| 1 ms | 5.765 ms | 1.740 ms | 3.2352（95% bootstrap 3.2342–3.2594） | 0.8629（0.8584–0.8769） |
| 10 ms | 24.015 ms | 1.752 ms | 13.0246（12.9824–13.0270） | 0.8432（0.8373–0.8688） |
| 50 ms | 104.081 ms | 1.754 ms | 56.3245（56.2386–57.1053） | 0.8845（0.8605–0.8930） |
| 100 ms | 204.114 ms | 1.766 ms | 107.3951（107.3693–108.0402） | 0.8130（0.7954–0.8166） |
| 200 ms | 404.171 ms | 1.767 ms | 212.5548（211.3442–213.1219） | 0.8021（0.8010–0.8127） |

prebuilt p50 在 1.74–1.77 ms 内基本不随 RTT 变化，而 cold p50 约随两个 cover
RTT 增长，这是消除 RTT 的核心证据。在 50 ms、c8 时 setup rate 为 cold 的
18.5491×（95% 区间 17.7258–19.2288）。另一次 warm-live 对 prebuilt 运行把
第二个 RTT 单独隔离出来：prebuilt 在 c1 为 28.9731×，c8 为 9.9656×，每连接
CPU 为 warm-live 的 0.8551×。所有样本的载荷完整性均通过。

聚合计数刻意包含非阻塞启动和 profile 预处理，因此实测 profile hit ratio 为
81.67%–97.92%；这里不把它表述成 99.9% 稳态结论。每个候选 slot 都恰好发布
四个保守的 Chrome class profile，没有 profile disagreement 或 collection
failure。顺序 collector 和会重复排队正在收集 class 的 controller 均被否决：
前者串行暴露网络时延，后者造成多余 refresh。保留实现由一个 controller task
并发执行四个有界 probe，并合并正在收集 class 的重复需求。

不可变 Phase-A 基线为提交 `2e09e6e`，二进制 SHA-256
`f541b02684d7a2fa4a9c97423a30b9651af458dcec3fbd30e53c6e76fbf45787`。
实测运行时候选为提交 `8464371`，SHA-256
`c893fbc7a94de996346aa5e22691f14385ea3064312f7cadad2d4cd6b0a23c13`；
50/200 ms 复测使用源码 `5540152`，SHA-256
`84d6c317c16bfb00cc186c2b649aa9b6df776120a9ec34ff1b5911e9075d934c`，
其唯一新增改动是 benchmark harness 中按 RTT 推导的 readiness timeout。资源
优先级自审修复后，50 ms 以源码 `a1c5aec`、二进制 SHA-256
`dcef737d0445f0a8c5190bc67a02d2e62a5cf0fcd1771a308a298b40b4516134`
重新测量；上述 c1/c8 和 CPU 收益保持，24/24 个样本有效。原始数据和被否决实验
保存在仓库外的
`artifacts/release-train/v1.7.0/cover-profiles/`。这些三组 block 的聚焦运行
证明了幅度大且无歧义的机制收益；仓库更长的正式发布评估器仍保留为 release
门禁，本文不把它改称为已通过。

证据覆盖稳定、单模式的本地 cover 和 Xray Chrome 133 ClientHello family。
多模式 cover、无法识别的 encrypted extension、PSK/resumption 和罕见的未收集
ClientHello class 会有意留在 warm-live 路径。这是保守的已验证 class 优化，
不是对所有 TLS 行为都完全相同的声明。

## v1.6.1 发布证据

v1.6.1 头条保留 v1.6.0 与已发布的 v1.5.1 二进制对比测量，因为 v1.6.1
加固列车不改变生产数据路径；精确 v1.6.1 候选另以已发布 v1.6.0 为门禁基线。
原正式评估器 40 项受保护指标全部
通过、零回归。保留的改动是 512 KiB splice pipe（fallback CPU/GiB 比值
0.953，bootstrap95 [0.925, 0.974]）和 framed 上行批量写入（c32 +5.5%，
源站 write 减少 3.5×）。公开对比对象仍为 Xray-core 26.7.28（`5ca6f4b`，
go1.26.0，二进制 SHA-256 `23d228d7…04c5268`）。完整建连、吞吐、DNS、路由、
RSS、限制、身份与证据路径见
[benchmarks.zh-CN.md](benchmarks.zh-CN.md#v161-发布对比证据)。

## v1.5.1 发布证据

v1.5.1 不含数据平面重设计；它是一次有针对性的成本削减与正确性修复发布，
在同一台主机上与已发布的 v1.5.0 发布二进制（`eda773b`）对比测量，每次
运行都在主机独占锁下串行。正式评估器 40 项受保护指标全部通过、零回归
（`artifacts/v1.5.1/gates/evaluator-report.json`）。

- **增量式握手 transcript 哈希。** REALITY 服务端 flight 现在对 TLS 1.3
  握手 transcript 做增量哈希，不再对不断增长的完整 transcript 重复哈希
  四次；transcript 值与线上输出不变。在发布门禁主机上测得：SHA-256
  compress 自时间从 setup CPU 的 22.0% 降至 13.8%，每建连服务端 CPU 下降
  6.7%（setup ABBA 中位比值 0.933，bootstrap95 [0.930, 0.934]；聚合
  task-clock 602 µs 对 646 µs；被发布评估器判定为统计显著的改进）。
- **惰性逐连接 debug 事件与 `log.output: "none"`。** 逐连接 debug 事件
  （`connection_accepted`、`connection_completed`、`connection_closed`）
  仅在 debug 输出能真正到达所配 sink 时才构造；在 `info` 或更高级别、或
  `log.output: "none"` 时，逐连接日志路径完全不做工作。warn 级的拒绝与
  准入事件保持即时构造，作为运维信号。因此 v1.5.1 对 Xray 的对比能让两侧
  服务器都在 warn 级运行，不存在日志不对称。
- **DNS 缓存标识包含查询类别。** 此前同名的静态配置对端与动态逐会话
  目的地共享一个缓存槽，静态查询可能命中动态条目（反之亦然），静态 TTL
  也可能延长动态答案。现在同一名字的静态与动态条目拥有相互独立的生命
  周期，都计入 `dns.cache.maxEntries`；静态否定结果仍不缓存。
- **DNS 缓存分片经证据否决。** 对单个有界缓存互斥锁重新测量了 1–1024
  并发的同名与异名查询：同名与异名墙钟时间基本相同，CPU 随核数扩展而
  非随自旋增长。该锁不是瓶颈，因此有意保留不分片。
- **对 Xray 的对比。** v1.5.1 对 Xray 26.7.28 的建连速率、吞吐、DNS、
  路由规模与 RSS 测量汇总于
  [benchmarks.zh-CN.md](benchmarks.zh-CN.md#v151-发布对比证据)。

## v1.5 cover flight 与发布证据

v1.5 候选在同一台四核验证主机上与不可变 v1.4 发布二进制比较。setup 测试架
使用两侧对称 warn 日志、三组预热后的平衡 ABBA block、精确二进制哈希，并分别
测量 c1/c8/c32。候选/基线 setup-rate 中位变化及 95% block-bootstrap 区间为：

| 并发 | 中位变化 | 95% 区间 |
|---:|---:|---:|
| 1 | -0.38% | -0.465% 至 +0.170% |
| 8 | +0.26% | -3.368% 至 +2.497% |
| 32 | +0.53% | -1.257% 至 +1.557% |

三个区间都跨越“无差异”。归一化计数器变化为 task-clock -0.768%、instructions
-0.190%、context switches +1.042%；最后一项约为每个 setup 连接 +0.058 次。
单独的当前 `strace` 回合测得候选每连接少 4.0013 次 `recvfrom`。trace 只用作
机制证据，其插桩时间不与未插桩 ABBA 对比。

两轮完整平衡矩阵覆盖双向、Direct 下行/上行、fallback、framed 下行/上行；
每轮均保留 219 个样本且无无效样本。载荷哈希全部通过，且每条 workload 的吞吐
与时延 95% block-bootstrap 区间都跨越“无差异”。Direct 上行的中位比值从首轮
0.9511 反转为次轮 1.1390，证实顺序/主机噪声。因此证据既未发现统计显著的受
保护路径回退，也不支持吞吐胜利声明。同一源码发布 portable 与 x86-64-v3
制品，但 CPU 档位身份本身不作为性能证据。

正式 x86-64-v3 对 portable 运行
`20260812T130000Z-matrix-v3-04285e63-r01` 使用同一源码提交和 feature、不可变
的分档二进制、六组平衡 ABBA block 与 warn 日志。共保留 219 个样本、无无效
样本；portable、v3 和 Xray 护栏分别通过一次精确 64 MiB SHA-256 传输。下表
比值均为 **v3 / portable**（吞吐越高越好；最差请求时延越低越好）：

| 路径 | 吞吐中位比（95% bootstrap） | 最差时延中位比（95% bootstrap） |
|---|---:|---:|
| 双向 | 1.0306（0.9240–1.1118） | 0.9935（0.8477–1.0862） |
| Direct 下行 | 1.0145（0.9820–1.0498） | 0.9906（0.9417–1.0372） |
| Direct 上行 | 0.9682（0.8462–1.1066） | 0.9970（0.8829–1.1871） |
| fallback | 0.9981（0.9280–1.0613） | 0.9795（0.8752–1.0169） |
| framed 下行 | 1.0091（0.9826–1.0278） | 1.0150（0.9996–1.0162） |
| framed 上行 | 1.0058（0.9865–1.0229） | 0.9751（0.9556–1.0074） |

所有吞吐与最差请求时延区间都包含 1，因此本轮没有证明该主机上的 v3 存在统计
可靠优势。可选档仍是面向兼容 CPU 的独立标识构建；它不是放宽 portable 回归
门禁的理由，未来任何 v3 结果也绝不能掩盖 portable 回退。

Xray 26.7.28 互操作门禁在 Microsoft、Google、Fastly 三个公开 cover 以及一个
不发送 CCS 的本地 OpenSSL 3.5.6 cover 上通过；每种情况都验证了精确 1 MiB
SHA-256 传输和 ML-DSA-65 key 兼容。这些门禁证明线正确性，不代表吞吐。

## v1.5.0 DNS、路由与 IPv6 证据

验证主机与方法学注意事项同上（Intel i3-8100、Linux 6.12、loopback/同机；
数字描述实现成本，绝不是互联网吞吐）。

- **共享 DNS 解析器。** 使用上游服务器列表时，128 个并发相同查询合并为
  2 次上游请求（原为 315 次），热路径 p50 从 12.9 ms 降到微秒以下；冷路径
  成本 +2.1%。system 模式（`dns.servers: ["system"]`）同样应用 singleflight
  合并和 `DnsLookup` 准入治理，但不缓存动态应答，因为 getaddrinfo 不提供
  TTL。
- **路由候选索引。** 64 条及以上的规则列表会编译自适应索引（实测占用约每条
  53 字节），first-match 语义不变。实测 P95 决策时延在 1,000 条规则时下降
  31–57%，在 10,000 条时下降 31–55%；小规模规则集保持原有线性路径不变。
- **真实 IPv6 验证。** `scripts/validate-ipv6-e2e.sh` 在真实全球 IPv6 与真实
  IPv6 互联网出方向上端到端运行：29 通过、0 失败、1 跳过。跳过项是外部
  入方向用例——验证主机上没有可用的外部 IPv6 来源，因此来自公网 IPv6 的
  入方向只由监听绑定和同机证据支撑，没有外部客户端验证。覆盖范围包括所有
  监听模式、全部地址族组合的 Xray 客户端会话（混合 A/AAAA、DNS 选择的
  地址族、IPv6 字面量、带方括号的伪装目标）、逐字节精确的 64 MiB 上行/
  下行/全双工传输、100 ms/1% netem 损伤、路由丢失与恢复，以及快速地址族
  拒绝回退（0.086 s）。
- **v3 对通用档。** 上面的正式分档 A/B（全部十二个区间都包含 1）就是完整的
  v3 证据：可选档没有实测优势，因为 ring 在每个档位都自己做 AES 运行时
  调度。它存在的意义是让本就要求 x86-64-v3 的运维者得到一个明确标识的
  构建，而不是一个更快的构建。

## v1.3 控制面与建连路径结构

v1.3 审计按用途区分哈希结构，而不是全局替换 `HashMap`：

- 攻击者可影响的可变重放状态和大型 Geo 资产集合保留带随机种子的标准哈希器，
  维持抗碰撞能力；
- 校验/reload 中的 map 只在启动路径使用，不值得引入自定义哈希器；
- 不可变 UUID 与出站 tag 索引只在实测的小基数边界内使用连续排序布局，超过
  边界自动使用标准哈希表。

发布主机 Criterion 选择 64 作为 UUID 边界：64 项时排序命中/未命中为
19.95/16.32 ns，同尺寸 value 的 SipHash map 为 20.26/20.76 ns；到 128 项，
排序命中升至 23.59 ns，切换后的哈希表示为 22.01 ns。出站 tag 在 4 项以内
使用排序存储（4 项命中 11.58 ns，对哈希 20.40 ns），超过后用哈希（16 项时
排序 27.02 ns，对哈希 25.85 ns）。

强化后的 short-ID/UUID 配对本身也是查找结构：一个解码 short ID 直接解析为
owner UUID，随后 VLESS 校验只做一次相等比较，不再二次搜索 short ID。owner
索引在 256 项以内保持排序表示（命中/未命中 17.41/16.87 ns，哈希为
19.60/18.17 ns），超过该实测边界后切换 SipHash；512 项时哈希以
19.59/18.18 ns 胜过排序的 20.23/19.84 ns。常见的两个 short ID 排序命中为
3.50 ns，比被替换的 owner-selecting 常量时间线性扫描 35.04 ns 低 10.0 倍。
对外失败策略没有被弱化：Finished 之前的所有认证失败仍进入同一条有界、逐字节
精确的 fallback。

short-ID owner 索引已经认证了相同身份，因此 REALITY 不再额外构建第二份每
listener UUID registry。owner UUID 直接随已建立会话传递，VLESS UUID 校验就是
一次相等比较。路由同样每次决策只查一次 UUID，同组全部 UUID 共享一个
`Arc<CompiledUserPolicy>`；空 DNS 结果有 allocation-counter 门禁证明堆分配为
零。Handoff 与普通连接也共用一次出站 tag 解析，不再分层各查一次。

VLESS 解析现在有两条明确专用路径：公共 API 直接构造 owned header；生产
Vision 路径从有界请求缓冲区借用 Addons、域名和预取载荷，只在请求被接受时把
域名拥有一次。allocation-counter 测得连续 1024 次 borrowed domain 解析为零
分配。完整 Criterion 重复测得 owned API：IPv4 27.23 ns、domain 53.67 ns、
IPv6 27.46 ns、最大头 425.01 ns；四项相对紧邻基线都在 Criterion 噪声门槛内。
请求缓冲区现在以协议最大头部 533 B 起步，只有 TLS 记录同时带入预取载荷时才
增长，不再预先保留整条记录。

重放缓存用哈希表做精确重复检测，用 deadline 最小堆做过期。REALITY 只清理目标
分片；NXR/Handoff 的常态 reserve 也只处理目标分片，只有真正触及全局容量才
扫描全部 16 个分片。已有 4096 个存活 nonce 时，连续预留 64 个 nonce 从旧版
全量 retain 的 593.18 µs 降到 17.43 µs（**34.0×**）；对无过期存活集合做 purge
约为与基数无关的 282 ns，而不是 10.54 µs。REALITY key 本来就是服务端计算的
SHA-256 digest，因此该表直接使用另一个独立的 64-bit digest word，不再对全部
32 字节跑 SipHash：4096 项时命中/未命中从 25.25/24.99 ns 降到
2.18/1.11 ns（**11.6×/22.4×**）。Handoff 与 NXR 的 nonce 仍由对端影响，继续
使用随机化哈希。

direct 拨号速率门从 `Mutex<f64 token bucket>` 改为原子 GCRA；它使用保守的整数
纳秒间隔，保留相同的一秒 burst 容量，既不排队也不会超过配置速率。连同未变的
Tokio 并发信号量，Criterion 测得单线程 68.34 vs 84.90 ns，四线程争用
145.60 vs 181.75 ns（耗时约低 **19.5%/19.9%**）。

常见 X25519 握手把固定 32 字节服务端 share 留在栈上。server flight 只构建一次
连续 wire 缓冲区，并直接密封现有 transcript 尾部；原来的外层 record vector、
重复 flight-plaintext vector，以及发送时组装分配/拷贝均已删除。

依赖 feature 已收紧到实际使用面，直接 `base64` 版本完成统一，Criterion 默认的
绘图/并行依赖图被移除，lockfile 共减少 10 个 package。全部源码变化后的剥离版
release 二进制为 6,309,616 字节，比审计前 6,332,536 字节少 22,920 字节
（0.36%）。规范值保存在
`benchmarks/final/v1.3-hot-structures/summary.json`。

随后以每个 cell 3 轮、每轮 96 条连接、零失败，对完整 setup 路径（accept 到
首个 Vision 载荷）与 Xray 26.7.28 做了复测。rust-reality 在 c1/c8/c32 的中位数
为 190/793/892 conn/s，Xray 为 177/721/833。按 864 条被测连接归一后的服务端
perf 成本为每连接 0.757 ms、4.00 M 指令，Xray 为 1.239 ms、5.69 M 指令。
这是组合路径的同机验证，不是 WAN 容量承诺；原始和汇总证据保存在
`benchmarks/final/v1.3-setup-refactor/`。

VLESS Encryption 的 REALITY + Vision 精确叠加 A/B 及不在该档位发布它的结论见
[ADR 0003](decisions/0003-do-not-stack-vless-encryption-on-reality.md)：p50 吞吐
为 0.696×，服务端 CPU/GiB 为 5.50×，且 Vision splice 被禁用。

## 鲁棒性门禁

每个有界解析器都有 libFuzzer 目标。v1.3 门禁对 `wire_parsers`（包含生产借用式
VLESS 解码器）、Vision framing、Handoff 头、Handoff blob 和完整 Handoff 开封各跑
20,000 个 ASan 插桩用例。受限验证 shell 在 ptrace 下无法初始化 LeakSanitizer，因而
本地 fuzz smoke 设置 `ASAN_OPTIONS=detect_leaks=0`；定时 CI 在普通 runner 上执行
完整 ASan + LSan 套件。

解析属性门禁对一个 533 字节最大请求的每个前缀，以及每个字节替换为 0/1/255 的情况，
比较 owned 与 borrowed VLESS 解码结果，要求错误或字段完全一致。重放、准入、FD 和
relay 测试覆盖取消、锁 poison 恢复、容量回收与并发争用。定时 CI 还会在
AddressSanitizer/LeakSanitizer 下跑完整测试，并在 ThreadSanitizer 下跑 REALITY 重放
并发竞态测试。单调 deadline 和计数器使用 checked 算术；时间域耗尽会返回明确的
unavailable，而不会饱和后错误放行。

## framed 路径成本分解

对 ring 之前构建的稳态 framed profile（仅已建立连接，不含 setup）中服务端
CPU 的分解：

| 类别 | 下行占比 | 上行占比 |
|---|---:|---:|
| AEAD（AES-128-GCM seal/open，RustCrypto 基线） | ≈51% | ≈39% |
| 内核边界（read/write/copy_user、页面清零、TCP 栈） | ≈47% | ≈57% |
| tokio 调度/定时器、Vision framing、记录解析、libc memcpy | 合计 <2% | 合计 <2% |

内核边界数字——包括 `clear_page` 首次触碰清零的占比（约占下行 CPU 的
3.9%）——特定于上述验证主机与内核（启用 `init_on_alloc` 的 Linux 6.12，因此
已释放页面的清零以内联方式出现）。它们描述的是该内核在该负载下的行为，不能
推广到其他内核、主机或 `init_on_alloc` 配置。

两个结论均由测量固定：

- **消除拷贝不是 framed 的机会。** 拷贝拓扑审计（源码 + profile）表明所有稳态
  路径上每载荷字节都没有可避免的用户态拷贝；framed 路径只剩两次不可约的
  系统调用边界拷贝，splice 路径完全不触碰用户态字节。libc memcpy 约占
  framed CPU 的 0.15%。
- **AEAD 是唯一的大用户态杠杆。** 按实测比例做 Amdahl 上限：AEAD 快 2.5 倍
  时端到端 framed 增益上限约为下行 1.44× / 上行 1.31×（服务端 CPU 受限
  模型）；AEAD 无限快时上限为 2.04×/1.63×。内核边界是限制一切 AEAD 收益的
  下限。

## 记录 AEAD 提供者：默认 ring

默认构建中，TLS 1.3 `TLS_AES_128_GCM_SHA256` 记录保护由 **ring**（源自
BoringSSL 的 C/汇编，静态链接）提供。使用 `--no-default-features` 构建则选择
纯 Rust 的 RustCrypto aes-gcm 提供者，没有其他行为差异；逐字节跨提供者等价性
和 RFC 8448 向量由两种配置下都会运行的测试保证。安全取舍（扩展密钥调度清
零）记录在 [SECURITY.zh-CN.md](../SECURITY.zh-CN.md)。

实测证据（上述验证主机）：

- 生产 16 KiB 记录下的独立 AES-128-GCM：ring seal 5.16 GiB/s，RustCrypto
  2.03 GiB/s——**约 2.5×**，且从 64 B 到 32 KiB 的每个记录尺寸都领先。
- 端到端 framed loopback（219 个有效样本、0 个无效、完整性校验一致）：ring
  在全部 16 个 cell 中 ≥ RustCrypto；512 MiB cell 提升 **1.05–1.16×**。低于
  Amdahl 上限是因为 loopback 吞吐受主机 CPU 共享限制；下面的每 GiB 服务端
  成本才是可迁移的测量。
- 每 GiB framed 下行的服务端成本：task-clock **−33%**（631 vs 940 ms/GiB），
  指令数 −30%，上下文切换 −39%；RSS +3%（噪声）。
- 同一矩阵下对比 Xray 26.7.28，ring 让 framed 512 MiB cell 达到 1.04–1.12×
  （RustCrypto 时为 0.95–1.12× 不等）：Xray 的记录 AEAD 是 Go 的缝合
  AES-NI+PCLMULQDQ 汇编，16 KiB 下约 4.8 GiB/s，因此这次提供者更换弥补的是
  实现质量差距，而不是特性探测缺失。
- 供应链：零新增依赖 crate（ring 已经由 ureq/rustls 存在于发布依赖图），完全
  静态链接，二进制体积还略小。

## raw relay 与 fallback

- 在 raw relay 测试面上（方向 × 载荷 × 并发），splice 在每个实测并发度上同时
  在吞吐和 CPU/GiB 上胜过 buffered 后端；64 KiB 缓冲比 32 KiB 好 2–12%，但仍
  全面低于 splice。因此 splice 全面优先，buffered 保留为拒绝时的回退。
- 对 Xray 26.7.28/Go 的机制审计解释了对比形态：Xray 的 REALITY **fallback**
  路径使用 readv/writev 64 KiB 用户态拷贝——完全不用 splice——而其 Vision
  下行通过 Go 运行时的 `sync.Pool`（1 MiB 管道池）做 splice（池热后每会话
  约 0 次管道系统调用）。rust-reality 的 `PipePool` 为其 512 KiB 管道消除了
  等价的每会话 pipe2/fcntl/close 抖动。
- 最终 v1.0.0 干净同源 fallback A/B（两侧 warn 级日志；
  `benchmarks/final/v1-fallback-ab/`）：c1–c32 时 splice fallback 为 Xray 的
  1.00–1.03×，task-clock 持平或更低。更早的 fallback 劣势读数被追溯
  到矩阵 harness 的 debug 级逐连接日志，而不是 relay 路径（见
  [benchmarks.zh-CN.md](benchmarks.zh-CN.md) 的方法一节）。D8 时期的历史
  机制测量在同主机上曾录得 1.04–1.05×；作为头条数值已被最终发布对比取代。

## 连接 setup

最终 v1.0.0 数字（accept → REALITY 握手 → VLESS 解析 → 路由 → 出站连接 →
第一次 Vision 转换；不含稳态；上述验证主机，本地 TLS 源站，裸 socket 客户
端；证据：`benchmarks/final/v1-setup-rate/`）：

| cell | rust-reality | Xray | 比值 |
|---|---:|---:|---:|
| c1 conn/s | 270 | 123 | 2.20× |
| c8 conn/s | 806 | 688 | 1.17× |
| c32 conn/s | 895 | 812 | 1.10× |
| c32 p99 setup 延迟 | 59.3 ms | 59.3 ms | 持平 |

测量窗口内（864 个连接）每连接服务端成本：CPU 0.65 vs 1.53 ms（**−58%**），
指令数 −29%，上下文切换 −77%。c32 时速率差距收窄是因为 4 CPU 主机同时限制了两端；
每连接成本列才是更干净的信号。CPU 优势能否在更大主机上转化为速率优势尚未
验证。

## 决策登记（D1–D11）

塑造 v1.0.0 的各项性能决策的一行结论：

- **D1——保留。** reload/资产刷新曾经放大进程级上限；共享 authority 提升为进程
  生命周期所有权。
- **D2——保留。** 让中止的传输可与正常完成区分：abort 路径设置
  `SO_LINGER{on,0}`，使对端观察到复位（RST/`ECONNRESET`）而非干净的短
  EOF；正常关闭保持 FIN 语义（`DirectionAbortGuard`）。
- **D3——保留。** DNS 工作有界化：查找池、许可持有覆盖阻塞操作、快速失败、无
  队列。
- **D4——保留。** 内核活性兜底：所有数据 socket 设置 `SO_KEEPALIVE` 30/10/3；
  `TCP_USER_TIMEOUT` 经评估后带理由拒绝。
- **D5——保留。** 内存采样来源显式化；管道容量降级在 relay 结果与连接日志中
  可见。
- **D6——作为原因被证伪，带取舍保留。** PipePool 消除了每会话管道系统调用/FD
  抖动（机制经 strace A/B 确认），但没有改变端到端 fallback 吞吐——splice 调
  用成本不是差距的来源。作为零成本机制保留，不作任何吞吐声明。
- **D7——以删除解决。** sockhash 后端在生产矩阵中从未 arm，特权 A/B 与 splice
  持平，且部署模型永远不具备其所需权限；已移除（约 5400 行）。
- **D8——证伪。** 表面上的 fallback c32 差距来自 harness 的 debug 日志而非
  splice 调用成本；当时的干净 A/B 录得 fallback splice 为 Xray 的 1.04–1.05× 且
  CPU 明显更低；最终 v1.0.0 对比（1.00–1.03×）取代其成为头条数值。
- **D9——证实，作为默认发布。** framed 路径受 AEAD 限制，ring 在生产记录尺寸
  下约为 RustCrypto 的 2.5×；作为默认记录 AEAD 提供者发布，RustCrypto 回退
  保留并持续测试。
- **D10——已分类，无需行动。** framed 稳态的 `clear_page` 份额是内核 TCP 发送
  路径的页清零（受验内核启用 `init_on_alloc`），按传输字节数伸缩，而非
  按连接的用户态缓冲成本（churn 实测每连接 28 次 minor fault，约占 churn
  CPU 的 2%）。未构建任何缓冲池或惰性增长。
- **D11——证实，已发布。** framed 下行记录批处理（一次 `readv` 读入 4 个记录
  槽 + 每 ≤64 KiB 一次写）使发送系统调用减少 4×、服务端 CPU/GiB 降低
  18.5%，并在 512 MiB c32 的 gated A/B 中使 framed 下载提升 7.6%。

## 最终发布矩阵（v1.0.0）

数字冻结自精确的发布候选生产二进制（git `d2fbb0c`，二进制 SHA-256
`a77fe34a…`，ring 默认），对比对象 Xray-core 26.7.28（`5ca6f4b`，go1.26.0，
二进制 SHA-256 `23d228d7…`）。543 个有效样本，0 个无效，每个实现的 SHA-256
完整性均匹配。矩阵单元中 rust-reality 使用 debug 日志（防绕过护栏要求），
Xray 使用 warning——对 rust-reality 不利；fallback 与建连速率行使用 warn
级别对称测试架。代表性行见 README 性能小节；原始样本在发布证据档案中。
说明：`direct-upload:32MiB:c1` 对两个实现都呈双峰（78–237 MiB/s），作为
不可判别单元剔除；矩阵 fallback 单元因日志级别不对称而低估
rust-reality——以干净 fallback A/B（1.00–1.03×）为准。

## 部署特性（v1.0.0）

- **路由正确性：通过**——26/26 个 (uuid, destination) 用例，覆盖 2 个用户组、
  direct/blackhole/SOCKS5 出站及 domain/GeoSite/IP/GeoIP/port/迟到/默认规则；
  每个 UUID 只到达其指定出站，均经字节校验。
- **路由决策开销：不可测**——simple（1 用户）、medium（100 UUID/16 规则）、
  complex（1000 UUID/72 规则）配置均为 896 conn/s、每连接 0.60 ms CPU；
  含 DNS 的变体经本地解析器增加 0.12 ms/连接。
- **NXR 两跳开销（对直连）：** 吞吐约 3–5%，每连接 CPU +0.15 ms。
- **NXR 对 SOCKS5（相同端点）：** 建连速率 +18%（880 对 748 conn/s），
  32/512 MiB c32 吞吐 +11–13%；在 100 ms netem RTT 下为 36 对 19 conn/s
  （p50 218 ms 对 413 ms）——每连接少一个往返。
- **rust+NXR 对 Xray+SOCKS5**（系统级，非协议隔离）：880 对 696 conn/s，
  每连接 CPU 0.77 对 1.02 ms。
- **完整性：** 所有单元经字节校验；无传输错误。

## Handoff 线路机卸载（实测，单机）

Handoff 拓扑把会话的逐字节 TLS/Vision 工作从线路机移到落地机：一次性的
转移完成后，线路机就是原始密文 splice relay。下面的实测 A/B 对比该拓扑与
NXR 两跳链路，工作负载相同（经未修改 Xray 客户端的 512 MiB 传输），主机
相同。

**证据标注：** 验证主机（Intel Core i3-8100，4C/4T）上的单机 loopback，
无 cgroup 隔离；loopback 由客户端、两个服务器节点和 origin 共享主机 CPU。
数字是 1.5 GiB 统计窗口内每 GiB 的 task-clock CPU 毫秒数——实现成本，
绝不是互联网吞吐，也不能跨主机搬用。

| 指标（ms CPU/GiB） | NXR 链路 | Handoff 链路 | Δ |
|---|---:|---:|---:|
| LINE 下载 | 549 | **98.1** | **−82.1%**（5.6×） |
| LINE 上传 | 1 043 | **415.0** | **−60.2%**（2.5×） |
| LANDING 下载 | 103 | 517.3 | 5.0×（按设计吸收了 TLS 工作） |
| **系统下载总计** | 652 | **615.4** | **−5.6%** |

profile 证实了机制：线路机稳态在任何百分比阈值下都没有 AEAD、记录层或
Vision 符号（用户态只剩 splice 泵和调度器粘合；转移路径——每会话一次
X25519 交换加一次有界密封——累计约 0.25%），而落地机的 profile 正是被
移植过来的 TLS 工作负载。线路机上上传比下载贵，是因为客户端记录以
≤16 KiB 分块到达，残余开销是系统调用速率决定的，而非密码学。

用运维语言解读：Handoff 是边缘算力迁移，不是免费午餐——线路机卸下逐字节
TLS，落地机吸收它，系统总 CPU 大致持平（此处略优）。公网线路机 CPU 受限
且有更强的私网落地机时选 **Handoff**；要求会话密钥绝不离开公网节点时选
**NXR**——NXR 不转移任何密钥材料，代价是载荷在一次性认证之后以明文穿越
私网链路。

## 热路径取证审计（v1.0.0）

在归因构建（同一源码树、DWARF、帧指针）上对六类工作负载采样并抽查反汇编：
所有重要用户态区域都是第三方加密原语（稳态为 ring 拼接 AES-GCM 汇编；握手
为 sha2/X25519/ML-KEM），或根本不存在——raw relay 用户态峰值仅 1.5%
（`splice_pump`），复杂 churn 配置下没有任何路由符号达到 1%。没有任何发现
达到保留门槛（≥2% 用户态且 ≥5% 现实端到端余量）；未做任何生产代码修改。
已知内核成本（copy_user、页清零）按 D10 分类。

## 已否决的方向（基于证据）

- io_uring：生命周期审计后移除——设计上并非零拷贝、无取消、无会话层；补完它
  等于重写，收益不如 splice。见
  [decisions/0002-io-uring-removed.md](decisions/0002-io-uring-removed.md)。
- 调度器/运行时重设计：Tokio 多线程运行时约占 framed CPU 的 1%；无争用证据。
- Vision framing / 记录解析工作：合计 <1%。
- 短流自适应分类器：没有新证据不做；一直没有找到证据。
