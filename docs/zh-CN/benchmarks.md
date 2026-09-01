# 基准策略与规范样本

[English](../en/benchmarks.md) | 简体中文

本文说明 rust-reality 的测量方式、v1.0.0 的规范样本，以及解释任何数字时的
边界。最终冻结的 v1.0.0 发布对比矩阵在发布时用同一批 harness 生成；数字背后
的设计级证据见 [performance.zh-CN.md](performance.md)。

## 测量策略

- 保留全部样本；不挑选最快的一次，写出原始文件前不做任何平均。
- 每一轮按记录的种子打乱实现顺序，使顺序无法偏袒任何一方。
- 两侧使用相同的源站、并发和载荷；对比结论在可行时必须条件对称。当观测手段
  不得不引入不对称时（矩阵 harness 需要 rust-reality 的 debug 级逐连接事件
  作为防绕过护栏，而 Xray 用 warning 级），不对称随数字一并披露，且敏感的
  头条单元（fallback、建连速率）会在 warn 级对称测试架下复测。
- loopback 数字描述实现成本，不是互联网吞吐。任何结果都不能声称抵御上游
  流量型 DDoS，也不能把一台主机的结果外推到其他 CPU、内核和网络。
- 后端拒绝和失败 cell 按拒绝/失败记录，绝不编造数字。

### 主动探测回归契约

`tools/fixtures/active-probe-cases.json` 是确定性用例的唯一清单。
`cargo dev check` 会校验该清单并确认每个指定测试仍然存在，拒绝缺失或被改名的用例。清单覆盖认证成功
与拒绝、重放、ClientHello 分片、ClientFinished 畸形或缺失、cover 超时/拒绝/畸形
flight、精确 fallback 前缀和资源压力。

`cargo dev bench run --suite tls-shape` 会把同一个由原版 Xray 生成并捕获的 ClientHello，
分别交给 rust-reality、适用时的固定 Xray 服务端以及本地 cover 直接入口。它保留 TLS
record 序列、可确定观测的进程 write 分段、可用时的抓包、精确前缀，以及重复测量的
首字节/flight 完成时间，并通过确定性的延迟 record cover 矩阵（already-buffered 与
absent-would-block 两种第五 record 分类，0/20/50/100/200 ms 延迟）驱动真实候选，
同时执行生产 reader 门禁。确定性的 wire 或关闭语义差异会失败；时间仅按分布报告，不以
脆弱的微秒相等作为门禁。分包行为仍依赖网络环境。这些测量不能证明各实现的网络观测
完全相同。

## Harness

机器可读的受保护 cell 契约位于 `benchmarks/contracts/protected-metrics-v1.json`。
`benchmarks/baselines/v1.6.1-cache-foundation.json` 保存 v1.6.1 的不可变测量基础：
干净 main 的二进制/编译器/主机身份、重要结构尺寸和已有的 record 路径零分配断言。
`cargo dev perf environment --tool stat`/`--tool c2c` 会验证被测二进制哈希并原子写出
JSON；如果内核或 VPS 策略拒绝某个事件，则记录带原始诊断的 `UNAVAILABLE`，不会编造
测量值。

| Harness | 用途 |
|---|---|
| `rust-reality benchmark`（内置） | 有界、机器可读的进程内协议测量（VLESS 解码、Vision framing、NXR 认证）。 |
| `cargo bench`（criterion） | VLESS 解码、Vision framing、relay 后端、双栈规划/setup/fallback、自适应 short-ID/身份/tag 查找、REALITY digest 哈希、重放过期/reserve 和 direct admission 争用的回归分析，带基线和图表。 |
| `cargo dev bench run --suite matrix` | 完整 A/B/C loopback 矩阵（baseline/final/Xray），覆盖 方向 × 载荷 × 并发；每个 cell 都有 origin 饱和、上传计量与隧道绕过守卫，并含端到端完整性校验。`--cells`/`--skip` 可裁剪计划。 |
| `cargo dev bench run --suite fallback` | 在固定基线 ELF 与候选之间做干净的 fallback A/B：两侧 warn 级日志、直连 listener，两侧固定相同的 relay splice/pipe-pool/buffer 策略，并在计时前逐 slot 校验载荷完整性。 |
| `cargo dev bench run --suite setup-rate` | 在固定基线 ELF 与候选之间做平衡 setup 速率 A/B（accept → 第一次 Vision 转换）。设置 `--cover-netem-rtt-ms` 时只把 TLS 伪装目标移到 veth/netns 后并施加有记录的单向延迟，同时保留 pool hit/miss 汇总。`--measure-mode perf` 在 warmup 后归因 task-clock/指令/context switch；`strace` 记录有界的 read/receive syscall 集，并先优雅停止 tracee，避免静默产生空汇总。`--profile` 在 benchmark 已持有的锁和精确 server 身份下采集第一个正式候选 slot。 |
| `cargo dev bench run --suite vision-direct`、`cargo dev bench run --suite xray` | 聚焦的 Vision-Direct 与 Xray 对比。Vision-Direct 支持 `--profile`，对 warmup 之后的完整测量 workload 采样精确的 Rust server。 |
| `cargo dev bench run --suite deployment` | 部署特征化：路由正确性证明、路由决策成本（含 DNS 策略）、NXR 拓扑（direct/NXR/SOCKS5/Xray）、长连接 relay 证据，以及正式单跳 netem matrix。RTT 段保留精确生产构建在 1/10/50/100/200 ms、c1/8/32/128/512 下 Handoff/NXR/SOCKS5 的 ABBA cold/warm 样本与无秘密 pool retirement summary。`--deployment-plan` 选择 `full`、`mechanism`、`robustness` 或非正式的 `smoke`。 |
| `cargo dev bench run --suite soak` | 可选长期回环证据：standalone 混合流量加 Handoff、NXR、仅 TCP SOCKS5、中点 reload、精确进程身份下的逐进程 RSS、汇总 PSS，以及带哈希绑定的 start/interval/reload/end 完整性尝试。`--soak-implementation xray` 选择保留的对照端。默认原生运行是计划任务/非阻塞证据；精确 12 小时且分布式间隔为 5–30 分钟的运行会记录是否满足严格长期资格。 |
| `cargo dev bench profiles` | 在精确 cgroup-v2 CPU、内存与零 swap 边界下执行 fail-closed 机器档位验证。它负责候选/Xray 身份、scope 进程清理、churn 与 512 MiB 下载、默认/调优空闲会话阶梯、RSS/FD/cgroup/OOM 采样、带逐阶梯基线的绝对日志计数、逐档汇总与聚合发布。 |
| `cargo dev perf hotspot` | 对内建 benchmark 或既有 server PID 进行身份绑定的 `perf record` 采集。Rust 负责参数边界、精确 PID/start-time/可执行文件身份、在目标或请求时间结束时正常停止的截止机制、只读二进制归档、report/build-ID 校验、校验和、发布与清理；`timeout`、`perf`、`readelf`、`sudo` 仅作为带类型 argv 的外部机制。 |
| `cargo dev perf hotspot-bundle` | 从已完成的原生 hotspot 运行中导出一个 `--dso-offset`，依次完成可执行 ELF `PT_LOAD` 归一化、DWARF、IDALib、LLVM 与精确 perf DSO 偏移样本分析。Rust 负责采集身份、文件偏移到静态地址的转换、私有二进制/数据库路径、IDALib 输出验证、函数选择、指令聚合、样本行数与 period 守恒、默认零容忍且硬上限低于 1% 的映射门、校验和、失败状态与发布。该流程支持 stripped PIE，既不会把 perf 的文件偏移误当成 ELF 虚拟地址，也不会把 IDA 合成的函数名当成 perf 符号。IDALib 仅有的 Python 自动化 API 被限制在运行时生成的私有直接 API 桥中；操作者提供 `--idalib-python` 与安装环境，仓库不保留 Python 策略文件或机器专用安装路径。 |
| `cargo dev deploy {canary-plan,canary-run,canary}` | 对约十分钟精确候选双 VPS 主动 canary 进行非修改计划、显式修改门禁执行与 fail-closed 评估：部署、真实 WAN Handoff、stock Xray、完整性、churn、reload、LANDING 重启/恢复、有界 pool 与资源恢复包络。 |
| `cargo dev bench run --suite real-path` | 真实互联网路径上与 Xray 的 A/B：崩溃与协议错误门禁；吞吐受路径最慢链路限制，不能用于区分带宽。 |
| `cargo dev bench run --suite vless-encryption` | Xray v26.7.28 下 `encryption:none` 与同一 REALITY + Vision 内叠加 VLESS Encryption 的 A/B；测吞吐、服务端 CPU/GiB 和预热后的 setup，执行顺序为带种子且已记录的随机序。 |
| `cargo dev bench run --suite xray-interop` | 兼容性门禁（见下），不是基准。 |

要执行整段 workload 的 CPU 归因，可在 `setup-rate` 或
`vision-direct` 中加入 `--profile`。benchmark 仍是排他主机锁、拓扑、
已注册精确 Rust ELF 和实时 server PID 的唯一所有者。它只在 warmup
后启动 `perf`，在测量 workload 后停止并回收子进程，验证结果，并将
普通的、可被 bundle 接受的 hotspot 契约写入 `OUT_DIR/hotspot/`。父
benchmark 只在清理与验证成功后发布。`--profile-record-seconds`
是硬上限；`--profile-event`、`--profile-frequency` 和
`--profile-call-graph` 选择采样配置。所有权决策记录在
[ADR 0014](../adr/0014-benchmark-owned-whole-session-profiling.md)。

## v1.7 LINE→LANDING 证据契约

v1.7 transport 结论只接受 `REQUIRE_NETEM=1` 的正式 deployment run。
`DEPLOYMENT_PLAN=mechanism` 是聚焦的前台 gate：只运行零丢包、并发 1 的
50/100/200 ms cell，每条 leg 保留 6 个平衡样本。`DEPLOYMENT_PLAN=robustness`
把完整 RTT/loss/concurrency 笛卡尔积作为异步证据任务；默认
`DEPLOYMENT_PLAN=full` 还保留 routing、topology、throughput 与 long-flow 证据。
聚焦 mechanism program 是发布性能结论的 gate。robustness run 只有在完整、
fail-closed 的 inventory 与 completion marker 都存在时才是 PASS。若外部 wall-clock
预算将其停止，preflight/incomplete contract 与 artifact 说明必须标明缺失 cell；
该部分运行只能作为 diagnostic 证据。这样数小时的 robustness campaign 不再阻塞
无关的 review 与工程工作。所有 plan 的 warm/cold 进程使用同一
release binary、peer、origin、client、整形 veth pair 与配置身份；
唯一差异是出站 `warmTcp` 开关。每个 protocol/mode cell 保留平衡 ABBA block、
p50/p90/p95/p99、setup rate、精确环境/二进制哈希和原始失败。profile inventory
fail-closed：每个 RTT、loss、concurrency 都必须有 Handoff/NXR/SOCKS5 cold/warm leg。

正式运行会给出 fail-closed 的性能判定。每种 transport 使用零丢包、并发 1 的
50/100/200 ms profile，保留完整 ABBA block，并以实测整形链路 RTT 评估
`median(cold p50) - median(warm p50)`。中位效果必须处于 0.65--1.35 RTT；
100 与 200 ms 下确定性 block-bootstrap 下界还必须大于 0.5 RTT。该判定只验证
warm hit 从用户路径移除一次 TCP 握手。丢包与高并发 cell 属于 robustness 证据，
不会被重新标记为干净的 RTT 机制估计，
也不会延迟聚焦 mechanism verdict。pool log
提供 startup-aware checkout、hit/miss、cold fallback、stale、ready/connecting/target、
EWMA、growth 与 shrink 计数。debug/instrumented run 可解释 phase，不能提供头条数字。
idle-age、burst、prebuilt-cover + warm-LANDING 组合、protected path 与 soak 是独立保留
的 release artifact；不能从本聚焦 matrix 推断缺失证据。

发布证据分三层：A 层是上述强制聚焦机制门禁，预算约 10–20 分钟；B 层是由
`cargo dev deploy canary` 评估的强制约十分钟双 VPS 主动 canary；C 层是可选的
数小时或整夜 soak。C 层仍可发现长期保持问题，但不再阻塞发布或下一开发 worktree。
B 层内存门禁比较基线、burst 峰值和恢复后的 FD/thread/RSS 包络，不会从十分钟
外推精确 MiB/hour，也不声称等价于长期证据。

## v1.0.0 规范样本

仓库保留最终 v1.0.0 证据集：`benchmarks/evidence/releases/v1-matrix/` 与 `v1-matrix-512/`
（36 单元发布矩阵）、`v1-fallback-ab/`、`v1-setup-rate/` 为发布规范样本；
`d9-framed-ab/`（ring 提供者 A/B）与 `d11-ab/`（记录批处理 A/B）是两项已发布
设计决策的机制证据。更大的历史矩阵已在仓库之外的发布证据档案中保存。


### framed AEAD 提供者 A/B —— `benchmarks/evidence/releases/d9-framed-ab/`

ring（默认）vs RustCrypto（`baseline`）vs Xray 26.7.28，framed cell，219 个
有效样本、0 个无效，三个实现的 2 GiB sha256 完整性校验全部一致。环境：Intel
Core i3-8100（4C/4T）、Linux 6.12.94+deb13-amd64、rustc 1.96.0、Xray 26.7.28
（`5ca6f4b`，Go 1.26.0）、loopback 配编译的 Go 源站、REALITY 目标
`dl.google.com:443`、种子 `0x5252`。

512 MiB cell，p50 MiB/s：

| cell | RustCrypto | ring（默认） | Xray | ring/RustCrypto | ring/Xray |
|---|---:|---:|---:|---:|---:|
| 下行，c1 | 682.3 | 736.5 | 655.1 | 1.079 | 1.124 |
| 下行，c32 | 1277.0 | 1481.4 | 1391.6 | 1.160 | 1.065 |
| 上行，c1 | 635.6 | 670.8 | 611.2 | 1.055 | 1.097 |
| 上行，c32 | 1331.3 | 1429.3 | 1375.0 | 1.074 | 1.040 |

全部 16 个 framed cell 的 ring/RustCrypto 比值 ≥1.00。每 GiB framed 下行的
服务端成本（perf stat，各 3 次）：task-clock 631 vs 940 ms/GiB（−33%），指令数
−30%，上下文切换 −39%；RSS +3%（噪声）。

### fallback A/B —— `benchmarks/evidence/releases/v1-fallback-ab/`

最终 v1.0.0 干净同源 fallback 对比（splice 后端 vs Xray，两侧 warn 级日志），
7 次取样取中位数：

| 并发 | rust-reality（splice） | Xray | 比值 |
|---|---:|---:|---:|
| c1 | 1631 MiB/s | 1631 MiB/s | 1.00× |
| c4 | 3075 MiB/s | 2999 MiB/s | 1.03× |
| c32 | 3279 MiB/s | 3194 MiB/s | 1.03× |

## v1.3 规范结构与加密样本

- `benchmarks/evidence/releases/v1.3-hot-structures/summary.json` 记录 Criterion 的
  short-ID/UUID/tag 交叉点、VLESS 零拷贝门禁、REALITY digest 哈希、无锁 direct
  admission 及重放 deadline 堆/目标分片 A/B；基准源码为
  `benches/short_id_lookup.rs`、`benches/identity_lookup.rs`、
  `benches/tag_lookup.rs`、`benches/replay_expiry.rs`、
  `benches/vless_decode.rs` 和 `benches/admission.rs`。admission 基准保留了被替换的
  mutex token bucket 作为可执行对照，使争用结论可以持续复现。
- `benchmarks/evidence/releases/v1.3-setup-refactor/` 保存分配/查找重构后的组合 setup 路径复测：
  原始样本、perf 计数器和 `summary.json`。它是同机 loopback 证据，不是 WAN 承诺。
- `benchmarks/evidence/releases/v1.3-vless-encryption/summary.json` 记录同机 Xray v26.7.28
  叠加栈 A/B。它只适用于 REALITY + Vision 内的 VLESS Encryption，不代表 raw
  VLESS Encryption；完整解释和重审门槛见 ADR 0003。

## 双栈变更验证（2026-08-18）

双栈修正在 Intel Core i3-8100、Linux 6.12.100+deb13-amd64、rustc 1.96.0
上测量；使用默认 feature 的 release 构建，并固定到 `main`（`ed8fea0`）、原始
PR head（`b322024`）和修正代码快照（二进制 SHA-256 前缀 `1ffe66c8`）。原始
head 含无关且未发布的 v1.5 祖先链，因此只用于 connector 机制对比，不作为
relay 基线。

Criterion connector 中位数（100 个样本）为：数字 IPv4 42.54 us、数字 IPv6
45.03 us、健康混合地址族 51.37 us、IPv6 立即拒绝后转 IPv4 48.26 us。相对原始
PR head，数字 IPv4 -0.06%、数字 IPv6 +1.12%、规划 +0.44%，立即错误 fallback
从 69.82 us 降至 48.26 us，改善 30.9%；该立即错误路径不会等待配置的 250 ms。
在 101 轮 connector 路径计时测试中使用注入且确定的地址族结果：250 ms 策略下
模拟 `ENETUNREACH` 的 P50/P95/P99 为 50.17/53.86/185.61 us；5 ms 策略下首选
尝试停滞时为 6.26/6.43/6.43 ms。这些注入场景在不发送探测、也不依赖公网 IPv6
路由的前提下验证调度与 fallback 开销。

已建立 relay 的基准使用 32 MiB 流，每次运行每个单元保留七个样本，并以 A-B-A
顺序夹住 `main`；修正值取前后两次运行中位数的几何平均。单位 MiB/s：

| 方向 | c1 main | c1 修正 | 变化 | c32 main | c32 修正 | 变化 |
|---|---:|---:|---:|---:|---:|---:|
| 上行 | 2720.0 | 2725.8 | +0.21% | 2657.2 | 2672.1 | +0.56% |
| 下行 | 2604.5 | 2591.2 | -0.51% | 2574.3 | 2581.8 | +0.29% |
| 全双工 | 2536.5 | 2499.4 | -1.46% | 2510.2 | 2505.6 | -0.18% |

端到端 setup harness 每个单元保留五个、每个 128 连接的样本，失败数为零。修正
版对 `main`：c1 为 268.35 对 269.38 连接/秒，P50/P95/P99 中位数为
3.68/3.91/4.23 ms 对 3.67/3.94/4.24 ms；c32 为 878.24 对 880.96 连接/秒，
29.65/53.43/76.98 ms 对 30.59/56.10/65.13 ms。c32 P99 在运行间有波动，
而 P50/P95 改善。同一批 1,280 个成功连接的 `perf stat` 测得每连接 task-clock
为 0.666 对 0.663 ms（+0.55%），每连接指令数 +0.15%。地址族规划、健康状态和
刷新逻辑均不进入已建立 relay 的读写循环。

鲁棒性证据与吞吐数字分开记录。此次历史双栈测量当时有六个有界 parser 目标，
每个运行 20,000 个用例。当前攻击面程序在 `fuzz/Cargo.toml` 声明 14 个目标，
其中包含结构化 REALITY 认证目标；
所有目标都进入有界、按时间计的 CI 分片，并有更深的定时预算。解析属性门禁仍覆盖
最大请求的每个前缀以及每个位置的三种字节变异。受限 shell 本地运行只关闭 ptrace
不支持的 LSan 泄漏检测；CI 保留泄漏检测，TSan 则覆盖重放重复竞态。

## 方法规则（以及让早期数字作废的陷阱）

1. **任何 A/B 结论都要求对称的日志级别。** rust-reality 的 debug 级别会把每个
   连接的 JSON 事件序列化到 stderr 锁上；Xray 的 warning 级别不会。一次不对称
   对比曾凭空造出约 25% 的 fallback 劣势。矩阵 harness 只为逐连接后端统计
   才让 rust 服务端跑 debug；任何对日志开销敏感的 cell 都必须在干净 warn 级
   harness 上重测后才能下结论。
2. **剥离代理环境变量。** 覆盖 `127.0.0.1` 的 `NO_PROXY` 会让 curl 对 loopback
   URL 绕过显式的 `--socks5-hostname`。所有 harness 都剥离代理变量，并通过
   服务端连接日志验证流量确实走了隧道；没有该保护测出的是直连，不是代理。
3. **按记录的种子交错运行**并保留全部样本；按 cell 报告中位数和无效样本数。
4. **注意文件系统。** 多 GiB 完整性传输在小型 tmpfs 上会假性失败（curl rc=23，
   磁盘满）；harness 工作目录必须放在磁盘 backed 存储上。
5. **守住源站。** 源站是编译的（Go）、流式传输并自报错误；源站报错的 cell 标记
   为无效，而不是当作代理结果解读。

## v1.5.1 发布对比证据

所有 v1.5.1 数字均在发布主机（Intel i3-8100 4C/4T，Linux
6.12.100+deb13-amd64，rustc 1.96.0）上测得，每次运行都在主机独占锁
`/tmp/v151-bench.lock` 下串行。身份：候选 `a6d6363`（二进制 SHA-256
`b3bff3f7…`），基线为已发布的 v1.5.0 发布二进制（`eda773b`，SHA-256
`344a9d8f…`），对比对象 Xray-core 26.7.28（`5ca6f4b`，go1.26.0，SHA-256
`23d228d7…04c5268`）。两侧服务器均使用 warn 级日志（rust-reality 在
warn 级不做任何逐连接日志工作），两台服务器前置同一个未修改的 Xray
SOCKS5 客户端，REALITY cover 为 TLS 1.3，origin 在 loopback 上，每次
传输逐字节校验，对比运行采用平衡 ABBA 交错。证据根目录：
`artifacts/v1.5.1/`（`gates/` 为发布门禁，`readme-comparison/` 为对
Xray 的对比测量）。

发布门禁（`artifacts/v1.5.1/gates/evaluator-report.json`）：正式评估器
40 项受保护指标全部通过、零回归，并判定两项统计显著的改进——
`setup:c1:throughput`（中位 1.013，原始 p = 0.0005）与
`setup:server-cpu`（中位比值 0.933，bootstrap95 [0.930, 0.934]；聚合
task-clock 每连接 602 µs 对 646 µs——增量式 transcript 哈希改动）。
正式并发 1 矩阵（867 个样本，0 个无效）报告受保护路径无显著变化；
10 分钟 soak 的描述符、线程与 RSS 均平坦，零传输失败。

### 建连速率与时延对比 Xray —— `readme-comparison/g1-setup-xray/`

288 样本平衡 ABBA（accept → 首次 Vision 转换），Xray 担任其中一腿：

| 并发 | rust-reality conn/s | Xray conn/s | 比值 | p50 rust | p50 Xray | p99 rust | p99 Xray |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 266.6 | 262.5 | 1.016× | 3.7 ms | 3.7 ms | 4.4 ms | 16.0 ms |
| 8 | 756.3 | 710.0 | 1.065× | 9.6 ms | 10.2 ms | 18.6 ms | 32.5 ms |
| 32 | 850.8 | 806.4 | 1.055× | 27.6 ms | 29.7 ms | 59.4 ms | 64.5 ms |

服务端每建连 CPU（perf task-clock 归因，同一基准）：rust-reality 609 µs，
Xray 988 µs（Xray/rust 比值 1.62×）。（上文 v1.5.1 对 v1.5.0 的
CPU/conn 数字来自纯 rust setup ABBA。）

### 吞吐对比 Xray —— `gates/matrix-formal-r01/`、`gates/matrix-r01/`、`gates/matrix-r02/`

候选对 Xray 的逐单元 p50 吞吐比值。并发 1 矩阵为正式门禁；两轮并发 32
矩阵为探索性。

| 路径 | 批量 512 MiB ×32（r01、r02） | c1 单元（正式） |
|---|---:|---:|
| 双向 | 1.29×、1.33× | 1.01–1.03× |
| Direct 下载 | 1.59×、1.48× | 1.00–1.01× |
| Direct 上传 | 1.11×、1.07× | 1.01× |
| framed 下载 | 1.13×、1.15× | 1.00–1.04× |
| framed 上传 | 1.02×、1.04× | 1.02–1.05× |
| fallback | 0.94×、1.02× | 1.00–1.01× |

如实说明的例外：在 32 MiB × c1 的 Direct 上传单元中 Xray 更快——正式
矩阵 223 MiB/s 对 197 MiB/s，两轮探索性矩阵也是同一顺序（214 对 169；
242 对 212 MiB/s）。小载荷 c1 单元受时延约束，部分在本机呈双峰分布。

### DNS 对比 Xray —— `readme-comparison/g3-dns/`

loopback 假解析器（TTL 300 s，RTT 约 0 ms），同一个 Xray 客户端，域名
目的地在服务端解析；每阶段 8 轮 × 32 连接：

| 阶段 | rust-reality | Xray |
|---|---:|---:|
| cold p50（全新唯一名字） | 10.95 ms | 11.16 ms |
| warm p50（已缓存名字） | 9.21 ms | 10.18 ms |
| burst，64 个并发同名，墙钟 | 73.8 ms | 107.2 ms |
| burst 上游查询数 | 2 | 1 |

warm 阶段两侧上游查询均为 0。配置差异：cold 阶段 rust-reality 发出 A 与
AAAA 两类上游查询（256 个名字对应 512 次），而该 Xray 配置仅发 A 查询
（256 次）——cold 数字不构成效率结论。上游时延约 0（loopback UDP），
因此 cold/warm 数字隔离的是解析器与缓存机制成本，不含网络时延。

### 路由规则规模对比 Xray —— `readme-comparison/g5-routing/`

显式 first-match 域名规则，全部指向 direct 出站；目标名字命中最后一条
规则（最坏情况完整遍历）；DNS 答案在热身后缓存，时延隔离规则求值；
每个规模点平衡 ABBA，每侧 320 个连接：

| 规则数 | rust-reality conn/s | Xray conn/s | 比值 | p50 rust | p50 Xray |
|---:|---:|---:|---:|---:|---:|
| 10 | 699 | 646 | 1.08× | 10.0 ms | 10.0 ms |
| 100 | 703 | 659 | 1.07× | 9.8 ms | 10.8 ms |
| 1,000 | 683 | 598 | 1.14× | 9.8 ms | 11.3 ms |
| 10,000 | 690 | 321 | 2.15× | 9.7 ms | 22.3 ms |

运维差异：Xray 服务器携带 10,000 条显式域名规则在本机启动约需 50 秒
（matcher 构建；服务器日志 15:10:09 读取配置 → 15:11:01 首次 accept），
而 rust-reality 约 1 秒启动，因为其路由索引在配置加载时编译。

### soak 下的内存 —— `gates/soak-candidate-r01/`、`readme-comparison/g2-xray-rss/`

10 分钟混合负载 soak 后，standalone rust-reality 服务器的 VmRSS 为
7,840 KiB（7.7 MiB；采样峰值 7.9 MiB，HWM 7.8 MiB）。等价负载形态下
Xray 服务器的 VmRSS 为 38,888 KiB（38.0 MiB；HWM 38.1 MiB）。两侧在
soak 期间的描述符、线程与 RSS 增长均平坦，零传输失败。

### v1.5.1 测量局限

- 单一主机（4 核 i3-8100）、单一内核、仅 loopback；4 核上的并发 32
  单元测的是调度争用与代理成本的混合。
- 并发 32 的矩阵轮次使用探索性样本量；只有并发 1 的矩阵是正式发布
  门禁。
- 小载荷 c1 单元受时延约束，部分呈双峰分布。
- DNS 各阶段使用 loopback 上游（RTT 约 0 ms）。
- 这些是本机测量结果，不是普遍性能结论。

## v1.8.0 发布对比证据

v1.8.0 没有引入新的对比表格。它是架构发布，其性能主张是相对 v1.7.0 的中性，由
四个独立正式门禁确立，而非由新的头条测量活动确立。门禁输入、结论与已声明的局限
记录在 [performance.zh-CN.md](performance.md#v180-发布证据)。

stock Xray 兼容性门禁照常运行：固定的 `artifacts/xray-reference-v26.7.28` 客户端
驱动了每个门禁的每个 matrix cell，无效样本为零，SHA-256 载荷完整性 cell 全部通过。

下方 v1.7.0 及更早的头条表格仍是测量基础，未作改动。

## v1.7.0 发布对比证据

v1.7.0 受保护的 Xray 对比头条沿用 v1.6.1 测量基础：即 v1.6.0
在发布主机测得的数字（Intel i3-8100 4C/4T、Linux 6.12、rustc
1.96.0），每次运行都由主机独占锁串行。身份：候选 `c182829`，基线为
已发布的 v1.5.1 二进制（`149f126`），对比对象 Xray-core 26.7.28（`5ca6f4b`，
go1.26.0，二进制 SHA-256 `23d228d7…04c5268`）。两侧使用 warn 日志、同一个
未经修改的 Xray SOCKS5 客户端、TLS 1.3 REALITY cover、loopback origin、
逐字节校验和平衡 ABBA 交错。正式评估器 40 项受保护指标全部通过、零回归。

144 样本建连测量在 c1/c8/c32 分别为 268.5/767.5/853.2 conn/s，对比 Xray
251.4/716.9/784.5 conn/s。32 MiB × c32 的 p50 比值依次为：双向 1.28×、
Direct 下载 1.61×、framed 下载 1.13×、Direct 上传 1.06×、framed 上传
1.10×、fallback 0.98×。完整原始证据与限制见英文同版本章节中的
`artifacts/v1.6.0/` 索引；历史章节仍保留旧版本测量，不能读作当前行为。

## 历史 README 头条表格

下列表格此前位于 README 性能章节开头，现按版本作为历史证据保留；当前
README 使用上文 v1.6.0 对比。已被取代的数字不得再读作当前行为。

### v1.0.0 头条表格（冻结于 v1.0.0）

对比对象：Xray-core 26.7.28（提交 `5ca6f4b`，go1.26.0）。主机：Intel
i3-8100（4C/4T），Linux 6.12.94，loopback，Go origin，每单元 5 次采样；
所有单元均经字节校验，并对每个实现做 2 GiB SHA-256 完整性运行。矩阵
单元中 rust-reality 使用 debug 日志（测试架的防绕过护栏要求），Xray
使用 warning——这对 rust-reality 不利；fallback 与建连速率两行来自
日志级别对称（warn）的测试架。

| 工作负载 | rust-reality 1.0.0 | Xray-core | 比值 |
|---|---:|---:|---:|
| Direct 下载，512 MiB ×32 | 1386 MiB/s | 516 MiB/s | **2.69×** |
| Direct 上传，512 MiB ×32 | 1155 MiB/s | 1031 MiB/s | 1.12× |
| Framed 下载，512 MiB ×32 | 1580 MiB/s | 1388 MiB/s | 1.14× |
| Framed 上传，512 MiB ×32 | 1442 MiB/s | 1383 MiB/s | 1.04× |
| 双向，512 MiB ×32 | 1017 MiB/s | 633 MiB/s | 1.61× |
| Fallback，32 MiB ×32（干净测试架） | 3279 MiB/s | 3194 MiB/s | 1.03× |
| 建连速率，c32 | 895 conn/s | 812 conn/s | 1.10× |

每连接建连成本远低于 Xray 的一半（在 864 个连接的测量窗口内服务端
CPU 为 0.65 ms 对 1.53 ms）。单流 loopback 单元受时延约束，基本持平
（0.94–1.04×）。完整 36 单元矩阵详见
[performance.zh-CN.md](performance.md) “最终发布矩阵（v1.0.0）”
一节。

### v1.5.0 摘要（冻结于 v1.5.0）

v1.5 对 v1.4 的同机平衡 ABBA 没有发现统计显著的 setup 或受保护路径
吞吐/时延变化：两轮完整矩阵的所有已报告 95% 区间都跨越“无差异”。
单独的系统调用 trace 测得候选每个 setup 连接少 4.0013 次 cover
`recvfrom`。这些是有边界的实现成本观察，不是吞吐胜利声明；精确区间见
[performance.zh-CN.md](performance.md#v15-cover-flight-与发布证据)。
v1.5.0 的共享 DNS 合并结果、≥64 条规则的路由索引测量，以及真实 IPv6
验证范围都记录在同一文档中。

## v1.5 平衡 ABBA 证据

v1.5 发布对比使用不可变候选与 v1.4 二进制。每项权威 setup 或数据路径比较都在
可复现预热后按平衡 ABBA block 排列；保留原始样本、失败、二进制 SHA-256、频率
和温度元数据。perf 归因与系统调用 trace 在独立回合运行，绝不把插桩时间用于未
插桩性能声明。

最终发布评估器不把 bootstrap 区间当作显著性检验。对每项受保护指标，它计算
配对 block 对数比的均值（统一定向为正值代表候选更好），并在“每个 block 内
候选/基线标签可交换”的严格零假设下枚举全部符号翻转。所有受保护指标的单侧回退
假设组成一个全局 family，改善假设则组成另一个独立的全局 family；各自在
family-wise alpha 0.05 下做 Holm 校正，发布失败只由回退 family 决定。确定性的
95% block bootstrap 只保留为效应区间。每项正式指标必须包含 12 至 16 个完整
ABBA block，否则证据无效。三个 block 即使全部同向，单侧原始 p 值最小也只能是
1/8，而且会因检验功效不足在正式评估前被拒绝。

矩阵还会控制 Linux 的用户级 pipe-page 软上限。六个常驻数据面端点都会跨 cell
保留 splice 管道，因此仅交错 ABBA 流量无法平衡“先填满管道池”的进程。在四核
发布主机上，默认 16,384 页会让第一个 Rust 实现保留 256 KiB 管道，而第二个实现
只能获得降级管道；反转 `ABBA_START` 会把表面上 20–25% 的 Direct 回退一起反转。
把软上限提高到 harness 按最大并发计算出的 49,152 页后，两种实现都保留完整管道
并重新收敛。因此正式回合会按最大并发计算下界，以非交互权限应用，记录原值与
生效值，并在成功、失败或收到信号时恢复精确原值；若检测到外部篡改或恢复失败，
整个回合立即作废。

三组预热 setup block 测得候选/基线中位变化：c1 -0.38%（95% bootstrap 区间
-0.465% 至 +0.170%）、c8 +0.26%（-3.368% 至 +2.497%）、c32 +0.53%
（-1.257% 至 +1.557%）。归一化 task-clock 与 instructions 分别变化 -0.768%
和 -0.190%；context switches 变化 +1.042%，约每连接 +0.058 次。单独的当前
系统调用 trace 测得候选每连接少 4.0013 次 `recvfrom`。

两轮六路径矩阵用精确载荷哈希覆盖双向、Direct 下行/上行、fallback、framed
下行/上行；每轮保留 219 个样本且无无效样本。每条 workload 的吞吐和时延 95%
block-bootstrap 区间都跨越“无差异”。Direct 上行中位比值在两轮间从 0.9511
反转为 1.1390，证实顺序/主机噪声。这些结果按无差异证据保留：既不证明受保护
路径回退，也不足以支持性能胜利标题。

正式 CPU 档位对比为
`20260812T130000Z-matrix-v3-04285e63-r01`：同一源码/feature 的 x86-64-v3
（`final`）对 portable（`baseline`），共六组平衡 ABBA block。保留 219 个
样本、零无效样本，portable、v3 与 Xray 护栏的三个 64 MiB 完整性哈希均匹配。

| 路径 | v3/portable 吞吐中位比（95% CI） | v3/portable 最差时延中位比（95% CI） |
|---|---:|---:|
| 双向 | 1.0306（0.9240–1.1118） | 0.9935（0.8477–1.0862） |
| Direct 下行 | 1.0145（0.9820–1.0498） | 0.9906（0.9417–1.0372） |
| Direct 上行 | 0.9682（0.8462–1.1066） | 0.9970（0.8829–1.1871） |
| fallback | 0.9981（0.9280–1.0613） | 0.9795（0.8752–1.0169） |
| framed 下行 | 1.0091（0.9826–1.0278） | 1.0150（0.9996–1.0162） |
| framed 上行 | 1.0058（0.9865–1.0229） | 0.9751（0.9556–1.0074） |

全部十二个区间都包含 1，因此本轮没有提供统计可靠的 v3 优势。portable 档位
仍独立受保护：v3 证据不能抵消或掩盖 portable 回退。

v1.5 互操作矩阵还用 Xray 26.7.28 覆盖 Microsoft、Google、Fastly 三个公开
cover 以及不发送 CCS 的本地 OpenSSL 3.5.6；每种情况都通过精确 1 MiB
SHA-256 和 ML-DSA-65 兼容校验。它是协议门禁，不携带计时结论。

### v1.5.0 DNS、路由与 IPv6 证据

主机级别和注意事项同本文其余部分（i3-8100、Linux 6.12、loopback/同机；
仅描述实现成本）。

- **DNS 合并（共享解析器，上游服务器模式）：** 128 个并发相同查询只产生
  2 次上游请求（原为 315 次）；热路径 p50 从 12.9 ms 降到微秒以下；冷路径
  成本 +2.1%。system 模式的合并与治理完全相同，但不缓存动态应答
  （getaddrinfo 不提供 TTL）。
- **路由索引：** 在实测的 64 条规则交叉点，编译后的候选索引每条约占 53
  字节，并保持精确的有序 first-match 语义。P95 决策时延在 1,000 条规则时
  下降 31–57%，在 10,000 条时下降 31–55%；低于阈值的列表保持线性路径。
- **IPv6：** 原生 `cargo dev bench run --suite ipv6` 门禁在真实全球 IPv6 与真实 IPv6
  互联网出方向上运行，结果为 29 通过 / 0 失败 / 1 跳过；跳过项是外部
  入方向用例（验证主机上没有外部 IPv6 来源），因此公网入方向 IPv6 没有
  外部 attest。已覆盖：监听模式、全部客户端/服务端地址族组合、逐字节
  精确的 64 MiB 上行/下行/全双工、100 ms/1% netem、路由丢失/恢复，以及
  0.086 s 的地址族拒绝回退。

## v1.2.0 分布式与 WAN 仿真证据（LAB-NETEM）

v1.2 周期在命名空间/veth 装置上用 `tc netem` 表征了分布式拓扑（LAB-NETEM；
**不是**真实 WAN 证据——真实多机、真实 WAN、≥8 核与 NUMA 仍未验证）：

- **RTT 扫描**（客户端↔线路机延迟 0–200 ms）：所有拓扑——standalone、NXR、
  Handoff 与 Xray 对照——在每个 RTT 上都处于运行级噪声范围内（例如 100 ms
  时四者都约为 15 MiB/s）；Handoff 的建连开销最多比 NXR 多约 0.5 个内部链路
  RTT，与其单次密封传输的设计一致。单流数值依赖宿主机 TCP 自动调优。
- **丢包**（50 ms 下 0.5%）：NXR 与 Handoff 的差异处于测量噪声范围内；两者都会出现
  装置的双稳态慢速模式（见下）。
- **双稳态警告**：该装置上的单流大传输约有 15–25% 的样本落入约 70–150
  MiB/s 的慢速模式，与拓扑和中继后端无关（用 `ss -ti` 定位为连接churn下
  错误初始 RTT 导致的接收窗口自动调优平衡）。因此单流单元需要 n≥15 且取
  中位数；n=3 的尖峰不构成证据。
- **多对端 Handoff**：1 线路机→2 落地机、2 线路机→1 落地机以及 2×2 网状
  都按 UUID 路由逐字节精确传输；只有目标落地机能打开其配对的密封转移。
- **滚动升级**：v1.1.0↔v1.2.0 混合线路机/落地机配对（Handoff 与 NXR）双向
  逐字节精确；任一侧都可先升级。
- **故障语义**：落地机宕机或密钥错误约在 12–13 ms 内使客户端失败；落地机在
  传输中被杀会截断客户端流（绝不会产生假的干净 EOF）；传输活跃时收到
  SIGTERM 会优雅排空至多 30 秒，然后强制中止。
- **背压**：1 MiB/s 的慢客户端通过 Handoff 链路传输完整 512 MiB 时，两个
  节点的 RSS/FD 都保持平稳。
- **浸泡**：6 小时混合分布式浸泡（Handoff + NXR + churn + 周期性线路机
  reload + 落地机重启）：零传输失败，两个节点的 RSS/FD 增长都有界。

## Xray 26.7.28 兼容性门禁

`cargo dev bench run --suite xray-interop` 证明未经修改的 Xray 客户端可以端到端驱动生产
公网栈：

```text
curl -> Xray SOCKS5 入站 -> VLESS + REALITY + xtls-rprx-vision
     -> rust-reality -> direct -> 目标
```

```shell
cargo dev bench run --suite xray-interop \
  --rust-bin /path/to/rust-reality --xray-bin /path/to/xray
```

原生 suite 使用所选 release 二进制，生成全新的临时 UUID、X25519 和 short ID 材料，在
loopback 启动两个进程，经 Xray 传输一个确定的 1 MiB 对象并校验 SHA-256，
对固定种子核对 ML-DSA-65 验证密钥生成是否与 Xray 一致，并可选择请求一个真实
HTTPS URL。全部生成的配置和密钥保留在有界临时目录中，退出时删除。

2026-08-03 在验证主机上记录（Linux 6.12.94+deb13-amd64、rustc 1.96.0、Xray
26.7.28 `5ca6f4b`、伪装目标 `www.microsoft.com:443`、uTLS 指纹 `chrome`）：
1 MiB 摘要匹配，ML-DSA-65 验证密钥与 Xray 输出逐字节一致，一次真实 HTTPS 请求
返回 HTTP 302，Xray debug 日志显示两次传输都成功完成 Vision padding/unpadding
和已认证 Direct 边界检测。

这是兼容性门禁，不是基准：它的一次互联网请求不携带吞吐信号。

### 低描述符上限恢复门禁

`cargo dev bench run --suite descriptor-pressure` 是描述符耗尽的 fail-closed
回归门禁。它通过直接、类型化的 `prlimit` 参数运行现有二进制，并设置相等且很低的
软/硬 `RLIMIT_NOFILE`，
然后保持真实的 Xray -> REALITY -> Vision -> 本地回显会话，直到服务端的派生
FD 预算耗尽。门禁要求以下全部证据：

- 运行中的可执行文件哈希、精确的子进程身份和两个继承的限制都与请求的测试身份一致；
- `descriptor_budget_report` 反映该低限制，且 `descriptor_pressure_changed`
  达到 `high`；
- 精确的服务端进程存活，且在压力前建立的连接继续通过回显完整性检查；
- 有界风暴中至少一个新连接被拒绝或停滞；
- 保持的会话关闭后，压力回到 `normal`，且一次新的 64 KiB 回显流的
  SHA-256 匹配。

原生门禁绝不构建或下载被测二进制，通过 PID/启动时间 RAII 管理全部子进程，
不经 shell 传递外部工具参数，并拒绝覆盖已有的证据目录：

```shell
cargo dev bench run --suite descriptor-pressure \
  --rust-bin /absolute/path/to/rust-reality \
  --xray-bin /absolute/path/to/xray \
  --run-id descriptor-pressure-run-01 \
  --out-dir diagnostics/final/descriptor-pressure-run-01
```

## 限制

- **真实链路带宽门禁在验证主机上无法验证。** 其网卡协商速率为 100 Mb/s，真实
  互联网测量对两个实现同等地被压在约 94 Mbps。真实链路运行（20 次交替、每次
  5 MiB、零崩溃零协议错误）只是正确性证据。下行对比由 loopback 隧道 Direct
  路径测量代替。
- **单流 TLS 源站 cell 受源站限制**（每条 Go TLS 连接约 400–500 MiB/s）；这些
  cell 的比值在多次运行间摆动 0.8–1.1，不作为代理性能报告。
- **loopback p99** 主要由客户端/源站进程启动主导，谨慎解读。
- **Miri 无法覆盖 `crates/rr-linux`**（不支持其中的裸系统调用）；该 crate 由
  ABI/布局测试和特权测试套件覆盖。
- **NXR 没有协议级 Xray 基线**（Xray 没有实现 NXR），但 NXR 有受控协议对比：
  部署特征化（`cargo dev bench run --suite deployment`）在相同的线路/落地/源站拓扑
  上对比 NXR 与 SOCKS5——建连速率、吞吐、每连接 CPU 以及 netem RTT 扫描——
  并附带明确标注为系统级的 rust+NXR 对 Xray+SOCKS5 对比。最终数字见
  [performance.zh-CN.md](performance.md#部署特性v100)。

更早的开发机样本（2026-08-03 的 Xray loopback 表格，以及自身结论为"与噪声
无法区分"的 2 vCPU relay 基线）已被上述规范样本取代并从仓库移除。
