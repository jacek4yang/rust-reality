# 基准策略与规范样本

[English](benchmarks.md) | 简体中文

本文说明 rust-reality 的测量方式、v1.0.0 的规范样本，以及解释任何数字时的
边界。最终冻结的 v1.0.0 发布对比矩阵在发布时用同一批 harness 生成；数字背后
的设计级证据见 [performance.zh-CN.md](performance.zh-CN.md)。

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

## Harness

| Harness | 用途 |
|---|---|
| `rust-reality benchmark`（内置） | 有界、机器可读的进程内协议测量（VLESS 解码、Vision framing、NXR 认证）。 |
| `cargo bench`（criterion） | VLESS 解码、Vision framing 和 relay 后端的回归分析，带基线和图表。 |
| `scripts/benchmark-matrix.sh` | 完整 A/B/C loopback 矩阵（baseline/final/Xray），覆盖 方向 × 载荷 × 并发。 |
| `scripts/benchmark-fallback-ab.sh` | 干净的 fallback A/B：两侧 warn 级日志，直连 listener。 |
| `scripts/benchmark-setup-rate.sh` | 连接 setup 速率模型（accept → 第一次 Vision 转换）。 |
| `scripts/benchmark-vision-direct.sh`、`scripts/benchmark-xray.sh` | 聚焦的 Vision-Direct 与 Xray 对比。 |
| `scripts/benchmark-deployment.sh` | 部署特征化：路由正确性证明、路由决策成本（含 DNS 策略）、NXR 拓扑（direct/NXR/SOCKS5/Xray）、可选的 netem RTT 扫描，以及长连接 relay 证据。 |
| `scripts/soak-test.sh` | 回环混合负载浸泡测试（隧道流量 + 连接churn），用 `/proc` 快照做泄漏上界检查；环境变量：`DURATION_MIN`、`ROUND_SLEEP`、`RUST_REALITY_BIN`、`XRAY_BIN`、`OUT_DIR`。 |
| `scripts/benchmark-real-path.sh` | 真实互联网路径上与 Xray 的 A/B：崩溃与协议错误门禁；吞吐受路径最慢链路限制，不能用于区分带宽。 |
| `scripts/test-xray-interop.sh` | 兼容性门禁（见下），不是基准。 |

## v1.0.0 规范样本

仓库保留最终 v1.0.0 证据集：`benchmarks/final/v1-matrix/` 与 `v1-matrix-512/`
（36 单元发布矩阵）、`v1-fallback-ab/`、`v1-setup-rate/` 为发布规范样本；
`d9-framed-ab/`（ring 提供者 A/B）与 `d11-ab/`（记录批处理 A/B）是两项已发布
设计决策的机制证据。更大的历史矩阵已在仓库之外的发布证据档案中保存。


### framed AEAD 提供者 A/B —— `benchmarks/final/d9-framed-ab/`

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

### fallback A/B —— `benchmarks/final/v1-fallback-ab/`

最终 v1.0.0 干净同源 fallback 对比（splice 后端 vs Xray，两侧 warn 级日志），
7 次取样取中位数：

| 并发 | rust-reality（splice） | Xray | 比值 |
|---|---:|---:|---:|
| c1 | 1631 MiB/s | 1631 MiB/s | 1.00× |
| c4 | 3075 MiB/s | 2999 MiB/s | 1.03× |
| c32 | 3279 MiB/s | 3194 MiB/s | 1.03× |

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

`scripts/test-xray-interop.sh` 证明未经修改的 Xray 客户端可以端到端驱动生产
公网栈：

```text
curl -> Xray SOCKS5 入站 -> VLESS + REALITY + xtls-rprx-vision
     -> rust-reality -> direct -> 目标
```

```shell
XRAY_BIN=/path/to/xray ./scripts/test-xray-interop.sh
```

脚本构建 release 二进制，生成全新的临时 UUID、X25519 和 short ID 材料，在
loopback 启动两个进程，经 Xray 传输一个确定的 1 MiB 对象并校验 SHA-256，
对固定种子核对 ML-DSA-65 验证密钥生成是否与 Xray 一致，并可选择请求一个真实
HTTPS URL。全部生成的配置和密钥保留在有界临时目录中，退出时删除。

2026-08-03 在验证主机上记录（Linux 6.12.94+deb13-amd64、rustc 1.96.0、Xray
26.7.28 `5ca6f4b`、伪装目标 `www.microsoft.com:443`、uTLS 指纹 `chrome`）：
1 MiB 摘要匹配，ML-DSA-65 验证密钥与 Xray 输出逐字节一致，一次真实 HTTPS 请求
返回 HTTP 302，Xray debug 日志显示两次传输都成功完成 Vision padding/unpadding
和已认证 Direct 边界检测。

这是兼容性门禁，不是基准：它的一次互联网请求不携带吞吐信号。

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
  部署特征化（`scripts/benchmark-deployment.sh`）在相同的线路/落地/源站拓扑
  上对比 NXR 与 SOCKS5——建连速率、吞吐、每连接 CPU 以及 netem RTT 扫描——
  并附带明确标注为系统级的 rust+NXR 对 Xray+SOCKS5 对比。最终数字见
  [performance.zh-CN.md](performance.zh-CN.md#部署特性v100)。

更早的开发机样本（2026-08-03 的 Xray loopback 表格，以及自身结论为"与噪声
无法区分"的 2 vCPU relay 基线）已被上述规范样本取代并从仓库移除。
