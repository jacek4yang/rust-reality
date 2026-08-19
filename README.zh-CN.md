# rust-reality

[![CI](https://github.com/jacek4yang/rust-reality/actions/workflows/ci.yml/badge.svg)](https://github.com/jacek4yang/rust-reality/actions/workflows/ci.yml)
[![Security](https://github.com/jacek4yang/rust-reality/actions/workflows/security.yml/badge.svg)](https://github.com/jacek4yang/rust-reality/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/jacek4yang/rust-reality?display_name=tag&sort=semver)](https://github.com/jacek4yang/rust-reality/releases)

[English](README.md) | 简体中文

`rust-reality` 是面向 Linux 的单二进制代理服务端。唯一的公网客户端入口是
**VLESS + REALITY + `xtls-rprx-vision`**。可选的独立 NXR 协议用于把线路机上
每一条已认证用户流量转发到仅受防火墙信任的落地机。

```text
兼容 Xray 的客户端
  -> VLESS + REALITY + Vision
  -> rust-reality 线路机或单机节点
  -> direct | SOCKS5 | blackhole | NXR | Handoff
  -> 可选的 NXR 或 Handoff 落地机
  -> 目标地址
```

## 核心亮点

- 公网 VLESS + REALITY + Vision 数据路径兼容 Xray-core 26.7.28，并以未经修改的
  Xray 客户端做端到端门禁。
- 方向级 Vision Direct：每个方向在认证完成的瞬间就切换到 raw 内核 relay
  （优先 `splice`），分裂脑从结构上不可能发生。
- 可选 Handoff 拓扑：线路机可以通过一条已认证的密封信道，把已接受会话的
  TLS 属主转移给防火墙限制的落地机，把逐字节 TLS CPU 卸给落地机（loopback
  实测：线路机下载 CPU/GiB −82%）。
- framed 记录打包、稳态每条记录零分配、每条数据路径零可避免的用户态拷贝。
- 默认使用 ring（源自 BoringSSL）的 AES-128-GCM 记录 AEAD；纯 Rust 的
  RustCrypto 回退构建只差一个参数，并持续测试。
- 已认证服务端 flight 保留伪装目标派生的 ServerHello，并跟随可选 CCS、实测的
  四位置/合并握手形状以及可选第五条 Finished 后形状；后者以不携带恢复状态的
  空 ApplicationData 假 NST 表示。检查前缀最多保留 66,642 字节，fallback
  仍逐字节精确。
- 一切皆有界：连接、握手、fallback、密码学工作、重放状态、缓冲区、DNS 结果、
  描述符和 splice 资源——压力下迟滞降级而不是崩溃。
- 支持具体和单标签通配的 REALITY server name、按 UUID 的路由分组、UUID 独占
  多 short ID 认证，以及兼容 Xray 的 GeoIP/GeoSite 资产（原子 last-known-good
  更新）。
- 基于实测的本机 `config autotune`（可审计原子输出），以及按基数自适应的
  UUID/路由/出站索引和 deadline 驱动的重放过期，不再无条件扫描存活表。
- 严格 JSON 配置、SIGHUP 原子热更新、不含秘密的有界日志、密钥生成、目标探测、
  self-test 和 Schema，全部由同一个二进制提供。
- 稳定 Rust：主协议 crate 禁止 `unsafe`（Linux ABI 的 unsafe 隔离在
  `crates/rr-linux` 并有显式 SAFETY 不变量），生产数据路径不使用
  panic/unwrap，标签发布包可复现。

## 与 Xray-core 的性能对比

对比对象：Xray-core 26.7.28（提交 `5ca6f4b`，go1.26.0，二进制 SHA-256
`23d228d7…04c5268`）——即互操作测试所用的同一二进制。以下所有 v1.5.1
数字均在发布主机（Intel i3-8100 4C/4T，Linux 6.12）上测得：两侧服务器均
使用 warn 级日志（rust-reality 在 warn 级不做任何逐连接日志工作），两台
服务器前置同一个未修改的 Xray SOCKS5 客户端，使用相同的 TLS 1.3 REALITY
cover，loopback origin，传输逐字节校验，并采用平衡 ABBA 交错。这些是受控
同机结果，不是互联网速率保证。完整方法与各次运行的工件索引见
[docs/benchmarks.zh-CN.md](docs/benchmarks.zh-CN.md)；更早版本的头条表格
作为历史证据保留在该文档中。

建连（accept → 首次 Vision 转换；288 样本 ABBA）：

| 并发 | rust-reality conn/s | Xray conn/s | 比值 | p99 rust | p99 Xray |
|---:|---:|---:|---:|---:|---:|
| 1 | 266.6 | 262.5 | 1.02× | 4.4 ms | 16.0 ms |
| 8 | 756.3 | 710.0 | 1.07× | 18.6 ms | 32.5 ms |
| 32 | 850.8 | 806.4 | 1.05× | 59.4 ms | 64.5 ms |

批量吞吐，v1.5.1 对 Xray 的 p50 比值（512 MiB × 并发 32，两轮）：

| 路径 | 比值 |
|---|---:|
| 双向 | 1.29–1.33× |
| Direct 下载 | 1.48–1.59× |
| framed 下载 | 1.13–1.15× |
| Direct 上传 | 1.07–1.11× |
| framed 上传 | 1.02–1.03× |
| fallback（伪装中继） | 0.94–1.02× |

服务端 DNS（loopback 解析器；每阶段 8 轮 × 32 连接）：cold p50 11.0 ms 对
11.2 ms，warm p50 9.2 ms 对 10.2 ms（两侧上游查询均为 0）；64 个并发同名
查询的 burst 在 73.8 ms 对 107.2 ms 墙钟时间内完成。

按规则数的路由决策成本（最坏情况——命中最后一条规则；每个规模点平衡
ABBA）：

| 规则数 | rust-reality conn/s | Xray conn/s | 比值 | p50 rust | p50 Xray |
|---:|---:|---:|---:|---:|---:|
| 10 | 699 | 646 | 1.08× | 10.0 ms | 10.0 ms |
| 100 | 703 | 659 | 1.07× | 9.8 ms | 10.8 ms |
| 1,000 | 683 | 598 | 1.14× | 9.8 ms | 11.3 ms |
| 10,000 | 690 | 321 | 2.15× | 9.7 ms | 22.3 ms |

内存：在 10 分钟混合负载 soak 后，standalone 服务器的常驻内存为
7.7 MiB（峰值 7.9 MiB），而 Xray 在等价负载形态下为 38.0 MiB。

对比 v1.5.0：v1.5.1 的增量式握手 transcript 哈希将每建连服务端 CPU 降低了
6.7%（setup ABBA 中位比值 0.933，bootstrap95 [0.930, 0.934]；聚合
task-clock 602 µs 对 646 µs），正式发布评估器 40 项受保护指标全部通过、
无回归。

### rust-reality 更快的场景

- 并发 32 下的批量 Direct 下载（1.48–1.59×）与双向负载（1.29–1.33×）——
  Vision Direct splice 快路径。
- 建连尾时延：c1 的 p99 最多低 3.6×（4.4 ms 对 16.0 ms），并一直领先到
  c32。
- 大规模路由：从 10 条到 10,000 条规则决策成本保持平坦，而 Xray 随之退化
  （10,000 条规则时建连速率领先 2.15×）。
- 同名 DNS burst（墙钟 1.45×）与常驻内存（10 分钟 soak 下 RSS 约低 5×）。

### 性能持平的场景

- fallback（伪装）中继：所有已测单元为 0.94–1.02×。
- framed 上传（1.02–1.03×）以及单流或小载荷单元（≈0.99–1.05×，loopback
  上受时延约束）。
- c1 建连速率（1.02×）与 cold/warm DNS 解析时延（p50 相差约 1 ms 以内）。

### 运维差异

- Xray 携带 10,000 条显式域名规则启动在本机约需 50 秒（matcher 构建）；
  rust-reality 约 1 秒启动，因为其路由索引在配置加载时编译。
- 在 cold DNS 测量中，rust-reality 发出 A 与 AAAA 两类上游查询（256 个
  名字对应 512 次上游查询），而该 Xray 配置仅发 A 查询（256 次）——这是
  配置差异，不是效率结论；warm 阶段两侧上游查询均为 0。

### 测量局限

- 单一主机（4 核 i3-8100）、单一内核（Linux 6.12）、仅 loopback；4 核上
  的并发 32 单元测的是调度争用与代理成本的混合。数字描述的是实现成本，
  不是互联网吞吐。
- 并发 32 的矩阵轮次使用探索性样本量；只有并发 1 的矩阵是正式发布门禁。
- 小载荷 c1 单元受时延约束，部分在本机呈双峰分布。
- 在 32 MiB × c1 的 Direct 上传单元中 Xray 更快（正式矩阵 223 MiB/s 对
  197 MiB/s；两轮探索性矩阵也是同一顺序）。
- Xray 的每建连服务端 CPU 未测量——perf 归因所需的权限在 Xray 腿上不
  可用。
- DNS 各阶段使用 loopback 上游（RTT 约 0 ms），因此 cold/warm 数字隔离的
  是解析器与缓存机制成本，不含网络时延。

## 架构

单个 Tokio 多线程运行时；每连接一个任务，认证后拆成两个独立的方向任务。
framed 阶段运行带 Vision padding 的外层 TLS 记录 I/O；在已认证的 Direct
边界，每个方向独立切换到 raw relay——两个方向都到达时合并 socket 做双向
`splice`，否则单向 `splice`，后端拒绝时回退到有界 buffered 用户态 relay。
到伪装目标的 fallback（ camouflage ）流量使用同一个统一的、计入 FD 预算的
relay。生命周期、热路径拓扑、描述符预算模型和可观测事件见
[docs/architecture.zh-CN.md](docs/architecture.zh-CN.md)，协议栈本身见
[docs/protocol.zh-CN.md](docs/protocol.zh-CN.md)。

## 支持范围

正式发布目标：采用现代内核的 Linux x86_64 和 Linux aarch64。Release 提供三个
压缩包：`linux-x86_64-generic`（基线 x86-64，推荐资产）、`linux-x86_64-v3`
（可选；要求 x86-64-v3 微架构级别，无运行时回退，在验证主机上没有实测优势——
记录 AEAD 在每个档位都于运行时调度到 AES 硬件），以及
`linux-aarch64-generic`（ARMv8.0 含 neon，在 ARM runner 上原生构建并通过冒烟
测试）。不确定机器能力时应选择通用包。公网入站不支持纯 VLESS、仅 TLS
的 VLESS、WebSocket、QUIC、UDP 代理或非 Vision flow。NXR 不是公网协议，一次
认证请求完成后也不会加密后续载荷。公网协议带有使用未经修改的 Xray-core
26.7.28 客户端的端到端互操作门禁；部署者仍须根据自己的 VPS 审查威胁模型、
防火墙、REALITY 目标和资源限制。

## 快速开始

从[最新 Release](https://github.com/jacek4yang/rust-reality/releases/latest)
下载适合你平台的压缩包、manifest 和校验文件，安装前验证全部资产：

```shell
sha256sum --check SHA256SUMS
# x86-64 通用包（不确定 CPU 能力时推荐）：
tar -xzf rust-reality-v<version>-linux-x86_64-generic.tar.gz
# 或在 x86-64-v3 CPU 上使用：
# tar -xzf rust-reality-v<version>-linux-x86_64-v3.tar.gz
# 在 ARM64（ARMv8.0 含 neon 或更高）上使用：
# tar -xzf rust-reality-v<version>-linux-aarch64-generic.tar.gz
sudo install -m 0755 rust-reality /usr/local/bin/rust-reality
```

`release-manifest.json` schema v3 记录每个档位的编译器、cargo features、目标
CPU/特性、是否在本机实测，以及最低 CPU 要求。

探测 REALITY 伪装目标并生成单机配置：

```shell
rust-reality probe-dest \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com

rust-reality config generate standalone \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com \
  > config.json 2> client-values.txt

rust-reality check --config config.json
rust-reality config autotune \
  --config config.json --output config.tuned.json
rust-reality check --config config.tuned.json
rust-reality self-test --config config.tuned.json
rust-reality serve --config config.tuned.json
```

生成的 JSON 已包含 UUID、REALITY 私钥、归该 UUID 独占的两个 short ID、入站
`listen.mode: auto`、出站 `network.dial.mode: auto` 和 direct 路由策略。入站使用
独立 IPv4/IPv6 套接字，出站由进程级自适应状态选择地址族。供客户端
使用的 REALITY 公钥写入标准错误，使服务器私密配置可以单独保存。两个输出都应
妥善保护；示例目标必须替换成从实际部署机器执行 `probe-dest` 能通过的目标。
完整步骤（含线路机/落地机 NXR 拓扑）见
[docs/getting-started.zh-CN.md](docs/getting-started.zh-CN.md)。

## 配置

配置采用严格 camelCase JSON。未知字段、缺失引用、重复 UUID/tag、不安全 URL、
无界限制、纯 VLESS 和已移除的加速开关都会在监听端口绑定前被拒绝。

路由依次匹配 `routing.globalRules`，再依次匹配已认证 UUID 所属
`routing.users[].rules`，最后使用该用户组的 `defaultOutbound`。同一规则中不同
条件类别之间是 AND；同一类别的多个值之间是 OR。所有字段、默认值、约束、匹配
器语法、热更新行为和专用资源模式见
[配置参考](docs/configuration.zh-CN.md)。v1.2 配置在 v1.3 重启前必须把原来共享的
`realitySettings.shortIds` 列表移到其所属的 `clients[]` 条目下。

## 部署

`serve`/`run` 在前台运行，适合 systemd；SIGINT/SIGTERM 优雅退出；SIGHUP 验证
并原子发布兼容的新配置，已建立连接继续使用旧 generation。请安装并审查
[`deploy/rust-reality.service`](deploy/rust-reality.service) 提供的 systemd 加固
基线；验证、服务账号、防火墙规则、升级与回滚见
[docs/deployment.zh-CN.md](docs/deployment.zh-CN.md)。

## 安全

开放监听端口前请阅读[威胁模型](docs/threat-model.zh-CN.md)；支持版本、私密
漏洞报告和密码学边界——包括 ring AEAD 提供者已披露的清零取舍和
`--no-default-features` RustCrypto 回退构建——见
[安全策略](SECURITY.zh-CN.md)。应用程序无法阻止上游流量型 DDoS 填满 VPS 链路。
NXR 必须由防火墙限制，其认证后的字节是明文。不要在 issue 或日志中公开真实
私钥、UUID、NXR PSK、凭据、抓包、访问令牌或部署配置。

## 文档

| 指南 | English | 简体中文 |
| --- | --- | --- |
| 文档索引 | [English](docs/index.md) | [简体中文](docs/index.zh-CN.md) |
| 快速上手 | [English](docs/getting-started.md) | [简体中文](docs/getting-started.zh-CN.md) |
| 命令行参考 | [English](docs/cli.md) | [简体中文](docs/cli.zh-CN.md) |
| 配置参考 | [English](docs/configuration.md) | [简体中文](docs/configuration.zh-CN.md) |
| 部署指南 | [English](docs/deployment.md) | [简体中文](docs/deployment.zh-CN.md) |
| 协议概览 | [English](docs/protocol.md) | [简体中文](docs/protocol.zh-CN.md) |
| 架构 | [English](docs/architecture.md) | [简体中文](docs/architecture.zh-CN.md) |
| 性能 | [English](docs/performance.md) | [简体中文](docs/performance.zh-CN.md) |
| 基准测试 | [English](docs/benchmarks.md) | [简体中文](docs/benchmarks.zh-CN.md) |
| 威胁模型 | [English](docs/threat-model.md) | [简体中文](docs/threat-model.zh-CN.md) |
| 安全策略 | [English](SECURITY.md) | [简体中文](SECURITY.zh-CN.md) |

## 构建与开发

固定工具链声明在 `rust-toolchain.toml`：

```shell
cargo install cargo-nextest --version 0.9.140 --locked
cargo install cargo-deny --version 0.19.4 --locked
cargo install cargo-audit --version 0.22.2 --locked
./scripts/check.sh
./scripts/build-release.sh
```

质量门禁包含格式化、严格 Clippy、依赖策略、RustSec 审计、文档、nextest、
release 模式测试、doc test 和基准入口执行。Security CI 还执行解析器 fuzz
smoke 以及定期 sanitizer 任务。默认构建使用 ring 作为 TLS 1.3 AES-128-GCM
记录 AEAD；`cargo build --release --no-default-features` 选择纯 Rust 的
RustCrypto 提供者，没有其他行为差异。

## 许可证

本仓库采用双重许可，可任选其一：

- Apache License 2.0 版（[LICENSE-APACHE](LICENSE-APACHE)）
- MIT 许可证（[LICENSE-MIT](LICENSE-MIT)）

第三方依赖保留其各自许可证；`deny.toml` 将其约束在宽松许可证白名单内。
