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
- 已认证服务端 flight 保留伪装目标派生的 ServerHello，并跟随目标实测的合并/
  四记录 post-ServerHello 形状。v1.4 仅在文档列出的记录/写入维度上与 OpenSSL
  参考对齐，不声称与参考流量完全相同。
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

对比对象：Xray-core 26.7.28（提交 `5ca6f4b`，go1.26.0），即互操作测试所用的
同一二进制。主机：Intel i3-8100（4C/4T），Linux 6.12.94，loopback，Go origin，
每单元 5 次采样；所有单元均经字节校验，并对每个实现做 2 GiB SHA-256 完整性
运行。矩阵单元中 rust-reality 使用 debug 日志（测试架的防绕过护栏要求），
Xray 使用 warning——这对 rust-reality 不利；fallback 与建连速率两行来自
日志级别对称（warn）的测试架。这些是受控同机结果，不是互联网速率保证。

| 工作负载 | rust-reality 1.0.0 | Xray-core | 比值 |
|---|---:|---:|---:|
| Direct 下载，512 MiB ×32 | 1386 MiB/s | 516 MiB/s | **2.69×** |
| Direct 上传，512 MiB ×32 | 1155 MiB/s | 1031 MiB/s | 1.12× |
| Framed 下载，512 MiB ×32 | 1580 MiB/s | 1388 MiB/s | 1.14× |
| Framed 上传，512 MiB ×32 | 1442 MiB/s | 1383 MiB/s | 1.04× |
| 双向，512 MiB ×32 | 1017 MiB/s | 633 MiB/s | 1.61× |
| Fallback，32 MiB ×32（干净测试架） | 3279 MiB/s | 3194 MiB/s | 1.03× |
| 建连速率，c32 | 895 conn/s | 812 conn/s | 1.10× |

每连接建连成本远低于 Xray 的一半（在 864 个连接的测量窗口内服务端 CPU 为
0.65 ms 对 1.53 ms）。单流
loopback 单元受时延约束，基本持平（0.94–1.04×）。完整 36 单元矩阵、部署特性
（路由、NXR 对 SOCKS5、RTT 敏感度）、热路径取证报告及复现方法见
[docs/performance.zh-CN.md](docs/performance.zh-CN.md) 和
[docs/benchmarks.zh-CN.md](docs/benchmarks.zh-CN.md)。

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

正式发布目标：采用现代内核的 Linux x86_64。公网入站不支持纯 VLESS、仅 TLS
的 VLESS、WebSocket、QUIC、UDP 代理或非 Vision flow。NXR 不是公网协议，一次
认证请求完成后也不会加密后续载荷。公网协议带有使用未经修改的 Xray-core
26.7.28 客户端的端到端互操作门禁；部署者仍须根据自己的 VPS 审查威胁模型、
防火墙、REALITY 目标和资源限制。

## 快速开始

Release 保留 portable `x86_64-unknown-linux-gnu` 压缩包，并额外提供可选的
`x86_64-v3` 压缩包。后者要求 CPU 支持 x86-64-v3，且没有运行时回退；不确定
机器能力时应选择 portable 包。

从[最新 Release](https://github.com/jacek4yang/rust-reality/releases/latest)
下载两个压缩包、manifest 和校验文件，安装前验证全部资产：

```shell
sha256sum --check SHA256SUMS
# portable 包（不确定 CPU 能力时推荐）：
tar -xzf rust-reality-v<version>-x86_64-unknown-linux-gnu.tar.gz
# 或在 x86-64-v3 CPU 上使用：
# tar -xzf rust-reality-v<version>-x86_64-v3-unknown-linux-gnu.tar.gz
sudo install -m 0755 rust-reality /usr/local/bin/rust-reality
```

`release-manifest.json` schema v2 会记录两个 CPU 档位及其运行要求。

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

生成的 JSON 已包含 UUID、REALITY 私钥、归该 UUID 独占的两个 short ID 和
direct 路由策略。供客户端
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
