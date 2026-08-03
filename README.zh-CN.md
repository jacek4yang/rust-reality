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
  -> direct | SOCKS5 | blackhole | NXR
  -> 可选的 NXR 落地机
  -> 目标地址
```

## 核心能力

- 公网 VLESS + REALITY + Vision 数据路径兼容 Xray 26.7.28。
- 支持具体 REALITY server name 和 `*.lmu.edu` 这样的证书式单标签模式；客户端仍发送具体 SNI。
- 只有验证正确的 TLS 1.3 ClientFinished 后才提交认证状态。
- 认证失败时，把已经读取的全部字节原样、按顺序转发到伪装目标，不返回可识别代理的合成响应。
- 使用清晰的 UUID 分组策略和有序 first-match 规则进行路由。
- 支持 Xray 社区格式的 GeoIP、GeoSite 和 `ext:文件:标签`；HTTPS 下载、大小、
  超时、缓存和原子 last-known-good 更新都有明确边界。
- 支持 direct、带认证 SOCKS5、blackhole 和低开销 NXR 出站。
- 对连接、握手、fallback、密码学工作、重放状态、缓冲区、DNS 结果和 Linux
  splice 资源设置硬上限。
- 严格 JSON 配置、SIGHUP 原子热更新、有界日志、密钥生成、目标探测、
  self-test、JSON Schema 和内置基准测试全部由同一个二进制提供。
- 使用稳定 Rust；crate 禁止 `unsafe`；生产数据路径不使用 panic/unwrap；
  标签发布包可复现。

## 发布状态与范围

`0.1.x` 是 1.0 之前的生产预览版本。项目使用未经修改的 Xray-core 26.7.28
客户端执行端到端兼容性门禁，但部署者仍须根据自己的 VPS 审查威胁模型、
防火墙、REALITY 目标和资源限制。

当前正式发布目标是采用现代内核的 Linux x86_64。公网入站不支持纯 VLESS、
仅 TLS 的 VLESS、WebSocket、QUIC、UDP 代理或非 Vision flow。NXR 不是公网协议，
一次认证请求完成后也不会加密后续载荷。

## 快速开始

从[最新 Release](https://github.com/jacek4yang/rust-reality/releases/latest)
下载压缩包、manifest 和校验文件，安装前验证全部资产：

```shell
sha256sum --check SHA256SUMS
tar -xzf rust-reality-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 0755 rust-reality /usr/local/bin/rust-reality
```

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
rust-reality self-test --config config.json
rust-reality serve --config config.json
```

生成的 JSON 已包含 UUID、REALITY 私钥、short ID 和 direct 路由策略。供客户端
使用的 REALITY 公钥写入标准错误，使服务器私密配置可以单独保存。两个输出都应
妥善保护；示例目标必须替换成从实际部署机器执行 `probe-dest` 能通过的目标。

线路机/落地机部署需要先生成独立 NXR 密钥，并在两台机器上使用同一个值：

```shell
rust-reality node-keygen
rust-reality config generate line --help
rust-reality config generate landing --help
```

落地机防火墙必须只允许线路机固定源 IP 访问 NXR 端口。

## 配置与路由

配置采用严格 camelCase JSON。未知字段、缺失引用、重复 UUID/tag、不安全 URL、
无界限制、纯 VLESS 和尚未实现的加速开关都会在监听端口绑定前被拒绝。

路由顺序如下：

1. 依次匹配 `routing.globalRules`；
2. 依次匹配已认证 UUID 所属 `routing.users[].rules`；
3. 使用该用户组的 `defaultOutbound`。

同一规则中，不同条件类别之间是 AND；同一类别的多个值之间是 OR。支持域名、
GeoSite、IP、GeoIP、端口、网络和公网入站 tag。所有字段、默认值、约束、匹配器
语法和热更新行为见[完整配置参考](docs/configuration.zh-CN.md)。

## 运行维护

- `serve` 与 `run` 在前台运行，适合 systemd 或其他进程管理器。
- SIGINT/SIGTERM 触发优雅退出。
- SIGHUP 验证并原子发布兼容的新配置；已有连接继续使用旧的不可变 generation。
- Geo 资产按配置周期进行条件重验证；下载或解析失败时保留最后一个有效快照。
- 日志可写入 stderr、journald 或受单文件大小、文件数和总大小共同限制的文件集合。
  结构化日志不会记录密钥和完整配置。

请安装并审查 [`deploy/rust-reality.service`](deploy/rust-reality.service) 提供的
systemd 加固基线。

## 命令行

单一二进制提供以下命令：

```text
serve, run, check, self-test, probe-dest
config generate, config format, schema
uuid, x25519, mldsa65, node-keygen
benchmark
```

所有参数、范围、默认值、输出、信号和示例见[命令行参考](docs/cli.zh-CN.md)。

## 文档

| 指南 | English | 简体中文 |
| --- | --- | --- |
| 文档索引 | [English](docs/index.md) | [简体中文](docs/index.zh-CN.md) |
| 命令行参考 | [English](docs/cli.md) | [简体中文](docs/cli.zh-CN.md) |
| 配置参考 | [English](docs/configuration.md) | [简体中文](docs/configuration.zh-CN.md) |
| 部署指南 | [English](docs/deployment.md) | [简体中文](docs/deployment.zh-CN.md) |
| 威胁模型 | [English](docs/threat-model.md) | [简体中文](docs/threat-model.zh-CN.md) |
| 基准测试 | [English](docs/benchmarks.md) | [简体中文](docs/benchmarks.zh-CN.md) |
| 安全策略 | [English](SECURITY.md) | [简体中文](SECURITY.zh-CN.md) |

协议复用审计、架构决策和 Xray 互操作证据也可从文档索引进入。

## 性能

内置 `benchmark` 命令输出机器可读且执行时间有界的协议测量结果；Criterion
覆盖 VLESS 解码、Vision framing 和路由。受控的同机 Xray 对比记录在
[`docs/benchmarks.zh-CN.md`](docs/benchmarks.zh-CN.md)。

这些数据不是互联网速度承诺。只有控制延迟、丢包、拥塞、CPU、内核、网卡、
目标站和客户端行为后，才能得出部署结论。

## 构建与测试

固定工具链声明在 `rust-toolchain.toml`：

```shell
cargo install cargo-nextest --version 0.9.140 --locked
cargo install cargo-deny --version 0.19.4 --locked
cargo install cargo-audit --version 0.22.2 --locked
./scripts/check.sh
./scripts/build-release.sh
```

质量门禁包含格式化、严格 Clippy、依赖策略、RustSec 审计、文档、nextest、
release 模式测试、doc test 和基准入口执行。Security CI 还执行解析器 fuzz smoke
以及定期 sanitizer 任务。

## 安全

开放监听端口前请阅读[威胁模型](docs/threat-model.zh-CN.md)。应用程序无法阻止
上游流量型 DDoS 填满 VPS 链路。NXR 必须由防火墙限制，其认证后的字节是明文。

敏感漏洞请按照 [`SECURITY.zh-CN.md`](SECURITY.zh-CN.md) 使用 GitHub 私密漏洞报告。
不要在 issue 或日志中公开真实私钥、UUID、NXR PSK、凭据、抓包、访问令牌或部署配置。
