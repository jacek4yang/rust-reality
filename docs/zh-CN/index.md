# 文档索引

[English](../en/index.md) | 简体中文

## 从这里开始

| 文档 | 用途 |
| --- | --- |
| [快速上手](getting-started.md) | 安装、生成材料、写配置、连上客户端。 |
| [配置是怎么回事](configuration/index.md) | 贯穿整份文件的规则：角色、名字、默认值、密钥、热更新。 |
| [排障](operations/troubleshooting.md) | 按症状组织，开头两条就是绝大多数问题的来源。 |

## 配置

| 文档 | 用途 |
| --- | --- |
| [单机节点](configuration/standalone.md) | 一次一个决定地搭出单节点配置。 |
| [用户与凭据](configuration/users-and-credentials.md) | 生成什么、哪一半放哪里、怎么轮换。 |
| [伪装目标](configuration/cover-targets.md) | 挑选并验证这台服务器要伪装成的主机。 |
| [出站](configuration/outbounds.md) | 两个内置出站，和你可以声明的三种。 |
| [路由](configuration/routing.md) | 规则、匹配器、按用户区分的策略，以及 geo 数据。 |
| [线路节点与落地节点](configuration/line-landing.md) | 两台机器，让客户端连的 IP 不是流量出去的 IP。 |
| [Handoff](configuration/handoff.md) | 同样的拓扑，但落地节点读不了它转发的东西。 |
| [多落地节点](configuration/multi-landing.md) | 多个出口，按用户选。 |
| [DNS 与网络](configuration/dns-and-network.md) | 解析器、缓存，以及出站地址族策略。 |
| [运行时与资源](configuration/runtime-and-resources.md) | 机器姿态、推导出的上限，以及什么时候钉住才正当。 |
| [配置参考手册](configuration/reference.md) | 每个对象、字段、类型、默认值和热更新规则。 |

## 运维

| 文档 | 用途 |
| --- | --- |
| [Linux 部署](operations/deployment.md) | Release 验证、systemd、防火墙、文件和升级。 |
| [命令行参考](cli.md) | 全部命令、选项、默认值、输出、信号和退出行为。 |
| [威胁模型](threat-model.md) | 安全目标、信任边界、NXR 局限与非目标。 |
| [工程与发布流程](release-process.md) | 证据等级、PR/tag 生命周期、金丝雀、回滚。 |
| [安全策略](../../SECURITY.md) | 支持的版本与私密漏洞报告。 |

## 设计与证据

| 文档 | 用途 |
| --- | --- |
| [协议概览](protocol.md) | VLESS + REALITY + Vision 公网栈与内部 NXR 跳转。 |
| [架构](architecture.md) | 连接生命周期、relay 后端、描述符预算和可观测性。 |
| [性能](performance.md) | 实测数据平面属性、ring AEAD 提供者和 D1–D11 决策登记。 |
| [v1.8 内存审计](../en/operations/memory-audit-v1.8.md) | 所有权映射、拷贝台账、分配台账与异步 future 尺寸，并明确列出未测量的内容（英文记录）。 |
| [性能调查记录](../en/operations/performance-investigation-record.md) | 已关闭性能调查的持久结论：控制路径台账、被否决的机制、历史吞吐问题（英文记录）。 |
| [冻结的评估器规范](../en/operations/frozen-evaluator-specification.md) | `cargo dev perf evaluate` 的方法学契约与被精确复现的旧语义（英文记录）。 |
| [模糊测试攻击面映射](../en/operations/fuzz-attack-surface.md) | 每个外部可达解析器对应的 fuzz 目标，以及已记录的缺口理由（英文记录）。 |
| [基准测试](benchmarks.md) | 测量策略、harness、规范样本、兼容性门禁和限制。 |
| [架构决策记录](../adr/README.md) | ADR，包括 io_uring 被移除的原因。 |

## 参与贡献

| 文档 | 用途 |
| --- | --- |
| [贡献指南](../../CONTRIBUTING.md) | 如何搭建环境、验证并合入一个变更。 |
| [仓库布局与变更路由](../en/development/repository-layout.md) | 每个目录负责什么，某类变更应放在哪里（英文记录）。 |
| [开发工作流](development/development-workflow.md) | 构建、`cargo dev` 工具、验证升级阶梯、GitHub 治理和 PR 规则。 |
| [测试](../en/development/testing.md) | 验证分层、聚焦运行和工具链门禁（英文记录）。 |
| [模糊测试](../en/development/fuzzing.md) | 攻击面覆盖、目标与命令（英文记录）。 |
| [工程宪法](../../AGENTS.md) | 面向贡献者和编码代理的规范性规则。 |

## 权威来源

命令语法和配置结构以二进制实际输出为准：

```shell
rust-reality --help
rust-reality COMMAND --help
rust-reality check -c config.json
```

每个 GitHub release 都附带一份供编辑器补全用的 JSON Schema，维护者可以用
`cargo dev config schema` 生成。
