# 文档索引

[English](../en/index.md) | 简体中文

## 运维指南

| 文档 | 用途 |
| --- | --- |
| [快速上手](getting-started.md) | 下载、验证、最小配置和第一条隧道。 |
| [命令行参考](cli.md) | 全部命令、选项、默认值、输出、信号和退出行为。 |
| [配置参考](configuration.md) | 全部 JSON 字段、变体、默认值、验证边界、路由匹配器和热更新规则。 |
| [Linux 部署](deployment.md) | Release 验证、单机与线路机/落地机、systemd、防火墙、文件和升级。 |
| [工程与发布流程](release-process.md) | 证据分层、PR/tag 生命周期、精确候选、VPS canary、回滚和 v1.7→v2.0 发布列车。 |
| [容量规划与调优](tuning.md) | 机型档位、资源参数、伪装目标选择和延迟/吞吐诊断。 |
| [威胁模型](threat-model.md) | 安全目标、信任边界、NXR 限制、资源控制和非目标。 |
| [安全策略](security.md) | 支持版本和私密漏洞报告。 |

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
rust-reality schema > rust-reality.schema.json
rust-reality check --config config.json
```

JSON Schema 描述结构类型；`check` 还会执行配置参考中记录的跨字段、引用、
安全和资源限制验证。
