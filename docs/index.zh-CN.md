# 文档索引

[English](index.md) | 简体中文

## 运维指南

| 文档 | 用途 |
| --- | --- |
| [快速上手](getting-started.zh-CN.md) | 下载、验证、最小配置和第一条隧道。 |
| [命令行参考](cli.zh-CN.md) | 全部命令、选项、默认值、输出、信号和退出行为。 |
| [配置参考](configuration.zh-CN.md) | 全部 JSON 字段、变体、默认值、验证边界、路由匹配器和热更新规则。 |
| [Linux 部署](deployment.zh-CN.md) | Release 验证、单机与线路机/落地机、systemd、防火墙、文件和升级。 |
| [工程与发布流程](release-process.zh-CN.md) | 证据分层、PR/tag 生命周期、精确候选、VPS canary、回滚和 v1.7→v2.0 发布列车。 |
| [容量规划与调优](tuning.zh-CN.md) | 机型档位、资源参数、伪装目标选择和延迟/吞吐诊断。 |
| [威胁模型](threat-model.zh-CN.md) | 安全目标、信任边界、NXR 限制、资源控制和非目标。 |
| [安全策略](zh-CN/security.md) | 支持版本和私密漏洞报告。 |

## 设计与证据

| 文档 | 用途 |
| --- | --- |
| [协议概览](protocol.zh-CN.md) | VLESS + REALITY + Vision 公网栈与内部 NXR 跳转。 |
| [架构](architecture.zh-CN.md) | 连接生命周期、relay 后端、描述符预算和可观测性。 |
| [性能](performance.zh-CN.md) | 实测数据平面属性、ring AEAD 提供者和 D1–D11 决策登记。 |
| [v1.8 内存审计](memory-audit-v1.8.md) | 所有权映射、拷贝台账、分配台账与异步 future 尺寸，并明确列出未测量的内容（英文记录）。 |
| [基准测试](benchmarks.zh-CN.md) | 测量策略、harness、规范样本、兼容性门禁和限制。 |
| [架构决策记录](decisions/) | ADR，包括 io_uring 被移除的原因。 |

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
