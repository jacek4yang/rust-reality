# 文档索引

[English](index.md) | 简体中文

## 运维指南

| 文档 | 用途 |
| --- | --- |
| [命令行参考](cli.zh-CN.md) | 全部命令、选项、默认值、输出、信号和退出行为。 |
| [配置参考](configuration.zh-CN.md) | 全部 JSON 字段、变体、默认值、验证边界、路由匹配器和热更新规则。 |
| [Linux 部署](deployment.zh-CN.md) | Release 验证、单机与线路机/落地机、systemd、防火墙、文件和升级。 |
| [威胁模型](threat-model.zh-CN.md) | 安全目标、信任边界、NXR 限制、资源控制和非目标。 |
| [基准策略](benchmarks.zh-CN.md) | 可复现测量、已有基线和结果解释边界。 |
| [安全策略](../SECURITY.zh-CN.md) | 支持版本和私密漏洞报告。 |

## 工程证据

以下文档保留设计和兼容性证据。为保证命令、线协议名称和审计引用与原始材料
完全一致，目前采用英文：

- [Xray 26.7.28 互操作测试](testing/xray-26.7.28-interop.md)
- [`rust-reality.7z` 复用审计](audits/rust-reality-7z.md)
- [架构决策记录](decisions/)

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
