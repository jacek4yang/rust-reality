# 工程与发布流程

[English](../en/release-process.md) | 简体中文

本文定义 v1.7 到 v2.0 的可执行发布程序。仓库实际状态、GitHub 必需检查以及精确
候选二进制证据高于路线图估计；发布时间不能凌驾于协议正确性、安全性和受保护
性能路径。

## 分层证据

| 层级 | 阻塞发布 | 时间预算 | 回答的问题 |
| --- | --- | --- | --- |
| A — 聚焦形式门禁 | 是 | 约 10–20 分钟 | 精确生产二进制是否实现目标机制、保持完整性且未回退受保护路径？ |
| B — 双 VPS 主动 canary | 是 | 约 10 分钟 | 精确候选能否在真实 WAN 部署，承受 churn、reload、LANDING 重启并回收资源？ |
| C — 长期 soak | 否 | 数小时或整夜 | 长期运行是否暴露保持性或罕见网络问题？ |

C 层可用于 nightly、发布后监控或泄漏调查，但不再是发布前置条件，也不能阻塞
下一 worktree。十分钟 canary 只能表述为高密度生命周期证据，不能宣称证明长期
绝无泄漏。每份证据保留 commit、二进制 SHA-256、ELF Build ID、版本、rustc、
target、features、主机、内核、负载、原始样本和完整性结果；证据按实际代码依赖
失效，而不是机械重跑一切。

## v1.7 执行顺序

1. 只读复核 Git、GitHub PR/check/release、worktree 与两台 SSH 主机。
2. 在聚焦分支完成单元/性质、重放、资源、reload、fuzz、sanitizer、主动探测、
   stock Xray 与打包门禁。
3. 以生产构建的平衡 ABBA 50/100/200 ms Handoff/NXR/SOCKS5 cold/warm 作为
   正式机制门禁；1/10 ms 是诊断证据。庞大笛卡尔矩阵不阻塞发布。
4. 自审 socket 单属主、完整认证写后不重试、重试状态全新、FD permit 生命周期、
   generation/credential 隔离、冷回退不受投机 backoff 阻塞，以及认证前无目的地
   副作用。
5. 用 `gh pr edit/ready/checks/merge` 更新证据并在精确 CI 绿色后合并。
6. 从新 main 创建 release 分支，更新版本、锁文件、CHANGELOG、中英文文档与证据，
   经 release PR 合并后建立不可变 worktree 和精确候选。

## 永久 LINE 部署模型

`rust-reality-vps` 是日常节点。22 是永久 SSH 基础设施，443 是唯一公网代理端口。
二进制代际位于 `/opt/rust-reality/releases/`，root 管理的兼容配置代际位于
`/etc/rust-reality/releases/`；`current` 选择运行代际，`previous` 选择唯一已验证
回滚代际。

REALITY/VLESS 身份是持久部署状态。正常升级必须保持密钥对应关系、UUID、short
ID、SNI/target、flow、endpoint、routing 与 outbound 语义。配置秘密不得打印
或进入公开工件；迁移前后用 `cargo dev config fingerprint` 只比较指纹。

首次迁移先复制已知良好二进制和兼容配置作为最小回滚包。`cargo dev deploy
inspect` 与 `cargo dev deploy plan` 只读；`cargo dev deploy apply` 没有显式
`--mutate-remote` 会拒绝执行。`apply stage` 在不切换 CURRENT 的情况下验证版本、
SHA、`check` 和 `self-test`；`apply cutover` 先准备 PREVIOUS，再以最短
stop/symlink/start 窗口切换，
验证二进制与 443，并拒绝切换期间新出现的非预期 wildcard TCP 监听。主机原有的
无关监听仍由主机管理员负责，部署工具不会擅自停止；启动或监听策略健康失败会
自动恢复旧代际。后续互操作或 canary 失败执行 `rollback`。`promote` 只保留
CURRENT 与 PREVIOUS；裁剪软件代际永远不能删除持久身份。

## 双 VPS 主动 canary

LANDING 的 443 只允许 LINE 公网 IPv4 `/32`，22 永不改变；origin 仅监听 loopback。
主拓扑为：

```text
stock Xray client -> LINE:443 -> warm Handoff -> LANDING:443 -> loopback origin
```

约十分钟内执行基线、steady 流量、高连接 churn、有界 burst 与恢复、warm
idle/stale 轮换、LINE reload、LANDING 服务受控重启与恢复、1 MiB 及更大下载/
上传/双向逐字节完整性、最后稳态回收。指标通过 SSH 获取，不开放公网指标端口。

`cargo dev deploy canary-plan` 不接触主机即可校验并记录完整输入；相同输入交给
`cargo dev deploy canary-run --mutate-remote` 执行，报告再由 fail-closed 的
`cargo dev deploy canary` 评估器验收。该合约必须有精确候选身份、两端 SSH、
端口/防火墙限制、stock Xray、完整性、warm Handoff、故意触发的 cold fallback、
generation 退休、LANDING 恢复、至少 500 次有界连接、pool 上界、无系统性落地机
拒绝 churn，以及可恢复的 FD/thread/RSS 包络。FD 门禁使用经评审的绝对上界，
并计入有界可复用 splice pipe pool，不会把预热后的进程与未负载起点做错误
比较。受控 LANDING restart 可以产生少量、有上界的 outbound failure，但不允许任何
authentication/protocol rejection。短 canary 不外推 MiB/hour；RSS 无需逐字节回到起点。
NXR 在同一 LANDING 443 上顺序做短补充验证，之后恢复预期日常配置。

## 标签、官方产物与回滚

精确 main 的 A/B 层通过后创建 annotated tag，推送并以 `gh run watch` 监控现有
全有或全无 workflow。验证 tag commit、完整矩阵、`SHA256SUMS`、
`release-manifest.json`、generic/musl smoke 与 aarch64 策略。下载校验官方产物，
以它替换预发布候选，再做一次兼容/完整性 smoke；成功后留在日常节点运行。失败则
恢复 PREVIOUS 并通过适当 patch release 向前修复。

## v1.8 到 v2.0

长期监控运行时在独立 worktree 推进 v1.8。先冻结 v1.7 的耦合、buffer 属主、copy、
allocation、future 大小、syscall、PMU、assembly 和结构大小基线，再用多个小 PR
抽取 codec/state、重试与不可逆边界、REALITY/VLESS/Vision 编排、Tokio Runtime
Adapter，并删除重复逻辑。Session Engine 不依赖 Tokio、`TcpStream`、fd 或 OS
调度；一次性 `RawRelayGrant` 把已认证 socket 交给现有 relay，语义抽象不进入逐块
数据路径。每个 PR 必须性能中性或更好，并增加语义状态机 fuzz。

v1.9 增加窄范围官方客户端；EarlyPrepare 必须先有独立 ADR，只携带有界加密请求
元数据，ClientFinished 仍是副作用屏障，stock Xray 始终兼容。v1.10 以后以 ABBA、
PMU、syscall/copy ledger 优化缓存、分配、future、指标争用和系统调用。io_uring、
send-zc、AF_XDP 只在隔离实验中验证，失败实验删除且默认部署不增加权限。

v2.0 必须代表 runtime-independent Session Engine、显式 Runtime Adapter/Transport、
大量 core/alloc 兼容纯逻辑、受支持客户端、经证明才启用的 EarlyPrepare、成熟 fuzz、
有界资源、stock Xray 互操作，以及逐路径 allocation/copy/syscall/cache/CPU/延迟审计；
发布次数本身不是 v2.0 的理由。
