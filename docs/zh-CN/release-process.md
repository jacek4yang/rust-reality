# 工程与发布流程

[English](../en/release-process.md) | 简体中文

本文定义 v1.7 到 v2.0 的可执行发布程序。仓库实际状态、GitHub 必需检查以及精确
候选二进制证据高于路线图估计；发布时间不能凌驾于协议正确性、安全性和受保护
性能路径。

v2 二进制升级期间，生产配置字节、身份、路由、systemd 语义、SSH 别名、防火墙和
云网络策略均保持不变。使用现有代际目录；即使官方产物替换候选，也保留升级前的
回滚二进制。配置拒绝属于软件兼容性缺陷，不授权改写管理员的配置文件。
有限的 v1.8 Handoff/direct 输入与 `serve --config` 调用见
[ADR 0027](../adr/0027-preserve-the-existing-v18-handoff-landing.md)。

## 分层证据

| 层级 | 阻塞发布 | 时间预算 | 回答的问题 |
| --- | --- | --- | --- |
| A — 聚焦形式门禁 | 是 | 约 10–20 分钟 | 精确生产二进制是否实现目标机制、保持完整性且未回退受保护路径？ |
| B — 压力与隔离多节点资格验证 | 是 | 有界工作量与明确故障用例 | 精确候选在重复负载、reload、分区和重启下是否保持完整性并回收有界资源？QEMU 系统虚拟机可以达标。 |
| C — 长期 soak | 否 | 数小时或整夜 | 长期运行是否暴露保持性或罕见网络问题？ |

B 层可以完全在隔离的 QEMU 系统虚拟机中完成；发布不再要求具备真实双 VPS。
真实 WAN canary 单独作为部署证据。C 层仍可用于 nightly、发布后监控或针对性调查，
但发布不要求额外的数小时、整夜或多日 soak。已有必需的原生检查不能因为被称为
soak 就被跳过或改为可选。

压力压缩的是操作次数，不是时间。提高并发不能证明一个月的 uptime，不能触发
尚未经过的定时边界，也不能凭空复现真实 WAN。时间相关边界需要确定性测试；
未覆盖的日历、内核和网络行为必须明确披露。决策依据见
[ADR 0033](../adr/0033-stress-and-virtual-machines-qualify-releases.md)。

每份证据保留 commit、二进制 SHA-256、ELF Build ID、版本、rustc、target、features、
主机、内核、负载、原始样本和完整性结果。传输源码变化重跑传输与多节点验证；
仅文档变化不使不可变传输二进制的证据失效；打包变化重跑包与官方产物 smoke。

### B 层：压力与隔离多节点资格验证

以下是发布验收合约；启动虚拟机或完成一次吞吐测试并不足以达标：

1. **身份与隔离。** 使用不可变发布候选及固定版本的 stock Xray。记录二进制哈希、
   build identity、fixture/controller/evaluator 源码哈希、命令、guest 镜像、
   加速模式、内核、不同的 boot ID、CPU/RAM/swap 限额及网络拓扑。使用两个 LINE
   guest 和一个 LANDING guest，各有独立内核；user-mode QEMU 或同一 guest 内的
   三个进程不等价。主机端口转发仅绑定 loopback；故障只影响自有 guest 链路，
   不修改主机或生产网络。
2. **互操作与资源压力。** 保留现有精确候选原生互操作、机制和描述符压力门禁，
   合约不变。两条 LINE 都通过 stock Xray 覆盖 Handoff 与 NXR。除常规多 worker
   场景外，加入 1 vCPU/1 GiB LANDING 的资源与恢复场景。不得出现 OOM、panic、
   非预期进程退出、认证/协议回退或字节损坏。
3. **重复有限压力。** 每种拓扑至少完成八个负载／排空／恢复循环，期间不得重启
   daemon。每轮每条 LINE 至少完成 100 次认证传输，覆盖并发 8 与 32、稳态和
   burst。记录尝试、成功操作、字节、错误和静默恢复检查点，而不只记录耗时。
   非故障传输必须全部成功。允许有界容量保持；不接受恢复后仍无法解释的活资源增长。
4. **生命周期与故障矩阵。** LINE reload 期间保持双向流进展，证明旧 generation
   退休和新连接准入。覆盖 warm reuse、stale retirement 与 cold fallback。
   杀死／重启 LANDING；隔离 LINE-A 数据链路 10 秒，同时证明 LINE-B 正常进展；
   覆盖 50/100/200 ms RTT 及 100 ms/1% 丢包。每次故障恢复后，首次新准入必须在
   已声明恢复上界内成功，随后连续 100 次新传输成功，且每次均在 deadline 内。
   杀死进程不要求保住旧 TCP 流，但已接收前缀必须逐字节正确。每次诱发失败必须
   计数并绑定故障时间窗；不得接受 authentication/protocol rejection，或把重启循环
   伪装成恢复。
5. **完整性与资源。** 对 1 MiB 及更大载荷的下载、上传和并发双向传输验证精确
   字节/SHA-256；上传回执必须是本次唯一路径的新追加记录。每个角色至少保留
   12 个绑定身份的资源样本，覆盖基线、负载、峰值与恢复；每轮压力恢复都采样，
   不允许替换 PID。恢复后的 LANDING 描述符和内存生命周期证据采用冻结的
   [所有权契约](../../benchmarks/contracts/stability.json) 及
   [ADR 0034](../adr/0034-qualify-resource-ownership-and-lifetime.md)。保留 LINE FD
   768/2,048、LANDING 峰值 FD 1,024、线程基线 +8/+16、RSS 基线 +32/+96 MiB。
   记录 PSS、匿名内存与
   进程启动时间用于归因。RSS 不必逐字节回到起点，不能仅凭驻留量判断泄漏，
   也不能把短测试外推为一个月的内存预测。
6. **时间边界。** 保留相关 replay/TTL、generation/credential 退休、共享不活动、
   write-stall、half-close 与取消合约的确定性测试。在支持处使用显式时间输入
   或受控测试 runtime 时钟；不得缩短生产 deadline、在产品生命周期内调整时钟，
   或用更多连接次数替代这些测试。启动前的客体时钟校准用于绑定主机时间表，
   不得加速任何生产期限。
7. **可审查判定。** 保留全部用例及失败、原始样本、完整性回执和按上述条件执行的
   fail-closed 审计。fixture 与 evaluator 源码必须可审查且经过验证；手写 success
   Boolean 不是证据。缺失用例仍标记未执行。范围使用 `LOCAL_QEMU` 或 `LOCAL_KVM`，
   不得标为 `dual-vps-active-release-canary`。发布 PR 必须列出精确证据并记录审查者
   的验收。

仓库拥有的部分使用 `cargo dev perf freeze`、`cargo dev check --all`、
`cargo dev bench run --suite no-ccs-interop`、带 `--deployment-plan mechanism`
的 `--suite deployment`，以及 `--suite descriptor-pressure`；传入同一个冻结
`--rust-bin` 与固定 reference 二进制。VM fixture 补充 guest 隔离与故障／压力用例，
不能替代这些命令。现有 `cargo dev deploy canary` 评估器仍专属于 WAN；不得伪造
SSH/防火墙断言，把本地运行包装成 VPS 运行。

每个受支持层级打包后，运行
`cargo dev release smoke TAG TIER ASSETS --receipt-dir FRESH_DIRECTORY` 保留绑定
发布包的执行证明；该目录应放在待汇总的资产目录之外。证据包含归档、实际执行
的二进制、工具、层级元数据、主机 CPU 观察及严格的 `receipt.json`。命令保留
进程身份、退出状态和输出哈希；生成的密钥与凭据只用于私有临时配置，不写入回执。
失败仍保留已有观察及最终归档／二进制／工具身份核验的尝试。稳定性离线校验核对
全部七个命令、原生主机架构、精确层级元数据及绑定归档中的二进制。GNU 包的
二进制必须与 VM 测试候选完全相同，其余层级绑定同一来源。仿真 smoke 仅证明
功能，不能满足原生发布包资格认证。候选包标签不会创建 Git tag 或授权发布。

## v1.7 执行顺序

1. 只读复核 Git、GitHub PR/check/release 与 worktree；发布本身不需要生产 SSH 连接。
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

本节和后续双 VPS canary 仅用于独立授权的真实部署；B 层在 QEMU 中达标后，
它们不再是额外的发布前提。仓库审查／合并、tag／发布和生产主机操作的授权
彼此独立。部署前才检查两个逻辑 SSH 角色及服务、二进制／配置哈希、监听、
用户、限额与防火墙；不得公开秘密。未知或异常服务阻止部署，但不阻止独立本地
验证，也不授权盲目修复。真实 WAN 报告与 gate identity 必须与本地 VM 证据分开。

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
SHA、`check` 和 `doctor`；`apply cutover` 先准备 PREVIOUS，再以最短
stop/symlink/start 窗口切换，
验证二进制与 443，并拒绝切换期间新出现的非预期 wildcard TCP 监听。主机原有的
无关监听仍由主机管理员负责，部署工具不会擅自停止；启动或监听策略健康失败会
自动恢复旧代际。后续互操作或 canary 失败执行 `rollback`。`promote` 记录验收；
可选裁剪是独立操作，不得删除升级前保留的回滚版本或持久身份。

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
如果切换协议模式需要修改生产配置，应在本地完成该补充测试。

实际生产拓扑由已确认的配置决定。如果公网 LINE 使用 SOCKS5 而非 Handoff，必须
如实报告，不能为了符合上图改动用户、凭据或路由。验证原有公网路径，同时以明确
授权、单独标注的补充测试使用 LINE 上仅监听 loopback 的入口连接现有限制访问的
LANDING:443。这证明真实 WAN 链路，不代表公网 LINE 监听器使用 Handoff。
不允许临时 wildcard/公网监听。历史 v1.8 补充证据中的配置改动属于当时的授权，
不能作为本次 v2 二进制升级修改配置的依据。

使用 `--line-baseline` 和 `--landing-baseline` 传入**切换前**由原生 inventory
保存的快照。canary 在流量开始前和恢复后，对照快照比较 wildcard 地址/端口对：
保留无关的已有监听，新增监听或地址族则失败。恢复后再次检查 LANDING TCP/443
防火墙限制。

补充 Handoff 使用 canonical LINE alias 上单独暂存的
`rust-reality-canary-<name>.service`，运行候选二进制并仅监听一个 loopback 端口。
同时传入 `--supplemental-line-service`、`--supplemental-line-port`、
`--public-socks-port`、`--public-url`、`--public-payload`。stock-Xray 配置必须有两个
明确绑定 loopback 的 SOCKS inbound，分别路由到补充入口（通过 SSH loopback
forward）及原有公网 LINE endpoint。不得替换 host alias、公网服务 unit 或路由配置。
runner 验证补充进程仅持有声明的 loopback 监听，reload 两个 LINE 进程，并在启动、
每个阶段及最终恢复时校验公网下载内容。报告明确标注拓扑，公网 LINE 与补充 LINE
分别采样，使用相同的已评审 LINE 资源上界。自动回滚仍作用于生产 generation；
测试结束后删除临时补充 unit 和 SSH forward。

loopback origin 使用 `cargo dev bench origin --access-log PATH`，通过
`--origin-access-log` 传入远端日志路径。one-MiB payload 必须恰好一 MiB，large
payload 必须更大。下载、上传和并发双向检查要求内容/SHA-256 精确一致。上传回执
必须是新追加的记录，并匹配本次运行唯一 PUT 路径、长度和摘要；旧回执或仅长度
相同不能证明完整性。

## 标签、官方产物与回滚

精确 main 的 A/B 层通过后创建 annotated tag，推送并以 `gh run watch` 监控现有
全有或全无 workflow。验证 tag commit、完整矩阵、`SHA256SUMS`、
`release-manifest.json`、generic/musl smoke 与 aarch64 策略。下载校验官方产物，
在已验证的隔离环境中重复兼容／完整性 smoke。发布本身不要求生产部署。
对于另行授权的真实 rollout，以官方产物替换候选，重复部署 canary 并保留 PREVIOUS；
部署失败恢复 PREVIOUS，通过适当 patch release 向前修复。

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
