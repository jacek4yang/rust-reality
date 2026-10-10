# 测试

本指南说明各验证层证明什么、应按何种顺序执行。验证升级规则位于
[开发工作流](development-workflow.md)。

## 生产测试层

- **单元及模块测试**与源代码放在一起（`src/**`、`crates/**`），验证协议、状态机
  和分配不变量。`src/protocol/reality/tls13/allocation_gate.rs` 验证稳定记录路径
  不分配内存；`crates/rr-session` 验证状态转换。
- **集成测试**位于 `tests/`，覆盖配置加载、服务生命周期及模块协作。
  `tests/layout_baseline.rs` 固定热点状态结构大小。
  同模块的 `server::production::reload_io` 回归还驱动真实生产 NXR 监听器：
  密钥发布时双向未读数据保持完整，已有连接继续逐字节传输，新连接使用新密钥认证。
  这属于回环热重载覆盖，不代表已覆盖 Handoff、网络隔离或独立内核。
- **架构边界测试**约束源代码依赖方向。`tests/transport_capability_boundary.rs`
  防止协议和会话语义绕过传输边界；`tests/protocol_core_boundary.rs` 保持协议
  核心独立于运行时、时钟和配置，参见 [ADR 0016](../../adr/0016-protocol-core-is-no-std-ready-but-stays-in-place.md)。
- **无默认功能测试**（`cargo test --workspace --no-default-features --locked`）
  验证 RustCrypto 后备构建保持相同的线路语义。
- **基准测试**位于 `benches/`，在 `cargo dev check --all` 中编译；参见
  [基准策略](../benchmarks.md)。
- **模糊测试**位于 `fuzz/fuzz_targets/`，覆盖外部可达解析、解码和重建路径；
  参见[模糊测试指南](../../en/development/fuzzing.md)。
- **Sanitizer** 由 Security workflow 执行，保留地址/泄漏检查。重放和传输并发回归仍由常规测试覆盖。
  移除 ThreadSanitizer 的明确取舍见 [ADR 0035](../../adr/0035-remove-thread-sanitizer-gate.md)。

## Actions 执行分工

CI 和 Security 提供日常回归反馈。原生资格验证运行真实进程与网络命名空间中的
互操作、压力恢复及连接生命周期测试；候选发布包验证实际分发产物。
QEMU 专项单独验证独立 guest 内核与受限 CPU/内存，不作为精细性能基准。

原生资格验证也支持显式 `workflow_dispatch`，绑定所选分支的精确 SHA，
包括最终合并后的 `main` 提交。完整资格任务和 600 秒连接矩阵检出相同 SHA。
PR head 的证据不能替代后续合并提交；发布前必须保留新的 exact-main 验证。
工作流进入默认分支后才可使用手动触发入口。

QEMU 在 `ready_for_review` 或显式 `workflow_dispatch` 时启动，不再随每次草稿推送
重跑。手动触发绑定所选分支的精确 SHA；新请求不取消已运行的 campaign。
结果不能替代另一 SHA 的验证：已进入评审的 PR 再有提交时，必须显式请求新 campaign。
缺失或跳过不算通过。在经过评审的替代方案覆盖相应义务前，既有 Tier B 合同仍然有效。
参见 [ADR 0036](../../adr/0036-separate-native-and-qemu-qualification.md)。

## 聚焦验证

```shell
cargo test -p rust-reality <test_name_substring> --locked
cargo nextest run -p rust-reality --locked
cargo test --workspace --locked
```

## 工具测试

`rr-dev` 拥有独立工具工作区。`cargo dev check` 在所有范围检查其格式和严格
clippy，在 `--all` 中执行完整工具测试。直接运行方式如下：

```shell
cargo test   --manifest-path tools/Cargo.toml --workspace --locked
cargo clippy --manifest-path tools/Cargo.toml --workspace --all-targets --all-features --locked -- -D warnings
```

资格门禁的 `run:` 步骤使用 bash-native Actions shell（[ADR 0044](../../adr/0044-signal-safe-gha-pipefail-shell.md)）：
`bash --noprofile --norc -e -o pipefail {0}`，避免 Python `KeyboardInterrupt`
堆栈淹没真实失败。类型化对等命令为 `cargo-dev ci gha-shell`；本地验证：
`cargo test --manifest-path tools/Cargo.toml -p rr-dev -- ci::`。

工具掌管基准、剖析和互操作验收，因此工具自身未经门禁验证的测量不能作为证据。
工具工作区曾在生产门禁之外漂移，导致 CLI 驱动、Xray 配置及格式检查失配。
两个工作区的依赖边界不代表质量边界。

## 不得削弱的要求

不得为使变更更容易而削弱或删除门禁、断言或 sanitizer 配置。若门禁本身存在
错误，应通过明确记录原因的评审变更修复，参见 [AGENTS.md](../../../AGENTS.md)。

## 离线稳定性证据

`/path/to/bundle/rr-dev bench stability-evaluate --evidence /path/to/bundle/evidence.json` 验证绑定
对象并按冻结的所有权契约判定。必须执行证据包指定的判定器二进制；相对对象路径
不得逃出证据包或经过符号链接。PASS 要求全部检查和用例通过；FAIL 表示已证实
的违例，NOT_RUN 表示缺失用例，INVALID 表示格式错误或证据不完整。
汇总结果优先标记 INVALID，但保留每项发现。
构建工具时，`RUST_REALITY_GIT_COMMIT` 必须设置为候选的精确来源提交。执行测试及
离线评估均拒绝来源提交不同的工具，即使契约内容相同。
必需检查的回执必须具有对应的语义验证器；退出码及不透明文件不能证明 PASS。
CI/Security 回执使用完整的
`gh run view RUN_ID --json headSha,workflowName,status,conclusion,databaseId,url,event`
响应。本地完整门禁使用 `check --all --output json`，保留各阶段 stdout/stderr 对象，
阶段列表必须与冻结工具一致。
生命周期检查绑定 `cargo test --lib --locked -- --color never` 的完整 stdout。
契约指定每个必需测试；忽略、缺失、重复或筛选用例均不能满足要求，最终计数必须
与实际观察到的测试结果一致。

解析器与纯判定器一起进行模糊测试。对抗测试覆盖泄漏套接字、脏管道或超量池、
缺失许可、临时资源和退役代际滞留、内存包络、载荷损坏、陈旧上传回执、采样缺失、
进程替换、二进制变化及无效数值。合成的判定器夹具仅为单元测试，不是验收证据。

契约在执行前固定负载开始时间、故障顺序和观察窗口；传输时间区间必须证明实际
达到指定并发。分区期间的进展及 RTT/丢包覆盖必须由故障生效期间的传输证明。
故障后的检查点（包括进程重启后）必须证明所有权恢复。重复使用原始观察、额外
未打开描述符的预留许可，以及超出峰值包络的内存高水位，均无法通过验证。

每次传输保留源载荷及收到的下载数据或前缀。离线验证逐字节比较数据，并从批次
开始前及结束后带哈希的源站访问日志快照重建 PUT 回执。日志前缀被改写、声明的
边界与保留快照不符、请求路径陈旧或重复、记录截断及载荷文件变更均会被拒绝。
代际发布历史必须从启动连续记录；遗漏发布或未知代际的退役事件使观察无效。

必需的 `native-resources` 检查引用原生持续测试生成的 `native-resources.json`。
离线验证会重新读取全部绑定的原始观察，核验启动策略、六个进程的身份、轮次覆盖、
固定恢复窗口以及各进程和汇总资源包络。短时集成测试的 PASS 不得替代必需的
30 分钟负载。来源、工具或契约替换、最终身份缺失及原始观察文件变更均会被拒绝。

验收时，debug 日志包含每秒的 `resource_ownership`、
`connection_task_ownership` 观察以及 `generation_retired` 事件。管道观察检查
保留管道的未读字节；检查失败会记录缺失值，不以零代替。这些观察并非分配器普查。
两种资源模式均在维护周期清理已过期 replay 占用，认证期限不变。

`cargo dev bench stability-observe --pid PID --log PATH` 在受控测试环境中采集
Linux 原始状态、比例内存、描述符目标、限制及完整调试日志，不向进程发送信号。
读取失败和采样中关闭的描述符会显式保留；中间读取失败后仍尝试最终进程及可执行
文件身份检查。每个归一化样本引用其原始观察，离线验证检查新鲜的所有权记录、
完整监听器任务集（包含已完成或取消的任务）、重放占用、代际退役、许可数量及
启动描述符清单。已接受的零字节套接字计入预认证许可及启动上限；准入计数器还
记录恢复时尚未结束的握手、回落、密码运算和 DNS 工作。声明的容量与期限必须
匹配实际运行的资源管理对象。这些观察不声称测量分配器字节清单。

固定运行时 Unix 套接字通过所选进程对应的内核 inode 记录与 TCP 区分，其数量
不得超过启动清单。采集器不保留命名空间内无关套接字的路径。采集器自身仍打开的
管道目标（fd > 2）会写入每次观察；与之匹配的子进程管道计入固定启动清单，而非
产品许可（[ADR 0045](../../adr/0045-collector-inherited-pipes-are-fixed-inventory.md)）。
产品管道与未知描述符仍保持失败关闭。可执行文件哈希使用发布工具相同的
`sha256sum`，避免调试构建的哈希开销占用采样窗口；哈希回执缺失或格式错误仍会
拒绝通过。

`cargo dev bench stability-fixture --fixture PATH --output FRESH_DIRECTORY`
启动已有且受控的三个 KVM 客体，检查客体 CPU、交换空间和进程身份，保留启动、
串口及终态收据，随后仅停止其拥有的子进程。`--constrained` 为 LANDING 选择
1 vCPU / 1 GiB。QEMU 临时磁盘快照保留原始客体磁盘；禁用 QMP/监视端点，SSH
仅通过回环地址使用固定主机密钥。这只是测试环境预检，不是候选版本资格认证，
输出明确将资格认证标记为 NOT RUN。

内部客体辅助进程拥有服务器、原版 Xray 客户端及源站子进程。它核验控制器提供的
客体启动身份与冻结可执行文件哈希，然后按契约的绝对时间表执行。采集不会移动
已错过的期限。重载、温/冷切换、陈旧池清理、LANDING 强制重启及数据接口 netem
操作保留操作回执和 netem 命令输出。重启核验被拥有进程的身份，并确认 SIGKILL
终止。启动或执行失败保留原始错误及最终观察的尝试。私密配置保留在受控测试环境
目录下，与证据包分离。

并发 8（每个 LINE 并发 4）的 RTT/丢包矩阵窗口为 90 秒，并在恢复前保留固定的
12 秒准入排空，使进行中的 1 MiB 传输能在故障区间内完成；其他故障及恢复阶段每个
LINE 并发 4，每个被测试的 LINE 至少完成 100 次传输。其他故障区间为 10 秒。方向完整性验证窗口
为 60 秒，随后恢复 180 秒。这些时间表在验收前固定于可执行契约，对受限资源的
LANDING 客体同样适用。
离线评估要求完整的方向验证检查点，包括最后一次传输后的所有权、内存及进程身份
恢复检查。原始 `/proc` 字段必须具有内核规定的单位及格式，仅有数字前缀无效。
产品启动前，控制器只同步受控快照客体的时钟并禁用其 NTP。前后时钟回执将客体
启动身份绑定到主机请求时间区间：偏差不超过 250 ms，往返不超过 500 ms，本地
墙钟与单调时钟漂移不超过 50 ms。采样在既有两秒期限内预留 350 ms 时钟不确定性。
缺失或偏斜的时钟使共享负载时间表无效；运行中不校正时钟。每次时钟交换前，
控制器先建立私有且受控的 SSH 控制连接，成功或失败后均关闭。认证耗时不计入
时钟不确定性，且绝不复用操作者的 SSH 连接。
VM 启动及终态回执必须与冻结身份匹配。前后内核观察绑定 CPU、内存、交换空间、
启动身份及 OOM 计数；完整产品日志绑定 LANDING 两次进程生命周期，并记录协议
拒绝或 panic。缺失结果或替换日志判为 INVALID。
每种故障要求三个客体均提供开始及结束操作回执。验证覆盖命令顺序及退出状态、
指定数据接口、实际安装及恢复的 netem 延迟/丢包、真实陈旧套接字清理、受控
SIGKILL 回执、稳定的温/冷配置哈希，以及期限内的重载发布记录。

VM 测试应使用冻结的 release 构建工具：
`RUST_REALITY_GIT_COMMIT=$(git rev-parse HEAD) cargo build --release --manifest-path tools/Cargo.toml -p rr-dev`，
然后以相同输入调用 `tools/target/release/rr-dev bench stability-run`。
执行期间，来宾绑定的物理核心及其 SMT 同胞线程不得运行其他编译或测试工作。

`cargo dev bench stability-run --fixture PATH --output FRESH_DIRECTORY
--candidate FROZEN_BINARY --xray XRAY_BINARY --openssl OPENSSL_BINARY` 执行四个
本地 VM 测试单元。要求工作区干净且提交与候选二进制内嵌提交一致，并保留来源、
契约、工具及可执行文件副本。每个压力周期先以指定并发数发送限速为 256 KiB/s 的
4 MiB 上传，随后完成每个 LINE 至少 100 次传输。回显探针保留跨故障边界实际收到
的精确前缀；方向探针包含同时运行的上传与下载。Curl 忽略用户配置与代理环境变量。
完成的客体观察也会流式写入有界的主机文件，最终取回失败时仍保留已采集数据，
且不在内存中保存无界副本。失败尝试保留部分测试单元、原始文件和终态。
VM 执行器不提供独立要求的原生、CI、安全或发布包检查回执；缺少这些回执时，
汇总资格认证仍为 NOT RUN。
VM 执行器退出后，使用 `cargo dev bench stability-check --evidence BUNDLE/evidence.json
--case local-full-gate` 收集权威本地门禁。`lifecycle` 运行未筛选的库测试，
绑定全部八项生命周期检查。`--case long-lived-connections` 运行被忽略的 600 秒
认证连接矩阵（SSE、WebSocket、单向静默、延迟响应、半关闭和写停滞）。未筛选的
生命周期运行只会把该测试标为 ignored，不能代替它。使用 `--case exact-head-ci --run-id ID` 和
`--case exact-head-security --run-id ID` 保留对应 GitHub 工作流回执。
必须从干净的冻结源码目录运行完全相同的冻结工具。每次尝试均保留命令、
所属子进程身份、原始 stdout/stderr、终态以及最终源码和可执行文件身份检查，
失败时也不例外。收集器串行更新汇总证据，并拒绝覆盖任何既有检查尝试。
完成后仍须单独离线评估整个证据包；收集成功本身不表示发布就绪。
同一收集器还使用冻结的候选程序、Xray 和 OpenSSL 副本执行 `native-interop`、
`native-mechanism`、`native-descriptor-pressure` 和 `native-resources`。
命令固定既有套件参数、保留嵌套的原始观测，并拒绝缩短原生测试时长或恢复覆盖。
这些独占主机的负载必须在 VM 活动释放主机锁后执行。
原生互操作性凭据保留源载荷、实际下载字节和 OpenSSL 握手跟踪。离线校验
核对字节完全一致、服务端未发送 CCS、固定的外部可执行文件及规定的 stock-Xray
命令；仅有声称成功的摘要不能通过。
描述符压力凭据必须使用固定的 192 描述符上限、96 连接填充上限和 12 连接突发。
离线校验重建启动预算及 high→normal 转换，核对 4-KiB 控制回显与 64-KiB
恢复回显；缺少原始日志或字节时拒绝通过。中断回显保留实际收到的前缀和原始失败。
原生机制凭据必须通过既有 netem 校验器，从绑定的原始文件重建已审定的
50/100/200 ms、零丢包、并发 1 矩阵。校验器核对来源、工具和可执行文件身份、
完整发布链及最终身份检查。迁移后的原始路径只能通过保留的工件绑定解析；
缺少样本、替换文件或与重算结果不符的 PASS 均不能通过。WAN 校验继续使用
独立的既有工作流及验收规则。
四个发布包检查均要求[发布流程](../release-process.md)所述的原生执行证据。
离线校验拒绝缺失命令、镜像变化、错误层级、仿真以及归档／二进制替换。

## 发布反馈闭环

发布门禁通过表示既定检查在该候选提交上全部通过，不保证所有部署环境都没有缺陷。
GitHub Actions 可以承载所需的原生和 QEMU 环境，但必须保留源码、二进制身份及
可验证凭据；改在 Actions 执行不代表省略必需场景或改变验收契约。

应区分确定性的状态机与所有权测试、短时真实协议集成、安全检测和完整多节点验收。
采集器问题先用短测试复现，再运行完整长测。动态 FD 扫描与另一个时刻的计数发生
竞态属于证据不完整，既不能据此认定产品泄漏，也不能视为测试通过。
不得反复重跑到绿或静默丢弃失败样本。

用户通过仓库的发布版本问题表单报告回归，填写版本及安装包、环境、脱敏拓扑、
最小复现和带时间的异常。维护者区分产品缺陷、测量缺陷及环境失败，保留原始证据，
修复时添加聚焦回归测试，再执行受影响的门禁。大体积轨迹使用有保留期限的外部产物，
不写入 Git；不得公开凭据或隐私流量。安全问题遵循 `SECURITY.md`。

## 候选发布包执行验证

PR 的 `Candidate packages` workflow 检出精确 head，从 `cargo dev release matrix`
取得四档矩阵，复用现有构建、打包、冒烟和汇总命令。每档在匹配架构的原生 runner
上执行测试及包内二进制；x86_64 musl 包在 x86_64 Linux 上运行。
产物名称包含候选 SHA，保留七天。包版本取自 Cargo metadata，不创建 Git 标签，
也没有发布 Release 的权限。通过此检查证明包的执行能力，不代表其他协议及资源
验收通过，也不代表获得正式发布授权。

陈旧连接故障注入产生的认证拒绝，只能依据已验证的故障动作回执归类：必须匹配
被断开的精确对端、LANDING 启动身份与角色、成功执行的固定 `ss -K` 命令及其
实际起止时间。每个被断开的连接，在全部保留的进程日志中最多解释一次匹配的
认证事件。其他对端、原因、时间、重复事件、准入限制和配置拒绝仍视为非预期。
此归类不会改写原始日志或历史判定。

主动重启 LANDING 时，LINE-A 在其公网监听端口（夹具端口 9444）记录唯一已建立回环入口连接，
并通过数据面 ACK（`rr-restart-census-ack/v1`，`192.0.2.2:19501`）将该对端发布给 LANDING。
LANDING 仅在接受恰好一条匹配 ACK 之后才中止。正确性来自握手，而不是挂钟 sleep。
只有该精确对端的 Handoff 中继 EPIPE，发生在已验证的 ACK 与入口普查之后、
完整接收前缀所记录的失败时刻加现有时钟保护界限之前，才可归类为一次注入事件。
缺失或不唯一的连接观测、缺失/重复/错误 ACK、其他对端、阶段、原因、错误码、重复错误及窗口外错误
仍会阻止验收。这只为测试夹具增加观测，不修改生产日志或生产行为。

可在数分钟内、无需四单元 QEMU 复现 landing-restart 普查/ACK 契约：

```shell
cargo dev bench stability-repro --fault landing-restart --output FRESH_DIRECTORY
```

重启后的恢复准入会等到第一个故障检查点窗口关闭
（[ADR 0043](../../adr/0043-landing-restart-baseline-before-recovery.md)），以便空闲的
替换后 LANDING 在恢复冲击开始前给出稳定的描述符普查。

该命令保留动作回执与 Class A/B/C 的 `diagnosis.json`。合法回执通过；历史空普查与
ACK 早于普查的形状以 Class B 夹具缺陷 fail-closed。 同一套 Class 标签也会写入每单元 `cell-diagnosis.json`、`cells-summary.json` 与合并后的 `merge-diagnosis.json`，使 fail-closed 的 QEMU 运行能在数分钟内区分夹具、基础设施与产品缺陷，而不是变成数小时后的模糊 INVALID。托管资格将四个单元作为 Actions matrix 并行（每 runner 一个单元），再经 `cargo dev bench stability-merge-cells` 做身份绑定聚合（[ADR 0042](../../adr/0042-four-cell-qemu-matrix-parallelism.md)）；普通 runner 仍在 `HostLock` 与固定 fixture 端口下保留单个单元的 vCPU 亲和预算。`stability-run` 可用重复的 `--cell NAME` 只跑子集；子集跑完后必须先 merge 再做离线 Pass 裁决。

故障批次在契约规定的边界软停止准入（普通故障为恢复时刻；RTT/丢包为恢复前的
排空时刻）。到达该边界属于计划内终止，不是传输失败。已提交的尝试及部分结果仍
保留；覆盖不足或在途请求超出规定窗口完成仍会失败，不会把恢复之后发起的请求悄
悄归入故障期。
