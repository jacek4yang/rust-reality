# 测试

本指南说明各验证层证明什么、应按何种顺序执行。验证升级规则位于
[开发工作流](development-workflow.md)。

## 生产测试层

- **单元及模块测试**与源代码放在一起（`src/**`、`crates/**`），验证协议、状态机
  和分配不变量。`src/protocol/reality/tls13/allocation_gate.rs` 验证稳定记录路径
  不分配内存；`crates/rr-session` 验证状态转换。
- **集成测试**位于 `tests/`，覆盖配置加载、服务生命周期及模块协作。
  `tests/layout_baseline.rs` 固定热点状态结构大小。
- **架构边界测试**约束源代码依赖方向。`tests/transport_capability_boundary.rs`
  防止协议和会话语义绕过传输边界；`tests/protocol_core_boundary.rs` 保持协议
  核心独立于运行时、时钟和配置，参见 [ADR 0016](../../adr/0016-protocol-core-is-no-std-ready-but-stays-in-place.md)。
- **无默认功能测试**（`cargo test --workspace --no-default-features --locked`）
  验证 RustCrypto 后备构建保持相同的线路语义。
- **基准测试**位于 `benches/`，在 `cargo dev check --all` 中编译；参见
  [基准策略](../benchmarks.md)。
- **模糊测试**位于 `fuzz/fuzz_targets/`，覆盖外部可达解析、解码和重建路径；
  参见[模糊测试指南](../../en/development/fuzzing.md)。
- **Sanitizer** 由 Security workflow 执行，包括地址/泄漏检查以及 replay 和
  warm-transport 的竞态检查。

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

工具掌管基准、剖析和互操作验收，因此工具自身未经门禁验证的测量不能作为证据。
工具工作区曾在生产门禁之外漂移，导致 CLI 驱动、Xray 配置及格式检查失配。
两个工作区的依赖边界不代表质量边界。

## 不得削弱的要求

不得为使变更更容易而削弱或删除门禁、断言或 sanitizer 配置。若门禁本身存在
错误，应通过明确记录原因的评审变更修复，参见 [AGENTS.md](../../../AGENTS.md)。

## 离线稳定性证据

`cargo dev bench stability-evaluate --evidence /path/to/evidence.json` 验证绑定
对象并按冻结的所有权契约判定。必须执行证据包指定的判定器二进制；相对对象路径
不得逃出证据包或经过符号链接。PASS 要求全部检查和用例通过；FAIL 表示已证实
的违例，NOT_RUN 表示缺失用例，INVALID 表示格式错误或证据不完整。
汇总结果优先标记 INVALID，但保留每项发现。

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
不得超过启动清单。采集器不保留命名空间内无关套接字的路径。可执行文件哈希使用
发布工具相同的 `sha256sum`，避免调试构建的哈希开销占用采样窗口；哈希回执缺失
或格式错误仍会拒绝通过。

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
终止。启动或执行失败保留原始错误及最终观察的尝试。私密配置与取回的证据目录
分别暂存。

并发 4 的 RTT/丢包矩阵窗口为 60 秒，其他故障区间为 10 秒。方向完整性验证窗口
为 60 秒，随后恢复 180 秒。这些时间表在验收前固定于可执行契约，对受限资源的
LANDING 客体同样适用。
