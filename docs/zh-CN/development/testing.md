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

验收时，debug 日志包含每秒的 `resource_ownership`、
`connection_task_ownership` 观察以及 `generation_retired` 事件。管道观察检查
保留管道的未读字节；检查失败会记录缺失值，不以零代替。这些观察并非分配器普查。
两种资源模式均在维护周期清理已过期 replay 占用，认证期限不变。
