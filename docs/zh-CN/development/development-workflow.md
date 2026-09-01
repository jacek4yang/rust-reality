# 开发工作流

[English](../../en/development/development-workflow.md) | 简体中文

本文说明如何构建、验证并合入变更。仓库布局和变更路由见
[repository-layout.md（英文）](../../en/development/repository-layout.md)；对人工贡献者和
代理都具有约束力的规范见 [AGENTS.md](../../../AGENTS.md)。

## 工具链

使用 [`rust-toolchain.toml`](../../../rust-toolchain.toml) 固定的工具链。
规范的开发者入口是 `cargo dev`（独立 `tools/` 工作区中的 `rr-dev` 二进制，
通过根目录 Cargo alias 暴露）：

```shell
cargo dev --help        # 查看命令组
cargo dev doctor        # 诊断开发/测量环境
```

命令组包括：`doctor`、`check`、`docs`、`repo`、`perf`、`release`、
`fuzz`、`config`、`bench`、`deploy`。运行 `cargo dev <group> --help`
查看详细说明。

## 构建

```shell
cargo build --locked                    # 生产工作区（根 package + crates/）
cargo build -p rr-dev --manifest-path tools/rr-dev/Cargo.toml --locked   # 工具
cargo build --release --locked          # release profile（thin LTO，codegen-units=1）
```

## 验证升级阶梯

验证深度应与变更匹配。不要在每次编辑后都运行完整门禁；也绝不能仅凭聚焦测试
合入变更。

1. **编辑期间：** 聚焦单元/模块测试
   （`cargo test -p rust-reality <module>` 或对应的 rr-dev 命令）。
2. **完成一个连贯切片后：** 受影响 package 的测试套件和严格 Clippy
   （`cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`）。
3. **PR 转为 ready 前：** 文档变更运行 `cargo dev docs check`，布局变更运行
   `cargo dev repo check`，并运行相关集成测试。
4. **合入前——完整权威门禁：**

```shell
cargo dev check --all
cargo test --workspace --no-default-features --locked
git diff --check
```

`cargo dev check --all` 会运行仓库门禁：仓库布局与文档策略检查、
`cargo fmt --all --check`、严格 Clippy、`cargo deny`、将警告视为错误的
`cargo doc`、nextest 测试套件、doc/release 测试 profile、benchmark 编译和
`cargo audit`。CI 还会构建 musl release；Security workflow 另外运行 fuzz shard
和 sanitizer。

### Check 结果协议

Check 门禁将完整本地诊断与精简终端结果分离：

```shell
cargo dev check --all --output human            # 精简易读的进度（默认）
cargo dev check --all --output agent            # 稳定的 CHECK_* 单行记录
cargo dev check --all --output json             # 单个 rr-dev-result/v1 JSON 对象
cargo dev check --all --log-dir target/my-check # 可选的新目录
```

每个已尝试阶段都会把原始 stdout 和 stderr 分别保留在一个新目录下。默认位置是
git 忽略的 `target/rr-dev/check/` 运行目录；相对 `--log-dir` 从仓库根目录解析，
已存在的目录会被拒绝而不会覆盖。每条输出流上限为 64 MiB；超限或无法读取的
输出会使该阶段按失败关闭。`cargo audit` 的在线尝试与缓存重试共同使用同一个
阶段上限。

所有模式都保持相同的步骤顺序、首次失败即停止的行为、进程超时、退出判定和
完整诊断日志。Human 模式为每个已完成阶段打印一条简短判定。Agent 模式输出
节省 token 的 `CHECK_START`、`CHECK_STAGE` 和 `CHECK_RESULT` 记录，其中值使用
JSON 引号。JSON 模式输出一个精简结果，包含总体判定、计数、耗时、最慢阶段、
日志目录，以及已尝试阶段的日志文件名。

## GitHub 治理

默认分支由启用状态的 repository ruleset 保护。所有变更都必须通过 pull request
进入；管理员没有常设 bypass。只有当当前精确 head 上的 CI 和 Security 检查基于
最新 base 状态全部成功，且所有 review conversation 都已解决时，PR 才能合入。
仓库只有一位维护者期间，所需批准数为零，因此规则能保护合入流程，又不会造成
无法完成的自我 review 死锁。禁止强制推送和删除默认分支。

所需检查的名称来自 `.github/workflows/` 中的 job。重命名、增加或删除强制 job
时，必须通过 GitHub API 协调更新 ruleset：先在 PR head 上验证新检查，再更新
ruleset，并在合入前重新读取实际生效规则。绝不能为了适应拼写错误或已过期的管理
context 而改变产品或 workflow 语义。

文档化的发布流程可以创建匹配 `v*` 的新 release tag。tag 创建后不得更新、
强制更新或删除。Release workflow 仍负责验证 tag 是 annotated tag、属于当前历史，
并与发布身份一致。

仓库 Actions 策略只允许 GitHub 自有 action 和当前 workflow 明确批准的第三方
action family。每个 `uses:` 引用都必须固定到完整 commit SHA。默认
`GITHUB_TOKEN` 只读，且不能批准 PR；只有 job 自己负责的操作确实需要写权限时，
才声明更窄的写权限。具体而言，只有 release publish job 需要
`contents: write`。增加 action 或写权限前，必须审计完整 workflow，并有意更新
仓库策略。

## Pull request

- 大型工作应尽早开启 Draft PR 并持续推送；PR/issue 是继续工作的状态台账。
  数小时的工作绝不能只存在于一台机器上。
- PR 保持范围集中；说明语义影响；列出已运行的测试和证据。
- 必须在计划合入的精确 head SHA 上通过 CI——旧 head 的绿色结果不能验证新提交。
- 合入后执行 `git fetch origin`，下一分支从更新后的 `origin/main` 开始。

## 工具格式化纪律

只格式化有意修改的文件。不要随意对 `tools/` 工作区运行 `cargo fmt --all`：
生产和工具工作区分别格式化，对未修改工具文件产生的 formatter churn 会污染 review。
