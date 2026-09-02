# 命令行参考

[English](../en/cli.md) | 简体中文

七个命令。每一个都是运维会主动去做的一件事。

```
rust-reality run         -c <config.json>
rust-reality check       -c <config.json>
rust-reality doctor      -c <config.json>
rust-reality explain     -c <config.json> [--json] [--route <HOST>]
rust-reality format      -c <config.json> [--write]
rust-reality check-cover --cover <HOST:PORT> [--server-name <NAME>] [--timeout-ms <N>]
rust-reality generate    uuid | x25519 | short-id | psk
```

外加 `--help` 和 `--version`。所有读配置的命令都接受 `-c` / `--config`。

| 命令 | 回答什么 |
| --- | --- |
| `run` | 提供服务，直到收到 SIGINT 或 SIGTERM |
| `check` | 这份配置自身合法吗？ |
| `doctor` | 这份配置在这台机器和这个网络上真的能用吗？ |
| `explain` | 这份配置在这里解析成了什么？ |
| `format` | 把我的配置改写成规范、已校验的形式 |
| `check-cover` | 这个候选主机能当 REALITY 伪装目标吗？ |
| `generate` | 生成我不该手写的材料 |

这里刻意没有基准测试、没有 schema 导出、没有性能剖析、也没有仓库工具。一个命令的
存在理由是运维想做这件事，而不是某个子系统能暴露出一个命令——工程能力放在
`cargo dev` 里，部署出去的守护进程不是本项目的工具箱。

## `run`

```shell
rust-reality run -c /etc/rust-reality/config.json
```

绑定所有配置的监听器，然后一直服务到 SIGINT 或 SIGTERM。它留在前台，这正是 systemd
和其它任何进程守护需要的形态。

**信号**

| 信号 | 效果 |
| --- | --- |
| `SIGHUP` | 原子地重载配置文件 |
| `SIGINT`、`SIGTERM` | 停止，并排空活跃连接 |

重载会先把新文件完整编译出来再发布。任何一步失败，正在跑的配置继续服务，失败记为
`configuration_rejected`，完整诊断打到 stderr。改动冷配置的重载会被指名拒绝——见
[热冷一览](configuration/reference.md#热冷一览)。

关停最多等 30 秒让活跃转发跑完，然后中止剩下的。

**退出码**在绑定失败、信号安装失败，或监听器意外停止时非零。

## `check`

```shell
rust-reality check -c /etc/rust-reality/config.json
```

```
/etc/rust-reality/config.json is a valid entry node
```

解析、校验每一个值、校验每一处交叉引用。然后就停。

**`check` 严格离线。** 它不解析名字、不开 socket、不下载、不绑定。这是保证，不是
倾向：有测试盯着。所以它在哪儿都能跑——笔记本上的 CI、没有网络的容器、或者针对一台
你人不在跟前的机器的文件。

失败打到 stderr 并附上出问题的那一行，stdout 保持为空：

```
error: invalid value for `runtime.profile`
 --> /etc/rust-reality/config.json:3:27
  |
3 |   "runtime": { "profile": "server" },
  |                           ^^^^^^^^ expected "auto", "shared", or "dedicated"
  |
  = actual value: "server"
  = help: use "dedicated" only when this process owns the bounded host or cgroup
```

密钥从不回显；关于密钥材料的诊断显示 `[REDACTED]`。

**退出码**合法为 0，否则非零。每次重载之前都跑一下。

## `doctor`

```shell
rust-reality doctor -c /etc/rust-reality/config.json
```

做完 `check` 做的一切，然后去联系文件里点名的东西：解析 DNS、拨号伪装目标并确认它
仍然能协商 TLS 1.3、加载并解析 geo 数据、检查文件权限和目录。

它从不绑定生产监听器，也从不改动系统。

```json
{
  "assets": { "domainLabels": 0, "domainSources": 0, "generation": 0, "ipLabels": 0, "ipSources": 0 },
  "configuration": "ok",
  "cover": [
    {
      "target": "www.microsoft.com:443",
      "serverName": "www.microsoft.com",
      "compatible": true,
      "cipherSuite": "TLS_AES_256_GCM_SHA384",
      "keyExchangeGroup": "X25519",
      "connectMillis": 322,
      "serverHelloMillis": 319,
      "totalMillis": 642
    }
  ],
  "role": "entry",
  "routing": "ok"
}
```

重启之前、改过伪装目标之后，以及原本好用的东西不好用了的时候，跑它。

## `explain`

```shell
rust-reality explain -c /etc/rust-reality/config.json
```

报告这份文件在这台机器上解析成了什么——报的是决定，不是内部状态的堆砌：

```
role: entry
listeners:
  0.0.0.0:443, [::]:443 (auto, at least one)
routing:
  default: landing-1 (1 rule, strategy resolveIfNoMatch)
  policy split: default landing-1 (1 rule, 1 user)
  outbounds: direct, block, landing-1
  geo data: required by at least one rule
machine: 4 effective cpus (4 logical), 524288 descriptors, 16194637824 bytes memory (cgroup_v2)
posture: profile auto -> standard, tuning startup, objective balanced
runtime: 4 worker threads, 512 blocking threads (tokio-default)
limits: 25 values, all derived from the machine (--json for the table)
```

钉住的上限会逐条列出，推导的只报个数。当主机自身的设置会限制这个进程时，后面会跟
advisory——而且它们在字面意义上就是"仅供参考"，因为这个进程从不写 sysctl、不写别的
进程的 rlimit、不写 cgroup 文件。

和 `check` 一样，它是离线的。

### `--json`

完整报告，给自动化用：

```shell
rust-reality explain -c config.json --json | jq '.fields[] | select(.source == "operator-pinned")'
```

每个字段都带着它的值、来源（`operator-pinned`、`startup-derived` 或 `default`）、
适用时的 objective 乘数，以及下限和上限。`schemaVersion` 标识报告形状。报告里没有
任何密钥材料，所以可以放心附在 bug 报告里。

### `--route HOST`

回答某一个目的地会去哪，而不是报告整份文件：

```shell
rust-reality explain -c config.json --route example.com
rust-reality explain -c config.json --route 10.1.2.3:443
rust-reality explain -c config.json --route '[2001:db8::1]:443'
```

```
example.com for alice -> landing-1 (routing.policies.split, default outbound)
```

回答会点名出站、做决定的那份列表，以及是怎么决定的：`global rule`、`policy rule`
或 `default outbound`。它接受 `host` 或 `host:port`，包括带方括号和不带方括号的
IPv6 字面量，端口默认 443。

离线这件事限定了它能说什么，而它会明说，而不是报出一条运行中的服务端不会选的路径：

```
note: geo conditions were not evaluated: `explain` is offline, so a rule
naming geoip: or geosite: was treated as not matching. Use `doctor` to load
the data.
```

落地节点会被直接拒绝：它不做路由，它把每一次转移都送去同一个出口。

## `format`

```shell
rust-reality format -c config.json           # 打印
rust-reality format -c config.json --write   # 原地改写
```

把配置改写成规范形式。它不是 `jq`，而这个区别正是关键：

1. **它会校验。** 它的输出一定是这个二进制接受的文件。`jq .` 会乐呵呵地把服务端
   拒绝的东西格式化得很漂亮。
2. **它按参考手册记载的顺序排键**——出站排在引用它们的路由前面，必填字段排在可选
   字段前面。`jq` 保留任意的输入顺序，`jq -S` 按字母排序，把相关字段拆得到处都是。
3. **它在构造上就是往返安全的**，因为它走的是类型化模型，所以不可能产出模型读不回来
   的形状。

契约，每一条都有测试盯着：

- 确定性，且**幂等**——`format(format(x))` 逐字节相同
- **保持语义**——`parse(format(x))` 等于 `parse(x)`
- 你写过的字段即使等于默认值也会留下
- 你没写的字段永远不会被展开进文件
- 非法输入被拒绝，而不是被格式化

`--write` 走崩溃安全的原子写，所以失败不会留下半个文件。它从不转换旧配置，也不是
迁移工具：上一个版本的文件在这里失败的方式，和它在 `check` 下失败的方式完全一样。

## `check-cover`

```shell
rust-reality check-cover --cover www.microsoft.com:443
rust-reality check-cover --cover www.example.org:443 --server-name www.example.org
```

在任何配置存在之前，检查一个主机能不能当 REALITY 伪装目标。

| 选项 | 默认 | 含义 |
| --- | --- | --- |
| `--cover HOST:PORT` | 必填 | 候选目标，带端口 |
| `--server-name DNS_NAME` | 伪装主机名 | 临时 ClientHello 里发送的名字 |
| `--timeout-ms N` | 5000 | DNS、连接、写入和 ServerHello 的总截止时间 |

```json
{
  "target": "www.microsoft.com:443",
  "serverName": "www.microsoft.com",
  "compatible": true,
  "cipherSuite": "TLS_AES_256_GCM_SHA384",
  "keyExchangeGroup": "X25519",
  "connectMillis": 304,
  "serverHelloMillis": 1892,
  "totalMillis": 2197
}
```

`compatible: true` 是硬要求；时延是答案的另一半，因为伪装目标的时延落在这个节点将来
服务的每一个连接的建立过程里。

**在部署主机上**跑它——答案取决于网络路径，一个在笔记本上能用的伪装目标可能在 VPS
上不行。`doctor` 会对配置里已有的伪装目标做同样的检查。

## `generate`

生成运维不该手写的材料，仅此而已。没有任何命令会拼出一份配置、一个客户端 profile
或者一条订阅链接。

```shell
rust-reality generate uuid [COUNT] [--json]
rust-reality generate x25519 [--json]
rust-reality generate short-id [COUNT] [--bytes N] [--json]
rust-reality generate psk [--json]
```

| 子命令 | 用于 | 备注 |
| --- | --- | --- |
| `uuid` | `users[].id` | RFC 4122 v4；`COUNT` 最多 1024 |
| `x25519` | `reality.privateKey`，或 Handoff 落地节点的 `landing.privateKey` | 每个用途一对 |
| `short-id` | `users[].shortIds` | `--bytes` 1–8，默认 8 |
| `psk` | NXR 或 Handoff 的 `psk` | 每个落地节点一个 |

给人看的输出带标签：

```
private key (keep secret): bkuHF6dZ2Elt_dkFKZoXkSUZ6gnLITrUZbRmDggVfuQ
public key  (give to peers): CyrxYetA0RSs9IxcGpb7vNfQ3GoKm6xTUL5qWdbjUAY
```

`--json` 是稳定的机器可读形式，给安装器用：

```json
{
  "privateKey": "005oawzDIFyUCdSjXtgGaP7UgGF7zFEzay4kL_nq9ww",
  "publicKey": "UWesja3AOowUwLohp5LcPtmE0gZmBSsn8I6623QczzY"
}
```

## 退出码

成功为 `0`。任何失败都非零，原因打在 stderr。

每个命令都把结果写到 stdout、把诊断写到 stderr，所以
`rust-reality explain --json -c config.json > report.json` 即使伴随警告也会得到一个
干净的文件。

## 开发用命令

基准测试、性能剖析、schema 生成、仓库检查、fuzz 清单和文档校验都是工具工作区里的
`cargo dev` 子命令，不属于发布出去的二进制。见
[开发流程](development/development-workflow.md)。

```shell
cargo dev check --all          # 完整校验闸门
cargo dev config schema        # 生成 JSON Schema
cargo dev docs check           # 文档策略，包括每一段示例
```
