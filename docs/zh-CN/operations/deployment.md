# Linux 部署

[English](../../en/operations/deployment.md) | 简体中文

把一份已校验的配置投入生产：验证 release、建服务账号、systemd unit、防火墙边界，
以及升级。

这一页假设你已经有一份能用的配置。还没有的话，[快速上手](../getting-started.md)
大约十五分钟就能产出一份，[配置指南](../configuration/index.md)会解释每个字段。

## 前提

- 64 位 Linux，较新的内核；用附带的 unit 则需要 systemd。
- root 权限，用于安装、服务账号、防火墙和特权端口。
- 每一台入口、落地和客户端主机的系统时间都要准。两种内部协议都会拒绝超出有界时钟
  差的转移。
- 一个**在部署主机上**能通过 `rust-reality check-cover` 的伪装目标。
- 落地节点还需要一条来自入口节点的私有通路，或者一条只放行入口节点地址的防火墙规则。

这个二进制需要出站 DNS 和 TCP 访问、对资产缓存的写权限，以及——仅在启用文件日志时
——对日志目录的写权限。它不需要任何运行时语言，也不需要配套守护进程。

## 安装官方 release

从同一个 [GitHub Release](https://github.com/jacek4yang/rust-reality/releases)
下载这六个文件：

- `rust-reality-vX.Y.Z-linux-x86_64-generic.tar.gz`
- `rust-reality-vX.Y.Z-linux-x86_64-musl.tar.gz`
- `rust-reality-vX.Y.Z-linux-x86_64-v3.tar.gz`
- `rust-reality-vX.Y.Z-linux-aarch64-generic.tar.gz`
- `release-manifest.json`
- `SHA256SUMS`

解包之前逐个校验：

```shell
sha256sum --check SHA256SUMS
tar -xzf rust-reality-v<version>-linux-x86_64-generic.tar.gz
sudo install -m 0755 rust-reality /usr/local/bin/rust-reality
rust-reality --version
```

| 压缩包 | 要求 | 什么时候用 |
| --- | --- | --- |
| `linux-x86_64-generic` | 基线 x86-64 | 常见的 glibc 发行版 |
| `linux-x86_64-musl` | 基线 x86-64 | Alpine 或精简容器；完全静态 |
| `linux-x86_64-v3` | x86-64-v3，**没有运行时回退** | 你已经确定 CPU 够格 |
| `linux-aarch64-generic` | ARMv8.0 带 neon | ARM64 |

v3 那一档是可选的，在验证主机上没有测出优势，因为每一档的记录层 AEAD 都在运行时
派发到 AES 硬件。

`release-manifest.json` schema v3 记录版本、tag、确切源码 commit、目标三元组、源码
时间戳、编译器、cargo feature，以及每一档的压缩包名、SHA-256、目标 CPU 与特性、
最低 CPU 要求。**不要把不同 release 的压缩包、manifest 或校验和混着用。**

想自己构建的话，用固定的工具链和锁定的依赖图：

```shell
cargo dev check --all
cargo dev release build linux-x86_64-generic
```

## 建服务账号和目录

```shell
sudo useradd --system --home /var/lib/rust-reality \
  --shell /usr/sbin/nologin rust-reality
sudo install -d -o root -g rust-reality -m 0750 /etc/rust-reality
sudo install -d -o rust-reality -g rust-reality -m 0750 \
  /var/lib/rust-reality/assets
sudo install -d -o rust-reality -g rust-reality -m 0750 \
  /var/log/rust-reality
```

推荐布局：

```text
/usr/local/bin/rust-reality              root:root          0755
/etc/rust-reality/config.json            root:rust-reality  0640
/var/lib/rust-reality/assets/            rust-reality       0750
/var/log/rust-reality/                   rust-reality       0750（仅文件日志时）
```

配置里有私钥。它对服务组可读，对其他任何人都不可读。

## 装配置

```shell
sudo install -o root -g rust-reality -m 0640 \
  config.json /etc/rust-reality/config.json
rust-reality check   -c /etc/rust-reality/config.json
rust-reality doctor  -c /etc/rust-reality/config.json
rust-reality explain -c /etc/rust-reality/config.json
```

`check` 离线地证明文件自身合法。`doctor` 证明这台机器和这个网络认可它。`explain`
显示没写的字段在这里解析成了什么——第一次启动前读一遍，省得那些推导出来的上限日后
变成意外。

落地节点要在拨号它的入口节点**之前**起来，并确认跨两份文件的三个值：端口、预共享
密钥，以及——用 Handoff 时——入口持有的是落地节点公钥那半。这些单文件检查一个都看不到；
见[线路节点与落地节点](../configuration/line-landing.md)。

## 防火墙

**入口节点。** 只有一个公网监听器，在 443 上。rust-reality 的其它任何东西都不该可达。

**落地节点。** 只对入口节点的地址开放入口节点会拨的那个端口：

```shell
sudo iptables -A INPUT -p tcp --dport 7443 -s <入口节点地址> -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 7443 -j DROP
```

一个从互联网可达的落地节点，就是一个 IP 可以被发现的落地节点，这就把要它的理由抵消
了。把它绑到私有地址而不是通配地址，这样防火墙配错也不会把它暴露出去：

```json
{ "listeners": [{ "port": 7443, "ip": "ipv4Only", "ipv4": "10.0.0.2" }] }
```

## 装并启动 systemd

复制 release 压缩包里附带的 unit：

```shell
sudo install -o root -g root -m 0644 \
  deploy/rust-reality.service /etc/systemd/system/rust-reality.service
sudo systemd-analyze verify /etc/systemd/system/rust-reality.service
sudo systemctl daemon-reload
sudo systemctl enable --now rust-reality
sudo systemctl status rust-reality
journalctl -u rust-reality -f
```

这个 unit 以专用账号运行 `rust-reality run -c /etc/rust-reality/config.json`，只保留
`CAP_NET_BIND_SERVICE`，保护主机文件系统和内核界面，并且只允许写资产目录和日志目录。
请对照你的发行版路径和本地加固策略去审查它，而不是因为某样东西没跑起来就删掉一条限制。

`CAP_NET_BIND_SERVICE` 是非 root 进程绑定 443 的方式。不要为了省掉这个能力而用 root
跑服务。

### 日志

普通安装用 `log.output: "stderr"` 或 `"journald"`，保留策略交给 journal。两者都写到
标准错误；`journald` 按 journald 自己的解析格式排版。

用 `"file"` 时 `log.file` 必填，`maxBytes`、`maxFiles`、`maxTotalBytes` 都会被强制执行。

`"none"` 在编码之前就丢弃所有事件。它同时也会把 warn 级的拒绝和准入信号静音，所以除非
日志本身不可接受，否则优先用 `level` 过滤。

### 确认启动

每次启动都在 journal 里确认：

| 事件 | 它告诉你什么 |
| --- | --- |
| `server_starting` | 进程开始启动 |
| `outbound_network_initialized` | 缓存的 IPv4/IPv6 路由可用性和初始出站倾向 |
| `descriptor_budget_report` | 描述符规划；`fd_clamped: true` 表示上限约束了它 |
| `listener_topology_active` | 每个监听器实际绑定了哪些 socket |
| `listener_started` | 某个 socket 开始接受连接 |
| `configuration_published` | 第 0 代上线 |

`listener_topology_active` 反映的是**绑定结果，不是可达性**：绑上了 IPv6 socket 并不
证明公网 IPv6 入向能用。在 `ip: "auto"` 下，缺一个地址族只有在
`listener_family_unavailable` 报出真实的地址族或协议能力错误时才可接受。地址被占用、
权限不足、以及具体地址相关的错误仍然是致命的，`dualStack` 从不降级。

## 热更新与重启

先校验，再重载：

```shell
rust-reality check -c /etc/rust-reality/config.json
sudo systemctl reload rust-reality
```

编译不过的候选配置会让当前这一代继续服务，并记录 `configuration_rejected`，完整诊断
打到 stderr。已建立的连接永远在接纳它们的那一代上跑完。

冷配置需要重启而不是重载：`role`、`listeners`、`network`、`dns`，以及 `runtime` 的每个
字段。改动其中之一的重载会被指名拒绝。完整表格见
[热冷一览](../configuration/reference.md#热冷一览)。

```shell
sudo systemctl restart rust-reality
```

SIGTERM 停止接受新连接，并给活跃转发最多 30 秒排空。unit 的 40 秒停止超时留有余量。

## 升级与回滚

1. 下载并校验新 tag 的每一个文件。
2. 把当前的二进制和配置留成 root-only 的回滚副本。
3. 拿生产配置的副本跑一遍新二进制的 `check` 和 `doctor`。
4. 原子地装上新二进制并重启。
5. 确认 journal、监听器、真实客户端握手和路由。

```shell
sudo install -m 0755 rust-reality /usr/local/bin/rust-reality.new
sudo mv /usr/local/bin/rust-reality /usr/local/bin/rust-reality.previous
sudo mv /usr/local/bin/rust-reality.new /usr/local/bin/rust-reality
sudo systemctl restart rust-reality
```

回滚时要把旧二进制和那个版本能接受的配置一起恢复，然后重启。不要一边降级一边保留旧
版本不认识的配置字段——它会把它们当未知字段拒绝，这是正确行为，不是需要绕开的 bug。

v1.9 之前的 release 写的配置不被接受，也没有迁移路径。重写一份新的：它短得多，
[单机节点](../configuration/standalone.md)会带你走一遍。

### 带版本的部署

长期生产节点应该把可替换的软件和持久身份分开。带类型的
`cargo dev deploy {inspect,plan,apply}` 流程维护这样的布局：

```text
/opt/rust-reality/releases/RELEASE/rust-reality
/opt/rust-reality/current -> releases/CURRENT
/opt/rust-reality/previous -> releases/PREVIOUS

/etc/rust-reality/releases/RELEASE/config.json
/etc/rust-reality/current -> releases/CURRENT
/etc/rust-reality/previous -> releases/PREVIOUS
```

各代配置归 root 所有、对服务组可读，并且在轮换不是一次明确的运维动作时，始终携带同一
份持久 REALITY 身份。第一次迁移会在 unit 开始使用 `current` 之前，把正在跑的二进制和
配置复制成一份已知可用的回滚包。金丝雀成功之后保留 CURRENT 和 PREVIOUS，只删更老的
release 代。

**绝不要因为旧二进制被清理了就顺手清理身份。** 一个 release 是可替换的软件世代；节点
的 REALITY 身份和它的 443 端点是持久部署状态，正常升级必须同时保住这两样，已经配好的
客户端才能继续用。

`cargo dev deploy apply` 的每一次改动都需要 `--mutate-remote`。`stage` 校验版本、
SHA-256、`check` 和 `doctor`，但不切换线上节点。`cutover` 会先准备好 PREVIOUS，并在
进程、可执行文件身份或 443 端口健康检查失败时自动恢复。这个工具从不改 SSH 配置、防火墙
规则或监听端口。

在边缘主机上，22 端口是长期的管理设施，443 是唯一的公网 rust-reality 监听器。辅助源站、
指标和基准测试助手都待在 loopback、Unix socket 或隔离命名空间里。

## 出问题的时候

[排障](troubleshooting.md)是按症状组织的。最先该跑的三个命令，按顺序：

```shell
rust-reality check   -c /etc/rust-reality/config.json
rust-reality explain -c /etc/rust-reality/config.json
rust-reality doctor  -c /etc/rust-reality/config.json
```

不要未经审查就公开 debug 日志，也绝不要把生产配置、密钥、UUID 或抓包贴到公开 issue 里。
`rust-reality explain --json` 不含任何密钥材料，可以放心分享。

## 已移除的内核转发后端

sockhash 后端被移除了：它在任何生产基准矩阵里都没有真正启用过，一次特权 A/B 显示它与
`splice` 持平，而非特权的生产部署模型根本没法启用它。

io_uring 后端被移除了，见 [ADR 0002](../../adr/0002-io-uring-removed.md)。

两者都没有留下配置界面。可移植的缓冲转发和 Linux `splice` 都不需要额外特权，而且除非
被[钉住](../configuration/runtime-and-resources.md#limits)，`splice` 的开关跟随检测到的
平台能力。
