# 排障

[English](../../en/operations/troubleshooting.md) | 简体中文

按症状组织。从你看到的现象开始，而不是从你怀疑的原因开始。

## 先跑三个命令

在做别的之前，按这个顺序：

```shell
rust-reality check   -c /etc/rust-reality/config.json   # 文件合法吗？
rust-reality explain -c /etc/rust-reality/config.json   # 它解析成了什么？
rust-reality doctor  -c /etc/rust-reality/config.json   # 环境同不同意？
```

`check` 离线，在哪儿跑都安全。`explain` 显示推导值和路由摘要。`doctor` 去联系文件里
点名的东西。这三个加起来，能在你翻日志之前回答掉大部分问题。

## 服务起不来

### `check` 报错

诊断会点名字段并指着那一行：

```
error: invalid value for `reality.privateKey`
 --> /etc/rust-reality/config.json:6:19
  |
6 |     "privateKey": "[REDACTED]"
  |                   ^^^^^^^^^^^^ must be URL-safe unpadded base64 decoding to exactly 32 bytes
```

常见原因：

| 报错里提到 | 原因 |
| --- | --- |
| `unknown field` | 拼错了，或者是上个版本的字段 |
| `unknown outbound` | `routing` 里点了一个 `outbounds` 没声明的名字 |
| `must be URL-safe unpadded base64` | 密钥复制时带了填充、空白，或者被截断 |
| `carries the same key material as` | 一个生成出来的值被用在了两处 |
| `field \`advanced\` was removed in v1.9` | 这是为更早版本写的配置 |

为旧版本写的文件会立刻失败并点名。没有迁移路径，也没有兼容模式：重写一份新的。它更
短，[单机节点](../configuration/standalone.md)会带你走一遍。

### `check` 过了但进程退出

看 journal 的头几行：

```shell
sudo journalctl -u rust-reality -n 50 --no-pager
```

| 事件 | 含义 |
| --- | --- |
| `:443` 绑定失败 | 端口被别人占了，或者进程没有绑定它的能力 |
| `descriptor_budget_report` 里 `fd_clamped: true` | 描述符上限撑不住配置的那些上限 |
| 完全没有 `listener_started` | 它在绑定之前就失败了；错误在这之前 |

要以非 root 用户绑定 443，在 unit 里授予能力，而不是用 root 跑——见
[部署](deployment.md)。

## 客户端连不上

几乎总是这两件事之一。先把两个都排掉再往下看。

### 1. 密钥两半拿反了

`rust-reality generate x25519` 打印两个值。**私钥**那半进服务端的
`reality.privateKey`，**公钥**那半进客户端。

如果你服务端文件里的值和客户端里的值是同一个，那就是拿反了。重新生成或者重新复制；
另外注意，公钥那半没法从服务端文件里恢复出来——生成那对的时候就该记下它。

症状按设计就没什么帮助：在服务端看来这个客户端只是没通过认证，于是它被代理到伪装
目标，拿到伪装目标真实的响应。客户端看到的是一条能用的 TLS 连接和一个从不承载流量的
代理。

### 2. 客户端 SNI 对不上

客户端的 server name 必须匹配 `reality.serverNames` 里的某一项。不写该字段时，唯一
被接受的名字是 `reality.cover` 的主机名部分。

```shell
rust-reality explain -c /etc/rust-reality/config.json
```

把客户端 SNI 设成那个主机名。注意在 `serverNames` 是隐式的情况下改 `cover`，同时也
改掉了被接受的 SNI。

### 然后再查这些

| 查什么 | 怎么查 |
| --- | --- |
| 端口通不通 | 从客户端网络 `nc -vz <服务器> 443` |
| UUID 对不对 | 它就是 `users[].id`，一字不差 |
| short ID 属不属于该用户 | 它必须是**那个用户**的 `shortIds` 里的一条 |
| flow 是不是 `xtls-rprx-vision` | 这个服务端不说别的 |
| 伪装目标还能不能用 | `rust-reality doctor` |

### 一开始能连，过一阵就不行了

在 journal 里找 `admission_limited`。节点顶到了某个推导出来的上限：

```shell
sudo journalctl -u rust-reality | grep admission_limited
```

```json
{"event":"admission_limited","resource":"connections"}
```

`rust-reality explain --json` 会显示那个上限、它的下限和上限。如果对这个负载来说它
确实太低，就钉住它——见[运行时与资源](../configuration/runtime-and-resources.md)。
如果不是，那就是有什么东西在不该占着的时候占着连接。

## 流量去错了地方

别读，直接问：

```shell
rust-reality explain -c /etc/rust-reality/config.json --route example.com
```

```
example.com for alice -> direct (routing, default outbound)
```

回答会点名出站、做决定的那份列表，以及是怎么决定的。然后：

- **期望命中规则却是 `default outbound`**——规则没匹配上。检查匹配器写法：
  `domain:example.com` 会匹配子域，光写 `example.com` 不会。
- **期望是策略规则却命中了全局规则**——`routing.rules` 在任何策略之前求值，且不可
  被覆盖。这正是它适合放"必须对所有人成立的规则"、而不适合放别的东西的原因。
- **用户不对**——没写 `policy` 的用户走 `routing.default`，不走任何策略。`explain`
  会列出每条策略被多少用户选用；零用户的策略是个错误。

### geo 规则从来不命中

`explain` 是离线的，求值不了它们，而且它明说：

```
note: geo conditions were not evaluated: `explain` is offline, so a rule
naming geoip: or geosite: was treated as not matching. Use `doctor` to load
the data.
```

对运行中的服务端来说，问题是数据到底加载了没有：

```shell
rust-reality doctor -c /etc/rust-reality/config.json
```

```json
{ "assets": { "domainLabels": 0, "domainSources": 0, "ipLabels": 0, "ipSources": 0 } }
```

标签数为零意味着什么都没加载。要么 `assets` 根本没写，要么下载失败了——翻 journal 找
资产相关事件，确认 URL 是 `https://` 且从服务器可达，确认服务账号拥有 `cacheDirectory`。

`geoip:private` 是内置的，完全不需要数据文件。

## 线路与落地节点的问题

### 连接在第一次转移时失败

两份文件各自都合法——`check` 只读一个文件，看不见另一个。核对跨越两者的三个值：

| 线路节点 | 落地节点 |
| --- | --- |
| `outbounds.<名字>.port` | `listeners[].port` |
| `outbounds.<名字>.psk` | `landing.psk` |
| `outbounds.<名字>.address` | 必须从线路节点可达 |

在线路节点上：

```shell
nc -vz 10.0.0.2 7443
```

这一步不通的话，是防火墙或地址的问题，不是配置的问题。

### Handoff 专有的

除上面之外，线路节点的 `landingPublicKey` 必须是落地节点 `privateKey` 的公钥那半。
配错的一对会产生一个落地节点打不开的转移——表现为认证成功之后连接才失败，这和 `psk`
写错的表现不一样。

确认不了这一对的话就重新生成：在落地节点上跑 `rust-reality generate x25519`，私钥那半
写进 `landing.privateKey`，公钥那半写进线路节点的 `landingPublicKey`。

### 轮换密钥之后

查窗口是不是还开着：

```shell
sudo journalctl -u rust-reality | grep handoff_rotation_window_open
```

只要还列着退役密钥，它每一代都会记一次。如果你看到它而轮换其实已经做完了，就删掉
`previousPsks` 和 `previousPrivateKeys` 再重载——在你删掉之前，退役密钥仍然能打开一次
转移。

## 热更新

### 重载被拒绝

```shell
sudo journalctl -u rust-reality -n 20 --no-pager
```

```
configuration configuration reload rejected:
runtime profile, tuning, or resource-mode changes require a process restart
```

旧配置还在服务，什么都没丢。要么把冷改动撤回去，要么重启：

| 报错 | 它点名的改动 |
| --- | --- |
| `listener addresses require a process restart` | `listeners` |
| `network dial policy requires a process restart` | `network` |
| `DNS resolver policy requires a process restart` | `dns` |
| `runtime profile, tuning, or resource-mode changes require a process restart` | `runtime` 的任意字段 |

重载前一定先 `check`。校验不过的重载会以同样方式被拒绝，而 journal 是个比你的终端更
糟糕的、用来得知自己打错字的地方。

### 重载成功了但什么都没变

已建立的连接按设计保留接纳它们的那一代——重载绝不给活着的会话改道。新连接才用新配置。
确认代号有没有前进：

```shell
sudo journalctl -u rust-reality | grep configuration_published
```

```json
{"event":"configuration_published","generation":3}
```

## 性能

在调任何东西之前，先搞清楚时间花在哪。

### 建立阶段慢

伪装目标的时延就在每一个连接的建立过程里：

```shell
rust-reality check-cover --cover www.microsoft.com:443
```

几百毫秒的 `totalMillis` 意味着这个伪装目标让每个连接都慢。换一个更近的——见
[伪装目标](../configuration/cover-targets.md)。

### 吞吐低

```shell
rust-reality explain -c /etc/rust-reality/config.json
```

看末尾的 advisory。主机的 `net.ipv4.tcp_rmem` / `tcp_wmem` 上限低于转发缓冲区档位会
限制大传输，而这个进程不会替你去改 sysctl。

然后看 `profile`。在这个进程独占的机器上，`dedicated` 会抬高描述符上限、按真实 CPU
视图给线程池定尺寸，并启用内存压力监控。没有 cgroup 边界可观察时，`auto` 判断不出
一台 VPS 是独占的。

## 读日志

事件是 JSON，一行一条，所以 `jq` 能直接用：

```shell
sudo journalctl -u rust-reality -o cat | jq -c 'select(.level != "info")'
```

常用的几个：

| 事件 | 含义 |
| --- | --- |
| `server_starting` | 进程开始启动 |
| `machine_report` | `dedicated` 下检测到了什么 |
| `descriptor_budget_report` | 描述符规划；`fd_clamped` 值得看 |
| `listener_started` | 某个 socket 开始接受连接 |
| `configuration_published` | 某一代上线了 |
| `configuration_rejected` | 一次重载被拒；完整诊断在 stderr |
| `connection_rejected` | 一个连接失败了；`reason` 给出分类 |
| `admission_limited` | 顶到了某个上限；`resource` 点名是哪个 |
| `handoff_rotation_window_open` | 退役的落地密钥仍被接受 |

`connection_rejected` 的 reason 有：`authentication`、`resource_limit`、`timeout`、
`outbound`、`protocol`、`socket_configuration`。公网节点上的 `authentication` 属于
正常背景噪声——那是扫描器产生的。

把 `log.level` 设成 `debug` 可以看到每连接事件。它很吵，但那是能把一个连接的一生从头
跟到尾的级别。

## 还是卡住

提问之前先收集这些：

```shell
rust-reality --version
rust-reality explain -c /etc/rust-reality/config.json --json
sudo journalctl -u rust-reality -n 200 --no-pager
```

`explain --json` 不含任何密钥材料，可以放心分享。配置文件不行——它里面有私钥。
