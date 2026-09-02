# 运行时与资源

[English](../../en/configuration/runtime-and-resources.md) | 简体中文

这个进程被允许消耗什么。这里每个值都有一个从机器推导出来的默认值，而在大多数节点上，
整段都该不存在。

## 先读这一段

二十五个上限、缓冲区大小和池边界，在启动时从这台机器实际拥有的 CPU 数、内存和描述符
上限推导出来。推导发生在第一个监听器绑定之前，不跑基准、不走网络，而且是确定性的。

所以诚实的默认建议是：**这一段什么都别写，去看推导出了什么。**

```shell
rust-reality explain -c /etc/rust-reality/config.json
```

```
machine: 4 effective cpus (4 logical), 524288 descriptors, 16194637824 bytes memory (cgroup_v2)
posture: profile auto -> standard, tuning startup, objective balanced
runtime: 4 worker threads, 512 blocking threads (tokio-default)
limits: 25 values, all derived from the machine (--json for the table)
```

`--json` 会打印每个值的来源、下限、上限，以及 objective 施加的乘数。在认定这一页上
的任何东西值得设置之前，先读那张表。

## `profile`

```json
{ "runtime": { "profile": "dedicated" } }
```

这是大多数节点唯一该考虑的字段，因为它回答了一个机器自己答不了的问题：**这个进程
是不是这台机器的主人？**

| 取值 | 含义 |
| --- | --- |
| `auto`（默认） | 找 cgroup 租户边界，据此判断 |
| `shared` | 这台机器上还跑着别的东西，保守估算 |
| `dedicated` | 这个进程独占这台主机或这个 cgroup |

`dedicated` 下，进程会把自己的软 `RLIMIT_NOFILE` 抬向硬上限、按放宽的余量做规划、
按 cgroup 感知的 CPU 视图给 Tokio 线程池定尺寸，并启动一个内存压力监控，在 cgroup
OOM kill 到来之前就开始拒绝新工作。

`shared` 下这些一样都不做，因为一个和别人共享主机的进程，没有资格给自己的线程池定
尺寸，也没有资格抢别的进程需要的描述符。

`auto` 找的是真实存在的租户边界。它在设了限额的容器上和普通 VPS 上都判断得对；但它
不可能知道你这台 VPS 上还跑着你的数据库。如果是这样，写 `shared`。

## `tuning`

```json
{ "runtime": { "tuning": "adaptive", "statusFile": "/run/rust-reality/status.json" } }
```

| 取值 | 含义 |
| --- | --- |
| `startup`（默认） | 启动时推导一次，之后不再变 |
| `adaptive` | 启动时推导，运行中根据压力调整部分软上限 |

`adaptive` 让一个控制器根据观察到的压力挪动几个准入上限和直连速率闸门。它永远不会
超过启动推导的结果——那是硬天花板——也永远不碰启动时定尺寸的东西，比如缓冲区大小。

`statusFile` 只在 `adaptive` 下有意义，在 `startup` 下写它会被拒绝，而不是被静静
忽略。控制器会在启动时以及每次变化时往那儿写一份快照：

```shell
jq . /run/rust-reality/status.json
```

没有任何命令会把它读回来。进程状态归 `systemctl status`，日志归 `journalctl`，配置
归 `explain`；这个状态文件是给你已经在用的那套指标采集消费的机器可读产物。

## `objective`

```json
{ "runtime": { "objective": "throughput" } }
```

| 取值 | 偏向 |
| --- | --- |
| `balanced`（默认） | 都不偏 |
| `latency` | 更小的缓冲区、更紧的并发 |
| `throughput` | 更大的缓冲区、更高的并发 |

objective 是在推导值的基础上缩放，而不是替换它们，之后上下限照样生效——所以
`throughput` 不可能超过机器撑得住的量，`latency` 也不可能低到不可用的地板以下。

转发缓冲区在 16 KiB、32 KiB、64 KiB 三档之间每步移动一档，出不了这三档。

## `limits`

```json
{
  "role": "entry",
  "listeners": [
    {
      "port": 443
    }
  ],
  "reality": {
    "cover": "www.microsoft.com:443",
    "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE"
  },
  "users": [
    {
      "id": "11111111-1111-4111-8111-111111111111",
      "shortIds": [
        "0123456789abcdef"
      ]
    }
  ],
  "routing": {
    "default": "direct"
  },
  "runtime": {
    "profile": "dedicated",
    "tuning": "adaptive",
    "objective": "throughput",
    "statusFile": "/run/rust-reality/status.json",
    "limits": {
      "maxConnections": 8000
    }
  }
}
```

八个字段，全部可选。**写了就是钉住**——你写下的值即使等于推导会得到的值也照样生效，
因为"写下来"本身就是信号。

| 字段 | 限制什么 |
| --- | --- |
| `maxConnections` | 同时接纳的连接数 |
| `maxHandshakes` | 同时进行的握手数 |
| `clientHelloTimeoutMs` | 等客户端第一批数据 |
| `handshakeTimeoutMs` | 完成一次握手 |
| `connectTimeoutMs` | 拨号目的地 |
| `fallbackTimeoutMs` | 把未认证连接代理到伪装目标 |
| `splice` | 使用内核零拷贝转发路径 |
| `pipePool` | 复用该路径需要的管道 |

那四个超时是协议安全参数而不是机器预算，所以它们从不推导：不钉的话取各自记载的默认
值，`explain` 会把它们报成 `default` 而不是 `startup-derived`。

`explain` 会准确显示你钉了什么：

```
limits: 1 pinned, 24 derived (--json for the table)
  governor.maxConnections = 8000
```

### 什么时候钉才正当

- **有实测出来的问题。** 你有证据表明推导值对这个负载是错的——不是怀疑。
- **有硬性外部约束。** 某个这个进程看不见的、来自外部的上限。
- **奇怪的内核。** `splice` 和 `pipePool` 存在，是因为一个宣称支持某能力然后又
  表现异常的内核需要一个逃生口。正常内核上别动它们。

把 `maxConnections` 钉到超过描述符预算能支撑的值，并不会抬高预算；进程照样拒绝它
没有描述符可用的工作，这个钉子什么也没买到。`explain --json` 会显示每个字段的下限和
上限，那是钉之前该做的检查。

### 你钉不了的

转发缓冲区大小、池边界、预热连接尺寸、直连闸门、重放缓存容量、DNS 缓存内部参数都是
推导出来的，没有对应字段。它们属于实现细节：正确取值由机器决定，而钉住它们的运维等于
在跟一次测量对赌。

这就是本项目划的那条线——有意义的运维策略保持可配，实现细节不变成旋钮。

## `runtime` 是冷的

这里每个字段都是冷的。改动其中任何一个的重载都会被拒绝，报
`runtime profile, tuning, or resource-mode changes require a process restart`，
正在跑的配置继续服务。

这是推论，不是政策：描述符预算、内存监控、线程池，以及每一个准入上限，都是在第一个
监听器绑定之前照着这些值定下来的。不重建这一切就改它们，等于让上限和池互相打架。

所以要计划一次重启：

```shell
rust-reality check -c /etc/rust-reality/config.json
rust-reality explain -c /etc/rust-reality/config.json
sudo systemctl restart rust-reality
```

重启前先 `explain`，这才是关键。它会在你把服务停下来之前，就告诉你新值在这台机器上
会解析成什么。

## 那些 advisory

当主机自身的设置会限制这个进程时，`explain` 末尾会给出 advisory：

```
advisories:
  kernel tuning is advisory only: the process never writes sysctls, other
  processes' rlimits, or cgroup files
  net.ipv4.tcp_rmem and net.ipv4.tcp_wmem maxima below the 64 KiB relay
  buffer tier can throttle large transfers
```

它们在字面意义上就是"仅供参考"：这个进程从不写 sysctl、不写别的进程的 rlimit、不写
cgroup 文件。它报告它注意到的东西，然后不去动这台机器。要不要照做是主机管理的决定，
不是配置的决定。
