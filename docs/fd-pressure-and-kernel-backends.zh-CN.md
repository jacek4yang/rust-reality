# 文件描述符压力与内核中继后端

本文档说明生产环境 `EMFILE` 事故之后引入的描述符准入架构，以及各内核中继后端的当前就绪状态。

## 1. 事故经过

生产服务器以如下错误终止：

```text
error: listener accept failed
```

系统调用追踪显示：

```text
pipe2(..., O_NONBLOCK|O_CLOEXEC) = -1 EMFILE (Too many open files)
pipe2(..., O_NONBLOCK|O_CLOEXEC) = -1 EMFILE (Too many open files)
accept4(..., SOCK_CLOEXEC|SOCK_NONBLOCK) = -1 EMFILE (Too many open files)
```

进程限制为 `Max open files  soft=1024  hard=1048576`。

三个相互独立的缺陷叠加导致了这次故障：

1. 监听循环向上传播了每一个 accept 错误，因此本可恢复的 `EMFILE` 变成了致命的进程错误。
2. 进程中没有任何代码读取 `RLIMIT_NOFILE`。默认配置允许约 24 000 个描述符，而继承到的软限制是 1 024。该配置只有在通过随附的 systemd 单元（`LimitNOFILE=1048576`）启动时才成立。
3. splice 中继会创建两组管道对，共四个描述符，却没有做任何预留。

## 2. 描述符预算

### 推导

在绑定任何监听器之前，于启动阶段计算：

```text
effective_dynamic_fd_budget = soft_rlimit - fixed_fd_reserve - safety_headroom
```

固定预留刻意取保守值：

| 组成部分 | 预留数量 |
|---|---|
| 监听套接字 | 每个已配置 inbound 一个 |
| 标准流与日志写入端 | 4 |
| 运行时 epoll、eventfd 与 waker | 16 |
| 不可取消的解析器描述符 | 32 |
| 应急预留 | 1 |

安全余量为 `max(soft_limit / 16, 64)`。

解析器描述符采用预留而非准入，原因是被取消的 `TcpStream::connect` 无法取消其底层的阻塞式 `getaddrinfo`；这些描述符的存活时间会超过发起请求的那条连接。

### 策略

只采用一种策略，并且已经过测试：

* 当软限制无法覆盖固定预留加上 64 个单位的最小可用动态预算时，**拒绝启动**。错误信息会给出实测限制与所需数值：

  ```text
  the process file-descriptor soft limit is 64 (hard limit 1048576) but at
  least 182 is required to serve traffic safely; raise it with
  `ulimit -n 182` or `LimitNOFILE=182` in the unit file
  ```

* 当配置的峰值超出限制所允许的范围时，**向下钳制并告警一次**。启动时的 `descriptor_budget_report` 会同时给出两个数值，以及可避免钳制的软限制建议值。

在任何策略下，进程都不会先以无法满足的配置启动、随后才在 `accept4` 中发现问题。

`maxConnections` 仍然是协议层限制，不会被下调；描述符预算只是在更紧的一侧先行生效。

### 准入

`FdBudget` 是严格上界的许可计数器。

* 快路径只有一次 relaxed load 和一次 `compare_exchange_weak`，整个模块不含任何互斥锁。
* 在任意交错执行下，使用中的计数都不可能超过容量，哪怕是瞬时超过。
* `FdPermit` 在 `Drop` 中释放，因此正常完成、错误、`?` 传播、超时、取消与任务中止都经由同一条路径释放。
* 释放使用**带检查的**减法。饱和减法会悄悄吞掉重复释放的缺陷并逐渐泄漏容量；带检查的形式会记录下溢，使测试能够据此失败。
* 压力下的等待是有界的 `Notify` 唤醒，而非轮询循环。等待者会在最终复检之前完成注册，因此期间到达的释放不会被漏掉。

保守的单位成本：

| 资源 | 单位 |
|---|---|
| 已接受的 inbound 套接字 | 1 |
| 已连接的 outbound 套接字 | 1 |
| 存活的连接候选 | 1 |
| 双向 splice 中继 | 4 |

该计数宁可多预留，也不去建模内核内部对象。它是预留，不是测量。

### 压力与迟滞

在容量的 15/16 处进入压力状态，在 13/16 处退出。留出这一间隔是为了避免一批释放之后在下一次 accept 时立即重新进入压力状态。压力日志基于状态跃迁，因此持续的压力状态只产生两行日志，而不是每条连接一行。

进程从不为准入而轮询 `/proc/self/fd`。

## 3. 监听器恢复

接受过程被拆分为三个具有不同失败语义的阶段：

```text
accept  ->  configure  ->  admit
```

`TcpAcceptor::accept_only` 只执行 accept。`configure_accepted` 单独设置 `TCP_NODELAY`，因此单条连接的套接字选项失败只会关闭该流、释放其许可、输出一条 `connection_rejected{reason:socketConfiguration}`，然后继续接受新连接。此前的实现把两者合并为一个 `io::Result`，可能因为单条连接的选项失败而终止整个监听器。

accept 错误依据原始 `errno` 分类，而非 `ErrorKind`：

| 类别 | errno | 响应 |
|---|---|---|
| `wouldBlock` | `EAGAIN` | 重试，不记日志 |
| `transient` | `EINTR`、`ECONNABORTED`、`EPROTO`、`ECONNRESET`、`ENETDOWN`、`ENETUNREACH`、`EHOSTDOWN`、`EHOSTUNREACH`、`ENONET`、`ETIMEDOUT`、`EPERM` | 立即重试，日志有界 |
| `descriptorPressure` | `EMFILE`、`ENFILE` | 应急描述符恢复、退避，绝不终止 |
| `memoryPressure` | `ENOBUFS`、`ENOMEM` | 有界指数退避 |
| `fatal` | `EBADF`、`ENOTSOCK`、`EOPNOTSUPP`、`EINVAL`、`EFAULT` | 仅终止该监听器，并附带 errno |
| `unknown` | 其他 | 退避后重试 |

将 `EINVAL` 归类为致命是经过判断的，而非草率处理。它仅有两个已记录成因：`accept4` 标志非法，以及套接字未处于监听状态。标志由 tokio 固定且按构造合法，因此剩下的成因是该监听器已永远无法再接受连接；此时重试只会空转。

退避从 5 毫秒开始翻倍，上限 500 毫秒，并在第一次成功 accept 后复位。

### 应急预留描述符

进程会在 `/dev/null` 上长期持有一个描述符。

准入只能约束**本进程**所记账的部分。描述符仍可能被库、解析器线程或另一个进程针对共享的 `ENFILE` 限制消耗掉。发生这种情况时，`accept4` 会在积压队列已满的情况下返回 `EMFILE`，而进程没有办法排空它。

在意外的 `EMFILE` 发生时，应急描述符被释放，随后在 1 毫秒的时限内尝试一次 accept，立即关闭所接受的套接字，再重新获取该描述符。对端会观察到连接关闭而不是挂起，积压队列也前进了一位。重新获取失败是可恢复的：下一次压力事件只是发现没有可用的预留而已。

这是最后手段，不能替代正确的准入。

## 4. splice 描述符

双向 splice 中继会创建两组管道对。四个单位在 `pipe2` **之前**获取，且该许可与管道由同一个对象持有。

当单位不足时后端拒绝本次请求。由于拒绝发生在传输任何字节之前，调用方会回退到带缓冲的后端而无需重放连接，因此"开始传输后不再回退"这一不变式得以保持。

若第二组管道对创建失败，第一组会被关闭，四个单位全部释放。释放本就未曾占用的单位属于保守方向。

## 5. 后端就绪状态

探测成功并不意味着生产流量可以使用某个后端。各后端当前的真实状态如下：

| 后端 | 内核支持 | 运行时已实现 | 自动选择 |
|---|---|---|---|
| buffered | 不适用 | 是 | 是 |
| splice | 是 | 是 | 是 |
| sockhash | — | **已移除**（D7）——见下文 | — |
| io_uring | — | **已移除**——见决策记录附录 | — |

### SOCKHASH

已移除（D7）。该后端在所有生产基准矩阵中从未 arm，特权 A/B 测试显示其与 splice 持平（c1 1642 对 1637、c4 3086 对 3109、c32 3245 对 3282 MiB/s），且无特权的生产部署模型永远无法 arm 它，因此删除了这些特权复杂度。保留的证据位于 `benchmarks/final/sockhash-ab/`。仍然设置 `sockhash`、`maxSockhashRelays` 或 `maxPinnedMemoryBytes` 的配置会作为未知字段校验失败。

### io_uring

已移除，未实现。审计与理由记录于 `decisions/adaptive-relay-implementation-plan.md` 的附录；仍然设置 `ioUring` 或 `maxIoUringRelays` 的配置会作为未知字段校验失败。

## 6. 部署建议

请依据启动报告而非 `maxConnections` 来设置软限制。报告会直接给出应配置的数值：

```json
{"event":"descriptor_budget_report","fdSoftLimit":1024,"fdHardLimit":1048576,
 "fdFixedReserve":54,"fdSafetyHeadroom":64,"fdEffectiveBudget":906,
 "fdClamped":true,"fdRecommendedSoftLimit":37494}
```

systemd 配置：

```ini
[Service]
LimitNOFILE=37494
```

对于从 shell 启动的进程，`ulimit -n` 必须在 exec **之前**提高；进程在没有特权的情况下无法把自身软限制提高到硬限制之上。

`fdClamped: true` 并非错误，它表示进程会比 `maxConnections` 所暗示的更早开始拒绝工作。此时应当提高限制，或者下调配置中的各项上界，使二者一致。

## 7. 可观测性

| 事件 | 触发时机 |
|---|---|
| `descriptor_budget_report` | 启动时一次 |
| `descriptor_pressure_changed` | 仅在状态跃迁时，绝不按 accept 输出 |
| `accept_error_recovered` | 出现可恢复的 accept 错误时，附带原始 errno |
| `connection_rejected{reason:socketConfiguration}` | 单条连接的套接字配置失败 |

任何事件都不携带目标地址、SNI、UUID、密钥或负载内容。
