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
| io_uring ring 描述符 | 启用时每分片一个 |
| eBPF map、program 与 link | 启用时 3 个 |
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
| io_uring 会话 | 2 |

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
| sockhash | 是 | 是——当策略启用且探测与控制器构建均成功时，由 `TcpRelay` 按中继 arm | 是 |
| io_uring | 仅探测 | **否**——驱动存在但中继路径无法到达 | 否 |

### SOCKHASH 运行时

启用 `policy.relay.sockHash` 后，`TcpRelay::new` 先执行内核探测，探测通过才构建进程级控制器：一个容量为 `maxSockhashRelays` 两倍条目的 `SOCKHASH`、一份携带的有界校验器日志加载的流裁决程序，以及 attach。启动时的 `RelayBackendReport` 只有在该控制器确实存在时才报告 sockhash 可用，否则给出精确的固定拒绝原因（探测失败、`missingCapability`、`verifierRejected` 等）。失败不会阻止中继服务——该后端只是在任何字节传输之前拒绝，自动选择顺序（`sockhash`、`splice`、`buffered`）随之回退。

arm 所需权限以探测在运行中的主机上实测为准（`CAP_BPF`/`CAP_NET_ADMIN` 或 root，外加 `RLIMIT_MEMLOCK` 余量），而非凭空假设。arm 本身是事务性的（两个方向要么都安装要么都不安装，失败回滚），并会拒绝借用套接字、已发生传输的中继账本以及仍有排队输入的连接；每条中继按两个方向计入准入。由于重定向会消耗 FIN 而不传播，已 arm 的会话自行检测每个半关闭，等待以 `TCP_INFO` 度量的排空屏障确认没有重定向字节被滞留，然后才用 `shutdown(2)` 传播该半关闭。字节计数采用内核报告的 `TCP_INFO` 差值，在拆除时快照。特权一致性门禁位于 `tests/sockhash_runtime.rs`。

以下为历史故障分析。

### SOCKHASH

已合并的后端创建了 map，`BPF_PROG_LOAD` 以 `EACCES` 失败，将其报告为 `blockedByLsm`，且从未执行 attach 或 update。

`BPF_PROG_LOAD` 返回的 `EACCES` 是**校验器拒绝**的标准 errno，而不是 LSM 拒绝。加载器现在会申请一份有界的 64 KiB 校验器日志，并对 `BPF_PROG_LOAD` 失败使用独立的映射：

| errno | 类别 |
|---|---|
| `EACCES` | `verifierRejected` |
| `EPERM` | `missingCapability` |
| 其他 | 通用映射 |

共发现并修复三处缺陷，其中第三处是通过实测得出的：

1. **上下文偏移量。** `__bpf_md_ptr` 以 8 字节对齐、占用 8 字节存放每个上下文指针，因此 `data`/`data_end` 占据 0..16，其后每个字段都比旧常量假设的位置靠后 8 字节。偏移量 12 落在了 `data_end` 内部，校验器给出 `invalid bpf_context access off=12 size=4`。

2. **键长度。** map 使用 40 字节键，而程序构造的是 16 字节键，导致 helper 的 `ARG_PTR_TO_MAP_KEY` 检查越过帧指针读取。现在由同一个常量同时驱动 map、程序与用户态序列化，程序构造函数也不再接收键长度参数。

3. **程序类型。** `SK_MSG` 挂载在 `sendmsg` 上——即本地应用**发出**的数据。而代理需要的是接收路径。`SK_MSG` 程序可以正常加载与 attach，却不会为被中继的连接对重定向任何字节。后端现已改为 `BPF_PROG_TYPE_SK_SKB` 配合 `BPF_SK_SKB_STREAM_VERDICT`，其上下文为 `__sk_buff`。72 号 helper `bpf_sk_redirect_hash` 从一开始就符合设计意图，不匹配的是程序类型。

**键的推导。** 旧程序构造的是**反转**键，而这只能定位到同一条连接的另一端。代理中继的是两条彼此独立的连接，它们之间不存在元组关系。现在程序只描述自身，由用户态把对端注册到该键上：

```text
map[key(inbound)]  = outbound socket
map[key(outbound)] = inbound socket
```

**键布局**，恰好 40 字节且无填充：

```text
[ 0..16]  本端地址，v4 流量使用 IPv4-mapped 形式
[16..32]  对端地址
[32..36]  本端端口                        (u32，本机字节序)
[36..40]  (family << 16) | 对端端口        (u32，本机字节序)
```

端口为 16 位，因此地址族被放入最后一个字的高半部分。这样既能区分 IPv4-mapped 地址与原生 IPv6 地址，又无需额外花费 1 字节加 3 字节填充。全部 40 字节在使用前均被清零，因此校验器的任何路径都不会看到未初始化的栈。

`__sk_buff.local_port` 以主机字节序到达。`remote_port` 则以网络字节序的 16 位端口出现在 32 位字的高半部分，需要右移并做字节交换。

IPv6 使用独立分支，以 4 字节为单位读取 `local_ip6`/`remote_ip6`；上下文会以 `invalid bpf_context access` 拒绝 8 字节访问。

### io_uring

`crates/rr-linux/src/uring.rs` 中的驱动可以编译，但只在其自身的测试中被构造。`TcpRelay::run_backend` 会拒绝 io_uring，`automatic_preference()` 也未包含它。启动报告不应被理解为生产流量正在使用它。

之所以将其排除在自动选择之外，是因为目标主机上没有保留下来的实测数据支持这一选择，而规范禁止引入推测性的分类器。

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

任何事件都不携带目标地址、SNI、UUID、密钥或负载内容。校验器日志仅出现在显式的诊断与测试输出中，且限制为 64 KiB。
