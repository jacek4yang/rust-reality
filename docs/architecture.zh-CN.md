# 架构

[English](architecture.md) | 简体中文

本文描述生产数据平面的结构：连接生命周期、raw relay 内核后端、文件描述符
admission 架构和运行时可观测性。设计背后的实测证据见
[performance.zh-CN.md](performance.zh-CN.md)；基准方法与规范样本见
[benchmarks.zh-CN.md](benchmarks.zh-CN.md)。

## 连接生命周期

1. **Accept。** listener 在 `accept(2)` *之前*获取 FD 预算许可，并对 accept
   错误分类；描述符压力下使用应急保留描述符释放容量。每个连接一个任务。
2. **REALITY。** ClientHello 在有界时限内读取，要么认证成功，要么进入
   fallback。fallback 逐字节精确：已从客户端读取的前缀原样转发到伪装目标，
   已检查的目标前缀回写给客户端，剩余 raw 连接对交给统一 relay
   （`TcpRelay::relay_owned`）——支持 splice、计入 FD 预算，绝不借用用户态
   拷贝。
3. **VLESS + Vision。** 请求从外层 TLS 流解码；路由选择出站；会话拆成两个
   独立的方向任务（上行、下行）。
4. **Framed 阶段。** 两个方向都运行带 Vision padding 的外层 TLS 记录 I/O。
   热路径属性（已测量并有回归门禁）：
   - 每条记录零稳态堆分配（`tls13/allocation_gate.rs` 的计数分配器门禁）；
   - socket 读取每次最多向连接自有、只增不减的缓冲区补充 ≤64 KiB，完整记录
     在缓冲区中原地解析和解密（每次补充一次系统调用，而不是每条记录两次）；
     越过 raw 边界的每个缓冲字节在任何 raw relay 开始前按顺序排空到对端；
   - 每个进度步只注册一次定时器（`IdleDeadline`），绝不对每个数据块新建
     `time::timeout`；空闲语义——有进度就重置窗口，长传输永远不会触发会话
     上限；
   - 外层下行把目标字节直接读入 AEAD 明文区域并原地 seal（只有一次拷贝：
     socket 读取）；
   - raw 模式的 Vision 记录以借用切片透传（没有每条记录 16 KiB 的 memcpy）；
   - 多条 Vision 帧打包进同一条外层 TLS 记录（更少的 AEAD seal 和写入；
     与 Xray 的流解码器线兼容）。
5. **Direct 转换。** 当某个方向到达其已认证的 Direct 边界（上行：客户端
   Direct 命令完整解码且此前全部明文字节已写出；下行：检测到 ServerHello
   之后第一条 TLS 1.3 应用记录，且携带 Direct 的 Vision 帧已完整 seal 并
   写出），该方向**只决策一次**：
   - 对端已在自己的 raw 边界（`RawReady`）或已提交（`PairPending`）→ 本方向
     存放下自己的两半；最后存放的一方把两个完整 socket 重新合并，运行
     **双向** raw relay；
   - 否则 → 本方向认领自己的两半（`Relaying`），立即启动**单向** raw
     relay。

   没有等待对端的 sleep、定时器或 watch channel。对配对唯一的让步是一个有界
   的两次调度让出窗口，让边界报文已在队列中的对端先提交（微秒级；以
   `*_handoff_delay_us` 上报）。方向状态单调（`Framed → DirectPending →
   RawReady → {PairPending, Relaying} → {Closed, Failed}`），从结构上排除了
   分裂脑：观察到 `RawReady`/`PairPending` 的对端不可能再走单向，观察到
   `Relaying` 的对端不可能再加入配对。

   边界不变量（由测试固定）：
   - 未认证或仍在 framed 的字节永远不会到达内核后端；
   - 两侧的读取者每次 socket 读取恰好消费一条 TLS 记录，因此边界之后不会有
     raw 字节滞留在用户态缓冲区；
   - 下行 raw relay 只在最后一次 framed 写入完成后启动；
   - 一旦某方向通过某后端移动过任何 raw 字节，就绝不会再经另一个后端重放
     （`TransferLedger`）。
6. **Raw 阶段后端。** 选择是诚实且基于证据的：

   | 场景 | 顺序 |
   |---|---|
   | 双向配对、socket 完整、未移动任何字节 | splice → buffered |
   | 单个 raw 方向 | 单向 splice → 单向 buffered |

   - **splice**：每个方向一对管道（双向 = 两对），每方向恰好 2 个 FD 单元，
     在 `pipe2` 之前预留。管道请求 256 KiB 容量（尽力而为，低于无特权 1 MiB
     上限），relay 块大小取管道实际容量；内核管道内存按每个配置的 splice
     relay 4 条管道 × 256 KiB 记账。管道由 `PipePool` 池化，稳态会话不再有
     pipe2/fcntl/close 抖动，池化管道绝不会带着未读数据复用。源端 EOF →
     对目标写端优雅 shutdown（每方向保留 half-close）。拒绝（池/FD 预算/
     pipe2 失败）只发生在第一个字节之前。
   - **buffered**：有界池，每方向一个缓冲区，只在分配时清零。

   每个后端只在移动第一个字节之前拒绝，并按上述顺序顺延。传输开始后发生的
   后端错误会终止 relay，绝不重放。
7. **拆除。** 源端 EOF 按同方向关闭目标写端；对端方向不受影响。raw 阶段的
   `BrokenPipe` 或 `ConnectionReset`（良性的对端拆除竞态）会带着累计统计
   干净地关闭该方向，而不是把会话作为协议拒绝处理。

## 热路径拓扑

每连接稳态成本：2 个任务，每条记录零分配，每个进度步一次定时器注册，热路径
无日志。

| 阶段 | 所有者 | 分配 | 原子操作/锁 | 系统调用 | 拷贝 |
|---|---|---|---|---|---|
| accept | 1 任务/listener | 稳态无 | FD 许可 CAS + governor CAS | accept4、setsockopt×4 | 0 |
| REALITY 认证 | 连接任务 | ClientHello 缓冲区（≤16 KiB，一次） | 握手/密码学 CAS 许可、重放缓存分片锁 | 1–3 次读，flight 写 | hello 解析基于借用 |
| fallback | 连接任务 | 前缀 vec（有界） | fallback CAS、FD CAS ×2、connect | connect、前缀写，然后 relay | 仅前缀写 |
| VLESS 请求 | 连接任务 | 请求缓冲区 ≤533+16 KiB，一次 | 0 | TLS 记录 | 0（借用预取） |
| 路由 | 连接任务 | 命中路径 0 | 共享规则（Arc） | 可选有界 DNS（spawn_blocking，信号量槽持有到操作结束） | 0 |
| 出站连接 | 连接任务 | 0 | FD 单元 CAS、direct barrier CAS | connect | 0 |
| Vision framed 上行 | 方向任务 | socket 缓冲区一次（只增） | 循环内 0 | 每次补充 1 读（≤64 KiB）、每记录 1 写 | AEAD 原地 open；Vision 借用解码（0） |
| Vision framed 下行 | 方向任务 | socket 缓冲区一次 | 循环内 0 | 每次补充 1 读、每组打包记录 1 写 | AEAD 原地 seal；Vision 帧打包 |
| Direct 转换 | 两个任务 | 0 | 2 个原子量 + 1 个互斥锁（一次） | 0 | 待排空数据写入 |
| raw relay（splice） | 方向任务 | 0 | 池互斥锁每次取/还（每会话 2 次） | 每块 splice×2；管道系统调用约 0（池化） | 0（内核） |
| raw relay（buffered） | 方向任务 | 池化 32 KiB 缓冲区 | 每会话池互斥锁 + 信号量 | 每块 read+write | 每块 1 次用户态拷贝 |
| 拆除 | 方向任务 | 0 | 状态 CAS | shutdown/close；abort→SO_LINGER+close | 0 |

## 描述符预算

启动时、绑定任何 listener 之前推导：

```text
effective_dynamic_fd_budget = soft_rlimit - fixed_fd_reserve - safety_headroom
```

固定预留刻意取悲观值：

| 组成部分 | 预留 |
|---|---|
| 监听 socket | 每个配置的入站一个 |
| 标准流与日志 sink | 4 |
| 运行时 epoll、eventfd 与 waker | 16 |
| 不可取消的解析器描述符 | 32 |
| 应急保留 | 1 |

解析器描述符按预留而非准入处理，因为被取消的 `TcpStream::connect` 无法取消
其底层阻塞的 `getaddrinfo`；这些描述符的存活期会超过发起它的连接。安全余量在
标准模式下为 `max(soft_limit / 16, 64)`；专用资源模式使用更大的自有余量
（见[配置参考](configuration.zh-CN.md#dedicated-resource-mode)）。

策略：

- 当软限制无法覆盖固定预留加最小可用动态预算 64 单元时**拒绝启动**；错误信息
  给出实测限制和所需值。
- 当配置的峰值超出限制允许范围时**向下钳制并告警一次**。启动时的
  `descriptor_budget_report` 同时给出两个数字以及避免钳制所需的软限制。

任何策略下进程都不会带着无法兑现的配置启动，然后在 `accept4` 里才发现问题。
`maxConnections` 仍是协议层限制；描述符预算更紧时先生效。

`FdBudget` 是严格上界许可计数器：快路径一次 relaxed load 加一次
`compare_exchange_weak`，无互斥锁；许可经 `Drop` 单路径释放；释放使用受检
减法，双重释放会被记录而不是被悄悄吞掉；压力下的等待是有界 `Notify` 唤醒，
绝不是轮询。保守单元成本：入站 socket 1、出站 socket 1、存活连接器候选 1、
双向 splice relay 4。

压力在容量的 15/16 进入、13/16 退出；迟滞间隙避免一批释放后下一次 accept 又
重新进入压力。压力日志按跳变记录。进程绝不为准入轮询 `/proc/self/fd`。

## Listener 恢复

接受连接分三个阶段，失败语义各不相同：`accept → configure → admit`。单连接的
socket 选项失败会关闭该流、释放其许可、发出一条
`connection_rejected{reason:socketConfiguration}` 并继续接受。

accept 错误按原始 `errno` 分类：

| 类别 | errno | 响应 |
|---|---|---|
| `wouldBlock` | `EAGAIN` | 重试，不记日志 |
| `transient` | `EINTR`、`ECONNABORTED`、`EPROTO`、`ECONNRESET`、`ENETDOWN`、`ENETUNREACH`、`EHOSTDOWN`、`EHOSTUNREACH`、`ENONET`、`ETIMEDOUT`、`EPERM` | 立即重试，有界日志 |
| `descriptorPressure` | `EMFILE`、`ENFILE` | 应急 FD 恢复，退避，绝不终止 |
| `memoryPressure` | `ENOBUFS`、`ENOMEM` | 有界指数退避 |
| `fatal` | `EBADF`、`ENOTSOCK`、`EOPNOTSUPP`、`EINVAL`、`EFAULT` | 仅终止该 listener，附带 errno |
| `unknown` | 其他 | 退避重试 |

退避从 5 ms 开始翻倍，上限 500 ms；第一次成功 accept 后重置。

进程生命周期内会在 `/dev/null` 上常驻打开一个描述符作为应急保留。准入只约束
本进程记账的部分；库、解析器线程或其他进程仍可能对着共享的 `ENFILE` 限制消耗
描述符。发生意外 `EMFILE` 时：释放保留描述符，在 1 ms 限时内尝试一次 accept，
立即关闭接受的 socket，然后重新获取保留。对端观察到的是关闭而不是挂起。这是
最后手段，不能替代正确的准入。

## splice 描述符

双向 splice relay 创建两对管道；4 个 FD 单元在 `pipe2` *之前*获取，许可与管道
由同一对象持有。单元不可用时后端拒绝——这是安全的，因为拒绝发生在任何字节
传输之前，调用方可以顺延到 buffered 后端而不重放连接。第二对管道失败时，第一
对会被关闭并释放全部 4 个单元。

## 已移除的内核 relay 后端

- **sockhash**：已移除。它在所有生产基准矩阵中从未 arm，特权 A/B 测试显示与
  splice 持平，无特权生产部署模型永远无法 arm。仍然设置 `sockhash`、
  `maxSockhashRelays` 或 `maxPinnedMemoryBytes` 配置键会作为未知字段校验失败。
- **io_uring**：已移除，未实现。理由见
  [decisions/0002-io-uring-removed.md](decisions/0002-io-uring-removed.md)。
  仍然设置 `ioUring` 或 `maxIoUringRelays` 配置键会作为未知字段校验失败。

自动后端顺序为 splice → buffered；可移植的 buffered relay 和 Linux `splice`
不需要额外权限。

## 资源治理

每种类别的静态准入信号量（连接、握手、密码学、fallback）加上带压力迟滞的
无锁 FD 预算在所有模式下都存在。`runtime.resourceMode: "dedicated"` 增加
机器感知预算和二维（FD + 内存）压力模型；见
[配置参考](configuration.zh-CN.md#dedicated-resource-mode)。

## 可观测性

| 事件 | 时机 |
|---|---|
| `relay_backend_report` | 启动一次：每个后端一行（已配置/受支持/运行时就绪/拒绝原因） |
| `descriptor_budget_report` | 启动一次；打印推荐软限制 |
| `machine_report` | 启动一次，仅专用资源模式 |
| `descriptor_pressure_changed` | 描述符压力跳变时，绝不按 accept 记录 |
| `resource_pressure_changed` | 组合状态跳变时，绝不按采样记录 |
| `accept_error_recovered` | 可恢复的 accept 错误，附原始 errno |
| `connection_rejected` | 每个被拒绝连接，原因来自封闭词表 |
| `admission_limited` | 每个被限制或压力状态拒绝的类别 |
| `connection_completed`（debug） | 每连接：字节数、按方向的 Direct 标志、选中的后端、交接延迟 |

任何事件都不携带目标地址、SNI 值、UUID、密钥或载荷。
