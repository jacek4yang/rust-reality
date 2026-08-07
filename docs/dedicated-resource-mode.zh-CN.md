# 专用机器资源模式

本文档说明 `runtime.resourceMode`：专用模式在启动时检测什么、改变什么，
精确的预算算法，以及使进程保持在推导出的内核与 cgroup 限制之下的
压力模型。

## 1. 模式是什么

```json
{ "runtime": { "resourceMode": "dedicated" } }
```

只有两个取值，没有其他字段：

| 取值 | 含义 |
|---|---|
| `standard` | 默认值。所有预算都从继承的进程限制推导；进程不假设机器上运行着什么。行为与历史行为完全一致。 |
| `dedicated` | 进程声明自己独占这台机器——或在容器运行时下独占其 cgroup。它按实测的机器资源做预算，并监督自身的内存压力。 |

该模式是**冷设置**。它影响进程生命周期的描述符预算、软限制提升和内存
监控器，因此通过 SIGHUP 热更新修改它会被拒绝
（`the runtime resource mode requires a process restart`）；最后一个
完好的 generation 继续运行。

## 2. 启动检测

在专用模式下，进程在绑定任何监听之前检测一次：

* `RLIMIT_NOFILE` 的软限制与硬限制；
* `RLIMIT_MEMLOCK` 的软限制与硬限制（仅为运维可见性上报，不由此推导预算）；
* 当前进程的 cgroup v2（`/proc/self/cgroup` + `/sys/fs/cgroup`）：
  `cpu.max`、`cpuset.cpus.effective`、`memory.current`、`memory.high`、
  `memory.max`——字面值 `max` 视为无界；任何缺失或不可读的文件降级为
  “不上报”，绝不编造数值；
* cgroup 文件缺失时的回退：`/proc/meminfo` 的 `MemTotal` 与进程可见的
  CPU 数量；
* 内核 relay 后端能力摘要，即已有的 `relay_backend_report`。

以上全部在 info 级别以一条结构化 `machine_report` 事件上报。任何字段
都不可能携带目标、对端或配置值。一次真实启动如下：

```json
{"event":"machine_report","resource_mode":"dedicated","fd_soft_limit":4096,
 "fd_hard_limit":524288,"fd_effective_soft_limit":524288,
 "fd_soft_raise_attempted":true,"fd_soft_limit_raised":true,
 "memlock_soft_limit":8388608,"memlock_hard_limit":8388608,
 "available_cpus":4,"cpu_period_us":100000,"memory_source":"cgroup_v2",
 "memory_current":9432547328,"memory_total":16192278528}
```

### 软限制提升

当 `RLIMIT_NOFILE` 硬限制高于软限制时，专用模式通过 `setrlimit(2)` 把
**进程自身的**软限制提升到硬限制。这不需要特权，也不触碰调用进程之外
的任何事物。上面的例子就是一次以 `ulimit -Sn 4096` 启动的真实运行：
提升生效，描述符预算按生效后的 524 288 推导。

提升失败不是致命错误。报告记录 `fd_soft_raise_attempted: true` 且
`fd_soft_limit_raised: false`，推导按生效的软限制继续进行。

## 3. 预算推导

### 描述符

```text
effective_dynamic_fd_budget = effective_soft_limit - fixed_reserve - headroom
```

固定预留与标准模式完全相同（监听 socket、标准流与日志、运行时 reactor、
不可取消的解析器描述符、应急预留）。只有余量策略不同：

| 模式 | 安全余量 | 结果 |
|---|---|---|
| `standard` | `max(limit / 16, 64)` | 约 94% 的限制减去预留可被 admission |
| `dedicated` | `max(limit / 10, 64)` | 约 90% 的限制减去预留可被 admission |

专用模式的余量是*更大*而非更小：进程按提升后的限制做规划，并保留十分
之一给无法核算的描述符消费者——库、解析器线程、内核侧 socket。
`budget + reserve + headroom <= effective_soft_limit` 这一不变量在两种
策略下都成立，并在全部限制范围内有测试覆盖。

各资源成本不变，并在获取资源的位置精确核算：每个入站 socket 一个单位，
每个出站 socket 一个单位，每个单向 splice 两个单位，每个双向 splice
relay 四个单位。专用模式不重复核算。

### 内存

有效内存总量是设置了有限值时的 cgroup `memory.max`（以 `MemTotal`
封顶），否则是 `MemTotal`。两者都不可读时总量为零，内存维度被禁用而
非编造。所有水位线都是该总量的分数：

| 边界 | 占总量比例 | 理由 |
|---|---|---|
| 可用预算 | 80% | 五分之一留给内核、socket 缓冲和运行时自身，这些都无法按分配核算 |
| pressure 进入 | 60% | 可用预算的四分之三 |
| pressure 退出 | 50% | 十个百分点的迟滞间隔 |
| critical 进入 | 90% | 低于 cgroup/机器硬限制，且足够早，拒绝新工作仍能改变曲线 |
| critical 退出 | 80% | 恰好是可用预算：只有回到自己的配额之内才恢复新工作 |

每一层都有独立的进入与退出水位线，因此在任何单一阈值附近振荡的用量
不会产生状态抖动。升级与恢复每次采样都只移动一层。

## 4. 压力模型

两个维度合成一个有效状态：

* **描述符**——现有的 `FdBudget` 水位线（高水位为容量的 15/16，低水位
  为 13/16）。描述符 `High` 映射到 `Pressure` 层；预算本身就是硬阻断，
  因此描述符维度不需要 `Critical` 层。
* **内存**——一个监控任务，每秒采样一次 cgroup `memory.current`
  （回退：`/proc/self/statm` 的常驻集大小），按上述水位线推进状态。

有效状态取各维度中最差者，以单个原子值发布。监控器是唯一写入者；读取
路径只是一次原子加载。数据路径附近没有任何全局互斥锁，也没有任何在
read、write 或 record 循环中的采样。采样不可读时保持前一状态——监控
缺口本身绝不会触发或解除告警。

### 优先级

| 状态 | 新 fallback | 新握手 | 新连接 accept | 新 direct 出站拨号 | 已建立流量 |
|---|---|---|---|---|---|
| `Normal` | 允许 | 允许 | 允许 | 允许 | 正常 |
| `Pressure` | **拒绝** | **拒绝** | 允许 | 允许 | 正常 |
| `Critical` | 拒绝 | 拒绝 | **暂停 / 快速失败** | **快速失败** | 正常 |

顺序是刻意的：首先削减 fallback 工作，其次是新的未认证建立过程，只有
到 `Critical` 才暂停所有新类别。已持有的许可绝不会被收回，因此已建立
的认证 relay 和普通 relay 流量在两个压力层中都继续运行。在监听器停在
`accept` 内时撞上 `Critical` 转换的连接会被立即关闭，并以
`connection_rejected{reason:resource_limit}` 上报一次；随后监听器停在
`Notify` 唤醒上——绝不是轮询循环——并在迟滞退出发布更低状态时自动
恢复。任何状态下关闭都保持迅速。

校准与基准工作在本代码库中是独立进程（`benchmark` 子命令）；它不需要
运行时钩子，也没有。

## 5. 该模式绝不做什么

* 绝不触碰 sysctl、cgroup 文件、其他进程或硬资源限制。专用启动路径中
  唯一的变更，是把进程自身的 `RLIMIT_NOFILE` 软限制提升到硬限制。
* 绝不允许超出推导预算。专用余量放宽的是*默认*比例；
  `budget + reserve + headroom <= limit` 不变量不变。
* 绝不为“利用”机器而空转 CPU，绝不预分配不需要的内存，也不运行任何
  后台“优化”工作。唯一的周期任务是每秒一次的内存采样。
* 绝不轮询 `/proc/self/fd`，绝不在 accept 路径上数描述符，也绝不会为
  持续的压力状态按连接记日志。

## 6. 运维指引

当进程是机器、VM 或 cgroup 的单一租户时使用 `dedicated`——标准的
standalone 和 line/landing 部署都属于此类。当其他不可预测的工作负载
共享同一描述符限制或内存 cgroup 时，保持 `standard`。

该模式不能替代 unit 文件。请在 systemd unit 中保留 `LimitNOFILE=`：
提升只能达到*继承的*硬限制，而硬限制由服务管理器设置。启动时的
`descriptor_budget_report` 仍会打印推荐值，`machine_report` 会显示
提升是否起了作用。

如果报告中 `memory_total` 为 `0`，说明主机既不暴露 cgroup v2 内存限制
也不暴露 `MemTotal`；描述符维度仍然有效，但不存在内存水位线。请把这
当作需要修复的监控缺口，而不是余量。

## 7. 可观测性

| 事件 | 时机 |
|---|---|
| `machine_report` | 启动时一次，仅专用模式 |
| `descriptor_budget_report` | 启动时一次，两种模式都有 |
| `descriptor_pressure_changed` | 描述符压力转换时，绝不按 accept |
| `resource_pressure_changed` | 合成状态转换时，绝不按采样 |
| `connection_rejected{reason:resource_limit}` | 每个在暂停期间被拒绝的连接 |
| `admission_limited` | 每个被限制或压力状态拒绝的类别 |

一次持续的压力状态只产生两条 `resource_pressure_changed`（进入、
退出），无论持续多久。
