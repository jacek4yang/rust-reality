# 性能

[English](performance.md) | 简体中文

本文记录 v1.0.0 数据平面的实测性能属性以及每项设计决策背后的证据。除非另有
说明，数字均在验证主机上测得：Intel Core i3-8100（4C/4T @ 3.60 GHz）、
16 GiB 内存、Debian 13、**Linux 6.12.94+deb13-amd64**、rustc 1.96.0、loopback
对编译的 Go 源站、未经修改的 Xray 26.7.28 客户端。loopback 让服务端、客户端
和源站共享主机 CPU；这些数字描述的是实现成本，绝不是互联网吞吐。冻结的
v1.0.0 发布对比矩阵见
[benchmarks.zh-CN.md](benchmarks.zh-CN.md)。

## framed 路径成本分解

对 ring 之前构建的稳态 framed profile（仅已建立连接，不含 setup）中服务端
CPU 的分解：

| 类别 | 下行占比 | 上行占比 |
|---|---:|---:|
| AEAD（AES-128-GCM seal/open，RustCrypto 基线） | ≈51% | ≈39% |
| 内核边界（read/write/copy_user、页面清零、TCP 栈） | ≈47% | ≈57% |
| tokio 调度/定时器、Vision framing、记录解析、libc memcpy | 合计 <2% | 合计 <2% |

内核边界数字——包括 `clear_page` 首次触碰清零的占比（约占下行 CPU 的
3.9%）——特定于上述验证主机与内核（启用 `init_on_alloc` 的 Linux 6.12，因此
已释放页面的清零以内联方式出现）。它们描述的是该内核在该负载下的行为，不能
推广到其他内核、主机或 `init_on_alloc` 配置。

两个结论均由测量固定：

- **消除拷贝不是 framed 的机会。** 拷贝拓扑审计（源码 + profile）表明所有稳态
  路径上每载荷字节都没有可避免的用户态拷贝；framed 路径只剩两次不可约的
  系统调用边界拷贝，splice 路径完全不触碰用户态字节。libc memcpy 约占
  framed CPU 的 0.15%。
- **AEAD 是唯一的大用户态杠杆。** 按实测比例做 Amdahl 上限：AEAD 快 2.5 倍
  时端到端 framed 增益上限约为下行 1.44× / 上行 1.31×（服务端 CPU 受限
  模型）；AEAD 无限快时上限为 2.04×/1.63×。内核边界是限制一切 AEAD 收益的
  下限。

## 记录 AEAD 提供者：默认 ring

默认构建中，TLS 1.3 `TLS_AES_128_GCM_SHA256` 记录保护由 **ring**（源自
BoringSSL 的 C/汇编，静态链接）提供。使用 `--no-default-features` 构建则选择
纯 Rust 的 RustCrypto aes-gcm 提供者，没有其他行为差异；逐字节跨提供者等价性
和 RFC 8448 向量由两种配置下都会运行的测试保证。安全取舍（扩展密钥调度清
零）记录在 [SECURITY.zh-CN.md](../SECURITY.zh-CN.md)。

实测证据（上述验证主机）：

- 生产 16 KiB 记录下的独立 AES-128-GCM：ring seal 5.16 GiB/s，RustCrypto
  2.03 GiB/s——**约 2.5×**，且从 64 B 到 32 KiB 的每个记录尺寸都领先。
- 端到端 framed loopback（219 个有效样本、0 个无效、完整性校验一致）：ring
  在全部 16 个 cell 中 ≥ RustCrypto；512 MiB cell 提升 **1.05–1.16×**。低于
  Amdahl 上限是因为 loopback 吞吐受主机 CPU 共享限制；下面的每 GiB 服务端
  成本才是可迁移的测量。
- 每 GiB framed 下行的服务端成本：task-clock **−33%**（631 vs 940 ms/GiB），
  指令数 −30%，上下文切换 −39%；RSS +3%（噪声）。
- 同一矩阵下对比 Xray 26.7.28，ring 让 framed 512 MiB cell 达到 1.04–1.12×
  （RustCrypto 时为 0.95–1.12× 不等）：Xray 的记录 AEAD 是 Go 的缝合
  AES-NI+PCLMULQDQ 汇编，16 KiB 下约 4.8 GiB/s，因此这次提供者更换弥补的是
  实现质量差距，而不是特性探测缺失。
- 供应链：零新增依赖 crate（ring 已经由 ureq/rustls 存在于发布依赖图），完全
  静态链接，二进制体积还略小。

## raw relay 与 fallback

- 在 raw relay 测试面上（方向 × 载荷 × 并发），splice 在每个实测并发度上同时
  在吞吐和 CPU/GiB 上胜过 buffered 后端；64 KiB 缓冲比 32 KiB 好 2–12%，但仍
  全面低于 splice。因此 splice 全面优先，buffered 保留为拒绝时的回退。
- 对 Xray 26.7.28/Go 的机制审计解释了对比形态：Xray 的 REALITY **fallback**
  路径使用 readv/writev 64 KiB 用户态拷贝——完全不用 splice——而其 Vision
  下行通过 Go 运行时的 `sync.Pool`（1 MiB 管道池）做 splice（池热后每会话
  约 0 次管道系统调用）。rust-reality 的 `PipePool` 为其 256 KiB 管道消除了
  等价的每会话 pipe2/fcntl/close 抖动。
- 干净的同源 fallback A/B（两侧 warn 级日志）：并发 32 时 splice fallback 为
  Xray 的 1.04–1.05×，task-clock 低 26–35%。更早的 fallback 劣势读数被追溯
  到矩阵 harness 的 debug 级逐连接日志，而不是 relay 路径（见
  [benchmarks.zh-CN.md](benchmarks.zh-CN.md) 的方法一节）。

## 连接 setup

setup 速率模型（accept → REALITY 握手 → VLESS 解析 → 路由 → 出站连接 →
第一次 Vision 转换；不含稳态；上述验证主机，本地 TLS 源站，裸 socket 客户
端）：

| cell | rust-reality | Xray | 比值 |
|---|---:|---:|---:|
| c1 conn/s | 269 | 198 | 1.36× |
| c8 conn/s | 775 | 782 | 0.99× |
| c32 conn/s | 874 | 857 | 1.02× |
| c32 p99 setup 延迟 | 70.8 ms | 84.1 ms | −16% |

c32 下每连接服务端成本：CPU 0.64 vs 1.16 ms（**−45%**），指令数 −30%，上下文
切换 −75%。并发下吞吐持平是因为 4 CPU 主机同时限制了两端；每连接成本列才是
更干净的信号。CPU 优势能否在更大主机上转化为速率优势尚未验证。

## 决策登记（D1–D9）

塑造 v1.0.0 的各项性能决策的一行结论：

- **D1——保留。** reload/资产刷新曾经放大进程级上限；共享 authority 提升为进程
  生命周期所有权。
- **D2——保留。** 让 abort 与干净 FIN 不可区分（abort 路径上的
  `SO_LINGER{on,0}` 加 abort guard）。
- **D3——保留。** DNS 工作有界化：查找池、许可持有覆盖阻塞操作、快速失败、无
  队列。
- **D4——保留。** 内核活性兜底：所有数据 socket 设置 `SO_KEEPALIVE` 30/10/3；
  `TCP_USER_TIMEOUT` 经评估后带理由拒绝。
- **D5——保留。** 内存采样来源显式化；管道容量降级在 relay 结果与连接日志中
  可见。
- **D6——作为原因被证伪，带取舍保留。** PipePool 消除了每会话管道系统调用/FD
  抖动（机制经 strace A/B 确认），但没有改变端到端 fallback 吞吐——splice 调
  用成本不是差距的来源。作为零成本机制保留，不作任何吞吐声明。
- **D7——以删除解决。** sockhash 后端在生产矩阵中从未 arm，特权 A/B 与 splice
  持平，且部署模型永远不具备其所需权限；已移除（约 5400 行）。
- **D8——证伪。** 表面上的 fallback c32 差距来自 harness 的 debug 日志而非
  splice 调用成本；干净 A/B 显示 fallback splice 为 Xray 的 1.04–1.05× 且
  CPU 明显更低。
- **D9——证实，作为默认发布。** framed 路径受 AEAD 限制，ring 在生产记录尺寸
  下约为 RustCrypto 的 2.5×；作为默认记录 AEAD 提供者发布，RustCrypto 回退
  保留并持续测试。

## 已否决的方向（基于证据）

- io_uring：生命周期审计后移除——设计上并非零拷贝、无取消、无会话层；补完它
  等于重写，收益不如 splice。见
  [decisions/0002-io-uring-removed.md](decisions/0002-io-uring-removed.md)。
- 调度器/运行时重设计：Tokio 多线程运行时约占 framed CPU 的 1%；无争用证据。
- Vision framing / 记录解析工作：合计 <1%。
- 短流自适应分类器：没有新证据不做；一直没有找到证据。
