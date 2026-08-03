# 基准策略与基线

[English](benchmarks.md) | 简体中文

## 内置协议测量

在空闲主机运行优化二进制：

```shell
./scripts/build-release.sh
target/release/rust-reality benchmark \
  --duration-ms 5000 \
  --warmup-ms 1000 \
  > benchmark.json
```

JSON 记录构建模式、嵌入 commit、目标 OS/架构、可见 CPU 数、请求时间、操作数、
总均值和每样本 p50/p95。每个 case 使用九个独立窗口。MiB/s 表示命名进程内操作的
逻辑输入吞吐，不是 socket、代理或互联网吞吐。

Criterion 用于带基线和图表的回归分析：

```shell
cargo bench --bench vless_decode
cargo bench --bench vision
```

## 已记录的开发机样本

该样本证明命令能运行并产生稳定有界数据，不是 Release 性能承诺：

- 日期：2026-08-03（Asia/Shanghai）
- 主机：Intel Core i3-8100，4 个逻辑 CPU
- 内核：Linux 6.12.94+deb13-amd64
- Rust：1.96.0
- 每个 case 测量 900 ms，预热 100 ms
- `vless.decode.ipv4`：26.99 ns/op，3706 万 ops/s
- `vision.decode.8k`：164.93 ns/op，606 万 ops/s
- `nxr.auth.encode.domain`：1237.62 ns/op，80.8 万 ops/s

做对比时应保存完整 JSON，在相同主机、CPU governor、内核、目标、载荷、并发和
网络损伤条件下随机化实现顺序并重复运行。报告全部样本和置信区间，不能只选最快结果。

## Xray 兼容性与性能的区别

`scripts/test-xray-interop.sh` 是兼容性门禁：未经修改的 Xray 26.7.28 客户端通过
真实公网 VLESS + REALITY + Vision 栈传输校验载荷。它的一次互联网请求不是基准。

未来的 Xray 性能比较必须分别测量：

- loopback 协议 CPU 成本；
- 固定并发下同机 relay 吞吐；
- 使用 `tc netem` 控制延迟、丢包和速率的测试；
- 完整披露 DNS、源站和互联网方差的真实网页样本。

任何结果都不能声称抵御上游流量型 DDoS，也不能把一台 VPS 的结果外推到其他 CPU
和网络。

## 已记录的 Xray 26.7.28 loopback 对比

`scripts/benchmark-xray.sh` 使用同一个未经修改的 Xray SOCKS5 客户端，分别经
VLESS + REALITY + Vision 连接两个服务端。脚本记录随机种子并随机化实现顺序，
验证每个响应长度，保留所有样本并输出机器可读 JSON。为了让两个服务端访问相同
loopback 源站，只在基准中显式覆盖 Xray 新版默认阻止私网目标的规则。

2026-08-03 记录环境：Linux 6.12.94、rustc 1.96.0、Xray 26.7.28、Intel
Core i3-8100（4 核）、REALITY 目标 `dl.google.com:443`、每个实现 9 个样本、
每请求 64 MiB：

| 并发 | 实现 | 平均 MiB/s | p50 MiB/s | 最低 MiB/s | 平均请求秒数 |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 | rust-reality | 266.56 | 259.34 | 231.38 | 0.2339 |
| 1 | Xray | 252.34 | 245.58 | 220.31 | 0.2481 |
| 4 | rust-reality | 762.57 | 799.18 | 616.96 | 0.3159 |
| 4 | Xray | 701.17 | 708.35 | 429.75 | 0.3390 |

并发 1 和 4 时 rust-reality/Xray 的 p50 吞吐比为 1.056 和 1.128。这是在该主机
上测得的小幅领先，不是数倍提升。共享的 Xray 客户端和 Python 源站仍在两组路径中，
所以该比较既没有隔离服务端 CPU，也没有测得网卡极限。

该主机没有可用的 `tc netem` 或同类特权网络损伤设施，因此结果不包含弱网结论。
延迟、丢包、乱序和限速必须在受控接口上采集，不能用未执行的模拟冒充数据。

复现任一 profile：

```shell
SAMPLES=9 CONCURRENCY=1 PAYLOAD_MIB=64 \
  XRAY_BIN=/home/jacek/src/Xray-core/xray \
  ./scripts/benchmark-xray.sh > xray-c1.json

SAMPLES=9 CONCURRENCY=4 PAYLOAD_MIB=64 \
  XRAY_BIN=/home/jacek/src/Xray-core/xray \
  ./scripts/benchmark-xray.sh > xray-c4.json
```
