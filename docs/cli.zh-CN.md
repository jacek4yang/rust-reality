# 命令行参考

[English](cli.md) | 简体中文

## 通用行为

```text
rust-reality [--help] [--version] <COMMAND>
```

主要机器可读或生成结果写入 stdout，诊断信息写入 stderr。生成公网 REALITY
服务端的命令会把包含私钥的服务器 JSON 写入 stdout，把供客户端使用的 REALITY
公钥写入 stderr，必须分别重定向。

每一级命令都支持 `--help`。成功返回退出码 0；配置、I/O、网络、运行时和基准
失败返回非零且不会打印秘密值。Clap 会报告无效语法或越界参数并输出对应 usage。

## 服务与验证命令

### `serve`

```text
rust-reality serve --config <PATH>
```

在前台加载、验证、编译并绑定生产服务。处理 SIGINT/SIGTERM 优雅退出和 SIGHUP
原子热更新。提供的 systemd unit 使用此命令。

| 选项 | 必填 | 含义 |
| --- | --- | --- |
| `-c, --config <PATH>` | 是 | 严格 JSON 配置文件。 |

### `run`

```text
rust-reality run --config <PATH>
```

`serve` 的完全等价别名，方便服务管理器使用常见的 `run` 命名。

### `check`

```text
rust-reality check --config <PATH>
```

最多读取 4 MiB，解析严格 JSON，拒绝未知字段，并验证所有字段和引用。不会下载
资产、探测目标或绑定端口。成功时输出 `configuration PATH is valid`。

### `self-test`

```text
rust-reality self-test --config <PATH>
```

执行 `check`，下载或条件重验证所需 Geo 资产，完成解析和路由编译，并为每一个
REALITY target/SNI 组合执行真实 TLS 1.3 兼容探测。不会绑定监听端口。JSON 报告
包含配置、资产、路由和目标结果。

配置中的通配符模式绝不会作为 SNI 发送。只有 target hostname 与通配符匹配时，
`self-test` 才从目标导出具体 SNI；例如 `www.lmu.edu:443` 可以探测 `*.lmu.edu`。

启用或重启服务前应在部署机器执行，因为网络路径和目标行为可能与开发机不同。

### `probe-dest`

```text
rust-reality probe-dest \
  --target <HOST:PORT> \
  --server-name <DNS_NAME> \
  [--timeout-ms <MILLISECONDS>]
```

发送临时 TLS ClientHello，验证真实伪装目标能否返回有界、严格可解析且适用于
REALITY 的 TLS 1.3 ServerHello。

| 选项 | 必填 | 默认值/范围 | 含义 |
| --- | --- | --- | --- |
| `--target <HOST:PORT>` | 是 | — | 含端口的目标；IPv6 字面量必须加方括号。 |
| `--server-name <DNS_NAME>` | 是 | — | ClientHello 中发送的 ASCII DNS SNI。 |
| `--timeout-ms <N>` | 否 | `5000`，`1..=60000` | DNS/连接/写入/ServerHello 工作使用的独立绝对上限。 |

JSON 结果只证明该目标当时的兼容性，不能保证目标以后永远不改变行为。
`probe-dest` 必须使用具体 DNS 名；通配符只是服务端匹配模式，不是合法 ClientHello SNI。

## 配置命令

### `config generate standalone`

```text
rust-reality config generate standalone \
  [--listen <IP>] [--port <PORT>] \
  --target <HOST:PORT> --server-name <DNS_NAME>
```

生成一个公网 VLESS + REALITY + Vision 入站、一个 UUID、一对 REALITY X25519
密钥、归该 UUID 独占的两个 short ID，以及 direct 出站和用户策略。

| 选项 | 必填 | 默认值 | 含义 |
| --- | --- | --- | --- |
| `--listen <IP>` | 否 | `0.0.0.0` | 公网绑定地址；未指定值会生成入站 `listen.mode: auto` 及独立 IPv4/IPv6 套接字。 |
| `--port <PORT>` | 否 | `443` | 公网 TCP 端口，`1..=65535`。 |
| `--target <HOST:PORT>` | 是 | — | REALITY 伪装目标。 |
| `--server-name <DNS_NAME>` | 是 | — | 客户端 SNI 和允许的服务名。 |

规范 JSON 写入 stdout；`REALITY public key for the client: ...` 写入 stderr。

### `config generate line`

```text
rust-reality config generate line \
  [--listen <IP>] [--port <PORT>] \
  --target <HOST:PORT> --server-name <DNS_NAME> \
  --nxr-address <HOST> [--nxr-port <PORT>] --nxr-key <BASE64>
```

生成相同的安全公网入站，并加入 NXR、direct 和 blackhole 出站。生成 UUID 默认
使用 NXR 落地出站。

| 附加选项 | 必填 | 默认值 | 含义 |
| --- | --- | --- | --- |
| `--nxr-address <HOST>` | 是 | — | 线路机可访问的落地机地址。 |
| `--nxr-port <PORT>` | 否 | `7443` | 防火墙限制的 NXR TCP 端口。 |
| `--nxr-key <BASE64>` | 是 | — | `node-keygen` 生成的 URL-safe 无填充 32 字节 PSK。 |

### `config generate landing`

```text
rust-reality config generate landing \
  [--listen <IP>] [--port <PORT>] --nxr-key <BASE64>
```

生成内部 NXR 监听和 direct 出站，不包含公网 VLESS、REALITY、Vision 或 TLS 状态。

| 选项 | 必填 | 默认值 | 含义 |
| --- | --- | --- | --- |
| `--listen <IP>` | 否 | `0.0.0.0` | 内部绑定地址；生成的 `auto` 策略会把未指定地址展开成独立 IPv4/IPv6 套接字。 |
| `--port <PORT>` | 否 | `7443` | 内部 NXR TCP 端口。 |
| `--nxr-key <BASE64>` | 是 | — | 与线路机 NXR 出站相同的 PSK。 |

### `config generate handoff`

```text
rust-reality config generate handoff \
  [--listen <IP>] [--port <PORT>] \
  --server-address <HOST> --target <HOST:PORT> --server-name <DNS_NAME> \
  --landing-address <HOST> [--landing-port <PORT>] --output-dir <DIR>
```

一步生成完整的 Handoff 部署：`line.json`（公网 VLESS + REALITY + Vision
线路机，用户默认路由到 handoff 出站）、`landing.json`（防火墙限制的内部
handoff 监听器）和 `xray-client.json`（面向线路机的 SOCKS 入站 Xray 客户端）。
所有密钥材料均独立生成：UUID、REALITY X25519 密钥对、归该 UUID 独占的两个 short ID、
Handoff 预共享密钥，以及落地机的静态 X25519 密钥对。两个服务器配置在写入前
都会通过完整校验。

| 附加选项 | 必填 | 默认值 | 含义 |
| --- | --- | --- | --- |
| `--server-address <HOST>` | 是 | — | 客户端拨号的线路机公网地址。 |
| `--landing-address <HOST>` | 是 | — | 线路机可访问的落地机地址。重复该标志即生成多落地部署。 |
| `--landing-port <PORT>` | 否 | `7443` | 防火墙限制的 Handoff TCP 端口。多落地时可只传一个端口应用于全部落地机，或按地址逐一重复。 |
| `--output-dir <DIR>` | 是 | — | 三个文件的写入目录。 |

三个文件路径写入 stdout；`REALITY public key for the client: ...` 和
`UUID for the client: ...` 写入 stderr。Handoff PSK 和私钥只存在于两个
服务器文件中。

重复 `--landing-address` 时生成多落地部署：

```shell
rust-reality config generate handoff \
  --server-address line.example.com \
  --target cover.example.com:443 \
  --server-name cover.example.com \
  --landing-address 10.0.0.2 --landing-port 7443 \
  --landing-address 10.0.0.3 --landing-port 7443 \
  --output-dir handoff/
```

此时写出 `line.json`、`landing-1.json`、`landing-2.json` 和
`xray-client.json`（单落地仍使用不带序号的 `landing.json`）。线路机为每个
落地机分配一个 UUID，并把每个 UUID 的用户组路由到对应落地的 handoff 出站
（`landing-1`、`landing-2`……）；每对落地的密钥材料相互独立，所有服务端文件
在写出前都经过校验。`xray-client.json` 保持单 UUID 形态，使用第一个落地的
UUID——是否把其余 UUID 分配给客户端由运维自行决定。

### `config autotune`

```text
rust-reality config autotune \
  --config <INPUT.json> --output <TUNED.json> \
  [--report <REPORT.json>] [--scratch-directory <DIR>] \
  [--duration-ms <N>] [--warmup-ms <N>] \
  [--storage-mib <N>] [--network-mib <N>] [--dedicated]
```

执行有界的本机协议、机器/cgroup、存储和 TCP loopback 探测，然后写出经过
完整校验的调优副本及测量报告。输入文件永不修改；输出文件权限为仅所有者
可读写（`0600`），并通过同目录原子 rename 发布。先发布报告，最后发布已
校验配置。

| 选项 | 必填 | 默认值/范围 | 含义 |
| --- | --- | --- | --- |
| `-c, --config <PATH>` | 是 | — | 现有有效配置；凭据、监听、路由、超时和日志保持不变。 |
| `-o, --output <PATH>` | 是 | — | 调优配置路径；必须与输入、报告路径不同。 |
| `--report <PATH>` | 否 | `<OUTPUT>.report.json` | 可审计的完整测量与最终所选 policy。 |
| `--duration-ms <N>` | 否 | `900`，`90..=30000` | 每个协议 case 的测量时间。 |
| `--warmup-ms <N>` | 否 | `100`，`1..=10000` | 每个协议 case 的预热时间。 |
| `--storage-mib <N>` | 否 | `32`，`1..=256` | 在 scratch 目录中写入、同步并读取的数据量。 |
| `--network-mib <N>` | 否 | `32`，`1..=256` | TCP loopback 每个方向的传输量。 |
| `--scratch-directory <DIR>` | 否 | 操作系统临时目录 | 有界存储探测要测量的文件系统。 |
| `--dedicated` | 否 | 关闭 | 同时把副本切换为 `runtime.resourceMode: "dedicated"`；仅在 rust-reality 独占主机或 cgroup 时使用。 |

自动调优只改变 resource governor、Direct 拨号和中继策略；不会替你选择安全
协议、UUID/short ID 归属、伪装目标、路由或超时策略。审查 diff 与报告，执行
`check`，再按正常重启流程部署。详见
[调优指南](tuning.zh-CN.md#自动测量的起始策略)。

### `config format`

```text
rust-reality config format --config <PATH>
```

验证完整文件并把确定性的规范美化 JSON 写入 stdout，不会原地编辑输入文件。
应重定向到新文件，审查后再原子替换。

### `schema`

```text
rust-reality schema > rust-reality.schema.json
```

输出完整 JSON Schema。Schema 描述结构和枚举；跨引用与安全不变量必须使用
`check` 验证。

## 身份与密钥命令

### `uuid`

```text
rust-reality uuid [COUNT]
```

使用操作系统熵，每行输出一个 RFC 4122 version 4 UUID。`COUNT` 默认 1，范围
`1..=1024`。

### `x25519`

```text
rust-reality x25519
```

输出包含 `privateKey` 与 `publicKey` 的 JSON，均采用 URL-safe 无填充 base64。
私钥只放在服务器配置，公钥提供给 Xray 客户端。

### `mldsa65`

```text
rust-reality mldsa65 [--seed <BASE64>]
```

生成兼容 Xray 的 ML-DSA-65 seed 和 verification key。没有 `--seed` 时使用系统熵
生成新的 32 字节 seed；传入时必须由 URL-safe 无填充 base64 解码为恰好 32 字节。
JSON 输出包含 `seed` 与 `verify`。这是兼容性/密钥工具，当前服务端配置没有
ML-DSA 字段。

### `node-keygen`

```text
rust-reality node-keygen
```

输出包含独立 32 字节 URL-safe 无填充 `preSharedKey` 的 JSON，用于一个 NXR
信任关系。不要复用 REALITY 密钥、密码，也不要让无关线路机/落地机共享 NXR 密钥。

## 性能命令

### `benchmark`

```text
rust-reality benchmark \
  [--duration-ms <MILLISECONDS>] \
  [--warmup-ms <MILLISECONDS>]
```

执行有界的进程内热点测量并输出适合归档和同机对比的 JSON。

| 选项 | 默认值/范围 | 含义 |
| --- | --- | --- |
| `--duration-ms <N>` | `1000`，`90..=30000` | 每个 case 请求的测量时间。 |
| `--warmup-ms <N>` | `250`，`1..=10000` | 每个 case 的预热时间。 |

报告包含嵌入 commit、构建/目标信息、计时、操作数、均值和样本分位数。它不是
互联网吞吐测试；详见[基准策略](benchmarks.zh-CN.md)。

## 信号与原子热更新

| 信号 | 行为 |
| --- | --- |
| SIGINT / SIGTERM | 停止接收新工作并执行有界优雅退出。 |
| SIGHUP | 从原路径加载、验证并编译完整候选配置，然后原子发布。 |

SIGHUP 失败时继续使用当前 generation；已有连接保留启动时的 generation。监听拓扑、
`runtime` 设置、resource governor、direct barrier、relay 策略和 NXR 重放缓存容量/保留时间必须重启；详见
[配置参考](configuration.zh-CN.md#热更新边界)。
