# Linux 部署

[English](deployment.md) | 简体中文

本指南使用官方 Linux Release（x86_64 或 aarch64）部署单机公网节点、线路机，
或受防火墙限制的 NXR 落地机。

## 环境要求

- 64 位 Linux 和现代内核；提供的 unit 需要 systemd。
- 安装、服务账号、防火墙和特权端口所需的 root 权限。
- 公网节点、线路机、落地机和客户端都必须保持正确系统时间。
- 一个能从公网节点通过 `probe-dest` 的 REALITY 伪装目标。
- NXR 使用固定/私有线路机到落地机路径，或只允许线路机固定源 IP 的防火墙。

二进制需要出站 DNS/TCP、资产缓存写权限，以及可选文件日志目录写权限；不需要
运行时语言或伴随守护进程。

机型选择、资源档位与性能诊断见[容量规划、性能调优与故障诊断](tuning.zh-CN.md)。

## 安装官方 Release

从同一个 [GitHub Release](https://github.com/jacek4yang/rust-reality/releases)
下载六个资产：

- `rust-reality-vX.Y.Z-linux-x86_64-generic.tar.gz`
- `rust-reality-vX.Y.Z-linux-x86_64-musl.tar.gz`
- `rust-reality-vX.Y.Z-linux-x86_64-v3.tar.gz`
- `rust-reality-vX.Y.Z-linux-aarch64-generic.tar.gz`
- `release-manifest.json`
- `SHA256SUMS`

解压前验证 `SHA256SUMS` 中列出的全部文件：

```shell
sha256sum --check SHA256SUMS
# x86-64 GNU/glibc 通用包：
tar -xzf rust-reality-v<version>-linux-x86_64-generic.tar.gz
# Alpine/musl 或极简容器使用完全静态包：
# tar -xzf rust-reality-v<version>-linux-x86_64-musl.tar.gz
# 或在 x86-64-v3 GNU/glibc CPU 上使用：
# tar -xzf rust-reality-v<version>-linux-x86_64-v3.tar.gz
# 在 ARM64（ARMv8.0 含 neon 或更高）上使用：
# tar -xzf rust-reality-v<version>-linux-aarch64-generic.tar.gz
sudo install -m 0755 rust-reality /usr/local/bin/rust-reality
rust-reality --version
```

`release-manifest.json` schema v3 记录版本、tag、精确源码 commit、target triple、
源码时间戳、编译器、cargo features，以及每个档位的压缩包名称、SHA-256、目标
CPU/特性、是否在本机实测，以及最低 CPU 要求。最低要求：
`linux-x86_64-generic` 和 `linux-x86_64-musl` 都运行于基线 x86-64；musl
资产完全静态，适合 Alpine 和极简容器。`linux-x86_64-v3` 要求 x86-64-v3
微架构级别，且没有运行时
回退；`linux-aarch64-generic` 要求 ARMv8.0 含 neon。v3 档是可选项，在验证主机
上没有实测优势（ring 在每个档位都于运行时做 AES 硬件调度），只有确认 CPU 满足
条件时才应选择它。不要混用不同 Release 的压缩包、manifest 或 checksum。

需要自行构建时使用固定工具链和锁定依赖图：

```shell
cargo dev check --all
cargo dev release build linux-x86_64-generic
```

### 发布后的逐档 Xray 验收

发布成功并不等于互操作验收完成。请在已发布 tag 的全新 checkout 中重新下载并
校验 Release 资产，把每个架构的二进制解压到各自独立的 mode-0700 目录，然后
在匹配的硬件上分别对下载得到的准确制品运行一次 Xray 门禁：

```shell
install -d -m 0700 release-smoke/generic release-smoke/x86-64-v3
tar -xzf rust-reality-v<version>-linux-x86_64-generic.tar.gz \
  -C release-smoke/generic
tar -xzf rust-reality-v<version>-linux-x86_64-v3.tar.gz \
  -C release-smoke/x86-64-v3

RUST_REALITY_BIN="$PWD/release-smoke/generic/rust-reality" \
  XRAY_BIN=/absolute/path/to/xray \
  ./scripts/test-xray-interop.sh
RUST_REALITY_BIN="$PWD/release-smoke/x86-64-v3/rust-reality" \
  XRAY_BIN=/absolute/path/to/xray \
  ./scripts/test-xray-interop.sh
```

每轮都会使用全新配置，证明准确的 1 MiB 传输、ML-DSA-65 一致性，以及未经修改
Xray 的 REALITY + Vision 互操作。应在支持 x86-64-v3、外部 DNS/TCP 正常的主机
执行；默认伪装目标不适用时用 `COVER_TARGET`/`COVER_SNI` 选择已探测的目标。在
ARM64 主机上，对 `linux-aarch64-generic` 二进制运行同一门禁。任一
档失败都属于 release no-go；不得以本地重建二进制替代下载到的制品。

## 创建服务账号和目录

```shell
sudo useradd --system --home /var/lib/rust-reality \
  --shell /usr/sbin/nologin rust-reality
sudo install -d -o root -g rust-reality -m 0750 /etc/rust-reality
sudo install -d -o rust-reality -g rust-reality -m 0750 \
  /var/lib/rust-reality/assets
sudo install -d -o rust-reality -g rust-reality -m 0750 \
  /var/log/rust-reality
```

建议布局：

```text
/usr/local/bin/rust-reality              root:root          0755
/etc/rust-reality/config.json            root:rust-reality  0640
/var/lib/rust-reality/assets/            rust-reality       0750
/var/log/rust-reality/                   rust-reality       0750（仅文件日志）
```

## 单机公网节点

### 1. 选择并探测伪装目标

v1.5 接受带或不带 compatibility CCS 的 TLS 1.3 伪装 flight，并可表达四条
位置化加密握手记录及可选的第五条 Finished 后记录。必须探测实际生产目标和
SNI；另一个主机探测成功不代表本目标可用。不支持、截断、超界或内部不一致的
flight 会 fail closed 到逐字节精确 fallback，没有削弱这些检查的运行时开关。

SNI 必须是目标实际服务的 DNS 名，目标必须协商兼容的 TLS 1.3 ServerHello。
从真实 VPS 执行：

```shell
rust-reality probe-dest \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com
```

目标可用性和行为属于外部依赖。持续握手失败或更换目标后应重新探测。

默认情况下，每个活跃 REALITY listener 会异步保留一小组有界、已完成 TCP 建连
的伪装目标 socket。只有认证成功的握手 checkout 后才发送 TLS 字节。warm hit 会
从认证关键路径移除伪装目标 TCP 握手。与此同时，有界 collector 发送受控探针，
只有四次观测在语义上完全一致时才发布内存 profile。精确命中已验证 profile 时，
还会移除伪装目标 ClientHello 到 flight 的 RTT；每个 server random、session ID
回显、临时 key share、流量秘密、REALITY 证书、CertificateVerify、Finished 与
记录序号仍逐会话全新生成。未知、过期、不稳定或无法安全表达的 class 使用真实目标。

prebuilt 模式只在 REALITY 认证及重放预留成功后使用。未认证、畸形、不兼容或重放
流量始终与真实伪装路径交互，不受 cache 状态影响。该优化不会消除物理传播时延，也
不能在数学意义上的无界瞬时流量中保证命中。只有进行聚焦兼容性排查时才关闭
`coverOptimization.warmTcp` 或 `coverOptimization.prebuiltProfiles`；任一 miss
都会安全降级到下一层真实目标路径，不改变正确性。

提供 ALPN 的伪装目标应当协商 ALPN。没有 ALPN 的伪装目标是受支持的——
v1.5 会把生成的 EncryptedExtensions ALPN 塑形成目标实际观测到的记录槽位——
但有 ALPN 的目标应优先，因为已认证会话此时能与目标的扩展形状完全一致。

`serverNames` 后续可以加入证书风格模式，例如 `*.lmu.edu`；客户端仍必须发送
`www.lmu.edu` 这样的具体单标签名称。为了让 `self-test` 验证该模式，配置的
target hostname 本身必须是一个匹配的具体名称。

### 2. 生成配置和客户端值

```shell
umask 077
rust-reality config generate standalone \
  --listen 0.0.0.0 \
  --port 443 \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com \
  > config.json 2> client-values.txt
```

服务器 JSON 包含 UUID、REALITY 私钥、归该 UUID 独占的两个 short ID 和策略；
`client-values.txt` 包含
REALITY 公钥。两者都不是普通日志，而是秘密部署材料，必须妥善保护和传输。

### 3. 配置 Xray 客户端

把服务器地址、端口、`settings.clients[0].id` 中的 UUID、`client-values.txt`
中的公钥、server name 和 `settings.clients[0].shortIds` 中的一个值写入
Xray 26.7.28 客户端：

```json
{
  "protocol": "vless",
  "settings": {
    "vnext": [{
      "address": "SERVER_ADDRESS",
      "port": 443,
      "users": [{
        "id": "SERVER_UUID",
        "encryption": "none",
        "flow": "xtls-rprx-vision"
      }]
    }]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
      "fingerprint": "chrome",
      "serverName": "www.microsoft.com",
      "publicKey": "REALITY_PUBLIC_KEY",
      "shortId": "SERVER_SHORT_ID",
      "spiderX": "/"
    }
  }
}
```

这只是 outbound 片段，不是完整 Xray 配置。

### 4. 验证并安装

```shell
rust-reality check --config config.json
rust-reality self-test --config config.json
sudo install -o root -g rust-reality -m 0640 \
  config.json /etc/rust-reality/config.json
```

`self-test` 会执行真实资产获取、路由编译和伪装目标探测，但不绑定端口。

## 线路机与 NXR 落地机

NXR 是内部、每流认证的原始 TCP 跳转；它不是 REALITY/TLS，认证后也不加密。

### 1. 生成独立 PSK

在可信主机执行：

```shell
umask 077
rust-reality node-keygen > nxr-key.json
```

`preSharedKey` 只用于这一对线路机/落地机信任关系。

### 2. 生成线路机配置

```shell
rust-reality config generate line \
  --listen 0.0.0.0 \
  --port 443 \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com \
  --nxr-address LANDING_PRIVATE_ADDRESS \
  --nxr-port 7443 \
  --nxr-key NXR_PSK \
  > line.json 2> line-client-values.txt
```

生成 UUID 默认使用 `landing` 出站；`direct` 和 `block` 可供显式用户规则选择。

### 3. 生成落地机配置

```shell
rust-reality config generate landing \
  --listen 0.0.0.0 \
  --port 7443 \
  --nxr-key NXR_PSK \
  > landing.json
```

落地配置只暴露 NXR，没有公网客户端身份。

### 4. 强制 NXR 防火墙边界

启动落地服务前，只允许线路机固定源 IP 访问 TCP 7443，并拒绝所有其他来源。
建议云安全组和主机防火墙同时限制。不能因为有 PSK 就把 NXR 公开到互联网。

保持时钟同步。默认 NXR 请求接受 30 秒误差并保留 nonce 120 秒；认证失败会在
DNS 和目标连接之前关闭。

生成的落地配置还允许有界的零字节 pre-auth idle 区间，使 LINE 可以维持未获协议
权限的 warm TCP。首个请求字节启动正常的短认证截止时间。应按所有允许的 LINE
节点为 `maxPreAuthIdleConnections` 与主机 FD 上限定容；允许的源 IP 仍未认证。
保持 `preAuthIdleTimeoutMs` 与 LINE warm idle/lifetime 策略一致，并在防火墙/NAT
变化后观察 `transport_pool_summary` 的 hit、stale、fallback、ready 和 connecting。

## 线路机与 Handoff 落地机

Handoff 把已接受会话的完整 TLS 所有权用一条密封且防重放的消息从线路机转移
到落地机。与 NXR 不同，转移之后该跳只承载会话的 TLS 密文，但落地机持有每个
已转移会话的活跃会话密钥。

### 1. 一步生成两侧配置

在可信主机执行：

```shell
rust-reality config generate handoff \
  --server-address LINE_PUBLIC_ADDRESS \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com \
  --landing-address LANDING_PRIVATE_ADDRESS \
  --output-dir handoff/
```

该命令写出 `line.json`（用户路由到 handoff 出站的公网线路机）、
`landing.json`（仅内部 Handoff 监听）和 `xray-client.json`。所有密钥材料
独立生成——UUID、REALITY X25519 密钥对、归该 UUID 独占的两个 short ID、Handoff 预共享密钥
和落地机静态 X25519 密钥对——且两份服务端配置在写出前均已通过校验。客户端
UUID 和 REALITY 公钥打印到标准错误；Handoff PSK 和私钥只存在于两份服务端
文件中。

一台线路机也可以同时对接多台落地机：重复 `--landing-address`（配合一个共用
的 `--landing-port`，或按地址逐一指定），生成器会写出 `landing-1.json`、
`landing-2.json`……以及一份为每个落地各持有一个 UUID、并把每个 UUID 的
用户组路由到对应 `landing-N` handoff 出站的 `line.json`。每对落地的密钥材料
相互独立。把不同的 UUID 组路由到不同的落地机，即可把客户端分流到不同的出网
路径；`xray-client.json` 使用第一个 UUID，其余 UUID 的分配由运维自行决定。

### 2. 部署并校验配置

把 `line.json` 安装到线路机、`landing.json` 安装到落地机，各自按单机流程的
[校验并安装](#4-验证并安装)步骤执行。落地配置只暴露内部 Handoff 监听，
没有公网客户端身份。

### 3. 强制 Handoff 防火墙边界

启动落地服务前，只允许线路机的源地址访问 Handoff TCP 端口（默认 7443），并
拒绝所有其他来源。建议云安全组和主机防火墙同时限制。这是硬性要求而非建议：
落地机不对转移的目标应用路由策略，且持有活跃会话密钥，暴露在外的监听会让
落地机变成任何可触达者的内部拨号器。

保持时钟同步。默认转移接受 30 秒误差并预留 nonce 120 秒。任何转移失败都静默
关闭、零响应字节，且线路机会重置客户端连接而不是在本地服务该会话。

Handoff listener 使用与 NXR 相同的有界零字节 pre-auth idle 阶段。首字节之前不
分配 continuation buffer，也不做 replay、X25519、HKDF、AEAD、DNS 或目标工作；
该字节会立即启动短认证截止时间。资源压力与 reload 会在影响活跃会话前关闭未用
idle socket；已 checkout 的会话由所属 generation 持有直至关闭。

默认情况下落地机直接连接每个被转移的目标。当落地机本身没有直连路由——目标
只能经由上游 SOCKS5 代理或再一跳 NXR 到达——在 Handoff 入站上把
`settings.egress` 设为该 `socks5` 或 `nxr` 出站的 tag；若设为 `blackhole`
tag，则每个已认证的转移会话都会被丢弃。该 tag 绝不能引用 `handoff` 出站：
落地机不允许串联。

### 4. v1.5 升级与回滚顺序

Handoff 的 `HND1` 线协议和 continuation-state 版本仍保持 v1。v1.5 落地机
同时接受服务端记录序号 0（原有边界）和序号 1（转移前已发送一个用于匹配伪装
形状的空应用记录）。v1.4 落地机只接受序号 0，因此不支持 v1.5 线路机搭配
v1.4 落地机：伪装形状消耗首个服务端应用序号的会话会静默失败。

滚动升级时，必须先升级并验证所有 LANDING，再升级 LINE；在此窗口中，v1.4
LINE 可以继续连接 v1.5 LANDING。回滚时，必须先降级所有 LINE，确保不再产生
新的序号 1 转移；随后停止接纳新的 Handoff 会话并排空 LANDING 上的活跃会话，
最后再降级 LANDING。不得在仍有活跃转移会话时重启或降级 LANDING。

记录序号安全边界与混合版本依据见
[ADR 0005](decisions/0005-handoff-server-record-sequences.md)。

## GeoIP 与 GeoSite

只需要 HTTPS URL。默认值已指向社区兼容文件，多数部署可完全省略 `assets`，
或只覆盖：

```json
{
  "assets": {
    "geoip": "https://example.invalid/releases/geoip.dat",
    "geosite": "https://example.invalid/releases/geosite.dat"
  }
}
```

请把示例域名换成真实可信来源。下载有大小/超时边界，支持条件重验证，解析完成
才发布，失败保留最后有效快照。`ext:文件名:标签` 只从配置缓存目录读取。

匹配器和 DNS 策略见[配置参考](configuration.zh-CN.md#routing)。

## 安装并启动 systemd

复制 Release 包内 unit：

```shell
sudo install -o root -g root -m 0644 \
  deploy/rust-reality.service /etc/systemd/system/rust-reality.service
sudo systemd-analyze verify /etc/systemd/system/rust-reality.service
sudo systemctl daemon-reload
sudo systemctl enable --now rust-reality
sudo systemctl status rust-reality
journalctl -u rust-reality -f
```

unit 使用专用账号，只保留 `CAP_NET_BIND_SERVICE`，保护主机文件系统/内核界面，
并只允许写资产和日志目录。应按发行版路径和本地加固策略审查，不能盲目删除限制。

正常部署优先使用 `log.output: "stderr"` 或 `"journald"`。文件日志必须配置
`path`、`maxBytes`、`maxFiles` 和 `maxTotalBytes`，全部都会强制执行。
`log.output: "none"` 会完全关闭日志——不创建文件、不写 stderr，所有事件在编码前
即被丢弃——但同时也会屏蔽 warn 级的拒绝与准入信号，因此除非日志本身不可接受，
否则应优先使用级别过滤而非 `none`。

每次启动都要核对 `outbound_network_initialized`，并为每个入站核对一条
`listener_topology_active`。前者记录缓存的 IPv4/IPv6 路由可用性及初始出站主族，
后者记录实际绑定成功的套接字——它反映的是绑定结果，而不是地址族可达性：
IPv6 套接字绑定成功并不证明公网 IPv6 出入方向可用。`listen.mode: auto` 仅在
`listener_family_unavailable` 报告真实地址族/协议能力错误时允许缺少一族；端口占用、
权限和具体地址错误仍然致命。`dualStack` 绝不降级。

## 热更新、重启与优雅退出

先验证再请求原子热更新：

```shell
rust-reality check --config /etc/rust-reality/config.json
rust-reality self-test --config /etc/rust-reality/config.json
sudo systemctl reload rust-reality
```

候选失败时当前 generation 继续工作，已有连接保留旧 generation。监听拓扑、
`runtime` 设置、resource governor、direct barrier、relay 策略和 NXR 重放缓存容量/保留时间是冷设置，必须受控重启。
完整列表见[热更新边界](configuration.zh-CN.md#热更新边界)。

SIGTERM 停止新 accept 并执行有界优雅退出；unit 的 40 秒停止超时覆盖程序 30 秒限制。

## 升级与回滚

从 1.4 升级必须迁移配置：标量形式 `"listen": "<ip>"` 和
`network.addressFamily` 都会被拒绝。新旧字段映射表见
[CHANGELOG 1.5.0 迁移说明](../CHANGELOG.md)；重启前先用新二进制对迁移后的
配置副本执行 `check`。

1. 下载并验证新 tag 的全部 Release 资产。
2. 以 root-only 文件保留当前二进制和配置。
3. 使用新二进制对生产配置副本执行 `check` 和 `self-test`。
4. 原子安装新二进制并重启。
5. 验证日志、监听、Xray 客户端握手、路由和真实流量。

示例二进制切换：

```shell
sudo install -m 0755 rust-reality /usr/local/bin/rust-reality.new
sudo mv /usr/local/bin/rust-reality /usr/local/bin/rust-reality.previous
sudo mv /usr/local/bin/rust-reality.new /usr/local/bin/rust-reality
sudo systemctl restart rust-reality
```

回滚时恢复旧二进制及其兼容配置后重启。不要降级二进制却保留旧版本不认识的新字段。

### 日常节点的版本化部署

永久生产化节点必须把可替换软件与持久身份分开。`scripts/deploy-release-vps.sh`
采用以下规范布局：

```text
/opt/rust-reality/releases/RELEASE/rust-reality
/opt/rust-reality/current -> releases/CURRENT
/opt/rust-reality/previous -> releases/PREVIOUS

/etc/rust-reality/releases/RELEASE/config.json
/etc/rust-reality/current -> releases/CURRENT
/etc/rust-reality/previous -> releases/PREVIOUS
```

配置代际由 root 管理，仅服务组可读；除非运维显式轮换，否则各代保持同一
REALITY/VLESS 持久身份。首次迁移先把正在运行的二进制和配置复制成最小已知良好
回滚包，然后 systemd 才改用 `current`。canary 成功后只保留 CURRENT 与 PREVIOUS，
删除的只能是更旧的可替换软件代际，绝不能随旧二进制裁剪部署身份。

部署脚本对每个远端修改都要求 `MUTATE_REMOTE=1`。`stage` 在不切换 live 节点时
验证版本、SHA-256、`check` 与 `self-test`；`cutover` 先准备 PREVIOUS，并在进程、
可执行文件身份或 443 健康检查失败时自动恢复它。后续 stock-Xray、字节完整性或
主动 canary 失败时立即执行 `rollback`。脚本不编辑 SSH、防火墙或监听端口。

日常边缘机的 22 是永久管理基础设施，443 是唯一公网 rust-reality 监听；origin、
指标与 benchmark helper 只能在 loopback、Unix socket 或隔离 namespace。正常
release 执行[发布流程](release-process.zh-CN.md)中的短时高密度 canary 后继续运行；
长期 soak 是计划任务/非阻塞证据，不再是发布等待。

**rust-reality release 是可替换的软件代际；VPS 的 REALITY/VLESS 身份是持久部署
状态。正常升级必须保持已有客户端可见身份和 443 endpoint，使现有配置继续有效。**

**live VPS 通常只保留两个已验证软件代际：CURRENT 与 PREVIOUS。失败候选自动回到
PREVIOUS。rust-reality 部署自动化永不修改 22 端口。**

## 故障排查清单

- `check`：JSON 语法、未知字段、引用或限制失败。
- `self-test`：资产 URL/缓存、DNS、路由标签或伪装目标失败。
- 绑定失败：端口被占用、缺少端口 capability、地址错误或重复监听。
- 地址族异常：对比 `outbound_network_initialized` 与 `listener_topology_active`；
  出站路由选择和入站监听拓扑有意相互独立。
- Xray 握手失败：UUID、flow、SNI、公钥、short ID、客户端时钟或伪装目标行为变化。
- NXR 失败：防火墙/源 IP、PSK、时钟误差、重放容量或落地机可达性。
- 路由异常：first-match 顺序、用户分配、domain strategy、缺少资产标签，或全局规则先于用户规则。

不要开启 debug 后未经审查公开日志。禁止把生产配置、密钥、UUID、凭据或抓包粘贴
到公开 issue。

## 已移除的内核中继后端

sockhash 后端已被移除：它在所有生产基准矩阵中从未 arm，特权 A/B 测试显示其与
splice 持平，且无特权的生产部署模型永远无法 arm 它。仍然设置 `policy.relay.sockhash`、
`policy.relay.maxSockhashRelays` 或 `policy.relay.maxPinnedMemoryBytes` 的配置会作为
未知字段被拒绝。

io_uring 后端已被移除（见
[`decisions/0002-io-uring-removed.md`](decisions/0002-io-uring-removed.md)）；仍然设置
`policy.relay.ioUring` 或 `policy.relay.maxIoUringRelays` 的配置会作为未知字段被拒绝。

可移植的缓冲中继和 Linux `splice` 不需要额外权限。
