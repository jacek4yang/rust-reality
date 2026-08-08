# Linux 部署

[English](deployment.md) | 简体中文

本指南使用官方 Linux x86_64 Release 部署单机公网节点、线路机，或受防火墙限制的
NXR 落地机。

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
下载三个资产：

- `rust-reality-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz`
- `release-manifest.json`
- `SHA256SUMS`

解压前验证列出的两个文件：

```shell
sha256sum --check SHA256SUMS
tar -xzf rust-reality-v<version>-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 0755 rust-reality /usr/local/bin/rust-reality
rust-reality --version
```

`release-manifest.json` 记录版本、tag、精确源码 commit、target triple、源码时间戳、
压缩包名和 SHA-256。不要混用不同 Release 的压缩包、manifest 或 checksum。

需要自行构建时使用固定工具链和锁定依赖图：

```shell
./scripts/check.sh
./scripts/build-release.sh
```

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

SNI 必须是目标实际服务的 DNS 名，目标必须协商兼容的 TLS 1.3 ServerHello。
从真实 VPS 执行：

```shell
rust-reality probe-dest \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com
```

目标可用性和行为属于外部依赖。持续握手失败或更换目标后应重新探测。

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

服务器 JSON 包含 UUID、REALITY 私钥、short ID 和策略；`client-values.txt` 包含
REALITY 公钥。两者都不是普通日志，而是秘密部署材料，必须妥善保护和传输。

### 3. 配置 Xray 客户端

把服务器地址、端口、`settings.clients[0].id` 中的 UUID、`client-values.txt`
中的公钥、server name 和 short ID 写入 Xray 26.7.28 客户端：

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
独立生成——UUID、REALITY X25519 密钥对、一个 short ID、Handoff 预共享密钥
和落地机静态 X25519 密钥对——且两份服务端配置在写出前均已通过校验。客户端
UUID 和 REALITY 公钥打印到标准错误；Handoff PSK 和私钥只存在于两份服务端
文件中。

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

1. 下载并验证新 tag 的全部三个资产。
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

## 故障排查清单

- `check`：JSON 语法、未知字段、引用或限制失败。
- `self-test`：资产 URL/缓存、DNS、路由标签或伪装目标失败。
- 绑定失败：端口被占用、缺少端口 capability、地址错误或重复监听。
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

