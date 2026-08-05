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

## 安装官方 Release

从同一个 [GitHub Release](https://github.com/jacek4yang/rust-reality/releases)
下载三个资产：

- `rust-reality-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz`
- `release-manifest.json`
- `SHA256SUMS`

解压前验证列出的两个文件：

```shell
sha256sum --check SHA256SUMS
tar -xzf rust-reality-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
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
resource governor、relay 策略和 NXR 重放缓存容量/保留时间是冷设置，必须受控重启。
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

## 可选的内核中继后端

sockhash 内核后端**默认关闭**，并且是探测得出而非假定。保持关闭是受支持的生产配置；
可移植的缓冲中继和 Linux `splice` 不需要额外权限。

io_uring 后端已被移除：其驱动从未进入生产中继路径，相较于可用的 splice 与
sockhash 后端，补全它并没有正当理由。仍然设置 `policy.relay.ioUring` 或
`policy.relay.maxIoUringRelays` 的配置会作为未知字段被拒绝。

### sockhash

`policy.relay.sockhash: true` 启用有界 eBPF `SOCKHASH` 后端。启动探测会创建 map
并加载流裁决程序；被拒绝时会给出固定原因。

**不要**假定 `CAP_BPF` 加 `CAP_NET_ADMIN` 普遍足够。实际需求取决于运行中的内核版本、
生效的 Linux 安全模块、seccomp 策略、用户命名空间以及程序和 map 类型。唯一可靠的
答案是目标主机上的探测结果。

随附的 systemd unit 刻意不会自动提升权限。若要选择加入，请使用 drop-in 而不是
修改打包的 unit：

```ini
# /etc/systemd/system/rust-reality.service.d/10-sockhash.conf
[Service]
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN
# eBPF map 与程序占用内核固定内存。
LimitMEMLOCK=infinity
# 保留打包 unit 中的其他所有加固指令。
```

随后在目标主机上验证探测确实报告可用，再依赖它：

```shell
cargo test -p rr-linux --test capability_report -- --nocapture
```

若探测拒绝，服务器仍会正常服务流量，只是使用下一个可用后端。
