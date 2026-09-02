# 快速上手

[English](../en/getting-started.md) | 简体中文

装好二进制、生成手写不出来的那几个值、写一份二十行的配置、连上客户端。
在一台干净的服务器上大约十五分钟。

配置是你自己写的。没有任何命令会替你生成一份完整配置，这是故意的：文件很短，
里面每一个字段都是一个决定，而自己写过的人才调得动它。这一页会在每加一个字段
时说明它为什么在那里。

## 你需要什么

- 一台有公网 IP 的 Linux 服务器，以及 root 权限。
- 这台机器上的 443 端口是空的。REALITY 只有待在真正的 TLS 端口上才说得通。
- 一个会说 VLESS + REALITY + Vision 的客户端——Xray-core，或者任何基于它的
  应用。

## 1. 安装

从 [最新 release](https://github.com/jacek4yang/rust-reality/releases/latest)
下载对应平台的压缩包、manifest 和校验和，先校验再安装：

```shell
sha256sum --check SHA256SUMS
tar -xzf rust-reality-v<version>-linux-x86_64-generic.tar.gz
sudo install -m 0755 rust-reality /usr/local/bin/rust-reality
rust-reality --version
```

按机器挑压缩包：

| 压缩包 | 什么时候用 |
| --- | --- |
| `linux-x86_64-generic` | 常见的 glibc 发行版 |
| `linux-x86_64-musl` | Alpine，或者精简容器 |
| `linux-x86_64-v3` | 你确定 CPU 是 x86-64-v3；它没有运行时回退 |
| `linux-aarch64-generic` | ARM64，ARMv8.0 带 neon 及以上 |

不要把不同 release 的文件混着用。`release-manifest.json` 记录了确切的源码
commit、编译器、feature，以及每一档压缩包的 SHA-256。

## 2. 选一个伪装目标

REALITY 的做法是：让到你服务器的连接看起来跟到另一台真实主机的 TLS 连接一模
一样。那台主机就是**伪装目标**（cover target），选它是这次部署里第一个真正的
决定。

**在服务器上**测候选目标，因为答案取决于网络路径：

```shell
rust-reality check-cover --cover www.microsoft.com:443
```

一个能用的伪装目标响应要快，并且能协商出 TLS 1.3 + X25519。如果命令给出的
不是这个结果，就换一个——具体要求和背后的道理在
[挑选伪装目标](configuration/cover-targets.md)。

## 3. 生成材料

有三类值是编不出来的。在服务器上逐个生成：

```shell
rust-reality generate x25519
rust-reality generate uuid
rust-reality generate short-id
```

`generate x25519` 会打印一对：

```
private key (keep secret): bkuHF6dZ2Elt_dkFKZoXkSUZ6gnLITrUZbRmDggVfuQ
public key  (give to peers): CyrxYetA0RSs9IxcGpb7vNfQ3GoKm6xTUL5qWdbjUAY
```

**私钥**那半写进服务端文件。**公钥**那半写进客户端，别的地方哪儿都不放。把这
两半弄反，是新部署失败最常见的原因，所以值得多花一秒确认：下面那份服务端文件
里绝不能出现公钥。

这几个命令都可以加 `--json`，输出机器可读的格式，安装脚本应该消费这个。

## 4. 写配置

新建 `/etc/rust-reality/config.json`：

```json
{
  "role": "entry",
  "listeners": [
    {
      "port": 443
    }
  ],
  "reality": {
    "cover": "www.microsoft.com:443",
    "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE"
  },
  "users": [
    {
      "id": "11111111-1111-4111-8111-111111111111",
      "shortIds": [
        "0123456789abcdef"
      ],
      "label": "alice"
    }
  ],
  "routing": {
    "default": "direct"
  }
}
```

> **上面的密钥、UUID 和 short ID 都是占位符。** 它们的格式是对的，好让这一页
> 的示例能被机器校验——也就是说 `check` 会接受它们，但它看不出这些值是公开的。
> 在这个节点可达之前，把三个都换成第 3 步的输出。

六个字段，每一个都是一个决定：

- **`role`**——`entry` 表示这个节点面向公网，说 VLESS + REALITY + Vision。
  另一个角色是 `landing`，见[线路节点与落地节点](configuration/line-landing.md)。
- **`listeners`**——在哪里收连接。只写 `port` 会同时监听 IPv4 和 IPv6，任意
  一边起来了就算启动成功。
- **`reality.cover`**——第 2 步选好的主机，带端口。
- **`reality.privateKey`**——第 3 步那对里的私钥。
- **`users`**——谁可以连。`label` 是给你自己的日志和报告看的，对协议没有影响。
- **`routing.default`**——没有规则命中时流量去哪。`direct` 和 `block` 一直都
  在，也永远不需要声明。

其余一切都有一个从这台机器推导出来的默认值。第 6 步会让你看到它们推导成了什么。

然后把文件锁上。它里面有私钥：

```shell
sudo chown root:root /etc/rust-reality/config.json
sudo chmod 0600 /etc/rust-reality/config.json
```

## 5. 校验

```shell
rust-reality check -c /etc/rust-reality/config.json
```

```
/etc/rust-reality/config.json is a valid entry node
```

`check` 严格离线。它解析、校验每一个值和每一处交叉引用，然后什么都不碰——不查
DNS、不开 socket、不下载。所以它在哪儿跑都安全，包括在笔记本上的 CI 里。

出问题时，它会指着导致问题的那一行：

```
error: invalid value for `reality.privateKey`
 --> /etc/rust-reality/config.json:6:19
  |
6 |     "privateKey": "[REDACTED]"
  |                   ^^^^^^^^^^^^ must be URL-safe unpadded base64 decoding to exactly 32 bytes
```

注意值本身被打码了。诊断信息从不回显密钥。

## 6. 校验环境

```shell
rust-reality doctor -c /etc/rust-reality/config.json
```

`doctor` 做完 `check` 做的一切，然后去联系文件里点名的东西：解析 DNS、拨号伪装
目标并确认它仍然能协商 TLS 1.3、加载 geo 数据、检查文件权限。它不监听端口，也
不改动任何东西。

```json
{
  "configuration": "ok",
  "cover": [
    {
      "target": "www.microsoft.com:443",
      "serverName": "www.microsoft.com",
      "compatible": true,
      "cipherSuite": "TLS_AES_256_GCM_SHA384",
      "keyExchangeGroup": "X25519",
      "totalMillis": 642
    }
  ],
  "role": "entry",
  "routing": "ok"
}
```

想看没写的那些字段在这台机器上推导成了什么：

```shell
rust-reality explain -c /etc/rust-reality/config.json
```

```
role: entry
listeners:
  0.0.0.0:443, [::]:443 (auto, at least one)
routing:
  default: direct (0 rules, strategy resolveIfNoMatch)
  outbounds: direct, block
machine: 4 effective cpus (4 logical), 524288 descriptors, 16194637824 bytes memory (cgroup_v2)
posture: profile auto -> standard, tuning startup, objective balanced
runtime: 4 worker threads, 512 blocking threads (tokio-default)
limits: 25 values, all derived from the machine (--json for the table)
```

## 7. 启动

```shell
rust-reality run -c /etc/rust-reality/config.json
```

`run` 留在前台，一直服务到收到 SIGINT 或 SIGTERM——这正是进程守护需要的形态。
systemd unit、用什么用户跑、防火墙怎么开，见[部署](operations/deployment.md)。

## 8. 连客户端

客户端需要六个值，其中只有一个不在它拿得到的文件里：

| 客户端字段 | 值 |
| --- | --- |
| 地址 | 服务器的 IP 或域名 |
| 端口 | `443`，来自 `listeners[0].port` |
| id / UUID | `users[0].id` |
| 公钥 | 第 3 步那半**公钥**——不是文件里的那个 |
| short id | 该用户 `shortIds` 里的任意一条 |
| server name / SNI | `www.microsoft.com`，也就是伪装主机名 |
| flow | `xtls-rprx-vision` |

flow 永远是 `xtls-rprx-vision`；这个服务端不说别的，所以配置里根本没有这个字段。

随便打开个网页。通了，部署就完成了。

没通的话，[排障](operations/troubleshooting.md)是按症状组织的，开头两条就是绝
大多数问题的来源：密钥拿反了，以及客户端 SNI 和伪装目标对不上。

## 接下来

- **看懂你刚写的这个文件**——[配置是怎么回事](configuration/index.md)。
- **加用户、换凭据**——[用户与凭据](configuration/users-and-credentials.md)。
- **把一部分流量送到别处**——[路由](configuration/routing.md)。
- **把出口 IP 藏到第二台机器后面**——[线路节点与落地节点](configuration/line-landing.md)。
- **规规矩矩地交给 systemd**——[部署](operations/deployment.md)。
- **搞清楚你暴露了什么**——[威胁模型](threat-model.md)。
