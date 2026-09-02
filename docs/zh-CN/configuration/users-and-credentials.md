# 用户与凭据

[English](../../en/configuration/users-and-credentials.md) | 简体中文

要生成哪些值、哪一半放哪里，以及怎么在不掉线的前提下换掉它们。

## 四类材料

| 用什么生成 | 写进哪里 | 要给谁 |
| --- | --- | --- |
| `generate x25519` | `reality.privateKey`（私钥那半） | **公钥**那半发给每个客户端 |
| `generate uuid` | `users[].id` | 这个身份对应的客户端 |
| `generate short-id` | `users[].shortIds` | 同一个客户端 |
| `generate psk` | 出站和落地节点的 `psk` | 配对的那个节点，别处都不给 |

文件里其它东西都是策略。这四类是密钥或身份，不该手写，也不该在不同部署之间复用。

```shell
rust-reality generate x25519
rust-reality generate uuid 3          # 一次三个
rust-reality generate short-id 3      # 一次三个
rust-reality generate psk
```

脚本要消费输出时，都可以加 `--json`：

```shell
rust-reality generate x25519 --json
```

```json
{
  "privateKey": "005oawzDIFyUCdSjXtgGaP7UgGF7zFEzay4kL_nq9ww",
  "publicKey": "UWesja3AOowUwLohp5LcPtmE0gZmBSsn8I6623QczzY"
}
```

没有任何命令会拼出一份配置、一个客户端 profile 或者一条订阅链接。`generate` 只
输出你要的那一个值。

## X25519 那一对，以及哪半放哪

这是最容易出错的一处。`generate x25519` 打印两个值：

```
private key (keep secret): bkuHF6dZ2Elt_dkFKZoXkSUZ6gnLITrUZbRmDggVfuQ
public key  (give to peers): CyrxYetA0RSs9IxcGpb7vNfQ3GoKm6xTUL5qWdbjUAY
```

- **私钥**那半写进服务端的 `reality.privateKey`，文件权限 `0600`。它不离开这台
  机器。
- **公钥**那半写进客户端的 `publicKey` / `pbk` 字段。它不是秘密——每个客户端都
  有——但必须是配对的那一半。

客户端配了私钥、或者服务端配了公钥，握手就会失败，而且日志里看不出什么有用的
东西，因为在服务端看来，这个客户端不过是没通过认证而已。

**每个用途生成一对。** Handoff 落地节点需要它自己的一对（`landing.privateKey`），
和 REALITY 身份分开。一对密钥兼两职会把两个本该独立的秘密合成一个；当校验器能在
同一份文件里同时看到它们时，它会拒绝。

## Short ID

short ID 是 2 到 16 个十六进制字符，个数必须是偶数，因为它在线路上是一串字节：

```json
{
  "users": [
    {
      "id": "11111111-1111-4111-8111-111111111111",
      "shortIds": ["0123456789abcdef", "aabb"],
      "label": "alice"
    }
  ]
}
```

客户端只出示其中一条。列多条，可以让同一个身份下的不同设备带不同的 short ID，
而不必给它们不同的 UUID——以后想单独作废某台设备的凭据时会很方便。

short ID 不像私钥那样是秘密，但它们是标识符：在整个节点内必须唯一，校验器会管
这件事。

有理由要更短的时候，`rust-reality generate short-id --bytes N` 可以生成；默认
8 字节，也就是 16 个十六进制字符。

## 客户端需要什么

六个值，来自三个地方：

| 客户端字段 | 从哪来 |
| --- | --- |
| 地址 | 服务器的公网 IP 或域名 |
| 端口 | `listeners[].port` |
| id / UUID | `users[].id` |
| 公钥 / `pbk` | **公钥**那半——不在服务端文件里 |
| short id / `sid` | 该用户 `shortIds` 里的一条 |
| server name / SNI | `reality.serverNames` 里的一项；没写就是伪装主机名 |
| flow | 恒为 `xtls-rprx-vision` |

flow 是固定的。这个服务端只说 Vision，不说别的，所以配置里没有对应字段——从来就
没有第二个值可选。

注意公钥是客户端需要的值里唯一**不在**服务端配置文件里的。生成那一对的时候就把
它记下来；之后从文件里是拿不回来的，除非重新推导。

## 加一个用户

往 `users` 里追加，然后重载：

```shell
rust-reality check -c /etc/rust-reality/config.json
sudo systemctl reload rust-reality
```

用户是热配置。已建立的连接继续在接纳它们的那一代上跑，新身份从下一个连接起生效。

重载前一定先 `check`。校验不过的重载会被拒绝，正在跑的配置继续服务——但你是从
journal 里知道这件事的，而不是从你的终端，那是个更糟糕的知情方式。

## 删一个用户

删掉条目再重载。这个身份**已有的**连接不会被切断：它们在接纳它们的那一代上跑完。
需要立刻清掉的话，重启服务。

## 轮换 REALITY 密钥

改 `reality.privateKey` 会一次性作废所有客户端——没有重叠窗口，因为一个 REALITY
身份就是一把密钥。

所以要有准备地换：生成新的一对、更新服务端文件、分发新公钥、重载。每个客户端都
得更新。如果这个代价太大，你想要的多半是轮换**用户**，那个可以一个一个来。

## 不中断流量地轮换落地节点密钥

落地节点的凭据**有**重叠窗口，因为两个节点都在你手里，可以一台一台改。

Handoff 落地节点接受当前这一对，外加一份有界的已退役列表：

```json
{
  "landing": {
    "protocol": "handoff",
    "psk": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
    "privateKey": "REREREREREREREREREREREREREREREREREREREREREQ",
    "previousPsks": ["MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM"],
    "previousPrivateKeys": ["ERERERERERERERERERERERERERERERERERERERERERE"]
  }
}
```

顺序是：

1. 在**落地节点**上把新的一对设为当前，把旧的写进 `previousPsks` /
   `previousPrivateKeys`。重载。它现在两套都接受。
2. 在**入口节点**上把出站换成新的 `psk` 和 `landingPublicKey`。重载。它现在只
   发新的。
3. 回到**落地节点**，删掉已退役的条目。重载。窗口关闭。

第 3 步别跳过。窗口开着的时候，退役密钥仍然能打开封装转移，也就是说这次轮换本来
要恢复的前向保密性质，在旧密钥被删掉之前并没有恢复。只要列表非空，服务端每一代
都会记录一次 `handoff_rotation_window_open`，所以没做完的轮换是看得见的，不会被
忘掉。

当前密钥不能同时出现在退役列表里，校验器会拒绝——那等于这次轮换根本没发生。

## 把文件看住

配置里有私钥，所以它就是秘密：

```shell
sudo chown root:root /etc/rust-reality/config.json
sudo chmod 0600 /etc/rust-reality/config.json
```

这个二进制打印的任何东西都不会泄露它们。日志事件不含密钥材料，`explain` 不打印
密钥，关于密钥格式的诊断会显示 `[REDACTED]` 并描述被违反的规则：

```
error: invalid value for `reality.privateKey`
 --> config.json:6:19
  |
6 |     "privateKey": "[REDACTED]"
  |                   ^^^^^^^^^^^^ must be URL-safe unpadded base64 decoding to exactly 32 bytes
```

把文件备份到同样加密的地方，并且记住：一份轮换前文件的备份，在你下次轮换之前，
都是一份活密钥的备份。
