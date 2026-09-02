# Handoff

[English](../../en/configuration/handoff.md) | 简体中文

和[线路节点与落地节点](line-landing.md)一样的两机拓扑，只有一处不同：落地节点读不
了它转发的东西。

## 它改变了什么

用 NXR 时，线路节点终结客户端会话，然后把明文转发给落地节点。落地节点什么都看得到。

用 Handoff 时，线路节点只终结客户端的**握手**，然后把整个活着的 TLS 会话封装后交给
落地节点。落地节点转发的是它没有密钥的密文，而线路节点彻底退出这条链路。

| | NXR | Handoff |
| --- | --- | --- |
| 落地节点能读数据流 | 能 | **不能** |
| 转移之后的线路节点 | 为整个连接周期做转发 | 什么都不做 |
| 入口侧每连接的内存 | 一个 relay | 转移后为零 |
| 落地节点需要被信任能看内容 | 需要 | 不需要 |

由此推出两个后果，两个都值得要：

**落地节点不再是一个流量可以被读到的地方。** 落地节点被查封、托管在你不完全信任的
地方、或者是共享的，它转发的都是它解释不了的字节。

**线路节点不再是瓶颈。** 转移之后它对那个连接不持有任何缓冲区和转发任务，所以它的
内存和 CPU 不随流量增长。

## 它的代价

转移是每个连接一次的密码学操作，而不是每个字节一次，所以代价在建立阶段，不在吞吐
上。落地节点必须跑和线路节点同一个版本系列，因为封装转移是两者之间的内部线路契约。

## 密钥

Handoff 需要两个互相独立的秘密，它们的角色不同：

| 值 | 线路节点上 | 落地节点上 |
| --- | --- | --- |
| `psk` | `outbounds.<名字>.psk` | `landing.psk`——同一个值 |
| 落地节点的密钥对 | `landingPublicKey`——公钥那半 | `privateKey`——私钥那半 |

分开生成：

```shell
rust-reality generate psk       # 共享的预共享密钥
rust-reality generate x25519    # 落地节点自己的一对
```

`psk` 让线路节点向落地节点证明身份。那对密钥用来封装转移，只有落地节点的私钥那半
能打开。

不要拿 REALITY 那对密钥来当落地节点的密钥。它们保护的是不同的东西，而且只要校验器
能在一份文件里同时看到这两个值，它就会拒绝这种复用。

## 落地节点

```json
{
  "role": "landing",
  "listeners": [
    {
      "port": 7443,
      "ip": "ipv4Only",
      "ipv4": "10.0.0.2"
    }
  ],
  "landing": {
    "protocol": "handoff",
    "psk": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
    "privateKey": "REREREREREREREREREREREREREREREREREREREREREQ"
  }
}
```

这里的 `privateKey` 是私钥那半。线路节点拿公钥那半；如果这份文件里的值也出现在线路
节点的文件里，说明拿反了。

## 线路节点

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
  "outbounds": {
    "landing-1": {
      "type": "handoff",
      "address": "10.0.0.2",
      "port": 7443,
      "psk": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
      "landingPublicKey": "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM"
    }
  },
  "routing": {
    "default": "landing-1"
  }
}
```

两个节点之间路径慢或者不稳时，有两个可选的截止时间：

| 字段 | 默认 | 含义 |
| --- | --- | --- |
| `connectTimeoutMs` | 10000 | 拨号落地节点 |
| `firstByteTimeoutMs` | 15000 | 等落地节点第一个字节 |

没有实测出来的问题就别动它们。

## 必须对上的东西

| 线路节点 | 落地节点 | 要求 |
| --- | --- | --- |
| `outbounds.landing-1.psk` | `landing.psk` | 相等 |
| `outbounds.landing-1.landingPublicKey` | `landing.privateKey` 的公钥那半 | 是同一对 |
| `outbounds.landing-1.port` | `listeners[].port` | 相等 |

`check` 只读一个文件，验不了跨两台机器的密钥**对**。配错的一对会产生一个落地节点
打不开的转移，表现为认证之后连接才失败——这和 `psk` 写错的表现不一样。

## 不中断流量地轮换

因为两台机器都是你的，Handoff 凭据可以带重叠窗口轮换。落地节点接受当前这一对，
外加一份有界的已退役列表：

```json
{
  "landing": {
    "protocol": "handoff",
    "psk": "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU",
    "privateKey": "REREREREREREREREREREREREREREREREREREREREREQ",
    "previousPsks": ["IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"],
    "previousPrivateKeys": ["ERERERERERERERERERERERERERERERERERERERERERE"]
  }
}
```

1. **落地节点**：新的一对设为当前，旧的写进 previous。重载。它现在两套都接受。
2. **线路节点**：换成新的 `psk` 和 `landingPublicKey`。重载。它现在只发新的。
3. **落地节点**：删掉已退役的条目。重载。窗口关闭。

第 3 步不是可选的。退役密钥只要还列在那儿就仍然能打开封装转移，所以这次轮换本来要
恢复的前向保密性质，在它被删掉之前并没有恢复。只要列表非空，落地节点每一代都会记录
一次 `handoff_rotation_window_open`，让没做完的轮换保持可见。

落地节点密钥是热配置，所以上面三次重载都是 SIGHUP，任何一次都不会掉连接。

## NXR 还是 Handoff

落地节点是一台你控制程度和线路节点一样高的机器、并且你更想要简单的那个时，用
**NXR**。

下面任意一条成立时，用 **Handoff**：

- 落地节点托管在你不完全信任的地方；
- 线路节点很小，你不希望它的内存随流量增长；
- 你想要"落地节点被查封也拿不到可读内容"这个性质。

除此之外两种拓扑的运维完全一样，入口节点的配置只差一个出站 `type` 和一个多出来的
密钥。
