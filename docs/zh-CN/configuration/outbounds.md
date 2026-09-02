# 出站

[English](../../en/configuration/outbounds.md) | 简体中文

出站就是离开这个节点的方式。有两个不用声明就存在，另有三种可以声明。

## 两个永远不声明的

| 名字 | 干什么 |
| --- | --- |
| `direct` | 从这台机器拨号目的地 |
| `block` | 拒绝这个连接 |

它们一直可用，声明其中任何一个都是错误。它们不是协议，也没有什么可配的，所以让
每份文件都各写一行纯属仪式。`rust-reality explain` 会把它们列出来，所以它们不会
变成隐形的：

```
outbounds: direct, block, landing-1
```

单机节点不需要别的——`{"routing": {"default": "direct"}}` 就是一份完整的路由配置。

## 声明一个

`outbounds` 是按名字索引的对象。键**就是**名字，所以没有 `tag` 字段，两个出站也
不可能撞名：

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
      ]
    }
  ],
  "outbounds": {
    "upstream": {
      "type": "socks5",
      "address": "127.0.0.1",
      "port": 1080
    }
  },
  "routing": {
    "default": "upstream"
  }
}
```

每个出站都有 `type`。用 `type` 而不是 `protocol`，是因为 `direct` 和 `block` 并
不是协议；整份文件的判别字段统一成一个词，比让五种里的三种用上熟悉的词更划算。

## `socks5`

转发给一个 SOCKS5 服务器——本地隐私工具、公司出口，或者另一个代理：

| 字段 | 必填 | 含义 |
| --- | --- | --- |
| `address` | 是 | SOCKS5 服务器主机 |
| `port` | 是 | SOCKS5 服务器端口 |
| `username` | 否 | 当且仅当设了 `password` 时必填 |
| `password` | 否 | 当且仅当设了 `username` 时必填 |
| `warmTcp` | 否 | 预建连接；默认开 |

凭据成对出现。只写一个是错误，而不是留下一个到第一个连接才失败的半吊子认证。

## `nxr` 与 `handoff`

两者都把流量送到**落地节点**——由第二台机器的 IP 去做真正的拨号，这样你的公网入口
IP 就不会作为源地址出现在任何目的地那里。它们的区别在于两者之间那一跳上跑的是
什么：

| | `nxr` | `handoff` |
| --- | --- | --- |
| 那一跳上跑的 | 目的地和明文流，重新认证过 | 客户端的 TLS 会话，仍是封装的 |
| 落地节点能读流量 | 能 | 不能 |
| 转移后入口侧的状态 | 为整个连接周期做转发 | 没有——会话已经交出去了 |

落地节点是你自己的、并且想要简单的时候选 `nxr`。不希望落地节点能读它转发的东西
时选 `handoff`。[线路节点与落地节点](line-landing.md)和 [Handoff](handoff.md)
各自展开讲，这一页只讲字段。

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
      ]
    }
  ],
  "outbounds": {
    "landing-handoff": {
      "type": "handoff",
      "address": "10.0.0.3",
      "port": 7443,
      "psk": "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU",
      "landingPublicKey": "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM"
    },
    "landing-nxr": {
      "type": "nxr",
      "address": "10.0.0.2",
      "port": 7443,
      "psk": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"
    },
    "upstream": {
      "type": "socks5",
      "address": "127.0.0.1",
      "port": 1080,
      "username": "proxyuser",
      "password": "proxypass",
      "warmTcp": false
    }
  },
  "routing": {
    "default": "landing-nxr"
  }
}
```

**`nxr`**

| 字段 | 必填 | 含义 |
| --- | --- | --- |
| `address` | 是 | 落地节点地址 |
| `port` | 是 | 落地节点监听的端口 |
| `psk` | 是 | 32 字节预共享密钥，与落地节点一致 |
| `warmTcp` | 否 | 预建连接；默认开 |

**`handoff`** 在上面基础上多两个：

| 字段 | 必填 | 含义 |
| --- | --- | --- |
| `landingPublicKey` | 是 | 落地节点那对密钥的**公钥**那半 |
| `connectTimeoutMs` | 否 | 拨号落地节点的截止时间；默认 10000 |
| `firstByteTimeoutMs` | 否 | 等落地节点第一个字节的截止时间；默认 15000 |

入口节点持有落地节点的**公钥**，落地节点持有私钥那半。入口节点的文件里不该有任何
落地节点的私钥；除了共享的 `psk` 之外，同时出现在两份文件里的值都是错的。

## 预热连接

`warmTcp` 默认开着，意思是节点会在有人来之前，先备好一小池到该出站的已建立 TCP
连接。它能从用到它的会话开头省掉一次往返。

池的大小是从机器推导的——备多少条、同时可以有多少条在连、涨缩多快——这些都没有对
应字段。如果某个出站不欢迎长连接，就把整件事关掉：

```json
{ "outbounds": { "upstream": { "type": "socks5", "address": "127.0.0.1", "port": 1080, "warmTcp": false } } }
```

会这么做的理由：按量计费的上游、会记录连接的 SOCKS5 服务器，或者一个把空闲连接
关得太狠、导致池不停重建的对端。

## 名字，以及谁在引用它们

出站按名字使用，来自三个地方：

- `routing.default`
- 某条规则的 `outbound`
- 某条策略的 `default`，或者策略里某条规则

引用没声明的名字会被拒绝，并且报错会列出有哪些可用：

```
error: invalid value for `routing.default`
 --> config.json:24:16
  |
24 |     "default": "landing-2"
  |                ^^^^^^^^^^^ unknown outbound; declared: landing-1; built in: direct, block
```

声明一个没人引用的出站是允许的。如果 `warmTcp` 开着，它会占一个预热池，所以不再
路由过去的就删掉。

## 热更新

`outbounds` 是热的。增删或换密钥在 SIGHUP 后生效，已建立的连接继续用它们开始时的
那张表——重载绝不会把活着的会话挪到另一个出站上。

删掉一个正被活连接使用的出站，不会切断那个连接。它在自己那一代上跑完。
