# 线路节点与落地节点

[English](../../en/configuration/line-landing.md) | 简体中文

用两台机器而不是一台，让客户端连的那个 IP，不是流量出去的那个 IP。

## 为什么要拆

单节点的公网 IP 同时干两件事：客户端连它，目的地也看见它。这意味着任何烧掉前者的
事情——扫描、封锁名单、对你 443 端口的枚举——同时也烧掉了后者；而任何能标识后者的
东西，也标识了前者。

拆开就把两种风险分开了：

```
客户端 ──REALITY──▶ 线路节点 ──NXR──▶ 落地节点 ──▶ 目的地
                    公网 IP            干净 IP
                    可牺牲             隐藏，有防火墙
```

**线路节点**面向公网。它按设计就是暴露的，被烧了就换掉：它并不持有任何独特的出口
信誉。

**落地节点**只能被线路节点访问。它没有公网监听、没有 REALITY 身份、没有用户。它的
IP 才是目的地看到的，而它之所以能保持干净，就是因为公网上没有东西能碰到它。

这也是为什么一个进程不能兼任两者。把两个角色放在同一台机器上，等于把可牺牲的 IP
和干净的 IP 放到一起，而这正是这套拓扑要防的事情。

## 一段话说清 NXR

NXR 是两者之间的内部协议。线路节点用预共享密钥向落地节点认证、发送目的地、转发
数据流；落地节点校验密钥、拒绝重放、拨号目的地、然后转发。它不是为了在敌对网络上
存活而设计的——它是为你自己控制的两台机器之间那一跳设计的，所以很轻。

如果落地节点不该能读它转发的东西，改用 [Handoff](handoff.md)。

## 开始之前

- 两台机器。落地节点不需要公网 IP，而且最好没有。
- 两者之间的一条私有通路——私有网络、VPC、WireGuard 隧道，或者一条只放行线路节点
  地址的防火墙规则。
- 一个预共享密钥，生成一次，两份文件都用它：

```shell
rust-reality generate psk
```

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
    "protocol": "nxr",
    "psk": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"
  }
}
```

整个文件就这些。落地节点没有 `reality`、没有 `users`、也没有 `routing`，因为这些
决定都不由它做——它转发的是线路节点已经认证过的东西。写了其中任何一个都是错误，
并且报错会点名那个字段。

注意那个显式的 `ipv4` 绑定。落地节点应该监听自己的私有地址而不是通配地址，这样
即使防火墙配错了也不会把它暴露出去。

流量默认经 `direct` 离开落地节点，除非你把 `egress` 指向一个已声明的出站；什么时候
有用见[多落地节点](multi-landing.md)。

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
      "type": "nxr",
      "address": "10.0.0.2",
      "port": 7443,
      "psk": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"
    }
  },
  "routing": {
    "default": "landing-1",
    "rules": [
      {
        "name": "block-private",
        "ip": [
          "geoip:private"
        ],
        "outbound": "block"
      }
    ]
  }
}
```

它就是一个单机入口节点加了一样东西：一个点名落地节点的 `nxr` 出站，以及把
`routing.default` 指向它而不是 `direct`。

`block-private` 那条规则在这里比在单机节点上更要紧。没有它，客户端可以让线路节点
去连 `10.0.0.2`，从而借你自己的代理够到落地节点的管理接口。凡是所在网络里有值得
够的东西的节点，都该拦掉私有地址段。

## 三个必须对上的值

`check` 只读一个文件，所以这些它一个都验不了。自己确认：

| 线路节点 | 落地节点 | 要求 |
| --- | --- | --- |
| `outbounds.landing-1.port` | `listeners[].port` | 相等 |
| `outbounds.landing-1.psk` | `landing.psk` | 相等 |
| `outbounds.landing-1.address` | 落地节点绑定的地址 | 可达 |

对不上不是配置错误——两份文件各自都合法。它是部署错误，表现为连接在第一次转移时
失败。

## 起服务

先起落地节点，好让线路节点有东西可连：

```shell
# 在落地节点上
rust-reality check -c /etc/rust-reality/config.json
rust-reality run -c /etc/rust-reality/config.json

# 在线路节点上
rust-reality check -c /etc/rust-reality/config.json
rust-reality doctor -c /etc/rust-reality/config.json
rust-reality run -c /etc/rust-reality/config.json
```

在把客户端指过来之前先确认路径：

```shell
rust-reality explain -c /etc/rust-reality/config.json --route example.com
```

```
example.com for alice -> landing-1 (routing, default outbound)
```

## 给落地节点上防火墙

落地节点的保护就在于别的东西碰不到它。把这件事做实：

```shell
# 在落地节点上——只放行线路节点
sudo iptables -A INPUT -p tcp --dport 7443 -s <线路节点私有 IP> -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 7443 -j DROP
```

一个从互联网可达的落地节点，就是一个 IP 可以被发现的落地节点，而这正是你一开始要
避免的事。

## 每个节点各自能看到什么

值得说准确，因为这决定了你能承受失去哪台机器：

| | 线路节点 | 落地节点 |
| --- | --- | --- |
| 客户端身份 | 能 | 不能 |
| 目的地主机名 | 能 | 能 |
| 明文数据流 | 能 | 能 |
| 你的出口 IP | 不是 | 它**就是**出口 |

落地节点看到的是明文。它是一台你控制并信任的机器；NXR 不是在保护流量不被落地节点
看到，而是在保护你的出口 IP 不被公网看到。当你需要落地节点本身也读不了数据流时，
那就是 [Handoff](handoff.md)。

## 接下来

- [Handoff](handoff.md)——同样的拓扑，但那一跳上只跑密文。
- [多落地节点](multi-landing.md)——多个出口，按用户选。
- [路由](routing.md)——只把一部分流量送过落地节点。
