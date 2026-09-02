# 搭一个单机节点

[English](../../en/configuration/standalone.md) | 简体中文

一台机器，既收客户端，也自己拨号目的地。这是最简单的部署形态，也是学这份文件的
正确起点——其它所有拓扑都是"这个再加点什么"。

这一页一次讲一个决定地把配置搭起来。只想快点跑起来的话，
[快速上手](../getting-started.md)是短路径；这一页解释每个字段为什么在那儿。

> 本页所有密钥、UUID 和 short ID 都是占位符。它们格式合法，好让示例能被机器
> 校验，也就是说 `check` 会接受它们。请换成 `rust-reality generate` 的输出。

## 能跑起来的最小文件

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
  "routing": {
    "default": "direct"
  }
}
```

这就是本项目不替你决定的全部东西。其余的——线程数、连接上限、缓冲区大小、超时、
DNS 缓存、转发策略——都在启动时从这台机器推导。

校验它，顺便看看推导出了什么：

```shell
rust-reality check -c config.json
rust-reality explain -c config.json
```

## `role`

```json
{ "role": "entry" }
```

`entry` 是公网节点：它终结跑在 REALITY 上的 VLESS（Vision flow），认证用户，
决定他们的流量去哪。它必须最先想清楚，因为它决定了别的字段哪些合法——`landing`
节点没有 `users`、没有 `reality`、也没有 `routing`，写了就是错误，而不是被静静
忽略。

## `listeners`

```json
{ "listeners": [{ "port": 443 }] }
```

只写 `port` 的意思是"在所有能用的地址族上监听这个端口"。双栈主机上是两个
socket，`0.0.0.0:443` 和 `[::]:443`；纯 IPv4 主机上就一个，节点照样启动。最后
这半句正是 `auto` 作为默认值的理由：一个因为主机没有 IPv6 就拒绝启动的节点，是
在毫无必要地失败。

想把行为钉死就写出来：

| `ip` | 监听 |
| --- | --- |
| `auto`（默认） | 两个地址族，至少一个成功就启动 |
| `dualStack` | 两个地址族，**都必须成功** |
| `ipv4Only` | 只 IPv4 |
| `ipv6Only` | 只 IPv6 |

想绑定具体地址而不是通配地址，就把它写出来：

```json
{ "listeners": [{ "port": 443, "ip": "ipv4Only", "ipv4": "203.0.113.10" }] }
```

多个监听器共用一份 REALITY 身份和一份用户表。当 443 不通而另一个端口通的时候
很有用——两个端口上是同一个节点。

监听器是冷配置：改它要重启，因为 socket 在别的一切存在之前就已经绑好了。

## `reality`

```json
{
  "reality": {
    "cover": "www.microsoft.com:443",
    "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE"
  }
}
```

**`cover`** 是这个节点要伪装成的那台真实 TLS 1.3 主机，带端口。没通过认证的连接
会被代理到它，这正是"探测你的节点看起来像在探测那台主机"的由来。选好它是一件
独立的事：见[伪装目标](cover-targets.md)。

**`privateKey`** 是 `rust-reality generate x25519` 生成的那对里的私钥。它的公钥
那半进每一个客户端。如果服务端文件里是客户端也有的那个值，说明你拿反了。

**`serverNames`** 可选，默认取伪装主机自己的域名，绝大多数情况下这就是你想要的。
只有当要接受一个和伪装主机不同的名字时才设它；另外注意，已认证客户端的 SNI 必须
匹配这里的某一项——对不上是新部署第二常见的失败原因。

用 IP 地址写的伪装目标没有域名可以默认，所以那种情况下 `serverNames` 变成必填。

## `users`

```json
{
  "users": [
    {
      "id": "11111111-1111-4111-8111-111111111111",
      "shortIds": ["0123456789abcdef"],
      "label": "alice"
    }
  ]
}
```

**`id`** 是客户端出示的 UUID。**`shortIds`** 是这个身份可以使用的 REALITY short
ID：2 到 16 个十六进制字符，个数必须是偶数。当你想让不同设备用不同 short ID、
又不想给它们不同 UUID 时，就给一个用户写多条。

**`label`** 是给你自己的。它出现在 `explain` 和各种报告里，对协议没有影响——它
存在的意义就是让路由摘要能写 `alice` 而不是一串 UUID。

身份和 short ID 在整个节点内必须唯一。

用户是热配置：增删或换发一个用户在 SIGHUP 后生效，已经建立的连接继续跑。

## `routing`

```json
{ "routing": { "default": "direct" } }
```

`default` 必填。它是所有规则都没命中时流量的去处，把它设成必填意味着没有哪份
文件会对自己的兜底行为含糊其辞。

`direct` 从这台机器拨号目的地，`block` 拒绝。两者一直都在，也从不声明。

单机节点的路由配置到此为止。想让某些目的地走不同的路时，[路由](routing.md)会讲
规则、匹配器和按用户区分的策略。

## 更完整一点的例子

两个监听器、两个用户、一条拒绝私有地址段的规则，以及显式的日志设置：

```json
{
  "role": "entry",
  "listeners": [
    {
      "port": 443,
      "ip": "ipv4Only",
      "ipv4": "203.0.113.10"
    },
    {
      "port": 8443
    }
  ],
  "reality": {
    "cover": "www.microsoft.com:443",
    "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE",
    "serverNames": [
      "www.microsoft.com"
    ]
  },
  "users": [
    {
      "id": "11111111-1111-4111-8111-111111111111",
      "shortIds": [
        "0123456789abcdef",
        "aabb"
      ],
      "label": "alice"
    },
    {
      "id": "22222222-2222-4222-8222-222222222222",
      "shortIds": [
        "fedcba9876543210"
      ],
      "label": "bob"
    }
  ],
  "routing": {
    "default": "direct",
    "rules": [
      {
        "name": "block-private",
        "ip": [
          "geoip:private"
        ],
        "outbound": "block"
      }
    ]
  },
  "log": {
    "level": "info",
    "output": "stderr"
  }
}
```

`geoip:private` 不需要下载任何数据——它是内置的。点名其它 `geoip:` 或 `geosite:`
标签的规则才需要 geo 文件，见[路由](routing.md#geo-data)。

## 你没必要写的那些

拿上面这份文件跑一次 `explain`，剩下的每个决定都列在那儿：

```
posture: profile auto -> standard, tuning startup, objective balanced
runtime: 4 worker threads, 512 blocking threads (tokio-default)
limits: 25 values, all derived from the machine (--json for the table)
```

二十五个准入上限、缓冲区大小和池边界，全部从这台机器实际拥有的 CPU 数、内存和
描述符上限推导出来。它们你都可以钉住，而在绝大多数机器上你不该这么做——什么情况
下算正当理由、怎么判断，见[运行时与资源](runtime-and-resources.md)。

## 接下来

- [用户与凭据](users-and-credentials.md)——生成什么、分发什么、怎么轮换。
- [伪装目标](cover-targets.md)——怎么选一个经得起看的。
- [路由](routing.md)——当 `direct` 不够用的时候。
- [部署](../operations/deployment.md)——systemd、权限、防火墙。
