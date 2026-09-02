# DNS 与网络

[English](../../en/configuration/dns-and-network.md) | 简体中文

这个节点怎么解析名字，以及用哪个地址族拨号。两者都有能用的默认值；这一页是给默认值
不合适的情况准备的。

## 默认行为

两段都不写，节点就用系统解析器，并拨号任何能用的地址族，倾向于主机路由表暗示的那个。
在一台正常的双栈 VPS 上这就是正确行为，没什么可配的。

## `network.ip`

```json
{ "network": { "ip": "preferIpv4" } }
```

这是出站策略——这个节点怎么拨号目的地。它和 `listeners[].ip` 是两回事，后者管的是
接收连接，两者不必一致：一个节点完全可以接收 IPv6 客户端而只拨号 IPv4。

| 取值 | 行为 |
| --- | --- |
| `auto`（默认） | 探测主机能力，据此选择倾向 |
| `preferIpv4` | 先试 IPv4，回退 IPv6 |
| `preferIpv6` | 先试 IPv6，回退 IPv4 |
| `ipv4Only` | 只 IPv4；纯 IPv6 的目的地不可达 |
| `ipv6Only` | 只 IPv6 |

`auto` 会定期重新探测，所以主机的 IPv6 连通性得而复失或失而复得，都不用重启就能跟上。

什么时候该钉死：主机的 IPv6 存在但是坏的——配了、也通告了，然后黑洞——这种情况
`auto` 未必分得清它和"能用"的区别。症状是连接要挂几秒才成功。

`network` 是冷配置。改它要重启，因为拨号策略在连接器构造时就定死了。

## `dns`

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
  },
  "dns": {
    "servers": [
      "1.1.1.1",
      "9.9.9.9"
    ],
    "timeoutMs": 4000,
    "cache": {
      "maxEntries": 8192,
      "minTtlSeconds": 60
    }
  },
  "network": {
    "ip": "preferIpv4"
  }
}
```

| 字段 | 默认 | 含义 |
| --- | --- | --- |
| `servers` | 系统解析器 | 要查询的解析器 |
| `timeoutMs` | 5000 | 单次查询截止时间 |
| `cache` | 推导 | 缓存边界，见下 |

`servers` 接受 IP 地址，或者单独一项 `"system"` 表示显式使用主机配置的解析器。
`"system"` 不能和别的混着写：要么主机说了算，要么这个文件说了算，一半一半没有明确
含义。

### 什么时候该设

**别动它**——如果主机上已经有一个快的本地解析器。那是最好的情况，一个由
`/etc/resolv.conf` 指向的本地缓存存根（`systemd-resolved` 或 `unbound`）胜过这里
配的任何东西，因为它服务整台机器。

**该设它**——如果主机解析器慢、在你不信任的网络路径上，或者返回的答案受到你正在
绕开的那套过滤影响。DNS 是代理泄露最多的地方：目的地名字对回答者是可见的。

### 缓存

```json
{ "dns": { "cache": { "maxEntries": 8192, "minTtlSeconds": 60 } } }
```

| 字段 | 含义 |
| --- | --- |
| `maxEntries` | 缓存多少条答案 |
| `minTtlSeconds` | 一条答案至少复用多久 |
| `maxTtlSeconds` | 同上的上限 |
| `negativeTtlSeconds` | 一次失败记多久 |
| `staticTtlSeconds` | 字面地址的缓存寿命 |
| `systemReuseMs` | 系统解析器答案的复用窗口 |

不写的话它们全部从机器推导，而在绝大多数节点上就该不写。上游返回的 TTL 极短、查询
速率成为问题时，抬高 `minTtlSeconds`；目的地会漂移、陈旧答案导致失败时，压低
`maxTtlSeconds`。

`maxTtlSeconds` 不能低于 `minTtlSeconds`，校验器会直说，而不是悄悄把两者对调。

`dns` 是冷配置：解析器在整个进程生命周期里只安装一次，所以改它要重启。

## 路由与 DNS

`routing.strategy` 决定的是**为了路由**要不要解析目的地名字，这和"为了连接要不要
解析"是两个问题。规则全是域名的节点在路由阶段根本不解析。见
[路由](routing.md#strategy)。

这个交互在成本上有意义：`resolveOnDemand` 配上一大堆 `ip` 规则，意味着那些本来靠
域名规则免费就能决定的连接也要查一次。

## 怎么诊断

`check` 从不解析任何东西——它是离线的，所以一份点名了不可达解析器的文件照样有效。

`doctor` 会：

```shell
rust-reality doctor -c /etc/rust-reality/config.json
```

它会查询配置的服务器并报告它们是否作答。一个能启动但什么都解析不了的节点，通常就是
这个问题。
