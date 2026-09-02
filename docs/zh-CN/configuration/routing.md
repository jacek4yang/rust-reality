# 路由

[English](../../en/configuration/routing.md) | 简体中文

决定每个连接去哪。默认出站必填；规则和按用户区分的策略都是可选的，大多数节点两个
都不需要。

## 默认出站

```json
{ "routing": { "default": "direct" } }
```

`default` 必填，这样没有哪份配置会对自己的兜底行为含糊其辞。这一页后面所有内容都
是在收窄它。

## 规则

`routing.rules` 对所有用户生效。它是数组，因为顺序有意义：**首个命中优先**，命中
即停止。

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
    "default": "direct",
    "strategy": "resolveIfNoMatch",
    "rules": [
      {
        "name": "block-private",
        "ip": [
          "geoip:private"
        ],
        "outbound": "block"
      },
      {
        "name": "block-ads",
        "domain": [
          "geosite:category-ads-all"
        ],
        "outbound": "block"
      },
      {
        "name": "no-smtp",
        "port": [
          "25",
          "465",
          "587"
        ],
        "outbound": "block"
      }
    ]
  }
}
```

一条规则由名字、至少一个条件、一个出站组成。`name` 可选，但值得写——它是规则命中
时 `explain --route` 报出来的东西，而"第三条规则"在凌晨三点是个很糟糕的读物。

没有条件的规则会被拒绝。空条件列表会匹配一切，而那正是 `default` 的职责；一条因为
某个字段留空就悄悄吞掉全部流量的规则，恰恰是本项目拒绝拥有的那种失败。

## 条件

一条规则可以带三种条件的任意组合：

| 条件 | 匹配 |
| --- | --- |
| `domain` | 目的地主机名 |
| `ip` | 目的地地址 |
| `port` | 目的地端口 |

同一个条件内部，各项是"或"——命中任意一项即可。不同条件之间是"与"：同时写了
`domain` 和 `port` 的规则，两者都要命中。

### 域名匹配器

| 形式 | 匹配 |
| --- | --- |
| `example.com` | 完全相同的名字 |
| `full:example.com` | 完全相同的名字，显式写法 |
| `domain:example.com` | 该名字及其任意子域 |
| `keyword:example` | 任何包含该子串的名字 |
| `regexp:^ad[0-9]+\\.` | 该正则能匹配的名字 |
| `geosite:cn` | 该 geo 列表里的名字 |
| `ext:file.dat:tag` | 外部数据文件里的一个标签 |

优先用 `domain:` 而不是 `keyword:`。`keyword:ads` 会连
`downloads.example.com` 一起匹配上。

### IP 匹配器

一个地址、一个 CIDR 段，或者一个 `geoip:` 标签：

```json
{ "ip": ["10.0.0.0/8", "192.168.0.0/16", "203.0.113.7", "geoip:private"] }
```

`geoip:private` 是内置的，不需要下载数据。其它 `geoip:` 标签都需要 geo 文件。

### 端口匹配器

单个端口，或者一个区间：

```json
{ "port": ["25", "465", "587", "6000-6010"] }
```

## `strategy`

```json
{ "routing": { "default": "direct", "strategy": "resolveIfNoMatch" } }
```

`ip` 条件需要地址，而目的地经常是以名字到达的。strategy 决定什么时候去解析它：

| 取值 | 行为 |
| --- | --- |
| `resolveIfNoMatch`（默认） | 先试域名规则；只有都没命中且存在 `ip` 规则时才解析 |
| `asIs` | 路由阶段从不解析；`ip` 规则只能命中本来就是地址的目的地 |
| `resolveOnDemand` | 只要有 `ip` 规则可能适用就解析 |

默认值是一个刻意的折中：全靠域名做决定的规则集永远不必为解析付费，而需要地址的
规则集能拿到地址。

DNS 慢或者不可信、并且你接受 `ip` 规则看不到域名目的地时，用 `asIs`。当某条 `ip`
规则是一条必须对名字也生效的安全边界时，用 `resolveOnDemand`——比如一条拦截私有
地址段的 `block` 规则，在 `resolveIfNoMatch` 下，一个解析到你内网的主机名可能会
先被某条域名规则命中而溜过去。

## 按用户区分的策略

需要区别对待用户时，给用户指定一条策略：

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
    },
    {
      "id": "22222222-2222-4222-8222-222222222222",
      "shortIds": [
        "fedcba9876543210"
      ],
      "label": "bob",
      "policy": "split"
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
    "default": "direct",
    "rules": [
      {
        "name": "block-private",
        "ip": [
          "geoip:private"
        ],
        "outbound": "block"
      }
    ],
    "policies": {
      "split": {
        "default": "landing-1",
        "rules": [
          {
            "name": "home-direct",
            "domain": [
              "geosite:cn"
            ],
            "outbound": "direct"
          }
        ]
      }
    }
  }
}
```

一条策略就是一个 `default` 加上可选的 `rules`，用户按名字选用它。没写 `policy`
的用户走全局默认。

一个连接的求值顺序：

1. `routing.rules`——全局规则，按顺序，首个命中优先。
2. 都没命中且该用户有策略，则走该策略的 `rules`，按顺序。
3. 否则走该策略的 `default`；没有策略的用户走 `routing.default`。

全局规则先跑，因此策略覆盖不了它们。这正是"必须对所有人都成立的规则"该待的地方
——比如拦截私有地址段。

策略按名字索引，所以用户点名一个不存在的策略会被拒绝，并列出可用的名字。

## 检查一个决定

靠读规则列表来推断某个目的地去哪，很容易出错。直接问：

```shell
rust-reality explain -c config.json --route example.com
```

```
example.com for alice -> direct (routing, default outbound)
```

回答会点名出站、做决定的那份列表，以及是怎么决定的。`global rule` 表示
`routing.rules`；`policy rule` 表示用户策略里的规则；`default outbound` 表示什么
都没命中，用了那份列表的 `default`。

它接受 `host` 或 `host:port`，包括带方括号和不带方括号的 IPv6 字面量，端口默认
443。

和 `explain` 的其它部分一样，它是离线的，这限定了它能说什么。`geoip:` 或
`geosite:` 条件是对着空数据求值的，所以永远不命中；回答会明说这一点，而不是报出
一条运行中的服务端不会选的路径：

```
note: geo conditions were not evaluated: `explain` is offline, so a rule
naming geoip: or geosite: was treated as not matching. Use `doctor` to load
the data.
```

## Geo 数据

点名了 `geoip:private` 以外的 `geoip:` 或 `geosite:` 标签的规则需要数据文件。指向
它们，它们就会被下载并缓存：

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
    "default": "direct",
    "rules": [
      {
        "name": "cn-direct",
        "domain": [
          "geosite:cn"
        ],
        "outbound": "direct"
      }
    ]
  },
  "assets": {
    "geoip": "https://example.com/geoip.dat",
    "geosite": "https://example.com/geosite.dat",
    "cacheDirectory": "/var/lib/rust-reality/assets",
    "reloadIntervalSeconds": 86400
  }
}
```

| 字段 | 含义 |
| --- | --- |
| `geoip` | GeoIP 数据文件的 HTTPS URL |
| `geosite` | GeoSite 数据文件的 HTTPS URL |
| `cacheDirectory` | 快照存放位置 |
| `reloadIntervalSeconds` | 多久重新拉一次 |

源必须是 `https://`，带内嵌凭据的 URL 会被拒绝。刷新失败时最后一份好快照继续服务，
不会把节点拖垮。

`check` 从不去拉——它是离线的。`doctor` 会拉，所以它才是那个能告诉你"规则里点名的
标签在你指向的数据里到底存不存在"的命令。

## 热更新

`routing` 是热的。规则、策略、默认出站和 strategy 都在 SIGHUP 后生效。已建立的
连接保留它们开始时的那张表，所以重载不会给活着的会话改道。
