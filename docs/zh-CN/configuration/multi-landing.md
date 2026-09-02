# 多落地节点

[English](../../en/configuration/multi-landing.md) | 简体中文

一个线路节点，多个出口，按用户或按目的地来选。

## 什么时候值得这么做

三个理由，大致按出现频率排：

- **不同的出口位置。** 有人需要欧洲出口，有人需要美国出口，但入口只有一个。
- **影响面。** 烧掉一个落地节点，只带走它的用户，而不是所有人。
- **容量。** 两个落地节点分担一个节点本来要扛的量。

这三条都不成立的话，一个落地节点更简单，而简单更好。

## 形状

```
                          ┌─▶ landing-eu ──▶ 目的地
客户端 ──▶ 线路节点 ───────┤
                          └─▶ landing-us ──▶ 目的地
```

每个落地节点都是普通的落地节点——就是[线路节点与落地节点](line-landing.md)里那份
文件，一字不改。要干的活全在线路节点上，而且全是路由。

## 把用户分配到落地节点

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
      "label": "alice",
      "policy": "via-eu"
    },
    {
      "id": "22222222-2222-4222-8222-222222222222",
      "shortIds": [
        "fedcba9876543210"
      ],
      "label": "bob",
      "policy": "via-us"
    }
  ],
  "outbounds": {
    "landing-eu": {
      "type": "nxr",
      "address": "10.0.0.2",
      "port": 7443,
      "psk": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"
    },
    "landing-us": {
      "type": "nxr",
      "address": "10.0.0.3",
      "port": 7443,
      "psk": "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU"
    }
  },
  "routing": {
    "default": "landing-eu",
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
      "via-eu": {
        "default": "landing-eu"
      },
      "via-us": {
        "default": "landing-us",
        "rules": [
          {
            "name": "eu-sites-stay-eu",
            "domain": [
              "geosite:category-eu"
            ],
            "outbound": "landing-eu"
          }
        ]
      }
    }
  }
}
```

每个落地节点是一个出站。每条策略点名它的默认落地节点。每个用户点名它的策略。没写
`policy` 的用户走 `routing.default`。

`via-us` 还带了一条规则：走美国出口的用户，访问欧洲站点时仍然从欧洲落地节点出去。
这就是通用形状——一条策略就是一个默认值，加上这组用户需要的那些例外。

分配结果别靠回读，直接看：

```shell
rust-reality explain -c config.json
```

```
routing:
  default: landing-eu (1 rule, strategy resolveIfNoMatch)
  policy via-eu: default landing-eu (0 rules, 1 user)
  policy via-us: default landing-us (1 rule, 1 user)
  outbounds: direct, block, landing-eu, landing-us
```

用户计数是这里最有用的部分。一条零用户的策略，要么是写错了，要么是没清理干净。

## 每个落地节点要有自己的密钥

每个落地节点都用自己的预共享密钥；如果是 Handoff，还要自己的密钥对：

```shell
rust-reality generate psk    # 每个落地节点一个
```

多个落地节点共用一个密钥，意味着从一个节点上拿到的密钥能打开所有节点。校验器会拒绝
同一份文件里两个出站带相同密钥材料——但这只是因为两个值恰好都在一个地方看得见。

## 混用 NXR 和 Handoff

没有规定落地节点必须用同一种协议。一个可信的落地节点走 NXR、另一个不太可信的走
Handoff，是完全合理的配置，线路节点的文件里就是两个 `type` 不同的出站。

## 故障是按连接计的

落地节点之间没有健康检查、没有故障转移、也没有负载均衡。路由到一个挂掉的落地节点的
连接会失败，下一个连接再试一次。

这是刻意的。自动故障转移会悄悄把某个用户的流量挪到另一个出口 IP，而那恰恰是他们
选定某个落地节点所要控制的性质。落地节点挂了，由运维来决定——改策略的默认值再重载，
立刻生效，且不影响任何已建立的连接。

```json
{ "routing": { "policies": { "via-us": { "default": "landing-eu" } } } }
```

## 加一个

1. 起好新落地节点，并用防火墙只放行线路节点。
2. 生成它的密钥材料。
3. 在线路节点上加出站和策略。
4. `check`，然后重载。
5. 按你想要的节奏把用户挪到新策略上。

第 3 到 5 步全是热的。不用重启，也不影响任何已建立的连接。

## 删一个

把它那条策略的默认值指到别处，重载，然后等已有连接跑完——它们会在接纳它们的那一代上
继续跑。然后删掉出站和策略、再重载一次，最后关掉那台落地节点。

在还有连接用着的时候删出站不会弄坏它们，但也意味着这次重载无法靠"把出站加回来"撤销：
无论如何那些连接都已经在它们自己那一代上了。
