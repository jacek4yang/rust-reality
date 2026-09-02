# 配置参考手册

[English](../../en/configuration/reference.md) | 简体中文

每个对象、每个字段、含义、是否必填，以及不写时它变成什么。指南讲**怎么做和为什么**，
这一页讲**是什么**。

全文约定：

- **推导**——不写这个字段意味着值在启动时从这台机器算出来，而不是用一个固定常数。
- **热 / 冷**——改动是 `SIGHUP` 生效，还是需要重启。
- 密钥材料是 URL-safe 无填充 base64，解码后恰好 32 字节。

## 顶层

`role` 字段决定整份文档的形状。存在两种形状，除了 `role` 和 `listeners` 之外它们没有
共同的必填字段。

### `role: "entry"`

| 字段 | 类型 | 必填 | 含义 |
| --- | --- | --- | --- |
| `role` | `"entry"` | 是 | 选定这种形状。 |
| `listeners` | [Listener](#listener) 数组 | 是 | 公网监听端点，共用一份 REALITY 身份。 |
| `reality` | [Reality](#reality) | 是 | REALITY 身份与伪装目标。 |
| `users` | [User](#user) 数组 | 是 | 被授权的客户端身份。 |
| `outbounds` | [Outbound](#outbound) 的对象 | 否 | 按名字索引的传输。不写表示只有 `direct` 和 `block`。 |
| `routing` | [Routing](#routing) | 是 | 流量去哪。 |
| `assets` | [Assets](#assets) | 否 | Geo 数据。只有 `geoip:`/`geosite:` 条件才需要。 |
| `dns` | [Dns](#dns) | 否 | 名字解析。 |
| `network` | [Network](#network) | 否 | 出站地址族策略。 |
| `log` | [Log](#log) | 否 | 日志目的地与保留。 |
| `runtime` | [Runtime](#runtime) | 否 | 资源姿态与专家级上限。 |

### `role: "landing"`

| 字段 | 类型 | 必填 | 含义 |
| --- | --- | --- | --- |
| `role` | `"landing"` | 是 | 选定这种形状。 |
| `listeners` | [Listener](#listener) 数组 | 是 | 受防火墙限制的监听端点。 |
| `landing` | [Landing](#landing) | 是 | 这里终结的内部协议及其凭据。 |
| `egress` | string | 否 | 怎么去够被转移过来的目的地。内置出站或 `outbounds` 的键。不写表示 `direct`。 |
| `outbounds` | [Outbound](#outbound) 的对象 | 否 | 按名字索引的传输。 |
| `dns` | [Dns](#dns) | 否 | 名字解析。 |
| `network` | [Network](#network) | 否 | 出站地址族策略。 |
| `log` | [Log](#log) | 否 | 日志目的地与保留。 |
| `runtime` | [Runtime](#runtime) | 否 | 资源姿态与专家级上限。 |

落地节点没有 `reality`、`users`、`routing`。写了其中之一是错误，报错会点名那个字段。

## Listener

冷。多个监听器可以共用地址族，但不能共用同一个 socket。

| 字段 | 类型 | 必填 | 不写表示 |
| --- | --- | --- | --- |
| `port` | 整数 1–65535 | 是 | — |
| `ip` | `"auto"` \| `"dualStack"` \| `"ipv4Only"` \| `"ipv6Only"` | 否 | `"auto"` |
| `ipv4` | string | 否 | IPv4 通配地址 `0.0.0.0` |
| `ipv6` | string | 否 | IPv6 通配地址 `::` |

`auto` 绑定两个地址族，至少一个成功就启动。`dualStack` 要求都成功。`ipv4` 和 `ipv6`
用来指定具体绑定地址而不是通配地址，且只对确实要绑定的那个族生效。

## Reality

热。仅入口节点。

| 字段 | 类型 | 必填 | 不写表示 |
| --- | --- | --- | --- |
| `cover` | `host:port` | 是 | — |
| `privateKey` | 密钥材料 | 是 | — |
| `serverNames` | string 数组 | 否 | `cover` 的主机名部分 |
| `maxTimeDiffMs` | 整数 | 否 | `60000`；填 0 关闭该检查 |
| `coverOptimization` | [CoverOptimization](#coveroptimization) | 否 | 全部优化开启 |

`cover` 必填，因为只有运维才能选出一个"这台服务器替它挡在前面"说得通的主机。
`privateKey` 是秘密；配对的公钥发给客户端。

`serverNames` 的条目是精确名字，或者最左单标签通配符，例如 `*.example.com`。用 IP
写的伪装目标没有主机名可默认，所以那种情况下 `serverNames` 变成必填。

### CoverOptimization

专家级接口。它们改变这台服务器朝伪装主机做的事，所以属于运维策略而不是推导值。

| 字段 | 类型 | 不写表示 |
| --- | --- | --- |
| `enabled` | 布尔 | 开启 |
| `warmTcp` | 布尔 | 开启 |
| `prebuiltProfiles` | 布尔 | 开启 |

`warmTcp` 备好已建立 TCP 的伪装 socket；取用之前不发任何 TLS 字节。
`prebuiltProfiles` 在后台构建伪装派生的 TLS profile，并且只在认证成功且重放预留完成
之后才使用。

## User

热。仅入口节点。身份和 short ID 在整个节点内唯一。

| 字段 | 类型 | 必填 | 不写表示 |
| --- | --- | --- | --- |
| `id` | UUID | 是 | — |
| `shortIds` | string 数组 | 是 | — |
| `label` | string | 否 | 该身份用 UUID 来报告 |
| `policy` | string | 否 | 走顶层 `routing` 的默认值和规则 |

short ID 是 2–16 个十六进制字符，个数为偶数。客户端每个连接挑一条；列多条可以让同一
身份下的设备带不同的 short ID。

`label` 非密，对协议无影响。`policy` 点名 `routing.policies` 的一个键。

## Outbound

热。按名字索引；键就是名字，所以没有 `tag` 字段。`direct` 和 `block` 是内置的，不可
声明。

### `type: "socks5"`

| 字段 | 类型 | 必填 | 不写表示 |
| --- | --- | --- | --- |
| `type` | `"socks5"` | 是 | — |
| `address` | string | 是 | — |
| `port` | 整数 | 是 | — |
| `username` | string | 否 | 不认证 |
| `password` | string | 否 | 不认证 |
| `warmTcp` | 布尔 | 否 | 开启 |

`username` 和 `password` 当且仅当另一个存在时必填。

### `type: "nxr"`

| 字段 | 类型 | 必填 | 不写表示 |
| --- | --- | --- | --- |
| `type` | `"nxr"` | 是 | — |
| `address` | string | 是 | — |
| `port` | 整数 | 是 | — |
| `psk` | 密钥材料 | 是 | — |
| `warmTcp` | 布尔 | 否 | 开启 |

`psk` 必须与落地节点的 `psk` 一致，并且与文件里其它每一个密钥相互独立。

### `type: "handoff"`

| 字段 | 类型 | 必填 | 不写表示 |
| --- | --- | --- | --- |
| `type` | `"handoff"` | 是 | — |
| `address` | string | 是 | — |
| `port` | 整数 | 是 | — |
| `psk` | 密钥材料 | 是 | — |
| `landingPublicKey` | 密钥材料 | 是 | — |
| `connectTimeoutMs` | 整数 | 否 | `10000` |
| `firstByteTimeoutMs` | 整数 | 否 | `15000` |
| `warmTcp` | 布尔 | 否 | 开启 |

`landingPublicKey` 是公开材料，不是秘密：它是落地节点 `privateKey` 的公钥那半。
`firstByteTimeoutMs` 是这个节点用来发现"被静默拒绝"的手段。

## Routing

热。仅入口节点。

| 字段 | 类型 | 必填 | 不写表示 |
| --- | --- | --- | --- |
| `default` | string | 是 | — |
| `rules` | [Rule](#rule) 数组 | 否 | 没有规则；一切走 `default` |
| `policies` | [Policy](#policy) 的对象 | 否 | 没有策略 |
| `strategy` | `"asIs"` \| `"resolveIfNoMatch"` \| `"resolveOnDemand"` | 否 | `"resolveIfNoMatch"` |

`default` 必填，因为"流量默认去哪"是文件里后果最重的一行，它从不被推断。

| `strategy` | 行为 |
| --- | --- |
| `asIs` | 路由阶段从不解析；`ip` 规则只命中字面地址 |
| `resolveIfNoMatch` | 只有域名规则都没命中且存在 `ip` 规则时才解析 |
| `resolveOnDemand` | 只要有 `ip` 规则可能适用就解析 |

### Policy

| 字段 | 类型 | 必填 | 不写表示 |
| --- | --- | --- | --- |
| `default` | string | 是 | — |
| `rules` | [Rule](#rule) 数组 | 否 | 没有规则；一切走本策略的 `default` |

对选用它的用户来说，一条策略同时替换全局默认和全局规则——但 `routing.rules` 先求值，
且不可被覆盖。

### Rule

有序，首个命中优先。至少要有一个条件；没有条件的规则会被拒绝。

| 字段 | 类型 | 必填 | 不写表示 |
| --- | --- | --- | --- |
| `outbound` | string | 是 | — |
| `name` | string | 否 | 该规则按位置来报告 |
| `domain` | string 数组 | 否 | 无域名条件 |
| `ip` | string 数组 | 否 | 无 IP 条件 |
| `port` | string 数组 | 否 | 无端口条件 |

同一条件内部各项是"或"；同时存在的多个条件必须全部命中。

**域名匹配器**

| 形式 | 匹配 |
| --- | --- |
| `example.com` | 完全相同的名字 |
| `full:example.com` | 完全相同的名字 |
| `domain:example.com` | 该名字及其任意子域 |
| `keyword:example` | 任何包含该子串的名字 |
| `regexp:…` | 该正则能匹配的名字 |
| `geosite:cn` | 该 geo 列表里的名字 |
| `ext:file.dat:tag` | 外部数据文件里的一个标签 |

**IP 匹配器**——字面地址、CIDR 段，或 `geoip:标签`。`geoip:private` 内置，不需要数据
文件。

**端口匹配器**——单个端口，或闭区间 `from-to`。

## Landing

热，包括密钥轮换。仅落地节点。用 `protocol` 做判别。

### `protocol: "nxr"`

| 字段 | 类型 | 必填 | 不写表示 |
| --- | --- | --- | --- |
| `protocol` | `"nxr"` | 是 | — |
| `psk` | 密钥材料 | 是 | — |
| `authenticationTimeoutMs` | 整数 | 否 | `3000` |
| `connectTimeoutMs` | 整数 | 否 | `10000` |
| `preAuthIdleTimeoutMs` | 整数 | 否 | `60000` |
| `maxTimeDifferenceSeconds` | 整数 | 否 | `30` |

### `protocol: "handoff"`

| 字段 | 类型 | 必填 | 不写表示 |
| --- | --- | --- | --- |
| `protocol` | `"handoff"` | 是 | — |
| `psk` | 密钥材料 | 是 | — |
| `privateKey` | 密钥材料 | 是 | — |
| `previousPsks` | 密钥材料数组 | 否 | 没有轮换窗口 |
| `previousPrivateKeys` | 密钥材料数组 | 否 | 没有轮换窗口 |
| `authenticationTimeoutMs` | 整数 | 否 | `3000` |
| `connectTimeoutMs` | 整数 | 否 | `10000` |
| `preAuthIdleTimeoutMs` | 整数 | 否 | `60000` |
| `maxTimeDifferenceSeconds` | 整数 | 否 | `30` |

每个列表最多两个退役密钥，且都要与当前密钥不同。发送方永远用当前密钥封装；退役密钥
的存在只是为了让轮换可以一台一台做。要尽快删掉——见
[Handoff](handoff.md#不中断流量地轮换)。

## Assets

热。仅入口节点。只有当某条路由规则点名了 `geoip:` 或 `geosite:` 条件（内置的
`geoip:private` 除外）时才会被读取。

| 字段 | 类型 | 必填 | 不写表示 |
| --- | --- | --- | --- |
| `geoip` | HTTPS URL | 否 | 没有 GeoIP 数据 |
| `geosite` | HTTPS URL | 否 | 没有 GeoSite 数据 |
| `cacheDirectory` | 路径 | 否 | `/var/lib/rust-reality/assets` |
| `reloadIntervalSeconds` | 整数 | 否 | 一天 |

源必须是 `https://`，带内嵌凭据的 URL 会被拒绝。轮询失败时最后一份好快照继续服务。

## Dns

冷。解析器在整个进程生命周期里只安装一次。

| 字段 | 类型 | 必填 | 不写表示 |
| --- | --- | --- | --- |
| `servers` | string 数组 | 否 | `["system"]` |
| `timeoutMs` | 整数 | 否 | `5000` |
| `cache` | [DnsCache](#dnscache) | 否 | 每个边界都推导 |

恰好是 `["system"]` 时通过 `getaddrinfo` 使用操作系统解析器，遵循 `/etc/resolv.conf`。
`"system"` 不能与其它条目混写。

### DnsCache

专家级接口。每个字段都能推导出安全值，普通部署没有理由写其中任何一个。

| 字段 | 类型 | 不写表示 |
| --- | --- | --- |
| `maxEntries` | 整数 | `1024` |
| `minTtlSeconds` | 整数 | `5` |
| `maxTtlSeconds` | 整数 | `3600` |
| `negativeTtlSeconds` | 整数 | `60` |
| `staticTtlSeconds` | 整数 | `300` |
| `systemReuseMs` | 整数 | 推导 |

`maxTtlSeconds` 不能低于 `minTtlSeconds`。没有 SOA TTL 的答案从不做负缓存。

## Network

冷。出站地址族策略，与 `listeners[].ip` 无关。

| 字段 | 类型 | 不写表示 |
| --- | --- | --- |
| `ip` | `"auto"` \| `"preferIpv4"` \| `"preferIpv6"` \| `"ipv4Only"` \| `"ipv6Only"` | `"auto"` |

## Log

热。

| 字段 | 类型 | 不写表示 |
| --- | --- | --- |
| `level` | `"error"` \| `"warn"` \| `"info"` \| `"debug"` | `"info"` |
| `output` | `"stderr"` \| `"journald"` \| `"file"` \| `"none"` | `"stderr"` |
| `file` | [FileLog](#filelog) | — |

`stderr` 是 systemd 无需额外配置就能收进 journal 的那个；`journald` 是同一路输出，
但按 journald 自己的解析格式排版。`none` 在任何编码和 I/O 之前就丢弃所有事件，因此也
会把 warn 级的拒绝和准入信号一并静音——除非日志本身不可接受，否则优先用 `level` 过滤。

`file` 由 `output: "file"` 要求，也只对它有意义，两者互为条件。

### FileLog

| 字段 | 类型 | 必填 | 不写表示 |
| --- | --- | --- | --- |
| `path` | 路径 | 是 | — |
| `maxBytes` | 整数 | 否 | 64 MiB |
| `maxFiles` | 整数 | 否 | `8` |
| `maxTotalBytes` | 整数 | 否 | `maxBytes` × `maxFiles` |

## Runtime

冷，每个字段都是。

| 字段 | 类型 | 不写表示 |
| --- | --- | --- |
| `profile` | `"auto"` \| `"shared"` \| `"dedicated"` | `"auto"` |
| `tuning` | `"startup"` \| `"adaptive"` | `"startup"` |
| `objective` | `"balanced"` \| `"latency"` \| `"throughput"` | `"balanced"` |
| `statusFile` | 路径 | 不发布快照 |
| `limits` | [Limits](#limits) | 每个值都推导 |

`statusFile` 只在 `tuning: "adaptive"` 下被读取，在 `startup` 下写它会被拒绝而不是
被忽略。

### Limits

专家级覆盖。**每个字段都可选，写了就钉死在所写的值上**——包括恰好等于推导值的那种。
不写的字段从检测到的机器推导。

| 字段 | 类型 | 不钉表示 |
| --- | --- | --- |
| `maxConnections` | 整数 | 推导 |
| `maxHandshakes` | 整数 | 推导 |
| `clientHelloTimeoutMs` | 整数 | 记载的默认值 |
| `handshakeTimeoutMs` | 整数 | 记载的默认值 |
| `connectTimeoutMs` | 整数 | 记载的默认值 |
| `fallbackTimeoutMs` | 整数 | 记载的默认值 |
| `splice` | 布尔 | 检测到的平台能力 |
| `pipePool` | 布尔 | 检测到的平台能力 |

那四个超时是协议安全参数而不是机器预算，所以从不推导。`splice` 和 `pipePool` 的存在
是为了绕开一个宣称支持某能力然后又表现异常的内核。

转发缓冲区大小、池边界、预热连接尺寸、直连闸门、重放缓存容量、DNS 缓存内部参数都没有
对应字段：它们是从机器推导的实现细节。见[运行时与资源](runtime-and-resources.md)。

## 热冷一览

| 段落 | 热 | 冷 |
| --- | --- | --- |
| `role` | | ✓ |
| `listeners` | | ✓ |
| `reality` | ✓ | |
| `users` | ✓ | |
| `outbounds` | ✓ | |
| `routing` | ✓ | |
| `landing` | ✓ | |
| `egress` | ✓ | |
| `assets` | ✓ | |
| `log` | ✓ | |
| `dns` | | ✓ |
| `network` | | ✓ |
| `runtime` | | ✓ |

改动冷配置的重载会被指名拒绝，正在跑的配置继续服务。已建立的连接永远在接纳它们的那
一代上跑完。
