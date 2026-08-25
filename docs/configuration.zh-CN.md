# 配置参考

[English](configuration.md) | 简体中文

本文覆盖 `rust-reality` 1.x 接受的全部 JSON 字段。最终权威仍是实际二进制：

```shell
rust-reality schema > rust-reality.schema.json
rust-reality check --config config.json
rust-reality config format --config config.json > config.formatted.json
```

## 格式与验证模型

- 文件是 UTF-8 JSON，最大 4 MiB。
- 字段名采用区分大小写的 camelCase；枚举字符串必须严格使用本文形式。
- 每一个强类型对象都会拒绝未知字段。
- 只有本文明确写出“默认值”的字段才会缺省填充。
- `check` 会验证 JSON Schema 无法表达的引用、跨字段安全和资源不变量。
- 最安全的起点是生成配置；不要复制文档中的示例密钥或 UUID。

顶层结构：

```json
{
  "log": {},
  "assets": {},
  "dns": {},
  "network": {},
  "inbounds": [],
  "outbounds": [],
  "routing": {},
  "advanced": {},
  "runtime": {}
}
```

| 字段 | 必填 | 默认值 | 含义 |
| --- | --- | --- | --- |
| `log` | 否 | stderr/info | 日志目标、级别和有界文件保留。 |
| `assets` | 否 | 社区 GeoIP/GeoSite URL 和有界缓存默认值 | 路由资产来源与刷新策略。 |
| `dns` | 否 | 系统解析器、5000 ms | 所有 connector 侧查询共用的共享解析器、缓存与超时策略。 |
| `network` | 否 | 自治双栈 | 出站地址族选择、健康记忆和回退时序。监听地址族由入站的 `listen` 决定。 |
| `inbounds` | 是 | — | 至少一个强类型 `vless` 或内部 `nxr`、`handoff` 监听。 |
| `outbounds` | 是 | — | 至少一个 `direct`、`blackhole`、`socks5`、`nxr` 或 `handoff` 传输。 |
| `routing` | 是 | — | 全局规则和显式 UUID 分组策略。 |
| `advanced` | 否 | 有界生产默认值 | 专家逃生舱：`advanced.limits` 保存数值化的 admission、direct 拨号、缓冲和 Linux relay 策略。 |
| `runtime` | 否 | `standard` 姿态、`auto` profile | 进程资源姿态、机器租户 profile 与策略调谐模式。 |

从 1.4 升级配置必须迁移：标量形式 `"listen": "<ip>"` 和
`network.addressFamily` 都会被拒绝。完整的新旧字段映射表见
[CHANGELOG 1.5.0 迁移说明](../CHANGELOG.md)。

## `log`

| 字段 | 必填 | 默认值/允许值 | 含义与约束 |
| --- | --- | --- | --- |
| `log.level` | 否 | `info`；`error`、`warn`、`info`、`debug` | 最低输出级别。Debug 也不会包含配置和密钥。 |
| `log.output` | 否 | `stderr`；`stderr`、`journald`、`file`、`none` | `journald` 仍写 stderr 供 systemd 捕获；`file` 启用内置轮转；`none` 在任何编码或 I/O 之前丢弃全部事件。 |
| `log.file` | 仅 `output: "file"` | 不存在 | stderr/journald/none 时禁止；包含下列全部字段。 |
| `log.file.path` | 是 | — | 非空活动日志路径，父目录必须允许服务账号写入。 |
| `log.file.maxBytes` | 是 | — | 单文件达到 `65536..=1073741824` 字节前轮转。 |
| `log.file.maxFiles` | 是 | — | 活动文件加轮转文件最多 `1..=64` 个。 |
| `log.file.maxTotalBytes` | 是 | — | 至少为 `maxBytes`，最多为 `maxBytes * maxFiles`。 |

结构化日志不会输出秘密、完整配置、UUID 值、凭据或密钥材料。上述限制只约束
应用日志保留，不能替代文件系统 quota。

## `assets`

| 字段 | 必填 | 默认值 | 含义与约束 |
| --- | --- | --- | --- |
| `assets.geoip` | 否 | jsDelivr 上 `Loyalsoldier/v2ray-rules-dat` 的 `geoip.dat` | 必须是有 host、无内嵌凭据的 HTTPS URL。 |
| `assets.geosite` | 否 | 同仓库的 `geosite.dat` | 必须是有 host、无内嵌凭据的 HTTPS URL。 |
| `assets.cacheDirectory` | 否 | `/var/lib/rust-reality/assets` | 非空持久目录，保存文件、HTTP validator 和外部资产。 |
| `assets.reloadIntervalSeconds` | 否 | `86400` | 条件重验证周期，必须大于零。 |
| `assets.requestTimeoutSeconds` | 否 | `120` | 单次请求（含响应体）绝对超时，`1..=300`。 |
| `assets.maxBytes` | 否 | `134217728` | 每个 GeoIP、GeoSite 或外部文件最大字节数，`1024..=536870912`。 |

重定向次数有界，HTTP validator 会复用，候选文件必须解析完成后才原子发布。
失败时保留内存和磁盘中的最后有效版本。只索引路由实际引用的 GeoIP/GeoSite 标签。

`ext:文件:标签` 从 `cacheDirectory` 下的相对路径读取兼容 Xray 的 DAT 文件。
文件部分只能包含正常相对路径组件；绝对路径、`.`/`..` 和路径穿越都会被拒绝。
外部文件由运维人员提供；程序只直接下载上面的两个主 Geo URL。

## `dns`

所有 connector 侧的域名解析——direct 出站拨号、REALITY 伪装目标，以及
SOCKS5/NXR/Handoff 服务器名——都经过一个共享的进程级解析器。每次解析
持有一个 `DnsLookup` 准入许可（`advanced.limits.resourceGovernor.maxDnsLookups`），
完全相同的并发查询会合并为一次上游请求（singleflight）。路由策略查询
（`domainStrategy: IPIfNonMatch`/`IPOnDemand`）则刻意使用系统解析器，
使 IP 规则检查的地址与实际拨号的地址完全一致。

| 字段 | 必填 | 默认值 | 含义与约束 |
| --- | --- | --- | --- |
| `dns.servers` | 否 | `["system"]` | 严格等于 `["system"]` 时选择操作系统解析器（getaddrinfo）。任何其他列表选择内置 DNS 协议解析器（UDP，TCP 回退）：条目可以是 IP 字面量、`ip:port`、`[v6]:port`，或启动时经系统解析器引导解析一次的主机名；默认端口 53。不允许把 `system` 与上游服务器混用，混用会被拒绝。 |
| `dns.timeoutMs` | 否 | `5000` | 单次解析的绝对超时，`1..=600000`。 |
| `dns.cache.maxEntries` | 否 | `1024` | 缓存域名数上限（计入阳性、阴性和在途条目），`1..=65536`。 |
| `dns.cache.minTtlSeconds` | 否 | `5` | 对上游阳性 TTL 施加的下限钳制；不得超过 `maxTtlSeconds`。 |
| `dns.cache.maxTtlSeconds` | 否 | `3600` | 对上游阳性 TTL 施加的上限钳制，`1..=86400`。 |
| `dns.cache.negativeTtlSeconds` | 否 | `60` | 对上游阴性（SOA）TTL 施加的上限钳制，`0..=86400`。没有 SOA TTL 的 NXDOMAIN/NODATA 应答绝不缓存。 |
| `dns.cache.staticTtlSeconds` | 否 | `300` | 已配置静态对端（REALITY 伪装目标、固定的 SOCKS5/NXR/Handoff 端点）在任意解析器模式下的缓存时长，`1..=86400`。 |
| `dns.cache.systemReuseMs` | 否 | `0` | 可选的近期完成复用窗口（毫秒），仅在 `dns.servers = ["system"]` 时生效：不带 TTL 的 getaddrinfo 阳性应答最多复用该时长，`0..=60000`。这不是权威 TTL 缓存——上游变更只在窗口过期后可见；阴性应答绝不缓存，也不提供过期期间旧应答（stale-while-revalidate）。`0` 表示关闭。使用真实 DNS 服务器时忽略此项，由上游 TTL 决定。 |

缓存标识是（查询类别，域名）二元组：同一域名的静态对端条目与动态
会话条目是相互独立的槽位，生命周期互不影响，并共同计入
`maxEntries`。静态 TTL 绝不会延长动态应答，动态应答也绝不会满足静态
查询。

system 模式不缓存动态应答：getaddrinfo 不提供 TTL，因此只有
singleflight 合并和准入治理生效，除非配置了可选的 `systemReuseMs`
近期完成复用窗口。使用真实 DNS 服务器时，每条缓存的
阳性或阴性应答都携带按上述边界钳制后的上游 TTL。已配置静态对端是
明确的例外：它们在任意解析器模式下都会被缓存，其过期风险由运维者
通过 `staticTtlSeconds` 自行承担；静态阴性结果绝不缓存。

一个域名最多保留 64 个唯一地址。direct 出站复用 IP/GeoIP 路由决策使用的
同一地址快照，避免第二次解析得到不一致结果。

解析器在启动时安装一次，属于进程生命周期：热更新时若 `dns.servers`、
`dns.timeoutMs` 或 `dns.cache` 发生变化会被拒绝（`DnsPolicyChanged`），
因为任何热更新生成都无法替换已安装的解析器。

上游 DNS 使用不带 DNSSEC 校验的明文 UDP/TCP，因此 `dns.servers` 必须指向
你信任的解析器；被伪造的应答最多按上述钳制后的 TTL 存续。

## `network`

```json
{
  "dial": {
    "mode": "auto",
    "fallbackDelayMs": 250,
    "routeRefreshSeconds": 30,
    "hardFailurePenaltySeconds": 30,
    "latencyMemorySeconds": 300
  }
}
```

| 字段 | 必填 | 默认值/允许值 | 含义与约束 |
| --- | --- | --- | --- |
| `network.dial.mode` | 否 | `auto`；`auto`、`preferIpv4`、`preferIpv6`、`ipv4Only`、`ipv6Only` | 控制本进程解析并拨号的端点地址族；不控制入站监听。 |
| `network.dial.fallbackDelayMs` | 否 | `250` | 启动首个备用地址族尝试前的延迟，`0..=5000`；首选族立即失败时不等待。 |
| `network.dial.routeRefreshSeconds` | 否 | `30` | 本地内核路由/源地址刷新周期，`1..=3600`。 |
| `network.dial.hardFailurePenaltySeconds` | 否 | `30` | 连续强地址族失败后的降级时间及有界恢复探测间隔，`1..=3600`。 |
| `network.dial.latencyMemorySeconds` | 否 | `300` | 每地址族成功建连延迟 EWMA 的记忆时间，`1..=86400`。 |

启动时，`auto` 只做一次本地内核路由/源地址选择并缓存为进程级快照。仅一个地址族
可用时选它为主；两个都可用时，以系统解析器/地址选择顺序建立稳定的初始偏好，绝不
无证据硬编码 IPv4 或 IPv6。检测不发送数据包，也不会访问公共探测主机。
`preferIpv4`/`preferIpv6` 启用两族并在可用时选择指定族；`ipv4Only`/`ipv6Only`
是严格模式，连数字字面量在内的另一族结果都会被过滤。

周期路由刷新与真实连接结果只更新两个固定原子健康记录。连续两次
`EAFNOSUPPORT`、`EPROTONOSUPPORT`、`ENETUNREACH`、`EHOSTUNREACH`、
`EADDRNOTAVAIL` 或 `ENODEV` 才触发临时惩罚。`ECONNREFUSED` 与
`ECONNRESET` 证明该族路径可达，并清除待定强失败；普通超时或单个不可达目标不会
污染全局健康。备用族获胜而首选尝试仍挂起只算弱证据，连续三次才切换主族。路由恢复
或惩罚到期后允许有界恢复尝试，两次成功后恢复配置/启动偏好。

混合 A/AAAA 结果会去重并交错排列。最多同时进行两个 connect；所有尝试共用一个绝对
截止时间；首个成功者获胜；返回前会取消并回收落败任务和套接字。每个活动候选都持有
一个 FD 预算单位；第二个单位不可用时会串行回退，绝不突破预算。SOCKS5/NXR/Handoff
服务器名称使用此策略解析；有意交给远端代理的原始目标保持不变。

## `inbounds`

`inbounds` 不得为空。每个监听的 `tag` 唯一，两个条目展开后不能绑定相同
`(listen, port)`。tag 长度 1–64，只能包含 ASCII 字母、数字、点、横线和下划线。
`port` 范围 `1..=65535`。

每个 `listen` 都是包含 `mode`、`ipv4`、`ipv6` 的对象。`auto` 尝试两个独立
套接字，至少一个绑定成功即可启动；只有地址族/协议不可用（`EAFNOSUPPORT`、
`EPROTONOSUPPORT`，或未指定通配地址上的 `EADDRNOTAVAIL`）可降级。
`EADDRINUSE`、`EACCES`、无效具体地址以及其他绑定错误均为致命。
`dualStack` 强制两族都成功；`ipv4Only`/`ipv6Only` 只绑定指定地址。IPv6 套接字
始终在 bind 前设置 `IPV6_V6ONLY=1`，不依赖 `net.ipv6.bindv6only`。启动日志会
准确列出活动与不可用地址族；拓扑到重启前固定。监听或出站拨号策略变更都需要重启。

### 公网 VLESS + REALITY + Vision 入站

```json
{
  "protocol": "vless",
  "tag": "public-reality",
  "listen": { "mode": "auto", "ipv4": "0.0.0.0", "ipv6": "::" },
  "port": 443,
  "settings": {
    "clients": [
      {
        "id": "GENERATED-UUID",
        "shortIds": ["0123456789abcdef", "1023456789abcdef"],
        "email": "operator-label",
        "flow": "xtls-rprx-vision"
      }
    ],
    "decryption": "none"
  },
  "streamSettings": {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
      "target": "www.example.com:443",
      "serverNames": ["www.example.com"],
      "privateKey": "GENERATED-X25519-PRIVATE-KEY",
      "maxTimeDiffMs": 60000,
      "coverOptimization": {
        "enabled": true,
        "warmTcp": true,
        "prebuiltProfiles": true
      }
    }
  }
}
```

以上占位符故意不能直接使用。请通过 `config generate standalone`、
`config generate line` 或 `config generate handoff` 生成真实状态。

| 字段 | 必填 | 默认值/固定值 | 含义与约束 |
| --- | --- | --- | --- |
| `protocol` | 是 | 固定 `vless` | 选择唯一公网协议。 |
| `tag` | 是 | — | 唯一监听/路由 tag。 |
| `listen` | 是 | — | 含 `mode`（`auto`、`dualStack`、`ipv4Only`、`ipv6Only`）及 `ipv4`/`ipv6` 地址的对象。 |
| `port` | 是 | — | 非零 TCP 端口。 |
| `settings.clients` | 是 | — | 非空授权客户端数组；UUID 在所有公网入站中全局唯一。 |
| `settings.clients[].id` | 是 | — | 带横线的规范 UUID；身份比较时十六进制大小写不敏感。 |
| `settings.clients[].shortIds` | 是 | — | 此 UUID 独占的非空 short ID 列表；每项为 2–16 个偶数长度十六进制字符，在本入站内大小写不敏感唯一；多个值用于轮换。 |
| `settings.clients[].email` | 否 | 不存在 | 非秘密运维标签，不参与认证或路由。 |
| `settings.clients[].flow` | 是 | 固定 `xtls-rprx-vision` | 其他 flow 全部拒绝。 |
| `settings.decryption` | 否 | 固定/默认 `none` | 为接近 Xray 配置形状而保留，其他值拒绝。 |
| `streamSettings.network` | 是 | 固定 `tcp` | 尚未实现公网 UDP。 |
| `streamSettings.security` | 是 | 固定 `reality` | 纯 VLESS 或仅 TLS VLESS 拒绝。 |
| `streamSettings.realitySettings.target` | 是 | — | `host:port` 伪装目标；IPv6 加方括号；先从服务器探测。 |
| `streamSettings.realitySettings.serverNames` | 是 | — | 非空、大小写不敏感唯一的具体 ASCII DNS 名或最左侧单标签模式，如 `*.lmu.edu`。 |
| `streamSettings.realitySettings.privateKey` | 是 | — | URL-safe 无填充 base64，解码为恰好 32 字节 X25519 私钥；秘密。 |
| `streamSettings.realitySettings.maxTimeDiffMs` | 否 | `60000` | 接受的客户端时钟差，`0..=600000`；零表示关闭该检查。 |
| `streamSettings.realitySettings.coverOptimization.enabled` | 否 | `true` | 已认证伪装优化总开关；绝不改变拒绝/fallback 行为。 |
| `streamSettings.realitySettings.coverOptimization.warmTcp` | 否 | `true` | 保留有界、已完成 TCP 建连的伪装 socket；认证 checkout 前不发送 TLS 字节。 |
| `streamSettings.realitySettings.coverOptimization.prebuiltProfiles` | 否 | `true` | 用受控探针收集有界、仅内存的伪装 profile；只有 ClientHello class 精确匹配且 profile 已验证时，才在本地生成全新认证 flight。miss 始终使用真实伪装目标。 |

每个公网 UUID 必须在 `routing.users[].userIds` 中恰好出现一次。

通配符 server name 使用与证书相同的单标签语义：

- `*.lmu.edu` 接受具体 SNI `www.lmu.edu` 或 `vpn.lmu.edu`；
- 不接受 `lmu.edu`、`a.b.lmu.edu`，也不接受客户端直接发送 `*.lmu.edu`；
- 通配符必须独占最左侧标签，且后缀至少两级，因此 `www.*.edu`、`*.*.edu`
  和 `*.edu` 都会拒绝；
- 客户端必须发送具体 SNI。`self-test` 只有在 `target` 含匹配的具体 hostname 时
  才能探测通配符，例如 target `www.lmu.edu:443` 配合模式 `*.lmu.edu`。

初次生成时尽量给 `--server-name` 传具体名称；只有确实需要多个真实证书名称时，
才在审查后加入通配符。

### 内部 NXR 入站

```json
{
  "protocol": "nxr",
  "tag": "internal-nxr",
  "listen": { "mode": "auto", "ipv4": "0.0.0.0", "ipv6": "::" },
  "port": 7443,
  "settings": {
    "preSharedKey": "GENERATED-NXR-KEY",
    "maxTimeDifferenceSeconds": 30,
    "maxNonceEntries": 65536,
    "nonceRetentionSeconds": 120,
    "authenticationTimeoutMs": 3000,
    "connectTimeoutMs": 10000
  }
}
```

| 字段 | 必填 | 默认值 | 含义与约束 |
| --- | --- | --- | --- |
| `protocol` | 是 | 固定 `nxr` | 选择内部落地协议。 |
| `tag` | 是 | — | 唯一监听/运维 tag。 |
| `listen` | 是 | — | 独立的入站监听拓扑；内部地址必须由主机/云防火墙限制。 |
| `port` | 是 | — | 非零原始 NXR TCP 端口。 |
| `settings.preSharedKey` | 是 | — | 独立 URL-safe 无填充 base64，解码为恰好 32 字节。 |
| `settings.maxTimeDifferenceSeconds` | 否 | `30` | 接受的绝对墙上时钟差，`1..=300`。 |
| `settings.maxNonceEntries` | 否 | `65536` | 已验证 nonce 最大条目数，`1..=1000000`。 |
| `settings.nonceRetentionSeconds` | 否 | `120` | 重放保留时间，从 `2 * maxTimeDifferenceSeconds + 1` 到 `86400`。 |
| `settings.authenticationTimeoutMs` | 否 | `3000` | 读取一次有界认证请求的截止时间，`1..=600000`。 |
| `settings.connectTimeoutMs` | 否 | `10000` | 认证成功后才开始的目标连接截止时间，`1..=600000`。 |

NXR 认证失败会在 DNS 和目标连接之前静默关闭；成功后连接切换成原始双向字节。
NXR 没有认证后加密，不得直接暴露在互联网。

### 内部 Handoff 入站

```json
{
  "protocol": "handoff",
  "tag": "internal-handoff",
  "listen": { "mode": "auto", "ipv4": "0.0.0.0", "ipv6": "::" },
  "port": 7443,
  "settings": {
    "preSharedKey": "GENERATED-HANDOFF-KEY",
    "privateKey": "GENERATED-X25519-PRIVATE-KEY",
    "maxTimeDifferenceSeconds": 30,
    "maxNonceEntries": 65536,
    "nonceRetentionSeconds": 120,
    "authenticationTimeoutMs": 3000,
    "connectTimeoutMs": 10000
  }
}
```

| 字段 | 必填 | 默认值 | 含义与约束 |
| --- | --- | --- | --- |
| `protocol` | 是 | 固定 `handoff` | 选择内部会话转移协议。 |
| `tag` | 是 | — | 唯一监听/运维 tag。 |
| `listen` | 是 | — | 独立的入站监听拓扑；内部地址必须由主机/云防火墙限制。 |
| `port` | 是 | — | 非零原始 Handoff TCP 端口。 |
| `settings.preSharedKey` | 是 | — | 独立 URL-safe 无填充 base64，解码为恰好 32 字节；与线路机 handoff 出站共享的成对 PSK。 |
| `settings.privateKey` | 是 | — | 独立的静态 X25519 私钥，URL-safe 无填充 base64，解码为恰好 32 字节；其公钥即线路出站的 `landingPublicKey`。 |
| `settings.maxTimeDifferenceSeconds` | 否 | `30` | 接受的绝对墙上时钟差，`1..=300`。 |
| `settings.maxNonceEntries` | 否 | `65536` | 已保留转移 nonce 最大条目数，`1..=1000000`。 |
| `settings.nonceRetentionSeconds` | 否 | `120` | 重放保留时间，从 `2 * maxTimeDifferenceSeconds + 1` 到 `86400`。 |
| `settings.authenticationTimeoutMs` | 否 | `3000` | 读取一次有界密封转移消息的截止时间，`1..=600000`。 |
| `settings.connectTimeoutMs` | 否 | `10000` | 认证成功后才开始的被转移目标连接截止时间，`1..=600000`。 |
| `settings.egress` | 否 | 直接连接 | 选择落地机到达被转移目标所用出站的 tag。该 tag 必须引用 `direct`、`socks5`、`nxr` 或 `blackhole` 出站；引用 `handoff` 出站会被拒绝——落地机不允许串联。 |
| `settings.previousPreSharedKeys` | 否 | `[]` | 有界密钥轮换窗口内仍被接受的已退役成对 PSK：最多两个独立的 URL-safe 无填充 base64 值，各解码为恰好 32 字节；列表内重复或与 `preSharedKey` 相同都会被拒绝。 |
| `settings.previousPrivateKeys` | 否 | `[]` | 有界密钥轮换窗口内仍被接受的已退役静态 X25519 私钥；形状、两条上限与相等性规则同 `previousPreSharedKeys`。 |

监听器对每条连接只验证一次单程转移—— fresh ephemeral X25519 对 `privateKey`
做 Diffie-Hellman，与成对 PSK 混合后用 ChaCha20-Poly1305 以完整 transcript 为
关联数据密封——顺序固定为：头部结构、时间戳窗口、nonce 在有界重放缓存中预留、
密钥协商、AEAD 开封，最后是内部一致性检查。任何失败都在 DNS 和目标连接之前
静默关闭，零响应字节。成功后监听器重建会话的 TLS 记录层，连接被转移的
目标——默认直接连接，或通过 `settings.egress` 选择的出站——并恢复会话；
此后该连接承载会话的原始 TLS 密文。

密钥独立性在同一配置文件内强制检查：Handoff `preSharedKey` 与任何 NXR
`preSharedKey` 或任何 REALITY `privateKey` 相同，或 Handoff `privateKey`
与任何 REALITY `privateKey` 相同，都无法通过校验；任何 previous-key 条目与上述材料相同同样会被拒绝。跨节点的
独立性仍是运维者的责任。Handoff 监听器承载在线会话
密钥，不得直接暴露在互联网：防火墙应只允许来自线路机源地址的访问。

#### 密钥轮换

`preSharedKey` 与 `privateKey` 通过三步实现零停机轮换。退役密钥从不出现在
线上——发送方始终只用活跃密钥对密封——因此从不配置这些字段的线路机与配置了
这些字段的落地机可以互操作，升级顺序不限。

1. 重载落地机：新密钥对作为活跃值，退役值列入
   `previousPreSharedKeys`/`previousPrivateKeys`。落地机同时能开启用退役材料
   密封的转移，并且只要仍配置着任何退役密钥，每个监听每代配置都会发出一条
   `handoff_rotation_window_open` 警告日志。
2. 把每台线路机的 handoff 出站切到新密钥对（`preSharedKey` 与新的
   `landingPublicKey`）。
3. 再次重载落地机，将两个 previous-key 列表清空。

退役密钥必须及时移除：只要退役密钥仍被接受，轮换所要恢复的前向保密界就尚未
生效（见[威胁模型](threat-model.zh-CN.md)）。开封路径总是先尝试活跃密钥对，
候选尝试以九次为硬上限，且绝不暴露哪个候选命中——失败保持封闭错误词汇与静默
关闭。

## `outbounds`

`outbounds` 不得为空。出站 tag 使用相同的 1–64 字符语法，并在出站之间唯一。

### Direct

```json
{ "protocol": "direct", "tag": "direct" }
```

受 `advanced.limits.directBarrier` 和连接超时约束，直接连接所选目标。不接受 `settings` 字段。

### Blackhole

```json
{
  "protocol": "blackhole",
  "tag": "block",
  "settings": { "responseDelayMs": 0 }
}
```

| 字段 | 必填 | 默认值 | 含义与约束 |
| --- | --- | --- | --- |
| `settings` | 否 | 空/默认 | 关闭行为。 |
| `settings.responseDelayMs` | 否 | `0` | 关闭前延迟，`0..=30000`。 |

不会建立目标连接。

### SOCKS5

```json
{
  "protocol": "socks5",
  "tag": "socks-egress",
  "settings": {
    "address": "127.0.0.1",
    "port": 1080,
    "username": "user",
    "password": "secret"
  }
}
```

| 字段 | 必填 | 默认值 | 含义与约束 |
| --- | --- | --- | --- |
| `settings.address` | 是 | — | 有效 ASCII hostname 或 IP。 |
| `settings.port` | 是 | — | 非零 SOCKS5 TCP 端口。 |
| `settings.username` | 否 | 不存在 | 必须与 `password` 同时出现，非空且最多 255 字节；Debug 输出受保护。 |
| `settings.password` | 否 | 不存在 | 必须与 `username` 同时出现，非空且最多 255 字节；秘密。 |

两个凭据都不存在时协商无认证；两者同时存在时使用用户名/密码认证。

### NXR 出站

```json
{
  "protocol": "nxr",
  "tag": "landing",
  "settings": {
    "address": "10.0.0.2",
    "port": 7443,
    "preSharedKey": "GENERATED-NXR-KEY"
  }
}
```

| 字段 | 必填 | 含义与约束 |
| --- | --- | --- |
| `settings.address` | 是 | 有效落地机 ASCII hostname 或 IP。 |
| `settings.port` | 是 | 防火墙限制的非零 NXR TCP 端口。 |
| `settings.preSharedKey` | 是 | 与落地入站相同的独立 URL-safe 无填充 32 字节密钥。 |

每条用户 TCP 流建立一条 NXR TCP 连接并发送一次严格有界认证请求；没有多路复用
或长期连接池。

### Handoff 出站

```json
{
  "protocol": "handoff",
  "tag": "landing",
  "settings": {
    "address": "10.0.0.2",
    "port": 7443,
    "preSharedKey": "GENERATED-HANDOFF-KEY",
    "landingPublicKey": "GENERATED-X25519-PUBLIC-KEY",
    "connectTimeoutMs": 10000,
    "firstByteTimeoutMs": 15000
  }
}
```

| 字段 | 必填 | 默认值 | 含义与约束 |
| --- | --- | --- | --- |
| `settings.address` | 是 | — | 有效落地机 ASCII hostname 或 IP。 |
| `settings.port` | 是 | — | 防火墙限制的非零 Handoff TCP 端口。 |
| `settings.preSharedKey` | 是 | — | 与落地入站相同的独立 URL-safe 无填充 32 字节成对 PSK。 |
| `settings.landingPublicKey` | 是 | — | 落地机的静态 X25519 公钥，URL-safe 无填充 base64，解码为恰好 32 字节；公开材料，不是秘密。 |
| `settings.connectTimeoutMs` | 否 | `10000` | 连接落地机并写入一次密封转移消息的截止时间，`1..=600000`。 |
| `settings.firstByteTimeoutMs` | 否 | `15000` | 转移后落地机首个下行字节的截止时间，`1000..=600000`；见下文。 |

把用户路由到 handoff 出站会在会话边界把整个已认证会话转移给落地机：每条
会话一条 TCP 连接，承载一次密封转移，随后承载会话的原始 TLS 密文——没有多路
复用或长期连接池。转移协议对任何失败都以静默关闭应答，因此线路机把
`firstByteTimeoutMs` 内没有首个下行字节视为拒绝信号，并重置客户端 socket；
转移失败后会话绝不在本地继续服务。

`firstByteTimeoutMs` 必须大于落地机的 `authenticationTimeoutMs +
connectTimeoutMs` 并留有余量：首个密封记录只有在转移被读取、认证完成、目标
连接建立之后才会产生，更短的截止时间会重置那些落地机缓慢或拥塞的正常会话。
默认值 15000 ms 覆盖落地机的默认预算（3000 + 10000 ms）。

## `routing`

```json
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "globalRules": [],
    "users": [
      {
        "name": "default-users",
        "userIds": ["GENERATED-UUID"],
        "defaultOutbound": "direct",
        "rules": []
      }
    ]
  }
}
```

| 字段 | 必填 | 默认值 | 含义与约束 |
| --- | --- | --- | --- |
| `routing.domainStrategy` | 否 | `IPIfNonMatch` | `AsIs`、`IPIfNonMatch` 或 `IPOnDemand`，行为见下文。 |
| `routing.globalRules` | 否 | `[]` | 每个公网用户都会先匹配的有序规则，建议保持少量且可审计。 |
| `routing.users` | 是 | — | 用户策略组；只有不存在公网 VLESS UUID（如纯 NXR 落地机）时才可为空。 |
| `routing.users[].name` | 是 | — | 非空且唯一的运维组名。 |
| `routing.users[].userIds` | 是 | — | 非空规范 UUID 数组；每个已配置公网 UUID 恰好分配一次。 |
| `routing.users[].defaultOutbound` | 是 | — | 无规则命中时选择的现有出站 tag。 |
| `routing.users[].rules` | 否 | `[]` | 与全局规则形状相同的有序规则。 |

确定性 first-match 顺序是：全部全局规则、已认证 UUID 所属组的规则、组默认值。
分组是可读性/所有权边界，不根据源 IP 或 email 选择。

### 规则字段

| 字段 | 必填 | 默认值 | 含义与约束 |
| --- | --- | --- | --- |
| `name` | 是 | — | 非空运维规则名。 |
| `outbound` | 是 | — | 现有出站 tag。 |
| `domain` | 否 | `[]` | 域名/GeoSite 匹配器。 |
| `ip` | 否 | `[]` | IP/CIDR/GeoIP 匹配器。 |
| `port` | 否 | `[]` | 如 `"443"` 或包含端点的 `"1000-2000"`；端口 `1..=65535`。 |
| `network` | 否 | `[]` | `"tcp"` 或 `"udp"`；当前公网数据路径是 TCP，因此 `udp` 不会命中它。 |
| `inboundTag` | 否 | `[]` | 已存在的公网 VLESS 入站 tag；内部 NXR tag 不是公网路由身份。 |

规则至少包含一个条件。不同类别之间 AND：同时存在 `domain` 和 `port` 时两者都要
命中。同一类别内 OR：任意一个域名以及任意一个端口即可满足各自类别。

### 域名匹配器

| 语法 | 行为 |
| --- | --- |
| `full:api.example.com` | 大小写不敏感的精确 hostname。 |
| `domain:example.com` | 识别 DNS label 的后缀；匹配 `example.com` 和 `a.example.com`，不匹配 `badexample.com`。 |
| `example.com` | 与 `domain:` 相同的后缀行为。 |
| `keyword:example` | 大小写不敏感 ASCII 子串。 |
| `regexp:<expression>` | 大小写不敏感 Rust 正则，在编译路由时验证。 |
| `geosite:cn` | 配置的社区 `geosite.dat` 标签。 |
| `ext:custom.dat:label` | `cacheDirectory` 下兼容 Xray 的 DAT 文件中的域名标签。 |

### IP 匹配器

| 语法 | 行为 |
| --- | --- |
| `192.0.2.1` / `2001:db8::1` | 单个精确地址。 |
| `10.0.0.0/8` / `2001:db8::/32` | 有效前缀的 IPv4/IPv6 CIDR。 |
| `geoip:private` | 配置的社区 `geoip.dat` 标签。 |
| `ext:custom.dat:label` | `cacheDirectory` 下兼容 Xray 的 DAT 文件中的 IP 标签。 |

### `domainStrategy`

| 值 | 域名目标的行为 |
| --- | --- |
| `AsIs` | 路由器不为 IP 规则解析；域名规则仍可匹配，最终出站按需解析。 |
| `IPIfNonMatch` | 先不做 DNS 匹配；只有到达用户默认值且存在适用全局/用户 IP 规则时才解析并再次匹配。 |
| `IPOnDemand` | 只要存在适用全局/用户 IP 规则，就在规则匹配前解析。 |

未知用户在 DNS 前失败。DNS 结果有界并附着到路由决策，使 direct 使用同一批地址。

### 路由示例

```json
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "globalRules": [
      {
        "name": "reject-private",
        "outbound": "block",
        "ip": ["geoip:private"]
      },
      {
        "name": "reject-ads",
        "outbound": "block",
        "domain": ["geosite:category-ads-all"]
      }
    ],
    "users": [
      {
        "name": "landing-users",
        "userIds": ["GENERATED-UUID-A"],
        "defaultOutbound": "landing",
        "rules": [
          {
            "name": "local-direct",
            "outbound": "direct",
            "domain": ["geosite:cn"]
          }
        ]
      },
      {
        "name": "direct-users",
        "userIds": ["GENERATED-UUID-B"],
        "defaultOutbound": "direct",
        "rules": []
      }
    ]
  }
}
```

占位符必须换成公网入站客户端中实际存在的 UUID。

## `advanced`

专家逃生舱。`advanced.limits` 保存完整的数值化资源与 relay 策略；每个字段都有
有界生产默认值，因此整个对象、`limits` 或其四个子对象都可以缺省。如果显式提供
`resourceGovernor`、`directBarrier`、`warmConnections` 或 `relay`，标记“对象存在时必填”的字段必须
提供；不能假设部分对象自动继承所有默认值。`config format` 会显示已应用默认值。

这些数值如何成为生效策略取决于 `runtime.tuning.mode`：`fixed` 下按原样使用；
推导模式（`startup`、`adaptive`）下，取值与内置默认值不同的字段视为运维钉死
（operator-pinned），始终优先，其余字段在启动时按检测到的机器推导。见
[启动策略推导](#启动策略推导)。

### `advanced.limits.resourceGovernor`

| 字段 | 对象存在时必填 | 整体默认值 | 约束/含义 |
| --- | --- | --- | --- |
| `maxConnections` | 是 | `16384` | 大于零；已接受连接的父级上限。 |
| `maxHandshakes` | 是 | `1024` | 大于零且不超过 `maxConnections`；并发认证前工作。 |
| `maxFallbacks` | 是 | `512` | 大于零且不超过 `maxConnections`；并发伪装转发。 |
| `maxCryptoOperations` | 是 | `128` | 大于零且不超过 `maxHandshakes`；昂贵密码学工作 admission。 |
| `maxReplayEntries` | 是 | `65536` | 大于零；pending 加 committed REALITY 重放条目。 |
| `replayRetentionMs` | 否 | `120000` | 验证 ClientFinished 后的保留时间，`1..=600000`。 |
| `maxDnsLookups` | 否 | `64` | 共享 DNS 解析器准入的并发解析数，覆盖系统 getaddrinfo 池和上游服务器请求。 |
| `clientHelloTimeoutMs` | 是 | `3000` | ClientHello 读取截止时间，`1..=600000`，不超过握手超时。 |
| `handshakeTimeoutMs` | 是 | `10000` | 认证握手截止时间，`1..=600000`。 |
| `connectTimeoutMs` | 是 | `10000` | 伪装/出站连接截止时间，`1..=600000`，不超过 fallback 超时。 |
| `fallbackTimeoutMs` | 是 | `120000` | fallback 最大生命周期，`1..=600000`。 |

### `advanced.limits.directBarrier`

| 字段 | 对象存在时必填 | 整体默认值 | 约束/含义 |
| --- | --- | --- | --- |
| `maxConcurrent` | 是 | `2048` | 并发 direct 拨号，大于零且不超过 `maxConnections`。 |
| `maxPerSecond` | 是 | `4096` | 每秒新 direct 拨号，范围为 1 至 1,000,000,000。 |

它把 direct 目标压力与已认证连接总数隔离。

### `advanced.limits.warmConnections`

| 字段 | 对象存在时必填 | 整体默认值 | 约束/含义 |
| --- | --- | --- | --- |
| `minReady` | 是 | `4` | 低负载 ready 下限；可为零且不超过 `maxReady`。 |
| `maxReady` | 是 | `256` | 每个伪装目标的 ready 上限，`1..=4096`。 |
| `maxConnecting` | 是 | `64` | 每目标推测性并发拨号，`1..=min(maxReady, 1024)`。 |
| `refillBatch` | 是 | `16` | 每次控制器协调提交的拨号数，`1..=maxConnecting`。 |
| `idleTimeoutMs` | 是 | `30000` | 未使用 idle 最大时长，`100..=3600000`。 |
| `maxLifetimeMs` | 是 | `300000` | 未使用 socket 绝对寿命，不小于 `idleTimeoutMs` 且不超过一小时。 |
| `shrinkDelayMs` | 是 | `30000` | 开始逐步回缩前的无需求迟滞，`100..=3600000`。 |

这些上限按 endpoint 计算；严格的进程级 authority 还会约束所有 generation，FD
预算仍是最终边界。checkout 从不等待 refill；压力下先释放推测性 ready socket，
再尝试普通冷路径。

### `advanced.limits.relay`

| 字段 | 对象存在时必填 | 整体默认值 | 约束/含义 |
| --- | --- | --- | --- |
| `bufferBytes` | 是 | `32768` | 每个池化用户态缓冲区字节数，`4096..=1048576`。 |
| `maxPooledBuffers` | 是 | `4096` | 全局池化缓冲区上限，`2..=65536`。 |
| `maxSpliceRelays` | 否 | `256` | splice 开启时大于零且不超过 `maxConnections`；每条 relay 使用两对 pipe。 |
| `maxRelayMemoryBytes` | 否 | `536870912` | 池化加注册中继缓冲内存上限。 |
| `pipePool` | 否 | `true` | 进程级复用 splice 管道，而不是每个会话创建/扩容/销毁。 |
| `maxPooledPipes` | 否 | `256` | 池化管道上限；管道池按 `maxPooledPipes × 2` 个管道容量核算内存。 |
| `splice` | 是 | `true` | 只允许在明文 TCP 边界使用有界非阻塞 Linux splice。 |

### 后端选择

自动优选顺序为 `splice`、`buffered`。

后端**只有在尚未传输任何字节时**才能把连接交给下一个后端。一旦有字节流动，后端
错误将终止该中继，连接绝不会在另一个后端上重放。这一点由结构保证：构造 decline
的唯一途径是共享传输账本，而账本在任一计数器非零时拒绝生成 decline。

内核后端永远不会看到仍携带 TLS 记录或 Vision 帧的字节。Vision 的每个方向都有
自己精确的已认证 Direct 边界：越过边界的方向可以由方向性 splice 中继，此时
对方向仍可保持成帧；只有当两个方向独立变为裸流且配对安全时，才使用合并整个
套接字的双向 splice。

### 资源核算

校验在任何监听器绑定之前拒绝不可能的预算，全部使用检查过的算术：

```text
buffered_memory = maxPooledBuffers * bufferBytes
pipe_memory     = splice 关闭时 0
                | pipePool 开启时 maxPooledPipes * 2 * 512 KiB
                | pipePool 关闭时 maxSpliceRelays * 4 * 512 KiB

buffered_memory + pipe_memory <= maxRelayMemoryBytes
```

`maxPooledBuffers` 是**缓冲区数量**，绝不是字节预算。

### 能力上报

启动时发出一条 `relay_backend_report` 事件，每个后端一行。不可用的后端会给出
封闭词表中的固定原因——`disabled`、`unsupportedOperatingSystem`、
`unsupportedKernel`、`missingOperation`、`missingCapability`、`blockedBySeccomp`、
`blockedByLsm`、`resourceLimit`、`queueUnavailable`、
`unsafeToArm`、`existingQueuedBytes`、`initializationFailure`——并且该拒绝原因
不会按连接重复输出。

splice 永远不会跨越 REALITY/TLS 安全边界。传输开始前无法获得 splice 资源时，
回退到有界用户态缓冲。

## `runtime`

进程级资源姿态。整个对象可选。

| 字段 | 对象存在时必填 | 默认值/允许值 | 含义与约束 |
| --- | --- | --- | --- |
| `runtime.profile` | 否 | `auto`；`auto`、`shared`、`dedicated` | 声明谁拥有这台机器。`shared` 选择标准资源姿态，`dedicated` 选择专用姿态（把 `RLIMIT_NOFILE` 软限制提升到硬限制、按专用余量推导描述符预算，并运行有界内存压力监控器；见[专用资源模式](#dedicated-resource-mode)）。`auto` 仅当 cgroup v2 租户边界完全可观测（`cpu.max` 配额有限且 `memory.max` 有限）时解析为 `dedicated`；在裸金属上绝不猜测为 dedicated。冷设置，修改必须重启。 |
| `runtime.tuning.mode` | 否 | `startup`；`fixed`、`startup`、`adaptive` | 数值策略的产生方式。`fixed` 取自 `advanced.limits`（或内置默认值）且永不变动——即 v1.5 行为。`startup` 在启动时按检测到的机器推导每个未钉死的字段。`adaptive` 的推导与 `startup` 完全一致，并额外运行自适应控制器，在启动推导的边界内调节软准入上限与直连拨号速率。见[启动策略推导](#启动策略推导)与[自适应上限](#自适应上限)。 |
| `runtime.tuning.objective` | 否 | `balanced`；`latency`、`balanced`、`throughput` | 推导数值的形态；只有推导调谐模式（`startup`、`adaptive`）才会使用。 |
| `runtime.statusFile` | 否 | 不设置；文件路径 | 仅在 `adaptive` 调谐模式下使用：控制器在启动时以及每次上限或压力状态变化时原子化重写这份 JSON 快照，`rust-reality runtime report` 读取它。冷设置，修改必须重启。 |

### 启动策略推导

`runtime.tuning.mode: startup`（默认值）下，serve 路径在启动时按检测到的机器
推导一次数值策略——公式与 `config autotune` 完全相同，但完全被动：启动时不运行
任何基准、存储或回环探测，就绪绝不延迟。`autotune` 实测的输入使用保守档位
（32 KiB 缓冲档位、无实测建链容量），因此没有测量数据时推导出的方案不会发明
autotuner 也不会产生的数值。

推导逐字段进行。`advanced.limits` 中取值与内置默认值不同的字段视为运维钉死，
始终优先；其余字段全部推导。（显式写出与默认值相同的值与不写无法区分。）所有
超时和 `replayRetentionMs` 永不推导——它们是协议安全参数，直接取自配置——未钉死
的 `relay.splice`/`relay.pipePool` 布尔值跟随推导出的平台能力。

目标（objective）在 balanced 推导之后、硬性上限之前缩放选定的推导输出；安全下限
最后应用，因此 `latency` 绝不会供给不足，`throughput` 也绝不会超过机器推导的
上限：

| 字段 | `latency` | `balanced` | `throughput` |
| --- | --- | --- | --- |
| `resourceGovernor.maxConnections` | ×0.5 | ×1 | ×1.5 |
| `resourceGovernor.maxHandshakes` | ×1 | ×1 | ×1 |
| `resourceGovernor.maxFallbacks` | ×0.5 | ×1 | ×1 |
| `resourceGovernor.maxCryptoOperations` | ×1 | ×1 | ×1 |
| `resourceGovernor.maxReplayEntries` | 跟随 `maxConnections`（×4） | | |
| `resourceGovernor.maxDnsLookups` | ×1 | ×1 | ×1 |
| `directBarrier.maxConcurrent` | ×0.5 | ×1 | ×1.5 |
| `directBarrier.maxPerSecond` | ×0.5 | ×1 | ×2 |
| `relay.bufferBytes` | 下移一档 | 32 KiB 默认档 | 上移一档（最高 64 KiB） |
| `relay.maxPooledBuffers` | ×0.5 | ×1 | ×2 |
| `relay.maxSpliceRelays` / `relay.maxPooledPipes` | ×1 | ×1 | ×2 |
| `relay.maxRelayMemoryBytes` | ×0.75 | ×1 | ×1.5（≤ 内存/4） |

未列出的字段——所有超时和 `replayRetentionMs`——按配置原样保留。

推导出的策略在绑定任何监听器之前经过与 `config autotune` 输出完全相同的校验。
启动时发出一条 `runtime_plan_report` 日志事件，记录解析出的资源模式、调谐模式
与目标、以及生效的运行时线程池大小。`rust-reality runtime explain --config …`
离线打印同一份方案：检测到的机器、解析出的 profile、每个字段的生效值及其来源
（`derived`、`override` 或 `default`）以及所应用的上下界。

生效策略是冷的。热更新会用当前机器视图重新推导候选配置，只要推导结果会不同就
拒绝——包括仅由启动后 cgroup 边界变化引起的漂移——因为 admission 池在进程启动时
已定尺寸，无法变更。

### 自适应上限

`runtime.tuning.mode: adaptive` 下，启动推导与 `startup` 模式完全一致，随后由
控制器在运行时调节*软*上限。软上限只能在已构建的池尺寸之下收紧准入；已持有的
许可绝不会被回收，已建立的会话不受影响。

- **调节对象**：六个 `resourceGovernor` 准入上限，外加
  `directBarrier.maxConcurrent` 与 `directBarrier.maxPerSecond`（GCRA 拨号速率，
  与并发上限共享同一个拨号需求信号）。其余一律不动：所有超时、
  `replayRetentionMs`、relay 缓冲区与池尺寸、描述符预算、监听器拓扑和 DNS 策略
  都仅在启动时确定。
- **边界**：每个旋钮的上界是其启动推导值（即构建池时使用的生效策略），下界是
  该字段的 v1.5 内置默认值；当运维钉死值低于默认值时下界降至启动值——钉死的
  上限被严格尊重，服务器始终保有可响应的最小容量。
- **决策**：控制器每 5 秒 tick 一次，测量持有许可数相对当前软上限的利用率。
  利用率连续 3 个 tick 不低于 85% 时上调，连续 6 个 tick 不高于 40% 时下调——
  保护要快、放松要慢——同一旋钮相邻两次调整至少间隔 30 秒。每步为启动值的
  25%，按量子取整（计数类 64，拨号速率 16）。
- **Critical 压力**：只要有一个 tick 处于 critical 资源压力，所有旋钮一步钳到
  下界，绕过迟滞与驻留。恢复时按正常迟滞逐步走回。
- **可观测性**：每次旋钮变动恰好发出一条 `adaptive_ceiling_changed` 日志事件，
  逐 tick 不记日志。设置了 `runtime.statusFile` 时，控制器还会在启动时以及每次
  上限或压力状态变化时原子化重写该 JSON 文件；
  `rust-reality runtime report --status-file <PATH> [--json]` 打印最后发布的
  快照。

### 启动时的运行时拓扑

`serve` 在构建 Tokio 运行时*之前*检测机器并解析 profile，因此运行时线程池与
策略推导使用同一份机器视图。`dedicated` 姿态下线程池显式定尺寸：
`worker_threads = effective_cpus().clamp(1, 64)`——感知 cgroup 配额，即使只有
1 vCPU 也保留多线程运行时——以及
`max_blocking_threads = (32 + 8 × effective_cpus).clamp(64, 512)`，DNS 与探测
工作运行在这个池上。shared/standard 姿态保留 tokio 默认值（每个可见 CPU 一个
worker、512 个阻塞线程），与 v1.5 构建运行时完全一致。两个尺寸都是冷设置：
tokio 无法调整存活运行时的大小，因此它们在进程生命周期内固定。纯 CLI 命令
使用小型单线程运行时。

### Dedicated resource mode

`{ "runtime": { "profile": "dedicated" } }` 声明进程独占机器——或在容器
运行时下独占其 cgroup——并针对实测机器资源做预算，而不是假设对同机负载一无
所知。该模式是**冷设置**：它塑造进程生命周期的描述符预算、软限制提升和内存
监控器，因此修改它的 SIGHUP 热更新会被拒绝，最后一个有效 generation 继续
运行。

**启动检测。** 在绑定任何 listener 之前检测一次：`RLIMIT_NOFILE` 软/硬限制、
`RLIMIT_MEMLOCK` 软/硬限制（仅上报）、当前进程的 cgroup v2（`cpu.max`、
`cpuset.cpus.effective`、`memory.current`、`memory.high`、`memory.max`；字面
`max` 视为无界，缺失或不可读的文件降级为"不上报"而不是编造数值），cgroup
文件缺失时回退到 `MemTotal` 和进程可见的 CPU 数。全部内容以一个结构化
`machine_report` 事件上报。

**软限制提升。** 当 `RLIMIT_NOFILE` 硬限制高于软限制时，专用模式通过
`setrlimit(2)` 把进程自己的软限制提升到硬限制——不需要特权，不触碰进程之外
的任何东西。提升失败不是致命错误；推导继续使用实际生效的软限制。systemd 单
元里的 `LimitNOFILE=` 仍要保留：提升最多只能达到*继承来的*硬限制。

**描述符预算。** 公式与标准模式相同（`effective_soft_limit - fixed_reserve -
headroom`），但安全余量更大：`max(limit / 10, 64)` 取代 `max(limit / 16,
64)`——进程按提升后的限制规划，并为其无法记账的描述符消费者保留十分之一。
两种策略下不变量 `budget + reserve + headroom <= effective_soft_limit` 都成立。

**内存预算。** 有效内存总量取有限的 cgroup `memory.max`（以 `MemTotal` 为
上限），否则取 `MemTotal`；两者都不可读时禁用内存维度而不是编造。各水位线
进入/退出阈值分离，围绕单一阈值振荡不会产生跳变：

| 边界 | 占总量比例 |
|---|---|
| 可用预算 | 80% |
| 压力 进入/退出 | 60% / 50% |
| 危急 进入/退出 | 90% / 80% |

**压力模型。** 两个维度合成一个有效状态：FD 预算水位线（容量的 15/16 进入、
13/16 退出）和一个每秒采样 cgroup `memory.current`（回退：`/proc/self/statm`
常驻集）的监控任务。监控器是唯一写入者；读取路径是一次原子 load，绝不在数据
循环中。采样不可读时保持上一个状态。

| 状态 | 新 fallback | 新握手 | 新 accept | 新 direct 拨号 | 已建立流量 |
|---|---|---|---|---|---|
| `Normal` | 准入 | 准入 | 准入 | 准入 | 流动 |
| `Pressure` | 拒绝 | 拒绝 | 准入 | 准入 | 流动 |
| `Critical` | 拒绝 | 拒绝 | 暂停 / 快速失败 | 快速失败 | 流动 |

已持有的许可绝不撤销，已建立 relay 在两个层级下都继续运行；listener 在
`Notify` 唤醒上停放，迟滞退出时自动恢复。

**该模式绝不做什么。** 绝不触碰 sysctl、cgroup 文件、其他进程或硬限制（唯一的
修改是提升自己的 `RLIMIT_NOFILE` 软限制）；绝不超出推导的预算准入；绝不为
"用满"机器而预分配或空转 CPU（唯一的周期任务是每秒一次的内存采样）；绝不
轮询 `/proc/self/fd`。

**运维指引。** 当进程是机器、VM 或 cgroup 的唯一租户时使用 `dedicated`；当有
不可预测的负载共享描述符限制或内存 cgroup 时保持 `standard`。如果
`machine_report` 中 `memory_total` 为 `0`，说明不存在内存水位线——应视为
监控缺口而不是余量。

## 热更新边界

`serve`/`run` 收到 SIGHUP 后构建完整候选配置。发布是原子的；失败时保留旧
generation，已有连接继续使用其获取的 generation。

监听拓扑兼容时可热更新：

- 日志；
- 资产 URL、缓存内容和刷新设置；
- VLESS 用户及 REALITY 认证/伪装状态；
- 出站定义、路由组和规则；
- 在重放容量/保留时间不变时，NXR 密钥、时钟窗口和 I/O 超时；
- 在重放容量/保留时间不变时，Handoff 密钥材料、时钟窗口、超时和 egress 出站选择。

必须重启：

- 添加/删除监听、修改 `listen.mode`、任一绑定地址、端口或协议；
- 任意 `network.dial` 修改，因为启动快照与共享健康状态属于进程生命周期；
- 任意 `dns` 修改（`servers`、`timeoutMs` 或 `cache`），因为共享解析器——
  包括其超时与缓存边界——在启动时安装一次，属于进程生命周期；
- 任意 `runtime` 修改（`profile`、`tuning` 或 `statusFile`），因为资源姿态影响
  进程生命周期的描述符预算和内存监控器，且自适应控制器是进程生命周期的；调谐模式
  严格比较，`fixed` ↔ `startup` ↔
  `adaptive` 之间的任何漂移都必须重启；
- 推导调谐模式（`startup`/`adaptive`）下任何会改变推导结果的修改——编辑过的
  `advanced.limits` 钉死字段，或启动后发生变化的机器边界——因为 admission 池在
  进程启动时已定尺寸；
- 任意 `advanced.limits.resourceGovernor` 修改，因为 REALITY 重放 admission/状态属于进程生命周期；
- 任意 `advanced.limits.directBarrier` 修改，因为直连拨号 authority 属于进程生命周期；
- 任意 `advanced.limits.warmConnections` 修改，因为跨 generation 的推测连接 authority 属于进程生命周期；
- 任意 `advanced.limits.relay` 修改，因为缓冲/splice 池属于进程生命周期；
- NXR `maxNonceEntries` 或 `nonceRetentionSeconds` 修改；
- Handoff `maxNonceEntries` 或 `nonceRetentionSeconds` 修改。

SIGHUP 前先运行 `check`，最好运行 `self-test`。文件本身有效仍可能不兼容热更新，
此时需要受控重启。

## 秘密与文件处理

- 配置权限使用 `0640 root:rust-reality` 或更严格。
- 不要提交生成 UUID、REALITY 私钥、应保密的 short ID、NXR PSK、Handoff PSK、
  Handoff 静态私钥、SOCKS 凭据或真实端点。
- 在可信主机使用操作系统熵生成密钥，并通过已认证信道传输。
- 使用专用可写资产目录；外部 DAT 文件必须留在该目录内。
- `config format` 会把包括秘密在内的完整配置写到 stdout；重定向时谨慎，不要管道到日志。
