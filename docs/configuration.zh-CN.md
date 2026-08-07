# 配置参考

[English](configuration.md) | 简体中文

本文覆盖 `rust-reality` 0.1.x 接受的全部 JSON 字段。最终权威仍是实际二进制：

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
  "inbounds": [],
  "outbounds": [],
  "routing": {},
  "policy": {},
  "runtime": {}
}
```

| 字段 | 必填 | 默认值 | 含义 |
| --- | --- | --- | --- |
| `log` | 否 | stderr/info | 日志目标、级别和有界文件保留。 |
| `assets` | 否 | 社区 GeoIP/GeoSite URL 和有界缓存默认值 | 路由资产来源与刷新策略。 |
| `dns` | 否 | 系统解析器、5000 ms | IP 辅助路由使用的 DNS 行为。 |
| `inbounds` | 是 | — | 至少一个强类型 `vless` 或内部 `nxr` 监听。 |
| `outbounds` | 是 | — | 至少一个 `direct`、`blackhole`、`socks5` 或 `nxr` 传输。 |
| `routing` | 是 | — | 全局规则和显式 UUID 分组策略。 |
| `policy` | 否 | 有界生产默认值 | admission、direct 拨号、缓冲和 Linux relay 策略。 |
| `runtime` | 否 | `standard` | 进程资源姿态。 |

## `log`

| 字段 | 必填 | 默认值/允许值 | 含义与约束 |
| --- | --- | --- | --- |
| `log.level` | 否 | `info`；`error`、`warn`、`info`、`debug` | 最低输出级别。Debug 也不会包含配置和密钥。 |
| `log.output` | 否 | `stderr`；`stderr`、`journald`、`file` | `journald` 仍写 stderr 供 systemd 捕获；`file` 启用内置轮转。 |
| `log.file` | 仅 `output: "file"` | 不存在 | stderr/journald 时禁止；包含下列全部字段。 |
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

| 字段 | 必填 | 默认值 | 含义与约束 |
| --- | --- | --- | --- |
| `dns.servers` | 否 | `["system"]` | 当前必须严格等于 `["system"]`；自定义 UDP/TCP/DoH 会被拒绝而不是静默忽略。 |
| `dns.timeoutMs` | 否 | `5000` | 路由解析绝对超时，`1..=600000`。 |

一个域名最多保留 64 个唯一地址。direct 出站复用 IP/GeoIP 路由决策使用的同一地址
快照，避免第二次解析得到不一致结果。

## `inbounds`

`inbounds` 不得为空。每个监听的 `tag` 唯一，两个条目不能绑定相同
`(listen, port)`。tag 长度 1–64，只能包含 ASCII 字母、数字、点、横线和下划线。
`port` 范围 `1..=65535`。

### 公网 VLESS + REALITY + Vision 入站

```json
{
  "protocol": "vless",
  "tag": "public-reality",
  "listen": "0.0.0.0",
  "port": 443,
  "settings": {
    "clients": [
      {
        "id": "GENERATED-UUID",
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
      "shortIds": ["0123456789abcdef"],
      "maxTimeDiffMs": 60000
    }
  }
}
```

以上占位符故意不能直接使用。请通过 `config generate standalone` 或
`config generate line` 生成真实状态。

| 字段 | 必填 | 默认值/固定值 | 含义与约束 |
| --- | --- | --- | --- |
| `protocol` | 是 | 固定 `vless` | 选择唯一公网协议。 |
| `tag` | 是 | — | 唯一监听/路由 tag。 |
| `listen` | 是 | — | IPv4 或 IPv6 绑定地址。 |
| `port` | 是 | — | 非零 TCP 端口。 |
| `settings.clients` | 是 | — | 非空授权客户端数组；UUID 在所有公网入站中全局唯一。 |
| `settings.clients[].id` | 是 | — | 带横线的规范 UUID；身份比较时十六进制大小写不敏感。 |
| `settings.clients[].email` | 否 | 不存在 | 非秘密运维标签，不参与认证或路由。 |
| `settings.clients[].flow` | 是 | 固定 `xtls-rprx-vision` | 其他 flow 全部拒绝。 |
| `settings.decryption` | 否 | 固定/默认 `none` | 为接近 Xray 配置形状而保留，其他值拒绝。 |
| `streamSettings.network` | 是 | 固定 `tcp` | 尚未实现公网 UDP。 |
| `streamSettings.security` | 是 | 固定 `reality` | 纯 VLESS 或仅 TLS VLESS 拒绝。 |
| `streamSettings.realitySettings.target` | 是 | — | `host:port` 伪装目标；IPv6 加方括号；先从服务器探测。 |
| `streamSettings.realitySettings.serverNames` | 是 | — | 非空、大小写不敏感唯一的具体 ASCII DNS 名或最左侧单标签模式，如 `*.lmu.edu`。 |
| `streamSettings.realitySettings.privateKey` | 是 | — | URL-safe 无填充 base64，解码为恰好 32 字节 X25519 私钥；秘密。 |
| `streamSettings.realitySettings.shortIds` | 是 | — | 非空且大小写不敏感唯一；每项为 2–16 个偶数长度十六进制字符。 |
| `streamSettings.realitySettings.maxTimeDiffMs` | 否 | `60000` | 接受的客户端时钟差，`0..=600000`；零表示关闭该检查。 |

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
  "listen": "0.0.0.0",
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
| `listen` | 是 | — | 内部绑定地址，必须由主机/云防火墙限制。 |
| `port` | 是 | — | 非零原始 NXR TCP 端口。 |
| `settings.preSharedKey` | 是 | — | 独立 URL-safe 无填充 base64，解码为恰好 32 字节。 |
| `settings.maxTimeDifferenceSeconds` | 否 | `30` | 接受的绝对墙上时钟差，`1..=300`。 |
| `settings.maxNonceEntries` | 否 | `65536` | 已验证 nonce 最大条目数，`1..=1000000`。 |
| `settings.nonceRetentionSeconds` | 否 | `120` | 重放保留时间，从 `2 * maxTimeDifferenceSeconds + 1` 到 `86400`。 |
| `settings.authenticationTimeoutMs` | 否 | `3000` | 读取一次有界认证请求的截止时间，`1..=600000`。 |
| `settings.connectTimeoutMs` | 否 | `10000` | 认证成功后才开始的目标连接截止时间，`1..=600000`。 |

NXR 认证失败会在 DNS 和目标连接之前静默关闭；成功后连接切换成原始双向字节。
NXR 没有认证后加密，不得直接暴露在互联网。

## `outbounds`

`outbounds` 不得为空。出站 tag 使用相同的 1–64 字符语法，并在出站之间唯一。

### Direct

```json
{ "protocol": "direct", "tag": "direct" }
```

受 `policy.directBarrier` 和连接超时约束，直接连接所选目标。不接受 `settings` 字段。

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

## `policy`

`policy` 或三个子对象之一缺失时，使用该子对象完整默认值。如果显式提供
`resourceGovernor`、`directBarrier` 或 `relay`，标记“对象存在时必填”的字段必须
提供；不能假设部分对象自动继承所有默认值。`config format` 会显示已应用默认值。

### `policy.resourceGovernor`

| 字段 | 对象存在时必填 | 整体默认值 | 约束/含义 |
| --- | --- | --- | --- |
| `maxConnections` | 是 | `16384` | 大于零；已接受连接的父级上限。 |
| `maxHandshakes` | 是 | `1024` | 大于零且不超过 `maxConnections`；并发认证前工作。 |
| `maxFallbacks` | 是 | `512` | 大于零且不超过 `maxConnections`；并发伪装转发。 |
| `maxCryptoOperations` | 是 | `128` | 大于零且不超过 `maxHandshakes`；昂贵密码学工作 admission。 |
| `maxReplayEntries` | 是 | `65536` | 大于零；pending 加 committed REALITY 重放条目。 |
| `replayRetentionMs` | 否 | `120000` | 验证 ClientFinished 后的保留时间，`1..=600000`。 |
| `clientHelloTimeoutMs` | 是 | `3000` | ClientHello 读取截止时间，`1..=600000`，不超过握手超时。 |
| `handshakeTimeoutMs` | 是 | `10000` | 认证握手截止时间，`1..=600000`。 |
| `connectTimeoutMs` | 是 | `10000` | 伪装/出站连接截止时间，`1..=600000`，不超过 fallback 超时。 |
| `fallbackTimeoutMs` | 是 | `120000` | fallback 最大生命周期，`1..=600000`。 |

### `policy.directBarrier`

| 字段 | 对象存在时必填 | 整体默认值 | 约束/含义 |
| --- | --- | --- | --- |
| `maxConcurrent` | 是 | `2048` | 并发 direct 拨号，大于零且不超过 `maxConnections`。 |
| `maxPerSecond` | 是 | `4096` | 每秒新 direct 拨号，大于零。 |

它把 direct 目标压力与已认证连接总数隔离。

### `policy.relay`

| 字段 | 对象存在时必填 | 整体默认值 | 约束/含义 |
| --- | --- | --- | --- |
| `bufferBytes` | 是 | `32768` | 每个池化用户态缓冲区字节数，`4096..=1048576`。 |
| `maxPooledBuffers` | 是 | `4096` | 全局池化缓冲区上限，`2..=65536`。 |
| `maxSpliceRelays` | 否 | `1024` | splice 开启时大于零且不超过 `maxConnections`；每条 relay 使用两对 pipe。 |
| `maxSockhashRelays` | 否 | `4096` | sockhash 开启时大于零且不超过 `maxConnections`；每条 relay 占用两个 map 条目。 |
| `maxRelayMemoryBytes` | 否 | `268435456` | 池化加注册中继缓冲内存上限。 |
| `maxPinnedMemoryBytes` | 否 | `134217728` | 内核固定内存上限（sockhash map 容量）。 |
| `splice` | 是 | `true` | 只允许在明文 TCP 边界使用有界非阻塞 Linux splice。 |
| `sockhash` | 是 | `false` | 运行时能力探测通过后，允许使用有界 eBPF `SOCKHASH` 后端。 |

### 后端选择

自动优选顺序为 `sockhash`、`splice`、`buffered`。

后端**只有在尚未传输任何字节时**才能把连接交给下一个后端。一旦有字节流动，后端
错误将终止该中继，连接绝不会在另一个后端上重放。这一点由结构保证：构造 decline
的唯一途径是共享传输账本，而账本在任一计数器非零时拒绝生成 decline。

内核后端永远不会看到仍然承载 TLS 记录或 Vision 帧的套接字。单向 Vision Direct
（一个方向为裸流、另一个方向仍在成帧）在有界用户态中继，绝不会作为一对交给内核
后端。

### 资源核算

校验在任何监听器绑定之前拒绝不可能的预算，全部使用检查过的算术：

```text
buffered_memory     = maxPooledBuffers * bufferBytes
sockhash_capacity   = maxSockhashRelays * 2 * (flowKey + socketEntry + statsEntry + overhead)

buffered_memory   <= maxRelayMemoryBytes
sockhash_capacity <= maxPinnedMemoryBytes
```

`maxPooledBuffers` 是**缓冲区数量**，绝不是字节预算。

### 能力上报

启动时发出一条 `relay_backend_report` 事件，每个后端一行。不可用的后端会给出
封闭词表中的固定原因——`disabled`、`unsupportedOperatingSystem`、
`unsupportedKernel`、`missingOperation`、`missingCapability`、`blockedBySeccomp`、
`blockedByLsm`、`resourceLimit`、`queueUnavailable`、`mapUnavailable`、
`unsafeToArm`、`existingQueuedBytes`、`initializationFailure`——并且该拒绝原因
不会按连接重复输出。

splice 永远不会跨越 REALITY/TLS 安全边界。传输开始前无法获得 splice 资源时，
回退到有界用户态缓冲。

## `runtime`

进程级资源姿态。整个对象可选。

| 字段 | 对象存在时必填 | 默认值/允许值 | 含义与约束 |
| --- | --- | --- | --- |
| `runtime.resourceMode` | 否 | `standard`；`standard`、`dedicated` | `dedicated` 声明独占机器或 cgroup：把 `RLIMIT_NOFILE` 软限制提升到硬限制、按专用余量推导描述符预算，并运行有界内存压力监控器。见[专用机器资源模式](dedicated-resource-mode.zh-CN.md)。冷设置，修改必须重启。 |

## 热更新边界

`serve`/`run` 收到 SIGHUP 后构建完整候选配置。发布是原子的；失败时保留旧
generation，已有连接继续使用其获取的 generation。

监听拓扑兼容时可热更新：

- 日志；
- 资产 URL、缓存内容和刷新设置；
- DNS 超时；
- VLESS 用户及 REALITY 认证/伪装状态；
- 出站定义、路由组和规则；
- direct barrier；
- 在重放容量/保留时间不变时，NXR 密钥、时钟窗口和 I/O 超时。

必须重启：

- 添加/删除监听、修改绑定地址/端口，或改变某地址的协议；
- 任意 `runtime` 修改，因为资源模式影响进程生命周期的描述符预算和内存监控器；
- 任意 `policy.resourceGovernor` 修改，因为 REALITY 重放 admission/状态属于进程生命周期；
- 任意 `policy.relay` 修改，因为缓冲/splice 池属于进程生命周期；
- NXR `maxNonceEntries` 或 `nonceRetentionSeconds` 修改。

SIGHUP 前先运行 `check`，最好运行 `self-test`。文件本身有效仍可能不兼容热更新，
此时需要受控重启。

## 秘密与文件处理

- 配置权限使用 `0640 root:rust-reality` 或更严格。
- 不要提交生成 UUID、REALITY 私钥、应保密的 short ID、NXR PSK、SOCKS 凭据或真实端点。
- 在可信主机使用操作系统熵生成密钥，并通过已认证信道传输。
- 使用专用可写资产目录；外部 DAT 文件必须留在该目录内。
- `config format` 会把包括秘密在内的完整配置写到 stdout；重定向时谨慎，不要管道到日志。
