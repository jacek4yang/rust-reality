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
| `inbounds` | 是 | — | 至少一个强类型 `vless` 或内部 `nxr`、`handoff` 监听。 |
| `outbounds` | 是 | — | 至少一个 `direct`、`blackhole`、`socks5`、`nxr` 或 `handoff` 传输。 |
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

以上占位符故意不能直接使用。请通过 `config generate standalone`、
`config generate line` 或 `config generate handoff` 生成真实状态。

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

### 内部 Handoff 入站

```json
{
  "protocol": "handoff",
  "tag": "internal-handoff",
  "listen": "0.0.0.0",
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
| `listen` | 是 | — | 内部绑定地址，必须由主机/云防火墙限制。 |
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
`preSharedKey` 相同，或 Handoff `privateKey` 与任何 REALITY `privateKey` 相同，
都无法通过校验；任何 previous-key 条目与上述材料相同同样会被拒绝。跨节点的
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
| `maxDnsLookups` | 否 | `64` | 有界解析池中并发阻塞 DNS 查找数。 |
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
| `maxSpliceRelays` | 否 | `256` | splice 开启时大于零且不超过 `maxConnections`；每条 relay 使用两对 pipe。 |
| `maxRelayMemoryBytes` | 否 | `536870912` | 池化加注册中继缓冲内存上限。 |
| `pipePool` | 否 | `true` | 进程级复用 splice 管道，而不是每个会话创建/扩容/销毁。 |
| `maxPooledPipes` | 否 | `512` | 池化管道上限；管道池按 `maxPooledPipes × 2` 页核算内存。 |
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
                | pipePool 开启时 maxPooledPipes * 2 * 256 KiB
                | pipePool 关闭时 maxSpliceRelays * 4 * 256 KiB

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
| `runtime.resourceMode` | 否 | `standard`；`standard`、`dedicated` | `dedicated` 声明独占机器或 cgroup：把 `RLIMIT_NOFILE` 软限制提升到硬限制、按专用余量推导描述符预算，并运行有界内存压力监控器。见[专用资源模式](#dedicated-resource-mode)。冷设置，修改必须重启。 |

### Dedicated resource mode

`{ "runtime": { "resourceMode": "dedicated" } }` 声明进程独占机器——或在容器
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
- DNS 超时；
- VLESS 用户及 REALITY 认证/伪装状态；
- 出站定义、路由组和规则；
- 在重放容量/保留时间不变时，NXR 密钥、时钟窗口和 I/O 超时；
- 在重放容量/保留时间不变时，Handoff 密钥材料、时钟窗口、超时和 egress 出站选择。

必须重启：

- 添加/删除监听、修改绑定地址/端口，或改变某地址的协议；
- 任意 `runtime` 修改，因为资源模式影响进程生命周期的描述符预算和内存监控器；
- 任意 `policy.resourceGovernor` 修改，因为 REALITY 重放 admission/状态属于进程生命周期；
- 任意 `policy.directBarrier` 修改，因为直连拨号 authority 属于进程生命周期；
- 任意 `policy.relay` 修改，因为缓冲/splice 池属于进程生命周期；
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
