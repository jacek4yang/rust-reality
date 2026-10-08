# 控制 API

[English](../../en/operations/control-api.md) | 简体中文

入口节点可以开放一个本地控制套接字，同一主机上的其他程序用它查看正在运行的一代，并在不
编辑配置文件的前提下管理用户和 short ID。本页是协议契约。设计理由记录在
[ADR 0031](../../adr/0031-local-control-interface.md)。

rust-reality 只提供这一通用接口。面板、机器人、计费、账户体系、远程管理都是建立在它之上
的外部程序，都不属于本仓库。

## 启用

```json
{ "control": { "socket": "/run/rust-reality/control.sock" } }
```

`control` 是入口节点的段落，属于冷配置：修改或删除它需要重启。不写表示不存在控制接口。
随附的 systemd 单元会为该路径创建 `/run/rust-reality`（权限 `0750`，属主为服务账户）。见
[配置参考](../configuration/reference.md#control)。

启动时，在所有数据监听器绑定完成之后，服务器会：

1. 打开套接字旁的 `<socket>.lock`（不存在时以权限 `0600` 创建，从不截断或删除），并在进程
   整个生命周期内对它持有一个排他、非阻塞的 `flock`；若另一个进程持有该锁，启动失败，已有的
   套接字保持原样；
2. 在持有该锁的前提下，删除上一个进程遗留在该路径上的旧*套接字*；若该路径上是其他任何类型的
   文件，则拒绝启动；
3. 创建套接字并把权限设为 `0600`；
4. 只接受 `SO_PEERCRED` uid 为套接字属主或 root 的对端。

关闭时，只有当该路径仍指向本进程创建的那个套接字（设备号与 inode 相同）时才删除它；别人放在
那里的文件保持原样。锁文件会保留，因此两个实例永远不会在删除并重建它时发生竞争。没有 TCP 监听，也没有能创建 TCP 监听的设置；需要远程访问时，请通过
你自己的已认证通道（例如 SSH）到达该套接字。

## 分帧

每个方向每行一个 JSON 对象，UTF-8，以 `\n` 结尾（也接受 `\r\n`）。一个连接可以发送任意
多个请求；每个请求按顺序恰好得到一行响应。空行会被忽略。

```shell
printf '%s\n' '{"v":1,"op":"system.status"}' \
  | sudo -u rust-reality socat - UNIX-CONNECT:/run/rust-reality/control.sock
```

### 请求

| 字段 | 类型 | 必填 | 含义 |
| --- | --- | --- | --- |
| `v` | 整数 | 是 | 协议版本。本构建使用 `1`。 |
| `op` | string | 是 | 操作名，见下表。 |
| `id` | 不超过 128 字节的 string | 否 | 不透明值，在响应中原样回显。 |
| `args` | 对象 | 否 | 该操作的参数。未知字段会被拒绝。 |
| `expectedGeneration` | 整数 | 否 | 仅用于变更：只有它仍是当前一代时才应用。 |

未知的信封字段会被拒绝。本构建不支持的版本得到 `unsupportedVersion`，绝不会被换一种方式
解读。

### 响应

```text
{"v":1,"id":"r1","ok":true,"generation":8,"result":{ }}
{"v":1,"id":"r1","ok":false,"generation":7,"error":{"code":"notFound","message":"no user has this handle"}}
```

`generation` 是生成响应时的当前一代：变更成功后就是新发布的那一代。校验错误可能带有
`error.path`，即失败的配置路径（`users[2].shortIds[0]`）。请依据 `error.code` 分支；消息
写给人看，可能会变。

## 用户与句柄

用户通过**句柄**指称：`u_` 后接 32 个小写十六进制字符。句柄由用户的 UUID 和一个从节点
REALITY 私钥派生的密钥计算得出：跨重载、跨重启保持不变，不泄露 UUID 的任何信息；若更换
REALITY 私钥，所有用户的句柄都会改变。

UUID 是凭据。控制接口在 `users.create` 上接收一个（或生成一个），并且只在该响应中返回一次。
任何列表、错误或日志行都不会包含 UUID。

`users.list` 与 `users.get` 返回的用户摘要如下：

```json
{"handle":"u_…","label":"phone","policy":"split","enabled":true,"shortIdCount":1}
```

变更操作结果中的 `user` 是完整视图，用 `shortIds` 代替 `shortIdCount`。未设置时省略
`label` 和 `policy`。

## 列表

`users.list` 与 `shortIds.list` 分页返回。它们接受 `limit`（1–1000，默认 100）和
`cursor`，返回 `total`，在仍有条目时还返回 `nextCursor`。把 `nextCursor` 作为 `cursor`
传回即可读取下一页。一页只包含完整的条目，编码后的条目达到 256 KiB 时停止增长，因此可能少于
`limit` 条；只要还有剩余条目，一页至少包含一条。

游标属于签发它的那一代。在另一代发布之后再出示它会得到 `cursorExpired`：请不带游标重新开始
列举。因此一次列举绝不会由两代拼接而成。

## 操作

| 操作 | 参数 | 结果 |
| --- | --- | --- |
| `system.status` | — | `server`（`name`、`version`、`commit`）、`protocol`（`version`、`supported`）、`role`、`generation`、`capabilities`（操作名）、`limits` |
| `generation.get` | — | `generation`、`origin`、`controlChanges` |
| `config.reload` | — | 同 `generation.get`，针对新发布的一代 |
| `users.list` | `cursor`?、`limit`? | `users`：用户摘要；`total`、`nextCursor`? |
| `users.get` | `user` | `user`：用户摘要 |
| `users.create` | `id`?、`shortIds`?、`label`?、`policy`?、`enabled`? | `user`、`id`（UUID，仅此一次） |
| `users.setEnabled` | `user`、`enabled` | `user` |
| `users.delete` | `user` | `handle` |
| `shortIds.list` | `user`?、`cursor`?、`limit`? | `shortIds`：`shortId`、`user`、`enabled`；`total`、`nextCursor`? |
| `shortIds.add` | `user`、`shortId` | `user` |
| `shortIds.remove` | `user`、`shortId` | `user` |
| `shortIds.rotate` | `user`、`retire`?、`bytes`? | `shortId`（新的那一条）、`user` |

- 不带 `id` 的 `users.create` 从操作系统 CSPRNG 生成 UUID；不带 `shortIds` 时生成一条
  8 字节 short ID。`label` 最多 128 字节且不含控制字符。
- `users.setEnabled` 传 `false` 时写入 `enabled: false`；传 `true` 时删除该字段，因为启用
  是默认值。
- `shortIds.rotate` 抽取一条 `bytes` 字节（1–8，默认 8）、无人占用且不在本次退役列表中的
  新 short ID 并加入，同时在同一代中删除 `retire` 中的每一条（最多 16 条，且都必须属于该
  用户）。不带 `retire` 时旧 short ID 继续有效：先把新的分发给客户端，再用第二次调用删除旧的。
- short ID 比较时不区分大小写，存储为小写。
- 每个变更结果都带有 `changed`。结果与当前配置相同的变更（例如把用户的 `users.setEnabled`
  设为它已有的状态）不会发布任何东西：`changed` 为 `false`，`generation` 为当前一代。

### 代的来源

`origin` 说明当前一代由什么产生：`startup`、`configuration`（由 `SIGHUP` 或
`config.reload` 触发的文件重载）、`assets`（对当前配置的定时资源刷新）或 `control`。当前一代
带有配置文件中没有的控制改动时，`controlChanges` 为 `true`。

## 代语义

一次变更是一个事务：

1. 获取存储的更新锁；
2. 若给出了 `expectedGeneration` 且它不是当前一代，以 `generationConflict` 结束；
3. 从*当前*配置派生恰好包含一处改动的候选；
4. 用与配置文件完全相同的标准检查它：配置大小上限、完整语义校验、拒绝冷改动；
5. 像 `SIGHUP` 重载那样编译并原子发布。

只在 `users` 上与当前配置不同的候选会走更窄的编译：REALITY 认证器、它的 short ID 索引以及
按 UUID 分组的路由表都从新用户重建，而已加载的地理资源、出站及其线路到落地的连接池、伪装回落
及其连接池、伪装画像则沿用当前一代。因此用户管理从不读取或下载资源，也从不让预热池冷却。任何
其他差异都走完整编译。

资源刷新也是同样的事务：它重新编译持锁时的当前配置，因此绝不会撤销它等待期间发布的控制改动。

服务器开始关闭时，会先关闭存储，再回收最后一代的连接池。此时仍在编译的事务以 `unavailable`
失败，不发布任何东西。

由此可得：

- 并发的控制程序绝不会悄悄覆盖彼此：每次改动都应用在上一次的结果之上。当某个改动只相对
  你读到的状态才正确时（比较并发布），或要让重试的请求变得安全时，请使用
  `expectedGeneration`。
- 被拒绝的改动不会触动当前一代，也不会推进代计数器。
- 更早建立的会话保持它们的那一代。禁用或删除用户、删除 short ID 只拒绝**新**连接。
- 被禁用用户的 short ID 仍保持占用；出示其中一条的处理方式与未知 short ID 完全相同。至少
  要有一个用户保持启用，每个用户至少保留一条 short ID。

## 控制改动与配置文件

服务器从不写自己的配置文件。控制改动只存在于正在运行的那一代中：

- 资源刷新会保留它们；
- 文件重载（`SIGHUP` 或 `config.reload`）会用文件内容**替换它们**，`controlChanges` 变为
  `false`；
- 重启会丢失它们。

因此，管理用户的外部控制程序要么作为唯一写入者并在重启后重新应用自己的状态，要么自行写配置
文件再调用 `config.reload`。控制状态的持久化边界将另行规划。

## 错误码

| 代码 | 含义 |
| --- | --- |
| `invalidRequest` | 该行不是有效的请求信封。 |
| `unsupportedVersion` | `v` 是本构建不支持的版本。 |
| `unknownOperation` | `op` 不是已知操作。 |
| `invalidArgument` | 参数格式错误、未知或超出范围。 |
| `notFound` | 没有用户持有该句柄，或该用户不拥有该 short ID。 |
| `conflict` | 身份已存在，或 short ID 已被某个用户占用。 |
| `generationConflict` | `expectedGeneration` 不是当前一代。 |
| `validationFailed` | 结果配置未通过校验；见 `error.path`。 |
| `updateFailed` | 编译或发布失败，或文件重载被拒绝。 |
| `unavailable` | 该操作需要本进程不具备的东西，例如 `config.reload` 需要配置文件；或服务器正在关闭。 |
| `requestTooLarge` | 请求行超过 64 KiB；连接被关闭。 |
| `busy` | 所有控制连接都在使用中；连接被关闭。 |
| `cursorExpired` | 列表的 `cursor` 属于已被替换的一代；请重新开始列举。 |
| `internal` | 内部不变量失败；没有任何改动。 |

## 上限

| 上限 | 值 |
| --- | --- |
| 请求行 | 64 KiB |
| 请求 `id` | 128 字节 |
| 并发连接 | 8 |
| 每连接在途请求 | 1 |
| 所有连接同时执行工作的请求 | 2 |
| 列表页 | 1000 条，条目共 256 KiB |
| 两次请求之间的空闲时间 | 60 s |
| 停滞的响应写入 | 10 s |
| 错误消息 | 4 KiB |
| 结果配置 | 4 MiB，与任何配置文件的上限相同 |

除 `system.status` 和 `generation.get` 外，所有操作都在阻塞线程池上运行，绝不在承载代理流量
的线程上运行；所有连接合计同时最多运行两个，其余的排队等候。句柄每一代只派生一次，并被该代的
每次读取复用。

`system.status` 在 `limits` 下报告请求、连接、工作、分页和空闲上限。

## 事件

| 事件 | 级别 | 字段 |
| --- | --- | --- |
| `control_started` | info | `socket` |
| `control_change_published` | info | `operation`、`generation` |
| `control_connection_refused` | warn | `reason`（`capacity` 或 `peerCredentials`），每分钟至多一次 |

每次发布还会发出已有的 `configuration_published`。没有任何事件携带 UUID、句柄、short ID 或
参数。
