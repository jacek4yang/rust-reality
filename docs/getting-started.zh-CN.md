# 快速上手

[English](getting-started.md) | 简体中文

从下载 Release 到跑通单机节点的最短路径。生产加固、线路机/落地机拓扑、升级
和防火墙规则请继续阅读 [deployment.zh-CN.md](deployment.zh-CN.md)。

## 1. 下载并验证 Release

从[最新 Release](https://github.com/jacek4yang/rust-reality/releases/latest)
下载适合你平台的压缩包、manifest 和校验文件，安装前验证全部资产：

```shell
sha256sum --check SHA256SUMS
# x86-64 GNU/glibc 通用包：
tar -xzf rust-reality-v<version>-linux-x86_64-generic.tar.gz
# Alpine/musl 或极简容器使用完全静态包：
# tar -xzf rust-reality-v<version>-linux-x86_64-musl.tar.gz
# 或在 x86-64-v3 GNU/glibc CPU 上使用：
# tar -xzf rust-reality-v<version>-linux-x86_64-v3.tar.gz
# 在 ARM64（ARMv8.0 含 neon 或更高）上使用：
# tar -xzf rust-reality-v<version>-linux-aarch64-generic.tar.gz
sudo install -m 0755 rust-reality /usr/local/bin/rust-reality
rust-reality --version
```

`release-manifest.json` schema v3 记录版本、标签、确切源码 commit、目标三元组、
源码时间戳、编译器、cargo features，以及每个档位的压缩包名称、SHA-256、目标
CPU/特性、是否在本机实测，以及最低 CPU 要求。两个 x86-64 通用包都面向
基线 x86-64：常规发行版选择 GNU/glibc 包，Alpine、其他 musl 系统和极简容器
选择完全静态 musl 包。v3 包要求 x86-64-v3 微架构级别，没有运行时回退，
且在验证主机上没有实测优势
（记录 AEAD 在每个档位都于运行时调度到 AES 硬件），只有确认 CPU 满足条件时才
应选择。aarch64 包要求 ARMv8.0 含 neon。不要混用不同 Release 的资产。

## 2. 探测伪装目标

REALITY 伪装目标必须是服务端可以合理 impersonate 的 TLS 1.3 端点。请在实际
部署机器上测试候选目标：

```shell
rust-reality probe-dest \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com
```

## 3. 生成单机配置

```shell
rust-reality config generate standalone \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com \
  > config.json 2> client-values.txt
```

生成的 JSON 包含 UUID、REALITY 私钥、归该 UUID 独占的两个 short ID、入站
`listen.mode: auto`、出站 `network.dial.mode: auto` 和 direct 路由策略。默认监听
绑定相互独立的 IPv4 与 IPv6 套接字；本地解析的出站对端使用共享自适应策略。客户端所需
的值（包括 REALITY 公钥）写入标准错误，使服务器私密配置可以单独保存。两个
输出都应妥善保护；示例目标必须替换成从实际部署机器执行 `probe-dest` 能通过
的目标。

## 4. 校验并自测

```shell
rust-reality check --config config.json
rust-reality self-test --config config.json
```

`check` 在不绑定监听端口的情况下验证结构、引用、安全不变量和资源限制。
`self-test` 进一步检查配置的资产、DNS 和伪装目标。

## 5. 运行

```shell
rust-reality serve --config config.json
```

`serve` 在前台运行，适合 systemd 或其他进程管理器。用第 3 步得到的值（地址、
端口、UUID、公钥、从该 UUID 的 `shortIds` 中选择的一个 short ID、server name、
flow `xtls-rprx-vision`）配置兼容
Xray 的客户端，确认流量正常。

## 下一步

- 线路机 + 受防火墙限制的 NXR 落地机：先用 `rust-reality node-keygen` 生成一
  个共享 NXR 密钥，然后阅读[部署指南](deployment.zh-CN.md)。
- 线路机 + Handoff 落地机（转移后该跳只承载 TLS 密文）：用
  `rust-reality config generate handoff` 一步生成两侧配置，然后阅读
  [部署指南](deployment.zh-CN.md#线路机与-handoff-落地机)。
- 全部配置字段：[configuration.zh-CN.md](configuration.zh-CN.md)。
- 全部命令：[cli.zh-CN.md](cli.zh-CN.md)。
- 开放监听端口前的安全姿态：
  [threat-model.zh-CN.md](threat-model.zh-CN.md)。
