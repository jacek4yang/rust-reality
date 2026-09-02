# 挑选伪装目标

[English](../../en/configuration/cover-targets.md) | 简体中文

REALITY 不是把流量混淆成认不出来的样子。它是让到你服务器的连接看起来和到另一台
**真实** TLS 主机的连接完全一样。那台主机就是**伪装目标**，选它这件事，最大程度
上决定了这次部署经不经得起细看。

## 伪装目标到底在做什么

两件事，而且是不同的两件：

1. **它决定每一次握手的形状。** 服务端会去拨号伪装目标，读它真实的 ServerHello，
   然后照着造自己的回应——加密套件、密钥交换组、扩展排布、记录长度。有人拿你服务
   器的握手和伪装目标的握手对比，会发现它们很像，因为其中一个就是照着另一个造的。
2. **它兜住所有认证失败的连接。** 探测器、扫描器，或者一个连上你端口但证明不了
   自己是客户端的浏览器，都会被代理到伪装目标，拿到伪装目标真实的响应。没有报错、
   没有 reset、也没有能用来区分的超时——在探测方看来，你的 IP 就是在跑那个站点。

所以伪装目标不是装饰。对任何不是客户端的人来说，你的服务器**就是**它。

## 硬性要求

候选目标必须：

- **会说 TLS 1.3**，密钥交换用 X25519。TLS 1.2 当不了伪装目标。
- **从服务器能快且稳地连上。** 它的时延落在每一个连接的建立阶段里，无论那个连接
  有没有通过认证。
- **不在你要绕开的那套封锁里。** 一个自己就被墙掉的伪装目标，会让你的服务器看起来
  像个被墙掉的站点。

在部署主机上测，不要在自己笔记本上测——答案是网络路径的属性：

```shell
rust-reality check-cover --cover www.microsoft.com:443
```

```json
{
  "target": "www.microsoft.com:443",
  "serverName": "www.microsoft.com",
  "compatible": true,
  "cipherSuite": "TLS_AES_256_GCM_SHA384",
  "keyExchangeGroup": "X25519",
  "connectMillis": 304,
  "serverHelloMillis": 1892,
  "totalMillis": 2197
}
```

`compatible: true` 是硬要求。时延是答案的另一半：`totalMillis` 会加进这个节点服务
的每一个连接的建立过程，所以一个兼容但很慢的伪装目标，就是一个让你节点变慢的伪装
目标。

失败的输出很简短，因为确实没什么可说的：

```
error: failed to connect to REALITY target
```

换下一个候选。命令有 `--timeout-ms`（默认 5000），用于 5 秒不足以下结论的路径。

`check-cover` 之所以是一个顶层命令，正是因为这件事发生在任何配置存在之前，而且发
生在一台只有 release 压缩包、没有编译工具链的机器上。

## 判断层面的要求

这些机器检不了，而且比技术要求更重要。

**你的服务器和它说话，得说得通。** 一台法兰克福的 VPS 与某个大 CDN 或云产品保持
长期 TLS 关系，这很平常。同一台 VPS 伪装成一个当地没人访问的小型区域站点，这个
故事就圆不上。

**它应该很忙。** 到热门主机的流量是噪声，到冷清主机的流量是样本。

**它不该是你的。** 你控制的、或者和你节点托管在同一处的伪装目标，会把两者关联
起来。

**它应该稳定。** 伪装目标一旦改了 TLS 配置，你的握手形状会跟着变。宁可选多年
如一日的主机，也不要选最近才立起来的。

**避开显眼的。** 在教程里流传的伪装目标是扫描器第一批要查的。你自己按上面的标准
挑出来的主机，比清单上抄来的值钱。

## 写进文件

```json
{
  "reality": {
    "cover": "www.microsoft.com:443",
    "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE"
  }
}
```

端口是这个值的一部分，不能省——不假定 443，因为伪装目标在别的端口上虽然少见，
但是个合法选择。

## `serverNames` 与客户端 SNI

`serverNames` 是已认证客户端可以出示的名字集合。不写的话，默认取伪装主机自己的
域名，几乎所有情况下这就是你要的：

```json
{
  "reality": {
    "cover": "www.microsoft.com:443",
    "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE",
    "serverNames": ["www.microsoft.com"]
  }
}
```

上面这两种写法等价。只有当客户端必须出示一个和伪装主机不同的名字时，才显式写它。

客户端的 SNI 必须与某一项完全匹配，或者匹配一个最左单标签通配符，例如
`*.example.com`。对不上就握手失败，这是新部署两大常见失败之一——另一个是密钥拿反。

如果伪装目标是用 IP 地址写的，就没有域名可以默认，`serverNames` 变成必填。优先用
域名：用 IP 的伪装目标更难圆得过去。

## 之后怎么复查

`check` 从不联系伪装目标——它按设计就是离线的，所以一份有效的文件在没有网络的机器
上依然有效。

`doctor` 会去联系它，所以它是重启前、以及任何伪装目标变更之后该跑的命令：

```shell
rust-reality doctor -c /etc/rust-reality/config.json
```

```json
{
  "configuration": "ok",
  "cover": [
    {
      "target": "www.microsoft.com:443",
      "serverName": "www.microsoft.com",
      "compatible": true,
      "cipherSuite": "TLS_AES_256_GCM_SHA384",
      "keyExchangeGroup": "X25519",
      "totalMillis": 642
    }
  ],
  "role": "entry",
  "routing": "ok"
}
```

一个不再兼容的伪装目标是一个现实问题，不是配置错误：文件没变，是互联网变了。要定
期复查，并且把变大的 `totalMillis` 当成这个节点每一个连接的时延回退来对待。

## 换伪装目标

`reality` 是热配置，所以新伪装目标在 SIGHUP 后生效。但换它就是换你服务器的样子，
而且所有已建立的连接都是照旧形状造出来的。

先验新的，再改再重载：

```shell
rust-reality check-cover --cover www.example.org:443
# 编辑 config.json
rust-reality check -c /etc/rust-reality/config.json
sudo systemctl reload rust-reality
```

如果原来 `serverNames` 是省略的，换伪装目标同时也换掉了客户端必须出示的 SNI。要么
一起更新客户端，要么在换伪装目标之前先把 `serverNames` 钉成旧值，让这两步互相独立。
