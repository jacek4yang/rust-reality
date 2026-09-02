# Choosing a cover target

English | [简体中文](../../zh-CN/configuration/cover-targets.md)

REALITY does not obfuscate traffic into something unrecognisable. It makes a
connection to your server look exactly like a connection to some other, real,
TLS host. That host is the **cover target**, and choosing it is the decision
that most determines whether the deployment survives scrutiny.

## What the cover actually does

Two things, and they are different:

1. **It shapes every handshake.** The server dials the cover, reads its real
   ServerHello, and builds its own reply to match — cipher suite, key exchange
   group, extension layout, record sizes. An observer comparing your server's
   handshake with the cover's finds them alike because one was derived from
   the other.
2. **It absorbs everything that fails authentication.** A probe, a scanner, or
   a browser that reaches your port and cannot prove it is a client gets
   proxied to the cover and receives the cover's genuine response. There is no
   error, no reset, no distinguishing timeout — from the prober's side, your
   IP is running that site.

So the cover is not a decoration. It is what your server *is*, to anybody who
is not a client.

## The hard requirements

A candidate must:

- **Speak TLS 1.3** with X25519 key exchange. TLS 1.2 cannot be a cover.
- **Be reachable from the server**, quickly and reliably. Its latency lands
  inside the setup phase of every connection, authenticated or not.
- **Not be behind the same censorship you are working around.** A cover that
  is itself blocked makes your server look like a blocked site.

Test from the deployment host, not from your laptop — the answer is a
property of the network path:

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

`compatible: true` is the requirement. The timings are the other half of the
answer: `totalMillis` is added to the setup of every connection this node
serves, so a cover that is compatible but slow is a cover that makes your
node slow.

Failure is terse, because there is not much to say:

```
error: failed to connect to REALITY target
```

Try the next candidate. The command has a `--timeout-ms` (default 5000) for
a path where 5 seconds is not enough to be conclusive.

`check-cover` exists as a top-level command precisely because this happens
before any configuration exists, and on a machine that has the release
tarball and no build toolchain.

## The judgement requirements

These are not machine-checkable, and they matter more than the technical ones.

**It should be plausible that your server talks to it.** A VPS in Frankfurt
holding a persistent TLS relationship with a large CDN or cloud property is
ordinary. The same VPS impersonating a small regional site nobody in that
region visits is a story that does not hold together.

**It should be busy.** Traffic to a popular host is noise. Traffic to a quiet
one is a sample.

**It should not be yours.** A cover you control, or that is hosted in the same
place as your node, correlates the two.

**It should be stable.** If the cover changes its TLS configuration, your
handshakes change shape with it. Prefer hosts that have looked the same for
years over something recently stood up.

**Avoid the obvious.** Cover targets that circulate in tutorials are the first
things a scanner checks for. A host chosen by you, meeting the criteria above,
is worth more than a host from a list.

## Putting it in the file

```json
{
  "reality": {
    "cover": "www.microsoft.com:443",
    "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE"
  }
}
```

The port is part of the value and is not optional — 443 is not assumed,
because a cover on another port is a legitimate, if unusual, choice.

## `serverNames`, and the client's SNI

`serverNames` is the set of names an authenticated client may present.
Omitted, it defaults to the cover's own hostname, which is what you want in
almost every case:

```json
{
  "reality": {
    "cover": "www.microsoft.com:443",
    "privateKey": "ERERERERERERERERERERERERERERERERERERERERERE",
    "serverNames": ["www.microsoft.com"]
  }
}
```

The two lines above are equivalent. Set it explicitly only when a client must
present a name that differs from the cover host.

The client's SNI must match an entry exactly, or match a leftmost single-label
wildcard such as `*.example.com`. A mismatch fails the handshake, and it is
one of the two most common first-deployment failures — the other being the
swapped key half.

If the cover is named by IP address there is no hostname to default to, so
`serverNames` becomes required. Prefer a hostname: an IP-addressed cover is
harder to make plausible.

## Checking it later

`check` never contacts the cover — it is offline by design, so a valid file
stays valid on a machine with no network.

`doctor` does contact it, which makes it the command to run before a restart
and after any change to the cover:

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

A cover that has stopped being compatible is a live problem, not a
configuration error: the file has not changed, the internet has. Re-check
periodically, and treat a rising `totalMillis` as a latency regression in
every connection the node serves.

## Changing the cover

`reality` is hot, so a new cover applies on SIGHUP. But changing it changes
what your server looks like, and every established connection was built
against the old shape.

Validate the new cover first, then change and reload:

```shell
rust-reality check-cover --cover www.example.org:443
# edit config.json
rust-reality check -c /etc/rust-reality/config.json
sudo systemctl reload rust-reality
```

If `serverNames` was implicit, changing the cover also changes the SNI clients
must present. Update the clients, or pin `serverNames` to the old value before
you change the cover so the two moves are independent.
