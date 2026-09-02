# Getting started

English | [简体中文](../zh-CN/getting-started.md)

Install the binary, generate the material you cannot invent by hand, write a
twenty-line configuration, and connect a client. About fifteen minutes on a
fresh server.

You write the configuration yourself. There is no command that generates one
for you, and that is deliberate: the file is short, every field in it is a
decision, and an operator who wrote it can debug it. This page walks through
each field as it is added.

## What you need

- A Linux server with a public IP and root access.
- Port 443 free on that server. REALITY is only convincing on the port real
  TLS uses.
- A client that speaks VLESS with REALITY and the Vision flow — Xray-core,
  or any application built on it.

## 1. Install

Download the archive for your platform, the manifest, and the checksums from
the [latest release](https://github.com/jacek4yang/rust-reality/releases/latest),
then verify before installing:

```shell
sha256sum --check SHA256SUMS
tar -xzf rust-reality-v<version>-linux-x86_64-generic.tar.gz
sudo install -m 0755 rust-reality /usr/local/bin/rust-reality
rust-reality --version
```

Pick the archive that matches the machine:

| archive | use it when |
| --- | --- |
| `linux-x86_64-generic` | any conventional glibc distribution |
| `linux-x86_64-musl` | Alpine, or a minimal container |
| `linux-x86_64-v3` | you know the CPU is x86-64-v3; there is no runtime fallback |
| `linux-aarch64-generic` | ARM64, ARMv8.0 with neon or later |

Do not mix assets from different releases. `release-manifest.json` records
the exact source commit, compiler, features, and per-archive SHA-256 for
every tier.

## 2. Choose a cover target

REALITY works by looking exactly like a TLS connection to some other,
entirely real, host. That host is the **cover target**, and choosing it is
the first real decision of the deployment.

Test candidates **from the server itself**, because the answer depends on the
network path:

```shell
rust-reality check-cover --cover www.microsoft.com:443
```

A usable cover answers quickly and negotiates TLS 1.3 with X25519. If the
command reports otherwise, try another host — the requirements and the
reasoning are in [choosing a cover target](configuration/cover-targets.md).

## 3. Generate the material

Three kinds of value cannot be made up. Generate each one on the server:

```shell
rust-reality generate x25519
rust-reality generate uuid
rust-reality generate short-id
```

`generate x25519` prints two halves:

```
private key (keep secret): bkuHF6dZ2Elt_dkFKZoXkSUZ6gnLITrUZbRmDggVfuQ
public key  (give to peers): CyrxYetA0RSs9IxcGpb7vNfQ3GoKm6xTUL5qWdbjUAY
```

The **private** half goes in the server file. The **public** half goes in the
client, and nowhere else. Getting these two backwards is the single most
common way a first deployment fails, so it is worth a moment: the server file
below must never contain the public key.

Add `--json` to any of them for machine-readable output, which is what an
installer script should consume.

## 4. Write the configuration

Create `/etc/rust-reality/config.json`:

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
    }
  ],
  "routing": {
    "default": "direct"
  }
}
```

> **The key, UUID, and short ID above are placeholders.** They are shaped
> correctly so this page's example can be machine-validated, which means
> `check` will accept them. It cannot tell that they are public knowledge.
> Replace all three with the output of step 3 before the node is reachable.

Six fields, and each one is a decision:

- **`role`** — `entry` means this node faces the public internet and speaks
  VLESS + REALITY + Vision. The other role is `landing`, covered in
  [line and landing nodes](configuration/line-landing.md).
- **`listeners`** — where to accept connections. A bare `port` binds both
  IPv4 and IPv6 and starts if either works.
- **`reality.cover`** — the host from step 2, with its port.
- **`reality.privateKey`** — the private half from step 3.
- **`users`** — who may connect. `label` is for your own logs and reports;
  it has no effect on the protocol.
- **`routing.default`** — where traffic goes when no rule says otherwise.
  `direct` and `block` always exist and are never declared.

Everything else has a default derived from this machine. You will see what
those defaults resolved to in step 6.

Then lock the file down. It contains a private key:

```shell
sudo chown root:root /etc/rust-reality/config.json
sudo chmod 0600 /etc/rust-reality/config.json
```

## 5. Check it

```shell
rust-reality check -c /etc/rust-reality/config.json
```

```
/etc/rust-reality/config.json is a valid entry node
```

`check` is strictly offline. It parses, validates every value and every
cross-reference, and touches nothing — no DNS, no sockets, no downloads. It
is safe to run anywhere, including in CI on a laptop.

When something is wrong it says so against the line that caused it:

```
error: invalid value for `reality.privateKey`
 --> /etc/rust-reality/config.json:6:19
  |
6 |     "privateKey": "[REDACTED]"
  |                   ^^^^^^^^^^^^ must be URL-safe unpadded base64 decoding to exactly 32 bytes
```

Note that the value itself is redacted. Diagnostics never echo secrets.

## 6. Check the environment

```shell
rust-reality doctor -c /etc/rust-reality/config.json
```

`doctor` does everything `check` does and then contacts what the file names:
it resolves DNS, dials the cover target and confirms it still negotiates
TLS 1.3, loads any geo data, and verifies filesystem permissions. It binds no
listener and changes nothing.

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

To see what the omitted fields resolved to on this machine:

```shell
rust-reality explain -c /etc/rust-reality/config.json
```

```
role: entry
listeners:
  0.0.0.0:443, [::]:443 (auto, at least one)
routing:
  default: direct (0 rules, strategy resolveIfNoMatch)
  outbounds: direct, block
machine: 4 effective cpus (4 logical), 524288 descriptors, 16194637824 bytes memory (cgroup_v2)
posture: profile auto -> standard, tuning startup, objective balanced
runtime: 4 worker threads, 512 blocking threads (tokio-default)
limits: 25 values, all derived from the machine (--json for the table)
```

## 7. Run

```shell
rust-reality run -c /etc/rust-reality/config.json
```

`run` stays in the foreground and serves until SIGINT or SIGTERM, which is
what a supervisor wants. For the systemd unit, the user to run as, and the
firewall rules, see [deployment](operations/deployment.md).

## 8. Connect a client

The client needs six values, and only one of them comes from a file it does
not have:

| client field | value |
| --- | --- |
| address | your server's IP or hostname |
| port | `443`, from `listeners[0].port` |
| id / UUID | `users[0].id` |
| public key | the **public** half from step 3 — *not* what is in the file |
| short id | any one entry from that user's `shortIds` |
| server name / SNI | `www.microsoft.com`, the cover host |
| flow | `xtls-rprx-vision` |

The flow is always `xtls-rprx-vision`; this server speaks no other, which is
why the configuration does not mention it.

Browse something. If it works, the deployment is done.

If it does not, [troubleshooting](operations/troubleshooting.md) is organised
by symptom, starting with the two failures that account for most of them: the
wrong half of the key pair, and a client SNI that does not match the cover.

## Where to go next

- **Understand the file you just wrote** —
  [how configuration works](configuration/index.md).
- **Add users, or rotate credentials** —
  [users and credentials](configuration/users-and-credentials.md).
- **Send some traffic somewhere else** —
  [routing](configuration/routing.md).
- **Hide your egress IP behind a second machine** —
  [line and landing nodes](configuration/line-landing.md).
- **Put it under systemd properly** —
  [deployment](operations/deployment.md).
- **Know what you are exposing** — [threat model](threat-model.md).
