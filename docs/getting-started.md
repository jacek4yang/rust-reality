# Getting started

English | [简体中文](getting-started.zh-CN.md)

The shortest path from a release download to a working standalone node. For
production hardening, line/landing topologies, upgrades, and firewall rules,
continue to [deployment.md](deployment.md).

## 1. Download and verify the release

Download both archives, the manifest, and checksums from the
[latest release](https://github.com/jacek4yang/rust-reality/releases/latest),
then verify all assets before installation:

```shell
sha256sum --check SHA256SUMS
# Portable package (recommended when CPU support is unknown):
tar -xzf rust-reality-v<version>-x86_64-unknown-linux-gnu.tar.gz
# Or, on an x86-64-v3 CPU:
# tar -xzf rust-reality-v<version>-x86_64-v3-unknown-linux-gnu.tar.gz
sudo install -m 0755 rust-reality /usr/local/bin/rust-reality
rust-reality --version
```

`release-manifest.json` schema v2 records the version, tag, exact source
commit, target triple, source timestamp, both archive names and SHA-256 values,
and each archive's CPU requirement. The portable package targets baseline
x86-64. The optimized package requires x86-64-v3 and has no runtime fallback.
Do not combine assets from different releases.

## 2. Probe a cover target

The REALITY cover must be a TLS 1.3 endpoint the server can plausibly
impersonate. Test candidates from the actual deployment host:

```shell
rust-reality probe-dest \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com
```

## 3. Generate a standalone configuration

```shell
rust-reality config generate standalone \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com \
  > config.json 2> client-values.txt
```

The generated JSON contains a UUID, a private REALITY key, two short IDs owned
by that UUID, inbound `listen.mode: auto`, outbound `network.dial.mode: auto`,
and a direct-routing policy. The default listener binds independent IPv4 and
IPv6 sockets; locally resolved outbound peers use the shared adaptive policy.
The client-facing values (including the REALITY public
key) are written to standard error so the private server configuration can be
captured separately. Protect both outputs, and replace the example target with
one that passes `probe-dest` from the deployment host.

## 4. Validate and self-test

```shell
rust-reality check --config config.json
rust-reality self-test --config config.json
```

`check` validates structure, references, security invariants, and resource
limits without binding listeners. `self-test` additionally exercises the
configured assets, DNS, and cover target.

## 5. Run

```shell
rust-reality serve --config config.json
```

`serve` stays in the foreground for systemd or another supervisor. Point an
Xray-compatible client at the node using the values from step 3 (address,
port, UUID, public key, one short ID selected from that UUID's `shortIds`,
server name, flow `xtls-rprx-vision`) and
confirm traffic flows.

## Next steps

- Line node + firewall-restricted NXR landing node: generate one shared NXR
  key with `rust-reality node-keygen` and see the
  [deployment guide](deployment.md).
- Line node + Handoff landing node (the hop carries only TLS ciphertext):
  generate both configurations in one step with
  `rust-reality config generate handoff` and see the
  [deployment guide](deployment.md#line-node-and-handoff-landing-node).
- Every configuration field: [configuration.md](configuration.md).
- Every command: [cli.md](cli.md).
- Security posture before exposing a listener:
  [threat-model.md](threat-model.md).
