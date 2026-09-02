# Linux deployment

English | [简体中文](../../zh-CN/operations/deployment.md)

Putting a validated configuration into production: verifying the release,
creating the service account, the systemd unit, the firewall boundary, and
upgrades.

This page assumes you already have a working configuration. If you do not,
[getting started](../getting-started.md) produces one in about fifteen
minutes, and the [configuration guides](../configuration/index.md) explain
each field.

## Requirements

- 64-bit Linux with a modern kernel, and systemd for the provided unit.
- Root access for installation, the service account, the firewall, and the
  privileged port.
- Correct system time on every entry, landing, and client host. Both internal
  protocols reject transfers outside a bounded clock difference.
- A cover target that passes `rust-reality check-cover` **from the deployment
  host**.
- For a landing node, a private path from the entry node, or a firewall that
  admits only the entry node's address.

The binary needs outbound DNS and TCP access, write access to its asset cache,
and — only with file logging — write access to its log directory. It requires
no runtime language and no companion daemon.

## Install an official release

Download these six assets from the same
[GitHub Release](https://github.com/jacek4yang/rust-reality/releases):

- `rust-reality-vX.Y.Z-linux-x86_64-generic.tar.gz`
- `rust-reality-vX.Y.Z-linux-x86_64-musl.tar.gz`
- `rust-reality-vX.Y.Z-linux-x86_64-v3.tar.gz`
- `rust-reality-vX.Y.Z-linux-aarch64-generic.tar.gz`
- `release-manifest.json`
- `SHA256SUMS`

Verify every file before extraction:

```shell
sha256sum --check SHA256SUMS
tar -xzf rust-reality-v<version>-linux-x86_64-generic.tar.gz
sudo install -m 0755 rust-reality /usr/local/bin/rust-reality
rust-reality --version
```

| archive | requires | use it when |
| --- | --- | --- |
| `linux-x86_64-generic` | baseline x86-64 | any conventional glibc distribution |
| `linux-x86_64-musl` | baseline x86-64 | Alpine, or a minimal container; fully static |
| `linux-x86_64-v3` | x86-64-v3, **no runtime fallback** | you already know the CPU qualifies |
| `linux-aarch64-generic` | ARMv8.0 with neon | ARM64 |

The v3 tier is opt-in and showed no measured advantage on the validation host,
because the record AEAD dispatches to AES hardware at runtime in every tier.

`release-manifest.json` schema v3 records the version, tag, exact source
commit, target triples, source timestamp, compiler, cargo features, and each
tier's archive name, SHA-256, target CPU and features, and minimum CPU
requirements. **Do not combine an archive, manifest, or checksum from
different releases.**

To build instead, use the pinned toolchain and locked dependency graph:

```shell
cargo dev check --all
cargo dev release build linux-x86_64-generic
```

## Create the service account and directories

```shell
sudo useradd --system --home /var/lib/rust-reality \
  --shell /usr/sbin/nologin rust-reality
sudo install -d -o root -g rust-reality -m 0750 /etc/rust-reality
sudo install -d -o rust-reality -g rust-reality -m 0750 \
  /var/lib/rust-reality/assets
sudo install -d -o rust-reality -g rust-reality -m 0750 \
  /var/log/rust-reality
```

Recommended layout:

```text
/usr/local/bin/rust-reality              root:root          0755
/etc/rust-reality/config.json            root:rust-reality  0640
/var/lib/rust-reality/assets/            rust-reality       0750
/var/log/rust-reality/                   rust-reality       0750 (file sink only)
```

The configuration contains private keys. It is readable by the service group
and by nobody else.

## Install the configuration

```shell
sudo install -o root -g rust-reality -m 0640 \
  config.json /etc/rust-reality/config.json
rust-reality check   -c /etc/rust-reality/config.json
rust-reality doctor  -c /etc/rust-reality/config.json
rust-reality explain -c /etc/rust-reality/config.json
```

`check` proves the file is internally valid, offline. `doctor` proves this
machine and network agree with it. `explain` shows what the omitted fields
resolved to here — read it once before the first start, so the derived
ceilings are not a surprise later.

For a landing node, bring it up **before** the entry node that dials it, and
confirm the three values that span the two files: port, pre-shared key, and —
for Handoff — that the entry holds the public half of the landing's key. No
single-file check can see any of that; see
[line and landing nodes](../configuration/line-landing.md).

## Firewall

**Entry node.** Exactly one public listener, on 443. Nothing else about
rust-reality should be reachable.

**Landing node.** The port the entry node dials, from the entry node's address
only:

```shell
sudo iptables -A INPUT -p tcp --dport 7443 -s <entry-node-address> -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 7443 -j DROP
```

A landing reachable from the internet is a landing whose IP can be discovered,
which defeats the reason for having one. Bind it to its private address rather
than the wildcard, so a firewall mistake does not expose it:

```json
{ "listeners": [{ "port": 7443, "ip": "ipv4Only", "ipv4": "10.0.0.2" }] }
```

## Install and start systemd

Copy the unit shipped in the release archive:

```shell
sudo install -o root -g root -m 0644 \
  deploy/rust-reality.service /etc/systemd/system/rust-reality.service
sudo systemd-analyze verify /etc/systemd/system/rust-reality.service
sudo systemctl daemon-reload
sudo systemctl enable --now rust-reality
sudo systemctl status rust-reality
journalctl -u rust-reality -f
```

The unit runs `rust-reality run -c /etc/rust-reality/config.json` as the
dedicated account, retains only `CAP_NET_BIND_SERVICE`, protects the host
filesystem and kernel surfaces, and allows writes only to the asset and log
directories. Review it against your distribution's paths and your local
hardening policy rather than removing a restriction because something failed.

`CAP_NET_BIND_SERVICE` is how a non-root process binds 443. Do not run the
service as root to avoid granting it.

### Logging

For a normal installation use `log.output: "stderr"` or `"journald"` and let
the journal handle retention. Both write to standard error; `journald`
formats for journald's own parsing.

With `"file"`, `log.file` is required, and `maxBytes`, `maxFiles`, and
`maxTotalBytes` are all enforced.

`"none"` drops every event before encoding. It also silences warn-level
rejection and admission signal, so prefer a `level` filter unless logging
itself is unacceptable.

### Verify the start

On every start, confirm in the journal:

| event | what it tells you |
| --- | --- |
| `server_starting` | the process began startup |
| `outbound_network_initialized` | the cached IPv4/IPv6 route availability and the initial outbound preference |
| `descriptor_budget_report` | the descriptor plan; `fd_clamped: true` means the limit constrained it |
| `listener_topology_active` | which sockets actually bound, per listener |
| `listener_started` | a socket is accepting |
| `configuration_published` | generation 0 went live |

`listener_topology_active` reflects **bind results, not reachability**: a
bound IPv6 socket does not prove public IPv6 ingress works. Under
`ip: "auto"`, a missing family is acceptable only when
`listener_family_unavailable` reports a genuine family or protocol capability
error. Address-in-use, permission, and concrete-address errors stay fatal, and
`dualStack` never degrades.

## Reload and restart

Validate first, then reload:

```shell
rust-reality check -c /etc/rust-reality/config.json
sudo systemctl reload rust-reality
```

A candidate that fails to compile leaves the current generation serving and
logs `configuration_rejected` with the full diagnostic on stderr. Established
connections always finish on the generation that admitted them.

Cold settings need a restart rather than a reload: `role`, `listeners`,
`network`, `dns`, and every `runtime` field. A reload that changes one is
refused by name. The complete table is
[the reload summary](../configuration/reference.md#reload-summary).

```shell
sudo systemctl restart rust-reality
```

SIGTERM stops new accepts and drains live relays for up to 30 seconds. The
unit's 40-second stop timeout covers that with margin.

## Upgrade and rollback

1. Download and verify every asset for the new tag.
2. Keep the current binary and configuration as root-only rollback copies.
3. Run the new binary's `check` and `doctor` against a copy of the production
   configuration.
4. Install the new binary atomically and restart.
5. Verify the journal, the listener, a real client handshake, and routing.

```shell
sudo install -m 0755 rust-reality /usr/local/bin/rust-reality.new
sudo mv /usr/local/bin/rust-reality /usr/local/bin/rust-reality.previous
sudo mv /usr/local/bin/rust-reality.new /usr/local/bin/rust-reality
sudo systemctl restart rust-reality
```

Roll back by restoring the previous binary together with the configuration
that version accepts, then restarting. Do not downgrade while keeping
configuration fields the older version does not know — it will refuse them as
unknown fields, which is the correct behaviour and not a bug to work around.

Configuration written for a release before v1.9 is not accepted, and there is
no migration path. Write the new file: it is much shorter, and
[standalone](../configuration/standalone.md) walks through it.

### Versioned deployment

A permanent production node should separate replaceable software from
persistent identity. The typed `cargo dev deploy {inspect,plan,apply}` workflow
maintains this layout:

```text
/opt/rust-reality/releases/RELEASE/rust-reality
/opt/rust-reality/current -> releases/CURRENT
/opt/rust-reality/previous -> releases/PREVIOUS

/etc/rust-reality/releases/RELEASE/config.json
/etc/rust-reality/current -> releases/CURRENT
/etc/rust-reality/previous -> releases/PREVIOUS
```

Configuration generations are root-owned and service-group-readable, and they
carry the same persistent REALITY identity unless rotation is an explicit
operator action. The first migration copies the running binary and its
configuration into a known-good rollback bundle before the unit starts using
`current`. After a successful canary, keep CURRENT and PREVIOUS and delete only
older release generations.

**Never prune identity merely because an old binary is pruned.** A release is a
replaceable software generation; the node's REALITY identity and its port 443
endpoint are persistent deployment state, and a normal upgrade must preserve
both so already-configured clients keep working.

`cargo dev deploy apply` requires `--mutate-remote` for every mutation.
`stage` validates version, SHA-256, `check`, and `doctor` without switching the
live node. `cutover` prepares PREVIOUS and restores it automatically if the
process, the executable identity, or the port-443 health check fails. The tool
never edits SSH configuration, firewall rules, or listener ports.

On an edge host, port 22 is permanent administrative infrastructure and port
443 is the only public rust-reality listener. Auxiliary origins, metrics, and
benchmark helpers stay on loopback, Unix sockets, or isolated namespaces.

## When something is wrong

[Troubleshooting](troubleshooting.md) is organised by symptom. The three
commands to run first, in order:

```shell
rust-reality check   -c /etc/rust-reality/config.json
rust-reality explain -c /etc/rust-reality/config.json
rust-reality doctor  -c /etc/rust-reality/config.json
```

Do not publish debug logs without review, and never paste a production
configuration, key, UUID, or packet capture into a public issue.
`rust-reality explain --json` contains no key material and is safe to share.

## Removed kernel relay backends

The sockhash backend was removed: it never armed in any production benchmark
matrix, a privileged A/B showed parity with `splice`, and the unprivileged
production deployment model could never arm it.

The io_uring backend was removed; see
[ADR 0002](../../adr/0002-io-uring-removed.md).

Both left no configuration surface behind. The portable buffered relay and
Linux `splice` require no additional privilege, and `splice` is enabled or
disabled by the detected platform capability unless
[pinned](../configuration/runtime-and-resources.md#limits).
