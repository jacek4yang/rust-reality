# Linux deployment

English | [简体中文](deployment.zh-CN.md)

This guide deploys an official Linux x86_64 release as either a standalone
public node, a public line node, or a firewall-restricted NXR landing node.

## Requirements

- 64-bit Linux with a modern kernel and systemd for the provided unit.
- Root access for installation, service account, firewall, and privileged port.
- Correct system time on every public, line, landing, and client host.
- One REALITY cover endpoint that passes `probe-dest` from the public node.
- For NXR, a fixed/private line-to-landing path or a firewall that allows only
  the line node's fixed source IP.

The binary needs outbound DNS/TCP access, write access to its asset cache, and
optional write access to its file-log directory. It does not require a runtime
language or companion daemon.

## Install an official release

Download these three assets from the same
[GitHub Release](https://github.com/jacek4yang/rust-reality/releases):

- `rust-reality-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz`
- `release-manifest.json`
- `SHA256SUMS`

Verify both listed files before extraction:

```shell
sha256sum --check SHA256SUMS
tar -xzf rust-reality-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 0755 rust-reality /usr/local/bin/rust-reality
rust-reality --version
```

`release-manifest.json` records the version, tag, exact source commit, target
triple, source timestamp, archive name, and archive SHA-256. Do not combine an
archive, manifest, or checksum from different releases.

To build instead, use the pinned toolchain and locked dependency graph:

```shell
./scripts/check.sh
./scripts/build-release.sh
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

## Standalone public node

### 1. Select and probe the cover target

The SNI must be a DNS name served by the target and the target must negotiate a
compatible TLS 1.3 ServerHello. Test from the real VPS:

```shell
rust-reality probe-dest \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com
```

Target availability and behavior are external dependencies. Re-run the probe
after persistent handshake failures or target changes.

`serverNames` may later contain a certificate-style pattern such as
`*.lmu.edu`. Clients must still send a concrete one-label name such as
`www.lmu.edu`. For `self-test` to verify the pattern, the configured target
hostname must itself be a matching concrete name.

### 2. Generate configuration and client values

```shell
umask 077
rust-reality config generate standalone \
  --listen 0.0.0.0 \
  --port 443 \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com \
  > config.json 2> client-values.txt
```

The server JSON contains the generated UUID, REALITY private key, short ID, and
policy. `client-values.txt` contains the REALITY public key. Neither file is a
log; protect and transfer it as secret deployment material.

### 3. Configure an Xray client

Insert the server address, port, UUID from `settings.clients[0].id`, public key
from `client-values.txt`, server name, and short ID into an Xray 26.7.28 client:

```json
{
  "protocol": "vless",
  "settings": {
    "vnext": [{
      "address": "SERVER_ADDRESS",
      "port": 443,
      "users": [{
        "id": "SERVER_UUID",
        "encryption": "none",
        "flow": "xtls-rprx-vision"
      }]
    }]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
      "fingerprint": "chrome",
      "serverName": "www.microsoft.com",
      "publicKey": "REALITY_PUBLIC_KEY",
      "shortId": "SERVER_SHORT_ID",
      "spiderX": "/"
    }
  }
}
```

This is an outbound fragment, not a complete Xray configuration.

### 4. Validate and install

```shell
rust-reality check --config config.json
rust-reality self-test --config config.json
sudo install -o root -g rust-reality -m 0640 \
  config.json /etc/rust-reality/config.json
```

`self-test` performs real asset retrieval, routing compilation, and cover probes
without binding listeners.

## Line node and NXR landing node

NXR is an internal, per-flow authenticated raw TCP hop. It is not REALITY, TLS,
or encrypted after authentication.

### 1. Generate one independent PSK

On a trusted host:

```shell
umask 077
rust-reality node-keygen > nxr-key.json
```

Use the `preSharedKey` value only for this line/landing trust relationship.

### 2. Generate the line configuration

```shell
rust-reality config generate line \
  --listen 0.0.0.0 \
  --port 443 \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com \
  --nxr-address LANDING_PRIVATE_ADDRESS \
  --nxr-port 7443 \
  --nxr-key NXR_PSK \
  > line.json 2> line-client-values.txt
```

The generated UUID defaults to outbound tag `landing`; `direct` and `block`
remain available for explicit user rules.

### 3. Generate the landing configuration

```shell
rust-reality config generate landing \
  --listen 0.0.0.0 \
  --port 7443 \
  --nxr-key NXR_PSK \
  > landing.json
```

The landing configuration exposes only NXR and has no public client identity.

### 4. Enforce the NXR firewall boundary

Before starting the landing service, allow TCP 7443 only from the line node's
fixed source IP and reject every other source. Prefer both provider security
groups and host firewall rules. Do not rely on the PSK as permission to expose
NXR publicly.

Keep clocks synchronized. The default NXR request accepts 30 seconds of skew
and retains nonces for 120 seconds. Authentication failure closes before DNS or
destination connect.

## GeoIP and GeoSite

Only HTTPS source URLs are required. Defaults point to community-compatible
files, so most deployments can omit `assets` entirely or override only:

```json
{
  "assets": {
    "geoip": "https://example.invalid/releases/geoip.dat",
    "geosite": "https://example.invalid/releases/geosite.dat"
  }
}
```

Replace the example domain with real trusted sources. Downloads are bounded,
conditionally revalidated, parsed before publication, and retained as a
last-known-good snapshot on failure. `ext:filename:tag` files are read only from
the configured cache directory.

See the [configuration reference](configuration.md#routing) for matcher and DNS
strategy details.

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

The unit runs as the dedicated account, retains only `CAP_NET_BIND_SERVICE`,
protects the host filesystem/kernel surfaces, and allows writes only to the
asset and log directories. Review it against distribution paths and local
hardening policy instead of blindly removing a restriction.

For normal installations use `log.output: "stderr"` or `"journald"`. If file
logging is required, configure `path`, `maxBytes`, `maxFiles`, and
`maxTotalBytes`; all are enforced.

## Reload, restart, and graceful shutdown

Validate first, then request atomic reload:

```shell
rust-reality check --config /etc/rust-reality/config.json
rust-reality self-test --config /etc/rust-reality/config.json
sudo systemctl reload rust-reality
```

A failed candidate leaves the current generation active. Existing connections
retain their previous generation. Listener topology, resource-governor policy,
relay policy, and NXR replay-cache capacity/retention are cold settings; use a
controlled restart for them. The exact list is in
[Reload boundaries](configuration.md#reload-boundaries).

SIGTERM stops new accepts and permits a bounded graceful shutdown. The unit's
40-second stop timeout covers the program's 30-second graceful limit.

## Upgrade and rollback

1. Download and verify all three assets for the new tag.
2. Keep the current binary and configuration as root-only rollback files.
3. Run the new binary's `check` and `self-test` against a copy of production
   configuration.
4. Atomically install the new binary and restart the service.
5. Verify logs, listener, Xray client handshake, routing, and real traffic.

Example binary swap:

```shell
sudo install -m 0755 rust-reality /usr/local/bin/rust-reality.new
sudo mv /usr/local/bin/rust-reality /usr/local/bin/rust-reality.previous
sudo mv /usr/local/bin/rust-reality.new /usr/local/bin/rust-reality
sudo systemctl restart rust-reality
```

Rollback by restoring the previous binary and its compatible configuration,
then restarting. Do not downgrade while retaining configuration fields unknown
to the older version.

## Troubleshooting checklist

- `check`: JSON syntax, unknown field, reference, or limit failure.
- `self-test`: asset URL/cache, DNS, routing label, or cover-target failure.
- Bind failure: another process, missing port capability, wrong address, or
  duplicate listener.
- Xray handshake failure: UUID, flow, SNI, public key, short ID, client clock,
  or changed cover behavior.
- NXR failure: firewall/source IP, PSK mismatch, clock skew, replay capacity, or
  landing reachability.
- Route surprise: first-match order, user assignment, domain strategy, missing
  asset label, or a global rule preceding the user rule.

Do not enable debug logs and publish them without review. Never paste production
configuration, keys, UUIDs, credentials, or packet captures into public issues.

## Optional kernel relay backends

The sockhash kernel backend is **off by default** and is probed rather than
assumed. Leaving it off is a supported production configuration; the portable
buffered relay and Linux `splice` require no additional privilege.

The io_uring backend was removed: its driver never reached the production relay
path, and completing it was not justified over the working splice and sockhash
backends. Configurations that still set `policy.relay.ioUring` or
`policy.relay.maxIoUringRelays` are rejected as unknown fields.

### sockhash

`policy.relay.sockhash: true` enables the bounded eBPF `SOCKHASH` backend. The
startup probe creates the map and loads the stream-verdict program; a refusal is
reported with a fixed reason.

Do **not** assume that `CAP_BPF` plus `CAP_NET_ADMIN` is universally sufficient.
What is actually required depends on the running kernel version, the active
Linux security module, the seccomp policy, the user namespace, and the program
and map types. The only reliable answer is the probe result on the target host.

The shipped systemd unit deliberately does not gain privileges automatically.
To opt in, add a drop-in rather than editing the packaged unit:

```ini
# /etc/systemd/system/rust-reality.service.d/10-sockhash.conf
[Service]
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN
# The eBPF map and program are pinned kernel memory.
LimitMEMLOCK=infinity
# Keep every other hardening directive from the packaged unit.
```

Then verify on the target host that the probe actually reports availability
before relying on it:

```shell
cargo test -p rr-linux --test capability_report -- --nocapture
```

If the probe declines, the server still serves traffic; it simply uses the next
available backend.
