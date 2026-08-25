# Linux deployment

English | [简体中文](deployment.zh-CN.md)

This guide deploys an official Linux release (x86_64 or aarch64) as either a
standalone public node, a public line node, or a firewall-restricted NXR
landing node.

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

For machine sizing, resource profiles, and performance diagnosis, see
[Capacity planning, tuning and troubleshooting](tuning.md).

## Install an official release

Download these six assets from the same
[GitHub Release](https://github.com/jacek4yang/rust-reality/releases):

- `rust-reality-vX.Y.Z-linux-x86_64-generic.tar.gz`
- `rust-reality-vX.Y.Z-linux-x86_64-musl.tar.gz`
- `rust-reality-vX.Y.Z-linux-x86_64-v3.tar.gz`
- `rust-reality-vX.Y.Z-linux-aarch64-generic.tar.gz`
- `release-manifest.json`
- `SHA256SUMS`

Verify every file listed in `SHA256SUMS` before extraction:

```shell
sha256sum --check SHA256SUMS
# Generic GNU/glibc x86-64 package:
tar -xzf rust-reality-v<version>-linux-x86_64-generic.tar.gz
# On Alpine/musl or in a minimal container, use the static package:
# tar -xzf rust-reality-v<version>-linux-x86_64-musl.tar.gz
# Or, on an x86-64-v3 GNU/glibc CPU:
# tar -xzf rust-reality-v<version>-linux-x86_64-v3.tar.gz
# On ARM64 (ARMv8.0 with neon or later):
# tar -xzf rust-reality-v<version>-linux-aarch64-generic.tar.gz
sudo install -m 0755 rust-reality /usr/local/bin/rust-reality
rust-reality --version
```

`release-manifest.json` schema v3 records the version, tag, exact source
commit, target triples, source timestamp, compiler, cargo features, and each
tier's archive name, SHA-256, target CPU/features, native-measurement status,
and minimum CPU requirements. Minimums: `linux-x86_64-generic` and
`linux-x86_64-musl` both run on baseline x86-64; the musl asset is fully
static and is the correct choice for Alpine/minimal containers.
`linux-x86_64-v3` requires the x86-64-v3 microarchitecture
level and has no runtime fallback; `linux-aarch64-generic` requires ARMv8.0
with neon. The v3 tier is opt-in with no measured advantage on the validation
host (ring dispatches AES hardware support at runtime in every tier), so pick
it only when you already know the CPU qualifies. Do not combine an archive,
manifest, or checksum from different releases.

To build instead, use the pinned toolchain and locked dependency graph:

```shell
./scripts/check.sh
./scripts/build-release.sh
```

### Post-publication per-tier Xray acceptance

Publishing is not the final interoperability check. From a clean checkout of
the published tag, download and verify the release assets again, extract each
architecture's binaries into separate mode-0700 directories, and run the Xray
gate once per exact downloaded tier on matching hardware:

```shell
install -d -m 0700 release-smoke/generic release-smoke/x86-64-v3
tar -xzf rust-reality-v<version>-linux-x86_64-generic.tar.gz \
  -C release-smoke/generic
tar -xzf rust-reality-v<version>-linux-x86_64-v3.tar.gz \
  -C release-smoke/x86-64-v3

RUST_REALITY_BIN="$PWD/release-smoke/generic/rust-reality" \
  XRAY_BIN=/absolute/path/to/xray \
  ./scripts/test-xray-interop.sh
RUST_REALITY_BIN="$PWD/release-smoke/x86-64-v3/rust-reality" \
  XRAY_BIN=/absolute/path/to/xray \
  ./scripts/test-xray-interop.sh
```

Each invocation uses a fresh configuration and proves an exact 1 MiB transfer,
ML-DSA-65 agreement, and unmodified-Xray REALITY + Vision interoperability.
Run it on an x86-64-v3 host with working external DNS/TCP and a cover target
selected through `COVER_TARGET`/`COVER_SNI` if the defaults are unsuitable. On
an ARM64 host, run the same gate against the `linux-aarch64-generic` binary.
A failure in any tier is a release no-go; do not substitute a locally rebuilt
binary for the downloaded asset.

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

v1.5 accepts TLS 1.3 cover flights with or without compatibility CCS and can
model four positional encrypted handshake records plus an optional fifth
post-Finished record. Probe the exact production target and SNI: a successful
probe of another host is not evidence for this one. Any unsupported,
truncated, oversized, or inconsistent flight fails closed into byte-exact
fallback; there is no operator switch that weakens these checks.

The SNI must be a DNS name served by the target and the target must negotiate a
compatible TLS 1.3 ServerHello. Test from the real VPS:

```shell
rust-reality probe-dest \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com
```

Target availability and behavior are external dependencies. Re-run the probe
after persistent handshake failures or target changes.

By default, each active REALITY listener asynchronously keeps a small bounded
set of TCP-established cover sockets. No TLS bytes are sent until a successfully
authenticated handshake checks one out. This removes the cover TCP handshake
from that authenticated critical path on a warm hit; it does not remove the
subsequent cover TLS response RTT, physical propagation latency, or guarantee a
hit under unbounded instantaneous demand. Rejected traffic always opens and
interacts with the real cover independently. Disable `coverOptimization.warmTcp`
only when an operator has evidence that the cover or network rejects idle
preconnected TCP.

A cover that offers ALPN should negotiate it. Covers without ALPN are
legitimately supported — v1.5 shapes the generated EncryptedExtensions ALPN to
the cover's observed record slot — but prefer covers that present ALPN when
they have one, because the authenticated session then matches the cover's
extension shape exactly.

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

The server JSON contains the generated UUID, REALITY private key, two short IDs
owned by that UUID, and policy. `client-values.txt` contains the REALITY public key. Neither file is a
log; protect and transfer it as secret deployment material.

### 3. Configure an Xray client

Insert the server address, port, UUID from `settings.clients[0].id`, public key
from `client-values.txt`, server name, and one value from
`settings.clients[0].shortIds` into an Xray 26.7.28 client:

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

## Line node and Handoff landing node

Handoff transfers an accepted session's full TLS ownership from the line node
to a landing node in one sealed, replay-protected message. Unlike NXR, the hop
carries only the session's TLS ciphertext after the transfer, and the landing
node holds live session keys for every transferred session.

### 1. Generate the pair in one step

On a trusted host:

```shell
rust-reality config generate handoff \
  --server-address LINE_PUBLIC_ADDRESS \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com \
  --landing-address LANDING_PRIVATE_ADDRESS \
  --output-dir handoff/
```

This writes `line.json` (public line node routing to the handoff outbound),
`landing.json` (internal Handoff listener only), and `xray-client.json`. All
key material is generated independently — the UUID, the REALITY X25519 pair,
two short IDs owned by that UUID, the Handoff pre-shared key, and the landing node's static
X25519 pair — and both server configurations are validated before they are
written. The client UUID and REALITY public key are printed to stderr; the
Handoff PSK and the private keys exist only in the two server files.

One line node can also front several landing nodes: repeat
`--landing-address` (with one shared `--landing-port`, or one per address)
and the generator writes `landing-1.json`, `landing-2.json`, ... plus a
`line.json` that carries one UUID per landing and routes each UUID's own
group to that landing's `landing-N` handoff outbound. Every landing pair
gets independent key material. Route different UUID groups to different
landings to split clients across egress paths; `xray-client.json` uses the
first UUID, and assigning the rest is an operator choice.

### 2. Place and validate the configurations

Install `line.json` on the line node and `landing.json` on the landing node,
validating and installing each as in the standalone
[validate and install](#4-validate-and-install) step. The landing
configuration exposes only the internal Handoff listener and has no public
client identity.

### 3. Enforce the Handoff firewall boundary

Before starting the landing service, allow the Handoff TCP port (default
7443) only from the line nodes' source addresses and reject every other
source. Prefer both provider security groups and host firewall rules. This is
a hard requirement, not a recommendation: the landing node applies no routing
policy to transferred destinations and holds live session keys, so an exposed
listener turns the landing node into an internal dialer for anyone who
reaches it.

Keep clocks synchronized. The default transfer accepts 30 seconds of skew and
reserves nonces for 120 seconds. Every transfer failure closes silently with
zero response bytes, and the line node resets the client socket rather than
serving the session locally.

By default the landing node dials every transferred destination directly. When
the landing itself has no direct route — its destinations are reachable only
through an upstream SOCKS5 proxy or a further NXR hop — set `settings.egress`
on the Handoff inbound to the tag of that `socks5` or `nxr` outbound; a
`blackhole` tag instead discards every transferred session after
authentication. The tag must never reference a `handoff` outbound: landings
cannot be chained.

### 4. Upgrade and rollback order for v1.5

Handoff keeps the `HND1` wire protocol and continuation-state versions at v1.
A v1.5 landing accepts both server record sequence 0 (the existing boundary)
and sequence 1 (one empty cover-shaped application record was emitted before
the transfer). A v1.4 landing accepts only sequence 0, so a v1.5 line paired
with a v1.4 landing is unsupported: sessions whose cover shape consumes the
first server application sequence fail closed.

For a rolling upgrade, upgrade and verify every LANDING first, then upgrade
the LINE nodes. A v1.4 LINE remains compatible with a v1.5 LANDING during this
window. For rollback, downgrade every LINE first so no new sequence-1 transfer
can be created, stop admitting new Handoff sessions and drain the active
sessions on the LANDINGs, then downgrade the LANDINGs. Never restart or
downgrade a LANDING underneath active transferred sessions.

The record-sequence safety boundary and mixed-version rationale are recorded in
[ADR 0005](decisions/0005-handoff-server-record-sequences.md).

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
`maxTotalBytes`; all are enforced. `log.output: "none"` disables logging
entirely — no file is created, nothing is written to stderr, and every event
is dropped before encoding — but it also silences warn-level rejection and
admission signal, so prefer a level filter over `none` unless logging itself
is unacceptable.

On every start, verify `outbound_network_initialized` and one
`listener_topology_active` event per inbound. The former records the cached
IPv4/IPv6 route availability and initial outbound primary. The latter records
the sockets actually bound — it reflects bind results, not family
reachability: a bound IPv6 socket does not prove public IPv6 egress or
ingress works. In `listen.mode: auto`, a missing family
is acceptable only when `listener_family_unavailable` reports a genuine
family/protocol capability error. Address-in-use, permission, and concrete
address errors remain fatal. `dualStack` never degrades.

## Reload, restart, and graceful shutdown

Validate first, then request atomic reload:

```shell
rust-reality check --config /etc/rust-reality/config.json
rust-reality self-test --config /etc/rust-reality/config.json
sudo systemctl reload rust-reality
```

A failed candidate leaves the current generation active. Existing connections
retain their previous generation. Listener topology, `runtime` settings,
resource-governor policy, direct-barrier policy, relay policy, and NXR
replay-cache capacity/retention are cold settings; use a controlled restart
for them. The exact list is in
[Reload boundaries](configuration.md#reload-boundaries).

SIGTERM stops new accepts and permits a bounded graceful shutdown. The unit's
40-second stop timeout covers the program's 30-second graceful limit.

## Upgrade and rollback

Upgrading from 1.4 requires configuration migration: scalar
`"listen": "<ip>"` values and `network.addressFamily` are rejected. The
old-to-new mapping table is in the
[CHANGELOG 1.5.0 migration notes](../CHANGELOG.md); run the new binary's
`check` against a migrated copy before restarting.

1. Download and verify all release assets for the new tag.
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
- Family surprise: compare `outbound_network_initialized` with
  `listener_topology_active`; outbound route selection and inbound topology are
  intentionally independent.
- Xray handshake failure: UUID, flow, SNI, public key, short ID, client clock,
  or changed cover behavior.
- NXR failure: firewall/source IP, PSK mismatch, clock skew, replay capacity, or
  landing reachability.
- Route surprise: first-match order, user assignment, domain strategy, missing
  asset label, or a global rule preceding the user rule.

Do not enable debug logs and publish them without review. Never paste production
configuration, keys, UUIDs, credentials, or packet captures into public issues.

## Removed kernel relay backends

The sockhash backend was removed: it never armed in any production
benchmark matrix, a privileged A/B showed parity with splice, and the
unprivileged production deployment model could never arm it. Stale
`policy.relay.sockhash`, `policy.relay.maxSockhashRelays` or
`policy.relay.maxPinnedMemoryBytes` keys are rejected as unknown fields.

The io_uring backend was removed (see
[`decisions/0002-io-uring-removed.md`](decisions/0002-io-uring-removed.md));
stale `policy.relay.ioUring` or `policy.relay.maxIoUringRelays` keys are
rejected as unknown fields.

The portable buffered relay and Linux `splice` require no additional
privilege.
