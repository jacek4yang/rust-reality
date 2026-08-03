# Linux deployment

## Build one release binary

Use the pinned stable toolchain and locked dependency graph:

```shell
./scripts/check.sh
./scripts/build-release.sh
```

The build script embeds the exact Git commit in `benchmark` reports and prints
the SHA-256 of the stripped release binary. Install only
`target/release/rust-reality`; no runtime language or companion process is
required.

## Generate a standalone public node

First verify a proposed REALITY cover endpoint:

```shell
rust-reality probe-dest \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com
```

Then generate the server config. The JSON goes to standard output and the
client-facing REALITY public key goes to standard error, so they can be captured
separately without placing private material in logs:

```shell
rust-reality config generate standalone \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com \
  > config.json 2> client-values.txt
rust-reality check --config config.json
```

The generated public inbound is always VLESS + REALITY + Vision. Add UUIDs and
`routing.users` groups in the JSON, then run `check` again.

## Generate a line node and NXR landing node

Generate one independent NXR PSK on a trusted host:

```shell
rust-reality node-keygen
```

Pass the `preSharedKey` value to both commands:

```shell
rust-reality config generate line \
  --target www.microsoft.com:443 \
  --server-name www.microsoft.com \
  --nxr-address LANDING_PRIVATE_ADDRESS \
  --nxr-port 7443 \
  --nxr-key NXR_PSK \
  > line.json 2> line-client-values.txt

rust-reality config generate landing \
  --listen 0.0.0.0 \
  --port 7443 \
  --nxr-key NXR_PSK \
  > landing.json
```

The line config exposes only the public VLESS + REALITY + Vision listener and
routes its generated UUID to the NXR outbound by default. The landing config
exposes only NXR and has no VLESS, REALITY, Vision, TLS, or public client state.

At the landing firewall, allow TCP port 7443 only from the line node's fixed
source IP and reject every other source before the process. Treat this firewall
rule as part of NXR deployment, not an optional optimization.

## Files and service account

Create a dedicated `rust-reality` user and group. Recommended paths are:

```text
/usr/local/bin/rust-reality
/etc/rust-reality/config.json       root:rust-reality 0640
/var/lib/rust-reality/assets/       rust-reality:rust-reality
/var/log/rust-reality/              rust-reality:rust-reality (file sink only)
```

Install `deploy/rust-reality.service`, review its paths and capability policy,
then enable it with systemd. Sending SIGHUP loads and validates a complete new
configuration and asset generation before atomic publication. Listener
addresses and replay/resource policies are cold settings and require restart.

For normal deployments prefer stderr/journald. If the file sink is selected,
configure `maxBytes`, `maxFiles`, and `maxTotalBytes`; all three are enforced.

## Geo assets

Only HTTPS source URLs are required. Defaults point at the community
`geoip.dat` and `geosite.dat` release. Files are downloaded into the bounded
cache, conditionally revalidated, parsed before publication, and retained as a
last-known-good snapshot when an update fails. `ext:filename:tag` assets are
resolved within the configured cache directory and cannot escape it.

Before enabling the service, run:

```shell
rust-reality self-test --config /etc/rust-reality/config.json
```

This performs real asset retrieval and routing compilation without binding the
listeners.
