#!/usr/bin/env bash
# A/B throughput comparison: rust-reality vs Xray-core with a TLS 1.3 origin,
# so inner traffic is TLS and Vision reaches its Direct (raw) boundary.
#
# This is the reproduction harness for the directional downlink throughput gap:
# Xray promotes the downlink to kernel splice as soon as the downlink reaches
# Direct, while rust-reality historically waited for a bilateral handoff.
#
# Requires: xray (XRAY_BIN), cargo, curl, jq, openssl, python3.
# Optional env: SAMPLES (9), CONCURRENCY (4), PAYLOAD_MIB (64),
#               COVER_TARGET/COVER_SNI (dl.google.com), KEEP_WORK (0),
#               RUST_LOG_LEVEL (debug), RUST_REALITY_BIN (target/release/rust-reality)
set -Eeuo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
xray=${XRAY_BIN:-xray}
rust_bin=${RUST_REALITY_BIN:-target/release/rust-reality}
cover_target=${COVER_TARGET:-dl.google.com:443}
cover_sni=${COVER_SNI:-dl.google.com}
samples=${SAMPLES:-9}
concurrency=${CONCURRENCY:-4}
payload_mib=${PAYLOAD_MIB:-64}
rust_log_level=${RUST_LOG_LEVEL:-debug}
temporary_root=${TMPDIR:-/tmp}
work=$(mktemp -d "$temporary_root/rust-reality-vision-direct.XXXXXX")
pids=()

cleanup() {
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    if [[ ${KEEP_WORK:-0} == 1 ]]; then
        printf 'benchmark temporary directory retained: %s\n' "$work" >&2
    elif [[ -d "$work" && "$work" == "$temporary_root"/rust-reality-vision-direct.* ]]; then
        rm -rf -- "$work"
    fi
}
trap cleanup EXIT

for program in "$xray" cargo curl jq openssl python3; do
    if ! command -v "$program" >/dev/null 2>&1; then
        echo "required program is unavailable: $program" >&2
        exit 1
    fi
done
if ! [[ $samples =~ ^[1-9][0-9]*$ && $concurrency =~ ^[1-9][0-9]*$ && $payload_mib =~ ^[1-9][0-9]*$ ]]; then
    echo "SAMPLES, CONCURRENCY, and PAYLOAD_MIB must be positive integers" >&2
    exit 1
fi
if (( samples > 100 || concurrency > 64 || payload_mib > 1024 )); then
    echo "benchmark bounds are samples<=100, concurrency<=64, payload_mib<=1024" >&2
    exit 1
fi

free_port() {
    python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_port() {
    local port=$1
    python3 - "$port" <<'PY'
import socket
import sys
import time
port = int(sys.argv[1])
deadline = time.monotonic() + 10
while time.monotonic() < deadline:
    with socket.socket() as sock:
        sock.settimeout(0.1)
        if sock.connect_ex(("127.0.0.1", port)) == 0:
            raise SystemExit(0)
    time.sleep(0.02)
raise SystemExit(f"port {port} did not become ready")
PY
}

start_process() {
    "$@" &
    pids+=("$!")
}

cd "$repository"
if [[ ! -x $rust_bin ]]; then
    cargo build --release --locked
fi

rust_port=$(free_port)
xray_port=$(free_port)
rust_socks=$(free_port)
xray_socks=$(free_port)
https_port=$(free_port)

"$rust_bin" config generate standalone \
    --listen 127.0.0.1 \
    --port "$rust_port" \
    --target "$cover_target" \
    --server-name "$cover_sni" \
    >"$work/rust.raw.json" 2>"$work/generate.log"

rust_public_key=$(sed -n 's/^REALITY public key for the client: //p' "$work/generate.log")
uuid=$(jq -r '.inbounds[0].settings.clients[0].id' "$work/rust.raw.json")
short_id=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$work/rust.raw.json")
"$xray" x25519 >"$work/xray.keys"
xray_private_key=$(sed -n 's/^PrivateKey: //p' "$work/xray.keys")
xray_public_key=$(sed -n 's/^Password (PublicKey): //p' "$work/xray.keys")
jq --arg cache "$work/assets" --arg level "$rust_log_level" \
    '.log.level = $level | .assets.cacheDirectory = $cache' \
    "$work/rust.raw.json" >"$work/rust.json"

jq -n \
    --arg uuid "$uuid" \
    --arg private_key "$xray_private_key" \
    --arg short_id "$short_id" \
    --arg target "$cover_target" \
    --arg server_name "$cover_sni" \
    --argjson port "$xray_port" \
    '{
      log: {loglevel: "warning"},
      inbounds: [{
        listen: "127.0.0.1",
        port: $port,
        protocol: "vless",
        settings: {
          clients: [{id: $uuid, flow: "xtls-rprx-vision"}],
          decryption: "none"
        },
        streamSettings: {
          network: "tcp",
          security: "reality",
          realitySettings: {
            show: false,
            target: $target,
            xver: 0,
            serverNames: [$server_name],
            privateKey: $private_key,
            shortIds: [$short_id]
          }
        }
      }],
      outbounds: [{
        tag: "direct",
        protocol: "freedom",
        settings: {finalRules: [{action: "allow"}]}
      }]
    }' >"$work/xray-server.json"

make_client() {
    local server_port=$1
    local socks_port=$2
    local reality_public_key=$3
    local output=$4
    jq -n \
        --arg uuid "$uuid" \
        --arg public_key "$reality_public_key" \
        --arg short_id "$short_id" \
        --arg server_name "$cover_sni" \
        --argjson server_port "$server_port" \
        --argjson socks_port "$socks_port" \
        '{
          log: {loglevel: "warning"},
          inbounds: [{
            listen: "127.0.0.1",
            port: $socks_port,
            protocol: "socks",
            settings: {auth: "noauth", udp: false}
          }],
          outbounds: [{
            protocol: "vless",
            settings: {vnext: [{
              address: "127.0.0.1",
              port: $server_port,
              users: [{id: $uuid, encryption: "none", flow: "xtls-rprx-vision"}]
            }]},
            streamSettings: {
              network: "tcp",
              security: "reality",
              realitySettings: {
                fingerprint: "chrome",
                serverName: $server_name,
                publicKey: $public_key,
                shortId: $short_id,
                spiderX: "/"
              }
            }
          }]
        }' >"$output"
}

make_client "$rust_port" "$rust_socks" "$rust_public_key" "$work/rust-client.json"
make_client "$xray_port" "$xray_socks" "$xray_public_key" "$work/xray-client.json"

start_process "$rust_bin" serve --config "$work/rust.json" \
    >"$work/rust.log" 2>&1
start_process "$xray" run -config "$work/xray-server.json" \
    >"$work/xray-server.log" 2>&1
wait_port "$rust_port"
wait_port "$xray_port"
start_process "$xray" run -config "$work/rust-client.json" \
    >"$work/rust-client.log" 2>&1
start_process "$xray" run -config "$work/xray-client.json" \
    >"$work/xray-client.log" 2>&1
wait_port "$rust_socks"
wait_port "$xray_socks"

python3 - "$work/payload.bin" "$payload_mib" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
remaining = int(sys.argv[2]) * 1024 * 1024
chunk = bytes(range(256)) * 4096
with path.open("wb") as output:
    while remaining:
        part = chunk[:min(len(chunk), remaining)]
        output.write(part)
        remaining -= len(part)
PY

# TLS 1.3 origin: inner traffic is TLS, so Vision can reach Direct.
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$work/origin.key" -out "$work/origin.crt" \
    -days 1 -subj "/CN=localhost" >/dev/null 2>&1

python3 - "$https_port" "$work" >"$work/https.log" 2>&1 <<'PY' &
import functools
import http.server
import ssl
import sys

port = int(sys.argv[1])
directory = sys.argv[2]
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)
server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(f"{directory}/origin.crt", f"{directory}/origin.key")
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
pids+=("$!")
wait_port "$https_port"

python3 - "$samples" "$concurrency" "$payload_mib" "$rust_socks" "$xray_socks" "$https_port" "$xray" "$cover_target" "$cover_sni" "$work/rust.log" <<'PY'
import concurrent.futures
import json
import math
import os
import platform
import random
import statistics
import subprocess
import sys
import time

samples = int(sys.argv[1])
concurrency = int(sys.argv[2])
payload_mib = int(sys.argv[3])
ports = {"rust-reality": int(sys.argv[4]), "xray": int(sys.argv[5])}
https_port = int(sys.argv[6])
xray = sys.argv[7]
cover_target = sys.argv[8]
cover_sni = sys.argv[9]
rust_log = sys.argv[10]
expected = payload_mib * 1024 * 1024
url = f"https://127.0.0.1:{https_port}/payload.bin"

# The workspace proxy environment (ALL_PROXY/HTTP_PROXY/...) sets NO_PROXY with
# 127.0.0.1, which makes curl bypass EVEN an explicit --socks5-hostname for
# loopback URLs — the transfer then measures a direct connection and the server
# never sees a session. Strip every proxy variable from the curl environment.
curl_env = {
    key: value
    for key, value in os.environ.items()
    if key.lower() not in ("all_proxy", "http_proxy", "https_proxy", "no_proxy")
}

def transfer(port):
    completed = subprocess.run(
        [
            "curl", "--fail", "--silent", "--show-error", "--insecure",
            "--tlsv1.3", "--socks5-hostname", f"127.0.0.1:{port}",
            "--max-time", "120", "--output", os.devnull,
            "--write-out", "%{size_download} %{time_total}", url,
        ],
        check=True,
        capture_output=True,
        text=True,
        env=curl_env,
    )
    size, elapsed = completed.stdout.split()
    if int(size) != expected:
        raise RuntimeError(f"payload length mismatch: {size} != {expected}")
    return float(elapsed)

def measure(name):
    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        latencies = list(executor.map(lambda _: transfer(ports[name]), range(concurrency)))
    wall = time.perf_counter() - started
    return {
        "implementation": name,
        "wallSeconds": wall,
        "meanRequestSeconds": statistics.fmean(latencies),
        "throughputMiBPerSecond": payload_mib * concurrency / wall,
    }

for name in ports:
    transfer(ports[name])

order = [name for _ in range(samples) for name in ports]
random.Random(0x4E5852).shuffle(order)
measurements = [measure(name) for name in order]

def percentile(values, fraction):
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * fraction) - 1)
    return ordered[index]

summaries = {}
for name in ports:
    throughput = [item["throughputMiBPerSecond"] for item in measurements if item["implementation"] == name]
    latency = [item["meanRequestSeconds"] for item in measurements if item["implementation"] == name]
    summaries[name] = {
        "samples": len(throughput),
        "throughputMiBPerSecond": {
            "mean": statistics.fmean(throughput),
            "p50": statistics.median(throughput),
            "p95": percentile(throughput, 0.95),
            "minimum": min(throughput),
        },
        "meanRequestSeconds": {
            "mean": statistics.fmean(latency),
            "p50": statistics.median(latency),
            "p95": percentile(latency, 0.95),
            "maximum": max(latency),
        },
    }

# Give the server a moment to flush per-connection completion events.
time.sleep(1.0)
accepted_connections = 0
direct_events = []
try:
    with open(rust_log, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("event") == "connection_accepted":
                accepted_connections += 1
            elif record.get("event") == "connection_completed":
                direct_events.append({
                    key: record.get(key)
                    for key in (
                        "uplink_bytes", "downlink_bytes",
                        "uplink_direct", "downlink_direct",
                        "relay_backend", "uplink_backend", "downlink_backend",
                        "uplink_direct_at_bytes", "downlink_direct_at_bytes",
                        "uplink_handoff_delay_us", "downlink_handoff_delay_us",
                    )
                })
except FileNotFoundError:
    pass

direct_summary = {
    "connections": len(direct_events),
    "acceptedConnections": accepted_connections,
    # The wait_port readiness probe accounts for one accepted connection; more
    # must be tunneled sessions. One or zero means curl bypassed the tunnel
    # (see curl_env above) and the measurements are invalid.
    "tunnelBypassDetected": accepted_connections <= 1,
    "uplinkDirect": sum(1 for event in direct_events if event["uplink_direct"]),
    "downlinkDirect": sum(1 for event in direct_events if event["downlink_direct"]),
    "backends": {},
}
for event in direct_events:
    for direction in ("uplink_backend", "downlink_backend", "relay_backend"):
        backend = event[direction]
        if backend:
            direct_summary["backends"][backend] = (
                direct_summary["backends"].get(backend, 0) + 1
            )

ratio = (
    summaries["rust-reality"]["throughputMiBPerSecond"]["p50"]
    / summaries["xray"]["throughputMiBPerSecond"]["p50"]
)
report = {
    "schemaVersion": 1,
    "harness": "benchmark-vision-direct",
    "environment": {
        "kernel": platform.release(),
        "machine": platform.machine(),
        "cpuCount": os.cpu_count(),
        "cpuModel": next(
            (
                line.split(":", 1)[1].strip()
                for line in open("/proc/cpuinfo", encoding="utf-8")
                if line.startswith("model name")
            ),
            "unknown",
        ),
        "rustRealityCommit": subprocess.run(
            ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True
        ).stdout.strip(),
        "rustVersion": subprocess.run(
            ["rustc", "--version"], check=True, capture_output=True, text=True
        ).stdout.strip(),
        "xrayVersion": subprocess.run(
            [xray, "version"], check=True, capture_output=True, text=True
        ).stdout.splitlines()[0],
    },
    "method": {
        "client": "Xray SOCKS5 -> VLESS + REALITY + xtls-rprx-vision",
        "destination": "loopback TLS 1.3 HTTPS origin (Vision Direct eligible)",
        "realityTarget": cover_target,
        "realityServerName": cover_sni,
        "samplesPerImplementation": samples,
        "concurrency": concurrency,
        "payloadMiBPerRequest": payload_mib,
        "randomSeed": "0x4e5852",
        "randomizedOrder": order,
    },
    "measurements": measurements,
    "rustRealityDirect": direct_summary,
    "summary": summaries,
    "rustRealityToXrayP50ThroughputRatio": ratio,
    "limitations": [
        "single-host loopback includes the same Xray client and Python TLS origin in both paths",
        "Xray's default private-target block is explicitly allowed only for this loopback origin",
        "this does not model Internet RTT, packet loss, bandwidth shaping, or multi-core saturation",
        "results are measurements of this host and are not a universal performance claim",
    ],
}
print(json.dumps(report, indent=2, sort_keys=True))
PY
