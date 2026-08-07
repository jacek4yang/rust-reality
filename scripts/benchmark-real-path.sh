#!/usr/bin/env bash
# Real-path A/B validation: alternating downloads from a real Internet
# destination through the rust-reality and Xray tunnel servers.
#
# Purpose: performance-gate evidence on a real network path — crash and
# protocol-error detection plus A/B behavior. Throughput is capped by the
# slowest link on the path (on the validation host: a 100 Mb/s NIC), so
# this is NOT a bandwidth-discriminating benchmark.
#
# Requires: xray (XRAY_BIN), curl, jq, python3, and direct Internet egress.
# Optional env: RUNS (20), BYTES (25000000), URL (Cloudflare speed endpoint),
#               RUST_REALITY_BIN, OUT (output JSON file).
set -Eeuo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
xray=${XRAY_BIN:-xray}
rust_bin=${RUST_REALITY_BIN:-target/release/rust-reality}
runs=${RUNS:-20}
bytes=${BYTES:-5000000}
url=${URL:-https://speed.cloudflare.com/__down?bytes=$bytes}
cover_target=${COVER_TARGET:-dl.google.com:443}
cover_sni=${COVER_SNI:-dl.google.com}
out=${OUT:-diagnostics/final/real-path.json}
temporary_root=${TMPDIR:-/tmp}
work=$(mktemp -d "$temporary_root/rust-reality-realpath.XXXXXX")
pids=()

cleanup() {
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    if [[ ${KEEP_WORK:-0} == 1 ]]; then
        printf 'real-path temporary directory retained: %s\n' "$work" >&2
    elif [[ -d "$work" && "$work" == "$temporary_root"/rust-reality-realpath.* ]]; then
        rm -rf -- "$work"
    fi
}
trap cleanup EXIT

for program in "$xray" curl jq python3; do
    if ! command -v "$program" >/dev/null 2>&1; then
        echo "required program is unavailable: $program" >&2
        exit 1
    fi
done
if ! [[ $runs =~ ^[1-9][0-9]*$ && $bytes =~ ^[1-9][0-9]*$ ]]; then
    echo "RUNS and BYTES must be positive integers" >&2
    exit 1
fi

# Direct egress is required: the servers dial the destination themselves.
# The speed endpoint ignores Range requests, so probe with a tiny download.
if ! env -u ALL_PROXY -u all_proxy -u HTTP_PROXY -u http_proxy -u HTTPS_PROXY -u https_proxy -u NO_PROXY -u no_proxy \
        curl --fail --silent --max-time 30 -o /dev/null "https://speed.cloudflare.com/__down?bytes=100000"; then
    echo "direct Internet egress to speed.cloudflare.com is unavailable; real-path gate NOT RUN" >&2
    exit 3
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
    python3 - "$1" <<'PY'
import socket, sys, time
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

rust_port=$(free_port)
xray_port=$(free_port)
rust_socks=$(free_port)
xray_socks=$(free_port)

"$rust_bin" config generate standalone \
    --listen 127.0.0.1 --port "$rust_port" \
    --target "$cover_target" --server-name "$cover_sni" \
    >"$work/rust.raw.json" 2>"$work/generate.log"
rust_public_key=$(sed -n 's/^REALITY public key for the client: //p' "$work/generate.log")
uuid=$(jq -r '.inbounds[0].settings.clients[0].id' "$work/rust.raw.json")
short_id=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$work/rust.raw.json")
"$xray" x25519 >"$work/xray.keys"
xray_private_key=$(sed -n 's/^PrivateKey: //p' "$work/xray.keys")
xray_public_key=$(sed -n 's/^Password (PublicKey): //p' "$work/xray.keys")
jq --arg cache "$work/assets" '.log.level = "warn" | .assets.cacheDirectory = $cache' \
    "$work/rust.raw.json" >"$work/rust.json"

jq -n --arg uuid "$uuid" --arg private_key "$xray_private_key" --arg short_id "$short_id" \
    --arg target "$cover_target" --arg server_name "$cover_sni" --argjson port "$xray_port" \
    '{
      log: {loglevel: "warning"},
      inbounds: [{
        listen: "127.0.0.1", port: $port, protocol: "vless",
        settings: {clients: [{id: $uuid, flow: "xtls-rprx-vision"}], decryption: "none"},
        streamSettings: {network: "tcp", security: "reality", realitySettings: {
          show: false, target: $target, xver: 0, serverNames: [$server_name],
          privateKey: $private_key, shortIds: [$short_id]}}
      }],
      outbounds: [{tag: "direct", protocol: "freedom"}]
    }' >"$work/xray-server.json"

make_client() {
    jq -n --arg uuid "$uuid" --arg public_key "$3" --arg short_id "$short_id" \
        --arg server_name "$cover_sni" --argjson server_port "$1" --argjson socks_port "$2" \
        '{
          log: {loglevel: "warning"},
          inbounds: [{listen: "127.0.0.1", port: $socks_port, protocol: "socks",
                      settings: {auth: "noauth", udp: false}}],
          outbounds: [{
            protocol: "vless",
            settings: {vnext: [{address: "127.0.0.1", port: $server_port,
              users: [{id: $uuid, encryption: "none", flow: "xtls-rprx-vision"}]}]},
            streamSettings: {network: "tcp", security: "reality", realitySettings: {
              fingerprint: "chrome", serverName: $server_name,
              publicKey: $public_key, shortId: $short_id, spiderX: "/"}}
          }]
        }' >"$4"
}
make_client "$rust_port" "$rust_socks" "$rust_public_key" "$work/rust-client.json"
make_client "$xray_port" "$xray_socks" "$xray_public_key" "$work/xray-client.json"

start_process "$rust_bin" serve --config "$work/rust.json" >"$work/rust.log" 2>&1
start_process "$xray" run -config "$work/xray-server.json" >"$work/xray-server.log" 2>&1
wait_port "$rust_port"
wait_port "$xray_port"
start_process "$xray" run -config "$work/rust-client.json" >"$work/rust-client.log" 2>&1
start_process "$xray" run -config "$work/xray-client.json" >"$work/xray-client.log" 2>&1
wait_port "$rust_socks"
wait_port "$xray_socks"

mkdir -p "$(dirname "$out")"
python3 - "$runs" "$bytes" "$url" "$rust_socks" "$xray_socks" "$rust_port" "$out" <<'PY'
import json
import os
import subprocess
import sys
import time

runs = int(sys.argv[1])
expected = int(sys.argv[2])
url = sys.argv[3]
ports = {"rust-reality": int(sys.argv[4]), "xray": int(sys.argv[5])}
rust_server_port = int(sys.argv[6])
out = sys.argv[7]

curl_env = {
    key: value
    for key, value in os.environ.items()
    if key.lower() not in ("all_proxy", "http_proxy", "https_proxy", "no_proxy")
}

results = []
order = ["rust-reality" if index % 2 == 0 else "xray" for index in range(runs)]
for index, name in enumerate(order):
    started = time.perf_counter()
    completed = subprocess.run(
        [
            "curl", "--fail", "--silent", "--show-error",
            "--socks5-hostname", f"127.0.0.1:{ports[name]}",
            "--max-time", "300", "--output", os.devnull,
            "--write-out", "%{size_download} %{time_total} %{http_code} %{speed_download}",
            url,
        ],
        capture_output=True,
        text=True,
        env=curl_env,
    )
    wall = time.perf_counter() - started
    record = {"index": index, "implementation": name, "wallSeconds": wall}
    if completed.returncode != 0:
        record.update(ok=False, error=completed.stderr.strip()[:200])
    else:
        size, total, code, speed = completed.stdout.split()
        record.update(
            ok=int(size) == expected and code == "200",
            bytes=int(size),
            seconds=float(total),
            httpCode=code,
            bytesPerSecond=float(speed),
        )
        record["ok"] = bool(record["ok"])
    results.append(record)

failed = [record for record in results if not record["ok"]]
summary = {"runs": runs, "alternatingOrder": order, "failures": len(failed), "failedRuns": failed}
for name in ports:
    speeds = [
        record["bytesPerSecond"] / 1_048_576
        for record in results
        if record["implementation"] == name and record.get("bytesPerSecond")
    ]
    if speeds:
        speeds.sort()
        summary[name] = {
            "samples": len(speeds),
            "medianMiBPerSecond": speeds[len(speeds) // 2],
            "minMiBPerSecond": speeds[0],
            "maxMiBPerSecond": speeds[-1],
        }
report = {
    "schemaVersion": 1,
    "harness": "benchmark-real-path",
    "url": url.split("?")[0],
    "expectedBytes": expected,
    "rustServerPort": rust_server_port,
    "timestampUnix": int(time.time()),
    "summary": summary,
    "results": results,
}
with open(out, "w", encoding="utf-8") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
print(json.dumps(summary["failures"] and {"failures": summary["failures"]} or summary.get("rust-reality"), sort_keys=True))
print(f"failures={summary['failures']} runs={runs} -> {out}")
sys.exit(1 if failed else 0)
PY
