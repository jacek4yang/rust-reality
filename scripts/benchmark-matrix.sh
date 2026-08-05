#!/usr/bin/env bash
# benchmark-matrix.sh — three-implementation loopback proxy benchmark matrix.
#
# Compares three VLESS + REALITY + xtls-rprx-vision server implementations:
#   baseline: $RUST_REALITY_BASELINE_BIN (default ../artifacts/rust-reality-baseline-717e69b)
#   final:    $RUST_REALITY_BIN          (default target/release/rust-reality)
#   xray:     $XRAY_BIN                  (default ../artifacts/xray-reference)
# Every server is fronted by an unmodified Xray SOCKS5 client (one per server
# port), identical to scripts/benchmark-xray.sh. rust servers run with debug
# log level so per-direction backend statistics and the tunnel-bypass guard can
# be collected from connection_accepted / connection_completed events.
#
# Scenarios (each forms one set of matrix cells):
#   framed-download  plain-HTTP loopback origin; Vision stays framed
#   direct-download  TLS 1.3 loopback origin; Vision reaches Direct
#   framed-upload    curl --upload-file (PUT + Content-Length) to the plain origin
#   direct-upload    same against the TLS 1.3 origin
#   bidi             CONCURRENCY parallel downloads + CONCURRENCY parallel uploads
#                    through the same tunnel client; aggregate wall time
#   fallback         curl directly to the server listener (no REALITY client);
#                    the cover target is the local HTTP origin, so this measures
#                    the REALITY fallback relay path (rust: automatic fallback on
#                    auth failure; xray: fallbacks = [{dest: http origin}])
#
# Default cell plan (all env-overridable):
#   all scenarios x {1, 32} MiB x {1, 4, 32} concurrency   (SAMPLES=5 per impl)
#   all scenarios x 512 MiB   x {1, 32} concurrency        (SAMPLES_LARGE=3)
# = 6*(2*3) + 6*(1*2) = 48 cells, 36*15 + 12*9 = 648 samples, plus one
# INTEGRITY_MIB=2048 direct-download per implementation with sha256
# verification. On a 4-core i3-8100 the small cells finish in minutes; the
# 512 MiB cells dominate and the full default plan targets ~45 minutes.
# Use CELLS/SKIP to trim.
#
# Origins: by default both listeners (plain HTTP + TLS 1.3) are served by the
# compiled Go origin in scripts/bench-origin (built once into the work dir),
# because the previous embedded-Python TLS origin collapsed under
# concurrency-32 workloads and invalidated cells for all implementations.
# ORIGIN_IMPL=python keeps the embedded Python origin as a fallback; if the
# go toolchain is missing the script warns and falls back to it. The Go
# origin also serves GET /__stats; after every cell the driver snapshots both
# origins' stats and marks the cell's samples invalid with reason
# "origin error" if an origin's error counter grew during the cell.
#
# Work dir: payload files (up to multi-GiB) live in a mktemp directory under
# $TMPDIR when TMPDIR is set, otherwise under the repository's benchmarks/
# directory (disk-backed — a small tmpfs /tmp exhausted mid-run before). The
# directory is removed on exit unless KEEP_WORK=1.
#
# Cell selection: CELLS and SKIP are comma/space separated fnmatch patterns
# matched against "<scenario>:<payloadMiB>:<concurrency>", e.g.
#   CELLS="direct-*:32:*,fallback:*:*" SKIP="*:512:32"
# An empty CELLS means "all planned cells".
#
# Other env: SEED (0x5252), OUT_DIR (benchmarks/final/matrix-<UTC timestamp>),
# COVER_TARGET/COVER_SNI (dl.google.com[:443]), RUST_LOG_LEVEL (debug),
# KEEP_WORK (0), SAMPLES, SAMPLES_LARGE, PAYLOADS, CONCURRENCIES,
# LARGE_PAYLOAD_MIB (512), LARGE_CONCURRENCIES ("1 32"), INTEGRITY_MIB (2048),
# ORIGIN_IMPL (go|python; go falls back to python when go is unavailable),
# RUST_REALITY_BASELINE_COMMIT (override baseline SHA detection).
#
# Output in OUT_DIR: samples.jsonl (one record per individual sample),
# summary.json (per-cell p50/p95/p99 + ratios), environment.json.
#
# CRITICAL: the workspace proxy environment (ALL_PROXY/HTTP_PROXY/... with
# NO_PROXY containing 127.0.0.1) makes curl bypass EVEN an explicit
# --socks5-hostname for loopback URLs. Every curl subprocess runs with all
# *_proxy variables stripped (curl_env in the driver). As a second line of
# defense, per-sample connection_accepted deltas from the rust debug logs must
# cover every curl connection, otherwise the sample is marked invalid loudly.
set -Eeuo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository"

baseline_bin=${RUST_REALITY_BASELINE_BIN:-../artifacts/rust-reality-baseline-717e69b}
rust_bin=${RUST_REALITY_BIN:-target/release/rust-reality}
xray=${XRAY_BIN:-../artifacts/xray-reference}
cover_target=${COVER_TARGET:-dl.google.com:443}
cover_sni=${COVER_SNI:-dl.google.com}
payloads=${PAYLOADS:-1 32 512}
concurrencies=${CONCURRENCIES:-1 4 32}
samples=${SAMPLES:-5}
samples_large=${SAMPLES_LARGE:-3}
large_payload_mib=${LARGE_PAYLOAD_MIB:-512}
large_concurrencies=${LARGE_CONCURRENCIES:-1 32}
integrity_mib=${INTEGRITY_MIB:-2048}
seed=${SEED:-0x5252}
cells_filter=${CELLS:-}
skip_filter=${SKIP:-}
rust_log_level=${RUST_LOG_LEVEL:-debug}
out_dir=${OUT_DIR:-benchmarks/final/matrix-$(date -u +%Y%m%dT%H%M%SZ)}
# Disk-backed default: /tmp may be a small tmpfs that cannot hold multi-GiB
# payload files. TMPDIR is still honored when set.
temporary_root=${TMPDIR:-$repository/benchmarks}
mkdir -p "$temporary_root"
work=$(mktemp -d "$temporary_root/rust-reality-matrix.XXXXXX")
pids=()

cleanup() {
    for pid in "${pids[@]:-}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    if [[ ${KEEP_WORK:-0} == 1 ]]; then
        printf 'benchmark temporary directory retained: %s\n' "$work" >&2
    elif [[ -d "$work" && "$work" == "$temporary_root"/rust-reality-matrix.* ]]; then
        rm -rf -- "$work"
    fi
}
trap cleanup EXIT

for program in curl jq openssl python3; do
    if ! command -v "$program" >/dev/null 2>&1; then
        echo "required program is unavailable: $program" >&2
        exit 1
    fi
done
for binary in "$baseline_bin" "$xray"; do
    if [[ ! -x $binary ]]; then
        echo "required benchmark binary is unavailable: $binary" >&2
        exit 1
    fi
done
if [[ ! -x $rust_bin ]]; then
    cargo build --release --locked
fi
origin_impl=${ORIGIN_IMPL:-go}
case $origin_impl in
    go)
        if command -v go >/dev/null 2>&1; then
            (cd scripts/bench-origin && go build -o "$work/bench-origin" .)
        else
            echo "warning: go toolchain unavailable; falling back to the embedded Python origin" >&2
            origin_impl=python
        fi
        ;;
    python) ;;
    *)
        echo "ORIGIN_IMPL must be 'go' or 'python', got: $origin_impl" >&2
        exit 1
        ;;
esac
if ! [[ $samples =~ ^[1-9][0-9]*$ && $samples_large =~ ^[1-9][0-9]*$ \
    && $large_payload_mib =~ ^[1-9][0-9]*$ && $integrity_mib =~ ^[0-9]+$ ]]; then
    echo "SAMPLES, SAMPLES_LARGE, LARGE_PAYLOAD_MIB, INTEGRITY_MIB must be integers (only INTEGRITY_MIB may be 0)" >&2
    exit 1
fi
for word in $payloads $concurrencies $large_concurrencies; do
    if ! [[ $word =~ ^[1-9][0-9]*$ ]]; then
        echo "PAYLOADS, CONCURRENCIES, LARGE_CONCURRENCIES must be positive integers: $word" >&2
        exit 1
    fi
done

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

# --------------------------------------------------------------------------
# Server configurations: three tunnel servers + three fallback servers.
# --------------------------------------------------------------------------

# make_rust_config <binary> <server_port> <target> <server_name> <prefix>
# Writes <prefix>.json (debug log, work-local asset cache) and
# <prefix>.client.env with PUBLIC_KEY/UUID/SHORT_ID for the client config.
make_rust_config() {
    local binary=$1 port=$2 target=$3 server_name=$4 prefix=$5
    "$binary" config generate standalone \
        --listen 127.0.0.1 \
        --port "$port" \
        --target "$target" \
        --server-name "$server_name" \
        >"$prefix.raw.json" 2>"$prefix.generate.log"
    jq --arg cache "$work/assets-$(basename "$prefix")" --arg level "$rust_log_level" \
        '.log.level = $level | .assets.cacheDirectory = $cache' \
        "$prefix.raw.json" >"$prefix.json"
    {
        sed -n 's/^REALITY public key for the client: /PUBLIC_KEY=/p' "$prefix.generate.log"
        jq -r '"UUID=" + .inbounds[0].settings.clients[0].id' "$prefix.raw.json"
        jq -r '"SHORT_ID=" + .inbounds[0].streamSettings.realitySettings.shortIds[0]' "$prefix.raw.json"
    } >"$prefix.client.env"
}

# make_xray_server_config <port> <target> <server_name> <fallbacks_json> <output>
make_xray_server_config() {
    local port=$1 target=$2 server_name=$3 fallbacks=$4 output=$5
    jq -n \
        --arg uuid "$xray_uuid" \
        --arg private_key "$xray_private_key" \
        --arg short_id "$xray_short_id" \
        --arg target "$target" \
        --arg server_name "$server_name" \
        --argjson port "$port" \
        --argjson fallbacks "$fallbacks" \
        '{
          log: {loglevel: "warning"},
          inbounds: [{
            listen: "127.0.0.1",
            port: $port,
            protocol: "vless",
            settings: ({
              clients: [{id: $uuid, flow: "xtls-rprx-vision"}],
              decryption: "none"
            } + (if $fallbacks == [] then {} else {fallbacks: $fallbacks} end)),
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
        }' >"$output"
}

# make_client <server_port> <socks_port> <public_key> <uuid> <short_id> <output>
make_client() {
    local server_port=$1 socks_port=$2 reality_public_key=$3 uuid=$4 short_id=$5 output=$6
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

baseline_port=$(free_port)
final_port=$(free_port)
xray_port=$(free_port)
baseline_fallback_port=$(free_port)
final_fallback_port=$(free_port)
xray_fallback_port=$(free_port)
baseline_socks=$(free_port)
final_socks=$(free_port)
xray_socks=$(free_port)
http_port=$(free_port)
https_port=$(free_port)

# Xray identity (fixed loopback-only values; each rust server has its own).
"$xray" x25519 >"$work/xray.keys"
xray_private_key=$(sed -n 's/^PrivateKey: //p' "$work/xray.keys")
xray_public_key=$(sed -n 's/^Password (PublicKey): //p' "$work/xray.keys")
xray_uuid="11111111-1111-1111-1111-111111111111"
xray_short_id="0123456789abcdef"

# Tunnel servers: REALITY cover = the public target, exactly like production.
make_rust_config "$baseline_bin" "$baseline_port" "$cover_target" "$cover_sni" "$work/baseline"
make_rust_config "$rust_bin" "$final_port" "$cover_target" "$cover_sni" "$work/final"
make_xray_server_config "$xray_port" "$cover_target" "$cover_sni" "[]" "$work/xray-server.json"

# Fallback servers: cover target = the local plain-HTTP origin, so a direct
# (non-REALITY) curl is relayed to it. Xray additionally gets an explicit
# VLESS fallbacks entry (see proxy/vless/inbound fallback parsing).
make_rust_config "$baseline_bin" "$baseline_fallback_port" "127.0.0.1:$http_port" "localhost" "$work/baseline-fallback"
make_rust_config "$rust_bin" "$final_fallback_port" "127.0.0.1:$http_port" "localhost" "$work/final-fallback"
make_xray_server_config "$xray_fallback_port" "127.0.0.1:$http_port" "localhost" \
    "[{\"dest\": \"127.0.0.1:$http_port\"}]" "$work/xray-fallback-server.json"

# One unmodified Xray SOCKS5 client per tunnel server.
# shellcheck disable=SC1090
source "$work/baseline.client.env"
make_client "$baseline_port" "$baseline_socks" "$PUBLIC_KEY" "$UUID" "$SHORT_ID" "$work/baseline-client.json"
# shellcheck disable=SC1090
source "$work/final.client.env"
make_client "$final_port" "$final_socks" "$PUBLIC_KEY" "$UUID" "$SHORT_ID" "$work/final-client.json"
make_client "$xray_port" "$xray_socks" "$xray_public_key" "$xray_uuid" "$xray_short_id" "$work/xray-client.json"

start_process "$baseline_bin" serve --config "$work/baseline.json" \
    >"$work/baseline.log" 2>&1
start_process "$rust_bin" serve --config "$work/final.json" \
    >"$work/final.log" 2>&1
start_process "$xray" run -config "$work/xray-server.json" \
    >"$work/xray-server.log" 2>&1
start_process "$baseline_bin" serve --config "$work/baseline-fallback.json" \
    >"$work/baseline-fallback.log" 2>&1
start_process "$rust_bin" serve --config "$work/final-fallback.json" \
    >"$work/final-fallback.log" 2>&1
start_process "$xray" run -config "$work/xray-fallback-server.json" \
    >"$work/xray-fallback-server.log" 2>&1
wait_port "$baseline_port"
wait_port "$final_port"
wait_port "$xray_port"
wait_port "$baseline_fallback_port"
wait_port "$final_fallback_port"
wait_port "$xray_fallback_port"
start_process "$xray" run -config "$work/baseline-client.json" \
    >"$work/baseline-client.log" 2>&1
start_process "$xray" run -config "$work/final-client.json" \
    >"$work/final-client.log" 2>&1
start_process "$xray" run -config "$work/xray-client.json" \
    >"$work/xray-client.log" 2>&1
wait_port "$baseline_socks"
wait_port "$final_socks"
wait_port "$xray_socks"

# --------------------------------------------------------------------------
# Payload files (deterministic bytes 0..255 repeated, one per size) + origins.
# --------------------------------------------------------------------------

mapfile -t payload_sizes < <(
    {
        tr ' ' '\n' <<<"$payloads"
        if (( integrity_mib > 0 )); then
            printf '%s\n' "$integrity_mib"
        fi
    } | sort -n | uniq
)
for mib in "${payload_sizes[@]}"; do
    file="$work/payload-$mib.bin"
    if [[ -f $file ]]; then
        continue
    fi
    python3 - "$file" "$mib" <<'PY'
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
done

if [[ $origin_impl == python ]]; then
cat >"$work/origin.py" <<'PY'
import argparse
import json
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

parser = argparse.ArgumentParser()
parser.add_argument("--port", type=int, required=True)
parser.add_argument("--payload-dir", required=True)
parser.add_argument("--put-log", required=True)
parser.add_argument("--tls-cert")
parser.add_argument("--tls-key")
args = parser.parse_args()

lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *arguments):
        pass

    def do_GET(self):
        name = os.path.basename(self.path.split("?", 1)[0])
        path = os.path.join(args.payload_dir, name)
        if not name or not os.path.isfile(path):
            self.send_error(404)
            return
        size = os.path.getsize(path)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.end_headers()
        with open(path, "rb") as source:
            while True:
                chunk = source.read(262144)
                if not chunk:
                    break
                self.wfile.write(chunk)

    def do_PUT(self):
        try:
            length = int(self.headers.get("Content-Length") or -1)
        except ValueError:
            length = -1
        if length < 0:
            self.send_error(411)
            return
        remaining = length
        while remaining:
            chunk = self.rfile.read(min(262144, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
        received = length - remaining
        with lock:
            with open(args.put_log, "a", encoding="utf-8") as log:
                log.write(json.dumps({"path": self.path, "bytes": received}) + "\n")
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
server.daemon_threads = True
if args.tls_cert:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(args.tls_cert, args.tls_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
fi

# TLS 1.3 origin certificate: inner traffic is TLS, so Vision can reach Direct.
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$work/origin.key" -out "$work/origin.crt" \
    -days 1 -subj "/CN=localhost" >/dev/null 2>&1

: >"$work/http-put.jsonl"
: >"$work/https-put.jsonl"
origin_stats_http=""
origin_stats_https=""
if [[ $origin_impl == go ]]; then
    start_process "$work/bench-origin" --port "$http_port" \
        --payload-dir "$work" --put-log "$work/http-put.jsonl" \
        >"$work/http-origin.log" 2>&1
    start_process "$work/bench-origin" --port "$https_port" \
        --payload-dir "$work" --put-log "$work/https-put.jsonl" \
        --tls-cert "$work/origin.crt" --tls-key "$work/origin.key" \
        >"$work/https-origin.log" 2>&1
    origin_stats_http="http://127.0.0.1:$http_port/__stats"
    origin_stats_https="https://127.0.0.1:$https_port/__stats"
else
    start_process python3 "$work/origin.py" --port "$http_port" \
        --payload-dir "$work" --put-log "$work/http-put.jsonl" \
        >"$work/http-origin.log" 2>&1
    start_process python3 "$work/origin.py" --port "$https_port" \
        --payload-dir "$work" --put-log "$work/https-put.jsonl" \
        --tls-cert "$work/origin.crt" --tls-key "$work/origin.key" \
        >"$work/https-origin.log" 2>&1
fi
wait_port "$http_port"
wait_port "$https_port"

# --------------------------------------------------------------------------
# Environment metadata + driver configuration.
# --------------------------------------------------------------------------

commit=$(git rev-parse HEAD)
baseline_commit=${RUST_REALITY_BASELINE_COMMIT:-}
if [[ -z $baseline_commit ]]; then
    baseline_commit=$(basename "$baseline_bin" | sed -n 's/.*[^0-9a-f]\([0-9a-f]\{7,40\}\)$/\1/p')
    baseline_commit=${baseline_commit:-unknown}
fi
nic_interface="unknown"
nic_speed="unknown"
if command -v ip >/dev/null 2>&1; then
    nic_interface=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
    nic_interface=${nic_interface:-unknown}
fi
if command -v ethtool >/dev/null 2>&1 && [[ $nic_interface != unknown ]]; then
    nic_speed=$(ethtool "$nic_interface" 2>/dev/null | sed -n 's/^[[:space:]]*Speed:[[:space:]]*//p')
    nic_speed=${nic_speed:-unknown}
fi
mkdir -p "$out_dir"

jq -n \
    --arg work "$work" \
    --arg out_dir "$out_dir" \
    --arg seed "$seed" \
    --arg payloads "$payloads" \
    --arg concurrencies "$concurrencies" \
    --arg large_concurrencies "$large_concurrencies" \
    --argjson samples "$samples" \
    --argjson samples_large "$samples_large" \
    --argjson large_payload_mib "$large_payload_mib" \
    --argjson integrity_mib "$integrity_mib" \
    --arg cells "$cells_filter" \
    --arg skip "$skip_filter" \
    --arg commit "$commit" \
    --arg baseline_commit "$baseline_commit" \
    --arg baseline_bin "$baseline_bin" \
    --arg rust_bin "$rust_bin" \
    --arg xray "$xray" \
    --arg cover_target "$cover_target" \
    --arg cover_sni "$cover_sni" \
    --arg nic_interface "$nic_interface" \
    --arg nic_speed "$nic_speed" \
    --argjson baseline_port "$baseline_port" \
    --argjson final_port "$final_port" \
    --argjson xray_port "$xray_port" \
    --argjson baseline_fallback_port "$baseline_fallback_port" \
    --argjson final_fallback_port "$final_fallback_port" \
    --argjson xray_fallback_port "$xray_fallback_port" \
    --argjson baseline_socks "$baseline_socks" \
    --argjson final_socks "$final_socks" \
    --argjson xray_socks "$xray_socks" \
    --argjson http_port "$http_port" \
    --argjson https_port "$https_port" \
    --arg origin_impl "$origin_impl" \
    --arg origin_stats_http "$origin_stats_http" \
    --arg origin_stats_https "$origin_stats_https" \
    '{
      work: $work,
      out_dir: $out_dir,
      seed: $seed,
      payloads: $payloads,
      concurrencies: $concurrencies,
      large_concurrencies: $large_concurrencies,
      samples: $samples,
      samples_large: $samples_large,
      large_payload_mib: $large_payload_mib,
      integrity_mib: $integrity_mib,
      cells: $cells,
      skip: $skip,
      commit: $commit,
      baseline_commit: $baseline_commit,
      baseline_bin: $baseline_bin,
      rust_bin: $rust_bin,
      xray: $xray,
      cover_target: $cover_target,
      cover_sni: $cover_sni,
      nic_interface: $nic_interface,
      nic_speed: $nic_speed,
      baseline_port: $baseline_port,
      final_port: $final_port,
      xray_port: $xray_port,
      baseline_fallback_port: $baseline_fallback_port,
      final_fallback_port: $final_fallback_port,
      xray_fallback_port: $xray_fallback_port,
      baseline_socks: $baseline_socks,
      final_socks: $final_socks,
      xray_socks: $xray_socks,
      http_port: $http_port,
      https_port: $https_port,
      origin_impl: $origin_impl,
      origin_stats_http: $origin_stats_http,
      origin_stats_https: $origin_stats_https
    }' >"$work/driver-config.json"

cat >"$work/driver.py" <<'PY'
"""Matrix driver: runs every cell, writes samples.jsonl / summary.json /
environment.json. Configuration comes from driver-config.json (argv[1]).
"""
import concurrent.futures
import fnmatch
import hashlib
import json
import math
import os
import platform
import random
import resource
import ssl
import statistics
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone

with open(sys.argv[1], encoding="utf-8") as handle:
    cfg = json.load(handle)

work = cfg["work"]
out_dir = cfg["out_dir"]
seed_text = cfg["seed"]
seed = int(seed_text, 0)
commit = cfg["commit"]
payloads_mib = sorted({int(word) for word in cfg["payloads"].split()})
concurrencies = sorted({int(word) for word in cfg["concurrencies"].split()})
large_concurrencies = sorted({int(word) for word in cfg["large_concurrencies"].split()})
samples_small = cfg["samples"]
samples_large = cfg["samples_large"]
large_payload_mib = cfg["large_payload_mib"]
integrity_mib = cfg["integrity_mib"]
cells_filter = [p for p in cfg["cells"].replace(",", " ").split() if p]
skip_filter = [p for p in cfg["skip"].replace(",", " ").split() if p]

SCENARIOS = [
    "framed-download",
    "direct-download",
    "framed-upload",
    "direct-upload",
    "bidi",
    "fallback",
]
DIRECTIONS = {
    "framed-download": "download",
    "direct-download": "download",
    "framed-upload": "upload",
    "direct-upload": "upload",
    "bidi": "bidi",
    "fallback": "download",
    "integrity": "download",
}

IMPLEMENTATIONS = {
    "baseline": {
        "kind": "rust",
        "socks": cfg["baseline_socks"],
        "fallback": cfg["baseline_fallback_port"],
        "log": os.path.join(work, "baseline.log"),
        "fallbackLog": os.path.join(work, "baseline-fallback.log"),
    },
    "final": {
        "kind": "rust",
        "socks": cfg["final_socks"],
        "fallback": cfg["final_fallback_port"],
        "log": os.path.join(work, "final.log"),
        "fallbackLog": os.path.join(work, "final-fallback.log"),
    },
    "xray": {
        "kind": "xray",
        "socks": cfg["xray_socks"],
        "fallback": cfg["xray_fallback_port"],
    },
}
IMPL_ORDER = ["baseline", "final", "xray"]

HTTP_PORT = cfg["http_port"]
HTTPS_PORT = cfg["https_port"]
PUT_LOGS = {"http": os.path.join(work, "http-put.jsonl"),
            "https": os.path.join(work, "https-put.jsonl")}

# Origin saturation detection: the compiled Go origin serves GET /__stats;
# the Python fallback origin does not, in which case these URLs are empty and
# the checks below become no-ops.
ORIGIN_STATS_URLS = {
    scheme: url or None
    for scheme, url in (
        ("http", cfg.get("origin_stats_http", "")),
        ("https", cfg.get("origin_stats_https", "")),
    )
}
# Which origin each scenario actually exercises (fallback curls are relayed to
# the plain-HTTP origin by the fallback servers).
ORIGIN_SCHEMES = {
    "framed-download": ["http"],
    "direct-download": ["https"],
    "framed-upload": ["http"],
    "direct-upload": ["https"],
    "bidi": ["https"],
    "fallback": ["http"],
}

_stats_tls = ssl.create_default_context()
_stats_tls.check_hostname = False
_stats_tls.verify_mode = ssl.CERT_NONE
# Never route stats queries through the workspace proxy environment.
_stats_opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=_stats_tls),
)


def fetch_origin_stats(url):
    """Returns the origin's /__stats JSON, or None when unavailable."""
    if not url:
        return None
    try:
        with _stats_opener.open(url, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception:
        return None


def snapshot_origin_stats():
    return {scheme: fetch_origin_stats(url)
            for scheme, url in ORIGIN_STATS_URLS.items()}

MIB = 1024 * 1024

# The workspace proxy environment (ALL_PROXY/HTTP_PROXY/...) sets NO_PROXY with
# 127.0.0.1, which makes curl bypass EVEN an explicit --socks5-hostname for
# loopback URLs — the transfer then measures a direct connection and neither
# proxy server sees a session. Strip every proxy variable from curl's
# environment.
curl_env = {
    key: value
    for key, value in os.environ.items()
    if not key.lower().endswith("_proxy")
}

samples_path = os.path.join(out_dir, "samples.jsonl")
samples_file = open(samples_path, "a", encoding="utf-8")


class LineTracker:
    """Incrementally reads an appended line-oriented file, tolerating a
    partially written final line by holding it back for the next read."""

    def __init__(self, path):
        self.path = path
        self.offset = 0

    def new_lines(self):
        try:
            with open(self.path, "rb") as handle:
                handle.seek(self.offset)
                data = handle.read()
        except FileNotFoundError:
            return []
        if not data:
            return []
        if data.endswith(b"\n"):
            complete = data
        else:
            complete, _, _ = data.rpartition(b"\n")
        self.offset += len(complete)
        return [line for line in complete.decode("utf-8", "replace").splitlines() if line]


class RustLogTracker(LineTracker):
    def events(self):
        parsed = []
        for line in self.new_lines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                parsed.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return parsed


log_trackers = {}
for name, impl in IMPLEMENTATIONS.items():
    if impl["kind"] == "rust":
        log_trackers[name] = {
            "tunnel": RustLogTracker(impl["log"]),
            "fallback": RustLogTracker(impl["fallbackLog"]),
        }
put_trackers = {scheme: LineTracker(path) for scheme, path in PUT_LOGS.items()}


def payload_path(mib):
    return os.path.join(work, f"payload-{mib}.bin")


def payload_bytes(mib):
    return mib * MIB


def max_time_for(mib):
    return max(180, mib // 8 + 120)


def run_curl(extra_args, mib):
    completed = subprocess.run(
        [
            "curl", "--fail", "--silent", "--show-error",
            "--max-time", str(max_time_for(mib)),
        ] + extra_args,
        capture_output=True,
        text=True,
        env=curl_env,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"curl rc={completed.returncode}: {completed.stderr.strip()[:300]}"
        )
    return completed.stdout


def curl_download(socks_port, mib, scheme):
    url = f"{scheme}://127.0.0.1:{HTTP_PORT if scheme == 'http' else HTTPS_PORT}/payload-{mib}.bin"
    args = []
    if scheme == "https":
        args += ["--insecure", "--tlsv1.3"]
    args += [
        "--socks5-hostname", f"127.0.0.1:{socks_port}",
        "--output", os.devnull,
        "--write-out", "%{size_download} %{time_total}",
        url,
    ]
    size, elapsed = run_curl(args, mib).split()
    return int(size), float(elapsed)


def curl_upload(socks_port, mib, scheme):
    url = f"{scheme}://127.0.0.1:{HTTP_PORT if scheme == 'http' else HTTPS_PORT}/upload/{mib}"
    args = []
    if scheme == "https":
        args += ["--insecure", "--tlsv1.3"]
    args += [
        "--socks5-hostname", f"127.0.0.1:{socks_port}",
        "--upload-file", payload_path(mib),
        "--output", os.devnull,
        "--write-out", "%{size_upload} %{time_total}",
        url,
    ]
    size, elapsed = run_curl(args, mib).split()
    return int(size), float(elapsed)


def curl_fallback_download(fallback_port, mib):
    url = f"http://127.0.0.1:{fallback_port}/payload-{mib}.bin"
    size, elapsed = run_curl(
        [
            "--output", os.devnull,
            "--write-out", "%{size_download} %{time_total}",
            url,
        ],
        mib,
    ).split()
    return int(size), float(elapsed)


def run_parallel(tasks):
    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        results = list(executor.map(lambda task: task(), tasks))
    return time.perf_counter() - started, results


def backend_stats(events):
    accepted = sum(1 for event in events if event.get("event") == "connection_accepted")
    completed = [e for e in events if e.get("event") == "connection_completed"]
    backends = {}
    for event in completed:
        for field in ("uplink_backend", "downlink_backend", "relay_backend"):
            value = event.get(field)
            if value:
                backends[value] = backends.get(value, 0) + 1
    return {
        "acceptedConnections": accepted,
        "connectionsCompleted": len(completed),
        "uplinkDirect": sum(1 for e in completed if e.get("uplink_direct")),
        "downlinkDirect": sum(1 for e in completed if e.get("downlink_direct")),
        "backends": backends,
    }


def run_workload(impl_name, scenario, mib, concurrency):
    """Returns (wall_seconds, per_request_seconds, request_count, put_schemes)."""
    impl = IMPLEMENTATIONS[impl_name]
    expected = payload_bytes(mib)
    put_schemes = []
    if scenario == "framed-download":
        wall, results = run_parallel(
            [lambda: curl_download(impl["socks"], mib, "http") for _ in range(concurrency)]
        )
    elif scenario == "direct-download":
        wall, results = run_parallel(
            [lambda: curl_download(impl["socks"], mib, "https") for _ in range(concurrency)]
        )
    elif scenario == "framed-upload":
        put_schemes = ["http"]
        wall, results = run_parallel(
            [lambda: curl_upload(impl["socks"], mib, "http") for _ in range(concurrency)]
        )
    elif scenario == "direct-upload":
        put_schemes = ["https"]
        wall, results = run_parallel(
            [lambda: curl_upload(impl["socks"], mib, "https") for _ in range(concurrency)]
        )
    elif scenario == "bidi":
        put_schemes = ["https"]
        tasks = [lambda: curl_download(impl["socks"], mib, "https") for _ in range(concurrency)]
        tasks += [lambda: curl_upload(impl["socks"], mib, "https") for _ in range(concurrency)]
        wall, results = run_parallel(tasks)
    elif scenario == "fallback":
        wall, results = run_parallel(
            [lambda: curl_fallback_download(impl["fallback"], mib) for _ in range(concurrency)]
        )
    else:
        raise ValueError(f"unknown scenario {scenario}")
    per_request = [elapsed for _, elapsed in results]
    mismatches = [size for size, _ in results if size != expected]
    if mismatches:
        raise RuntimeError(
            f"payload length mismatch: {len(mismatches)}/{len(results)} requests "
            f"returned {mismatches[0]} != {expected} bytes"
        )
    return wall, per_request, len(results), put_schemes


def verify_uploads(put_schemes, mib, expected_puts):
    """Checks the origin-side per-request byte logs for upload scenarios."""
    expected = payload_bytes(mib)
    problems = []
    for scheme in put_schemes:
        entries = []
        for line in put_trackers[scheme].new_lines():
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        if len(entries) != expected_puts:
            problems.append(
                f"{scheme} origin logged {len(entries)} PUTs, expected {expected_puts}"
            )
        for entry in entries:
            if entry.get("bytes") != expected:
                problems.append(
                    f"{scheme} origin received {entry.get('bytes')} != {expected} bytes"
                )
    return problems


def rust_events_for(impl_name, scenario):
    if IMPLEMENTATIONS[impl_name]["kind"] != "rust":
        return None
    which = "fallback" if scenario == "fallback" else "tunnel"
    return log_trackers[impl_name][which].events()


failures = []
total_samples = 0
invalid_samples = 0


def record_sample(impl_name, scenario, mib, concurrency, sample_index):
    global total_samples, invalid_samples
    expected_connections = concurrency * (2 if scenario == "bidi" else 1)
    record = {
        "schemaVersion": 1,
        "commit": commit,
        "implementation": impl_name,
        "scenario": scenario,
        "direction": DIRECTIONS[scenario],
        "payloadBytes": payload_bytes(mib),
        "concurrency": concurrency,
        "sampleIndex": sample_index,
        "wallSeconds": None,
        "throughputMiBPerSecond": None,
        "perRequestSeconds": [],
        "bytesVerified": False,
        "sha256": None,
        "backendStats": None,
        "originStats": None,
        "invalid": False,
        "invalidReason": None,
    }
    problems = []
    try:
        wall, per_request, requests, put_schemes = run_workload(
            impl_name, scenario, mib, concurrency
        )
        record["wallSeconds"] = wall
        record["perRequestSeconds"] = per_request
        record["throughputMiBPerSecond"] = (
            payload_bytes(mib) * requests / wall / MIB
        )
        record["bytesVerified"] = True
    except Exception as error:  # keep the matrix running on single failures
        problems.append(str(error))
        requests = expected_connections
        put_schemes = []
    # Give the servers a moment to flush per-connection events, then check the
    # bypass guard and per-direction backend stats from the rust debug log.
    time.sleep(0.25)
    events = rust_events_for(impl_name, scenario)
    if events is not None:
        stats = backend_stats(events)
        record["backendStats"] = stats
        accepted = stats["acceptedConnections"]
        if accepted < expected_connections:
            problems.append(
                "TUNNEL BYPASS SUSPECTED: only "
                f"{accepted} connection_accepted events for {expected_connections} "
                "curl connections (proxy environment may have leaked into curl)"
            )
    if record["bytesVerified"] and put_schemes:
        # Every upload scenario issues exactly `concurrency` PUT requests
        # (bidi adds `concurrency` downloads on top, which are not PUTs).
        upload_problems = verify_uploads(put_schemes, mib, concurrency)
        if upload_problems:
            record["bytesVerified"] = False
            problems.extend(upload_problems)
    if problems:
        record["invalid"] = True
        record["invalidReason"] = "; ".join(problems)
    return record


def finalize_record(record, key):
    """Counts and persists a sample once all cell-level checks have run."""
    global total_samples, invalid_samples
    if record["invalid"]:
        invalid_samples += 1
        failures.append({
            "cell": key,
            "implementation": record["implementation"],
            "sampleIndex": record["sampleIndex"],
            "reason": record["invalidReason"],
        })
        print(
            f"INVALID SAMPLE {key} "
            f"{record['implementation']}#{record['sampleIndex']}: "
            f"{record['invalidReason']}",
            file=sys.stderr,
            flush=True,
        )
    total_samples += 1
    samples_file.write(json.dumps(record, sort_keys=True) + "\n")
    samples_file.flush()


def cell_key(scenario, mib, concurrency):
    return f"{scenario}:{mib}:{concurrency}"


def planned_cells():
    cells = []
    for scenario in SCENARIOS:
        for mib in payloads_mib:
            if mib >= large_payload_mib:
                cell_concurrencies = large_concurrencies
            else:
                cell_concurrencies = concurrencies
            for concurrency in cell_concurrencies:
                cells.append((scenario, mib, concurrency))
    if cells_filter:
        cells = [c for c in cells
                 if any(fnmatch.fnmatchcase(cell_key(*c), p) for p in cells_filter)]
    if skip_filter:
        cells = [c for c in cells
                 if not any(fnmatch.fnmatchcase(cell_key(*c), p) for p in skip_filter)]
    return cells


def samples_for(mib):
    return samples_large if mib >= large_payload_mib else samples_small


# Warm up every implementation and path once (results discarded, not recorded),
# so the first measured sample does not absorb one-time client/server setup —
# same warm-up step as scripts/benchmark-xray.sh. Log/byte trackers are
# delta-based, so warm-up traffic does not leak into the per-sample guards.
warmup_mib = payloads_mib[0]
for impl_name in IMPL_ORDER:
    impl = IMPLEMENTATIONS[impl_name]
    for warmup in (
        lambda: curl_download(impl["socks"], warmup_mib, "http"),
        lambda: curl_download(impl["socks"], warmup_mib, "https"),
        lambda: curl_upload(impl["socks"], warmup_mib, "http"),
        lambda: curl_upload(impl["socks"], warmup_mib, "https"),
        lambda: curl_fallback_download(impl["fallback"], warmup_mib),
    ):
        try:
            warmup()
        except Exception as error:
            print(f"warm-up failed for {impl_name}: {error}", file=sys.stderr, flush=True)
# Drain warm-up bytes from the origin PUT logs and the rust server logs.
for tracker in put_trackers.values():
    tracker.new_lines()
for trackers in log_trackers.values():
    for tracker in trackers.values():
        tracker.new_lines()

cells = planned_cells()
cell_results = {}
started_utc = datetime.now(timezone.utc).isoformat()
run_started = time.perf_counter()

for scenario, mib, concurrency in cells:
    key = cell_key(scenario, mib, concurrency)
    order = [impl for _ in range(samples_for(mib)) for impl in IMPL_ORDER]
    random.Random(f"{seed}:{key}").shuffle(order)
    counters = {impl: 0 for impl in IMPL_ORDER}
    records = []
    stats_before = snapshot_origin_stats()
    for impl in order:
        sample_index = counters[impl]
        counters[impl] += 1
        records.append(record_sample(impl, scenario, mib, concurrency, sample_index))
    stats_after = snapshot_origin_stats()
    # Origin saturation guard: if an origin's own error counter grew during
    # the cell, the origin — not the proxy — choked; the samples must not be
    # interpreted as proxy results.
    origin_problems = []
    for scheme in ORIGIN_SCHEMES[scenario]:
        before = stats_before.get(scheme)
        after = stats_after.get(scheme)
        if before is None or after is None:
            continue
        delta = after.get("errors", 0) - before.get("errors", 0)
        if delta > 0:
            origin_problems.append(
                f"origin error: {scheme} origin reported {delta} "
                "new error(s) during the cell"
            )
    for record in records:
        record["originStats"] = stats_after
        if origin_problems:
            record["invalid"] = True
            extra = "; ".join(origin_problems)
            if record["invalidReason"]:
                record["invalidReason"] += "; " + extra
            else:
                record["invalidReason"] = extra
        finalize_record(record, key)
    cell_results[key] = {
        "scenario": scenario,
        "direction": DIRECTIONS[scenario],
        "payloadMiB": mib,
        "concurrency": concurrency,
        "samplesPerImplementation": samples_for(mib),
        "interleaveOrder": order,
        "originStats": {"before": stats_before, "after": stats_after},
        "records": records,
    }
    print(f"cell {key} done ({len(records)} samples)", file=sys.stderr, flush=True)

# ----------------------------------------------------------------------
# Integrity run: one multi-GiB direct-download per implementation with
# end-to-end sha256 verification.
# ----------------------------------------------------------------------

integrity = {}
if integrity_mib > 0:
    origin_hash = hashlib.sha256()
    with open(payload_path(integrity_mib), "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            origin_hash.update(chunk)
    for impl_name in IMPL_ORDER:
        impl = IMPLEMENTATIONS[impl_name]
        received_path = os.path.join(work, f"integrity-{impl_name}.bin")
        record = {
            "schemaVersion": 1,
            "commit": commit,
            "implementation": impl_name,
            "scenario": "integrity",
            "direction": "download",
            "payloadBytes": payload_bytes(integrity_mib),
            "concurrency": 1,
            "sampleIndex": 0,
            "wallSeconds": None,
            "throughputMiBPerSecond": None,
            "perRequestSeconds": [],
            "bytesVerified": False,
            "sha256": None,
            "backendStats": None,
            "originStats": None,
            "invalid": False,
            "invalidReason": None,
        }
        problems = []
        try:
            started = time.perf_counter()
            run_curl(
                [
                    "--insecure", "--tlsv1.3",
                    "--socks5-hostname", f"127.0.0.1:{impl['socks']}",
                    "--output", received_path,
                    f"https://127.0.0.1:{HTTPS_PORT}/payload-{integrity_mib}.bin",
                ],
                integrity_mib,
            )
            wall = time.perf_counter() - started
            record["wallSeconds"] = wall
            record["perRequestSeconds"] = [wall]
            record["throughputMiBPerSecond"] = payload_bytes(integrity_mib) / wall / MIB
            received_hash = hashlib.sha256()
            with open(received_path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    received_hash.update(chunk)
            match = received_hash.hexdigest() == origin_hash.hexdigest()
            record["sha256"] = {
                "origin": origin_hash.hexdigest(),
                "received": received_hash.hexdigest(),
                "match": match,
            }
            record["bytesVerified"] = match
            if not match:
                problems.append("sha256 mismatch between origin and received payload")
        except Exception as error:
            problems.append(str(error))
        time.sleep(0.25)
        events = rust_events_for(impl_name, "direct-download")
        if events is not None:
            stats = backend_stats(events)
            record["backendStats"] = stats
            if stats["acceptedConnections"] < 1:
                problems.append(
                    "TUNNEL BYPASS SUSPECTED: no connection_accepted event for the integrity transfer"
                )
        if problems:
            record["invalid"] = True
            record["invalidReason"] = "; ".join(problems)
            invalid_samples += 1
            failures.append({
                "cell": "integrity",
                "implementation": impl_name,
                "sampleIndex": 0,
                "reason": record["invalidReason"],
            })
            print(f"INVALID SAMPLE integrity {impl_name}: {record['invalidReason']}",
                  file=sys.stderr, flush=True)
        total_samples += 1
        samples_file.write(json.dumps(record, sort_keys=True) + "\n")
        samples_file.flush()
        integrity[impl_name] = {
            "payloadBytes": payload_bytes(integrity_mib),
            "wallSeconds": record["wallSeconds"],
            "sha256": record["sha256"],
            "invalid": record["invalid"],
            "invalidReason": record["invalidReason"],
        }
        print(f"integrity {impl_name} done", file=sys.stderr, flush=True)

samples_file.close()

# ----------------------------------------------------------------------
# Summary aggregation.
# ----------------------------------------------------------------------


def percentile(values, fraction):
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * fraction) - 1)
    return ordered[index]


def distribution(values):
    return {
        "p50": statistics.median(values),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "mean": statistics.fmean(values),
    }


summary_cells = {}
for key, cell in cell_results.items():
    per_impl = {}
    p50s = {}
    for impl in IMPL_ORDER:
        records = [r for r in cell["records"] if r["implementation"] == impl]
        valid = [r for r in records if not r["invalid"]]
        throughput = [r["throughputMiBPerSecond"] for r in valid]
        per_request = [s for r in valid for s in r["perRequestSeconds"]]
        entry = {
            "samples": len(records),
            "validSamples": len(valid),
            "invalidSamples": len(records) - len(valid),
        }
        if throughput:
            entry["throughputMiBPerSecond"] = distribution(throughput)
            p50s[impl] = entry["throughputMiBPerSecond"]["p50"]
        if per_request:
            entry["perRequestSeconds"] = distribution(per_request)
        per_impl[impl] = entry

    def ratio(numerator, denominator):
        if numerator in p50s and p50s.get(denominator):
            return p50s[numerator] / p50s[denominator]
        return None

    summary_cells[key] = {
        "scenario": cell["scenario"],
        "direction": cell["direction"],
        "payloadMiB": cell["payloadMiB"],
        "concurrency": cell["concurrency"],
        "samplesPerImplementation": cell["samplesPerImplementation"],
        "interleaveOrder": cell["interleaveOrder"],
        "originStats": cell["originStats"]["after"],
        "implementations": per_impl,
        "p50ThroughputRatios": {
            "baselineVsXray": ratio("baseline", "xray"),
            "finalVsXray": ratio("final", "xray"),
            "finalVsBaseline": ratio("final", "baseline"),
        },
    }

summary = {
    "schemaVersion": 1,
    "harness": "benchmark-matrix",
    "seed": seed_text,
    "commit": commit,
    "startedUtc": started_utc,
    "wallSeconds": time.perf_counter() - run_started,
    "plan": {
        "scenarios": SCENARIOS,
        "payloadsMiB": payloads_mib,
        "concurrencies": concurrencies,
        "samplesPerCell": samples_small,
        "samplesPerLargeCell": samples_large,
        "largePayloadMiB": large_payload_mib,
        "largeCellConcurrencies": large_concurrencies,
        "cellsFilter": cells_filter,
        "skipFilter": skip_filter,
        "integrityMiB": integrity_mib,
    },
    "totals": {
        "cells": len(cell_results),
        "samples": total_samples,
        "invalidSamples": invalid_samples,
    },
    "cells": summary_cells,
    "integrity": integrity,
    "failures": failures,
    "limitations": [
        "single-host loopback includes the same Xray client and loopback origins in every path",
        "the tunnel-bypass guard only covers the rust implementations (their debug logs); "
        "xray cells rely on byte-count verification",
        "Xray's default private-target block is explicitly allowed only for the loopback origin",
        "this does not model Internet RTT, packet loss, bandwidth shaping, or multi-core saturation",
        "results are measurements of this host and are not a universal performance claim",
    ],
}
with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as handle:
    json.dump(summary, handle, indent=2, sort_keys=True)
    handle.write("\n")


def command_output(command):
    try:
        return subprocess.run(
            command, check=True, capture_output=True, text=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
environment = {
    "schemaVersion": 1,
    "dateUtc": datetime.now(timezone.utc).isoformat(),
    "kernel": platform.release(),
    "machine": platform.machine(),
    "cpuModel": next(
        (
            line.split(":", 1)[1].strip()
            for line in open("/proc/cpuinfo", encoding="utf-8")
            if line.startswith("model name")
        ),
        "unknown",
    ),
    "cpuCount": os.cpu_count(),
    "rustcVersion": command_output(["rustc", "--version"]),
    "xrayVersion": (lambda output: output.splitlines()[0] if output != "unknown" else output)(
        command_output([cfg["xray"], "version"])
    ),
    "finalCommit": commit,
    "baselineCommit": cfg["baseline_commit"],
    "binaries": {
        "baseline": cfg["baseline_bin"],
        "final": cfg["rust_bin"],
        "xray": cfg["xray"],
    },
    "nic": {"interface": cfg["nic_interface"], "speed": cfg["nic_speed"]},
    "rlimitNofile": {"soft": soft_limit, "hard": hard_limit},
    "realityCover": {"target": cfg["cover_target"], "serverName": cfg["cover_sni"]},
    "originImplementation": cfg["origin_impl"],
    "seed": seed_text,
}
with open(os.path.join(out_dir, "environment.json"), "w", encoding="utf-8") as handle:
    json.dump(environment, handle, indent=2, sort_keys=True)
    handle.write("\n")

print(
    f"matrix complete: {total_samples} samples, {invalid_samples} invalid -> {out_dir}",
    flush=True,
)
PY

python3 "$work/driver.py" "$work/driver-config.json"
