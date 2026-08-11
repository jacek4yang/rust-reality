#!/usr/bin/env bash
# Fallback backend A/B: production fallback-path throughput with splice
# on (pooled) vs splice off (buffered at a chosen buffer size), using direct
# curl-to-listener connections, which reach TcpRelay::relay_owned directly.
#
# Env: RUST_REALITY_BIN, XRAY_BIN, SAMPLES (7), CONCURRENCIES ("1 4 32"),
#      PAYLOAD_MIB (32), OUT_DIR, LEGS ("splice buffered32 buffered64 buffered128").
#      LEGS="splice xray" gives the symmetric Xray comparison. The default
#      OUT_DIR is timestamped so reruns never overwrite retained evidence.
set -Eeuo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
rust_bin=${RUST_REALITY_BIN:-target/release/rust-reality}
xray=${XRAY_BIN:-../artifacts/xray-reference}
samples=${SAMPLES:-7}
concurrencies=${CONCURRENCIES:-1 4 32}
payload_mib=${PAYLOAD_MIB:-32}
out_dir=${OUT_DIR:-benchmarks/final/fallback-ab-$(date -u +%Y%m%dT%H%M%SZ)}
work=$(mktemp -d "$repository/benchmarks/fallback-ab.XXXXXX")
pids=()

cleanup() {
    for pid in "${pids[@]}"; do
        sudo -n kill "$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
        sudo -n wait "$pid" 2>/dev/null || wait "$pid" 2>/dev/null || true
    done
    if [[ ${KEEP_WORK:-0} == 1 ]]; then
        printf 'fallback A/B work dir retained: %s\n' "$work" >&2
    else
        sudo -n rm -rf -- "$work" 2>/dev/null || rm -rf -- "$work"
    fi
}
trap cleanup EXIT

sudo -n true || { echo "passwordless sudo required" >&2; exit 1; }
for program in curl jq python3 go; do
    command -v "$program" >/dev/null || { echo "missing: $program" >&2; exit 1; }
done

cd "$repository"
mkdir -p "$out_dir"

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

http_port=$(free_port)
python3 -c "
chunk = bytes(range(256)) * 4096
with open('$work/payload-$payload_mib.bin', 'wb') as f:
    for _ in range($payload_mib):
        f.write(chunk)"
(cd scripts/bench-origin && go build -o "$work/bench-origin" .)
"$work/bench-origin" --port "$http_port" --payload-dir "$work" \
    --put-log "$work/http-put.jsonl" >"$work/origin.log" 2>&1 &
pids+=("$!")
wait_port "$http_port"

make_config() {
    local port=$1 splice=$2 kib=$3 out=$4
    local pool=${5:-true}
    "$rust_bin" config generate standalone \
        --listen 127.0.0.1 --port "$port" \
        --target "127.0.0.1:$http_port" --server-name "localhost" \
        >"$work/base.$label.json" 2>"$work/gen.$splice.$kib.log"
    jq --arg cache "$work/assets.$splice.$kib" --argjson splice "$splice" --argjson kib "$kib" --argjson pool "$pool" '
        .log.level = "warn" |
        .assets.cacheDirectory = $cache |
        .policy.relay.splice = $splice |
        .policy.relay.pipePool = $pool |
        .policy.relay.bufferBytes = ($kib * 1024)
    ' "$work/base.$label.json" >"$out"
}

run_leg() {
    # $1 = label, $2 = splice true|false, $3 = buffer KiB, $4 = pipePool true|false
    local label=$1 splice=$2 kib=$3 pool=${4:-true} port stats_file
    port=$(free_port)
    stats_file="$out_dir/perf-$label.txt"
    make_config "$port" "$splice" "$kib" "$work/server.$label.json" "$pool"
    "$rust_bin" serve --config "$work/server.$label.json" \
        >"$work/server.$label.log" 2>&1 &
    pids+=("$!")
    wait_port "$port"
    sleep 0.3
    local stat_pid=${pids[-1]}
    sudo -n perf stat -e task-clock,instructions,context-switches -p "$stat_pid" \
        -o "$stats_file" -- \
        python3 - "$samples" "$payload_mib" "$port" "$http_port" "$label" "$concurrencies" "$SAMPLES_OUT" <<'PY'
import concurrent.futures
import json
import os
import random
import statistics
import subprocess
import sys

samples, mib, server_port, http_port, label = (
    int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5])
concurrencies = [int(c) for c in sys.argv[6].split()]
samples_out = sys.argv[7]
expected = mib * 1024 * 1024
url = f"http://127.0.0.1:{server_port}/payload-{mib}.bin"
curl_env = {k: v for k, v in os.environ.items()
            if k.lower() not in ("all_proxy", "http_proxy", "https_proxy", "no_proxy")}

def transfer(_):
    r = subprocess.run(
        ["curl", "--fail", "-sS", "--max-time", "300", "-o", os.devnull,
         "-w", "%{size_download} %{time_total}", url],
        capture_output=True, text=True, env=curl_env)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip()[:160])
    size, elapsed = r.stdout.split()
    if int(size) != expected:
        raise RuntimeError(f"short read {size}")
    return float(elapsed)

out = []
for conc in concurrencies:
    transfer(0)  # warm
    per_request = []
    for index in range(samples):
        started = __import__("time").perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as ex:
            lats = list(ex.map(transfer, range(conc)))
        wall = __import__("time").perf_counter() - started
        per_request.extend(lats)
        out.append({"concurrency": conc, "sampleIndex": index,
                    "wallSeconds": wall,
                    "throughputMiBPerSecond": mib * conc / wall,
                    "perRequestSeconds": lats})
with open(samples_out, "w") as fh:
    json.dump(out, fh)
print(f"{label}: " + "; ".join(
    f"c{conc} p50={statistics.median(x['throughputMiBPerSecond'] for x in out if x['concurrency']==conc):.0f} MiB/s"
    for conc in concurrencies))
PY
    grep -o '"backend":"[a-z]*","available":[a-z]*' "$work/server.$label.log" | head -3 > "$out_dir/backend-$label.txt" || true
}

run_xray_leg() {
    local port uuid sid stats_file
    port=$(free_port)
    stats_file="$out_dir/perf-xray.txt"
    uuid=$(jq -r '.inbounds[0].settings.clients[0].id' "$work/base.splice.json")
    sid=$(jq -r '.inbounds[0].settings.clients[0].shortIds[0]' "$work/base.splice.json")
    local xpriv xpub
    xpriv=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey' "$work/base.splice.json")
    xpub=$(sed -n 's/^REALITY public key for the client: //p' "$work/gen.true.32.log")
    jq -n --arg uuid "$uuid" --arg pk "$xpriv" --arg sid "$sid" --argjson port "$port"         --arg target "127.0.0.1:$http_port"         '{log:{loglevel:"warning"},inbounds:[{listen:"127.0.0.1",port:$port,protocol:"vless",settings:{clients:[{id:$uuid,flow:"xtls-rprx-vision"}],decryption:"none",fallbacks:[{dest:$target}]},streamSettings:{network:"tcp",security:"reality",realitySettings:{show:false,target:($target),xver:0,serverNames:["localhost"],privateKey:$pk,shortIds:[$sid]}}}],outbounds:[{tag:"direct",protocol:"freedom",settings:{finalRules:[{action:"allow"}]}}]}'         > "$work/xray-server.json"
    "$xray" run -config "$work/xray-server.json" > "$work/xray-server.log" 2>&1 &
    pids+=("$!")
    wait_port "$port"
    sleep 0.3
    sudo -n perf stat -e task-clock,instructions,context-switches -p "${pids[-1]}"         -o "$stats_file" -- \
        python3 - "$samples" "$payload_mib" "$port" "$http_port" "xray" "$concurrencies" "$SAMPLES_OUT" <<'PY'
import concurrent.futures
import json
import os
import statistics
import subprocess
import sys

samples, mib, server_port, http_port, label = (
    int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5])
concurrencies = [int(c) for c in sys.argv[6].split()]
samples_out = sys.argv[7]
expected = mib * 1024 * 1024
url = f"http://127.0.0.1:{server_port}/payload-{mib}.bin"
curl_env = {k: v for k, v in os.environ.items()
            if k.lower() not in ("all_proxy", "http_proxy", "https_proxy", "no_proxy")}

def transfer(_):
    r = subprocess.run(
        ["curl", "--fail", "-sS", "--max-time", "300", "-o", os.devnull,
         "-w", "%{size_download} %{time_total}", url],
        capture_output=True, text=True, env=curl_env)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip()[:160])
    size, elapsed = r.stdout.split()
    if int(size) != expected:
        raise RuntimeError(f"short read {size}")
    return float(elapsed)

out = []
for conc in concurrencies:
    transfer(0)
    for index in range(samples):
        started = __import__("time").perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as ex:
            lats = list(ex.map(transfer, range(conc)))
        wall = __import__("time").perf_counter() - started
        out.append({"concurrency": conc, "sampleIndex": index,
                    "wallSeconds": wall,
                    "throughputMiBPerSecond": mib * conc / wall,
                    "perRequestSeconds": lats})
with open(samples_out, "w") as fh:
    json.dump(out, fh)
print(f"{label}: " + "; ".join(
    f"c{conc} p50={statistics.median(x['throughputMiBPerSecond'] for x in out if x['concurrency']==conc):.0f} MiB/s"
    for conc in concurrencies))
PY
    : > "$out_dir/backend-xray.txt"
}

export SAMPLES_OUT="$out_dir/samples.json"
: > "$SAMPLES_OUT"
python3 -c "import json; json.dump([], open('$SAMPLES_OUT','w'))"

for leg in ${LEGS:-splice buffered32 buffered64}; do
    case "$leg" in
        splice) run_leg splice true 32 true ;;
        splice-nopool) run_leg splice-nopool true 32 false ;;
        buffered32) run_leg buffered32 false 32 ;;
        buffered64) run_leg buffered64 false 64 ;;
        buffered128) run_leg buffered128 false 128 ;;
        xray) run_xray_leg ;;
        *) echo "unknown leg: $leg" >&2; exit 2 ;;
    esac
    cp "$SAMPLES_OUT" "$out_dir/samples-$leg.json"
done

for leg in ${LEGS:-splice buffered32 buffered64}; do
    echo "perf stat ($leg):"; grep -E "task-clock|context-switches|seconds" "$out_dir/perf-$leg.txt" | grep -v "^#"
done
