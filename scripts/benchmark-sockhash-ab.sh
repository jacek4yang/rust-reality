#!/usr/bin/env bash
# SOCKHASH A/B: production-path throughput with the sockHash policy off
# (bilateral splice) vs on (kernel SOCKHASH redirect), using the REALITY
# fallback path, which reaches TcpRelay::relay_owned directly.
#
# The sockHash-enabled leg runs the prebuilt server under sudo (CAP_BPF).
# Never `sudo cargo` — only the already-built binary runs privileged.
#
# Requires: sudo -n, curl, jq, python3, go (for bench-origin build), perf.
# Env: RUST_REALITY_BIN (target/release/rust-reality), SAMPLES (7),
#      CONCURRENCIES ("1 4 32"), PAYLOAD_MIB (32), OUT_DIR.
set -Eeuo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
rust_bin=${RUST_REALITY_BIN:-target/release/rust-reality}
samples=${SAMPLES:-7}
concurrencies=${CONCURRENCIES:-1 4 32}
payload_mib=${PAYLOAD_MIB:-32}
out_dir=${OUT_DIR:-benchmarks/final/sockhash-ab}
work=$(mktemp -d "$repository/benchmarks/sockhash-ab.XXXXXX")
pids=()

cleanup() {
    for pid in "${pids[@]}"; do
        sudo -n kill "$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
        sudo -n wait "$pid" 2>/dev/null || wait "$pid" 2>/dev/null || true
    done
    if [[ ${KEEP_WORK:-0} == 1 ]]; then
        printf 'sockhash A/B work dir retained: %s\n' "$work" >&2
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
    local port=$1 sockhash=$2 out=$3
    "$rust_bin" config generate standalone \
        --listen 127.0.0.1 --port "$port" \
        --target "127.0.0.1:$http_port" --server-name "localhost" \
        >"$work/base.json" 2>"$work/gen.$sockhash.log"
    jq --arg cache "$work/assets.$sockhash" --argjson sh "$([ "$sockhash" = 1 ] && echo true || echo false)" '
        .log.level = "info" |
        .assets.cacheDirectory = $cache |
        .policy.relay.sockhash = $sh |
        .policy.relay.maxSockhashRelays = 256
    ' "$work/base.json" >"$out"
}

run_leg() {
    # $1 = label (splice|sockhash), $2 = sockhash 0|1
    local label=$1 sh=$2 port stats_file
    port=$(free_port)
    stats_file="$out_dir/perf-$label.txt"
    make_config "$port" "$sh" "$work/server.$label.json"
    if (( sh == 1 )); then
        sudo -n "$rust_bin" serve --config "$work/server.$label.json" \
            >"$work/server.$label.log" 2>&1 &
    else
        "$rust_bin" serve --config "$work/server.$label.json" \
            >"$work/server.$label.log" 2>&1 &
    fi
    pids+=("$!")
    wait_port "$port"
    sleep 0.3
    # Confirm the backend actually engaged (startup report in the log).
    local backend_line
    backend_line=$(grep -o '"backend":"sockhash"[^}]*' "$work/server.$label.log" | head -1 || true)
    if (( sh == 1 )) && ! grep -q '"backend":"sockhash","available":true' "$work/server.$label.log"; then
        echo "sockhash backend not available on this host:" >&2
        grep relay_backend_report "$work/server.$label.log" >&2
        exit 4
    fi
    local stat_pid=${pids[-1]}
    if (( sh == 1 )); then
        # perf must count the server child, not the waiting sudo parent.
        stat_pid=$(pgrep -n -x rust-reality)
    fi
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
    echo "$backend_line" > "$out_dir/backend-$label.txt"
}

export SAMPLES_OUT="$out_dir/samples.json"
: > "$SAMPLES_OUT"
python3 -c "import json; json.dump([], open('$SAMPLES_OUT','w'))"

run_leg splice 0
cp "$SAMPLES_OUT" "$out_dir/samples-splice.json"
run_leg sockhash 1
cp "$SAMPLES_OUT" "$out_dir/samples-sockhash.json"

echo "perf stat (splice):"; grep -E "task-clock|instructions|context-switches|seconds" "$out_dir/perf-splice.txt" | grep -v "^#"
echo "perf stat (sockhash):"; grep -E "task-clock|instructions|context-switches|seconds" "$out_dir/perf-sockhash.txt" | grep -v "^#"
