#!/usr/bin/env bash
# cpu-per-gib.sh — measure rust-reality server CPU per GiB on the Direct path.
#
# Starts a local TLS 1.3 origin (Go bench-origin), one rust-reality server
# (binary under test), and one unmodified Xray SOCKS5 client — the same
# topology as scripts/benchmark-matrix.sh — then drives bulk transfers while
# `perf stat -p` watches the server process. Output: one JSON record per cell
# in <out-dir>/cpu-samples.jsonl.
#
# Usage: cpu-per-gib.sh <server-binary> <label> <out-dir> [port-base]
# Cells: direct-download 512MiB c1, direct-download 32MiB c32,
#        direct-upload 512MiB c1, direct-upload 32MiB c32 (2 rounds each).
#
# v1.6.0: repository / xray / tmp-parent paths are parameterized (v150
# hardcoded the v150-gates worktree and artifacts/xray-reference):
#   RR_REPOSITORY  harness repository worktree (default worktrees/v16-gates)
#   XRAY_BIN       Xray client binary (default artifacts/xray-reference-v26.7.28)
#   GATES_TMP      existing scratch parent (default artifacts/v1.6.0/gates/tmp)
set -Eeuo pipefail

binary=${1:?server binary required}
label=${2:?label required}
out_dir=${3:?out dir required}
port_base=${4:-61600}

ROOT=/home/jacek/work/kimi-rust-reality-performance
repository=${RR_REPOSITORY:-$ROOT/worktrees/v16-gates}
xray=${XRAY_BIN:-$ROOT/artifacts/xray-reference-v26.7.28}
gates_tmp=${GATES_TMP:-$ROOT/artifacts/v1.6.0/gates/tmp}
http_port=$((port_base)); https_port=$((port_base + 1))
server_port=$((port_base + 2)); socks_port=$((port_base + 3))

[[ -x $binary && -x $xray ]] || { echo "binary missing" >&2; exit 2; }
[[ -d $gates_tmp && ! -L $gates_tmp ]] || { echo "GATES_TMP must be an existing non-symlink directory: $gates_tmp" >&2; exit 2; }
mkdir -p "$out_dir"
[[ ! -e $out_dir/cpu-samples.jsonl ]] || { echo "output exists: $out_dir/cpu-samples.jsonl" >&2; exit 2; }
work=$(mktemp -d "$gates_tmp/cpu-per-gib.XXXXXX")
pids=()
cleanup() {
    set +e
    for pid in "${pids[@]:-}"; do kill "$pid" 2>/dev/null; done
    for pid in "${pids[@]:-}"; do wait "$pid" 2>/dev/null; done
    rm -rf -- "$work"
}
trap cleanup EXIT

# Payloads: 512 MiB (c1) and 32 MiB (c32 cells).
python3 - "$work" <<'PY'
from pathlib import Path
import sys
work = Path(sys.argv[1])
chunk = bytes(range(256)) * 4096
for mib in (32, 512):
    remaining = mib * 1024 * 1024
    with (work / f"payload-{mib}.bin").open("wb") as out:
        while remaining:
            part = chunk[:min(len(chunk), remaining)]
            out.write(part)
            remaining -= len(part)
PY

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/origin.key" -out "$work/origin.crt" \
    -days 1 -subj "/CN=localhost" >/dev/null 2>&1
(cd "$repository/scripts/bench-origin" && GOFLAGS=-buildvcs=false go build -o "$work/bench-origin" .)
: >"$work/put.jsonl"
"$work/bench-origin" --port "$https_port" --payload-dir "$work" --put-log "$work/put.jsonl" \
    --tls-cert "$work/origin.crt" --tls-key "$work/origin.key" >"$work/origin.log" 2>&1 &
pids+=($!)

"$binary" config generate standalone --listen 127.0.0.1 --port "$server_port" \
    --target "127.0.0.1:$https_port" --server-name localhost >"$work/server.raw.json" 2>"$work/generate.log"
public_key=$(sed -n 's/^REALITY public key for the client: //p' "$work/generate.log")
uuid=$(jq -er '.inbounds[0].settings.clients[0].id' "$work/server.raw.json")
short_id=$(jq -er '.inbounds[0].settings.clients[0].shortIds[0]' "$work/server.raw.json")
jq --arg cache "$work/assets" '.log.level="warn"|.assets.cacheDirectory=$cache' \
    "$work/server.raw.json" >"$work/server.json"
"$binary" serve --config "$work/server.json" >"$work/server.log" 2>&1 &
server_pid=$!
pids+=($server_pid)

jq -n --arg uuid "$uuid" --arg pk "$public_key" --arg sid "$short_id" \
    --argjson server "$server_port" --argjson socks "$socks_port" \
    '{log:{loglevel:"warning"},inbounds:[{listen:"127.0.0.1",port:$socks,protocol:"socks",settings:{auth:"noauth",udp:false}}],outbounds:[{protocol:"vless",settings:{vnext:[{address:"127.0.0.1",port:$server,users:[{id:$uuid,encryption:"none",flow:"xtls-rprx-vision"}]}]},streamSettings:{network:"tcp",security:"reality",realitySettings:{fingerprint:"chrome",serverName:"localhost",publicKey:$pk,shortId:$sid,spiderX:"/"}}}]}' \
    >"$work/client.json"
"$xray" run -config "$work/client.json" >"$work/client.log" 2>&1 &
pids+=($!)

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
raise SystemExit(f"port {port} not ready")
PY
}
wait_port "$https_port"; wait_port "$server_port"; wait_port "$socks_port"

# curl with a proxy-stripped environment (see benchmark-matrix.sh header).
curl_clean() { env -i PATH="$PATH" HOME="$HOME" curl --fail --silent --show-error "$@"; }

run_cell() { # <scenario> <mib> <concurrency> <round>
    local scenario=$1 mib=$2 conc=$3 round=$4
    local url="https://127.0.0.1:$https_port"
    local perf_csv="$work/perf-$scenario-$mib-$conc-$round.csv"
    local -a args
    if [[ $scenario == download ]]; then
        args=(--output /dev/null "$url/payload-$mib.bin")
    else
        args=(--upload-file "$work/payload-$mib.bin" --output /dev/null "$url/upload/$mib")
    fi
    local started wall
    started=$(python3 -c 'import time; print(time.perf_counter())')
    sudo -n perf stat --no-big-num -x, -e task-clock -p "$server_pid" -o "$perf_csv" -- \
        bash -c '
            url=$1; mib=$2; conc=$3; shift 3
            pids=()
            for ((i = 0; i < conc; i++)); do
                env -i PATH="$PATH" HOME="$HOME" curl --fail --silent --show-error \
                    --insecure --tlsv1.3 --socks5-hostname 127.0.0.1:'"$socks_port"' \
                    "$@" &
                pids+=($!)
            done
            rc=0
            for pid in "${pids[@]}"; do wait "$pid" || rc=1; done
            exit "$rc"
        ' _ "$url" "$mib" "$conc" "${args[@]}"
    wall=$(python3 -c "import time; print(time.perf_counter() - $started)")
    local task_clock
    task_clock=$(awk -F, '$3 == "task-clock" {print $1}' "$perf_csv")
    [[ -n $task_clock ]] || { echo "perf stat produced no task-clock for $scenario/$mib/c$conc" >&2; exit 1; }
    local transfers=$conc bytes
    bytes=$((mib * 1024 * 1024 * transfers))
    jq -nc --arg label "$label" --arg scenario "$scenario" --argjson mib "$mib" \
        --argjson concurrency "$conc" --argjson round "$round" --argjson bytes "$bytes" \
        --argjson taskClockMs "$task_clock" --arg wallSeconds "$wall" \
        '{label:$label,scenario:("direct-" + $scenario),payloadMiB:$mib,concurrency:$concurrency,round:$round,bytes:$bytes,wallSeconds:($wallSeconds|tonumber),serverTaskClockMs:$taskClockMs,serverMsPerGiB:($taskClockMs / ($bytes / 1073741824))}' \
        >>"$out_dir/cpu-samples.jsonl"
}

# Warm-up (not measured).
curl_clean --insecure --tlsv1.3 --socks5-hostname "127.0.0.1:$socks_port" \
    --output /dev/null "https://127.0.0.1:$https_port/payload-32.bin"

for round in 1 2; do
    run_cell download 512 1 "$round"
    run_cell download 32 32 "$round"
    run_cell upload 512 1 "$round"
    run_cell upload 32 32 "$round"
done
echo "cpu-per-gib complete: $out_dir/cpu-samples.jsonl"
