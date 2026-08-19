#!/usr/bin/env bash
# RSS/FD sampling for an Xray SERVER under the same sustained load shape as
# scripts/soak-test.sh (README gap G2): an Xray VLESS + REALITY + vision
# server fronts the same Go bench-origin pair (TLS + plain), the same
# unmodified Xray SOCKS5 client drives it, and each round repeats the soak
# mix — direct download (TLS origin), framed download (plain origin),
# fallback (direct-to-listener), and rapid connect/drop churn — while /proc
# snapshots record VmRSS/VmHWM/fd/thread counts of the Xray server process.
# resources.jsonl keeps the soak-test.sh record schema
# (label/monotonicSeconds/processes/totals) so README rows can compare RSS
# under sustained load across implementations.
#
# Env: RUN_ID OUT_DIR TMPDIR PORT_BASE XRAY_BIN XRAY_SHA256
# DURATION_MIN (10 formal / 1 exploratory) ROUND_SLEEP (5)
# EXPLORATORY=1 (wrap in `flock -x /tmp/v151-bench.lock`).
set -Eeuo pipefail
umask 077

repository=$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$repository/scripts/benchmark-contract.sh"
xray=${XRAY_BIN:-../artifacts/xray-reference-v26.7.28}
duration_min=${DURATION_MIN:-$([[ ${EXPLORATORY:-0} == 1 ]] && echo 1 || echo 10)}
round_sleep=${ROUND_SLEEP:-5}
[[ $duration_min =~ ^[1-9][0-9]*$ ]] || { echo "DURATION_MIN must be positive" >&2; exit 2; }
[[ $round_sleep =~ ^[0-9]+$ ]] || { echo "ROUND_SLEEP must be non-negative" >&2; exit 2; }

# Default the port block above the ephemeral range (32768-60999) so client
# sockets cannot collide with it mid-run.
if [[ -z ${PORT_BASE:-} ]]; then
    PORT_BASE=$(python3 - 8 <<'PY'
import socket, sys
width = int(sys.argv[1])
for base in range(61000, 65536 - width, 37):
    sockets = []
    bound = True
    try:
        for port in range(base, base + width):
            sock = socket.socket()
            sock.bind(("127.0.0.1", port))
            sockets.append(sock)
    except OSError:
        bound = False
    finally:
        for sock in sockets:
            sock.close()
    if bound:
        print(base)
        break
else:
    raise SystemExit("no free port block above the ephemeral range")
PY
)
    export PORT_BASE
fi
rr_contract_init "$repository" sampling-xray-resources benchmarks/final 8
rr_register_binary xray "$xray" "${XRAY_SHA256:-}" xray
xray=${RR_BINARY_PATHS[xray]}
rr_register_harness_tree "$repository/scripts/bench-origin"
rr_write_contract_metadata
out_dir=$RR_OUT_DIR
temporary_root=$RR_TMPDIR

for program in curl go jq openssl python3 sha256sum; do
    command -v "$program" >/dev/null || { echo "missing: $program" >&2; exit 1; }
done

work=$(mktemp -d "$temporary_root/rust-reality-xray-resources.XXXXXX")
declare -a pids=()
declare -A active_starts=()
last_pid=

pid_is_owned() {
    local pid=$1 observed
    observed=$(rr_pid_starttime "$pid" 2>/dev/null) || return 1
    [[ $observed == "${active_starts[$pid]:-}" ]]
}

start_logged() {
    local log=$1
    shift
    "$@" >"$log" 2>&1 &
    last_pid=$!
    pids+=("$last_pid")
    active_starts["$last_pid"]=$(rr_pid_starttime "$last_pid") || {
        echo "cannot identify started process PID $last_pid" >&2
        return 1
    }
    if [[ $1 == "$xray" ]]; then rr_register_pid "$last_pid" "$1"; else rr_register_pid "$last_pid"; fi
}

stop_pid() {
    local pid=$1
    pid_is_owned "$pid" && {
        kill -TERM "$pid" 2>/dev/null || true
        for _ in {1..50}; do pid_is_owned "$pid" || break; sleep 0.02; done
        pid_is_owned "$pid" && kill -KILL "$pid" 2>/dev/null || true
    }
    wait "$pid" 2>/dev/null || true
    unset "active_starts[$pid]"
}

cleanup() {
    local original_status=$? final_status pid
    trap - EXIT INT TERM
    set +e
    for pid in "${pids[@]:-}"; do stop_pid "$pid"; done
    if [[ -d $work && $work == "$temporary_root"/rust-reality-xray-resources.* ]]; then
        rm -rf -- "$work"
    fi
    final_status=$original_status
    rr_contract_verify_on_exit "$original_status"
    final_status=$?
    exit "$final_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_port() {
    local port=$1 pid=$2
    python3 - "$port" "$pid" "${active_starts[$pid]}" <<'PY'
import socket, sys, time
port, pid, expected = int(sys.argv[1]), sys.argv[2], sys.argv[3]
deadline = time.monotonic() + 10
while time.monotonic() < deadline:
    try:
        raw = open(f"/proc/{pid}/stat").read()
        observed = raw[raw.rfind(")") + 2:].split()[19]
    except OSError:
        raise SystemExit(f"process {pid} exited before port {port} became ready")
    if observed != expected:
        raise SystemExit(f"process {pid} identity changed before port {port} became ready")
    with socket.socket() as sock:
        sock.settimeout(0.1)
        if sock.connect_ex(("127.0.0.1", port)) == 0:
            raise SystemExit(0)
    time.sleep(0.02)
raise SystemExit(f"port {port} did not become ready")
PY
}

clean_curl() {
    env -u ALL_PROXY -u all_proxy -u HTTP_PROXY -u http_proxy \
        -u HTTPS_PROXY -u https_proxy -u NO_PROXY -u no_proxy curl "$@"
}

cd "$repository"
python3 - "$work" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
chunk = bytes(range(256)) * 4096
(root / "payload-1.bin").write_bytes(chunk)
(root / "payload-4.bin").write_bytes(chunk * 4)
PY
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
    -keyout "$work/origin.key" -out "$work/origin.crt" >/dev/null 2>&1
(cd scripts/bench-origin && GOFLAGS=-buildvcs=false go build -o "$work/bench-origin" .)

https_port=$(rr_next_port); http_port=$(rr_next_port)
server_port=$(rr_next_port); socks_port=$(rr_next_port)

start_logged "$out_dir/origin-https.log" "$work/bench-origin" \
    --port "$https_port" --payload-dir "$work" --put-log "$work/https-put.jsonl" \
    --tls-cert "$work/origin.crt" --tls-key "$work/origin.key"
https_pid=$last_pid
start_logged "$out_dir/origin-http.log" "$work/bench-origin" \
    --port "$http_port" --payload-dir "$work" --put-log "$work/http-put.jsonl"
http_pid=$last_pid
wait_port "$https_port" "$https_pid"
wait_port "$http_port" "$http_pid"

uuid=$(python3 -c 'import uuid; print(uuid.uuid4())')
short_id=$(openssl rand -hex 8)
"$xray" x25519 >"$work/xray.keys"
private_key=$(sed -n 's/^PrivateKey: //p' "$work/xray.keys")
public_key=$(sed -n 's/^Password (PublicKey): //p' "$work/xray.keys")
jq -n --arg uuid "$uuid" --arg pk "$private_key" --arg sid "$short_id" \
    --arg target "127.0.0.1:$https_port" --argjson port "$server_port" \
    '{log:{loglevel:"warning"},
      inbounds:[{listen:"127.0.0.1",port:$port,protocol:"vless",
        settings:{clients:[{id:$uuid,flow:"xtls-rprx-vision"}],decryption:"none"},
        streamSettings:{network:"tcp",security:"reality",
          realitySettings:{show:false,target:$target,xver:0,
            serverNames:["localhost"],privateKey:$pk,shortIds:[$sid]}}}],
      outbounds:[{tag:"direct",protocol:"freedom",
        settings:{finalRules:[{action:"allow"}]}}]}' >"$work/xray-server.json"
cp "$work/xray-server.json" "$out_dir/server-config.json"
jq -n --arg uuid "$uuid" --arg pk "$public_key" --arg sid "$short_id" \
    --argjson server "$server_port" --argjson socks "$socks_port" \
    '{log:{loglevel:"warning"},inbounds:[{listen:"127.0.0.1",port:$socks,protocol:"socks",settings:{auth:"noauth",udp:false}}],outbounds:[{protocol:"vless",settings:{vnext:[{address:"127.0.0.1",port:$server,users:[{id:$uuid,encryption:"none",flow:"xtls-rprx-vision"}]}]},streamSettings:{network:"tcp",security:"reality",realitySettings:{fingerprint:"chrome",serverName:"localhost",publicKey:$pk,shortId:$sid,spiderX:"/"}}}]}' \
    >"$work/xray-client.json"
cp "$work/xray-client.json" "$out_dir/client-config.json"

start_logged "$out_dir/server.log" "$xray" run -config "$work/xray-server.json"
server_pid=$last_pid
start_logged "$out_dir/client.log" "$xray" run -config "$work/xray-client.json"
client_pid=$last_pid
wait_port "$server_port" "$server_pid"
wait_port "$socks_port" "$client_pid"

snapshot() {
    local label=$1
    python3 - "$label" "$server_pid" "${active_starts[$server_pid]}" \
        >>"$out_dir/resources.jsonl" <<'PY'
import json, os, sys, time
label, pid, expected = sys.argv[1], int(sys.argv[2]), sys.argv[3]
try:
    raw = open(f"/proc/{pid}/stat", encoding="ascii").read()
except FileNotFoundError:
    raise SystemExit(f"xray server exited: {pid}/{expected}")
observed = raw[raw.rfind(")") + 2:].split()[19]
if observed != expected:
    raise SystemExit(f"xray server identity changed: {pid}/{expected} -> {observed}")
with open(f"/proc/{pid}/status", encoding="ascii") as handle:
    fields = dict(line.split(":", 1) for line in handle if ":" in line)
process = {
    "alive": True,
    "pid": pid,
    "pidStarttime": observed,
    "fds": len(os.listdir(f"/proc/{pid}/fd")),
    "vmRssKiB": int(fields["VmRSS"].split()[0]),
    "vmHwmKiB": int(fields.get("VmHWM", fields["VmRSS"]).split()[0]),
    "threads": int(fields["Threads"].split()[0]),
}
totals = {field: process[field] for field in ("fds", "vmRssKiB", "vmHwmKiB", "threads")}
print(json.dumps({
    "label": label,
    "monotonicSeconds": time.monotonic(),
    "serverAlive": True,
    "processes": {"xray-server": process},
    "totals": totals,
    "fds": totals["fds"],
    "vmRssKiB": totals["vmRssKiB"],
    "vmHwmKiB": totals["vmHwmKiB"],
    "threads": totals["threads"],
}))
PY
}

expected_payload_sha256=$(sha256sum "$work/payload-4.bin" | awk '{print $1}')
verify_download() {
    local actual
    if ! actual=$(clean_curl "$@" | sha256sum | awk '{print $1}'); then
        return 1
    fi
    [[ $actual == "$expected_payload_sha256" ]]
}

failures=0
round=0
deadline=$((SECONDS + duration_min * 60))
snapshot start
while ((SECONDS < deadline)); do
    round=$((round + 1))
    # direct download (TLS origin) through the tunnel
    verify_download -sS --insecure --fail --socks5-hostname 127.0.0.1:$socks_port \
        --max-time 60 "https://127.0.0.1:$https_port/payload-4.bin" \
        || failures=$((failures + 1))
    # framed download (plain origin) through the tunnel
    verify_download -sS --fail --socks5-hostname 127.0.0.1:$socks_port \
        --max-time 60 "http://127.0.0.1:$http_port/payload-4.bin" \
        || failures=$((failures + 1))
    # fallback: direct TLS to the listener (REALITY fallback to the cover)
    verify_download -sS --insecure --fail --max-time 60 \
        "https://127.0.0.1:$server_port/payload-4.bin" || failures=$((failures + 1))
    # churn: rapid short-lived connections through the fallback path
    for _ in $(seq 1 16); do
        clean_curl -sS --insecure --max-time 5 -o /dev/null -r 0-1023 \
            "https://127.0.0.1:$server_port/payload-4.bin" 2>/dev/null \
            || failures=$((failures + 1))
    done
    snapshot "round-$round"
    sleep "$round_sleep"
done
sleep 2
snapshot end

python3 - "$out_dir/resources.jsonl" "$failures" "$round" "$duration_min" \
    "$out_dir/xray-resource-summary.json" <<'PY'
import json, statistics, sys
records = [json.loads(line) for line in open(sys.argv[1])]
failures, rounds, duration_minutes = map(int, sys.argv[2:5])
output = sys.argv[5]
start, end = records[0], records[-1]
values = [record["totals"] for record in records]
tail_offset = max(1, len(values) // 2)
tail_records = records[tail_offset:]
tail_values = values[tail_offset:]
xs = [record["monotonicSeconds"] for record in tail_records]
ys = [value["vmRssKiB"] / 1024 for value in tail_values]
if len(xs) >= 2 and len(set(xs)) > 1:
    xbar, ybar = statistics.mean(xs), statistics.mean(ys)
    denominator = sum((x - xbar) ** 2 for x in xs)
    slope = 3600 * sum(
        (x - xbar) * (y - ybar) for x, y in zip(xs, ys)
    ) / denominator
else:
    slope = 0.0
summary = {
    "schemaVersion": 1,
    "harness": "sampling-xray-resources",
    "process": "xray-server",
    "rounds": rounds,
    "transferFailures": failures,
    "durationMinutes": duration_minutes,
    "elapsedSeconds": round(end["monotonicSeconds"] - start["monotonicSeconds"], 1),
    "start": start,
    "end": end,
    "fdGrowth": end["fds"] - start["fds"],
    "threadGrowth": end["threads"] - start["threads"],
    "rssGrowthMiB": round((end["vmRssKiB"] - start["vmRssKiB"]) / 1024, 1),
    "fdPeakGrowth": max(value["fds"] for value in values) - start["fds"],
    "threadPeakGrowth": max(value["threads"] for value in values) - start["threads"],
    "rssPeakGrowthMiB": round(
        (max(value["vmHwmKiB"] for value in values) - start["vmHwmKiB"]) / 1024, 1),
    "rssTailSlopeMiBPerHour": round(slope, 3),
    "startRssMiB": round(start["vmRssKiB"] / 1024, 1),
    "endRssMiB": round(end["vmRssKiB"] / 1024, 1),
    "ok": failures == 0 and all(record.get("serverAlive") for record in records),
}
with open(output, "x") as handle:
    json.dump(summary, handle, indent=2)
print(json.dumps(summary))
PY

rr_finalize_contract
printf 'xray resource sampling complete: %s\n' "$out_dir/xray-resource-summary.json"
