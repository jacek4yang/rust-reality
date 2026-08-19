#!/usr/bin/env bash
# Setup-rate comparison where the SERVER is either rust-reality or Xray
# (README gap G1): scripts/benchmark-setup-rate.sh drives only rust servers
# and uses Xray solely as the SOCKS client.  Here both implementations serve
# the identical VLESS + REALITY + xtls-rprx-vision shape against the same
# loopback origins, the same unmodified Xray SOCKS5 client drives both, and
# blocks interleave rust/xray/xray/rust (balanced ABBA) so drift cannot favor
# one side.  Output summary.json keeps the setup-rate cell schema
# (per-concurrency p50/p95/p99 setup latency + conn/s), plus optional
# perf-stat server CPU per connection (MEASURE_MODE=perf).
#
# Env: RUN_ID OUT_DIR TMPDIR PORT_BASE RUST_REALITY_BIN RUST_REALITY_SHA256
# XRAY_BIN XRAY_SHA256 EXPECTED_SOURCE_COMMIT (formal), BLOCKS (3), SAMPLES
# (3), CONNS (96), CONCURRENCIES ("1 8 32"), ABBA_START (rust), MEASURE_MODE
# (perf formal / wall exploratory), EXPLORATORY=1 for a fast unlocked-by-
# contract run (wrap the whole script in `flock -x /tmp/v151-bench.lock`).
set -Eeuo pipefail
export LC_ALL=C

repository=$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$repository/scripts/benchmark-contract.sh"
rust_bin=${RUST_REALITY_BIN:-target/release/rust-reality}
xray=${XRAY_BIN:-../artifacts/xray-reference-v26.7.28}
blocks=${BLOCKS:-3}
samples=${SAMPLES:-3}
connections=${CONNS:-96}
concurrencies=${CONCURRENCIES:-1 8 32}
abba_start=${ABBA_START:-rust}
measure_mode=${MEASURE_MODE:-}
[[ $measure_mode == wall || $measure_mode == perf ]] ||
    measure_mode=$([[ ${EXPLORATORY:-0} == 1 ]] && echo wall || echo perf)
[[ $blocks =~ ^[1-9][0-9]*$ ]] && ((blocks >= 1 && blocks <= 20)) ||
    { echo "BLOCKS must be in 1..20" >&2; exit 2; }
[[ $samples =~ ^[1-9][0-9]*$ && $connections =~ ^[1-9][0-9]*$ ]] ||
    { echo "SAMPLES and CONNS must be positive integers" >&2; exit 2; }
[[ $abba_start == rust || $abba_start == xray ]] ||
    { echo "ABBA_START must be rust or xray" >&2; exit 2; }
for value in $concurrencies; do
    [[ $value =~ ^[1-9][0-9]*$ ]] || { echo "invalid concurrency: $value" >&2; exit 2; }
done
if [[ $measure_mode == perf ]]; then
    command -v perf >/dev/null || { echo "perf is unavailable" >&2; exit 2; }
    sudo -n true >/dev/null 2>&1 ||
        { echo "MEASURE_MODE=perf requires passwordless sudo" >&2; exit 2; }
fi

slot_count=$((blocks * 4))
port_width=$((slot_count * 2 + 8))
# Default the port block above the ephemeral range (32768-60999): the load
# driver's own outbound sockets are allocated from that range and would
# collide with an auto-picked in-range block mid-run.
if [[ -z ${PORT_BASE:-} ]]; then
    PORT_BASE=$(python3 - "$port_width" <<'PY'
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
rr_contract_init "$repository" benchmark-setup-rate-xray benchmarks/final "$port_width"
rr_register_binary rust-reality "$rust_bin" "${RUST_REALITY_SHA256:-}" rust \
    "${EXPECTED_SOURCE_COMMIT:-}"
rust_bin=${RR_BINARY_PATHS[rust-reality]}
rr_register_binary xray "$xray" "${XRAY_SHA256:-}" xray
xray=${RR_BINARY_PATHS[xray]}
rr_register_harness_tree "$repository/scripts/bench-origin"
rr_write_contract_metadata
out_dir=$RR_OUT_DIR
temporary_root=$RR_TMPDIR

for program in go jq openssl python3 sha256sum; do
    command -v "$program" >/dev/null || { echo "missing: $program" >&2; exit 1; }
done

work=$(mktemp -d "$temporary_root/rust-reality-setup-rate-xray.XXXXXX")
declare -a pids=()
declare -A active_starts=()
last_pid=

pid_start_time() { rr_pid_starttime "$1"; }

pid_is_owned() {
    local pid=$1 observed
    observed=$(pid_start_time "$pid" 2>/dev/null) || return 1
    [[ $observed == "${active_starts[$pid]:-}" ]]
}

start_logged() {
    local log=$1
    shift
    "$@" >"$log" 2>&1 &
    last_pid=$!
    pids+=("$last_pid")
    active_starts["$last_pid"]=$(pid_start_time "$last_pid") || {
        echo "cannot identify started process PID $last_pid" >&2
        return 1
    }
    case $1 in
        "$rust_bin" | "$xray") rr_register_pid "$last_pid" "$1" ;;
        *) rr_register_pid "$last_pid" ;;
    esac
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
    if [[ -d $work && $work == "$temporary_root"/rust-reality-setup-rate-xray.* ]]; then
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

cat >"$work/driver.py" <<'PY'
import concurrent.futures, json, socket, sys, time
samples, conns, socks, origin = map(int, sys.argv[1:5])
concurrencies = [int(x) for x in sys.argv[5].split()]
output, implementation, block, position = sys.argv[6], sys.argv[7], int(sys.argv[8]), int(sys.argv[9])
def exact(sock, n):
    out = b""
    while len(out) < n:
        part = sock.recv(n - len(out))
        if not part: raise OSError("short SOCKS reply")
        out += part
    return out
def one(_):
    started = time.perf_counter()
    try:
        with socket.create_connection(("127.0.0.1", socks), timeout=30) as sock:
            sock.sendall(b"\x05\x01\x00")
            if exact(sock, 2) != b"\x05\x00": return None
            sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + origin.to_bytes(2, "big"))
            reply = exact(sock, 10)
            if reply[1] != 0: return None
            sock.sendall(f"GET /payload.bin HTTP/1.0\r\nHost: 127.0.0.1:{origin}\r\n\r\n".encode())
            response = bytearray()
            while b"\r\n\r\n" not in response:
                part = sock.recv(4096)
                if not part or len(response) + len(part) > 65536: return None
                response.extend(part)
            header, body = bytes(response).split(b"\r\n\r\n", 1)
            status = header.split(b"\r\n", 1)[0].split()
            if len(status) < 2 or status[1] != b"200": return None
            while not body:
                body = sock.recv(1)
                if not body: return None
            if body[:1] != b"x": return None
        return time.perf_counter() - started
    except OSError: return None
if samples == 0:
    for _ in range(3):
        if one(0) is None: raise SystemExit("warm-up failed")
    raise SystemExit(0)
rows = []
for conc in concurrencies:
    for sample in range(samples):
        wall0 = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as pool:
            values = list(pool.map(one, range(conns)))
        good = sorted(x for x in values if x is not None); wall = time.perf_counter() - wall0
        row = {"block": block, "position": position, "implementation": implementation,
               "concurrency": conc, "sampleIndex": sample, "connections": len(good),
               "failed": len(values) - len(good), "wallSeconds": wall,
               "latenciesSeconds": good}
        if good:
            row.update(connectionsPerSecond=len(good) / wall,
                       p50Seconds=good[len(good) // 2],
                       p95Seconds=good[min(len(good) - 1, int(len(good) * .95))],
                       p99Seconds=good[min(len(good) - 1, int(len(good) * .99))])
        rows.append(row)
with open(output, "x") as handle: json.dump(rows, handle, indent=2)
if len(rows) != samples * len(concurrencies) or any(
        r["failed"] or r["connections"] != conns for r in rows):
    raise SystemExit("incomplete setup samples")
PY

cd "$repository"
printf '%s' "$(printf 'x%.0s' {1..256})" >"$work/payload.bin"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
    -keyout "$work/origin.key" -out "$work/origin.crt" >/dev/null 2>&1
(cd scripts/bench-origin && GOFLAGS=-buildvcs=false go build -o "$work/bench-origin" .)
http_port=$(rr_next_port); https_port=$(rr_next_port)
start_logged "$out_dir/origin-http.log" "$work/bench-origin" --port "$http_port" \
    --payload-dir "$work" --put-log "$work/http-put.jsonl"
http_pid=$last_pid
start_logged "$out_dir/origin-https.log" "$work/bench-origin" --port "$https_port" \
    --payload-dir "$work" --put-log "$work/https-put.jsonl" \
    --tls-cert "$work/origin.crt" --tls-key "$work/origin.key"
https_pid=$last_pid
wait_port "$http_port" "$http_pid"
wait_port "$https_port" "$https_pid"

make_client() { # <server-port> <socks-port> <public-key> <uuid> <short-id> <output>
    jq -n --arg uuid "$4" --arg pk "$3" --arg sid "$5" \
        --argjson server "$1" --argjson socks "$2" \
        '{log:{loglevel:"warning"},inbounds:[{listen:"127.0.0.1",port:$socks,protocol:"socks",settings:{auth:"noauth",udp:false}}],outbounds:[{protocol:"vless",settings:{vnext:[{address:"127.0.0.1",port:$server,users:[{id:$uuid,encryption:"none",flow:"xtls-rprx-vision"}]}]},streamSettings:{network:"tcp",security:"reality",realitySettings:{fingerprint:"chrome",serverName:"localhost",publicKey:$pk,shortId:$sid,spiderX:"/"}}}]}' \
        >"$6"
}

# Pre-generate the fixed Xray server key pair once (all Xray slots share it;
# the rust slots get fresh generated key pairs per slot, matching
# benchmark-setup-rate.sh slot freshness).
"$xray" x25519 >"$work/xray.keys"
xray_private_key=$(sed -n 's/^PrivateKey: //p' "$work/xray.keys")
xray_public_key=$(sed -n 's/^Password (PublicKey): //p' "$work/xray.keys")
[[ -n $xray_private_key && -n $xray_public_key ]] ||
    { echo "xray x25519 produced no key pair" >&2; exit 1; }

python3 - "$out_dir/order.json" "$blocks" "$abba_start" <<'PY'
import json, sys
path, blocks, start = sys.argv[1], int(sys.argv[2]), sys.argv[3]
rows = []
for block in range(1, blocks + 1):
    rust_first = (block % 2 == 1) == (start == "rust")
    order = ["rust", "xray", "xray", "rust"] if rust_first else ["xray", "rust", "rust", "xray"]
    for position, implementation in enumerate(order, 1):
        rows.append({"block": block, "position": position, "implementation": implementation})
json.dump({"schemaVersion": 1, "method": "alternating balanced ABBA blocks",
           "slots": rows}, open(path, "x"), indent=2)
PY

while IFS=$'\t' read -r block position implementation; do
    slot=$(printf 'block-%02d-slot-%02d-%s' "$block" "$position" "$implementation")
    slot_dir="$out_dir/slots/$slot"; mkdir -p "$slot_dir"
    server_port=$(rr_next_port); socks_port=$(rr_next_port)
    if [[ $implementation == rust ]]; then
        "$rust_bin" config generate standalone --listen 127.0.0.1 --port "$server_port" \
            --target "127.0.0.1:$https_port" --server-name localhost \
            >"$work/$slot.raw.json" 2>"$slot_dir/generate.log"
        public_key=$(sed -n 's/^REALITY public key for the client: //p' "$slot_dir/generate.log")
        uuid=$(jq -er '.inbounds[0].settings.clients[0].id' "$work/$slot.raw.json")
        short_id=$(jq -er '.inbounds[0].settings.clients[0].shortIds[0]' "$work/$slot.raw.json")
        jq --arg cache "$work/assets-$slot" '.log.level="warn"|.assets.cacheDirectory=$cache' \
            "$work/$slot.raw.json" >"$work/$slot.server.json"
        start_logged "$slot_dir/server.log" "$rust_bin" serve --config "$work/$slot.server.json"
        server_pid=$last_pid
    else
        uuid=$(python3 -c 'import uuid; print(uuid.uuid4())')
        short_id=$(openssl rand -hex 8)
        jq -n --arg uuid "$uuid" --arg pk "$xray_private_key" --arg sid "$short_id" \
            --arg target "127.0.0.1:$https_port" --argjson port "$server_port" \
            '{log:{loglevel:"warning"},inbounds:[{listen:"127.0.0.1",port:$port,protocol:"vless",settings:{clients:[{id:$uuid,flow:"xtls-rprx-vision"}],decryption:"none"},streamSettings:{network:"tcp",security:"reality",realitySettings:{show:false,target:$target,xver:0,serverNames:["localhost"],privateKey:$pk,shortIds:[$sid]}}}],outbounds:[{tag:"direct",protocol:"freedom",settings:{finalRules:[{action:"allow"}]}}]}' \
            >"$work/$slot.server.json"
        cp "$work/$slot.server.json" "$slot_dir/server-config.json"
        start_logged "$slot_dir/server.log" "$xray" run -config "$work/$slot.server.json"
        server_pid=$last_pid
    fi
    make_client "$server_port" "$socks_port" \
        "$([[ $implementation == rust ]] && echo "$public_key" || echo "$xray_public_key")" \
        "$uuid" "$short_id" "$work/$slot.client.json"
    cp "$work/$slot.client.json" "$slot_dir/client-config.json"
    [[ $implementation == rust ]] && cp "$work/$slot.server.json" "$slot_dir/server-config.json"
    start_logged "$slot_dir/client.log" "$xray" run -config "$work/$slot.client.json"
    client_pid=$last_pid
    wait_port "$server_port" "$server_pid"
    wait_port "$socks_port" "$client_pid"
    python3 "$work/driver.py" 0 "$connections" "$socks_port" "$http_port" \
        "$concurrencies" /dev/null "$implementation" "$block" "$position"
    if [[ $measure_mode == perf ]]; then
        sudo -n perf stat --no-big-num -x, -e task-clock -p "$server_pid" \
            -o "$slot_dir/perf.csv" -- \
            python3 "$work/driver.py" "$samples" "$connections" "$socks_port" "$http_port" \
                "$concurrencies" "$slot_dir/samples.json" "$implementation" "$block" "$position"
        task_clock_ms=$(awk -F, '$3 == "task-clock" {print $1}' "$slot_dir/perf.csv")
        [[ $task_clock_ms =~ ^[0-9]+(\.[0-9]+)?$ ]] ||
            { echo "perf stat produced no task-clock in $slot" >&2; exit 1; }
    else
        task_clock_ms=
        python3 "$work/driver.py" "$samples" "$connections" "$socks_port" "$http_port" \
            "$concurrencies" "$slot_dir/samples.json" "$implementation" "$block" "$position"
    fi
    jq -n --arg implementation "$implementation" --argjson block "$block" \
        --argjson position "$position" --argjson serverPid "$server_pid" \
        --argjson serverPort "$server_port" --argjson socksPort "$socks_port" \
        --arg taskClockMs "${task_clock_ms:-}" \
        '{block:$block,position:$position,implementation:$implementation,
          process:{serverPid:$serverPid},ports:{server:$serverPort,socks:$socksPort},
          serverTaskClockMs:(if $taskClockMs == "" then null else ($taskClockMs|tonumber) end)}' \
        >"$slot_dir/identity.json"
    stop_pid "$client_pid"
    stop_pid "$server_pid"
done < <(jq -r '.slots[]|[.block,.position,.implementation]|@tsv' "$out_dir/order.json")

python3 - "$out_dir" "$blocks" "$samples" "$connections" "$concurrencies" "$measure_mode" <<'PY'
import json, pathlib, statistics, sys
root = pathlib.Path(sys.argv[1])
blocks, samples, connections = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
concurrencies = [int(x) for x in sys.argv[5].split()]
mode = sys.argv[6]
order = json.load(open(root / "order.json"))["slots"]
slot_dirs = sorted((root / "slots").iterdir())
if len(order) != blocks * 4 or len(slot_dirs) != blocks * 4:
    raise SystemExit("missing ABBA slots")
all_rows, identities = [], []
for slot in slot_dirs:
    identity = json.load(open(slot / "identity.json"))
    rows = json.load(open(slot / "samples.json"))
    if len(rows) != samples * len(concurrencies):
        raise SystemExit(f"missing samples: {slot}")
    if any(r["failed"] or r["connections"] != connections for r in rows):
        raise SystemExit(f"failed setup sample: {slot}")
    all_rows.extend(rows)
    identities.append(identity)
expected = {(r["block"], r["position"]): r["implementation"] for r in order}
observed = {(r["block"], r["position"]): r["implementation"] for r in identities}
if observed != expected:
    raise SystemExit("slot identity/order does not match order manifest")


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


cells = {}
for conc in concurrencies:
    per_impl = {}
    for impl in ("rust", "xray"):
        rows = [r for r in all_rows
                if r["implementation"] == impl and r["concurrency"] == conc]
        latencies = [v for r in rows for v in r["latenciesSeconds"]]
        rates = [r["connectionsPerSecond"] for r in rows]
        per_impl[impl] = {
            "samples": len(rows),
            "connections": len(latencies),
            "connectionsPerSecondMedian": statistics.median(rates),
            "p50Seconds": percentile(latencies, 0.50),
            "p95Seconds": percentile(latencies, 0.95),
            "p99Seconds": percentile(latencies, 0.99),
        }
    cells[str(conc)] = {
        **per_impl,
        "rustVsXrayConnPerSecondRatio":
            per_impl["rust"]["connectionsPerSecondMedian"]
            / per_impl["xray"]["connectionsPerSecondMedian"],
        "xrayVsRustP50LatencyRatio":
            per_impl["xray"]["p50Seconds"] / per_impl["rust"]["p50Seconds"],
    }
cpu_summary = None
if mode == "perf":
    per_slot_connections = samples * len(concurrencies) * connections
    cpu = {}
    for impl in ("rust", "xray"):
        values = [
            i["serverTaskClockMs"] * 1000 / per_slot_connections
            for i in identities if i["implementation"] == impl
        ]
        cpu[impl] = {"microsecondsPerConnectionMedian": statistics.median(values),
                     "slots": len(values)}
    cpu_summary = {**cpu,
                   "xrayVsRustCpuRatio":
                       cpu["xray"]["microsecondsPerConnectionMedian"]
                       / cpu["rust"]["microsecondsPerConnectionMedian"]}
with open(root / "raw-samples.jsonl", "x") as handle:
    for row in all_rows:
        row = {k: v for k, v in row.items() if k != "latenciesSeconds"}
        handle.write(json.dumps(row, sort_keys=True) + "\n")
summary = {"schemaVersion": 1, "status": "COMPLETE",
           "performanceVerdict": "NOT_EVALUATED",
           "method": "alternating balanced ABBA blocks; Xray serves one leg",
           "slotCount": len(identities), "rawSampleCount": len(all_rows),
           "cells": cells, "serverCpuPerConnection": cpu_summary, "failures": 0}
json.dump(summary, open(root / "summary.json", "x"), indent=2)
print(json.dumps(summary))
PY

rr_finalize_contract
printf 'setup-rate xray comparison complete: %s\n' "$out_dir"
