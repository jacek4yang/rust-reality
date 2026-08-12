#!/usr/bin/env bash
# Formal connection-setup A/B benchmark.  A is the pinned baseline ELF and B
# is the pinned candidate ELF.  Every block is A-B-B-A or B-A-A-B, each slot
# owns fresh server/client processes and evidence, and no process or target/
# artifact is reused between slots.
set -Eeuo pipefail
export LC_ALL=C

readonly REPOSITORY="$({ cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."; pwd; })"
run_id=${RUN_ID:-}
out_dir=${OUT_DIR:-}
temporary_root=${TMPDIR:-}
port_base=${PORT_BASE:-}
baseline_bin=${RUST_REALITY_BASELINE_BIN:-}
candidate_bin=${RUST_REALITY_BIN:-}
xray_bin=${XRAY_BIN:-}
baseline_sha_expected=${RUST_REALITY_BASELINE_SHA256:-}
candidate_sha_expected=${RUST_REALITY_SHA256:-}
xray_sha_expected=${XRAY_SHA256:-}
baseline_commit=${RUST_REALITY_BASELINE_COMMIT:-}
candidate_commit=${RUST_REALITY_COMMIT:-}
baseline_identity=${RUST_REALITY_BASELINE_IDENTITY:-}
blocks=${BLOCKS:-3}
samples=${SAMPLES:-3}
concurrencies=${CONCURRENCIES:-1 8 32}
connections=${CONNS:-96}
abba_start=${ABBA_START:-baseline}
measure_mode=${MEASURE_MODE:-perf}
self_test=${SELF_TEST:-0}

die() { printf 'benchmark-setup-rate: %s\n' "$*" >&2; exit 2; }

validate_perf_csv() {
    python3 - "$1" "$2" <<'PY'
import csv, json, math, sys

source, output = sys.argv[1:]
expected = {"task-clock", "instructions", "context-switches"}
events = {}
with open(source, newline="", encoding="utf-8") as handle:
    for row in csv.reader(handle):
        if len(row) < 5:
            continue
        event = row[2].strip()
        if event not in expected:
            continue
        if event in events:
            raise SystemExit(f"duplicate perf event: {event}")
        raw_value = row[0].strip()
        if raw_value.startswith("<"):
            raise SystemExit(f"perf event was not counted: {event}: {raw_value}")
        try:
            value = float(raw_value)
            enabled_ns = float(row[3].strip())
            running_percent = float(row[4].strip().rstrip("%"))
        except ValueError as error:
            raise SystemExit(f"malformed perf event {event}: {row}") from error
        if not all(math.isfinite(item) for item in (value, enabled_ns, running_percent)):
            raise SystemExit(f"non-finite perf event: {event}")
        if value < 0 or enabled_ns <= 0 or not 95.0 <= running_percent <= 100.01:
            raise SystemExit(
                f"invalid perf event {event}: value={value}, enabled={enabled_ns}, "
                f"running={running_percent}%"
            )
        unit = row[1].strip()
        if event == "task-clock" and unit not in {"msec", "ms"}:
            raise SystemExit(f"unexpected task-clock unit: {unit!r}")
        events[event] = {
            "value": value,
            "unit": unit,
            "enabledNanoseconds": enabled_ns,
            "runningPercent": running_percent,
        }
missing = expected - events.keys()
if missing:
    raise SystemExit("missing perf events: " + ", ".join(sorted(missing)))
record = {
    "schemaVersion": 1,
    "events": events,
    "taskClockMilliseconds": events["task-clock"]["value"],
}
with open(output, "x", encoding="utf-8") as handle:
    json.dump(record, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
}

block_order() {
    local index=$1
    if ((index % 2 == 1)); then
        [[ $abba_start == baseline ]] && printf '%s\n' A B B A || printf '%s\n' B A A B
    else
        [[ $abba_start == baseline ]] && printf '%s\n' B A A B || printf '%s\n' A B B A
    fi
}

if [[ $self_test == 1 ]]; then
    run_id=self-test out_dir=/abs/out temporary_root=/abs/tmp port_base=20000
    blocks=3 abba_start=baseline
    [[ $(block_order 1 | paste -sd '') == ABBA ]]
    [[ $(block_order 2 | paste -sd '') == BAAB ]]
    [[ $(block_order 3 | paste -sd '') == ABBA ]]
    blocks=4 abba_start=candidate
    [[ $(block_order 1 | paste -sd '') == BAAB ]]
    [[ $(block_order 2 | paste -sd '') == ABBA ]]
    test_directory=$(mktemp -d)
    trap 'rm -rf -- "$test_directory"' EXIT
    printf '%s\n' \
        '12.500,msec,task-clock,100000000,100.00,,' \
        '12345,,instructions,100000000,100.00,,' \
        '10,,context-switches,100000000,100.00,,' >"$test_directory/valid.csv"
    validate_perf_csv "$test_directory/valid.csv" "$test_directory/valid.json"
    python3 - "$test_directory/valid.json" <<'PY'
import json, sys
record = json.load(open(sys.argv[1], encoding="utf-8"))
assert record["taskClockMilliseconds"] == 12.5
assert set(record["events"]) == {"task-clock", "instructions", "context-switches"}
PY
    printf '%s\n' \
        '12.500,msec,task-clock,100000000,94.99,,' \
        '12345,,instructions,100000000,100.00,,' \
        '10,,context-switches,100000000,100.00,,' >"$test_directory/invalid.csv"
    if validate_perf_csv "$test_directory/invalid.csv" "$test_directory/invalid.json" \
        >/dev/null 2>&1; then
        die 'low-running perf self-test unexpectedly passed'
    fi
    printf 'benchmark-setup-rate self-test: PASS\n'
    exit 0
fi

[[ $run_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || die 'RUN_ID is required and must be one safe component'
for name in OUT_DIR TMPDIR RUST_REALITY_BASELINE_BIN RUST_REALITY_BIN XRAY_BIN RUST_REALITY_BASELINE_IDENTITY; do
    value=${!name:-}
    [[ $value == /* ]] || die "$name must be an absolute path"
done
[[ ! -e $out_dir && ! -L $out_dir ]] || die "OUT_DIR already exists: $out_dir"
[[ -d $temporary_root && ! -L $temporary_root ]] || die 'TMPDIR must be an existing, non-symlink directory'
[[ $port_base =~ ^[0-9]+$ ]] || die 'PORT_BASE is required'
[[ $blocks =~ ^[1-9][0-9]*$ ]] && ((blocks >= 3 && blocks <= 20)) || die 'BLOCKS must be in 3..20'
[[ $samples =~ ^[1-9][0-9]*$ ]] || die 'SAMPLES must be positive'
[[ $connections =~ ^[1-9][0-9]*$ ]] || die 'CONNS must be positive'
[[ $abba_start == baseline || $abba_start == candidate ]] || die 'ABBA_START must be baseline or candidate'
[[ $measure_mode == perf || $measure_mode == strace ]] || die 'MEASURE_MODE must be perf or strace'
for value in $concurrencies; do
    [[ $value =~ ^[1-9][0-9]*$ ]] || die "invalid concurrency: $value"
done
for name in RUST_REALITY_BASELINE_SHA256 RUST_REALITY_SHA256 XRAY_SHA256; do
    value=${!name:-}
    [[ $value =~ ^[0-9a-fA-F]{64}$ ]] || die "$name must be a 64-digit SHA-256"
done
[[ $baseline_commit =~ ^[0-9a-fA-F]{40}$ ]] || die 'RUST_REALITY_BASELINE_COMMIT must be a full commit ID'
[[ $candidate_commit =~ ^[0-9a-fA-F]{7,40}$ ]] || die 'RUST_REALITY_COMMIT must identify a commit'
for program in git go jq openssl perf python3 readelf realpath sha256sum sudo; do
    command -v "$program" >/dev/null 2>&1 || die "required program unavailable: $program"
done
case "$(realpath -m "$out_dir")/" in "$REPOSITORY"/*) die 'OUT_DIR must be outside the Git worktree' ;; esac
case "$(realpath "$temporary_root")/" in "$REPOSITORY"/*) die 'TMPDIR must be outside the Git worktree' ;; esac
[[ $measure_mode != strace ]] || command -v strace >/dev/null 2>&1 || die 'strace is unavailable'
sudo -n true >/dev/null 2>&1 || die 'passwordless sudo is required'
for binary in "$baseline_bin" "$candidate_bin" "$xray_bin"; do
    [[ -x $binary ]] || die "binary is not executable: $binary"
done
baseline_bin=$(realpath "$baseline_bin")
candidate_bin=$(realpath "$candidate_bin")
xray_bin=$(realpath "$xray_bin")
[[ -f $baseline_identity && ! -L $baseline_identity ]] || die 'RUST_REALITY_BASELINE_IDENTITY must be a regular non-symlink file'
baseline_identity=$(realpath "$baseline_identity")
baseline_sha=$(sha256sum "$baseline_bin" | awk '{print $1}')
candidate_sha=$(sha256sum "$candidate_bin" | awk '{print $1}')
xray_sha=$(sha256sum "$xray_bin" | awk '{print $1}')
[[ ${baseline_sha_expected,,} == $baseline_sha ]] || die 'baseline SHA-256 mismatch'
[[ ${candidate_sha_expected,,} == $candidate_sha ]] || die 'candidate SHA-256 mismatch'
[[ ${xray_sha_expected,,} == $xray_sha ]] || die 'Xray SHA-256 mismatch'
baseline_build_id=$(readelf -n "$baseline_bin" | awk '/Build ID:/ {print $3; exit}')
candidate_build_id=$(readelf -n "$candidate_bin" | awk '/Build ID:/ {print $3; exit}')
xray_build_id=$(readelf -n "$xray_bin" | awk '/Build ID:/ {print $3; exit}')
[[ -n $baseline_build_id && -n $candidate_build_id && -n $xray_build_id ]] || die 'every binary must have a GNU Build ID'
baseline_commit=${baseline_commit,,}
jq -e --arg commit "$baseline_commit" --arg sha "$baseline_sha" '
    (.sourceCommit | ascii_downcase) == $commit
    and (.binarySha256 | ascii_downcase) == $sha
    and .sha256sumsVerified == true
' "$baseline_identity" >/dev/null || die 'baseline identity does not bind the requested commit and binary SHA-256'
baseline_identity_sha=$(sha256sum "$baseline_identity" | awk '{print $1}')
repository_head=$(git -C "$REPOSITORY" rev-parse --verify HEAD)
repository_dirty=false
[[ -z $(git -C "$REPOSITORY" status --porcelain=v1 --untracked-files=normal) ]] || repository_dirty=true
[[ $repository_dirty == false ]] || die 'formal benchmark requires a clean repository'
candidate_commit=$(git -C "$REPOSITORY" rev-parse --verify "$candidate_commit^{commit}") || die 'RUST_REALITY_COMMIT is not present in the repository'
[[ ${candidate_commit,,} == ${repository_head,,} ]] || die 'RUST_REALITY_COMMIT must match the harness repository HEAD'
grep -aFq -- "$candidate_commit" "$candidate_bin" || die 'candidate ELF does not embed RUST_REALITY_COMMIT'

slot_count=$((blocks * 4))
port_count=$((2 + slot_count * 2))
((port_base >= 1024 && port_base + port_count - 1 <= 65535)) || die 'PORT_BASE does not leave a large enough port block'
python3 - "$port_base" "$port_count" <<'PY'
import socket, sys
base, count = map(int, sys.argv[1:])
sockets = []
try:
    for port in range(base, base + count):
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        sock.bind(("127.0.0.1", port))
        sockets.append(sock)
finally:
    for sock in sockets:
        sock.close()
PY

mkdir -m 700 -p "$(dirname "$out_dir")"
mkdir -m 700 "$out_dir"
work=$(mktemp -d "$temporary_root/rust-reality-setup-rate.XXXXXX")
declare -a tracked_pids=() tracked_starts=() tracked_names=()
last_pid=

pid_start_time() {
    python3 - "$1" <<'PY'
from pathlib import Path
import sys
raw = Path(f"/proc/{sys.argv[1]}/stat").read_text()
end = raw.rfind(")")
print(raw[end + 2:].split()[19])
PY
}
pid_owned() {
    local pid=$1 expected=$2 observed
    [[ -r /proc/$pid/stat ]] || return 1
    observed=$(pid_start_time "$pid" 2>/dev/null) || return 1
    [[ $observed == "$expected" ]]
}
track_last() {
    local name=$1 pid=$2 start
    start=$(pid_start_time "$pid") || die "$name exited before registration"
    tracked_names+=("$name"); tracked_pids+=("$pid"); tracked_starts+=("$start")
    last_pid=$pid
}
stop_tracked() {
    local pid=$1 index
    for index in "${!tracked_pids[@]}"; do
        [[ ${tracked_pids[index]} == "$pid" ]] || continue
        if pid_owned "$pid" "${tracked_starts[index]}"; then
            kill -TERM "$pid" 2>/dev/null || true
            for _ in {1..50}; do pid_owned "$pid" "${tracked_starts[index]}" || break; sleep 0.02; done
            pid_owned "$pid" "${tracked_starts[index]}" && kill -KILL "$pid" 2>/dev/null || true
        fi
        wait "$pid" 2>/dev/null || true
        tracked_pids[index]=
        return
    done
}
cleanup() {
    local status=$? index pid
    trap - EXIT INT TERM
    set +e
    for ((index=${#tracked_pids[@]} - 1; index >= 0; index--)); do
        pid=${tracked_pids[index]}
        [[ -n $pid ]] && stop_tracked "$pid"
    done
    if [[ -d $work && $work == "$temporary_root"/rust-reality-setup-rate.* ]]; then rm -rf -- "$work"; fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_port() {
    local port=$1 pid=$2 start
    start=$(pid_start_time "$pid") || return 1
    python3 - "$port" "$pid" "$start" <<'PY'
import os, socket, sys, time
port, pid, expected = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
deadline = time.monotonic() + 10
while time.monotonic() < deadline:
    try:
        raw = open(f"/proc/{pid}/stat").read(); observed = raw[raw.rfind(")") + 2:].split()[19]
    except OSError:
        raise SystemExit("registered process exited")
    if observed != expected: raise SystemExit("PID identity changed")
    with socket.socket() as sock:
        sock.settimeout(.1)
        if sock.connect_ex(("127.0.0.1", port)) == 0: raise SystemExit(0)
    time.sleep(.02)
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
        part = sock.recv(n-len(out))
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
    with open(output,"x") as handle: json.dump([],handle)
    raise SystemExit(0)
rows=[]
for conc in concurrencies:
    for sample in range(samples):
        wall0=time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as pool:
            values=list(pool.map(one, range(conns)))
        good=sorted(x for x in values if x is not None); wall=time.perf_counter()-wall0
        row={"block":block,"position":position,"implementation":implementation,
             "concurrency":conc,"sampleIndex":sample,"connections":len(good),
             "failed":len(values)-len(good),"wallSeconds":wall}
        if good:
            row.update(connectionsPerSecond=len(good)/wall,p50Seconds=good[len(good)//2],
                       p95Seconds=good[min(len(good)-1,int(len(good)*.95))],
                       p99Seconds=good[min(len(good)-1,int(len(good)*.99))])
        rows.append(row)
with open(output,"x") as handle: json.dump(rows,handle,indent=2)
if len(rows)!=samples*len(concurrencies) or any(r["failed"] or r["connections"]!=conns for r in rows):
    raise SystemExit("incomplete setup samples")
PY

cd "$REPOSITORY"
printf '%s' "$(printf 'x%.0s' {1..256})" >"$work/payload.bin"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
    -keyout "$work/origin.key" -out "$work/origin.crt" >/dev/null 2>&1
(cd scripts/bench-origin && go build -o "$work/bench-origin" .)
http_port=$port_base; https_port=$((port_base + 1))
"$work/bench-origin" --port "$http_port" --payload-dir "$work" --put-log "$work/http-put.jsonl" \
    >"$out_dir/origin-http.log" 2>&1 & track_last origin-http "$!"; http_pid=$last_pid
"$work/bench-origin" --port "$https_port" --payload-dir "$work" --put-log "$work/https-put.jsonl" \
    --tls-cert "$work/origin.crt" --tls-key "$work/origin.key" >"$out_dir/origin-https.log" 2>&1 &
track_last origin-https "$!"; https_pid=$last_pid
wait_port "$http_port" "$http_pid"; wait_port "$https_port" "$https_pid"

python3 - "$out_dir/order.json" "$blocks" "$abba_start" "$port_base" <<'PY'
import json, sys
path, blocks, start, base = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
rows=[]
for block in range(1,blocks+1):
    baseline_first=(block%2==1)==(start=="baseline")
    order=["baseline","candidate","candidate","baseline"] if baseline_first else ["candidate","baseline","baseline","candidate"]
    for position,implementation in enumerate(order,1):
        ordinal=(block-1)*4+(position-1)
        rows.append({"block":block,"position":position,"implementation":implementation,
                     "serverPort":base+2+ordinal*2,"socksPort":base+3+ordinal*2})
json.dump({"schemaVersion":1,"method":"alternating balanced ABBA blocks","slots":rows},open(path,"x"),indent=2)
PY

jq -n --arg runId "$run_id" --arg startedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg baselineBin "$baseline_bin" --arg baselineSha "$baseline_sha" --arg baselineBuildId "$baseline_build_id" --arg baselineCommit "$baseline_commit" --arg baselineIdentity "$baseline_identity" --arg baselineIdentitySha "$baseline_identity_sha" \
    --arg candidateBin "$candidate_bin" --arg candidateSha "$candidate_sha" --arg candidateBuildId "$candidate_build_id" --arg candidateCommit "$candidate_commit" \
    --arg xrayBin "$xray_bin" --arg xraySha "$xray_sha" --arg xrayBuildId "$xray_build_id" \
    --arg repositoryHead "$repository_head" --argjson repositoryDirty "$repository_dirty" --arg mode "$measure_mode" --arg concurrencies "$concurrencies" --argjson blocks "$blocks" --argjson samples "$samples" --argjson conns "$connections" \
    --argjson portBase "$port_base" --argjson portCount "$port_count" \
    '{schemaVersion:2,runId:$runId,startedAt:$startedAt,repository:{head:$repositoryHead,dirty:$repositoryDirty},method:"balanced block ABBA",blocks:$blocks,samplesPerSlot:$samples,connectionsPerSample:$conns,concurrencies:$concurrencies,measureMode:$mode,ports:{address:"127.0.0.1",base:$portBase,count:$portCount},baseline:{path:$baselineBin,sha256:$baselineSha,buildId:$baselineBuildId,commit:$baselineCommit,identity:{path:$baselineIdentity,sha256:$baselineIdentitySha}},candidate:{path:$candidateBin,sha256:$candidateSha,buildId:$candidateBuildId,commit:$candidateCommit},xray:{path:$xrayBin,sha256:$xraySha,buildId:$xrayBuildId}}' >"$out_dir/environment.json"

slot_index=0
while IFS=$'\t' read -r block position implementation server_port socks_port; do
    slot_index=$((slot_index + 1))
    slot=$(printf 'block-%02d-slot-%02d-%s' "$block" "$position" "$implementation")
    slot_dir="$out_dir/slots/$slot"; mkdir -p "$slot_dir"
    if [[ $implementation == baseline ]]; then binary=$baseline_bin; binary_sha=$baseline_sha; binary_build_id=$baseline_build_id; else binary=$candidate_bin; binary_sha=$candidate_sha; binary_build_id=$candidate_build_id; fi
    "$binary" config generate standalone --listen 127.0.0.1 --port "$server_port" \
        --target "127.0.0.1:$https_port" --server-name localhost >"$work/$slot.raw.json" 2>"$slot_dir/generate.log"
    public_key=$(sed -n 's/^REALITY public key for the client: //p' "$slot_dir/generate.log")
    uuid=$(jq -er '.inbounds[0].settings.clients[0].id' "$work/$slot.raw.json")
    short_id=$(jq -er '.inbounds[0].settings.clients[0].shortIds[0]' "$work/$slot.raw.json")
    jq --arg cache "$work/assets-$slot" '.log.level="warn"|.assets.cacheDirectory=$cache' "$work/$slot.raw.json" >"$work/$slot.server.json"
    jq -n --arg uuid "$uuid" --arg pk "$public_key" --arg sid "$short_id" --argjson server "$server_port" --argjson socks "$socks_port" \
        '{log:{loglevel:"warning"},inbounds:[{listen:"127.0.0.1",port:$socks,protocol:"socks",settings:{auth:"noauth",udp:false}}],outbounds:[{protocol:"vless",settings:{vnext:[{address:"127.0.0.1",port:$server,users:[{id:$uuid,encryption:"none",flow:"xtls-rprx-vision"}]}]},streamSettings:{network:"tcp",security:"reality",realitySettings:{fingerprint:"chrome",serverName:"localhost",publicKey:$pk,shortId:$sid,spiderX:"/"}}}]}' >"$work/$slot.client.json"
    if [[ $measure_mode == strace ]]; then
        strace --kill-on-exit -f -qq -c -e trace=recvfrom,recvmsg,read -o "$slot_dir/strace.txt" \
            "$binary" serve --config "$work/$slot.server.json" >"$slot_dir/server.log" 2>&1 &
        track_last "$slot-strace" "$!"; wrapper_pid=$last_pid; server_pid=
        for _ in {1..250}; do
            for child in $(cat "/proc/$wrapper_pid/task/$wrapper_pid/children" 2>/dev/null || true); do
                if [[ $(readlink -f "/proc/$child/exe" 2>/dev/null || true) == "$binary" ]]; then server_pid=$child; break 2; fi
            done
            sleep .02
        done
        [[ $server_pid =~ ^[1-9][0-9]*$ ]] || die "cannot identify straced server in $slot"
    else
        "$binary" serve --config "$work/$slot.server.json" >"$slot_dir/server.log" 2>&1 &
        track_last "$slot-server" "$!"; server_pid=$last_pid; wrapper_pid=
    fi
    [[ $(sha256sum "/proc/$server_pid/exe" | awk '{print $1}') == "$binary_sha" ]] || die "server ELF mismatch in $slot"
    "$xray_bin" run -config "$work/$slot.client.json" >"$slot_dir/client.log" 2>&1 &
    track_last "$slot-client" "$!"; client_pid=$last_pid
    wait_port "$server_port" "$server_pid"; wait_port "$socks_port" "$client_pid"
    python3 "$work/driver.py" 0 "$connections" "$socks_port" "$http_port" "$concurrencies" "$slot_dir/warmup.json" "$implementation" "$block" "$position"
    if [[ $measure_mode == perf ]]; then
        sudo -n perf stat --no-big-num -x, -e task-clock,instructions,context-switches -p "$server_pid" -o "$slot_dir/perf.csv" -- \
            python3 "$work/driver.py" "$samples" "$connections" "$socks_port" "$http_port" "$concurrencies" "$slot_dir/samples.json" "$implementation" "$block" "$position"
        validate_perf_csv "$slot_dir/perf.csv" "$slot_dir/perf.json"
    else
        python3 "$work/driver.py" "$samples" "$connections" "$socks_port" "$http_port" "$concurrencies" "$slot_dir/samples.json" "$implementation" "$block" "$position"
    fi
    jq -n --arg implementation "$implementation" --arg binary "$binary" --arg sha "$binary_sha" --arg buildId "$binary_build_id" \
        --argjson block "$block" --argjson position "$position" --argjson serverPid "$server_pid" --argjson serverPort "$server_port" --argjson socksPort "$socks_port" \
        '{block:$block,position:$position,implementation:$implementation,binary:{path:$binary,sha256:$sha,buildId:$buildId},process:{serverPid:$serverPid},ports:{server:$serverPort,socks:$socksPort}}' >"$slot_dir/identity.json"
    stop_tracked "$client_pid"
    [[ -z $wrapper_pid ]] && stop_tracked "$server_pid" || stop_tracked "$wrapper_pid"
    if [[ $measure_mode == perf ]]; then [[ -s $slot_dir/perf.json ]] || die "missing validated perf evidence in $slot"; else [[ -s $slot_dir/strace.txt ]] || die "missing strace evidence in $slot"; fi
    [[ $(sha256sum "$binary" | awk '{print $1}') == "$binary_sha" ]] || die "$implementation binary changed after $slot"
    [[ $(sha256sum "$xray_bin" | awk '{print $1}') == "$xray_sha" ]] || die "Xray changed after $slot"
done < <(jq -r '.slots[]|[.block,.position,.implementation,.serverPort,.socksPort]|@tsv' "$out_dir/order.json")

python3 - "$out_dir" "$blocks" "$samples" "$connections" "$concurrencies" "$measure_mode" <<'PY'
import json, pathlib, random, statistics, sys
root=pathlib.Path(sys.argv[1]); blocks,samples,connections=int(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4]); concurrencies=[int(x) for x in sys.argv[5].split()]; mode=sys.argv[6]
order=json.load(open(root/'order.json'))['slots']; slot_dirs=sorted((root/'slots').iterdir())
if len(order)!=blocks*4 or len(slot_dirs)!=blocks*4: raise SystemExit('missing ABBA slots')
all_rows=[]; slots=[]; perf_rows=[]
for slot in slot_dirs:
    identity=json.load(open(slot/'identity.json')); rows=json.load(open(slot/'samples.json'))
    if len(rows)!=samples*len(concurrencies): raise SystemExit(f'missing samples: {slot}')
    if any(r['failed'] or r['connections']!=connections for r in rows): raise SystemExit(f'failed setup sample: {slot}')
    all_rows.extend(rows); slots.append(identity)
    if mode == 'perf':
        perf = json.load(open(slot/'perf.json'))
        perf_rows.append({**identity, **perf})
expected={(row['block'],row['position']):(row['implementation'],row['serverPort'],row['socksPort']) for row in order}
observed={(row['block'],row['position']):(row['implementation'],row['ports']['server'],row['ports']['socks']) for row in slots}
if observed != expected: raise SystemExit('slot identity/order does not match order manifest')
with open(root/'raw-samples.jsonl','x') as out:
    for row in all_rows: out.write(json.dumps(row,sort_keys=True)+'\n')
cells={}
for conc in concurrencies:
    ratios=[]; block_rows=[]
    for block in range(1,blocks+1):
        values={}
        for impl in ('baseline','candidate'):
            observed=[r['connectionsPerSecond'] for r in all_rows if r['block']==block and r['implementation']==impl and r['concurrency']==conc]
            if len(observed)!=2*samples: raise SystemExit('unbalanced block')
            values[impl]=statistics.median(observed)
        ratio=values['candidate']/values['baseline']; ratios.append(ratio); block_rows.append({**values,'candidateVsBaseline':ratio})
    rng=random.Random(0x525200+conc); boot=sorted(statistics.median(rng.choices(ratios,k=len(ratios))) for _ in range(20000))
    cells[str(conc)]={'blocks':block_rows,'medianCandidateVsBaseline':statistics.median(ratios),'bootstrap95':[boot[500],boot[19499]]}
cpu_summary=None
if mode == 'perf':
    per_slot_connections=samples*len(concurrencies)*connections
    cpu_blocks=[]; cpu_ratios=[]
    for block in range(1,blocks+1):
        values={}
        for impl in ('baseline','candidate'):
            observed=[r['taskClockMilliseconds']*1000/per_slot_connections for r in perf_rows if r['block']==block and r['implementation']==impl]
            if len(observed)!=2: raise SystemExit('unbalanced perf block')
            values[impl]=statistics.median(observed)
        ratio=values['candidate']/values['baseline']; cpu_ratios.append(ratio); cpu_blocks.append({**values,'candidateVsBaseline':ratio})
    rng=random.Random(0x5252C0); boot=sorted(statistics.median(rng.choices(cpu_ratios,k=len(cpu_ratios))) for _ in range(20000))
    cpu_summary={'unit':'microsecondsPerConnection','blocks':cpu_blocks,'medianCandidateVsBaseline':statistics.median(cpu_ratios),'bootstrap95':[boot[500],boot[19499]]}
summary={'schemaVersion':2,'status':'COMPLETE','performanceVerdict':'NOT_EVALUATED','method':'alternating balanced ABBA blocks; block bootstrap','slotCount':len(slots),'rawSampleCount':len(all_rows),'cells':cells,'serverCpuPerConnection':cpu_summary,'failures':0}
json.dump(summary,open(root/'summary.json','x'),indent=2); print(json.dumps(summary))
PY

[[ $(sha256sum "$baseline_bin" | awk '{print $1}') == "$baseline_sha" ]] || die 'baseline changed during run'
[[ $(sha256sum "$candidate_bin" | awk '{print $1}') == "$candidate_sha" ]] || die 'candidate changed during run'
[[ $(sha256sum "$xray_bin" | awk '{print $1}') == "$xray_sha" ]] || die 'Xray changed during run'
jq -e --argjson slots "$slot_count" '.status=="COMPLETE" and .slotCount==$slots and .failures==0' "$out_dir/summary.json" >/dev/null || die 'aggregate gate failed'
printf 'setup ABBA complete: %s\n' "$out_dir"
