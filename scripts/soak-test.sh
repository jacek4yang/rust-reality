#!/usr/bin/env bash
# Bounded loopback soak: mixed tunnel traffic + connection churn against a
# local rust-reality server, with resource snapshots proving nothing leaks.
#
# Workload mix per round: direct download (TLS origin), framed download
# (plain origin), fallback (direct-to-listener), and rapid connect/drop
# churn. A fail-closed distributed preflight additionally proves one real
# cover-NST/sequence-one Handoff resume and one byte-exact NXR transfer.
# /proc snapshots (FDs, RSS, threads) are captured at start, each round, and
# end; the summary fails the run if the end snapshot exceeds the start by
# more than a bounded slack after a drain pause.
#
# Env: DURATION_MIN (30), ROUND_SLEEP (5), RUST_REALITY_BIN, XRAY_BIN, OUT_DIR.
set -Eeuo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
rust_bin=${RUST_REALITY_BIN:-target/release/rust-reality}
xray=${XRAY_BIN:-../artifacts/xray-reference}
duration_min=${DURATION_MIN:-30}
round_sleep=${ROUND_SLEEP:-5}
minimum_rounds=${MIN_ROUNDS:-$duration_min}
expected_rust_sha256=${RUST_REALITY_SHA256:-}
expected_xray_sha256=${XRAY_SHA256:-}
out_dir=${OUT_DIR:-diagnostics/final/soak-$(date -u +%Y%m%dT%H%M%SZ)}
work=$(readlink -f "$(mktemp -d "$repository/benchmarks/soak.XXXXXX")")
pids=()
declare -A active_pids=()
declare -A active_starts=()
last_pid=

pid_start_time() {
    python3 - "$1" <<'PY'
from pathlib import Path
import sys

raw = Path(f"/proc/{sys.argv[1]}/stat").read_text()
end = raw.rfind(")")
if end < 0:
    raise SystemExit(1)
print(raw[end + 2:].split()[19])
PY
}

pid_is_owned() {
    local pid=$1 expected=$2 observed
    [[ -r /proc/$pid/stat ]] || return 1
    observed=$(pid_start_time "$pid" 2>/dev/null) || return 1
    [[ $observed == "$expected" ]]
}

stop_pid() {
    local pid=${1:-} expected=
    [[ -n $pid ]] || return 0
    expected=${active_starts[$pid]:-}
    if [[ -n $expected ]] && pid_is_owned "$pid" "$expected"; then
        kill -TERM "$pid" 2>/dev/null || true
        for _ in {1..50}; do
            pid_is_owned "$pid" "$expected" || break
            sleep 0.02
        done
        if pid_is_owned "$pid" "$expected"; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
    fi
    wait "$pid" 2>/dev/null || true
    unset "active_pids[$pid]"
    unset "active_starts[$pid]"
}

cleanup() {
    local index pid
    for ((index=${#pids[@]} - 1; index >= 0; index--)); do
        pid=${pids[index]}
        if [[ ${active_pids[$pid]+present} ]]; then
            stop_pid "$pid"
        fi
    done
    if [[ -d $work && $work == "$repository"/benchmarks/soak.* ]]; then
        rm -rf -- "$work"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd "$repository"
for program in curl go grep jq openssl python3 sha256sum stat; do
    command -v "$program" >/dev/null || { echo "missing: $program" >&2; exit 1; }
done
[[ $duration_min =~ ^[1-9][0-9]*$ ]] || { echo "DURATION_MIN must be positive" >&2; exit 2; }
[[ $round_sleep =~ ^[0-9]+$ ]] || { echo "ROUND_SLEEP must be non-negative" >&2; exit 2; }
[[ $minimum_rounds =~ ^[1-9][0-9]*$ ]] || { echo "MIN_ROUNDS must be positive" >&2; exit 2; }
[[ -x $rust_bin ]] || { echo "RUST_REALITY_BIN not executable: $rust_bin" >&2; exit 1; }
rust_bin=$(realpath "$rust_bin")
rust_sha256=$(sha256sum "$rust_bin" | awk '{print $1}')
if [[ -n $expected_rust_sha256 && ${expected_rust_sha256,,} != $rust_sha256 ]]; then
    echo "RUST_REALITY_SHA256 mismatch: expected $expected_rust_sha256, got $rust_sha256" >&2
    exit 1
fi
command -v "$xray" >/dev/null 2>&1 || { echo "XRAY_BIN is required" >&2; exit 1; }
xray=$(realpath "$(command -v "$xray")")
xray_sha256=$(sha256sum "$xray" | awk '{print $1}')
if [[ -n $expected_xray_sha256 && ${expected_xray_sha256,,} != $xray_sha256 ]]; then
    echo "XRAY_SHA256 mismatch: expected $expected_xray_sha256, got $xray_sha256" >&2
    exit 1
fi

[[ ! -e $out_dir && ! -L $out_dir ]] \
    || { echo "OUT_DIR already exists: $out_dir" >&2; exit 1; }
mkdir -p "$(dirname "$out_dir")"
mkdir "$out_dir"
jq -n --arg rustBin "$rust_bin" --arg rustSha256 "$rust_sha256" \
    --arg xrayBin "$xray" --arg xraySha256 "$xray_sha256" \
    --arg startedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson durationMinutes "$duration_min" \
    '{schemaVersion:1,startedAt:$startedAt,durationMinutes:$durationMinutes,
      rustReality:{path:$rustBin,sha256:$rustSha256},
      xray:{path:$xrayBin,sha256:$xraySha256}}' \
    >"$out_dir/environment.json"

allocate_ports() {
    python3 - <<'PY'
import socket
sockets = []
try:
    for _ in range(4):
        sock = socket.socket()
        sockets.append(sock)
        sock.bind(("127.0.0.1", 0))
    print(*(sock.getsockname()[1] for sock in sockets))
finally:
    for sock in sockets:
        sock.close()
PY
}

read -r rust_port rust_socks https_port http_port < <(allocate_ports)

free_port() {
    python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_port() {
    local port=$1 pid=$2
    python3 - "$port" "$pid" <<'PY'
import os, socket, sys, time
port, pid = int(sys.argv[1]), int(sys.argv[2])
deadline = time.monotonic() + 10
while time.monotonic() < deadline:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        raise SystemExit(f"process {pid} exited before port {port} became ready")
    with socket.socket() as sock:
        sock.settimeout(0.1)
        if sock.connect_ex(("127.0.0.1", port)) == 0:
            raise SystemExit(0)
    time.sleep(0.02)
raise SystemExit(f"port {port} did not become ready")
PY
}

start_logged() {
    local log=$1
    shift
    "$@" >"$log" 2>&1 &
    last_pid=$!
    pids+=("$last_pid")
    active_pids["$last_pid"]=1
    active_starts["$last_pid"]=$(pid_start_time "$last_pid") || {
        echo "cannot identify started process PID $last_pid" >&2
        return 1
    }
}

clean_curl() {
    env -u ALL_PROXY -u all_proxy -u HTTP_PROXY -u http_proxy \
        -u HTTPS_PROXY -u https_proxy -u NO_PROXY -u no_proxy curl "$@"
}

"$rust_bin" config generate standalone --listen 127.0.0.1 --port "$rust_port" \
    --target "127.0.0.1:$https_port" --server-name localhost \
    > "$work/base.json" 2> "$work/gen.log"
rust_pub=$(sed -n 's/^REALITY public key for the client: //p' "$work/gen.log")
uuid=$(jq -r '.inbounds[0].settings.clients[0].id' "$work/base.json")
sid=$(jq -r '.inbounds[0].settings.clients[0].shortIds[0]' "$work/base.json")
jq --arg c "$work/assets" '.log.level="warn" | .assets.cacheDirectory=$c' \
    "$work/base.json" > "$work/rust.json"
jq -n --arg uuid "$uuid" --arg pk "$rust_pub" --arg sid "$sid" \
    --argjson sp "$rust_port" --argjson cp "$rust_socks" \
    '{log:{loglevel:"warning"},inbounds:[{listen:"127.0.0.1",port:$cp,protocol:"socks",settings:{auth:"noauth",udp:false}}],outbounds:[{protocol:"vless",settings:{vnext:[{address:"127.0.0.1",port:$sp,users:[{id:$uuid,encryption:"none",flow:"xtls-rprx-vision"}]}]},streamSettings:{network:"tcp",security:"reality",realitySettings:{fingerprint:"chrome",serverName:"localhost",publicKey:$pk,shortId:$sid,spiderX:"/"}}}]}' \
    > "$work/rust-client.json"

python3 - "$work" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
chunk = bytes(range(256)) * 4096
(root / "payload-1.bin").write_bytes(chunk)
(root / "payload-4.bin").write_bytes(chunk * 4)
PY
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/o.key" -out "$work/o.crt" \
    -days 1 -subj "/CN=localhost" >/dev/null 2>&1
(cd scripts/bench-origin && go build -o "$work/bench-origin" .)
start_logged "$work/https-origin.log" "$work/bench-origin" \
    --port "$https_port" --payload-dir "$work" --put-log "$work/https-put.jsonl" \
    --tls-cert "$work/o.crt" --tls-key "$work/o.key"
https_origin_pid=$last_pid
start_logged "$work/http-origin.log" "$work/bench-origin" \
    --port "$http_port" --payload-dir "$work" --put-log "$work/http-put.jsonl"
http_origin_pid=$last_pid
wait_port "$https_port" "$https_origin_pid"
wait_port "$http_port" "$http_origin_pid"

wait_log_event() {
    local log=$1 event=$2
    for _ in {1..500}; do
        grep -Fq "$event" "$log" && return 0
        sleep 0.02
    done
    echo "required event did not appear in $log: $event" >&2
    return 1
}

make_xray_client() {
    local server_port=$1 socks_port=$2 public_key=$3 client_uuid=$4 short_id=$5 output=$6
    jq -n --arg uuid "$client_uuid" --arg pk "$public_key" --arg sid "$short_id" \
        --argjson sp "$server_port" --argjson cp "$socks_port" \
        '{log:{loglevel:"warning"},
          inbounds:[{listen:"127.0.0.1",port:$cp,protocol:"socks",
            settings:{auth:"noauth",udp:false}}],
          outbounds:[{protocol:"vless",settings:{vnext:[{address:"127.0.0.1",
            port:$sp,users:[{id:$uuid,encryption:"none",flow:"xtls-rprx-vision"}]}]},
            streamSettings:{network:"tcp",security:"reality",realitySettings:{
              fingerprint:"chrome",serverName:"localhost",publicKey:$pk,
              shortId:$sid,spiderX:"/"}}}]}' >"$output"
}

verify_one_mib_download() {
    local socks_port=$1 output=$2 expected=$3
    clean_curl -sS --fail --socks5-hostname "127.0.0.1:$socks_port" \
        --max-time 30 "http://127.0.0.1:$http_port/payload-1.bin" --output "$output"
    [[ $(stat -c %s "$output") == 1048576 ]] \
        || { echo "distributed gate download is not exactly 1 MiB: $output" >&2; return 1; }
    local actual
    actual=$(sha256sum "$output" | awk '{print $1}')
    [[ $actual == "$expected" ]] \
        || { echo "distributed gate payload SHA-256 mismatch: $output" >&2; return 1; }
}

# -------------------------------------------------------------------------
# One-shot distributed correctness gates. These are deliberately outside the
# timed resource loop: the soak evidence must prove both distributed paths at
# least once without making their extra server processes part of the primary
# server's leak baseline.
# -------------------------------------------------------------------------
distributed_payload_sha256=$(sha256sum "$work/payload-1.bin" | awk '{print $1}')

# Handoff: split the cover target's Certificate over enough TLS records to
# create a fifth positional encrypted record.  Cover Flight maps that fifth
# position to its fake NewSessionTicket ApplicationData, consuming server
# application sequence zero before Vision begins. A byte-exact download through the generated
# LINE -> sealed HND1 transfer -> LANDING topology then proves the first
# visible response resumed and decrypted at sequence one.
handoff_cover_port=$(free_port)
handoff_line_port=$(free_port)
handoff_landing_port=$(free_port)
handoff_socks_port=$(free_port)
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
    -subj '/CN=rust-reality Handoff soak CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "$work/handoff-cover-ca.key" -out "$work/handoff-cover-ca.crt" \
    >"$work/handoff-cover-ca.log" 2>&1
openssl req -new -newkey rsa:2048 -nodes -sha256 -subj '/CN=localhost' \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
    -addext 'extendedKeyUsage=serverAuth' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -keyout "$work/handoff-cover.key" -out "$work/handoff-cover.csr" \
    >"$work/handoff-cover-csr.log" 2>&1
openssl x509 -req -sha256 -days 1 -in "$work/handoff-cover.csr" \
    -CA "$work/handoff-cover-ca.crt" -CAkey "$work/handoff-cover-ca.key" \
    -CAcreateserial -copy_extensions copy -out "$work/handoff-cover.crt" \
    >"$work/handoff-cover-sign.log" 2>&1
openssl verify -CAfile "$work/handoff-cover-ca.crt" -verify_hostname localhost \
    "$work/handoff-cover.crt" >"$out_dir/handoff-cover-certificate-verify.log"
start_logged "$out_dir/handoff-cover-trace.log" openssl s_server \
    -accept "127.0.0.1:$handoff_cover_port" -www -ign_eof -tls1_3 \
    -cert "$work/handoff-cover.crt" -key "$work/handoff-cover.key" \
    -alpn 'h2,http/1.1' -max_send_frag 512 -trace -msg -state
handoff_cover_pid=$last_pid
wait_port "$handoff_cover_port" "$handoff_cover_pid"

"$rust_bin" config generate handoff \
    --listen 127.0.0.1 --port "$handoff_line_port" \
    --server-address 127.0.0.1 \
    --target "localhost:$handoff_cover_port" --server-name localhost \
    --landing-address 127.0.0.1 --landing-port "$handoff_landing_port" \
    --output-dir "$work/handoff" >"$work/handoff-generate.out" \
    2>"$work/handoff-generate.log"
jq --arg cache "$work/assets-handoff-line" \
    '.log.level="debug" | .assets.cacheDirectory=$cache' \
    "$work/handoff/line.json" >"$work/handoff-line.json"
jq --arg cache "$work/assets-handoff-landing" \
    '.log.level="debug" | .assets.cacheDirectory=$cache' \
    "$work/handoff/landing.json" >"$work/handoff-landing.json"
jq --argjson port "$handoff_socks_port" '.inbounds[0].port=$port' \
    "$work/handoff/xray-client.json" >"$work/handoff-client.json"
"$rust_bin" check --config "$work/handoff-line.json" >/dev/null
"$rust_bin" check --config "$work/handoff-landing.json" >/dev/null
start_logged "$out_dir/handoff-landing.log" \
    "$rust_bin" serve --config "$work/handoff-landing.json"
handoff_landing_pid=$last_pid
wait_port "$handoff_landing_port" "$handoff_landing_pid"
start_logged "$out_dir/handoff-line.log" env SSL_CERT_FILE="$work/handoff-cover-ca.crt" \
    "$rust_bin" serve --config "$work/handoff-line.json"
handoff_line_pid=$last_pid
wait_port "$handoff_line_port" "$handoff_line_pid"
start_logged "$out_dir/handoff-xray.log" "$xray" run -config "$work/handoff-client.json"
handoff_xray_pid=$last_pid
wait_port "$handoff_socks_port" "$handoff_xray_pid"
verify_one_mib_download "$handoff_socks_port" "$work/handoff-download.bin" \
    "$distributed_payload_sha256"
wait_log_event "$out_dir/handoff-line.log" '"event":"connection_completed"'
stop_pid "$handoff_xray_pid"
stop_pid "$handoff_line_pid"
stop_pid "$handoff_landing_pid"
stop_pid "$handoff_cover_pid"
handoff_encrypted_handshake_records=$(python3 - \
    "$out_dir/handoff-cover-trace.log" <<'PY'
from pathlib import Path
import sys

lines = Path(sys.argv[1]).read_text(errors="replace").splitlines()
count = 0
for index, line in enumerate(lines):
    if not line.lstrip().startswith(">>> TLS 1.2, RecordHeader"):
        continue
    boundary = len(lines)
    for cursor in range(index + 1, len(lines)):
        if lines[cursor].lstrip().startswith(">>> TLS 1.2, RecordHeader"):
            boundary = cursor
            break
    block = [item.strip() for item in lines[index + 1:boundary]]
    if not any(item.startswith("17 03 03") for item in block):
        continue
    for cursor, item in enumerate(block[:-1]):
        if item.startswith(">>> TLS 1.2, InnerContent") and block[cursor + 1] == "16":
            count += 1
            break
print(count)
PY
)
(( handoff_encrypted_handshake_records >= 5 )) || {
    echo "Handoff cover emitted only $handoff_encrypted_handshake_records encrypted handshake records; need at least five" >&2
    exit 1
}

# NXR: a separate generated LINE -> authenticated NXR -> LANDING topology
# must carry the same one-MiB payload byte-exactly. No failure is masked.
nxr_line_port=$(free_port)
nxr_landing_port=$(free_port)
nxr_socks_port=$(free_port)
nxr_key=$("$rust_bin" node-keygen | jq -r .preSharedKey)
"$rust_bin" config generate line --listen 127.0.0.1 --port "$nxr_line_port" \
    --target "127.0.0.1:$https_port" --server-name localhost \
    --nxr-address 127.0.0.1 --nxr-port "$nxr_landing_port" --nxr-key "$nxr_key" \
    >"$work/nxr-line.raw.json" 2>"$work/nxr-line-generate.log"
"$rust_bin" config generate landing --listen 127.0.0.1 --port "$nxr_landing_port" \
    --nxr-key "$nxr_key" >"$work/nxr-landing.raw.json"
jq --arg cache "$work/assets-nxr-line" \
    '.log.level="debug" | .assets.cacheDirectory=$cache' \
    "$work/nxr-line.raw.json" >"$work/nxr-line.json"
jq --arg cache "$work/assets-nxr-landing" \
    '.log.level="debug" | .assets.cacheDirectory=$cache' \
    "$work/nxr-landing.raw.json" >"$work/nxr-landing.json"
nxr_public_key=$(sed -n 's/^REALITY public key for the client: //p' \
    "$work/nxr-line-generate.log")
nxr_uuid=$(jq -r '.inbounds[0].settings.clients[0].id' "$work/nxr-line.raw.json")
nxr_short_id=$(jq -r '.inbounds[0].settings.clients[0].shortIds[0]' \
    "$work/nxr-line.raw.json")
make_xray_client "$nxr_line_port" "$nxr_socks_port" "$nxr_public_key" \
    "$nxr_uuid" "$nxr_short_id" "$work/nxr-client.json"
"$rust_bin" check --config "$work/nxr-line.json" >/dev/null
"$rust_bin" check --config "$work/nxr-landing.json" >/dev/null
start_logged "$out_dir/nxr-landing.log" "$rust_bin" serve --config "$work/nxr-landing.json"
nxr_landing_pid=$last_pid
wait_port "$nxr_landing_port" "$nxr_landing_pid"
start_logged "$out_dir/nxr-line.log" "$rust_bin" serve --config "$work/nxr-line.json"
nxr_line_pid=$last_pid
wait_port "$nxr_line_port" "$nxr_line_pid"
start_logged "$out_dir/nxr-xray.log" "$xray" run -config "$work/nxr-client.json"
nxr_xray_pid=$last_pid
wait_port "$nxr_socks_port" "$nxr_xray_pid"
verify_one_mib_download "$nxr_socks_port" "$work/nxr-download.bin" \
    "$distributed_payload_sha256"
wait_log_event "$out_dir/nxr-line.log" '"event":"connection_completed"'
stop_pid "$nxr_xray_pid"
stop_pid "$nxr_line_pid"
stop_pid "$nxr_landing_pid"

jq -n --arg payloadSha256 "$distributed_payload_sha256" \
    --argjson handoffEncryptedRecords "$handoff_encrypted_handshake_records" \
    --arg handoffLineConfigSha256 "$(sha256sum "$work/handoff-line.json" | awk '{print $1}')" \
    --arg handoffLandingConfigSha256 "$(sha256sum "$work/handoff-landing.json" | awk '{print $1}')" \
    --arg nxrLineConfigSha256 "$(sha256sum "$work/nxr-line.json" | awk '{print $1}')" \
    --arg nxrLandingConfigSha256 "$(sha256sum "$work/nxr-landing.json" | awk '{print $1}')" \
    '{schemaVersion:1,payloadBytes:1048576,payloadSha256:$payloadSha256,
      handoffSeq1:{attempts:1,successes:1,fakeNstExpected:true,
        coverServerEncryptedHandshakeRecords:$handoffEncryptedRecords,
        evidence:{coverTrace:"handoff-cover-trace.log",lineLog:"handoff-line.log",
          landingLog:"handoff-landing.log"},lineConfigSha256:$handoffLineConfigSha256,
        landingConfigSha256:$handoffLandingConfigSha256},
      nxrByteIntegrity:{attempts:1,successes:1,lineLog:"nxr-line.log",
        landingLog:"nxr-landing.log",lineConfigSha256:$nxrLineConfigSha256,
        landingConfigSha256:$nxrLandingConfigSha256},ok:true}' \
    >"$out_dir/distributed-gates.json"

start_logged "$work/rust.log" "$rust_bin" serve --config "$work/rust.json"
server_pid=$last_pid
start_logged /dev/null "$xray" run -config "$work/rust-client.json"
sleep 1.5

snapshot() {
    python3 - "$server_pid" "$1" >> "$out_dir/resources.jsonl" <<'PY'
import json, os, sys
pid, label = sys.argv[1], sys.argv[2]
with open(f"/proc/{pid}/status") as fh:
    fields = dict(line.split(":", 1) for line in fh if ":" in line)
print(json.dumps({
    "label": label,
    "monotonicSeconds": __import__("time").monotonic(),
    "serverAlive": True,
    "fds": len(os.listdir(f"/proc/{pid}/fd")),
    "vmRssKiB": int(fields["VmRSS"].split()[0]),
    "threads": int(fields["Threads"].split()[0]),
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
deadline=$(( $(date +%s) + duration_min * 60 ))
snapshot start
while (( $(date +%s) < deadline )); do
    round=$((round + 1))
    verify_download -sS --insecure --fail --socks5-hostname 127.0.0.1:$rust_socks \
        --max-time 60 https://127.0.0.1:$https_port/payload-4.bin \
        || failures=$((failures + 1))
    verify_download -sS --fail --socks5-hostname 127.0.0.1:$rust_socks \
        --max-time 60 http://127.0.0.1:$http_port/payload-4.bin \
        || failures=$((failures + 1))
    verify_download -sS --insecure --fail --max-time 60 \
        https://127.0.0.1:$rust_port/payload-4.bin || failures=$((failures + 1))
    # churn: rapid short-lived connections through every path
    for _ in $(seq 1 16); do
        clean_curl -sS --insecure --max-time 5 -o /dev/null -r 0-1023 \
            https://127.0.0.1:$rust_port/payload-4.bin 2>/dev/null \
            || failures=$((failures + 1))
    done
    snapshot "round-$round"
    sleep "$round_sleep"
done
sleep 5
snapshot end

final_rust_sha256=$(sha256sum "$rust_bin" | awk '{print $1}')
final_xray_sha256=$(sha256sum "$xray" | awk '{print $1}')
[[ $final_rust_sha256 == "$rust_sha256" ]] \
    || { echo 'RUST_REALITY_BIN changed during soak' >&2; exit 1; }
[[ $final_xray_sha256 == "$xray_sha256" ]] \
    || { echo 'XRAY_BIN changed during soak' >&2; exit 1; }

python3 - "$out_dir/resources.jsonl" "$failures" "$round" "$minimum_rounds" \
    "$expected_payload_sha256" "$out_dir/distributed-gates.json" \
    "$out_dir/soak-summary.json" <<'PY'
import json, statistics, sys
records = [json.loads(line) for line in open(sys.argv[1])]
failures, rounds, minimum_rounds = map(int, sys.argv[2:5])
payload_sha256, distributed_path, output = sys.argv[5:8]
with open(distributed_path) as handle:
    distributed = json.load(handle)
start, end = records[0], records[-1]
# Slack: a few dozen FDs/threads and 32 MiB RSS cover allocator arenas and
# parked runtime state; anything beyond that is a leak.
fd_growth = end["fds"] - start["fds"]
thread_growth = end["threads"] - start["threads"]
rss_growth_mib = (end["vmRssKiB"] - start["vmRssKiB"]) / 1024
fd_peak_growth = max(r["fds"] for r in records) - start["fds"]
thread_peak_growth = max(r["threads"] for r in records) - start["threads"]
rss_peak_growth_mib = (max(r["vmRssKiB"] for r in records) - start["vmRssKiB"]) / 1024
tail = records[max(1, len(records) // 2):]
xs = [r["monotonicSeconds"] for r in tail]
ys = [r["vmRssKiB"] / 1024 for r in tail]
if len(xs) >= 2 and len(set(xs)) > 1:
    xbar, ybar = statistics.mean(xs), statistics.mean(ys)
    denominator = sum((x - xbar) ** 2 for x in xs)
    rss_slope_mib_per_hour = 3600 * sum(
        (x - xbar) * (y - ybar) for x, y in zip(xs, ys)
    ) / denominator
else:
    rss_slope_mib_per_hour = 0.0
ok = (
    failures == 0
    and rounds >= minimum_rounds
    and fd_growth <= 32
    and thread_growth <= 8
    and rss_growth_mib <= 32
    and fd_peak_growth <= 128
    and thread_peak_growth <= 8
    and rss_peak_growth_mib <= 64
    and rss_slope_mib_per_hour <= 2
    and all(r.get("serverAlive") for r in records)
    and distributed.get("ok") is True
    and distributed.get("handoffSeq1", {}).get("attempts") == 1
    and distributed.get("handoffSeq1", {}).get("successes") == 1
    and distributed.get("handoffSeq1", {}).get("fakeNstExpected") is True
    and distributed.get("handoffSeq1", {}).get("coverServerEncryptedHandshakeRecords", 0) >= 5
    and distributed.get("nxrByteIntegrity", {}).get("attempts") == 1
    and distributed.get("nxrByteIntegrity", {}).get("successes") == 1
)
summary = {
    "rounds": rounds,
    "transferFailures": failures,
    "start": start,
    "end": end,
    "fdGrowth": fd_growth,
    "threadGrowth": thread_growth,
    "rssGrowthMiB": round(rss_growth_mib, 1),
    "minimumRounds": minimum_rounds,
    "payloadSha256": payload_sha256,
    "fdPeakGrowth": fd_peak_growth,
    "threadPeakGrowth": thread_peak_growth,
    "rssPeakGrowthMiB": round(rss_peak_growth_mib, 1),
    "rssTailSlopeMiBPerHour": round(rss_slope_mib_per_hour, 3),
    "distributedGates": distributed,
    "ok": ok,
}
with open(output, "x") as fh:
    json.dump({"summary": summary, "snapshots": records}, fh, indent=2)
print(json.dumps(summary))
sys.exit(0 if ok else 1)
PY
