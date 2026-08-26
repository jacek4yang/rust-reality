#!/usr/bin/env bash
# Bounded loopback soak: mixed tunnel traffic + connection churn against a
# local rust-reality server, with resource snapshots proving nothing leaks.
#
# Workload mix per round: direct download (TLS origin), framed download
# (plain origin), fallback (direct-to-listener), and rapid connect/drop
# churn. Real cover-NST/sequence-one Handoff, byte-exact NXR, and TCP-warm
# SOCKS5 topologies remain alive for the timed soak and are exercised at the
# start, at each monotonic interval, and at the end. /proc snapshots cover every
# rust-reality process individually and in aggregate.
#
# Env: DURATION_MIN (30), ROUND_SLEEP (5), DISTRIBUTED_INTERVAL_SECONDS (1800),
# RUST_REALITY_BIN, XRAY_BIN, OUT_DIR. REQUIRE_RELEASE_QUALIFIED=1 additionally
# requires explicit RUN_ID, absolute new OUT_DIR, disk-backed TMPDIR, PORT_BASE,
# RUST_REALITY_SHA256, XRAY_SHA256, EXPECTED_SOURCE_COMMIT, and read-only
# absolute binary paths.
set -Eeuo pipefail
umask 077

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$repository/scripts/benchmark-contract.sh"
rust_bin=${RUST_REALITY_BIN:-target/release/rust-reality}
xray=${XRAY_BIN:-../artifacts/xray-reference}
duration_min=${DURATION_MIN:-30}
round_sleep=${ROUND_SLEEP:-5}
minimum_rounds=${MIN_ROUNDS:-$duration_min}
require_release_qualified=${REQUIRE_RELEASE_QUALIFIED:-0}
distributed_interval_seconds=${DISTRIBUTED_INTERVAL_SECONDS:-1800}
max_distributed_attempts=145
run_id=${RUN_ID:-${RR_RUN_ID:-soak-$(date -u +%Y%m%dT%H%M%SZ)-$$}}
port_base=${PORT_BASE:-}
expected_rust_sha256=${RUST_REALITY_SHA256:-}
expected_xray_sha256=${XRAY_SHA256:-}
out_dir=${OUT_DIR:-diagnostics/final/soak-$(date -u +%Y%m%dT%H%M%SZ)}
temporary_root=${TMPDIR:-$repository/benchmarks}
work=
contract_initialized=0
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
    local original_status=$? final_status index pid
    trap - EXIT INT TERM
    set +e
    for ((index=${#pids[@]} - 1; index >= 0; index--)); do
        pid=${pids[index]}
        if [[ ${active_pids[$pid]+present} ]]; then
            stop_pid "$pid"
        fi
    done
    if [[ -n $work && -d $work && $work == "$temporary_root"/rust-reality-soak.* ]]; then
        rm -rf -- "$work"
    fi
    final_status=$original_status
    if (( contract_initialized == 1 )); then
        rr_contract_verify_on_exit "$original_status"
        final_status=$?
    fi
    exit "$final_status"
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
[[ $require_release_qualified == 0 || $require_release_qualified == 1 ]] \
    || { echo "REQUIRE_RELEASE_QUALIFIED must be 0 or 1" >&2; exit 2; }
[[ $distributed_interval_seconds =~ ^[1-9][0-9]*$ ]] \
    || { echo "DISTRIBUTED_INTERVAL_SECONDS must be positive" >&2; exit 2; }
if (( require_release_qualified == 1 \
    && (distributed_interval_seconds < 300 || distributed_interval_seconds > 1800) )); then
    echo "release soak DISTRIBUTED_INTERVAL_SECONDS must be in 300..1800" >&2
    exit 2
fi
planned_distributed_attempts=$((
    3 + (duration_min * 60 - 1) / distributed_interval_seconds
))
if (( planned_distributed_attempts > max_distributed_attempts )); then
    echo "distributed attempt count $planned_distributed_attempts exceeds hard limit $max_distributed_attempts" >&2
    exit 2
fi
planned_distributed_payload_bytes=$((
    (planned_distributed_attempts * 3 + 3) * 1048576
))
[[ $run_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] \
    || { echo "RUN_ID is invalid: $run_id" >&2; exit 2; }
if (( require_release_qualified == 1 )); then
    [[ ${EXPLORATORY:-0} == 0 ]] \
        || { echo "release-qualified soak cannot be exploratory" >&2; exit 2; }
    rr_contract_init "$repository" soak-test diagnostics/final 15
    contract_initialized=1
    case $(realpath -m -- "$RR_OUT_DIR")/ in
        "$repository"/*)
            echo "release-qualified OUT_DIR must be outside the repository" >&2
            exit 2
            ;;
    esac
    case "$RR_TMPDIR"/ in
        "$repository"/*)
            echo "release-qualified TMPDIR must be outside the repository" >&2
            exit 2
            ;;
    esac
    rr_register_harness_file "$repository/scripts/cover-flight-shape-proxy.py"
    rr_register_harness_file "$repository/scripts/deployment_driver.py"
    rr_register_harness_tree "$repository/scripts/bench-origin"
    rr_register_binary rust-reality "$rust_bin" "$expected_rust_sha256" rust \
        "${EXPECTED_SOURCE_COMMIT:-}"
    rr_register_binary xray "$xray" "$expected_xray_sha256" xray
    [[ ${RR_BINARY_BUILD_IDS[rust-reality]} =~ ^[0-9a-f]+$ ]] \
        || { echo "release-qualified rust-reality binary has no ELF Build ID" >&2; exit 2; }
    [[ ${RR_BINARY_BUILD_IDS[xray]} =~ ^[0-9a-f]+$ ]] \
        || { echo "release-qualified Xray binary has no ELF Build ID" >&2; exit 2; }
    [[ $RR_HARNESS_COMMIT == "${EXPECTED_SOURCE_COMMIT:-}" ]] \
        || { echo "release-qualified binary source commit must equal harness HEAD" >&2; exit 2; }
    rr_write_contract_metadata preflight
    run_id=$RR_RUN_ID
    port_base=$RR_PORT_BASE
    out_dir=$RR_OUT_DIR
    temporary_root=$RR_TMPDIR
    rust_bin=${RR_BINARY_PATHS[rust-reality]}
    rust_sha256=${RR_BINARY_SHA256[rust-reality]}
    xray=${RR_BINARY_PATHS[xray]}
    xray_sha256=${RR_BINARY_SHA256[xray]}
else
    if [[ -n $port_base ]]; then
        [[ $port_base =~ ^[0-9]+$ ]] && (( port_base >= 1024 && port_base <= 65521 )) \
            || { echo "PORT_BASE must leave a 15-port block in 1024..65535" >&2; exit 2; }
    fi
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
fi
mkdir -p "$temporary_root"
temporary_root=$(readlink -f "$temporary_root")
work=$(readlink -f "$(mktemp -d "$temporary_root/rust-reality-soak.${run_id}.XXXXXX")")
mkdir "$out_dir/distributed"
proxy_max_accepted=$((planned_distributed_attempts + 16))
allocate_ports() {
    python3 - "$port_base" <<'PY'
import socket
import sys

base = int(sys.argv[1]) if sys.argv[1] else None
sockets = []
try:
    for index in range(15):
        sock = socket.socket()
        sockets.append(sock)
        port = base + index if base is not None else 0
        sock.bind(("127.0.0.1", port))
    print(*(sock.getsockname()[1] for sock in sockets))
finally:
    for sock in sockets:
        sock.close()
PY
}

read -r rust_port rust_socks https_port http_port \
    handoff_cover_upstream_port handoff_cover_port handoff_line_port \
    handoff_landing_port handoff_socks_port nxr_line_port nxr_landing_port \
    nxr_socks_port socks_line_port socks_upstream_port socks_client_port \
    < <(allocate_ports)
port_block_json=$(printf '%s\n' "$rust_port" "$rust_socks" "$https_port" "$http_port" \
    "$handoff_cover_upstream_port" "$handoff_cover_port" "$handoff_line_port" \
    "$handoff_landing_port" "$handoff_socks_port" "$nxr_line_port" \
    "$nxr_landing_port" "$nxr_socks_port" "$socks_line_port" \
    "$socks_upstream_port" "$socks_client_port" | jq -sc 'map(tonumber)')
run_contract_file=
(( contract_initialized == 0 )) || run_contract_file=run-contract.json

jq -n --arg runId "$run_id" --arg rustBin "$rust_bin" --arg rustSha256 "$rust_sha256" \
    --arg xrayBin "$xray" --arg xraySha256 "$xray_sha256" \
    --arg runContract "$run_contract_file" \
    --arg startedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson durationMinutes "$duration_min" \
    --argjson distributedIntervalSeconds "$distributed_interval_seconds" \
    --argjson plannedDistributedAttempts "$planned_distributed_attempts" \
    --argjson maxDistributedAttempts "$max_distributed_attempts" \
    --argjson plannedDistributedPayloadBytes "$planned_distributed_payload_bytes" \
    --argjson requireReleaseQualified "$require_release_qualified" \
    --argjson portBlock "$port_block_json" \
    '{schemaVersion:2,runId:$runId,startedAt:$startedAt,durationMinutes:$durationMinutes,
      distributedIntervalSeconds:$distributedIntervalSeconds,
      plannedDistributedAttempts:$plannedDistributedAttempts,
      maxDistributedAttempts:$maxDistributedAttempts,
      plannedDistributedPayloadBytes:$plannedDistributedPayloadBytes,
      requireReleaseQualified:$requireReleaseQualified,
      formalRunContract:(if $runContract == "" then null else $runContract end),
      ports:{address:"127.0.0.1",block:$portBlock},
      rustReality:{path:$rustBin,sha256:$rustSha256},
      xray:{path:$xrayBin,sha256:$xraySha256}}' \
    >"$out_dir/environment.json"

wait_port() {
    local port=$1 pid=$2 expected=${active_starts[$2]:-}
    [[ -n $expected ]] || { echo "unregistered process PID $pid" >&2; return 1; }
    python3 - "$port" "$pid" "$expected" <<'PY'
import os, socket, sys, time
port, pid, expected = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]


def owned():
    try:
        raw = open(f"/proc/{pid}/stat", encoding="ascii").read()
    except FileNotFoundError:
        return False
    end = raw.rfind(")")
    return end >= 0 and raw[end + 2:].split()[19] == expected


deadline = time.monotonic() + 10
while time.monotonic() < deadline:
    if not owned():
        raise SystemExit(f"process identity {pid}/{expected} exited before port {port} became ready")
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
(cd scripts/bench-origin && go build -buildvcs=false -o "$work/bench-origin" .)
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
# Long-lived distributed correctness topologies. Their rust-reality processes
# are part of the timed resource baseline and every later snapshot.
# -------------------------------------------------------------------------
distributed_payload_sha256=$(sha256sum "$work/payload-1.bin" | awk '{print $1}')

# Handoff: keep the cover's four standard TLS 1.3 handshake records intact,
# then use a loopback wire shim to append one opaque fifth ApplicationData
# record in the same write. Cover Flight maps that fifth position to its fake
# NewSessionTicket ApplicationData, consuming server application sequence zero
# before Vision begins. A byte-exact download through the generated
# LINE -> sealed HND1 transfer -> LANDING topology then proves the first
# visible response resumed and decrypted at sequence one.
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
    -accept "127.0.0.1:$handoff_cover_upstream_port" -www -ign_eof -tls1_3 \
    -cert "$work/handoff-cover.crt" -key "$work/handoff-cover.key" \
    -alpn 'h2,http/1.1' -trace -msg -state
handoff_cover_upstream_pid=$last_pid
wait_port "$handoff_cover_upstream_port" "$handoff_cover_upstream_pid"
start_logged "$out_dir/handoff-cover-shape-proxy.log" python3 -u \
    "$repository/scripts/cover-flight-shape-proxy.py" \
    --listen-port "$handoff_cover_port" \
    --upstream-port "$handoff_cover_upstream_port" \
    --max-shaped "$planned_distributed_attempts" \
    --max-accepted "$proxy_max_accepted"
handoff_cover_proxy_pid=$last_pid
wait_port "$handoff_cover_port" "$handoff_cover_proxy_pid"

"$rust_bin" config generate handoff \
    --listen 127.0.0.1 --port "$handoff_line_port" \
    --server-address 127.0.0.1 \
    --target "localhost:$handoff_cover_port" --server-name localhost \
    --landing-address 127.0.0.1 --landing-port "$handoff_landing_port" \
    --output-dir "$work/handoff" >"$work/handoff-generate.out" \
    2>"$work/handoff-generate.log"
jq --arg cache "$work/assets-handoff-line" \
    '.log.level="debug" | .assets.cacheDirectory=$cache
     | .inbounds[0].streamSettings.realitySettings.coverOptimization.warmTcp=false
     | .inbounds[0].streamSettings.realitySettings.coverOptimization.prebuiltProfiles=false' \
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

# NXR: a separate generated LINE -> authenticated NXR -> LANDING topology
# must carry the same one-MiB payload byte-exactly. No failure is masked.
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

# SOCKS5: the rust-reality LINE owns a TCP-only warm pool to a conventional
# no-auth SOCKS5 server. Method negotiation and CONNECT still begin only after
# checkout; repeated byte-exact transfers exercise that boundary during the
# same idle, churn, and resource-observation window as Handoff and NXR.
start_logged "$out_dir/socks-upstream.log" python3 \
    "$repository/scripts/deployment_driver.py" socks-server \
    --port "$socks_upstream_port"
socks_upstream_pid=$last_pid
wait_port "$socks_upstream_port" "$socks_upstream_pid"
"$rust_bin" config generate line --listen 127.0.0.1 --port "$socks_line_port" \
    --target "127.0.0.1:$https_port" --server-name localhost \
    --nxr-address 127.0.0.1 --nxr-port 9 --nxr-key "$nxr_key" \
    >"$work/socks-line.raw.json" 2>"$work/socks-line-generate.log"
jq --arg cache "$work/assets-socks-line" --argjson port "$socks_upstream_port" \
    '.log.level="debug" | .assets.cacheDirectory=$cache
     | .outbounds |= map(select(.protocol != "nxr"))
     | .outbounds += [{protocol:"socks5",tag:"via-socks",
                       settings:{address:"127.0.0.1",port:$port,warmTcp:true}}]
     | .routing.users[0].defaultOutbound="via-socks"' \
    "$work/socks-line.raw.json" >"$work/socks-line.json"
socks_public_key=$(sed -n 's/^REALITY public key for the client: //p' \
    "$work/socks-line-generate.log")
socks_uuid=$(jq -r '.inbounds[0].settings.clients[0].id' \
    "$work/socks-line.raw.json")
socks_short_id=$(jq -r '.inbounds[0].settings.clients[0].shortIds[0]' \
    "$work/socks-line.raw.json")
make_xray_client "$socks_line_port" "$socks_client_port" "$socks_public_key" \
    "$socks_uuid" "$socks_short_id" "$work/socks-client.json"
"$rust_bin" check --config "$work/socks-line.json" >/dev/null
start_logged "$out_dir/socks-line.log" "$rust_bin" serve --config "$work/socks-line.json"
socks_line_pid=$last_pid
wait_port "$socks_line_port" "$socks_line_pid"
start_logged "$out_dir/socks-xray.log" "$xray" run -config "$work/socks-client.json"
socks_xray_pid=$last_pid
wait_port "$socks_client_port" "$socks_xray_pid"

distributed_samples="$out_dir/distributed-samples.jsonl"
: >"$distributed_samples"
distributed_attempts=0
last_handoff_download=
last_nxr_download=
last_socks_download=

monotonic_now() {
    python3 - <<'PY'
import time
print(f"{time.monotonic():.6f}")
PY
}

wait_handoff_sequence() {
    local expected_index=$1
    python3 - "$out_dir/handoff-line.log" "$expected_index" <<'PY'
import json
from pathlib import Path
import sys
import time

path, expected_index = Path(sys.argv[1]), int(sys.argv[2])
deadline = time.monotonic() + 10
while time.monotonic() < deadline:
    sequences = []
    for line in path.read_text(errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event") == "connection_completed" and event.get("handoff_server_sequence") is not None:
            sequences.append(event["handoff_server_sequence"])
    if len(sequences) >= expected_index:
        print(sequences[expected_index - 1])
        raise SystemExit(0)
    time.sleep(0.02)
raise SystemExit(f"missing Handoff completion {expected_index}")
PY
}

record_distributed_sample() {
    local attempt=$1 trigger=$2 path=$3 success=$4 failure_class=$5
    local bytes=$6 sha256=$7 sequence=$8 output=$9
    local monotonic
    monotonic=$(monotonic_now)
    jq -cn --argjson attempt "$attempt" --arg trigger "$trigger" --arg path "$path" \
        --argjson success "$success" --arg failureClass "$failure_class" \
        --argjson bytes "$bytes" --arg sha256 "$sha256" \
        --arg serverSequence "$sequence" --arg output "$output" \
        --arg expectedSha256 "$distributed_payload_sha256" \
        --argjson monotonicSeconds "$monotonic" \
        '{attempt:$attempt,trigger:$trigger,path:$path,success:$success,
          failureClass:($failureClass | if length == 0 then null else . end),
          bytes:$bytes,sha256:($sha256 | if length == 0 then null else . end),
          expectedBytes:1048576,expectedSha256:$expectedSha256,
          serverSequence:($serverSequence | if length == 0 then null else tonumber end),output:$output,
          monotonicSeconds:$monotonicSeconds}' >>"$distributed_samples"
}

run_distributed_download() {
    local attempt=$1 trigger=$2 path=$3 socks_port=$4 output=$5
    local curl_rc=0 bytes=0 sha256= sequence= success=true failure_class=
    local relative_output=${output#"$out_dir"/}
    if clean_curl -sS --fail --socks5-hostname "127.0.0.1:$socks_port" \
        --max-time 30 "http://127.0.0.1:$http_port/payload-1.bin" --output "$output"; then
        :
    else
        curl_rc=$?
        success=false
        failure_class="curl_exit_$curl_rc"
    fi
    if [[ -f $output ]]; then
        bytes=$(stat -c %s "$output")
        sha256=$(sha256sum "$output" | awk '{print $1}')
    fi
    if [[ $success == true && $bytes != 1048576 ]]; then
        success=false
        failure_class=size_mismatch
    fi
    if [[ $success == true && $sha256 != "$distributed_payload_sha256" ]]; then
        success=false
        failure_class=sha256_mismatch
    fi
    if [[ $path == handoff-seq1 ]]; then
        if observed_sequence=$(wait_handoff_sequence "$attempt" 2>/dev/null); then
            sequence=$observed_sequence
            if [[ $success == true && $sequence != 1 ]]; then
                success=false
                failure_class=server_sequence_mismatch
            fi
        elif [[ $success == true ]]; then
            success=false
            failure_class=server_sequence_missing
        fi
    fi
    record_distributed_sample "$attempt" "$trigger" "$path" "$success" \
        "$failure_class" "$bytes" "$sha256" "$sequence" "$relative_output"
}

run_distributed_attempt() {
    local trigger=$1 attempt
    distributed_attempts=$((distributed_attempts + 1))
    attempt=$distributed_attempts
    last_handoff_download=$(printf '%s/distributed/handoff-%04d.bin' "$out_dir" "$attempt")
    last_nxr_download=$(printf '%s/distributed/nxr-%04d.bin' "$out_dir" "$attempt")
    last_socks_download=$(printf '%s/distributed/socks-%04d.bin' "$out_dir" "$attempt")
    run_distributed_download "$attempt" "$trigger" handoff-seq1 \
        "$handoff_socks_port" "$last_handoff_download"
    run_distributed_download "$attempt" "$trigger" nxr-byte-integrity \
        "$nxr_socks_port" "$last_nxr_download"
    run_distributed_download "$attempt" "$trigger" socks5-byte-integrity \
        "$socks_client_port" "$last_socks_download"
}

start_logged "$work/rust.log" "$rust_bin" serve --config "$work/rust.json"
server_pid=$last_pid
wait_port "$rust_port" "$server_pid"
start_logged /dev/null "$xray" run -config "$work/rust-client.json"
rust_xray_pid=$last_pid
wait_port "$rust_socks" "$rust_xray_pid"

rust_process_names=(standalone handoff-line handoff-landing nxr-line nxr-landing socks-line)
rust_process_pids=("$server_pid" "$handoff_line_pid" "$handoff_landing_pid" \
    "$nxr_line_pid" "$nxr_landing_pid" "$socks_line_pid")

snapshot() {
    local label=$1 index pid expected
    local -a identities=()
    for index in "${!rust_process_pids[@]}"; do
        pid=${rust_process_pids[index]}
        expected=${active_starts[$pid]:-}
        [[ -n $expected ]] || {
            echo "rust process ${rust_process_names[index]} PID $pid is not registered" >&2
            return 1
        }
        identities+=("${rust_process_names[index]}" "$pid" "$expected")
    done
    python3 - "$label" "${identities[@]}" >> "$out_dir/resources.jsonl" <<'PY'
import json
import os
import sys
import time

label, raw_identities = sys.argv[1], sys.argv[2:]
if len(raw_identities) % 3:
    raise SystemExit("invalid process identity argument count")
processes = {}
for offset in range(0, len(raw_identities), 3):
    name, pid_text, expected = raw_identities[offset:offset + 3]
    pid = int(pid_text)
    try:
        raw = open(f"/proc/{pid}/stat", encoding="ascii").read()
    except FileNotFoundError:
        raise SystemExit(f"rust process exited: {name} {pid}/{expected}")
    end = raw.rfind(")")
    observed = raw[end + 2:].split()[19] if end >= 0 else None
    if observed != expected:
        raise SystemExit(
            f"rust process identity changed: {name} {pid}/{expected} -> {observed}"
        )
    with open(f"/proc/{pid}/status", encoding="ascii") as handle:
        fields = dict(line.split(":", 1) for line in handle if ":" in line)
    rss = int(fields["VmRSS"].split()[0])
    processes[name] = {
        "alive": True,
        "pid": pid,
        "pidStarttime": observed,
        "fds": len(os.listdir(f"/proc/{pid}/fd")),
        "vmRssKiB": rss,
        "vmHwmKiB": int(fields.get("VmHWM", fields["VmRSS"]).split()[0]),
        "threads": int(fields["Threads"].split()[0]),
    }
totals = {
    field: sum(process[field] for process in processes.values())
    for field in ("fds", "vmRssKiB", "vmHwmKiB", "threads")
}
print(json.dumps({
    "label": label,
    "monotonicSeconds": time.monotonic(),
    "serverAlive": all(process["alive"] for process in processes.values()),
    "processes": processes,
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
timed_start_seconds=$SECONDS
deadline=$(( timed_start_seconds + duration_min * 60 ))
next_distributed=$(( timed_start_seconds + distributed_interval_seconds ))
reload_at=$(( timed_start_seconds + duration_min * 30 ))
reload_triggered=0
run_distributed_attempt start
snapshot start
while (( SECONDS < deadline )); do
    round=$((round + 1))
    if (( reload_triggered == 0 && SECONDS >= reload_at )); then
        snapshot before-reload
        reload_pids=("$handoff_line_pid" "$handoff_landing_pid" "$nxr_line_pid" \
            "$nxr_landing_pid" "$socks_line_pid")
        reload_logs=("$out_dir/handoff-line.log" "$out_dir/handoff-landing.log" \
            "$out_dir/nxr-line.log" "$out_dir/nxr-landing.log" \
            "$out_dir/socks-line.log")
        for pid in "${reload_pids[@]}"; do
            expected=${active_starts[$pid]:-}
            [[ -n $expected ]] && pid_is_owned "$pid" "$expected" \
                || { echo "cannot reload unowned process PID $pid" >&2; exit 1; }
            kill -HUP "$pid"
        done
        for log in "${reload_logs[@]}"; do
            wait_log_event "$log" '"event":"configuration_published","generation":1'
        done
        reload_triggered=1
        run_distributed_attempt reload
        snapshot after-reload
    fi
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
    while (( next_distributed < deadline && SECONDS >= next_distributed )); do
        run_distributed_attempt interval
        next_distributed=$((next_distributed + distributed_interval_seconds))
    done
    snapshot "round-$round"
    sleep "$round_sleep"
done
run_distributed_attempt end
install -m 0600 "$last_handoff_download" "$out_dir/handoff-download.bin"
install -m 0600 "$last_nxr_download" "$out_dir/nxr-download.bin"
install -m 0600 "$last_socks_download" "$out_dir/socks-download.bin"
sleep 5
snapshot end

python3 - "$distributed_samples" "$out_dir/handoff-cover-shape-proxy.log" \
    "$out_dir/handoff-landing.log" "$out_dir/nxr-landing.log" \
    "$distributed_interval_seconds" "$distributed_payload_sha256" \
    "$(sha256sum "$work/handoff-line.json" | awk '{print $1}')" \
    "$(sha256sum "$work/handoff-landing.json" | awk '{print $1}')" \
    "$(sha256sum "$work/nxr-line.json" | awk '{print $1}')" \
    "$(sha256sum "$work/nxr-landing.json" | awk '{print $1}')" \
    "$(sha256sum "$work/socks-line.json" | awk '{print $1}')" \
    "$out_dir/distributed-gates.json" <<'PY'
import collections
import json
from pathlib import Path
import sys

(
    samples_path,
    proxy_log_path,
    handoff_landing_log_path,
    nxr_landing_log_path,
    interval_text,
    payload_sha256,
    handoff_line_sha256,
    handoff_landing_sha256,
    nxr_line_sha256,
    nxr_landing_sha256,
    socks_line_sha256,
    output_path,
) = sys.argv[1:]
interval = int(interval_text)
samples = [json.loads(line) for line in Path(samples_path).read_text().splitlines()]
paths = {
    name: [sample for sample in samples if sample.get("path") == name]
    for name in ("handoff-seq1", "nxr-byte-integrity", "socks5-byte-integrity")
}
handoff, nxr = paths["handoff-seq1"], paths["nxr-byte-integrity"]
socks = paths["socks5-byte-integrity"]
attempts = len({sample.get("attempt") for sample in samples})
elapsed = handoff[-1]["monotonicSeconds"] - handoff[0]["monotonicSeconds"] if handoff else 0
required_attempts = 1 + int(elapsed // interval)
shape_events = []
proxy_completions = []
for line in Path(proxy_log_path).read_text(errors="replace").splitlines():
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
    if (
        event.get("event") == "flight_shaped"
        and len(event.get("upstreamEncryptedWireLengths", [])) == 4
        and event.get("appendedWireLength") == 139
    ):
        shape_events.append(event)
    elif event.get("event") == "proxy_complete":
        proxy_completions.append(event)


def path_summary(records, require_sequence):
    failures = [record for record in records if record.get("success") is not True]
    final = records[-1] if records else {}
    return {
        "attempts": len(records),
        "successes": sum(record.get("success") is True for record in records),
        "failures": len(failures),
        "failureClasses": dict(collections.Counter(
            record.get("failureClass", "unclassified") for record in failures
        )),
        "allPayloadBytes": all(record.get("bytes") == 1048576 for record in records),
        "allPayloadSha256": all(record.get("sha256") == payload_sha256 for record in records),
        "allServerSequenceOne": (
            all(record.get("serverSequence") == 1 for record in records)
            if require_sequence else None
        ),
        "download": {
            "path": final.get("output"),
            "bytes": final.get("bytes"),
            "sha256": final.get("sha256"),
        },
    }


handoff_summary = path_summary(handoff, True)
handoff_summary.update({
    "fakeNstExpected": True,
    "coverShapeEvents": len(shape_events),
    "appendedWireLength": 139,
    "exportedServerSequence": 1 if handoff_summary["allServerSequenceOne"] else None,
    "evidence": {
        "coverTrace": "handoff-cover-trace.log",
        "shapeProxyLog": "handoff-cover-shape-proxy.log",
        "lineLog": "handoff-line.log",
        "landingLog": "handoff-landing.log",
    },
    "lineConfigSha256": handoff_line_sha256,
    "landingConfigSha256": handoff_landing_sha256,
})
nxr_summary = path_summary(nxr, False)
nxr_summary.update({
    "lineLog": "nxr-line.log",
    "landingLog": "nxr-landing.log",
    "lineConfigSha256": nxr_line_sha256,
    "landingConfigSha256": nxr_landing_sha256,
})
socks_summary = path_summary(socks, False)
socks_summary.update({
    "lineLog": "socks-line.log",
    "upstreamLog": "socks-upstream.log",
    "lineConfigSha256": socks_line_sha256,
    "preparation": "tcp-only",
})
triggers = collections.Counter(sample.get("trigger") for sample in handoff)
proxy_complete = proxy_completions[-1] if proxy_completions else None


def rejection_reasons(path):
    reasons = collections.Counter()
    for line in Path(path).read_text(errors="replace").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event") == "connection_rejected":
            reasons[event.get("reason", "unclassified")] += 1
    return dict(reasons)


handoff_landing_rejections = rejection_reasons(handoff_landing_log_path)
nxr_landing_rejections = rejection_reasons(nxr_landing_log_path)
ok = (
    attempts >= required_attempts
    and len(handoff) == attempts
    and len(nxr) == attempts
    and len(socks) == attempts
    and triggers.get("start") == 1
    and triggers.get("reload") == 1
    and triggers.get("end") == 1
    and handoff_summary["successes"] == attempts
    and handoff_summary["failures"] == 0
    and handoff_summary["allPayloadBytes"]
    and handoff_summary["allPayloadSha256"]
    and handoff_summary["allServerSequenceOne"]
    and nxr_summary["successes"] == attempts
    and nxr_summary["failures"] == 0
    and nxr_summary["allPayloadBytes"]
    and nxr_summary["allPayloadSha256"]
    and socks_summary["successes"] == attempts
    and socks_summary["failures"] == 0
    and socks_summary["allPayloadBytes"]
    and socks_summary["allPayloadSha256"]
    and not handoff_landing_rejections
    and not nxr_landing_rejections
    and len(shape_events) == attempts
    and proxy_complete is not None
    and proxy_complete.get("shaped") == attempts
)
result = {
    "schemaVersion": 2,
    "payloadBytes": 1048576,
    "payloadSha256": payload_sha256,
    "intervalSeconds": interval,
    "elapsedSeconds": round(elapsed, 3),
    "attempts": attempts,
    "requiredAttempts": required_attempts,
    "reload": {
        "triggerAttempts": triggers.get("reload", 0),
        "expectedGeneration": 1,
        "logs": [
            "handoff-line.log",
            "handoff-landing.log",
            "nxr-line.log",
            "nxr-landing.log",
            "socks-line.log",
        ],
    },
    "samplesPath": "distributed-samples.jsonl",
    "handoffSeq1": handoff_summary,
    "nxrByteIntegrity": nxr_summary,
    "socks5ByteIntegrity": socks_summary,
    "landingConnectionRejections": {
        "handoff": handoff_landing_rejections,
        "nxr": nxr_landing_rejections,
    },
    "proxy": {
        "accepted": proxy_complete.get("accepted") if proxy_complete else None,
        "shaped": proxy_complete.get("shaped") if proxy_complete else None,
        "maxAccepted": proxy_complete.get("maxAccepted") if proxy_complete else None,
        "maxShaped": proxy_complete.get("maxShaped") if proxy_complete else None,
    },
    "ok": ok,
}
with open(output_path, "x", encoding="utf-8") as handle:
    json.dump(result, handle, indent=2)
print(json.dumps(result, separators=(",", ":")))
PY

final_rust_sha256=$(sha256sum "$rust_bin" | awk '{print $1}')
final_xray_sha256=$(sha256sum "$xray" | awk '{print $1}')
[[ $final_rust_sha256 == "$rust_sha256" ]] \
    || { echo 'RUST_REALITY_BIN changed during soak' >&2; exit 1; }
[[ $final_xray_sha256 == "$xray_sha256" ]] \
    || { echo 'XRAY_BIN changed during soak' >&2; exit 1; }

python3 - "$out_dir/resources.jsonl" "$failures" "$round" "$minimum_rounds" \
    "$duration_min" "$require_release_qualified" "$expected_payload_sha256" \
    "$max_distributed_attempts" "$out_dir/distributed-gates.json" \
    "$out_dir/soak-summary.json" <<'PY'
import json, statistics, sys
records = [json.loads(line) for line in open(sys.argv[1])]
failures, rounds, minimum_rounds = map(int, sys.argv[2:5])
duration_minutes = int(sys.argv[5])
require_release_qualified = bool(int(sys.argv[6]))
payload_sha256 = sys.argv[7]
max_distributed_attempts = int(sys.argv[8])
distributed_path, output = sys.argv[9:11]
with open(distributed_path) as handle:
    distributed = json.load(handle)
start, end = records[0], records[-1]
slope_gate_applied = duration_minutes >= 30
elapsed_seconds = end["monotonicSeconds"] - start["monotonicSeconds"]


def resource_stats(values):
    first, last = values[0], values[-1]
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
    sampled_rss_peak_growth_mib = (
        max(value["vmRssKiB"] for value in values) - first["vmRssKiB"]
    ) / 1024
    rss_hwm_growth_mib = (
        max(value["vmHwmKiB"] for value in values) - first["vmHwmKiB"]
    ) / 1024
    return {
        "start": first,
        "end": last,
        "fdGrowth": last["fds"] - first["fds"],
        "threadGrowth": last["threads"] - first["threads"],
        "rssGrowthMiB": round((last["vmRssKiB"] - first["vmRssKiB"]) / 1024, 1),
        "fdPeakGrowth": max(value["fds"] for value in values) - first["fds"],
        "threadPeakGrowth": max(value["threads"] for value in values) - first["threads"],
        # VmHWM persists process-lifetime transient peaks that can disappear
        # before the next sampled VmRSS snapshot. This is the gated RSS peak.
        "rssPeakGrowthMiB": round(rss_hwm_growth_mib, 1),
        "rssSampledPeakGrowthMiB": round(sampled_rss_peak_growth_mib, 1),
        "rssTailSlopeMiBPerHour": round(slope, 3),
    }


aggregate_resources = resource_stats([record["totals"] for record in records])
process_names = set(start["processes"])
if any(set(record["processes"]) != process_names for record in records):
    raise SystemExit("rust process set changed during soak")
resources_by_process = {
    name: resource_stats([record["processes"][name] for record in records])
    for name in sorted(process_names)
}


def resources_ok(stats):
    return (
        stats["fdGrowth"] <= 32
        and stats["threadGrowth"] <= 8
        and stats["rssGrowthMiB"] <= 32
        and stats["fdPeakGrowth"] <= 128
        and stats["threadPeakGrowth"] <= 8
        and stats["rssPeakGrowthMiB"] <= 64
        and (
            not slope_gate_applied
            or stats["rssTailSlopeMiBPerHour"] <= 2
        )
    )


distributed_attempts = distributed.get("attempts", 0)
required_distributed_attempts = distributed.get("requiredAttempts", 0)
ok = (
    failures == 0
    and rounds >= minimum_rounds
    and resources_ok(aggregate_resources)
    and all(resources_ok(stats) for stats in resources_by_process.values())
    and all(r.get("serverAlive") for r in records)
    and distributed.get("ok") is True
    and distributed_attempts >= required_distributed_attempts
    and distributed.get("reload", {}).get("triggerAttempts") == 1
    and distributed.get("reload", {}).get("expectedGeneration") == 1
    and len(distributed.get("reload", {}).get("logs", [])) == 5
    and distributed.get("landingConnectionRejections") == {
        "handoff": {},
        "nxr": {},
    }
    and distributed.get("handoffSeq1", {}).get("attempts") == distributed_attempts
    and distributed.get("handoffSeq1", {}).get("successes") == distributed_attempts
    and distributed.get("handoffSeq1", {}).get("failures") == 0
    and distributed.get("handoffSeq1", {}).get("fakeNstExpected") is True
    and distributed.get("handoffSeq1", {}).get("coverShapeEvents") == distributed_attempts
    and distributed.get("handoffSeq1", {}).get("appendedWireLength") == 139
    and distributed.get("handoffSeq1", {}).get("exportedServerSequence") == 1
    and distributed.get("handoffSeq1", {}).get("allServerSequenceOne") is True
    and distributed.get("handoffSeq1", {}).get("download", {}).get("bytes") == 1048576
    and distributed.get("handoffSeq1", {}).get("download", {}).get("sha256") == distributed.get("payloadSha256")
    and distributed.get("nxrByteIntegrity", {}).get("attempts") == distributed_attempts
    and distributed.get("nxrByteIntegrity", {}).get("successes") == distributed_attempts
    and distributed.get("nxrByteIntegrity", {}).get("failures") == 0
    and distributed.get("nxrByteIntegrity", {}).get("download", {}).get("bytes") == 1048576
    and distributed.get("nxrByteIntegrity", {}).get("download", {}).get("sha256") == distributed.get("payloadSha256")
    and distributed.get("socks5ByteIntegrity", {}).get("attempts") == distributed_attempts
    and distributed.get("socks5ByteIntegrity", {}).get("successes") == distributed_attempts
    and distributed.get("socks5ByteIntegrity", {}).get("failures") == 0
    and distributed.get("socks5ByteIntegrity", {}).get("preparation") == "tcp-only"
    and distributed.get("socks5ByteIntegrity", {}).get("download", {}).get("bytes") == 1048576
    and distributed.get("socks5ByteIntegrity", {}).get("download", {}).get("sha256") == distributed.get("payloadSha256")
)
release_qualified = (
    ok
    and duration_minutes == 720
    and elapsed_seconds >= 720 * 60
    and slope_gate_applied
    and distributed.get("intervalSeconds", 1801) <= 1800
    and distributed.get("intervalSeconds", 0) >= 300
    and distributed_attempts >= 25
    and distributed_attempts <= max_distributed_attempts
    and distributed.get("handoffSeq1", {}).get("attempts", 0) >= 25
    and distributed.get("handoffSeq1", {}).get("successes", 0) >= 25
    and distributed.get("handoffSeq1", {}).get("failures") == 0
    and distributed.get("nxrByteIntegrity", {}).get("attempts", 0) >= 25
    and distributed.get("nxrByteIntegrity", {}).get("successes", 0) >= 25
    and distributed.get("nxrByteIntegrity", {}).get("failures") == 0
    and distributed.get("socks5ByteIntegrity", {}).get("attempts", 0) >= 25
    and distributed.get("socks5ByteIntegrity", {}).get("successes", 0) >= 25
    and distributed.get("socks5ByteIntegrity", {}).get("failures") == 0
)
summary = {
    "rounds": rounds,
    "transferFailures": failures,
    "start": start,
    "end": end,
    "fdGrowth": aggregate_resources["fdGrowth"],
    "threadGrowth": aggregate_resources["threadGrowth"],
    "rssGrowthMiB": aggregate_resources["rssGrowthMiB"],
    "minimumRounds": minimum_rounds,
    "maxDistributedAttempts": max_distributed_attempts,
    "payloadSha256": payload_sha256,
    "fdPeakGrowth": aggregate_resources["fdPeakGrowth"],
    "threadPeakGrowth": aggregate_resources["threadPeakGrowth"],
    "rssPeakGrowthMiB": aggregate_resources["rssPeakGrowthMiB"],
    "rssSampledPeakGrowthMiB": aggregate_resources["rssSampledPeakGrowthMiB"],
    "rssTailSlopeMiBPerHour": aggregate_resources["rssTailSlopeMiBPerHour"],
    "resourceAggregate": aggregate_resources,
    "resourceByProcess": resources_by_process,
    "rssTailSlopeGateApplied": slope_gate_applied,
    "durationMinutes": duration_minutes,
    "elapsedSeconds": round(elapsed_seconds, 3),
    "releaseQualified": release_qualified,
    "distributedGates": distributed,
    "ok": ok,
}
with open(output, "x") as fh:
    json.dump({"summary": summary, "snapshots": records}, fh, indent=2)
print(json.dumps(summary))
sys.exit(0 if ok and (not require_release_qualified or release_qualified) else 1)
PY
if (( contract_initialized == 1 )); then
    rr_finalize_contract
fi
