#!/usr/bin/env bash
# Compare one exact stock-Xray ClientHello against a pinned libssl reference,
# rust-reality, and Xray. Raw captures are written outside Git by default.
set -Eeuo pipefail

readonly REPOSITORY="$({ cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."; pwd; })"
readonly HELPER="$REPOSITORY/scripts/tls-shape-helper.py"
readonly REFERENCE_SOURCE="$REPOSITORY/scripts/tls-shape-reference.c"

reference_server=
reference_sha256=
openssl_reference_version=
rust_binary=
rust_sha256=
baseline_rust_binary=
baseline_rust_sha256=
xray_binary=
xray_sha256=
reference_certificate=
reference_private_key=
case_name=openssl-reference-shape
ciphersuites=TLS_AES_128_GCM_SHA256
tls_groups=X25519MLKEM768:X25519
alpn=h2
middlebox=1
max_fragment=0
split_fragment=0
padding=0
tcp_nodelay=0
samples=3
base_port=39460
xray_server_comparator=1
output_dir=
strace_mode=auto
tcpdump_mode=auto
self_test=0

usage() {
    cat <<'EOF'
Usage:
  scripts/benchmark-tls-shape.sh --self-test

  scripts/benchmark-tls-shape.sh \
    --reference-server PATH --reference-sha256 HEX \
    --openssl-reference-version TEXT \
    --reference-cert PATH --reference-key PATH \
    --rust-binary PATH --rust-sha256 HEX \
    [--baseline-rust-binary PATH --baseline-rust-sha256 HEX] \
    --xray-binary PATH --xray-sha256 HEX [OPTIONS]

Required identities are verified before any listener starts. The reference
server must implement the positional interface and --identity output in
tls-shape-reference.c. --openssl-reference-version is a human-readable expected
label; the linked OpenSSL compile/runtime identity is read from the executable.
When the optional baseline is supplied, baseline and candidate run sequentially
with the same generated config and exact captured authenticated ClientHello.

Options:
  --case NAME                    Result label (default: openssl-reference-shape)
  --baseline-rust-binary PATH    Optional before comparator; requires its SHA
  --baseline-rust-sha256 HEX     SHA-256 for the optional before comparator
  --ciphersuites LIST           TLS 1.3 suites (default: TLS_AES_128_GCM_SHA256)
  --tls-groups LIST             OpenSSL group list (default: X25519MLKEM768:X25519)
  --alpn VALUE                  Selected ALPN (default: h2)
  --middlebox 0|1               CCS compatibility mode (default: 1)
  --max-fragment N              Maximum send fragment; 0 leaves default
  --split-fragment N            Split send fragment; 0 leaves default
  --padding N                   Fixed TLS 1.3 record padding bytes (default: 0)
  --tcp-nodelay 0|1             Reference TCP_NODELAY (default: 0)
  --samples N                   Repetitions, 1..10 (default: 3)
  --base-port N                 Seven consecutive loopback ports (default: 39460)
  --xray-server-comparator 0|1 Compare the replayed flight with Xray's server
                                (default: 1). Set to 0 only when the captured
                                ClientHello shape is unsupported by that server;
                                Xray still generates the authenticated ClientHello.
  --output-dir PATH             Must be outside the Git worktree. Default:
                                ../artifacts/tls-shape/CASE-UTC_TIMESTAMP
  --strace auto|required|off    Process-write capture (default: auto)
  --tcpdump auto|required|off   Raw loopback PCAP capture (default: auto)
  --help                        Show this help

Build the reference server against the exact pinned OpenSSL build, then hash
the executable. One example (dynamic linkage is only reproducible when its
libraries are separately pinned):

  cc -std=c11 -O2 -g -fno-omit-frame-pointer \
    scripts/tls-shape-reference.c -o /external/reference_server \
    $(pkg-config --cflags --libs openssl)
  sha256sum /external/reference_server

Security and methodology:
  * Secret configs and generated REALITY keys exist only in a mode-0700 temp
    directory and are deleted on exit.
  * Persisted JSON contains identities, hashes, record/write/packet shape, and
    timings—not UUIDs, private keys, short IDs, or AuthKey material.
  * ClientHello, wire, strace, and optional PCAP files are raw research data.
    The script requires their output directory to be outside Git.
  * TLS packetization is reported separately from process-write shape.
    Loopback packet comparisons are always classified NETWORK_DEPENDENT.
  * Timings collected while strace is active are retained as raw observations
    but classified NOT_COMPARABLE.
  * Missing optional tools are recorded as unavailable, never reported PASS.
  * Each proxy/replay transaction has a 5-second absolute deadline. ClientHello
    capture is capped at one legal 16-KiB TLS record and each server first
    flight at 1 MiB; a bound breach preserves partial evidence as INVALID.
EOF
}

die() {
    printf 'benchmark-tls-shape: %s\n' "$*" >&2
    exit 1
}

need_argument() {
    [[ $# -ge 2 ]] || die "missing value for $1"
}

while (($#)); do
    case "$1" in
        --reference-server) need_argument "$@"; reference_server=$2; shift 2 ;;
        --reference-sha256) need_argument "$@"; reference_sha256=$2; shift 2 ;;
        --openssl-reference-version)
            need_argument "$@"; openssl_reference_version=$2; shift 2 ;;
        --reference-cert) need_argument "$@"; reference_certificate=$2; shift 2 ;;
        --reference-key) need_argument "$@"; reference_private_key=$2; shift 2 ;;
        --rust-binary) need_argument "$@"; rust_binary=$2; shift 2 ;;
        --rust-sha256) need_argument "$@"; rust_sha256=$2; shift 2 ;;
        --baseline-rust-binary)
            need_argument "$@"; baseline_rust_binary=$2; shift 2 ;;
        --baseline-rust-sha256)
            need_argument "$@"; baseline_rust_sha256=$2; shift 2 ;;
        --xray-binary) need_argument "$@"; xray_binary=$2; shift 2 ;;
        --xray-sha256) need_argument "$@"; xray_sha256=$2; shift 2 ;;
        --case) need_argument "$@"; case_name=$2; shift 2 ;;
        --ciphersuites) need_argument "$@"; ciphersuites=$2; shift 2 ;;
        --tls-groups) need_argument "$@"; tls_groups=$2; shift 2 ;;
        --alpn) need_argument "$@"; alpn=$2; shift 2 ;;
        --middlebox) need_argument "$@"; middlebox=$2; shift 2 ;;
        --max-fragment) need_argument "$@"; max_fragment=$2; shift 2 ;;
        --split-fragment) need_argument "$@"; split_fragment=$2; shift 2 ;;
        --padding) need_argument "$@"; padding=$2; shift 2 ;;
        --tcp-nodelay) need_argument "$@"; tcp_nodelay=$2; shift 2 ;;
        --samples) need_argument "$@"; samples=$2; shift 2 ;;
        --base-port) need_argument "$@"; base_port=$2; shift 2 ;;
        --xray-server-comparator)
            need_argument "$@"; xray_server_comparator=$2; shift 2 ;;
        --output-dir) need_argument "$@"; output_dir=$2; shift 2 ;;
        --strace) need_argument "$@"; strace_mode=$2; shift 2 ;;
        --tcpdump) need_argument "$@"; tcpdump_mode=$2; shift 2 ;;
        --self-test) self_test=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

if ((self_test)); then
    python3 "$HELPER" self-test
    if command -v cc >/dev/null 2>&1 && command -v pkg-config >/dev/null 2>&1 &&
        pkg-config --exists openssl; then
        self_test_directory=$(mktemp -d)
        trap 'rm -rf -- "$self_test_directory"' EXIT
        # shellcheck disable=SC2046
        cc -std=c11 -Wall -Wextra -Werror $(pkg-config --cflags openssl) \
            "$REFERENCE_SOURCE" -o "$self_test_directory/reference" \
            $(pkg-config --libs openssl)
        "$self_test_directory/reference" --identity \
            >"$self_test_directory/identity.json"
        python3 - "$self_test_directory/identity.json" <<'PY'
import json
import sys

identity = json.loads(open(sys.argv[1], encoding="utf-8").read())
assert identity["schemaVersion"] == 1
assert identity["opensslCompileVersion"]
assert identity["opensslRuntimeVersion"]
assert identity["configPolicy"] == "OPENSSL_INIT_NO_LOAD_CONFIG"
assert identity["providerPolicy"] == ["default"]
PY
        printf 'tls-shape reference C build/identity: PASS\n'
    else
        printf '%s\n' \
            'tls-shape reference C build/identity: INFRASTRUCTURE-BLOCKED (cc/pkg-config/openssl missing)'
    fi
    exit 0
fi

for program in curl jq python3 sha256sum setsid; do
    command -v "$program" >/dev/null 2>&1 || die "required tool unavailable: $program"
done

[[ -n $reference_server ]] || die '--reference-server is required'
[[ -n $reference_sha256 ]] || die '--reference-sha256 is required'
[[ -n $openssl_reference_version ]] || die '--openssl-reference-version is required'
[[ -n $reference_certificate ]] || die '--reference-cert is required'
[[ -n $reference_private_key ]] || die '--reference-key is required'
[[ -n $rust_binary ]] || die '--rust-binary is required'
[[ -n $rust_sha256 ]] || die '--rust-sha256 is required'
[[ -n $xray_binary ]] || die '--xray-binary is required'
[[ -n $xray_sha256 ]] || die '--xray-sha256 is required'
baseline_present=false
if [[ -n $baseline_rust_binary || -n $baseline_rust_sha256 ]]; then
    [[ -n $baseline_rust_binary && -n $baseline_rust_sha256 ]] ||
        die '--baseline-rust-binary and --baseline-rust-sha256 must be provided together'
    baseline_present=true
fi

for value in "$middlebox" "$max_fragment" "$split_fragment" "$padding" \
    "$tcp_nodelay" "$samples" "$base_port" "$xray_server_comparator"; do
    [[ $value =~ ^[0-9]+$ ]] || die "numeric option is not an unsigned integer: $value"
done
((middlebox <= 1)) || die '--middlebox must be 0 or 1'
((tcp_nodelay <= 1)) || die '--tcp-nodelay must be 0 or 1'
((xray_server_comparator <= 1)) || die '--xray-server-comparator must be 0 or 1'
((max_fragment <= 16384)) || die '--max-fragment exceeds 16384'
((split_fragment <= 16384)) || die '--split-fragment exceeds 16384'
((padding <= 16384)) || die '--padding exceeds 16384'
((samples >= 1 && samples <= 10)) || die '--samples must be in 1..10'
((base_port >= 1024 && base_port + 6 <= 65535)) || die '--base-port is out of range'
[[ $case_name =~ ^[A-Za-z0-9._-]+$ ]] || die '--case contains unsafe path characters'
[[ $strace_mode =~ ^(auto|required|off)$ ]] || die 'invalid --strace mode'
[[ $tcpdump_mode =~ ^(auto|required|off)$ ]] || die 'invalid --tcpdump mode'

for path in "$reference_server" "$reference_certificate" "$reference_private_key" \
    "$rust_binary" "$xray_binary" "$HELPER"; do
    [[ -f $path ]] || die "file does not exist: $path"
done
[[ -x $reference_server ]] || die "reference server is not executable: $reference_server"
[[ -x $rust_binary ]] || die "rust-reality binary is not executable: $rust_binary"
[[ -x $xray_binary ]] || die "Xray binary is not executable: $xray_binary"
if [[ $baseline_present == true ]]; then
    [[ -f $baseline_rust_binary ]] ||
        die "baseline rust-reality file does not exist: $baseline_rust_binary"
    [[ -x $baseline_rust_binary ]] ||
        die "baseline rust-reality is not executable: $baseline_rust_binary"
fi

reference_server=$(realpath "$reference_server")
reference_certificate=$(realpath "$reference_certificate")
reference_private_key=$(realpath "$reference_private_key")
rust_binary=$(realpath "$rust_binary")
xray_binary=$(realpath "$xray_binary")
if [[ $baseline_present == true ]]; then
    baseline_rust_binary=$(realpath "$baseline_rust_binary")
fi

verify_sha256() {
    local label=$1 path=$2 expected=$3 actual
    [[ $expected =~ ^[0-9a-fA-F]{64}$ ]] || die "$label expected SHA-256 is malformed"
    actual=$(sha256sum "$path" | awk '{print $1}')
    [[ ${actual,,} == ${expected,,} ]] ||
        die "$label SHA-256 mismatch: expected $expected, got $actual"
}

verify_sha256 OPENSSL_REFERENCE "$reference_server" "$reference_sha256"
verify_sha256 rust-reality "$rust_binary" "$rust_sha256"
verify_sha256 Xray "$xray_binary" "$xray_sha256"
if [[ $baseline_present == true ]]; then
    verify_sha256 baseline-rust-reality "$baseline_rust_binary" \
        "$baseline_rust_sha256"
fi

if [[ -z $output_dir ]]; then
    output_dir="$REPOSITORY/../artifacts/tls-shape/${case_name}-$(date -u +%Y%m%dT%H%M%SZ)"
fi
mkdir -p "$(dirname -- "$output_dir")"
output_parent=$(realpath "$(dirname -- "$output_dir")")
output_dir="$output_parent/$(basename -- "$output_dir")"
case "$output_dir/" in
    "$REPOSITORY"/*) die '--output-dir must be outside the Git worktree' ;;
esac
[[ ! -e $output_dir ]] || die "output directory already exists: $output_dir"
mkdir -m 700 "$output_dir"

umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/rust-reality-tls-shape.XXXXXX")
declare -A active_pids=()
declare -A active_process_groups=()
declare -A active_capture_paths=()
run_state=RUNNING
run_phase=setup
run_sample=
run_sample_dir=
run_started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)

write_run_status() {
    local temporary_status="$output_dir/.run-status.$$"
    jq -n --arg state "$run_state" --arg phase "$run_phase" \
        --arg sample "$run_sample" --arg started_at "$run_started_utc" \
        --arg updated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{state:$state,phase:$phase,sample:(if $sample == "" then null else $sample end),startedAt:$started_at,updatedAt:$updated_at}' \
        >"$temporary_status"
    mv -f -- "$temporary_status" "$output_dir/run-status.json"
}

pid_start_time() {
    local pid=$1
    [[ -r /proc/$pid/stat ]] || return 1
    awk '{print $22}' "/proc/$pid/stat"
}

pid_matches_registration() {
    local pid=$1 map_name=$2 current
    local -n registrations=$map_name
    [[ -n ${registrations[$pid]:-} ]] || return 1
    current=$(pid_start_time "$pid" 2>/dev/null) || return 1
    [[ $current == "${registrations[$pid]}" ]]
}

register_pid() {
    local start_time
    start_time=$(pid_start_time "$1") || die "could not register child PID $1"
    active_pids["$1"]=$start_time
}

register_group() {
    local start_time
    start_time=$(pid_start_time "$1") || die "could not register process group $1"
    active_process_groups["$1"]=$start_time
}

cleanup() {
    local pid
    for pid in "${!active_process_groups[@]}"; do
        if pid_matches_registration "$pid" active_process_groups; then
            kill -TERM -- "-$pid" 2>/dev/null || true
        fi
    done
    for pid in "${!active_pids[@]}"; do
        if pid_matches_registration "$pid" active_pids; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    for pid in "${!active_process_groups[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    for pid in "${!active_pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    for pid in "${!active_capture_paths[@]}"; do
        if [[ -f ${active_capture_paths[$pid]} ]]; then
            normalize_capture "${active_capture_paths[$pid]}" 2>/dev/null || true
        fi
    done
    [[ -n ${work:-} && -d $work ]] && rm -rf -- "$work"
}

finish() {
    local status=$?
    trap - EXIT
    if ((status != 0)); then
        run_state=FAILED
        if [[ -n $run_sample_dir && -d $run_sample_dir ]]; then
            jq -n --arg status INVALID --arg phase "$run_phase" \
                --arg sample "$run_sample" --argjson exit_code "$status" \
                '{status:$status,phase:$phase,sample:$sample,exitCode:$exit_code}' \
                >"$run_sample_dir/invalid.json" 2>/dev/null || true
        fi
        write_run_status 2>/dev/null || true
    fi
    cleanup
    exit "$status"
}
trap finish EXIT
write_run_status

strace_status=disabled
if [[ $strace_mode != off ]]; then
    if command -v strace >/dev/null 2>&1; then
        strace_status=available
    elif [[ $strace_mode == required ]]; then
        die 'strace is required but unavailable'
    else
        strace_status=unavailable
        printf '%s\n' 'strace: INFRASTRUCTURE-BLOCKED; process write shape will be NOT_COMPARABLE' >&2
    fi
fi

tcpdump_status=disabled
tcpdump_command=()
if [[ $tcpdump_mode != off ]]; then
    if command -v tcpdump >/dev/null 2>&1; then
        if ((EUID == 0)); then
            tcpdump_command=(tcpdump)
            tcpdump_status=available
        elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
            tcpdump_command=(sudo -n tcpdump)
            tcpdump_status=available
        fi
    fi
    if [[ $tcpdump_status != available ]]; then
        if [[ $tcpdump_mode == required ]]; then
            die 'tcpdump is required but unavailable or lacks capture permission'
        fi
        tcpdump_status=unavailable
        printf '%s\n' 'tcpdump: INFRASTRUCTURE-BLOCKED; packet shape will be NOT_COMPARABLE' >&2
    fi
fi

readonly cover_port=$base_port
readonly rust_port=$((base_port + 1))
readonly proxy_port=$((base_port + 2))
readonly socks_port=$((base_port + 3))
readonly origin_port=$((base_port + 4))
readonly direct_reference_port=$((base_port + 5))
readonly xray_server_port=$((base_port + 6))

python3 - "$cover_port" "$rust_port" "$proxy_port" "$socks_port" \
    "$origin_port" "$direct_reference_port" "$xray_server_port" <<'PY'
import socket
import sys

sockets = []
try:
    for text in sys.argv[1:]:
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", int(text)))
        sock.listen(1)
        sockets.append(sock)
finally:
    for sock in sockets:
        sock.close()
PY

wait_port() {
    python3 - "$1" <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
deadline = time.monotonic() + 10
while time.monotonic() < deadline:
    with socket.socket() as connection:
        connection.settimeout(0.05)
        if connection.connect_ex(("127.0.0.1", port)) == 0:
            raise SystemExit(0)
    time.sleep(0.02)
raise SystemExit(f"port {port} did not become ready")
PY
}

wait_log() {
    local path=$1 pattern=$2
    local attempt
    for attempt in $(seq 1 500); do
        if [[ -f $path ]] && grep -Eq "$pattern" "$path"; then
            return 0
        fi
        sleep 0.02
    done
    die "timed out waiting for a readiness marker"
}

stop_pid() {
    local pid=$1
    if pid_matches_registration "$pid" active_pids; then
        kill -TERM "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
    unset 'active_pids[$pid]'
}

stop_group() {
    local pid=$1
    if pid_matches_registration "$pid" active_process_groups; then
        kill -TERM -- "-$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
    unset 'active_process_groups[$pid]'
}

stop_tcpdump() {
    local parent=$1
    local children=()
    if pid_matches_registration "$parent" active_pids &&
        [[ -r /proc/$parent/task/$parent/children ]]; then
        read -r -a children <"/proc/$parent/task/$parent/children" || true
    fi
    local child
    for child in "${children[@]:-}"; do
        if ((EUID == 0)); then
            kill -INT "$child" 2>/dev/null || true
        else
            sudo -n kill -INT "$child" 2>/dev/null || true
        fi
    done
    if pid_matches_registration "$parent" active_pids; then
        kill -INT "$parent" 2>/dev/null || true
    fi
    wait "$parent" 2>/dev/null || true
    if [[ -f ${active_capture_paths[$parent]:-} ]]; then
        normalize_capture "${active_capture_paths[$parent]}"
    fi
    unset 'active_capture_paths[$parent]'
    unset 'active_pids[$parent]'
}

normalize_capture() {
    local path=$1
    if ((EUID == 0)); then
        chown -- "$(id -u):$(id -g)" "$path"
    else
        sudo -n chown -- "$(id -u):$(id -g)" "$path"
    fi
    chmod 600 "$path"
}

start_tcpdump() {
    local destination=$1 port=$2 log=$3
    started_tcpdump_pid=
    [[ $tcpdump_status == available ]] || return 0
    "${tcpdump_command[@]}" --immediate-mode -i lo -U -s 0 -w "$destination" \
        "tcp port $port" >"$log" 2>&1 &
    started_tcpdump_pid=$!
    register_pid "$started_tcpdump_pid"
    active_capture_paths["$started_tcpdump_pid"]=$destination
    wait_log "$log" 'listening on'
}

start_traced_group() {
    local prefix=$1 stdout_path=$2 stderr_path=$3
    shift 3
    if [[ $strace_status == available ]]; then
        setsid strace -ff -ttt -yy -s 1 -e trace=write,writev,sendto,sendmsg \
            -o "$prefix" "$@" >"$stdout_path" 2>"$stderr_path" &
    else
        setsid "$@" >"$stdout_path" 2>"$stderr_path" &
    fi
    started_group_pid=$!
    register_group "$started_group_pid"
}

proxy_free_env=(env -u ALL_PROXY -u all_proxy -u HTTP_PROXY -u http_proxy
    -u HTTPS_PROXY -u https_proxy -u NO_PROXY -u no_proxy)

run_phase=reference-self-identity
write_run_status
"$reference_server" --identity >"$work/reference-self-identity.json"
jq -e '.schemaVersion == 1 and
    (.opensslCompileVersion | type == "string" and length > 0) and
    (.opensslRuntimeVersion | type == "string" and length > 0) and
    .configPolicy == "OPENSSL_INIT_NO_LOAD_CONFIG" and
    .providerPolicy == ["default"]' \
    "$work/reference-self-identity.json" >/dev/null ||
    die 'reference server did not emit its required linked-OpenSSL identity'
reference_self_identity_sha256=$(sha256sum "$work/reference-self-identity.json" |
    awk '{print $1}')

run_phase=stock-xray-clienthello
write_run_status
printf 'tls-shape\n' >"$work/health.txt"
"${proxy_free_env[@]}" python3 -m http.server "$origin_port" --bind 127.0.0.1 \
    --directory "$work" >"$work/origin.log" 2>&1 &
origin_pid=$!
register_pid "$origin_pid"
wait_port "$origin_port"

"$rust_binary" config generate standalone --listen 127.0.0.1 --port "$rust_port" \
    --target "127.0.0.1:$cover_port" --server-name localhost \
    >"$work/rust.raw.json" 2>"$work/generate.log"
jq --arg cache "$work/assets" '.log.level="warn" | .assets.cacheDirectory=$cache' \
    "$work/rust.raw.json" >"$work/rust.json"
sed -n 's/^REALITY public key for the client: //p' "$work/generate.log" \
    >"$work/public-key"
[[ -s $work/public-key ]] || die 'generated REALITY public key was incomplete'
jq -e '[.inbounds[0].settings.clients[0].id,
    .inbounds[0].settings.clients[0].shortIds[0],
    .inbounds[0].streamSettings.realitySettings.privateKey] |
    all(. != null and type == "string" and length > 0)' \
    "$work/rust.raw.json" >/dev/null || die 'generated REALITY identity was incomplete'

jq -n --slurpfile rust "$work/rust.raw.json" \
    --rawfile public_key "$work/public-key" \
    --argjson server_port "$proxy_port" --argjson socks_port "$socks_port" \
    '($rust[0].inbounds[0].settings.clients[0].id) as $uuid |
    ($rust[0].inbounds[0].settings.clients[0].shortIds[0]) as $short_id |
    ($public_key | rtrimstr("\n")) as $client_public_key |
    {log:{loglevel:"warning"},inbounds:[{listen:"127.0.0.1",port:$socks_port,protocol:"socks",settings:{auth:"noauth",udp:false}}],outbounds:[{protocol:"vless",settings:{vnext:[{address:"127.0.0.1",port:$server_port,users:[{id:$uuid,encryption:"none",flow:"xtls-rprx-vision"}]}]},streamSettings:{network:"tcp",security:"reality",realitySettings:{fingerprint:"chrome",serverName:"localhost",publicKey:$client_public_key,shortId:$short_id,spiderX:"/"}}}]}' \
    >"$work/xray-client.json"
jq -n --slurpfile rust "$work/rust.raw.json" --argjson port "$xray_server_port" \
    --arg target "127.0.0.1:$cover_port" \
    '($rust[0].inbounds[0].settings.clients[0].id) as $uuid |
    ($rust[0].inbounds[0].settings.clients[0].shortIds[0]) as $short_id |
    ($rust[0].inbounds[0].streamSettings.realitySettings.privateKey) as $private_key |
    {log:{loglevel:"warning"},inbounds:[{listen:"127.0.0.1",port:$port,protocol:"vless",settings:{clients:[{id:$uuid,flow:"xtls-rprx-vision"}],decryption:"none"},streamSettings:{network:"tcp",security:"reality",realitySettings:{show:false,target:$target,xver:0,serverNames:["localhost"],privateKey:$private_key,shortIds:[$short_id]}}}],outbounds:[{tag:"direct",protocol:"freedom",settings:{finalRules:[{action:"allow"}]}}]}' \
    >"$work/xray-server.json"

"${proxy_free_env[@]}" "$rust_binary" serve --config "$work/rust.json" \
    >"$work/rust-initial.log" 2>&1 &
rust_initial_pid=$!
register_pid "$rust_initial_pid"
wait_port "$rust_port"
"$reference_server" "$cover_port" "$reference_certificate" "$reference_private_key" \
    "$ciphersuites" "$tls_groups" "$alpn" "$middlebox" "$max_fragment" \
    "$split_fragment" "$padding" "$tcp_nodelay" \
    >"$work/cover-initial.stdout" 2>"$work/cover-initial.stderr" &
cover_initial_pid=$!
register_pid "$cover_initial_pid"
wait_log "$work/cover-initial.stderr" '^READY '
python3 "$HELPER" proxy --listen-port "$proxy_port" --upstream-port "$rust_port" \
    --output "$output_dir/clienthello.bin" >"$work/proxy.log" 2>"$work/proxy.stderr" &
proxy_pid=$!
register_pid "$proxy_pid"
wait_log "$work/proxy.log" '^READY '
"${proxy_free_env[@]}" "$xray_binary" run -config "$work/xray-client.json" \
    >"$work/xray-client.log" 2>&1 &
xray_client_pid=$!
register_pid "$xray_client_pid"
wait_port "$socks_port"
"${proxy_free_env[@]}" curl --fail --silent --show-error \
    --socks5-hostname "127.0.0.1:$socks_port" --max-time 10 \
    "http://127.0.0.1:$origin_port/health.txt" --output "$work/download.txt"
grep -qx 'tls-shape' "$work/download.txt" || die 'stock Xray compatibility payload differed'
wait_log "$work/proxy.log" '^CAPTURED '
chmod 600 "$output_dir/clienthello.bin"
stop_pid "$xray_client_pid"
stop_pid "$proxy_pid"
stop_pid "$rust_initial_pid"
stop_pid "$cover_initial_pid"

repository_head=$(git -C "$REPOSITORY" rev-parse HEAD 2>/dev/null || printf unavailable)
repository_describe=$(git -C "$REPOSITORY" describe --tags --always --dirty \
    2>/dev/null || printf unavailable)
repository_dirty=false
if [[ -n $(git -C "$REPOSITORY" status --porcelain=v1 --untracked-files=normal \
    2>/dev/null) ]]; then
    repository_dirty=true
fi
reference_actual_sha256=$(sha256sum "$reference_server" | awk '{print $1}')
rust_actual_sha256=$(sha256sum "$rust_binary" | awk '{print $1}')
xray_actual_sha256=$(sha256sum "$xray_binary" | awk '{print $1}')
baseline_rust_actual_sha256=
baseline_rust_version=
if [[ $baseline_present == true ]]; then
    baseline_rust_actual_sha256=$(sha256sum "$baseline_rust_binary" | awk '{print $1}')
    baseline_rust_version=$("$baseline_rust_binary" --version 2>/dev/null |
        sed -n '1p' || printf unavailable)
fi
certificate_sha256=$(sha256sum "$reference_certificate" | awk '{print $1}')
client_hello_sha256=$(sha256sum "$output_dir/clienthello.bin" | awk '{print $1}')
ephemeral_rust_config_sha256=$(sha256sum "$work/rust.json" | awk '{print $1}')
rust_version=$("$rust_binary" --version 2>/dev/null | sed -n '1p' || printf unavailable)
xray_version=$("$xray_binary" version 2>/dev/null | sed -n '1p' || printf unavailable)
capture_host_rustc=$(rustc --version 2>/dev/null || printf unavailable)
capture_host_cc=$(cc --version 2>/dev/null | sed -n '1p' || printf unavailable)
kernel=$(uname -srmo)
cpu=$(awk -F ': *' '/^model name[[:space:]]*:/ {print $2; exit}' /proc/cpuinfo)
reference_build_id=
if command -v readelf >/dev/null 2>&1; then
    reference_build_id=$(readelf -n "$reference_server" 2>/dev/null |
        sed -n 's/.*Build ID: //p' | sed -n '1p' || true)
fi
[[ -n $reference_build_id ]] || reference_build_id=unavailable
harness_sha256=$(sha256sum "$0" | awk '{print $1}')
helper_sha256=$(sha256sum "$HELPER" | awk '{print $1}')
reference_source_sha256=$(sha256sum "$REFERENCE_SOURCE" | awk '{print $1}')

jq -n --slurpfile reference_self_identity "$work/reference-self-identity.json" \
    --arg repository_head "$repository_head" \
    --arg repository_describe "$repository_describe" \
    --argjson repository_dirty "$repository_dirty" \
    --arg capture_host_rustc "$capture_host_rustc" \
    --arg capture_host_cc "$capture_host_cc" --arg kernel "$kernel" \
    --arg cpu "$cpu" --arg case_name "$case_name" \
    --arg reference_path "$reference_server" \
    --arg reference_sha256 "$reference_actual_sha256" \
    --arg reference_version_label "$openssl_reference_version" \
    --arg reference_build_id "$reference_build_id" \
    --arg reference_self_identity_sha256 "$reference_self_identity_sha256" \
    --arg certificate_sha256 "$certificate_sha256" \
    --arg rust_path "$rust_binary" --arg rust_sha256 "$rust_actual_sha256" \
    --arg rust_version "$rust_version" --arg xray_path "$xray_binary" \
    --argjson baseline_present "$baseline_present" \
    --arg baseline_rust_path "$baseline_rust_binary" \
    --arg baseline_rust_sha256 "$baseline_rust_actual_sha256" \
    --arg baseline_rust_version "$baseline_rust_version" \
    --arg xray_sha256 "$xray_actual_sha256" --arg xray_version "$xray_version" \
    --argjson xray_server_comparator "$xray_server_comparator" \
    --arg ciphersuites "$ciphersuites" --arg tls_groups "$tls_groups" \
    --arg alpn "$alpn" --argjson middlebox "$middlebox" \
    --argjson max_fragment "$max_fragment" --argjson split_fragment "$split_fragment" \
    --argjson padding "$padding" --argjson tcp_nodelay "$tcp_nodelay" \
    --argjson cover_port "$cover_port" --argjson rust_port "$rust_port" \
    --argjson proxy_port "$proxy_port" --argjson socks_port "$socks_port" \
    --argjson origin_port "$origin_port" \
    --argjson reference_port "$direct_reference_port" \
    --argjson xray_server_port "$xray_server_port" \
    --arg strace_status "$strace_status" --arg tcpdump_status "$tcpdump_status" \
    --arg client_hello_sha256 "$client_hello_sha256" \
    --arg ephemeral_rust_config_sha256 "$ephemeral_rust_config_sha256" \
    --arg harness_sha256 "$harness_sha256" --arg helper_sha256 "$helper_sha256" \
    --arg reference_source_sha256 "$reference_source_sha256" \
    '{repository:{head:$repository_head,describe:$repository_describe,dirty:$repository_dirty,role:"capture harness worktree; not proof of binary source provenance"},captureHost:{rustc:$capture_host_rustc,cc:$capture_host_cc,kernel:$kernel,cpu:$cpu},case:$case_name,reference:{path:$reference_path,sha256:$reference_sha256,requestedVersionLabel:$reference_version_label,selfIdentity:$reference_self_identity[0],selfIdentitySha256:$reference_self_identity_sha256,buildId:$reference_build_id,certificateFileSha256:$certificate_sha256},baselineRustReality:(if $baseline_present then {path:$baseline_rust_path,sha256:$baseline_rust_sha256,version:$baseline_rust_version,logging:"warn",sourceProvenance:"UNVERIFIED_BY_HARNESS"} else null end),rustReality:{role:"candidate",path:$rust_path,sha256:$rust_sha256,version:$rust_version,logging:"warn",sourceProvenance:"UNVERIFIED_BY_HARNESS"},xray:{path:$xray_path,sha256:$xray_sha256,version:$xray_version,logging:"warning",sourceProvenance:"UNVERIFIED_BY_HARNESS",serverComparatorEnabled:($xray_server_comparator == 1)},referenceOptions:{tlsVersion:"1.3-only",ciphersuites:$ciphersuites,groups:$tls_groups,alpn:$alpn,middlebox:$middlebox,maxFragment:$max_fragment,splitFragment:$split_fragment,padding:$padding,tcpNodelay:$tcp_nodelay},topology:{network:"loopback",packetCaptureInterface:"lo",ports:{cover:$cover_port,rustRealitySequentialComparators:$rust_port,captureProxy:$proxy_port,socks:$socks_port,origin:$origin_port,opensslReference:$reference_port,xrayServer:(if $xray_server_comparator == 1 then $xray_server_port else null end)}},clientHello:{source:"stock Xray chrome/uTLS",sha256:$client_hello_sha256,sharedAcrossAllComparators:true,ephemeralServerConfigSha256:$ephemeral_rust_config_sha256,ephemeralServerConfigRetained:false},tools:{strace:$strace_status,tcpdump:$tcpdump_status},harness:{entrypointSha256:$harness_sha256,helperSha256:$helper_sha256,referenceSourceSha256:$reference_source_sha256},rawCaptureNotice:"Raw ClientHello, wire, strace, and PCAP data; keep outside Git."}' \
    >"$output_dir/identity.json"

run_reference_sample() {
    local sample_dir=$1
    local tcpdump_pid=
    start_tcpdump "$sample_dir/reference.pcap" "$direct_reference_port" \
        "$sample_dir/reference.tcpdump.log"
    tcpdump_pid=$started_tcpdump_pid
    start_traced_group "$sample_dir/reference.strace" "$work/reference.stdout" \
        "$work/reference.stderr" "$reference_server" "$direct_reference_port" \
        "$reference_certificate" "$reference_private_key" "$ciphersuites" \
        "$tls_groups" "$alpn" "$middlebox" "$max_fragment" "$split_fragment" \
        "$padding" "$tcp_nodelay"
    local server_pid=$started_group_pid
    wait_log "$work/reference.stderr" '^READY '
    python3 "$HELPER" replay --port "$direct_reference_port" \
        --client-hello "$output_dir/clienthello.bin" \
        --wire-output "$sample_dir/reference.wire" \
        --summary-output "$sample_dir/reference.json"
    wait "$server_pid" || true
    unset 'active_process_groups[$server_pid]'
    if [[ -n $tcpdump_pid ]]; then
        stop_tcpdump "$tcpdump_pid"
        tcpdump -nn -tt -r "$sample_dir/reference.pcap" \
            >"$sample_dir/reference.packets.txt" 2>/dev/null
    fi
}

run_rust_sample() {
    local sample_dir=$1 stem=$2 binary=$3
    local tcpdump_pid=
    start_tcpdump "$sample_dir/$stem.pcap" "$rust_port" \
        "$sample_dir/$stem.tcpdump.log"
    tcpdump_pid=$started_tcpdump_pid
    start_traced_group "$sample_dir/$stem.strace" "$work/$stem.stdout" \
        "$work/$stem.stderr" "${proxy_free_env[@]}" "$binary" serve \
        --config "$work/rust.json"
    local server_pid=$started_group_pid
    wait_port "$rust_port"
    "$reference_server" "$cover_port" "$reference_certificate" \
        "$reference_private_key" "$ciphersuites" "$tls_groups" "$alpn" \
        "$middlebox" "$max_fragment" "$split_fragment" "$padding" "$tcp_nodelay" \
        >"$work/cover-$stem.stdout" 2>"$work/cover-$stem.stderr" &
    local cover_pid=$!
    register_pid "$cover_pid"
    wait_log "$work/cover-$stem.stderr" '^READY '
    python3 "$HELPER" replay --port "$rust_port" \
        --client-hello "$output_dir/clienthello.bin" \
        --wire-output "$sample_dir/$stem.wire" \
        --summary-output "$sample_dir/$stem.json"
    stop_group "$server_pid"
    stop_pid "$cover_pid"
    if [[ -n $tcpdump_pid ]]; then
        stop_tcpdump "$tcpdump_pid"
        tcpdump -nn -tt -r "$sample_dir/$stem.pcap" \
            >"$sample_dir/$stem.packets.txt" 2>/dev/null
    fi
}

run_xray_sample() {
    local sample_dir=$1
    local tcpdump_pid=
    start_tcpdump "$sample_dir/xray.pcap" "$xray_server_port" \
        "$sample_dir/xray.tcpdump.log"
    tcpdump_pid=$started_tcpdump_pid
    start_traced_group "$sample_dir/xray.strace" "$work/xray.stdout" \
        "$work/xray.stderr" "${proxy_free_env[@]}" "$xray_binary" run \
        -config "$work/xray-server.json"
    local server_pid=$started_group_pid
    wait_port "$xray_server_port"
    "$reference_server" "$cover_port" "$reference_certificate" \
        "$reference_private_key" "$ciphersuites" "$tls_groups" "$alpn" \
        "$middlebox" "$max_fragment" "$split_fragment" "$padding" "$tcp_nodelay" \
        >"$work/cover-xray.stdout" 2>"$work/cover-xray.stderr" &
    local cover_pid=$!
    register_pid "$cover_pid"
    wait_log "$work/cover-xray.stderr" '^READY '
    python3 "$HELPER" replay --port "$xray_server_port" \
        --client-hello "$output_dir/clienthello.bin" \
        --wire-output "$sample_dir/xray.wire" --summary-output "$sample_dir/xray.json"
    stop_group "$server_pid"
    stop_pid "$cover_pid"
    if [[ -n $tcpdump_pid ]]; then
        stop_tcpdump "$tcpdump_pid"
        tcpdump -nn -tt -r "$sample_dir/xray.pcap" \
            >"$sample_dir/xray.packets.txt" 2>/dev/null
    fi
}

mkdir "$output_dir/samples"
for sample in $(seq 1 "$samples"); do
    sample_dir=$(printf '%s/samples/%03d' "$output_dir" "$sample")
    mkdir "$sample_dir"
    run_sample=$(printf '%03d' "$sample")
    run_sample_dir=$sample_dir
    run_phase=sample-reference
    write_run_status
    run_reference_sample "$sample_dir"
    if [[ $baseline_present == true ]]; then
        run_phase=sample-baseline-rust-reality
        write_run_status
        run_rust_sample "$sample_dir" baseline-rust "$baseline_rust_binary"
    fi
    run_phase=sample-rust-reality
    write_run_status
    run_rust_sample "$sample_dir" rust "$rust_binary"
    if ((xray_server_comparator)); then
        run_phase=sample-xray
        write_run_status
        run_xray_sample "$sample_dir"
    fi
    run_sample=
    run_sample_dir=
done

run_phase=final-identity-verification
write_run_status
verify_sha256 OPENSSL_REFERENCE "$reference_server" "$reference_actual_sha256"
verify_sha256 rust-reality "$rust_binary" "$rust_actual_sha256"
verify_sha256 Xray "$xray_binary" "$xray_actual_sha256"
if [[ $baseline_present == true ]]; then
    verify_sha256 baseline-rust-reality "$baseline_rust_binary" \
        "$baseline_rust_actual_sha256"
fi
verify_sha256 harness-entrypoint "$0" "$harness_sha256"
verify_sha256 harness-helper "$HELPER" "$helper_sha256"
verify_sha256 reference-source "$REFERENCE_SOURCE" "$reference_source_sha256"
"$reference_server" --identity >"$work/reference-self-identity.final.json"
verify_sha256 reference-self-identity "$work/reference-self-identity.final.json" \
    "$reference_self_identity_sha256"

run_phase=summarize
write_run_status
summary_baseline_arguments=()
if [[ $baseline_present == true ]]; then
    summary_baseline_arguments=(--baseline-rust-present)
fi
summary_xray_arguments=()
if ((! xray_server_comparator)); then
    summary_xray_arguments=(--xray-server-comparator-disabled)
fi
python3 "$HELPER" summarize --identity "$output_dir/identity.json" \
    --samples-root "$output_dir/samples" --sample-count "$samples" \
    --reference-port "$direct_reference_port" --rust-port "$rust_port" \
    --xray-port "$xray_server_port" --strace-status "$strace_status" \
    --tcpdump-status "$tcpdump_status" "${summary_baseline_arguments[@]}" \
    "${summary_xray_arguments[@]}" \
    --output "$output_dir/summary.json"

run_state=COMPLETE
run_phase=complete
write_run_status
printf 'TLS shape capture complete: %s\n' "$output_dir"
printf 'Summary: %s\n' "$output_dir/summary.json"
