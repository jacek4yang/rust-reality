#!/usr/bin/env bash
# Formal connection-setup A/B benchmark.  A is the pinned baseline ELF and B
# is the pinned candidate ELF.  Every block is A-B-B-A or B-A-A-B, each slot
# owns fresh server/client processes and evidence, and no process or target/
# artifact is reused between slots.
set -Eeuo pipefail
export LC_ALL=C

readonly REPOSITORY="$({ cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."; pwd; })"
source "$REPOSITORY/scripts/benchmark-contract.sh"
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
cover_netem_rtt_ms=${COVER_NETEM_RTT_MS:-}
baseline_cover_mode=${BASELINE_COVER_MODE:-default}
candidate_cover_mode=${CANDIDATE_COVER_MODE:-default}

die() { printf 'benchmark-setup-rate: %s\n' "$*" >&2; exit 2; }

for cover_mode in "$baseline_cover_mode" "$candidate_cover_mode"; do
    case "$cover_mode" in
        default|cold|warm|prebuilt) ;;
        *) die "unsupported cover mode: $cover_mode" ;;
    esac
done


harness_tree_snapshot() {
    python3 - "$1" <<'PY_HARNESS'
import hashlib
from pathlib import Path
import sys
root = Path(sys.argv[1])
files = []
for path in root.rglob("*"):
    if path.is_symlink():
        raise SystemExit(f"symlink in harness tree: {path}")
    if path.is_file():
        files.append(path.relative_to(root).as_posix())
files.sort()
if not files:
    raise SystemExit("empty harness tree")
digest = hashlib.sha256()
for relative in files:
    digest.update(relative.encode())
    digest.update(b"\0")
    digest.update(hashlib.sha256((root / relative).read_bytes()).digest())
print(digest.hexdigest(), len(files))
PY_HARNESS
}

verify_harness_inputs() {
    local current_manifest current_count current_head current_identity_sha
    [[ $(sha256sum "$script_path" | awk '{print $1}') == "$script_sha" ]] ||
        die 'benchmark entrypoint changed during run'
    read -r current_manifest current_count < <(harness_tree_snapshot "$bench_origin_tree")
    [[ $current_manifest == "$bench_origin_manifest_sha" &&
       $current_count == "$bench_origin_file_count" ]] ||
        die 'bench-origin source tree changed during run'
    current_head=$(git -C "$REPOSITORY" rev-parse --verify 'HEAD^{commit}') ||
        die 'repository HEAD became invalid during run'
    [[ $current_head == "$repository_head" ]] || die 'repository HEAD changed during run'
    [[ -z $(git -C "$REPOSITORY" status --porcelain=v1 --untracked-files=normal) ]] ||
        die 'repository became dirty during run'
    current_identity_sha=$(sha256sum "$baseline_identity" | awk '{print $1}')
    [[ $current_identity_sha == "$baseline_identity_sha" ]] ||
        die 'baseline identity sidecar changed during run'
    [[ $(sha256sum "$host_contract_path" | awk '{print $1}') == "$host_contract_sha" ]] ||
        die 'host lock contract changed during run'
    [[ $(sha256sum "$host_helper_path" | awk '{print $1}') == "$host_helper_sha" ]] ||
        die 'host lock keeper helper changed during run'
}

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

host_lock_active=0
host_lock_only_cleanup() {
    local status=$? lock_status=0
    trap - EXIT INT TERM
    set +e
    if (( host_lock_active )); then
        rr_host_lock_verify || lock_status=1
        rr_host_lock_stop || lock_status=1
        host_lock_active=0
    fi
    (( status == 0 && lock_status != 0 )) && status=2
    exit "$status"
}
if ! rr_host_lock_acquire "$REPOSITORY" "${RR_HOST_EXCLUSIVE_LOCK:-}"; then
    rr_host_lock_stop >/dev/null 2>&1 || true
    die 'could not acquire the formal host-exclusive lock'
fi
host_lock_active=1
trap host_lock_only_cleanup EXIT
host_lock_evidence=$(rr_host_lock_evidence_begin) ||
    die 'could not record host lock preflight evidence'
host_contract_path=$RR_CONTRACT_PATH
host_contract_sha=$RR_CONTRACT_SHA256
host_helper_path=$RR_HOST_EXCLUSIVE_KEEPER_HELPER
host_helper_sha=${RR_HARNESS_SHA256[$host_helper_path]:-}
[[ $host_contract_sha =~ ^[0-9a-f]{64}$ && $host_helper_sha =~ ^[0-9a-f]{64}$ ]] ||
    die 'host lock contract/helper identity is incomplete'

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
if [[ -n $cover_netem_rtt_ms ]]; then
    [[ $cover_netem_rtt_ms =~ ^[1-9][0-9]*$ ]] && ((cover_netem_rtt_ms <= 2000)) ||
        die 'COVER_NETEM_RTT_MS must be an integer in 1..2000'
    for program in ip tc ping setpriv; do
        command -v "$program" >/dev/null 2>&1 ||
            die "COVER_NETEM_RTT_MS requires $program"
    done
fi
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
repository_head=$(git -C "$REPOSITORY" rev-parse --verify 'HEAD^{commit}')
script_path=$(realpath "$0")
script_sha=$(sha256sum "$script_path" | awk '{print $1}')
bench_origin_tree=$(realpath "$REPOSITORY/scripts/bench-origin")
read -r bench_origin_manifest_sha bench_origin_file_count < <(
    harness_tree_snapshot "$bench_origin_tree"
)
[[ $bench_origin_manifest_sha =~ ^[0-9a-f]{64}$ &&
   $bench_origin_file_count =~ ^[1-9][0-9]*$ ]] || die 'invalid bench-origin source manifest'
repository_dirty=false
[[ -z $(git -C "$REPOSITORY" status --porcelain=v1 --untracked-files=normal) ]] || repository_dirty=true
[[ $repository_dirty == false ]] || die 'formal benchmark requires a clean repository'
candidate_commit=$(git -C "$REPOSITORY" rev-parse --verify "$candidate_commit^{commit}") || die 'RUST_REALITY_COMMIT is not present in the repository'
[[ ${candidate_commit,,} == ${repository_head,,} ]] || die 'RUST_REALITY_COMMIT must match the harness repository HEAD'
grep -aFq -- "$candidate_commit" "$candidate_bin" || die 'candidate ELF does not embed RUST_REALITY_COMMIT'

slot_count=$((blocks * 4))
port_count=$((2 + slot_count * 2))
((port_base >= 1024 && port_base + port_count - 1 <= 65535)) || die 'PORT_BASE does not leave a large enough port block'
[[ -r /proc/sys/net/ipv4/ip_local_port_range ]] ||
    die 'cannot verify the Linux ephemeral port range'
read -r ephemeral_port_min ephemeral_port_max </proc/sys/net/ipv4/ip_local_port_range
[[ $ephemeral_port_min =~ ^[0-9]+$ && $ephemeral_port_max =~ ^[0-9]+$ ]] ||
    die 'invalid Linux ephemeral port range'
port_last=$((port_base + port_count - 1))
((port_last < ephemeral_port_min || port_base > ephemeral_port_max)) ||
    die "benchmark port block $port_base-$port_last overlaps the Linux ephemeral range $ephemeral_port_min-$ephemeral_port_max"
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
netns_name=
host_veth=
netns_created=0
host_veth_created=0

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
    local status=$? index pid lock_status=0 publication_status=0
    trap - EXIT INT TERM
    set +e
    for ((index=${#tracked_pids[@]} - 1; index >= 0; index--)); do
        pid=${tracked_pids[index]}
        [[ -n $pid ]] && stop_tracked "$pid"
    done
    if ((host_veth_created)); then
        sudo -n ip link del "$host_veth" >/dev/null 2>&1 || true
        host_veth_created=0
    fi
    if ((netns_created)); then
        sudo -n ip netns del "$netns_name" >/dev/null 2>&1 || true
        netns_created=0
    fi
    if (( host_lock_active )); then
        (( status != 0 )) || rr_host_lock_verify || lock_status=1
        rr_host_lock_stop || lock_status=1
        host_lock_active=0
    fi
    if (( status == 0 && lock_status == 0 )); then
        [[ -f $out_dir/.environment.complete.json && ! -L $out_dir/.environment.complete.json ]] ||
            publication_status=1
        if (( publication_status == 0 )); then
            mv -- "$out_dir/.environment.complete.json" "$out_dir/environment.json" ||
                publication_status=1
        fi
        if (( publication_status == 0 )); then
            rr_write_success_marker "$out_dir/completion.json" \
                "$out_dir/environment.json" "$run_id" benchmark-setup-rate ||
                publication_status=1
        fi
        (( publication_status != 0 )) || printf 'setup ABBA complete: %s\n' "$out_dir"
    fi
    rm -f -- "$out_dir/.environment.complete.json"
    if [[ -d $work && $work == "$temporary_root"/rust-reality-setup-rate.* ]]; then rm -rf -- "$work"; fi
    (( status == 0 && (lock_status != 0 || publication_status != 0) )) && status=2
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_port() {
    local port=$1 pid=$2 host=${3:-127.0.0.1} rtt_ms=${4:-0} start
    start=$(pid_start_time "$pid") || return 1
    python3 - "$port" "$pid" "$start" "$host" "$rtt_ms" <<'PY'
import os, socket, sys, time
port, pid, expected, host, rtt_ms = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4], int(sys.argv[5])
connect_timeout = max(.1, rtt_ms * 3 / 1000)
deadline = time.monotonic() + max(10, connect_timeout * 5)
while time.monotonic() < deadline:
    try:
        raw = open(f"/proc/{pid}/stat").read(); observed = raw[raw.rfind(")") + 2:].split()[19]
    except OSError:
        raise SystemExit("registered process exited")
    if observed != expected: raise SystemExit("PID identity changed")
    with socket.socket() as sock:
        sock.settimeout(connect_timeout)
        if sock.connect_ex((host, port)) == 0: raise SystemExit(0)
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
# The harness identity is the fail-closed source-tree manifest recorded above.
# Go's VCS discovery follows a linked worktree's common Git directory and can
# otherwise inspect the non-repository workspace parent, so disable redundant
# VCS stamping for this ephemeral helper explicitly.
(cd scripts/bench-origin && go build -buildvcs=false -o "$work/bench-origin" .)
http_port=$port_base; https_port=$((port_base + 1))
"$work/bench-origin" --port "$http_port" --payload-dir "$work" --put-log "$work/http-put.jsonl" \
    >"$out_dir/origin-http.log" 2>&1 & track_last origin-http "$!"; http_pid=$last_pid
cover_target="127.0.0.1:$https_port"
cover_address=127.0.0.1
if [[ -n $cover_netem_rtt_ms ]]; then
    net_suffix=$(printf '%s' "$run_id" | sha256sum | cut -c1-8)
    netns_name="rrc-$net_suffix"
    host_veth="rch$net_suffix"
    ns_veth="rcn$net_suffix"
    cover_address=10.204.0.2
    cover_target="$cover_address:$https_port"
    sudo -n ip netns add "$netns_name"
    netns_created=1
    sudo -n ip link add "$host_veth" type veth peer name "$ns_veth"
    host_veth_created=1
    sudo -n ip link set "$ns_veth" netns "$netns_name"
    sudo -n ip addr add 10.204.0.1/30 dev "$host_veth"
    sudo -n ip link set "$host_veth" up
    sudo -n ip netns exec "$netns_name" ip addr add 10.204.0.2/30 dev "$ns_veth"
    sudo -n ip netns exec "$netns_name" ip link set "$ns_veth" up
    sudo -n ip netns exec "$netns_name" ip link set lo up
    sudo -n tc qdisc replace dev "$host_veth" root netem delay "${cover_netem_rtt_ms}ms"
    {
        printf 'coverTarget=%s\nrequestedCoverRttMs=%s\n' "$cover_target" "$cover_netem_rtt_ms"
        ip -brief address show dev "$host_veth"
        tc qdisc show dev "$host_veth"
        ping -n -c 3 -i 0.1 -w 3 "$cover_address"
    } >"$out_dir/cover-netem.txt"
    sudo -n ip netns exec "$netns_name" \
        setpriv --reuid "$(id -u)" --regid "$(id -g)" --clear-groups \
        "$work/bench-origin" --listen-address "$cover_address" --port "$https_port" \
        --payload-dir "$work" --put-log "$work/https-put.jsonl" \
        --tls-cert "$work/origin.crt" --tls-key "$work/origin.key" \
        >"$out_dir/origin-https.log" 2>&1 &
    track_last origin-https-netns "$!"; https_pid=$last_pid
else
    "$work/bench-origin" --port "$https_port" --payload-dir "$work" \
        --put-log "$work/https-put.jsonl" --tls-cert "$work/origin.crt" \
        --tls-key "$work/origin.key" >"$out_dir/origin-https.log" 2>&1 &
    track_last origin-https "$!"; https_pid=$last_pid
fi
wait_port "$http_port" "$http_pid"
wait_port "$https_port" "$https_pid" "$cover_address" "${cover_netem_rtt_ms:-0}"

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
    --arg scriptPath "$script_path" --arg scriptSha "$script_sha" --arg benchOriginTree "$bench_origin_tree" --arg benchOriginManifest "$bench_origin_manifest_sha" --argjson benchOriginFiles "$bench_origin_file_count" \
    --arg contractPath "$host_contract_path" --arg contractSha "$host_contract_sha" --arg helperPath "$host_helper_path" --arg helperSha "$host_helper_sha" --argjson hostLock "$host_lock_evidence" \
    --arg xrayBin "$xray_bin" --arg xraySha "$xray_sha" --arg xrayBuildId "$xray_build_id" \
    --arg repositoryHead "$repository_head" --argjson repositoryDirty "$repository_dirty" --arg mode "$measure_mode" --arg concurrencies "$concurrencies" --argjson blocks "$blocks" --argjson samples "$samples" --argjson conns "$connections" \
    --arg coverTarget "$cover_target" --arg coverNetemRttMs "$cover_netem_rtt_ms" --arg baselineCoverMode "$baseline_cover_mode" --arg candidateCoverMode "$candidate_cover_mode" \
    --argjson portBase "$port_base" --argjson portCount "$port_count" \
    '{schemaVersion:2,runId:$runId,startedAt:$startedAt,repository:{head:$repositoryHead,dirty:$repositoryDirty},method:"balanced block ABBA",blocks:$blocks,samplesPerSlot:$samples,connectionsPerSample:$conns,concurrencies:$concurrencies,measureMode:$mode,ports:{address:"127.0.0.1",base:$portBase,count:$portCount},coverNetwork:{target:$coverTarget,netemRttMs:(if $coverNetemRttMs == "" then null else ($coverNetemRttMs|tonumber) end),model:(if $coverNetemRttMs == "" then "loopback" else "one-leg-veth-netem" end)},coverModes:{baseline:$baselineCoverMode,candidate:$candidateCoverMode},baseline:{path:$baselineBin,sha256:$baselineSha,buildId:$baselineBuildId,commit:$baselineCommit,identity:{path:$baselineIdentity,sha256:$baselineIdentitySha}},candidate:{path:$candidateBin,sha256:$candidateSha,buildId:$candidateBuildId,commit:$candidateCommit},harness:{entrypoint:{path:$scriptPath,sha256:$scriptSha},contract:{path:$contractPath,sha256:$contractSha},keeperHelper:{path:$helperPath,sha256:$helperSha},benchOrigin:{path:$benchOriginTree,manifestSha256:$benchOriginManifest,fileCount:$benchOriginFiles}},hostExclusiveLock:$hostLock,xray:{path:$xrayBin,sha256:$xraySha,buildId:$xrayBuildId}}' >"$out_dir/environment.json"

slot_index=0
while IFS=$'\t' read -r block position implementation server_port socks_port; do
    slot_index=$((slot_index + 1))
    slot=$(printf 'block-%02d-slot-%02d-%s' "$block" "$position" "$implementation")
    slot_dir="$out_dir/slots/$slot"; mkdir -p "$slot_dir"
    if [[ $implementation == baseline ]]; then binary=$baseline_bin; binary_sha=$baseline_sha; binary_build_id=$baseline_build_id; else binary=$candidate_bin; binary_sha=$candidate_sha; binary_build_id=$candidate_build_id; fi
    if [[ $implementation == baseline ]]; then cover_mode=$baseline_cover_mode; else cover_mode=$candidate_cover_mode; fi
    "$binary" config generate standalone --listen 127.0.0.1 --port "$server_port" \
        --target "$cover_target" --server-name localhost >"$work/$slot.raw.json" 2>"$slot_dir/generate.log"
    public_key=$(sed -n 's/^REALITY public key for the client: //p' "$slot_dir/generate.log")
    uuid=$(jq -er '.inbounds[0].settings.clients[0].id' "$work/$slot.raw.json")
    short_id=$(jq -er '.inbounds[0].settings.clients[0].shortIds[0]' "$work/$slot.raw.json")
    jq --arg cache "$work/assets-$slot" --arg netem "$cover_netem_rtt_ms" --arg coverMode "$cover_mode" --arg implementation "$implementation" \
        '.log.level=(if $netem == "" then "warn" else "info" end)
         |.assets.cacheDirectory=$cache
         |if $coverMode == "cold" then
              .inbounds[0].streamSettings.realitySettings.coverOptimization=(if $implementation == "baseline" then {enabled:true,warmTcp:false} else {enabled:true,warmTcp:false,prebuiltProfiles:false} end)
          elif $coverMode == "warm" then
              .inbounds[0].streamSettings.realitySettings.coverOptimization=(if $implementation == "baseline" then {enabled:true,warmTcp:true} else {enabled:true,warmTcp:true,prebuiltProfiles:false} end)
          elif $coverMode == "prebuilt" then
              .inbounds[0].streamSettings.realitySettings.coverOptimization={enabled:true,warmTcp:true,prebuiltProfiles:true}
          else . end' "$work/$slot.raw.json" >"$work/$slot.server.json"
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
    if [[ -n $cover_netem_rtt_ms ]]; then
        warm_concurrency=$(printf '%s\n' $concurrencies | sort -nr | head -1)
        warm_connections=$((warm_concurrency * 2))
        # Chrome 133 legitimately rotates among four GREASE-ECH payload
        # lengths. Precondition every implementation symmetrically with enough
        # sessions to characterize that bounded class corpus before perf starts;
        # startup collection remains visible in the aggregate profile counters.
        if [[ $candidate_cover_mode == prebuilt || $candidate_cover_mode == default ]] &&
           ((warm_connections < 32)); then
            warm_connections=32
        fi
        ((warm_connections > 64)) && warm_connections=64
        python3 "$work/driver.py" 1 "$warm_connections" "$socks_port" "$http_port" \
            "$warm_concurrency" "$slot_dir/warmup.json" "$implementation" "$block" "$position"
        python3 - "$cover_netem_rtt_ms" <<'PY'
import sys, time
time.sleep((int(sys.argv[1]) * 2 + 100) / 1000)
PY
    else
        python3 "$work/driver.py" 0 "$connections" "$socks_port" "$http_port" \
            "$concurrencies" "$slot_dir/warmup.json" "$implementation" "$block" "$position"
    fi
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
    if [[ -z $wrapper_pid ]]; then
        stop_tracked "$server_pid"
    else
        # Let the tracee perform normal graceful shutdown. strace then exits
        # naturally and flushes its -c summary; terminating the wrapper itself
        # can leave the output file empty.
        kill -TERM "$server_pid" 2>/dev/null || true
        for _ in {1..50}; do
            [[ -r /proc/$wrapper_pid/stat ]] || break
            sleep 0.02
        done
        stop_tracked "$wrapper_pid"
    fi
    if [[ $implementation == candidate && -n $cover_netem_rtt_ms ]]; then
        python3 - "$slot_dir/server.log" "$slot_dir/pool-summary.json" <<'PY'
import json, sys
records = []
for line in open(sys.argv[1], encoding="utf-8"):
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        continue
    if record.get("event") == "cover_pool_summary":
        records.append(record)
if len(records) != 1:
    raise SystemExit(f"expected one cover_pool_summary, found {len(records)}")
record = records[0]
total = record["pool_checkout_total"]
hits = record["pool_checkout_hit"]
misses = record["pool_checkout_miss"]
if total <= 0 or hits + misses != total:
    raise SystemExit("incoherent cover pool checkout counters")
record["warmHitRatio"] = hits / total
with open(sys.argv[2], "x", encoding="utf-8") as output:
    json.dump(record, output, indent=2, sort_keys=True)
    output.write("\n")
PY
        if [[ $candidate_cover_mode == prebuilt || $candidate_cover_mode == default ]]; then
            python3 - "$slot_dir/server.log" "$slot_dir/profile-summary.json" <<'PY'
import json, sys
records = []
for line in open(sys.argv[1], encoding="utf-8"):
    try:
        record = json.loads(line)
    except json.JSONDecodeError:
        continue
    if record.get("event") == "cover_profile_summary":
        records.append(record)
if len(records) != 1:
    raise SystemExit(f"expected one cover_profile_summary, found {len(records)}")
record = records[0]
hits = record["cover_profile_hit"]
misses = record["cover_profile_miss"]
if hits <= 0 or record["cover_profile_validated"] <= 0:
    raise SystemExit("candidate benchmark did not exercise a validated profile hit")
if (record["cover_profile_state"] != "validated"
        or record["cover_profile_unstable"] != 0
        or record["cover_profile_refresh_failure"] != 0
        or record["cover_profile_disagreement"] != 0):
    raise SystemExit("controlled cover-profile differential consensus failed")
record["profileHitRatio"] = hits / (hits + misses)
with open(sys.argv[2], "x", encoding="utf-8") as output:
    json.dump(record, output, indent=2, sort_keys=True)
    output.write("\n")
PY
        fi
    fi
    if [[ $measure_mode == perf ]]; then [[ -s $slot_dir/perf.json ]] || die "missing validated perf evidence in $slot"; else [[ -s $slot_dir/strace.txt ]] || die "missing strace evidence in $slot"; fi
    [[ $(sha256sum "$binary" | awk '{print $1}') == "$binary_sha" ]] || die "$implementation binary changed after $slot"
    [[ $(sha256sum "$xray_bin" | awk '{print $1}') == "$xray_sha" ]] || die "Xray changed after $slot"
done < <(jq -r '.slots[]|[.block,.position,.implementation,.serverPort,.socksPort]|@tsv' "$out_dir/order.json")

python3 - "$out_dir" "$blocks" "$samples" "$connections" "$concurrencies" "$measure_mode" <<'PY'
import json, pathlib, random, statistics, sys
root=pathlib.Path(sys.argv[1]); blocks,samples,connections=int(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4]); concurrencies=[int(x) for x in sys.argv[5].split()]; mode=sys.argv[6]
order=json.load(open(root/'order.json'))['slots']; slot_dirs=sorted((root/'slots').iterdir())
if len(order)!=blocks*4 or len(slot_dirs)!=blocks*4: raise SystemExit('missing ABBA slots')
all_rows=[]; slots=[]; perf_rows=[]; pool_rows=[]; profile_rows=[]
for slot in slot_dirs:
    identity=json.load(open(slot/'identity.json')); rows=json.load(open(slot/'samples.json'))
    if len(rows)!=samples*len(concurrencies): raise SystemExit(f'missing samples: {slot}')
    if any(r['failed'] or r['connections']!=connections for r in rows): raise SystemExit(f'failed setup sample: {slot}')
    all_rows.extend(rows); slots.append(identity)
    pool_path=slot/'pool-summary.json'
    if pool_path.exists(): pool_rows.append(json.load(open(pool_path)))
    profile_path=slot/'profile-summary.json'
    if profile_path.exists(): profile_rows.append(json.load(open(profile_path)))
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
pool_summary=None
if pool_rows:
    pool_summary={'slotCount':len(pool_rows),
                  'checkoutTotal':sum(row['pool_checkout_total'] for row in pool_rows),
                  'checkoutHit':sum(row['pool_checkout_hit'] for row in pool_rows),
                  'checkoutMiss':sum(row['pool_checkout_miss'] for row in pool_rows),
                  'coldFallback':sum(row['pool_cold_fallback'] for row in pool_rows),
                  'staleDiscard':sum(row['pool_stale_discard'] for row in pool_rows)}
    pool_summary['warmHitRatio']=pool_summary['checkoutHit']/pool_summary['checkoutTotal']
profile_summary=None
if profile_rows:
    profile_summary={'slotCount':len(profile_rows),
                     'hit':sum(row['cover_profile_hit'] for row in profile_rows),
                     'miss':sum(row['cover_profile_miss'] for row in profile_rows),
                     'stale':sum(row['cover_profile_stale'] for row in profile_rows),
                     'unstable':sum(row['cover_profile_unstable'] for row in profile_rows),
                     'refresh':sum(row['cover_profile_refresh'] for row in profile_rows),
                     'refreshFailure':sum(row['cover_profile_refresh_failure'] for row in profile_rows),
                     'disagreement':sum(row['cover_profile_disagreement'] for row in profile_rows)}
    profile_summary['profileHitRatio']=profile_summary['hit']/(profile_summary['hit']+profile_summary['miss'])
summary={'schemaVersion':3,'status':'COMPLETE','performanceVerdict':'NOT_EVALUATED','method':'alternating balanced ABBA blocks; block bootstrap','slotCount':len(slots),'rawSampleCount':len(all_rows),'cells':cells,'serverCpuPerConnection':cpu_summary,'coverPool':pool_summary,'coverProfile':profile_summary,'failures':0}
json.dump(summary,open(root/'summary.json','x'),indent=2); print(json.dumps(summary))
PY

[[ $(sha256sum "$baseline_bin" | awk '{print $1}') == "$baseline_sha" ]] || die 'baseline changed during run'
[[ $(sha256sum "$candidate_bin" | awk '{print $1}') == "$candidate_sha" ]] || die 'candidate changed during run'
[[ $(sha256sum "$xray_bin" | awk '{print $1}') == "$xray_sha" ]] || die 'Xray changed during run'
verify_harness_inputs
jq -e --argjson slots "$slot_count" '.status=="COMPLETE" and .slotCount==$slots and .failures==0' "$out_dir/summary.json" >/dev/null || die 'aggregate gate failed'
host_lock_evidence=$(rr_host_lock_evidence_complete "$host_lock_evidence") ||
    die 'host-exclusive lock identity changed before completion'
jq --argjson hostLock "$host_lock_evidence" '.hostExclusiveLock=$hostLock' \
    "$out_dir/environment.json" >"$out_dir/.environment.complete.json"
rr_host_lock_verify || die 'host-exclusive lock failed final verification'
