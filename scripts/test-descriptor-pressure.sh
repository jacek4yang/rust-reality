#!/usr/bin/env bash
# Fail-closed, real-socket descriptor-pressure recovery gate.
#
# This harness deliberately runs rust-reality with a low hard *and* soft
# RLIMIT_NOFILE, establishes real Xray -> REALITY -> Vision -> echo streams,
# fills the server's derived descriptor budget, and proves that:
#
#   1. the exact server process survives pressure;
#   2. a connection established before pressure remains usable;
#   3. new work is refused while the budget is exhausted; and
#   4. releasing held connections returns pressure to normal and a fresh,
#      integrity-checked stream succeeds.
#
# The script never builds. RUST_REALITY_BIN and XRAY_BIN must name existing,
# executable artifacts. All processes are tracked by PID plus /proc start time;
# cleanup never uses pkill, a process-name match, or a wildcard unit name.
set -Eeuo pipefail

readonly REPOSITORY="$({ cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."; pwd; })"
source "$REPOSITORY/scripts/benchmark-contract.sh"
rust_bin=${RUST_REALITY_BIN:-}
xray_bin=${XRAY_BIN:-}
openssl_bin=${OPENSSL_BIN:-}
if [[ ${EXPLORATORY:-0} == 1 && -z $openssl_bin ]]; then
    openssl_bin=$(command -v openssl 2>/dev/null || true)
fi
expected_source_commit=${EXPECTED_SOURCE_COMMIT:-}
nofile_limit=${NOFILE_LIMIT:-192}
max_held=${MAX_HELD_CONNECTIONS:-96}
storm_connections=${STORM_CONNECTIONS:-12}
launcher=${RLIMIT_LAUNCHER:-systemd-user}

die() {
    printf 'descriptor-pressure gate: %s\n' "$*" >&2
    exit 2
}

[[ $nofile_limit =~ ^[1-9][0-9]*$ ]] || die 'NOFILE_LIMIT must be a positive integer'
[[ $max_held =~ ^[1-9][0-9]*$ ]] || die 'MAX_HELD_CONNECTIONS must be positive'
[[ $storm_connections =~ ^[1-9][0-9]*$ ]] || die 'STORM_CONNECTIONS must be positive'
(( nofile_limit >= 182 && nofile_limit <= 4096 )) ||
    die 'NOFILE_LIMIT must be in 182..4096 (serviceable but intentionally bounded)'
(( max_held >= 8 && max_held <= 512 )) || die 'MAX_HELD_CONNECTIONS must be in 8..512'
(( storm_connections >= 4 && storm_connections <= 64 )) ||
    die 'STORM_CONNECTIONS must be in 4..64'
[[ $launcher == systemd-user || $launcher == ulimit ]] ||
    die 'RLIMIT_LAUNCHER must be systemd-user or ulimit'

for program in jq python3 readlink sha256sum; do
    command -v "$program" >/dev/null 2>&1 || die "required program unavailable: $program"
done
rr_contract_init "$REPOSITORY" test-descriptor-pressure diagnostics/final 8
rr_register_binary rust-reality "$rust_bin" "${RUST_REALITY_SHA256:-}" rust \
    "$expected_source_commit"
rr_register_binary xray "$xray_bin" "${XRAY_SHA256:-}" xray
rr_register_binary openssl "$openssl_bin" "${OPENSSL_SHA256:-}" generic
run_id=$RR_RUN_ID
out_dir=$RR_OUT_DIR
temporary_root=$RR_TMPDIR
rust_bin=${RR_BINARY_PATHS[rust-reality]}
xray_bin=${RR_BINARY_PATHS[xray]}
openssl_bin=${RR_BINARY_PATHS[openssl]}
rust_sha256=${RR_BINARY_SHA256[rust-reality]}
xray_sha256=${RR_BINARY_SHA256[xray]}
openssl_sha256=${RR_BINARY_SHA256[openssl]}
openssl_identity=$("$openssl_bin" version -a)
RR_BINARY_IDENTITIES[openssl]=${openssl_identity%%$'\n'*}
rr_write_contract_metadata
readonly run_id out_dir temporary_root rust_bin xray_bin openssl_bin
readonly rust_sha256 xray_sha256 openssl_sha256 openssl_identity
work=$(mktemp -d "$temporary_root/rust-reality-fd-pressure.XXXXXX")
readonly out_dir temporary_root work

tracked_pids=()
tracked_starts=()
tracked_names=()
server_pid=
server_start=
runner_pid=
unit=
unit_started=false

pid_start_time() {
    python3 - "$1" <<'PY'
from pathlib import Path
import sys
raw = Path(f"/proc/{sys.argv[1]}/stat").read_text()
end = raw.rfind(")")
if end < 0:
    raise SystemExit(1)
# The suffix begins with field 3 (state); field 22 is suffix index 19.
print(raw[end + 2:].split()[19])
PY
}

track_pid() {
    local name=$1 pid=$2 expected_exe=${3:-} expected_sha=${4:-} start actual_sha
    [[ $pid =~ ^[1-9][0-9]*$ ]] || die "invalid PID for $name: $pid"
    start=$(pid_start_time "$pid") || die "cannot identify $name PID $pid"
    tracked_names+=("$name")
    tracked_pids+=("$pid")
    tracked_starts+=("$start")
    rr_register_pid "$pid" "$expected_exe"
    if [[ -n $expected_sha ]]; then
        actual_sha=$(sha256sum -- "/proc/$pid/exe" | awk '{print $1}')
        [[ $actual_sha == "$expected_sha" ]] ||
            die "$name PID $pid executable SHA-256 mismatch"
    fi
}

pid_is_owned() {
    local pid=$1 expected=$2 observed
    [[ -r /proc/$pid/stat ]] || return 1
    observed=$(pid_start_time "$pid" 2>/dev/null) || return 1
    [[ $observed == "$expected" ]]
}

terminate_owned_pid() {
    local pid=$1 expected=$2
    pid_is_owned "$pid" "$expected" || return 0
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 50); do
        pid_is_owned "$pid" "$expected" || return 0
        sleep 0.1
    done
    pid_is_owned "$pid" "$expected" && kill -KILL "$pid" 2>/dev/null || true
}

cleanup() {
    local status=$? final_status index
    trap - EXIT INT TERM
    set +e
    if [[ -n $server_pid && -n $server_start ]]; then
        terminate_owned_pid "$server_pid" "$server_start"
    fi
    if $unit_started; then
        systemctl --user stop "$unit" >/dev/null 2>&1 || true
    fi
    for ((index=${#tracked_pids[@]} - 1; index >= 0; index--)); do
        rr_stop_registered_pid "${tracked_pids[index]}"
    done
    if [[ -d $work && $work == "$temporary_root"/rust-reality-fd-pressure.* ]]; then
        rm -rf -- "$work"
    fi
    if (( status != 0 )); then
        printf 'descriptor-pressure gate failed; evidence retained in %s\n' "$out_dir" >&2
        if [[ -s $out_dir/server.log ]]; then
            printf '%s\n' '--- final server events ---' >&2
            tail -20 "$out_dir/server.log" >&2
        fi
    fi
    rr_contract_verify_on_exit "$status"
    final_status=$?
    exit "$final_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_port() {
    local port=$1 name=$2
    python3 - "$port" "$name" <<'PY'
import socket
import sys
import time
port, name = int(sys.argv[1]), sys.argv[2]
deadline = time.monotonic() + 15
while time.monotonic() < deadline:
    with socket.socket() as sock:
        sock.settimeout(0.1)
        if sock.connect_ex(("127.0.0.1", port)) == 0:
            raise SystemExit(0)
    time.sleep(0.03)
raise SystemExit(f"{name} port {port} did not become ready")
PY
}

server_port=$(rr_next_port)
socks_port=$(rr_next_port)
cover_port=$(rr_next_port)
echo_port=$(rr_next_port)
readonly server_port socks_port cover_port echo_port

# A small local TLS 1.3 cover target; no external network or shared cache is used.
# Keep its private CA isolated to the rust-reality child.  A CA-signed leaf is
# intentional: the cover probe performs normal hostname and chain validation.
"$openssl_bin" req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
    -subj '/CN=rust-reality descriptor gate CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "$work/ca.key" -out "$work/ca.crt" >/dev/null 2>&1
"$openssl_bin" req -new -newkey rsa:2048 -nodes -sha256 \
    -subj '/CN=localhost' \
    -addext 'basicConstraints=critical,CA:FALSE' \
    -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
    -addext 'extendedKeyUsage=serverAuth' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -keyout "$work/cover.key" -out "$work/cover.csr" >/dev/null 2>&1
"$openssl_bin" x509 -req -sha256 -days 1 \
    -in "$work/cover.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" \
    -CAcreateserial -copy_extensions copy -out "$work/cover.crt" >/dev/null 2>&1
"$openssl_bin" verify -CAfile "$work/ca.crt" -verify_hostname localhost \
    "$work/cover.crt" >"$out_dir/certificate-verify.log" 2>&1
"$openssl_bin" s_server -quiet -tls1_3 -no_middlebox \
    -accept "127.0.0.1:$cover_port" -alpn 'h2,http/1.1' \
    -key "$work/cover.key" -cert "$work/cover.crt" -CAfile "$work/ca.crt" \
    >"$out_dir/cover.log" 2>&1 &
cover_pid=$!
track_pid cover "$cover_pid" "$openssl_bin" "$openssl_sha256"
wait_port "$cover_port" cover

# A process-owned threaded echo origin. The ready file is created only after bind.
python3 - "$echo_port" "$work/echo.ready" >"$out_dir/echo.log" 2>&1 <<'PY' &
import socketserver
import sys
from pathlib import Path

port = int(sys.argv[1])
ready = Path(sys.argv[2])

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data)

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True

with Server(("127.0.0.1", port), Handler) as server:
    ready.write_text("ready\n", encoding="ascii")
    server.serve_forever(poll_interval=0.1)
PY
echo_pid=$!
track_pid echo "$echo_pid" "$(command -v python3)"
for _ in $(seq 1 150); do
    [[ -s $work/echo.ready ]] && break
    sleep 0.1
done
[[ -s $work/echo.ready ]] || die 'echo origin did not become ready'

"$rust_bin" config generate standalone \
    --listen 127.0.0.1 --port "$server_port" \
    --target "localhost:$cover_port" --server-name localhost \
    >"$work/server.raw.json" 2>"$work/generate.log"
public_key=$(sed -n 's/^REALITY public key for the client: //p' "$work/generate.log")
uuid=$(jq -er '.inbounds[0].settings.clients[0].id' "$work/server.raw.json")
short_id=$(jq -er '.inbounds[0].settings.clients[0].shortIds[0]' "$work/server.raw.json")
[[ -n $public_key ]] || die 'config generator did not emit the REALITY public key'
# Generated routing rules are already empty, avoiding asset downloads. Info
# logging proves the exact derived budget; pressure transitions are warnings.
jq --arg cache "$work/assets" '
    .log.level = "info"
    | .assets.cacheDirectory = $cache
' "$work/server.raw.json" >"$work/server.json"
"$rust_bin" check --config "$work/server.json" >/dev/null

jq -n --arg uuid "$uuid" --arg publicKey "$public_key" --arg shortId "$short_id" \
    --argjson serverPort "$server_port" --argjson socksPort "$socks_port" '
    {
      log: {loglevel: "warning"},
      inbounds: [{
        listen: "127.0.0.1", port: $socksPort, protocol: "socks",
        settings: {auth: "noauth", udp: false}
      }],
      outbounds: [{
        protocol: "vless",
        settings: {vnext: [{
          address: "127.0.0.1", port: $serverPort,
          users: [{id: $uuid, encryption: "none", flow: "xtls-rprx-vision"}]
        }]},
        streamSettings: {
          network: "tcp", security: "reality",
          realitySettings: {
            fingerprint: "chrome", serverName: "localhost",
            publicKey: $publicKey, shortId: $shortId, spiderX: "/"
          }
        }
      }]
    }
' >"$work/xray.json"

pidfile="$work/server.pid"
if [[ $launcher == systemd-user ]]; then
    command -v systemd-run >/dev/null 2>&1 || die 'systemd-run is unavailable'
    systemctl --user is-system-running >/dev/null 2>&1 ||
        die 'the user systemd manager is not running; select RLIMIT_LAUNCHER=ulimit explicitly'
    unit="rr-fd-pressure-$UID-$$-$RANDOM.scope"
    [[ $unit =~ ^rr-fd-pressure-[0-9]+-[0-9]+-[0-9]+\.scope$ ]] || die 'unsafe scope name'
    systemd-run --user --scope --collect --quiet --unit="$unit" \
        -- \
        bash -c '
            ulimit -Sn "$1"
            ulimit -Hn "$1"
            printf "%s\n" "$$" >"$2"
            exec env -i PATH=/usr/local/bin:/usr/bin:/bin \
                SSL_CERT_FILE="$5" \
                "$3" serve --config "$4"
        ' _ "$nofile_limit" "$pidfile" "$rust_bin" "$work/server.json" "$work/ca.crt" \
        >"$out_dir/server.log" 2>&1 &
    runner_pid=$!
    track_pid systemd-run "$runner_pid" "$(command -v systemd-run)"
    unit_started=true
else
    bash -c '
        ulimit -Sn "$1"
        ulimit -Hn "$1"
        printf "%s\n" "$$" >"$2"
        exec env -i PATH=/usr/local/bin:/usr/bin:/bin \
            SSL_CERT_FILE="$5" \
            "$3" serve --config "$4"
    ' _ "$nofile_limit" "$pidfile" "$rust_bin" "$work/server.json" "$work/ca.crt" \
        >"$out_dir/server.log" 2>&1 &
    runner_pid=$!
    track_pid server-runner "$runner_pid"
fi

for _ in $(seq 1 150); do
    [[ -s $pidfile ]] && break
    sleep 0.1
done
[[ -s $pidfile ]] || die 'server PID file was not created'
server_pid=$(<"$pidfile")
[[ $server_pid =~ ^[1-9][0-9]*$ ]] || die "server PID file is invalid: $server_pid"
server_start=$(pid_start_time "$server_pid") || die 'server process disappeared during startup'
server_exe=$(readlink -f -- "/proc/$server_pid/exe")
[[ $server_exe == "$rust_bin" ]] || die "server executable mismatch: $server_exe"
server_process_sha256=$(sha256sum -- "/proc/$server_pid/exe" | awk '{print $1}')
[[ $server_process_sha256 == "$rust_sha256" ]] || die 'running server binary SHA-256 changed'
if [[ -z ${RR_PID_STARTS[$server_pid]:-} ]]; then
    rr_register_pid "$server_pid" "$rust_bin"
fi
read -r observed_soft observed_hard < <(
    awk '$1 == "Max" && $2 == "open" && $3 == "files" {print $4, $5}' \
        "/proc/$server_pid/limits"
)
[[ $observed_soft == "$nofile_limit" && $observed_hard == "$nofile_limit" ]] ||
    die "server RLIMIT_NOFILE is soft=$observed_soft hard=$observed_hard, expected $nofile_limit/$nofile_limit"
if [[ $launcher == systemd-user ]]; then
    cgroup=$(systemctl --user show "$unit" --property=ControlGroup --value)
    [[ -n $cgroup && -d /sys/fs/cgroup$cgroup ]] || die "scope cgroup is unavailable: $cgroup"
    grep -Fxq "$server_pid" "/sys/fs/cgroup$cgroup/cgroup.procs" ||
        die "server PID $server_pid is not owned by scope $unit"
fi
wait_port "$server_port" rust-reality

env -i PATH=/usr/local/bin:/usr/bin:/bin \
    "$xray_bin" run -config "$work/xray.json" >"$out_dir/xray.log" 2>&1 &
xray_pid=$!
track_pid xray "$xray_pid" "$xray_bin" "$xray_sha256"
wait_port "$socks_port" Xray
sleep 0.5
pid_is_owned "$server_pid" "$server_start" || die 'server exited before pressure test'

python3 - "$socks_port" "$echo_port" "$server_pid" "$server_start" \
    "$out_dir/server.log" "$out_dir/pressure-result.json" \
    "$max_held" "$storm_connections" <<'PY'
import concurrent.futures
import hashlib
import json
import os
import socket
import sys
import time
from pathlib import Path

(
    socks_port, echo_port, server_pid, expected_start, log_path, result_path,
    max_held, storm_connections,
) = sys.argv[1:]
socks_port = int(socks_port)
echo_port = int(echo_port)
server_pid = int(server_pid)
max_held = int(max_held)
storm_connections = int(storm_connections)
log_path = Path(log_path)
result_path = Path(result_path)
held = []
evidence = {"ok": False}

def server_start_time():
    raw = Path(f"/proc/{server_pid}/stat").read_text()
    end = raw.rfind(")")
    if end < 0:
        raise RuntimeError("server stat is malformed")
    return raw[end + 2:].split()[19]

def assert_server_owned():
    if server_start_time() != expected_start:
        raise RuntimeError("server PID exited or was reused")

def fd_count():
    return len(list(Path(f"/proc/{server_pid}/fd").iterdir()))

def events():
    output = []
    if not log_path.exists():
        return output
    for raw in log_path.read_bytes().splitlines():
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if isinstance(value, dict):
            output.append(value)
    return output

def wait_event(name, predicate=lambda event: True, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for event in events():
            if event.get("event") == name and predicate(event):
                return event
        assert_server_owned()
        time.sleep(0.05)
    raise RuntimeError(f"required event did not arrive: {name}")

def recv_exact(sock, length):
    output = bytearray()
    while len(output) < length:
        block = sock.recv(length - len(output))
        if not block:
            raise OSError("unexpected EOF")
        output.extend(block)
    return bytes(output)

def open_tunnel(timeout=2.0):
    sock = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise OSError("SOCKS greeting was rejected")
        request = b"\x05\x01\x00\x01\x7f\x00\x00\x01" + echo_port.to_bytes(2, "big")
        sock.sendall(request)
        header = recv_exact(sock, 4)
        if header[0] != 5 or header[1] != 0:
            raise OSError(f"SOCKS connect failed: {header!r}")
        if header[3] == 1:
            recv_exact(sock, 6)
        elif header[3] == 3:
            recv_exact(sock, recv_exact(sock, 1)[0] + 2)
        elif header[3] == 4:
            recv_exact(sock, 18)
        else:
            raise OSError(f"unknown SOCKS address type: {header[3]}")
        return sock
    except BaseException:
        sock.close()
        raise

def echo(sock, payload):
    sock.sendall(payload)
    received = recv_exact(sock, len(payload))
    if received != payload:
        raise RuntimeError("echo integrity mismatch")
    return received

def storm_attempt(index):
    try:
        with open_tunnel(timeout=1.5) as sock:
            echo(sock, f"storm-{index}".encode())
        return True
    except OSError:
        return False

try:
    budget = wait_event("descriptor_budget_report", timeout=10)
    effective_budget = int(budget["fd_effective_budget"])
    if int(budget["fd_soft_limit"]) != int(budget["fd_hard_limit"]):
        raise RuntimeError("budget report does not show equal hard/soft limits")
    baseline_fds = fd_count()

    control = open_tunnel(timeout=5)
    held.append(control)
    echo(control, b"control-before-pressure")

    fill_failures = 0
    for index in range(1, max_held):
        assert_server_owned()
        try:
            sock = open_tunnel(timeout=2)
            echo(sock, f"held-{index}".encode())
            held.append(sock)
        except OSError:
            fill_failures += 1
            break
    if fill_failures == 0:
        raise RuntimeError("MAX_HELD_CONNECTIONS did not exhaust descriptor admission")
    successful_held = len(held)
    if successful_held < 8:
        raise RuntimeError(f"pressure arrived after only {successful_held} established streams")
    high = wait_event(
        "descriptor_pressure_changed",
        lambda event: event.get("fd_pressure_state") == "high",
        timeout=10,
    )
    pressure_fds = fd_count()
    if pressure_fds <= baseline_fds:
        raise RuntimeError("server FD count did not increase under pressure")

    with concurrent.futures.ThreadPoolExecutor(max_workers=storm_connections) as pool:
        storm = list(pool.map(storm_attempt, range(storm_connections)))
    storm_successes = sum(storm)
    storm_failures = len(storm) - storm_successes
    if storm_failures == 0:
        raise RuntimeError("connection storm observed no refused or stalled new flow")

    assert_server_owned()
    control_payload = bytes(range(256)) * 16
    control_sha = hashlib.sha256(echo(control, control_payload)).hexdigest()
    expected_control_sha = hashlib.sha256(control_payload).hexdigest()
    if control_sha != expected_control_sha:
        raise RuntimeError("pre-existing control connection failed under pressure")

    for sock in held[1:]:
        sock.close()
    del held[1:]
    normal = wait_event(
        "descriptor_pressure_changed",
        lambda event: event.get("fd_pressure_state") == "normal",
        timeout=15,
    )
    assert_server_owned()

    recovery_payload = bytes(range(256)) * 256
    expected_recovery_sha = hashlib.sha256(recovery_payload).hexdigest()
    with open_tunnel(timeout=8) as recovered:
        actual_recovery_sha = hashlib.sha256(echo(recovered, recovery_payload)).hexdigest()
    if actual_recovery_sha != expected_recovery_sha:
        raise RuntimeError("post-pressure recovery payload hash mismatch")

    evidence.update({
        "ok": True,
        "serverPid": server_pid,
        "serverStartTime": expected_start,
        "effectiveBudget": effective_budget,
        "baselineFdCount": baseline_fds,
        "pressureFdCount": pressure_fds,
        "successfulHeldConnectionsAtPressure": successful_held,
        "fillFailures": fill_failures,
        "stormConnections": storm_connections,
        "stormSuccesses": storm_successes,
        "stormFailures": storm_failures,
        "highTransitionUnits": high.get("fd_units_in_use"),
        "normalTransitionUnits": normal.get("fd_units_in_use"),
        "controlSha256": control_sha,
        "recoverySha256": actual_recovery_sha,
        "expectedRecoverySha256": expected_recovery_sha,
    })
except BaseException as error:
    evidence["error"] = f"{type(error).__name__}: {error}"
    raise
finally:
    evidence.setdefault("serverPid", server_pid)
    evidence.setdefault("serverStartTime", expected_start)
    evidence.setdefault("heldConnectionsAtExit", len(held))
    for sock in held:
        try:
            sock.close()
        except OSError:
            pass
    with result_path.open("x", encoding="utf-8") as output:
        json.dump(evidence, output, indent=2, sort_keys=True)
        output.write("\n")
PY

pid_is_owned "$server_pid" "$server_start" || die 'server did not survive the completed gate'
[[ $(sha256sum -- "/proc/$server_pid/exe" | awk '{print $1}') == "$rust_sha256" ]] ||
    die 'running server binary SHA-256 changed after pressure test'
rr_pid_is_registered "$server_pid" || die 'server PID identity changed after pressure test'
rr_pid_is_registered "$xray_pid" || die 'Xray PID identity changed after pressure test'
rr_pid_is_registered "$cover_pid" || die 'OpenSSL cover PID identity changed after pressure test'
[[ $(sha256sum -- "/proc/$xray_pid/exe" | awk '{print $1}') == "$xray_sha256" ]] ||
    die 'running Xray binary SHA-256 changed after pressure test'
[[ $(sha256sum -- "/proc/$cover_pid/exe" | awk '{print $1}') == "$openssl_sha256" ]] ||
    die 'running OpenSSL binary SHA-256 changed after pressure test'
server_config_sha256=$(sha256sum -- "$work/server.json" | awk '{print $1}')
xray_config_sha256=$(sha256sum -- "$work/xray.json" | awk '{print $1}')
jq -e '.ok == true and .stormFailures > 0 and .recoverySha256 == .expectedRecoverySha256' \
    "$out_dir/pressure-result.json" >/dev/null || die 'pressure result did not satisfy the gate'

git_head=$(git -C "$REPOSITORY" rev-parse --verify HEAD)
jq -n \
    --arg runId "$run_id" \
    --arg startedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg gitHead "$git_head" \
    --arg launcher "$launcher" \
    --arg rustBinary "$rust_bin" --arg rustSha256 "$rust_sha256" \
    --arg xrayBinary "$xray_bin" --arg xraySha256 "$xray_sha256" \
    --arg opensslBinary "$openssl_bin" --arg opensslSha256 "$openssl_sha256" \
    --arg opensslIdentity "$openssl_identity" \
    --arg serverConfigSha256 "$server_config_sha256" \
    --arg xrayConfigSha256 "$xray_config_sha256" \
    --argjson nofileLimit "$nofile_limit" \
    --argjson serverPort "$server_port" --argjson socksPort "$socks_port" \
    --argjson coverPort "$cover_port" --argjson echoPort "$echo_port" \
    --slurpfile result "$out_dir/pressure-result.json" '
    {
      schemaVersion: 1,
      runId: $runId,
      gate: "descriptor-pressure-recovery",
      startedAt: $startedAt,
      repositoryHead: $gitHead,
      launcher: $launcher,
      nofile: {soft: $nofileLimit, hard: $nofileLimit},
      binaries: {
        rustReality: {path: $rustBinary, sha256: $rustSha256},
        xray: {path: $xrayBinary, sha256: $xraySha256},
        openssl: {path: $opensslBinary, sha256: $opensslSha256,
                  identity: $opensslIdentity}
      },
      configSha256: {server: $serverConfigSha256, xray: $xrayConfigSha256},
      ports: {server: $serverPort, socks: $socksPort, cover: $coverPort, echo: $echoPort},
      result: $result[0]
    }
' >"$out_dir/gate-summary.json"
[[ $("$openssl_bin" version -a) == "$openssl_identity" ]] ||
    die 'OpenSSL identity changed during the run'
rr_finalize_contract
(
    cd -- "$out_dir"
    sha256sum cover.log echo.log server.log xray.log pressure-result.json gate-summary.json \
        >SHA256SUMS
    sha256sum --check SHA256SUMS >/dev/null
)
printf 'descriptor-pressure recovery gate: PASS (%s)\n' "$out_dir"
