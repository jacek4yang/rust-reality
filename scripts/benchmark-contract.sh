#!/usr/bin/env bash
# Shared fail-closed contract for authoritative performance and interop runs.
# Source this file; do not execute it directly.

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    echo "formal-run-contract.sh must be sourced" >&2
    exit 2
fi

declare -ag RR_BINARY_LABELS=()
declare -Ag RR_BINARY_PATHS=()
declare -Ag RR_BINARY_SHA256=()
declare -Ag RR_BINARY_BUILD_IDS=()
declare -Ag RR_BINARY_SOURCE_COMMITS=()
declare -Ag RR_BINARY_IDENTITIES=()
declare -Ag RR_PID_STARTS=()
declare -ag RR_HARNESS_FILES=()
declare -Ag RR_HARNESS_SHA256=()
RR_CONTRACT_PATH=$(readlink -f -- "${BASH_SOURCE[0]}")
RR_CONTRACT_SHA256=$(sha256sum -- "$RR_CONTRACT_PATH" | awk '{print $1}')

rr_contract_die() {
    printf 'formal run contract: %s\n' "$*" >&2
    return 2
}

rr_contract_require_safe_name() {
    local label=$1 value=$2
    [[ $value =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] ||
        rr_contract_die "$label must be a safe 1..128 character name"
}

rr_contract_find_free_block() {
    python3 - "$1" <<'PY'
import os
import socket
import sys

width = int(sys.argv[1])
start = 20000 + (os.getpid() * 131 % 30000)
for step in range(30000):
    base = 20000 + ((start - 20000 + step * max(width, 17)) % (45000 - width))
    sockets = []
    try:
        for port in range(base, base + width):
            sock = socket.socket()
            sock.bind(("127.0.0.1", port))
            sockets.append(sock)
    except OSError:
        pass
    else:
        print(base)
        raise SystemExit(0)
    finally:
        for sock in sockets:
            sock.close()
raise SystemExit("no free exploratory port block")
PY
}

rr_contract_check_port_block() {
    python3 - "$1" "$2" <<'PY'
import socket
import sys

base, width = map(int, sys.argv[1:])
sockets = []
try:
    for port in range(base, base + width):
        sock = socket.socket()
        sock.bind(("127.0.0.1", port))
        sockets.append(sock)
finally:
    for sock in sockets:
        sock.close()
PY
}

# rr_contract_init REPOSITORY SCRIPT_NAME DEFAULT_OUTPUT_PARENT PORT_BLOCK_WIDTH
rr_contract_init() {
    local repository=$1 script_name=$2 default_output_parent=$3 port_width=$4
    local output_input temporary_input filesystem_type

    local program
    for program in git jq python3 readelf readlink sha256sum stat; do
        command -v "$program" >/dev/null ||
            rr_contract_die "required identity tool is unavailable: $program" || return
    done

    RR_REPOSITORY=$(readlink -f -- "$repository")
    RR_SCRIPT=$(readlink -f -- "$0")
    RR_SCRIPT_NAME=$script_name
    RR_EXPLORATORY=${EXPLORATORY:-0}
    [[ $RR_EXPLORATORY == 0 || $RR_EXPLORATORY == 1 ]] ||
        rr_contract_die "EXPLORATORY must be 0 or 1" || return

    RR_RUN_ID=${RUN_ID:-}
    if [[ -z $RR_RUN_ID ]]; then
        if [[ $RR_EXPLORATORY == 0 ]]; then
            rr_contract_die "RUN_ID is required for a formal run" || return
        fi
        RR_RUN_ID="$script_name-$(date -u +%Y%m%dT%H%M%SZ)-$$"
    fi
    rr_contract_require_safe_name RUN_ID "$RR_RUN_ID" || return

    output_input=${OUT_DIR:-}
    if [[ -z $output_input ]]; then
        if [[ $RR_EXPLORATORY == 0 ]]; then
            rr_contract_die "OUT_DIR is required for a formal run" || return
        fi
        output_input="$RR_REPOSITORY/$default_output_parent/$RR_RUN_ID"
    fi
    if [[ $output_input != /* ]]; then
        if [[ $RR_EXPLORATORY == 0 ]]; then
            rr_contract_die "OUT_DIR must be absolute for a formal run" || return
        fi
        output_input="$RR_REPOSITORY/$output_input"
    fi
    RR_OUT_DIR=$output_input
    [[ ! -e $RR_OUT_DIR && ! -L $RR_OUT_DIR ]] ||
        rr_contract_die "OUT_DIR must not already exist or be a symlink: $RR_OUT_DIR" || return

    temporary_input=${TMPDIR:-}
    if [[ -z $temporary_input ]]; then
        if [[ $RR_EXPLORATORY == 0 ]]; then
            rr_contract_die "TMPDIR is required for a formal run" || return
        fi
        temporary_input="$RR_REPOSITORY/benchmarks"
        mkdir -p -- "$temporary_input"
    fi
    [[ $temporary_input == /* ]] ||
        rr_contract_die "TMPDIR must be absolute" || return
    [[ -d $temporary_input && ! -L $temporary_input ]] ||
        rr_contract_die "TMPDIR must be an existing non-symlink directory" || return
    RR_TMPDIR=$(readlink -f -- "$temporary_input")
    if [[ $RR_EXPLORATORY == 0 ]]; then
        command -v findmnt >/dev/null ||
            rr_contract_die "findmnt is required to prove TMPDIR is disk-backed" || return
        filesystem_type=$(findmnt -T "$RR_TMPDIR" -n -o FSTYPE)
        case $filesystem_type in
            tmpfs|ramfs) rr_contract_die "TMPDIR must be disk-backed, got $filesystem_type" || return ;;
            '') rr_contract_die "could not determine TMPDIR filesystem" || return ;;
        esac
    fi

    [[ $port_width =~ ^[1-9][0-9]*$ && $port_width -le 1024 ]] ||
        rr_contract_die "invalid port block width: $port_width" || return
    RR_PORT_WIDTH=$port_width
    RR_PORT_BASE=${PORT_BASE:-}
    if [[ -z $RR_PORT_BASE ]]; then
        if [[ $RR_EXPLORATORY == 0 ]]; then
            rr_contract_die "PORT_BASE is required for a formal run" || return
        fi
        RR_PORT_BASE=$(rr_contract_find_free_block "$RR_PORT_WIDTH")
    fi
    [[ $RR_PORT_BASE =~ ^[0-9]+$ ]] ||
        rr_contract_die "PORT_BASE must be an integer" || return
    (( RR_PORT_BASE >= 1024 && RR_PORT_BASE + RR_PORT_WIDTH - 1 <= 65535 )) ||
        rr_contract_die "PORT_BASE does not leave the required $RR_PORT_WIDTH-port block" || return
    rr_contract_check_port_block "$RR_PORT_BASE" "$RR_PORT_WIDTH" || {
        rr_contract_die "requested loopback port block is not fully available"
        return
    }

    mkdir -p -- "$(dirname -- "$RR_OUT_DIR")"
    mkdir -- "$RR_OUT_DIR"
    RR_PORT_STATE="$RR_OUT_DIR/.next-port"
    printf '%s\n' "$RR_PORT_BASE" >"$RR_PORT_STATE"
    chmod 600 "$RR_PORT_STATE"
    RR_SCRIPT_SHA256=$(sha256sum -- "$RR_SCRIPT" | awk '{print $1}')
    RR_HARNESS_COMMIT=$(git -C "$RR_REPOSITORY" rev-parse HEAD 2>/dev/null || printf unavailable)
}

rr_next_port() {
    python3 - "$RR_PORT_STATE" "$RR_PORT_BASE" "$RR_PORT_WIDTH" <<'PY'
import fcntl
from pathlib import Path
import sys

path = Path(sys.argv[1])
base, width = map(int, sys.argv[2:])
with path.open("r+", encoding="ascii") as handle:
    fcntl.flock(handle, fcntl.LOCK_EX)
    value = int(handle.read().strip())
    if value >= base + width:
        raise SystemExit("formal port block exhausted")
    handle.seek(0)
    handle.truncate()
    handle.write(f"{value + 1}\n")
    handle.flush()
print(value)
PY
}

# rr_register_binary LABEL ABSOLUTE_PATH EXPECTED_SHA KIND [EXPECTED_COMMIT]
# KIND is rust, xray, or generic.
rr_register_binary() {
    local label=$1 path=$2 expected_sha=$3 kind=$4 expected_commit=${5:-}
    local canonical actual_sha mode build_id source_commit=not-applicable identity
    rr_contract_require_safe_name binary-label "$label" || return
    [[ -z ${RR_BINARY_PATHS[$label]:-} ]] ||
        rr_contract_die "duplicate binary label: $label" || return
    if [[ $path != /* ]]; then
        if [[ $RR_EXPLORATORY == 0 ]]; then
            rr_contract_die "$label binary path must be absolute" || return
        fi
        path="$RR_REPOSITORY/$path"
    fi
    [[ -f $path && -x $path ]] ||
        rr_contract_die "$label binary is not an executable regular file: $path" || return
    canonical=$(readlink -f -- "$path")
    if [[ $RR_EXPLORATORY == 0 ]]; then
        [[ ! -L $path && $canonical == "$path" ]] ||
            rr_contract_die "$label binary must not be a symlink" || return
        mode=$(stat -c %a -- "$path")
        (( (8#$mode & 8#222) == 0 )) ||
            rr_contract_die "$label binary must be read-only for a formal run" || return
        [[ $expected_sha =~ ^[0-9a-f]{64}$ ]] ||
            rr_contract_die "$label expected SHA-256 is required" || return
    fi
    actual_sha=$(sha256sum -- "$canonical" | awk '{print $1}')
    if [[ -n $expected_sha && $actual_sha != "$expected_sha" ]]; then
        rr_contract_die "$label SHA-256 mismatch: expected $expected_sha, got $actual_sha" || return
    fi
    expected_sha=${expected_sha:-$actual_sha}
    build_id=$(readelf -n -- "$canonical" 2>/dev/null |
        awk '/Build ID:/ {print $3; exit}' || true)
    build_id=${build_id:-unavailable}

    case $kind in
        rust)
            if [[ $RR_EXPLORATORY == 0 && ! $expected_commit =~ ^[0-9a-f]{40}$ ]]; then
                rr_contract_die "$label EXPECTED_SOURCE_COMMIT is required" || return
            fi
            identity=$("$canonical" benchmark --duration-ms 90 --warmup-ms 1) ||
                rr_contract_die "$label could not emit benchmark identity JSON" || return
            source_commit=$(jq -er '.environment.gitCommit |
                select(type == "string" and test("^[0-9a-f]{40}$"))' <<<"$identity") ||
                rr_contract_die "$label benchmark JSON has no valid environment.gitCommit" || return
            if [[ -n $expected_commit && $source_commit != "$expected_commit" ]]; then
                rr_contract_die "$label source commit mismatch: expected $expected_commit, got $source_commit" || return
            fi
            identity=$(jq -c '.environment' <<<"$identity")
            ;;
        xray)
            identity=$("$canonical" version 2>&1 | sed -n '1p') ||
                rr_contract_die "$label version identity failed" || return
            ;;
        generic)
            identity=not-requested
            ;;
        *) rr_contract_die "unknown binary identity kind: $kind" || return ;;
    esac

    RR_BINARY_LABELS+=("$label")
    RR_BINARY_PATHS[$label]=$canonical
    RR_BINARY_SHA256[$label]=$expected_sha
    RR_BINARY_BUILD_IDS[$label]=$build_id
    RR_BINARY_SOURCE_COMMITS[$label]=$source_commit
    RR_BINARY_IDENTITIES[$label]=$identity
}

rr_register_harness_file() {
    local path=$1 canonical sha
    [[ $path == /* && -f $path && ! -L $path ]] ||
        rr_contract_die "harness file must be an absolute regular non-symlink: $path" || return
    canonical=$(readlink -f -- "$path")
    sha=$(sha256sum -- "$canonical" | awk '{print $1}')
    RR_HARNESS_FILES+=("$canonical")
    RR_HARNESS_SHA256[$canonical]=$sha
}

rr_assert_pid_exe() {
    local pid=$1 expected=$2 attempt actual
    expected=$(readlink -f -- "$expected")
    for attempt in $(seq 1 50); do
        if [[ -e /proc/$pid/exe ]]; then
            actual=$(readlink -f -- "/proc/$pid/exe" 2>/dev/null || true)
            [[ $actual == "$expected" ]] && return 0
            [[ -n $actual ]] && break
        fi
        sleep 0.01
    done
    rr_contract_die "PID $pid executable mismatch: expected $expected, got ${actual:-unavailable}"
}

rr_pid_starttime() {
    python3 - "$1" <<'PY'
from pathlib import Path
import sys

text = (Path("/proc") / sys.argv[1] / "stat").read_text()
rest = text[text.rfind(") ") + 2:].split()
if len(rest) <= 19:
    raise SystemExit("short /proc stat")
print(rest[19])
PY
}

rr_register_pid() {
    local pid=$1 expected_exe=${2:-} start
    start=$(rr_pid_starttime "$pid") ||
        rr_contract_die "PID $pid exited before registration" || return
    RR_PID_STARTS[$pid]=$start
    if [[ -n $expected_exe ]]; then
        rr_assert_pid_exe "$pid" "$expected_exe"
    fi
}

rr_pid_is_registered() {
    local pid=$1 expected=${RR_PID_STARTS[$1]:-} actual
    [[ -n $expected ]] || return 1
    actual=$(rr_pid_starttime "$pid" 2>/dev/null) || return 1
    [[ $actual == "$expected" ]]
}

rr_stop_registered_pid() {
    local pid=$1
    if rr_pid_is_registered "$pid"; then
        kill -TERM "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
    unset 'RR_PID_STARTS[$pid]'
}

rr_contract_binary_json() {
    local label
    for label in "${RR_BINARY_LABELS[@]}"; do
        jq -cn --arg label "$label" \
            --arg path "${RR_BINARY_PATHS[$label]}" \
            --arg sha "${RR_BINARY_SHA256[$label]}" \
            --arg build_id "${RR_BINARY_BUILD_IDS[$label]}" \
            --arg source_commit "${RR_BINARY_SOURCE_COMMITS[$label]}" \
            --arg identity "${RR_BINARY_IDENTITIES[$label]}" \
            '{label:$label,path:$path,sha256:$sha,buildId:$build_id,
              sourceCommit:$source_commit,identity:$identity}'
    done | jq -s .
}

rr_write_contract_metadata() {
    local phase=${1:-preflight} binary_json harness_json path
    binary_json=$(rr_contract_binary_json)
    harness_json=$(for path in "${RR_HARNESS_FILES[@]}"; do
        jq -cn --arg path "$path" --arg sha "${RR_HARNESS_SHA256[$path]}" \
            '{path:$path,sha256:$sha}'
    done | jq -s .)
    jq -n --arg run_id "$RR_RUN_ID" --arg phase "$phase" \
        --argjson exploratory "$RR_EXPLORATORY" \
        --arg out_dir "$RR_OUT_DIR" --arg tmpdir "$RR_TMPDIR" \
        --argjson port_base "$RR_PORT_BASE" --argjson port_width "$RR_PORT_WIDTH" \
        --arg script "$RR_SCRIPT" --arg script_sha "$RR_SCRIPT_SHA256" \
        --arg contract "$RR_CONTRACT_PATH" --arg contract_sha "$RR_CONTRACT_SHA256" \
        --arg harness_commit "$RR_HARNESS_COMMIT" --argjson binaries "$binary_json" \
        --argjson harness_files "$harness_json" \
        --arg date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{schemaVersion:1,runId:$run_id,phase:$phase,exploratory:($exploratory == 1),
          outDir:$out_dir,tmpDir:$tmpdir,portBlock:{base:$port_base,width:$port_width},
          script:{path:$script,sha256:$script_sha,harnessCommit:$harness_commit},
          contract:{path:$contract,sha256:$contract_sha},
          harnessFiles:$harness_files,binaries:$binaries,recordedUtc:$date}' \
        >"$RR_OUT_DIR/run-contract.json"
}

rr_verify_registered_files() {
    local label actual path
    actual=$(sha256sum -- "$RR_SCRIPT" | awk '{print $1}')
    [[ $actual == "$RR_SCRIPT_SHA256" ]] ||
        rr_contract_die "script changed during run" || return
    actual=$(sha256sum -- "$RR_CONTRACT_PATH" | awk '{print $1}')
    [[ $actual == "$RR_CONTRACT_SHA256" ]] ||
        rr_contract_die "benchmark contract changed during run" || return
    for path in "${RR_HARNESS_FILES[@]}"; do
        actual=$(sha256sum -- "$path" | awk '{print $1}')
        [[ $actual == "${RR_HARNESS_SHA256[$path]}" ]] ||
            rr_contract_die "harness file changed during run: $path" || return
    done
    for label in "${RR_BINARY_LABELS[@]}"; do
        actual=$(sha256sum -- "${RR_BINARY_PATHS[$label]}" | awk '{print $1}')
        [[ $actual == "${RR_BINARY_SHA256[$label]}" ]] ||
            rr_contract_die "$label binary changed during run" || return
    done
}

rr_finalize_contract() {
    rr_verify_registered_files || return
    rm -f -- "$RR_PORT_STATE"
    rr_write_contract_metadata complete
}
