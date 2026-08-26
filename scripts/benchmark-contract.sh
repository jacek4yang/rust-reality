#!/usr/bin/env bash
# Shared fail-closed contract for authoritative performance and interop runs.
# Source this file; do not execute it directly. Formal runs hold the repository
# sibling `.coord/v1.5.0/locks/host-exclusive.lock` from rr_contract_init until
# process exit. RR_HOST_EXCLUSIVE_LOCK may select another absolute path. Formal
# scripts are the sole lock owners: an outer systemd/tmux runner must not take
# this lock first. A dedicated keeper holds the only lock FD so benchmark child
# processes cannot extend lock lifetime by inheriting it. Non-contract build
# gates may still use their own outer lock discipline.

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
declare -ag RR_HARNESS_TREES=()
declare -Ag RR_HARNESS_TREE_MANIFEST_SHA256=()
declare -Ag RR_HARNESS_TREE_FILE_COUNTS=()
RR_CONTRACT_FINALIZED=0
RR_HOST_EXCLUSIVE_LOCK_PATH=
RR_HOST_EXCLUSIVE_LOCK_DEVICE_INODE=
RR_HOST_EXCLUSIVE_LOCK_MODE=notRequired
RR_HOST_EXCLUSIVE_KEEPER_PID=
RR_HOST_EXCLUSIVE_KEEPER_STARTTIME=
RR_HOST_EXCLUSIVE_KEEPER_PARENT_PID=
RR_HOST_EXCLUSIVE_KEEPER_PARENT_STARTTIME=
RR_HOST_EXCLUSIVE_KEEPER_LOCK_FD=
RR_HOST_EXCLUSIVE_KEEPER_EXE=
RR_HOST_EXCLUSIVE_KEEPER_HELPER=
readonly RR_HOST_LOCK_PROTOCOL_VERSION=1
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

rr_contract_keeper_pid_is_exact() {
    local current_start
    [[ $RR_HOST_EXCLUSIVE_KEEPER_PID =~ ^[1-9][0-9]*$ &&
        $RR_HOST_EXCLUSIVE_KEEPER_STARTTIME =~ ^[1-9][0-9]*$ ]] || return 1
    current_start=$(rr_pid_starttime "$RR_HOST_EXCLUSIVE_KEEPER_PID" 2>/dev/null) || return 1
    [[ $current_start == "$RR_HOST_EXCLUSIVE_KEEPER_STARTTIME" ]]
}

rr_contract_keeper_is_exact() {
    local actual_exe
    rr_contract_keeper_pid_is_exact || return 1
    [[ -n $RR_HOST_EXCLUSIVE_KEEPER_EXE ]] || return 1
    actual_exe=$(readlink -f -- "/proc/$RR_HOST_EXCLUSIVE_KEEPER_PID/exe" 2>/dev/null) || return 1
    [[ $actual_exe == "$RR_HOST_EXCLUSIVE_KEEPER_EXE" ]]
}

rr_contract_keeper_lock_target() {
    local target observed_identity path_identity
    rr_contract_keeper_is_exact || return 1
    [[ $RR_HOST_EXCLUSIVE_KEEPER_LOCK_FD =~ ^[0-9]+$ ]] || return 1
    (( RR_HOST_EXCLUSIVE_KEEPER_LOCK_FD >= 3 )) || return 1
    [[ -e /proc/$RR_HOST_EXCLUSIVE_KEEPER_PID/fd/$RR_HOST_EXCLUSIVE_KEEPER_LOCK_FD ]] || return 1
    target=$(readlink -- "/proc/$RR_HOST_EXCLUSIVE_KEEPER_PID/fd/$RR_HOST_EXCLUSIVE_KEEPER_LOCK_FD" \
        2>/dev/null) || return 1
    [[ $target == "$RR_HOST_EXCLUSIVE_LOCK_PATH" ]] || return 1
    observed_identity=$(stat -Lc '%d:%i' -- \
        "/proc/$RR_HOST_EXCLUSIVE_KEEPER_PID/fd/$RR_HOST_EXCLUSIVE_KEEPER_LOCK_FD" \
        2>/dev/null) || return 1
    [[ $observed_identity == "$RR_HOST_EXCLUSIVE_LOCK_DEVICE_INODE" ]] || return 1
    [[ -f $RR_HOST_EXCLUSIVE_LOCK_PATH && ! -L $RR_HOST_EXCLUSIVE_LOCK_PATH ]] || return 1
    path_identity=$(stat -Lc '%d:%i' -- "$RR_HOST_EXCLUSIVE_LOCK_PATH" 2>/dev/null) || return 1
    [[ $path_identity == "$RR_HOST_EXCLUSIVE_LOCK_DEVICE_INODE" ]] || return 1
    rr_contract_keeper_is_exact
}

rr_contract_acquire_host_lock() {
    local common_git_dir coordination_root lock_input lock_parent_input lock_parent lock_basename
    local state_dir ready_file error_file parent_start keeper_pid keeper_start
    local attempt keeper_launcher ready_identity ready_fd ready_exe
    [[ -z ${RR_HOST_EXCLUSIVE_FD+x} ]] ||
        rr_contract_die "RR_HOST_EXCLUSIVE_FD is unsupported; formal scripts own a dedicated keeper" || return
    [[ $RR_HOST_EXCLUSIVE_LOCK_MODE != dedicatedKeeper ]] ||
        rr_contract_die "host-exclusive lock keeper is already registered" || return
    common_git_dir=$(git -C "$RR_REPOSITORY" rev-parse --path-format=absolute \
        --git-common-dir 2>/dev/null) ||
        rr_contract_die "could not resolve the repository common Git directory" || return
    common_git_dir=$(readlink -f -- "$common_git_dir") ||
        rr_contract_die "could not canonicalize the repository common Git directory" || return
    coordination_root=$(dirname -- "$(dirname -- "$common_git_dir")")
    lock_input=${RR_HOST_EXCLUSIVE_LOCK:-"$coordination_root/.coord/v1.5.0/locks/host-exclusive.lock"}
    [[ $lock_input == /* ]] ||
        rr_contract_die "RR_HOST_EXCLUSIVE_LOCK must be absolute" || return
    lock_parent_input=$(dirname -- "$lock_input")
    mkdir -p -- "$lock_parent_input" ||
        rr_contract_die "could not create host-exclusive lock directory" || return
    [[ -d $lock_parent_input && ! -L $lock_parent_input ]] ||
        rr_contract_die "host-exclusive lock directory must be a non-symlink directory" || return
    lock_parent=$(readlink -f -- "$lock_parent_input") ||
        rr_contract_die "could not canonicalize host-exclusive lock directory" || return
    lock_basename=$(basename -- "$lock_input")
    [[ $lock_input == "$lock_parent/$lock_basename" ]] ||
        rr_contract_die "host-exclusive lock path must be canonical and contain no symlink components" || return
    [[ ! -L $lock_input ]] ||
        rr_contract_die "host-exclusive lock must not be a symlink" || return
    [[ ! -e $lock_input || -f $lock_input ]] ||
        rr_contract_die "host-exclusive lock must be a regular non-symlink" || return
    RR_HOST_EXCLUSIVE_LOCK_PATH=$lock_input

    RR_HOST_EXCLUSIVE_KEEPER_HELPER="$RR_REPOSITORY/scripts/host-exclusive-lock-keeper.py"
    rr_register_harness_file "$RR_HOST_EXCLUSIVE_KEEPER_HELPER" || return
    keeper_launcher=$(readlink -f -- "${RR_HOST_LOCK_PYTHON3_TEST_ONLY:-$(command -v python3)}") ||
        rr_contract_die "could not resolve python3 for host lock keeper" || return
    parent_start=$(rr_pid_starttime "$$") ||
        rr_contract_die "could not identify host lock keeper parent" || return
    RR_HOST_EXCLUSIVE_KEEPER_PARENT_PID=$$
    RR_HOST_EXCLUSIVE_KEEPER_PARENT_STARTTIME=$parent_start

    state_dir=$(mktemp -d "$lock_parent/.host-lock-keeper.$$.XXXXXXXX") ||
        rr_contract_die "could not create private host lock keeper state" || return
    chmod 700 -- "$state_dir"
    ready_file="$state_dir/ready.json"
    error_file="$state_dir/stderr"
    "$keeper_launcher" "$RR_HOST_EXCLUSIVE_KEEPER_HELPER" \
        --lock "$RR_HOST_EXCLUSIVE_LOCK_PATH" --parent-pid "$$" \
        --parent-starttime "$parent_start" --ready "$ready_file" \
        </dev/null >/dev/null 2>"$error_file" &
    keeper_pid=$!
    RR_HOST_EXCLUSIVE_KEEPER_PID=$keeper_pid
    for attempt in $(seq 1 50); do
        keeper_start=$(rr_pid_starttime "$keeper_pid" 2>/dev/null || true)
        [[ -n $keeper_start ]] && break
        kill -0 "$keeper_pid" 2>/dev/null || break
        sleep 0.01
    done
    RR_HOST_EXCLUSIVE_KEEPER_STARTTIME=$keeper_start
    if [[ -z $keeper_start ]]; then
        wait "$keeper_pid" 2>/dev/null || true
        [[ ! -s $error_file ]] || sed -n '1,8p' "$error_file" >&2
        rm -f -- "$ready_file" "$error_file"
        rmdir -- "$state_dir" 2>/dev/null || true
        rr_contract_die "host-exclusive lock keeper exited before identity registration" || return
    fi

    for attempt in $(seq 1 100); do
        [[ -f $ready_file && ! -L $ready_file ]] && break
        rr_contract_keeper_pid_is_exact || break
        sleep 0.05
    done
    if [[ ! -f $ready_file || -L $ready_file ]]; then
        rr_contract_stop_host_lock_keeper
        [[ ! -s $error_file ]] || sed -n '1,8p' "$error_file" >&2
        rm -f -- "$ready_file" "$error_file"
        rmdir -- "$state_dir" 2>/dev/null || true
        rr_contract_die "host-exclusive lock keeper did not become ready" || return
    fi

    if ! jq -e --arg lock "$RR_HOST_EXCLUSIVE_LOCK_PATH" \
        --arg parent_start "$parent_start" --arg keeper_start "$keeper_start" \
        --argjson parent_pid "$$" --argjson keeper_pid "$keeper_pid" \
        '.schemaVersion == 1 and .mode == "dedicatedKeeper" and
         .lockPath == $lock and .parentPid == $parent_pid and
         .parentStarttime == $parent_start and .keeperPid == $keeper_pid and
         .keeperStarttime == $keeper_start and
         (.keeperExe | type == "string" and startswith("/")) and
         (.lockDevice | type == "number") and (.lockInode | type == "number") and
         (.lockFd | type == "number" and . >= 3) and
         (.lockDeviceInode | type == "string")' "$ready_file" >/dev/null; then
        rr_contract_stop_host_lock_keeper
        rm -f -- "$ready_file" "$error_file"
        rmdir -- "$state_dir" 2>/dev/null || true
        rr_contract_die "host-exclusive lock keeper returned an invalid identity" || return
    fi
    ready_identity=$(jq -er '.lockDeviceInode' "$ready_file")
    ready_fd=$(jq -er '.lockFd | tostring' "$ready_file")
    ready_exe=$(jq -er '.keeperExe' "$ready_file")
    [[ $(readlink -f -- "$ready_exe" 2>/dev/null) == "$ready_exe" ]] || {
        rr_contract_stop_host_lock_keeper
        rm -f -- "$ready_file" "$error_file"
        rmdir -- "$state_dir" 2>/dev/null || true
        rr_contract_die "host-exclusive lock keeper returned a non-canonical interpreter" || return
    }
    RR_HOST_EXCLUSIVE_LOCK_DEVICE_INODE=$ready_identity
    RR_HOST_EXCLUSIVE_KEEPER_LOCK_FD=$ready_fd
    RR_HOST_EXCLUSIVE_KEEPER_EXE=$ready_exe
    RR_HOST_EXCLUSIVE_LOCK_MODE=dedicatedKeeper
    rm -f -- "$ready_file" "$error_file"
    rmdir -- "$state_dir" || {
        rr_contract_stop_host_lock_keeper
        rr_contract_die "could not remove private host lock keeper state" || return
    }
    rr_contract_keeper_lock_target || {
        rr_contract_stop_host_lock_keeper
        rr_contract_die "host-exclusive lock keeper FD has the wrong identity" || return
    }
}

rr_contract_verify_host_lock() {
    (( RR_EXPLORATORY == 1 )) && return 0
    [[ $RR_HOST_EXCLUSIVE_LOCK_MODE == dedicatedKeeper ]] ||
        rr_contract_die "formal run has no dedicated host-exclusive lock keeper" || return 1
    rr_contract_keeper_lock_target ||
        rr_contract_die "host-exclusive lock keeper identity changed during run" || return 1
}

rr_contract_stop_host_lock_keeper() {
    local attempt current_start
    [[ -n $RR_HOST_EXCLUSIVE_KEEPER_PID ]] || return 0
    [[ $RR_HOST_EXCLUSIVE_KEEPER_STARTTIME =~ ^[1-9][0-9]*$ ]] || {
        rr_contract_die "host-exclusive lock keeper has no registered starttime"
        return 1
    }
    current_start=$(rr_pid_starttime "$RR_HOST_EXCLUSIVE_KEEPER_PID" 2>/dev/null || true)
    if [[ -z $current_start ]]; then
        wait "$RR_HOST_EXCLUSIVE_KEEPER_PID" 2>/dev/null || true
        return 0
    fi
    [[ $current_start == "$RR_HOST_EXCLUSIVE_KEEPER_STARTTIME" ]] || {
        rr_contract_die "host-exclusive lock keeper PID/starttime changed before cleanup"
        return 1
    }
    kill -TERM "$RR_HOST_EXCLUSIVE_KEEPER_PID" 2>/dev/null || true
    for attempt in $(seq 1 50); do
        rr_contract_keeper_pid_is_exact || break
        sleep 0.02
    done
    if rr_contract_keeper_pid_is_exact; then
        kill -KILL "$RR_HOST_EXCLUSIVE_KEEPER_PID" 2>/dev/null || true
    fi
    wait "$RR_HOST_EXCLUSIVE_KEEPER_PID" 2>/dev/null || true
    rr_contract_keeper_pid_is_exact && {
        rr_contract_die "could not stop exact host-exclusive lock keeper"
        return 1
    }
    return 0
}

# Standalone formal harness API. This deliberately performs only lock ownership;
# callers remain responsible for their own immutable-input and output contracts.
# It is safe to use after sourcing this file without calling rr_contract_init.
rr_host_lock_acquire() {
    local repository=${1:?repository is required} explicit_lock=${2:-}
    RR_REPOSITORY=$(readlink -f -- "$repository") ||
        rr_contract_die "could not canonicalize host lock repository" || return
    [[ -d $RR_REPOSITORY ]] ||
        rr_contract_die "host lock repository is not a directory" || return
    RR_EXPLORATORY=0
    if [[ -n $explicit_lock ]]; then
        [[ $explicit_lock == /* ]] ||
            rr_contract_die "standalone host lock path must be absolute" || return
        RR_HOST_EXCLUSIVE_LOCK=$explicit_lock
    fi
    rr_contract_acquire_host_lock
}

rr_host_lock_verify() {
    rr_contract_verify_host_lock
}

rr_host_lock_stop() {
    rr_contract_stop_host_lock_keeper
}

rr_host_lock_metadata_json() {
    local helper_sha=
    rr_contract_verify_host_lock || return
    [[ -z $RR_HOST_EXCLUSIVE_KEEPER_HELPER ]] ||
        helper_sha=${RR_HARNESS_SHA256[$RR_HOST_EXCLUSIVE_KEEPER_HELPER]:-}
    jq -n --argjson protocol_version "$RR_HOST_LOCK_PROTOCOL_VERSION" \
        --arg path "$RR_HOST_EXCLUSIVE_LOCK_PATH" \
        --arg identity "$RR_HOST_EXCLUSIVE_LOCK_DEVICE_INODE" \
        --arg mode "$RR_HOST_EXCLUSIVE_LOCK_MODE" \
        --arg keeper_pid "$RR_HOST_EXCLUSIVE_KEEPER_PID" \
        --arg keeper_start "$RR_HOST_EXCLUSIVE_KEEPER_STARTTIME" \
        --arg keeper_exe "$RR_HOST_EXCLUSIVE_KEEPER_EXE" \
        --arg parent_pid "$RR_HOST_EXCLUSIVE_KEEPER_PARENT_PID" \
        --arg parent_start "$RR_HOST_EXCLUSIVE_KEEPER_PARENT_STARTTIME" \
        --arg helper "$RR_HOST_EXCLUSIVE_KEEPER_HELPER" --arg helper_sha "$helper_sha" \
        '{protocolVersion:$protocol_version,path:$path,deviceInode:$identity,mode:$mode,
          keeperPid:($keeper_pid | tonumber),keeperStarttime:$keeper_start,
          keeperExe:$keeper_exe,
          parentPid:($parent_pid | tonumber),parentStarttime:$parent_start,
          keeperHelper:{path:$helper,sha256:$helper_sha},required:true}'
}

rr_host_lock_evidence_begin() {
    local preflight
    preflight=$(rr_host_lock_metadata_json) || return
    jq -cn --argjson preflight "$preflight" \
        '$preflight + {preflight:$preflight,postflight:null}'
}

rr_host_lock_evidence_complete() {
    local evidence=${1:?preflight lock evidence is required} postflight
    postflight=$(rr_host_lock_metadata_json) || return
    jq -ecn --argjson evidence "$evidence" --argjson postflight "$postflight" '
        def identity:
          {protocolVersion,path,deviceInode,mode,keeperPid,keeperStarttime,keeperExe,
           parentPid,parentStarttime,keeperHelper,required};
        ($evidence.postflight == null)
        and (($evidence | del(.preflight,.postflight)) == $evidence.preflight)
        and (($evidence.preflight | identity) == ($postflight | identity))
        | if . then $evidence + {postflight:$postflight} else error(
            "host-exclusive lock identity changed between preflight and postflight") end
    '
}

rr_write_success_marker() {
    local marker=${1:?marker path is required} evidence=${2:?evidence path is required}
    local run_id=${3:?run ID is required} collector=${4:?collector is required}
    local parent temporary evidence_sha
    [[ $marker == /* && $evidence == /* ]] ||
        rr_contract_die "success marker and evidence paths must be absolute" || return
    [[ -f $evidence && ! -L $evidence ]] ||
        rr_contract_die "success marker evidence must be a regular non-symlink" || return
    [[ ! -e $marker && ! -L $marker ]] ||
        rr_contract_die "success marker already exists: $marker" || return
    parent=$(dirname -- "$marker")
    [[ $parent == "$(dirname -- "$evidence")" && -d $parent && ! -L $parent ]] ||
        rr_contract_die "success marker and evidence must share one non-symlink directory" || return
    evidence_sha=$(sha256sum -- "$evidence" | awk '{print $1}')
    temporary=$(mktemp "$parent/.success-marker.$$.XXXXXXXX") ||
        rr_contract_die "could not allocate success marker temporary file" || return
    if ! jq -n --arg run_id "$run_id" --arg collector "$collector" \
        --arg evidence "$evidence" --arg evidence_sha "$evidence_sha" \
        --arg recorded "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{schemaVersion:1,status:"COMPLETE",exitCode:0,runId:$run_id,
          collector:$collector,evidence:{path:$evidence,sha256:$evidence_sha},
          recordedUtc:$recorded}' >"$temporary"; then
        rm -f -- "$temporary"
        rr_contract_die "could not serialize success marker" || return
    fi
    chmod 600 -- "$temporary" || {
        rm -f -- "$temporary"
        rr_contract_die "could not protect success marker temporary file" || return
    }
    if ! ln -- "$temporary" "$marker"; then
        rm -f -- "$temporary"
        rr_contract_die "could not atomically publish success marker" || return
    fi
    rm -f -- "$temporary" || {
        rm -f -- "$marker"
        rr_contract_die "could not remove success marker temporary file" || return
    }
}

# rr_contract_init REPOSITORY SCRIPT_NAME DEFAULT_OUTPUT_PARENT PORT_BLOCK_WIDTH
rr_contract_init() {
    local repository=$1 script_name=$2 default_output_parent=$3 port_width=$4
    local output_input temporary_input filesystem_type

    local program
    for program in git jq mktemp python3 readelf readlink sha256sum stat; do
        command -v "$program" >/dev/null ||
            rr_contract_die "required identity tool is unavailable: $program" || return
    done

    RR_REPOSITORY=$(readlink -f -- "$repository")
    RR_SCRIPT=$(readlink -f -- "$0")
    RR_SCRIPT_NAME=$script_name
    RR_EXPLORATORY=${EXPLORATORY:-0}
    [[ $RR_EXPLORATORY == 0 || $RR_EXPLORATORY == 1 ]] ||
        rr_contract_die "EXPLORATORY must be 0 or 1" || return
    [[ -z ${RR_HOST_EXCLUSIVE_FD+x} ]] ||
        rr_contract_die "RR_HOST_EXCLUSIVE_FD is unsupported; formal scripts own a dedicated keeper" || return

    RR_HARNESS_COMMIT=$(git -C "$RR_REPOSITORY" rev-parse --verify 'HEAD^{commit}' \
        2>/dev/null || true)
    RR_HARNESS_TRACKED_DIRTY=1
    if [[ $RR_HARNESS_COMMIT =~ ^[0-9a-f]{40}$ ]] &&
        git -C "$RR_REPOSITORY" diff --quiet --ignore-submodules=none -- &&
        git -C "$RR_REPOSITORY" diff --cached --quiet --ignore-submodules=none --; then
        RR_HARNESS_TRACKED_DIRTY=0
    fi
    if [[ $RR_EXPLORATORY == 0 ]]; then
        command -v flock >/dev/null ||
            rr_contract_die "flock is required for a formal run" || return
        [[ $RR_HARNESS_COMMIT =~ ^[0-9a-f]{40}$ ]] ||
            rr_contract_die "repository HEAD is not a valid commit" || return
        (( RR_HARNESS_TRACKED_DIRTY == 0 )) ||
            rr_contract_die "repository has tracked or staged changes" || return
        rr_contract_acquire_host_lock || return
    fi
    RR_HARNESS_COMMIT=${RR_HARNESS_COMMIT:-unavailable}

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
    if [[ -n $build_id && $build_id =~ ^([0-9a-fA-F]{2})+$ ]]; then
        build_id=${build_id,,}
    elif [[ $RR_EXPLORATORY == 0 ]]; then
        rr_contract_die "$label has no valid hexadecimal GNU Build ID" || return
    else
        build_id=unavailable
    fi

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
    local path=$1 canonical sha relative
    [[ $path == /* && -f $path && ! -L $path ]] ||
        rr_contract_die "harness file must be an absolute regular non-symlink: $path" || return
    canonical=$(readlink -f -- "$path")
    [[ -z ${RR_HARNESS_SHA256[$canonical]:-} ]] ||
        rr_contract_die "duplicate harness file: $canonical" || return
    if [[ $RR_EXPLORATORY == 0 ]]; then
        case $canonical in
            "$RR_REPOSITORY"/*) relative=${canonical#"$RR_REPOSITORY"/} ;;
            *) rr_contract_die "formal harness file is outside the repository: $canonical" || return ;;
        esac
        git -C "$RR_REPOSITORY" ls-files --error-unmatch -- "$relative" >/dev/null 2>&1 ||
            rr_contract_die "formal harness file is not tracked at HEAD: $canonical" || return
    fi
    sha=$(sha256sum -- "$canonical" | awk '{print $1}')
    RR_HARNESS_FILES+=("$canonical")
    RR_HARNESS_SHA256[$canonical]=$sha
}

rr_harness_tree_snapshot() {
    python3 - "$1" <<'PY'
import hashlib
from pathlib import Path
import sys

root = Path(sys.argv[1])
files = []
for path in root.rglob("*"):
    if path.is_symlink():
        raise SystemExit(f"symlink in harness source tree: {path}")
    if path.is_file():
        files.append(path.relative_to(root).as_posix())
files.sort()
if not files:
    raise SystemExit("empty harness source tree")
digest = hashlib.sha256()
for relative in files:
    digest.update(relative.encode("utf-8"))
    digest.update(b"\0")
    digest.update(hashlib.sha256((root / relative).read_bytes()).digest())
print(digest.hexdigest(), len(files))
PY
}

rr_register_harness_tree() {
    local path=$1 canonical snapshot manifest_sha file_count file
    local -a files=()
    [[ $path == /* && -d $path && ! -L $path ]] ||
        rr_contract_die "harness source tree must be an absolute non-symlink directory: $path" || return
    canonical=$(readlink -f -- "$path")
    [[ -z ${RR_HARNESS_TREE_MANIFEST_SHA256[$canonical]:-} ]] ||
        rr_contract_die "duplicate harness source tree: $canonical" || return
    snapshot=$(rr_harness_tree_snapshot "$canonical") ||
        rr_contract_die "could not snapshot harness source tree: $canonical" || return
    read -r manifest_sha file_count <<<"$snapshot"
    [[ $manifest_sha =~ ^[0-9a-f]{64}$ && $file_count =~ ^[1-9][0-9]*$ ]] ||
        rr_contract_die "invalid harness source manifest: $canonical" || return
    mapfile -d '' -t files < <(find -P "$canonical" -type f -print0 | sort -z)
    (( ${#files[@]} == file_count )) ||
        rr_contract_die "harness source tree changed while registering: $canonical" || return
    for file in "${files[@]}"; do
        rr_register_harness_file "$file" || return
    done
    RR_HARNESS_TREES+=("$canonical")
    RR_HARNESS_TREE_MANIFEST_SHA256[$canonical]=$manifest_sha
    RR_HARNESS_TREE_FILE_COUNTS[$canonical]=$file_count
}

rr_assert_pid_exe() {
    local pid=$1 expected=$2 attempt actual registered_start current_start
    expected=$(readlink -f -- "$expected")
    registered_start=${RR_PID_STARTS[$pid]:-}
    [[ -n $registered_start ]] ||
        rr_contract_die "PID $pid has no registered starttime" || return
    for attempt in $(seq 1 50); do
        current_start=$(rr_pid_starttime "$pid" 2>/dev/null) || break
        [[ $current_start == "$registered_start" ]] || {
            rr_contract_die "PID $pid starttime changed during executable verification"
            return
        }
        if [[ -e /proc/$pid/exe ]]; then
            actual=$(readlink -f -- "/proc/$pid/exe" 2>/dev/null || true)
            [[ $actual == "$expected" ]] && return 0
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
    local pid=${1:-} expected actual
    [[ $pid =~ ^[1-9][0-9]*$ ]] || return 1
    expected=${RR_PID_STARTS[$pid]:-}
    [[ -n $expected ]] || return 1
    actual=$(rr_pid_starttime "$pid" 2>/dev/null) || return 1
    [[ $actual == "$expected" ]]
}

rr_stop_registered_pid() {
    local pid=${1:-} attempt
    [[ $pid =~ ^[1-9][0-9]*$ ]] || return 0
    if rr_pid_is_registered "$pid"; then
        kill -TERM "$pid" 2>/dev/null || true
    fi
    for attempt in $(seq 1 50); do
        rr_pid_is_registered "$pid" || break
        sleep 0.1
    done
    if rr_pid_is_registered "$pid"; then
        kill -KILL "$pid" 2>/dev/null || true
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
    local phase=${1:-preflight} binary_json harness_json tree_json host_lock_json path
    rr_contract_verify_host_lock || return
    binary_json=$(rr_contract_binary_json)
    if [[ $RR_EXPLORATORY == 0 ]]; then
        host_lock_json=$(rr_host_lock_metadata_json) || return
    else
        host_lock_json='{"protocolVersion":1,"path":"","deviceInode":"","mode":"notRequired",
          "keeperPid":null,"keeperStarttime":null,"parentPid":null,
          "parentStarttime":null,"keeperExe":"","keeperHelper":{"path":"","sha256":""},
          "required":false}'
    fi
    harness_json=$(for path in "${RR_HARNESS_FILES[@]}"; do
        jq -cn --arg path "$path" --arg sha "${RR_HARNESS_SHA256[$path]}" \
            '{path:$path,sha256:$sha}'
    done | jq -s .)
    tree_json=$(for path in "${RR_HARNESS_TREES[@]}"; do
        jq -cn --arg path "$path" \
            --arg sha "${RR_HARNESS_TREE_MANIFEST_SHA256[$path]}" \
            --argjson count "${RR_HARNESS_TREE_FILE_COUNTS[$path]}" \
            '{path:$path,manifestSha256:$sha,fileCount:$count}'
    done | jq -s .)
    jq -n --arg run_id "$RR_RUN_ID" --arg phase "$phase" \
        --argjson exploratory "$RR_EXPLORATORY" \
        --arg out_dir "$RR_OUT_DIR" --arg tmpdir "$RR_TMPDIR" \
        --argjson port_base "$RR_PORT_BASE" --argjson port_width "$RR_PORT_WIDTH" \
        --arg script "$RR_SCRIPT" --arg script_sha "$RR_SCRIPT_SHA256" \
        --arg contract "$RR_CONTRACT_PATH" --arg contract_sha "$RR_CONTRACT_SHA256" \
        --arg harness_commit "$RR_HARNESS_COMMIT" --argjson binaries "$binary_json" \
        --argjson host_lock "$host_lock_json" \
        --argjson harness_dirty "$RR_HARNESS_TRACKED_DIRTY" \
        --argjson harness_files "$harness_json" --argjson harness_trees "$tree_json" \
        --arg date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{schemaVersion:1,runId:$run_id,phase:$phase,exploratory:($exploratory == 1),
          outDir:$out_dir,tmpDir:$tmpdir,portBlock:{base:$port_base,width:$port_width},
          script:{path:$script,sha256:$script_sha,harnessCommit:$harness_commit,
                  trackedDirty:($harness_dirty == 1)},
          contract:{path:$contract,sha256:$contract_sha},
          hostExclusiveLock:$host_lock,
          harnessFiles:$harness_files,harnessSourceTrees:$harness_trees,
          binaries:$binaries,recordedUtc:$date}' \
        >"$RR_OUT_DIR/run-contract.json"
}

rr_verify_registered_files() {
    local label actual path snapshot manifest_sha file_count
    if [[ $RR_EXPLORATORY == 0 ]]; then
        rr_contract_verify_host_lock || return 1
        actual=$(git -C "$RR_REPOSITORY" rev-parse --verify 'HEAD^{commit}' 2>/dev/null || true)
        [[ $actual == "$RR_HARNESS_COMMIT" ]] ||
            rr_contract_die "repository HEAD changed during run" || return 1
        git -C "$RR_REPOSITORY" diff --quiet --ignore-submodules=none -- &&
            git -C "$RR_REPOSITORY" diff --cached --quiet --ignore-submodules=none -- ||
            rr_contract_die "repository acquired tracked or staged changes during run" || return 1
    fi
    actual=$(sha256sum -- "$RR_SCRIPT" | awk '{print $1}')
    [[ $actual == "$RR_SCRIPT_SHA256" ]] ||
        rr_contract_die "script changed during run" || return 1
    actual=$(sha256sum -- "$RR_CONTRACT_PATH" | awk '{print $1}')
    [[ $actual == "$RR_CONTRACT_SHA256" ]] ||
        rr_contract_die "benchmark contract changed during run" || return 1
    for path in "${RR_HARNESS_FILES[@]}"; do
        actual=$(sha256sum -- "$path" | awk '{print $1}')
        [[ $actual == "${RR_HARNESS_SHA256[$path]}" ]] ||
            rr_contract_die "harness file changed during run: $path" || return 1
    done
    for path in "${RR_HARNESS_TREES[@]}"; do
        snapshot=$(rr_harness_tree_snapshot "$path") ||
            rr_contract_die "could not re-snapshot harness source tree: $path" || return 1
        read -r manifest_sha file_count <<<"$snapshot"
        [[ $manifest_sha == "${RR_HARNESS_TREE_MANIFEST_SHA256[$path]}" &&
            $file_count == "${RR_HARNESS_TREE_FILE_COUNTS[$path]}" ]] ||
            rr_contract_die "harness source manifest changed during run: $path" || return 1
    done
    for label in "${RR_BINARY_LABELS[@]}"; do
        actual=$(sha256sum -- "${RR_BINARY_PATHS[$label]}" | awk '{print $1}')
        [[ $actual == "${RR_BINARY_SHA256[$label]}" ]] ||
            rr_contract_die "$label binary changed during run" || return 1
    done
}

rr_finalize_contract() {
    rr_verify_registered_files || return
    rm -f -- "$RR_PORT_STATE"
    rr_write_contract_metadata complete
    RR_CONTRACT_FINALIZED=1
}

# Call from every EXIT trap after process cleanup. Always recheck immutable
# inputs at actual shell exit: preserve an existing failure, otherwise upgrade
# a successful run when verification fails.
rr_contract_verify_on_exit() {
    local original_status=$1 verify_status=0 keeper_status=0 marker_status=0
    rr_verify_registered_files || verify_status=1
    rr_contract_stop_host_lock_keeper || keeper_status=1
    if (( original_status != 0 )); then
        return "$original_status"
    fi
    if (( RR_EXPLORATORY == 0 )); then
        if (( RR_CONTRACT_FINALIZED != 1 || verify_status != 0 || keeper_status != 0 )); then
            marker_status=1
        else
            rr_write_success_marker "$RR_OUT_DIR/run-completion.json" \
                "$RR_OUT_DIR/run-contract.json" "$RR_RUN_ID" "$RR_SCRIPT_NAME" ||
                marker_status=1
        fi
    fi
    (( verify_status == 0 && keeper_status == 0 && marker_status == 0 ))
}
