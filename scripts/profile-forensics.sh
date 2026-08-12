#!/usr/bin/env bash
# Capture an identity-pinned perf profile from the built-in benchmark or an
# already-running rust-reality server. Every run is immutable and self-contained.
set -Eeuo pipefail

readonly REPOSITORY="$({ cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."; pwd; })"

mode=${MODE:-}
binary=${BIN:-}
expected_binary_sha256=${BIN_SHA256:-}
out_dir=${OUT_DIR:-}
run_id=${RUN_ID:-}
server_pid=${SERVER_PID:-}
record_seconds=${RECORD_SECONDS:-35}
duration_ms=${DURATION_MS:-10000}
warmup_ms=${WARMUP_MS:-1000}
event=${PERF_EVENT:-cycles:u}
frequency=${PERF_FREQUENCY:-999}
call_graph=${PERF_CALL_GRAPH:-fp}

usage() {
    cat <<'EOF'
Usage:
  scripts/profile-forensics.sh --mode built-in --binary PATH \
    --out-dir PATH --run-id ID [OPTIONS]

  scripts/profile-forensics.sh --mode attach-server --binary PATH --pid PID \
    --out-dir PATH --run-id ID [OPTIONS]

The run is written to OUT_DIR/RUN_ID. That path must not already exist. The
exact ELF is archived with perf.data, and its SHA-256 and GNU build ID are
checked against perf's build-ID table before the run is accepted.

Options:
  --mode built-in|attach-server
  --binary PATH
  --binary-sha256 HEX             Optional expected identity
  --out-dir PATH
  --run-id ID                     Safe path component, unique per run
  --pid PID                       Required for attach-server
  --record-seconds N              Default: 35
  --duration-ms N                 Built-in benchmark case duration
  --warmup-ms N                   Built-in benchmark warmup
  --event EVENT                   Default: cycles:u
  --frequency N                   Default: 999
  --call-graph fp|dwarf[,BYTES]|lbr
EOF
}

die() {
    printf 'profile-forensics: %s\n' "$*" >&2
    exit 2
}

need_argument() {
    [[ $# -ge 2 ]] || die "missing value for $1"
}

while (($#)); do
    case "$1" in
        --mode) need_argument "$@"; mode=$2; shift 2 ;;
        --binary) need_argument "$@"; binary=$2; shift 2 ;;
        --binary-sha256) need_argument "$@"; expected_binary_sha256=$2; shift 2 ;;
        --out-dir) need_argument "$@"; out_dir=$2; shift 2 ;;
        --run-id) need_argument "$@"; run_id=$2; shift 2 ;;
        --pid) need_argument "$@"; server_pid=$2; shift 2 ;;
        --record-seconds) need_argument "$@"; record_seconds=$2; shift 2 ;;
        --duration-ms) need_argument "$@"; duration_ms=$2; shift 2 ;;
        --warmup-ms) need_argument "$@"; warmup_ms=$2; shift 2 ;;
        --event) need_argument "$@"; event=$2; shift 2 ;;
        --frequency) need_argument "$@"; frequency=$2; shift 2 ;;
        --call-graph) need_argument "$@"; call_graph=$2; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ $mode == built-in || $mode == attach-server ]] ||
    die '--mode must be built-in or attach-server'
[[ -n $binary ]] || die '--binary is required'
[[ -n $out_dir ]] || die '--out-dir is required'
[[ $run_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] ||
    die '--run-id must be one safe path component'
[[ $record_seconds =~ ^[1-9][0-9]*$ ]] || die '--record-seconds must be positive'
[[ $duration_ms =~ ^[1-9][0-9]*$ ]] || die '--duration-ms must be positive'
[[ $warmup_ms =~ ^[0-9]+$ ]] || die '--warmup-ms must be non-negative'
[[ $frequency =~ ^[1-9][0-9]*$ ]] || die '--frequency must be positive'
[[ $call_graph =~ ^(fp|lbr|dwarf(,[1-9][0-9]*)?)$ ]] ||
    die '--call-graph must be fp, lbr, or dwarf[,BYTES]'
if [[ -n $expected_binary_sha256 ]]; then
    [[ $expected_binary_sha256 =~ ^[0-9a-fA-F]{64}$ ]] ||
        die '--binary-sha256 is malformed'
fi
if [[ $mode == attach-server ]]; then
    [[ $server_pid =~ ^[1-9][0-9]*$ ]] || die '--pid is required for attach-server'
fi

for program in perf python3 readelf sha256sum sudo; do
    command -v "$program" >/dev/null 2>&1 || die "required tool unavailable: $program"
done
sudo -n true >/dev/null 2>&1 || die 'passwordless sudo is required for perf'
[[ -x $binary ]] || die "binary is not executable: $binary"
binary=$(realpath "$binary")
binary_sha256=$(sha256sum -- "$binary" | awk '{print $1}')
if [[ -n $expected_binary_sha256 && ${binary_sha256,,} != ${expected_binary_sha256,,} ]]; then
    die "binary SHA-256 mismatch: expected $expected_binary_sha256, got $binary_sha256"
fi
binary_build_id=$(readelf -n -- "$binary" | awk '/Build ID:/ {print $3; exit}')
[[ -n $binary_build_id ]] || die 'binary has no GNU build ID'

mkdir -p -- "$out_dir"
out_dir=$(realpath "$out_dir")
run_dir="$out_dir/$run_id"
[[ ! -e $run_dir ]] || die "run directory already exists: $run_dir"
mkdir -m 700 -- "$run_dir"
mkdir -m 700 -- "$run_dir/binary"
archived_binary="$run_dir/binary/$(basename -- "$binary")"
cp --reflink=auto -- "$binary" "$archived_binary"
[[ $(sha256sum -- "$archived_binary" | awk '{print $1}') == "$binary_sha256" ]] ||
    die 'archived binary identity changed during copy'

perf_data="$run_dir/perf.data"
benchmark_json="$run_dir/benchmark.json"
benchmark_stderr="$run_dir/benchmark.stderr"
report="$run_dir/perf-report.txt"
buildids="$run_dir/perf-buildids.txt"
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
repo_head=$(git -C "$REPOSITORY" rev-parse HEAD)
repo_dirty=false
if [[ -n $(git -C "$REPOSITORY" status --porcelain=v1) ]]; then
    repo_dirty=true
fi

write_metadata() {
    local state=$1 perf_rc=${2:-null} workload_rc=${3:-null}
    python3 - "$run_dir/metadata.json" "$state" "$mode" "$run_id" \
        "$started_at" "$binary" "$archived_binary" "$binary_sha256" \
        "$binary_build_id" "$repo_head" "$repo_dirty" "$event" "$frequency" \
        "$call_graph" "$record_seconds" "$duration_ms" "$warmup_ms" \
        "$perf_rc" "$workload_rc" <<'PY'
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone

(
    output, state, mode, run_id, started_at, source_binary, archived_binary,
    sha256, build_id, repo_head, repo_dirty, event, frequency, call_graph,
    record_seconds, duration_ms, warmup_ms, perf_rc, workload_rc,
) = sys.argv[1:]

def nullable_int(value):
    return None if value == "null" else int(value)

record = {
    "schemaVersion": 1,
    "state": state,
    "runId": run_id,
    "mode": mode,
    "startedAt": started_at,
    "updatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "sourceBinary": source_binary,
    "archivedBinary": archived_binary,
    "binarySha256": sha256,
    "binaryBuildId": build_id,
    "repositoryHead": repo_head,
    "repositoryDirty": repo_dirty == "true",
    "perf": {
        "version": subprocess.run(
            ["perf", "--version"], check=True, capture_output=True, text=True
        ).stdout.strip(),
        "event": event,
        "frequency": int(frequency),
        "callGraph": call_graph,
        "recordSeconds": int(record_seconds),
        "exitCode": nullable_int(perf_rc),
    },
    "builtIn": {
        "durationMs": int(duration_ms),
        "warmupMs": int(warmup_ms),
        "exitCode": nullable_int(workload_rc),
    } if mode == "built-in" else None,
    "host": {
        "hostname": platform.node(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "logicalCpus": os.cpu_count(),
    },
}
temporary = output + ".tmp"
with open(temporary, "w", encoding="utf-8") as handle:
    json.dump(record, handle, indent=2, sort_keys=True)
    handle.write("\n")
os.replace(temporary, output)
PY
}

write_metadata RUNNING

profile_pid=
owned_pid=
cleanup() {
    if [[ -n $owned_pid ]]; then
        kill "$owned_pid" 2>/dev/null || true
        wait "$owned_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

if [[ $mode == built-in ]]; then
    "$binary" benchmark --duration-ms "$duration_ms" --warmup-ms "$warmup_ms" \
        >"$benchmark_json" 2>"$benchmark_stderr" &
    profile_pid=$!
    owned_pid=$profile_pid
    sleep 0.5
    kill -0 "$profile_pid" 2>/dev/null || {
        wait "$profile_pid" || true
        die "built-in benchmark exited before perf attached; see $benchmark_stderr"
    }
else
    kill -0 "$server_pid" 2>/dev/null || die "server PID is not alive: $server_pid"
    process_sha256=$(sha256sum -- "/proc/$server_pid/exe" | awk '{print $1}')
    [[ $process_sha256 == "$binary_sha256" ]] ||
        die "PID $server_pid executable SHA-256 does not match --binary"
    profile_pid=$server_pid
fi

set +e
sudo -n perf record -e "$event" -F "$frequency" -g \
    --call-graph "$call_graph" -p "$profile_pid" -o "$perf_data" -- \
    sleep "$record_seconds"
perf_rc=$?
set -e

workload_rc=0
if [[ $mode == built-in ]]; then
    set +e
    wait "$profile_pid"
    workload_rc=$?
    set -e
fi
profile_pid=
owned_pid=
trap - EXIT INT TERM

if [[ -f $perf_data ]]; then
    sudo -n chown "$(id -u):$(id -g)" "$perf_data"
fi
[[ $perf_rc -eq 0 ]] || {
    write_metadata FAILED "$perf_rc" "$workload_rc"
    die "perf record failed with exit code $perf_rc"
}
[[ $workload_rc -eq 0 ]] || {
    write_metadata FAILED "$perf_rc" "$workload_rc"
    die "workload failed with exit code $workload_rc"
}
[[ -s $perf_data ]] || die 'perf produced no data'

perf buildid-list -i "$perf_data" >"$buildids"
grep -Fqi -- "$binary_build_id" "$buildids" || {
    write_metadata FAILED "$perf_rc" "$workload_rc"
    die "perf data does not contain archived binary build ID $binary_build_id"
}
perf report --stdio --no-children --sort comm,dso,symbol -i "$perf_data" \
    >"$report" 2>&1
if [[ $mode == built-in ]]; then
    python3 -m json.tool "$benchmark_json" >/dev/null
fi

sha256sum -- "$archived_binary" "$perf_data" "$report" "$buildids" \
    >"$run_dir/SHA256SUMS"
write_metadata COMPLETE "$perf_rc" "$workload_rc"
printf 'forensic profile complete: %s\n' "$run_dir"
