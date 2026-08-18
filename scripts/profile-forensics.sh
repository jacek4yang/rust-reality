#!/usr/bin/env bash
# Capture an identity-pinned perf profile from the built-in benchmark or an
# already-running rust-reality server. Formal runs use benchmark-contract.sh.
set -Eeuo pipefail

readonly REPOSITORY="$({ cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."; pwd; })"
source "$REPOSITORY/scripts/benchmark-contract.sh"

mode=${MODE:-}
binary=${BIN:-}
expected_binary_sha256=${BIN_SHA256:-${RUST_REALITY_SHA256:-}}
expected_source_commit=${EXPECTED_SOURCE_COMMIT:-}
server_pid=${SERVER_PID:-}
record_seconds=${RECORD_SECONDS:-35}
duration_ms=${DURATION_MS:-10000}
warmup_ms=${WARMUP_MS:-1000}
event=${PERF_EVENT:-cycles:u}
frequency=${PERF_FREQUENCY:-999}
call_graph=${PERF_CALL_GRAPH:-fp}
readonly MAX_RECORD_SECONDS=300
readonly MAX_DURATION_MS=600000
readonly MAX_WARMUP_MS=600000
readonly MAX_FREQUENCY=9999
readonly MAX_DWARF_BYTES=65528

usage() {
    cat <<'EOF'
Usage:
  RUN_ID=ID OUT_DIR=/new/absolute/path TMPDIR=/disk/path \
  EXPECTED_SOURCE_COMMIT=HEX scripts/profile-forensics.sh \
    --mode built-in --binary /absolute/readonly/rust-reality \
    --binary-sha256 HEX [OPTIONS]

  RUN_ID=ID OUT_DIR=/new/absolute/path TMPDIR=/disk/path \
  EXPECTED_SOURCE_COMMIT=HEX scripts/profile-forensics.sh \
    --mode attach-server --binary /absolute/readonly/rust-reality \
    --binary-sha256 HEX --pid PID [OPTIONS]

OUT_DIR itself is the immutable run directory and must not already exist.
The binary must emit matching environment.gitCommit in benchmark JSON.

Options:
  --mode built-in|attach-server
  --binary PATH
  --binary-sha256 HEX             Required for a formal run
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
[[ $record_seconds =~ ^[1-9][0-9]*$ ]] || die '--record-seconds must be positive'
[[ $duration_ms =~ ^[1-9][0-9]*$ ]] || die '--duration-ms must be positive'
[[ $warmup_ms =~ ^[0-9]+$ ]] || die '--warmup-ms must be non-negative'
[[ $frequency =~ ^[1-9][0-9]*$ ]] || die '--frequency must be positive'
[[ $call_graph =~ ^(fp|lbr|dwarf(,[1-9][0-9]*)?)$ ]] ||
    die '--call-graph must be fp, lbr, or dwarf[,BYTES]'
((record_seconds <= MAX_RECORD_SECONDS)) || die '--record-seconds exceeds 300'
((duration_ms <= MAX_DURATION_MS)) || die '--duration-ms exceeds 600000'
((warmup_ms <= MAX_WARMUP_MS)) || die '--warmup-ms exceeds 600000'
((frequency <= MAX_FREQUENCY)) || die '--frequency exceeds 9999'
if [[ $call_graph == dwarf,* ]]; then
    dwarf_bytes=${call_graph#dwarf,}
    ((dwarf_bytes <= MAX_DWARF_BYTES)) || die 'DWARF stack bytes exceed 65528'
fi
if [[ $mode == attach-server ]]; then
    [[ $server_pid =~ ^[1-9][0-9]*$ ]] || die '--pid is required for attach-server'
fi

for program in perf python3 readelf sha256sum sudo; do
    command -v "$program" >/dev/null 2>&1 || die "required tool unavailable: $program"
done
sudo -n true >/dev/null 2>&1 || die 'passwordless sudo is required for perf'

rr_contract_init "$REPOSITORY" profile-forensics artifacts/perf-profile 1
rr_register_binary rust-reality "$binary" "$expected_binary_sha256" rust \
    "$expected_source_commit"
binary=${RR_BINARY_PATHS[rust-reality]}
binary_sha256=${RR_BINARY_SHA256[rust-reality]}
binary_build_id=${RR_BINARY_BUILD_IDS[rust-reality]}
binary_source_commit=${RR_BINARY_SOURCE_COMMITS[rust-reality]}
run_dir=$RR_OUT_DIR
rr_write_contract_metadata

mkdir -m 700 -- "$run_dir/binary"
archived_binary="$run_dir/binary/$(basename -- "$binary")"
cp --reflink=auto -- "$binary" "$archived_binary"
chmod a-w -- "$archived_binary"
[[ $(sha256sum -- "$archived_binary" | awk '{print $1}') == "$binary_sha256" ]] ||
    die 'archived binary identity changed during copy'
[[ $(readelf -n -- "$archived_binary" | awk '/Build ID:/ {print $3; exit}') == \
    "$binary_build_id" ]] || die 'archived binary build ID changed during copy'

perf_data="$run_dir/perf.data"
benchmark_json="$run_dir/benchmark.json"
benchmark_stderr="$run_dir/benchmark.stderr"
report="$run_dir/perf-report.txt"
buildids="$run_dir/perf-buildids.txt"
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
perf_rc=null
workload_rc=null
completed=0
owned_pid=
owned_starttime=
profile_pid=
profile_starttime=
profile_exe_sha256_pre=
profile_exe_sha256_post=
profile_exe_build_id_pre=
profile_exe_build_id_post=

pid_starttime() {
    rr_pid_starttime "$1"
}

pid_is_owned() {
    local observed
    [[ -n $owned_pid && -n $owned_starttime && -r /proc/$owned_pid/stat ]] || return 1
    observed=$(pid_starttime "$owned_pid" 2>/dev/null) || return 1
    [[ $observed == "$owned_starttime" ]]
}

profile_process_identity() {
    local pid=$1 phase=$2 current_start exe_sha exe_build_id
    current_start=$(pid_starttime "$pid") || die "PID $pid exited during $phase identity check"
    [[ $current_start == "$profile_starttime" ]] ||
        die "PID $pid starttime changed during $phase identity check"
    exe_sha=$(sha256sum -- "/proc/$pid/exe" | awk '{print $1}')
    exe_build_id=$(readelf -n -- "/proc/$pid/exe" |
        awk '/Build ID:/ {print $3; exit}')
    [[ $exe_sha == "$binary_sha256" ]] ||
        die "PID $pid executable SHA-256 mismatch during $phase"
    [[ $exe_build_id == "$binary_build_id" ]] ||
        die "PID $pid executable build ID mismatch during $phase"
    if [[ $phase == pre ]]; then
        profile_exe_sha256_pre=$exe_sha
        profile_exe_build_id_pre=$exe_build_id
    else
        profile_exe_sha256_post=$exe_sha
        profile_exe_build_id_post=$exe_build_id
    fi
}

write_metadata() {
    local state=$1 exit_code=${2:-null}
    python3 - "$run_dir/metadata.json" "$state" "$exit_code" "$mode" \
        "$RR_RUN_ID" "$started_at" "$binary" "$archived_binary" \
        "$binary_sha256" "$binary_build_id" "$binary_source_commit" \
        "$event" "$frequency" "$call_graph" "$record_seconds" \
        "$duration_ms" "$warmup_ms" "$perf_rc" "$workload_rc" \
        "${profile_pid:-}" "${profile_starttime:-}" \
        "${profile_exe_sha256_pre:-}" "${profile_exe_sha256_post:-}" \
        "${profile_exe_build_id_pre:-}" "${profile_exe_build_id_post:-}" <<'PY'
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone

(
    output, state, exit_code, mode, run_id, started_at, source_binary,
    archived_binary, sha256, build_id, source_commit, event, frequency,
    call_graph, record_seconds, duration_ms, warmup_ms, perf_rc, workload_rc,
    pid, starttime, exe_sha_pre, exe_sha_post, exe_build_pre, exe_build_post,
) = sys.argv[1:]

def nullable_int(value):
    return None if value in ("", "null") else int(value)

record = {
    "schemaVersion": 2,
    "state": state,
    "exitCode": nullable_int(exit_code),
    "runId": run_id,
    "mode": mode,
    "startedAt": started_at,
    "updatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "sourceBinary": source_binary,
    "archivedBinary": archived_binary,
    "binarySha256": sha256,
    "binaryBuildId": build_id,
    "binarySourceCommit": source_commit,
    "profileProcess": ({
        "pid": nullable_int(pid),
        "starttime": nullable_int(starttime),
        "exeSha256Pre": exe_sha_pre or None,
        "exeSha256Post": exe_sha_post or None,
        "exeBuildIdPre": exe_build_pre or None,
        "exeBuildIdPost": exe_build_post or None,
    } if pid else None),
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

cleanup_owned() {
    if pid_is_owned; then
        kill -TERM "$owned_pid" 2>/dev/null || true
        for _ in {1..50}; do
            pid_is_owned || break
            sleep 0.02
        done
        pid_is_owned && kill -KILL "$owned_pid" 2>/dev/null || true
    fi
    [[ -n $owned_pid ]] && wait "$owned_pid" 2>/dev/null || true
}

finish() {
    local original_rc=$? final_rc
    trap - EXIT INT TERM
    set +e
    cleanup_owned
    rr_contract_verify_on_exit "$original_rc"
    final_rc=$?
    # An incomplete fall-through is never success. More importantly, the
    # second immutable-input verification can fail after metadata was marked
    # COMPLETE; rewrite it with the actual final status in that case.
    if (( completed == 0 && final_rc == 0 )); then
        final_rc=1
    fi
    if (( completed == 0 || final_rc != 0 )); then
        write_metadata FAILED "$final_rc" || true
    fi
    exit "$final_rc"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

write_metadata RUNNING null

if [[ $mode == built-in ]]; then
    "$binary" benchmark --duration-ms "$duration_ms" --warmup-ms "$warmup_ms" \
        >"$benchmark_json" 2>"$benchmark_stderr" &
    profile_pid=$!
    owned_pid=$profile_pid
    owned_starttime=$(pid_starttime "$owned_pid") ||
        die 'cannot identify built-in benchmark PID'
    profile_starttime=$owned_starttime
    profile_process_identity "$profile_pid" pre
    sleep 0.5
    pid_is_owned || {
        wait "$profile_pid" || true
        die "built-in benchmark exited before perf attached; see $benchmark_stderr"
    }
else
    profile_pid=$server_pid
    profile_starttime=$(pid_starttime "$profile_pid") ||
        die "server PID is not alive: $profile_pid"
    profile_process_identity "$profile_pid" pre
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
    owned_pid=
    owned_starttime=
else
    profile_process_identity "$profile_pid" post
fi

[[ -f $perf_data ]] && sudo -n chown "$(id -u):$(id -g)" "$perf_data"
[[ $perf_rc -eq 0 ]] || die "perf record failed with exit code $perf_rc"
[[ $workload_rc -eq 0 ]] || die "workload failed with exit code $workload_rc"
[[ -s $perf_data ]] || die 'perf produced no data'

if [[ $mode == built-in ]]; then
    python3 -m json.tool "$benchmark_json" >/dev/null
    measured_commit=$(jq -er '.environment.gitCommit |
        select(type == "string" and test("^[0-9a-f]{40}$"))' "$benchmark_json")
    [[ $measured_commit == "$binary_source_commit" ]] ||
        die "built-in benchmark source identity changed: $measured_commit"
fi

perf buildid-list -i "$perf_data" >"$buildids"
grep -Fqi -- "$binary_build_id" "$buildids" ||
    die "perf data does not contain archived binary build ID $binary_build_id"
perf report --stdio --no-children --sort comm,dso,symbol -i "$perf_data" \
    >"$report" 2>&1

[[ $(sha256sum -- "$binary" | awk '{print $1}') == "$binary_sha256" ]] ||
    die 'source binary changed after profiling'
[[ $(readelf -n -- "$binary" | awk '/Build ID:/ {print $3; exit}') == \
    "$binary_build_id" ]] || die 'source binary build ID changed after profiling'

sha256sum -- "$archived_binary" "$perf_data" "$report" "$buildids" \
    >"$run_dir/SHA256SUMS"
rr_finalize_contract
write_metadata COMPLETE 0
completed=1
printf 'forensic profile complete: %s\n' "$run_dir"
