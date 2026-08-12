#!/usr/bin/env bash
# validate-profiles.sh — machine-profile validation harness for rust-reality.
#
# Simulates machine classes with cgroup v2 scopes (systemd-run --scope with
# CPUQuota + MemoryMax) and measures the server's real capacity per class:
# startup budget derivation, idle/assets RSS, setup churn, sustained 512 MiB
# throughput, and an idle-connection ladder looking for pressure events or
# cgroup OOM kills. The server never runs as root: the scope is created with
# sudo and the payload process is dropped back to the invoking user with
# setpriv. Scopes are torn down on every exit path (trap EXIT).
#
# Output (untracked evidence, do not commit):
#   benchmarks/profile-validation/<class>/cells.jsonl   one record per cell
#   benchmarks/profile-validation/<class>/server-*.log  structured server logs
#   benchmarks/profile-validation/<class>/samples-*.tsv 1 Hz RSS/FD/cgroup series
#   benchmarks/profile-validation/<class>/summary.json + summary.md
#   benchmarks/profile-validation/environment.json
#
# Env: CLASSES, ONLY, LADDER_LEVELS_<CLASS> / LADDER_LEVELS, CONNS (96),
#      SAMPLES_CHURN (3), SAMPLES_DOWNLOAD (2), HOLD (8), SETTLE (3),
#      STANDARD_COMPARISON (1 adds a 1c1g run with resourceMode=standard),
#      RUST_REALITY_BIN (default: this repository's target/release/rust-reality;
#      the script never builds it — run `cargo build --release` yourself first,
#      ideally via scripts/build-release.sh so the binary embeds the git commit),
#      XRAY_BIN (REQUIRED, no default: path to an xray-core client binary),
#      OUT_ROOT (default: a unique UTC/PID run directory; an existing path or
#      symlink is always rejected), ASSET_CACHE_DIR (default: the repository's
#      reusable benchmarks/profile-validation/.asset-cache), KEEP_WORK (0),
#      FORCE (0), IDENTITY_STRICT (1: a positively
#      detected binary/HEAD commit mismatch aborts the run; 0 only warns).
# The one-time geo-asset fetch needs outbound network access; if your
# environment requires a proxy, export the standard *_PROXY variables for
# curl before running, or pre-populate the asset cache by hand (see below).
set -Eeuo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository"

rust_bin=${RUST_REALITY_BIN:-$repository/target/release/rust-reality}
xray=${XRAY_BIN:-}
out_root_input=${OUT_ROOT:-benchmarks/profile-validation/$(date -u +%Y%m%dT%H%M%SZ)-$$}
asset_cache_input=${ASSET_CACHE_DIR:-benchmarks/profile-validation/.asset-cache}
classes=${CLASSES:-"1c1g:100:1G 1c2g:100:2G 2c2g:200:2G 2c4g:200:4G 4c4g:400:4G 4c8g:400:8G"}
only=${ONLY:-}
standard_comparison=${STANDARD_COMPARISON:-1}
comparison_name=${COMPARISON_NAME:-1c1g-standard}
conns=${CONNS:-96}
samples_churn=${SAMPLES_CHURN:-3}
samples_download=${SAMPLES_DOWNLOAD:-2}
hold=${HOLD:-8}
settle=${SETTLE:-3}
uid=$(id -u)
gid=$(id -g)

work=$(mktemp -d "$repository/benchmarks/profile-validation.XXXXXX")
runner_pids=()
client_pids=()
sampler_pids=()
active_units=()
class_summaries=()
class_summary_statuses=()
declare -A pid_start_times=()
declare -A unit_cgroups=()
declare -A unit_runner_pids=()
declare -A planned_class_names=()
pid_snapshot_start=""
pid_snapshot_state=""

CLEANENV=(env -u ALL_PROXY -u all_proxy -u HTTP_PROXY -u http_proxy
          -u HTTPS_PROXY -u https_proxy -u NO_PROXY -u no_proxy -u CARGO_HTTP_PROXY)

pid_snapshot() {
    local stat rest
    local -a fields
    IFS= read -r stat < "/proc/$1/stat" || return 1
    # comm is parenthesized and may itself contain spaces or ')' characters.
    # Remove through the final ") "; the remainder starts at state (field 3).
    rest=${stat##*) }
    read -r -a fields <<< "$rest"
    (( ${#fields[@]} > 19 )) || return 1
    pid_snapshot_start=${fields[19]}
    pid_snapshot_state=${fields[0]}
}

register_pid() {
    local pid=$1 start
    pid_snapshot "$pid" || {
        echo "background process $pid exited before it could be registered" >&2
        return 1
    }
    start=$pid_snapshot_start
    pid_start_times[$pid]=$start
}

pid_is_registered() {
    local pid=$1 expected=${pid_start_times[$1]:-} actual state
    [[ -n $expected ]] || return 1
    pid_snapshot "$pid" || return 1
    actual=$pid_snapshot_start
    state=$pid_snapshot_state
    [[ $actual == "$expected" && $state != Z ]]
}

signal_registered_pid() {
    local signal=$1 pid=$2 expected=${pid_start_times[$2]:-} actual state
    [[ -n $expected ]] || return 0
    pid_snapshot "$pid" || return 0
    actual=$pid_snapshot_start
    state=$pid_snapshot_state
    if [[ $actual != "$expected" ]]; then
        echo "refusing to signal PID $pid: /proc starttime no longer matches" >&2
        return 0
    fi
    [[ $state == Z ]] || kill "-$signal" "$pid" 2>/dev/null || true
}

forget_pid() {
    unset 'pid_start_times[$1]'
}

unit_is_registered() {
    local unit=$1 expected=${unit_cgroups[$1]:-} runner actual actual_id
    runner=${unit_runner_pids[$unit]:-}
    [[ -n $expected && -n $runner ]] || return 1
    pid_is_registered "$runner" || return 1
    actual_id=$(systemctl show -p Id --value "$unit" 2>/dev/null) || return 1
    actual=$(systemctl show -p ControlGroup --value "$unit" 2>/dev/null) || return 1
    [[ $actual_id == "$unit" && -n $actual && $actual == "$expected" \
        && -d /sys/fs/cgroup$actual ]]
}

stop_registered_unit() {
    local unit=$1
    if unit_is_registered "$unit"; then
        if ! sudo -n systemctl stop "$unit" >/dev/null 2>&1; then
            echo "failed to stop registered unit $unit" >&2
            return 1
        fi
    elif [[ -n ${unit_cgroups[$unit]:-} ]]; then
        echo "refusing to stop unit $unit: registered cgroup no longer matches" >&2
        return 1
    fi
}

terminate_registered_pid() {
    local pid=$1
    signal_registered_pid TERM "$pid"
    for _ in $(seq 1 50); do
        pid_is_registered "$pid" || break
        sleep 0.1
    done
    signal_registered_pid KILL "$pid"
    wait "$pid" 2>/dev/null || true
    forget_pid "$pid"
}

cleanup() {
    set +e
    local pid unit live scoped_server=${server_pid:-}
    for pid in "${sampler_pids[@]:-}" "${client_pids[@]:-}"; do
        [[ -n $pid ]] && signal_registered_pid TERM "$pid"
    done
    # Stop scopes while the exact registered cgroup still exists; only then
    # terminate the systemd-run client processes that created them.
    for unit in "${active_units[@]:-}"; do
        [[ -n $unit ]] && stop_registered_unit "$unit"
    done
    [[ -n $scoped_server ]] && signal_registered_pid TERM "$scoped_server"
    for pid in "${runner_pids[@]:-}"; do
        [[ -n $pid ]] && signal_registered_pid TERM "$pid"
    done
    # Give every registered child the same bounded grace period.  Identity is
    # rechecked on every poll so PID reuse can never redirect a later signal.
    for _ in $(seq 1 50); do
        live=0
        for pid in "${sampler_pids[@]:-}" "${client_pids[@]:-}" "${runner_pids[@]:-}"; do
            [[ -n $pid ]] && pid_is_registered "$pid" && live=1
        done
        [[ -n $scoped_server ]] && pid_is_registered "$scoped_server" && live=1
        (( live == 0 )) && break
        sleep 0.1
    done
    for pid in "${sampler_pids[@]:-}" "${client_pids[@]:-}" "${runner_pids[@]:-}"; do
        [[ -n $pid ]] && signal_registered_pid KILL "$pid"
    done
    [[ -n $scoped_server ]] && signal_registered_pid KILL "$scoped_server"
    for pid in "${sampler_pids[@]:-}" "${client_pids[@]:-}" "${runner_pids[@]:-}"; do
        [[ -n $pid ]] || continue
        wait "$pid" 2>/dev/null || true
        forget_pid "$pid"
    done
    [[ -n $scoped_server ]] && forget_pid "$scoped_server"
    if [[ ${KEEP_WORK:-0} == 1 ]]; then
        printf 'work directory retained: %s\n' "$work" >&2
    elif [[ -d $work && $work == "$repository"/benchmarks/profile-validation.* ]]; then
        rm -rf -- "$work"
    fi
}
trap cleanup EXIT

for program in curl jq python3 go setpriv systemctl; do
    command -v "$program" >/dev/null || { echo "missing: $program" >&2; exit 1; }
done
sudo -n true || { echo "passwordless sudo required for systemd-run scopes" >&2; exit 1; }
[[ -x $rust_bin ]] || {
    echo "server binary missing or not executable: $rust_bin" >&2
    echo "build it first with \`cargo build --release\` (scripts/build-release.sh also" >&2
    echo "embeds the git commit for the identity check), or set RUST_REALITY_BIN." >&2
    exit 1
}
[[ -n $xray ]] || {
    echo "XRAY_BIN is required (no default): path to an xray-core client binary," >&2
    echo "e.g. from https://github.com/XTLS/Xray-core/releases." >&2
    exit 1
}
[[ -x $xray ]] || { echo "xray client binary missing or not executable: $xray" >&2; exit 1; }

absolute_from_repository() {
    python3 - "$repository" "$1" <<'PY'
import os
import sys

root, value = sys.argv[1:]
if not os.path.isabs(value):
    value = os.path.join(root, value)
print(os.path.abspath(value))
PY
}

register_planned_class() {
    local class=$1
    if [[ ! $class =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ || $class == . || $class == .. ]]; then
        echo "class output name is not a safe basename: $class" >&2
        return 1
    fi
    if [[ -n ${planned_class_names[$class]:-} ]]; then
        echo "duplicate class output name: $class" >&2
        return 1
    fi
    planned_class_names[$class]=1
}

for spec in $classes; do
    class=${spec%%:*}
    rest=${spec#*:}
    cpu=${rest%%:*}
    mem=${rest#*:}
    if [[ $rest == "$spec" || $mem == "$rest" || -z $cpu || -z $mem ]]; then
        echo "invalid class specification (expected name:cpu:memory): $spec" >&2
        exit 1
    fi
    if [[ -z $only || $class == "$only" ]]; then
        register_planned_class "$class"
    fi
    if [[ $standard_comparison == 1 && $class == 1c1g \
        && ( -z $only || $comparison_name == "$only" ) ]]; then
        register_planned_class "$comparison_name"
    fi
done

out_root=$(absolute_from_repository "$out_root_input")
asset_cache=$(absolute_from_repository "$asset_cache_input")
if [[ -e $out_root || -L $out_root ]]; then
    echo "OUT_ROOT must be unique and must not already exist: $out_root" >&2
    exit 1
fi
case "$asset_cache/" in
    "$out_root/"*)
        echo "ASSET_CACHE_DIR must be outside OUT_ROOT so cached assets cannot be overwritten" >&2
        exit 1
        ;;
esac
stray=$(pgrep -af 'release/rust-reality serve|xray.* run|bench-origin --port' || true)
if [[ -n $stray && ${FORCE:-0} != 1 ]]; then
    echo "stray benchmark processes found (refusing to run in a polluted window):" >&2
    echo "$stray" >&2
    exit 1
fi

mkdir -p -- "$(dirname "$out_root")"
mkdir -- "$out_root"
mkdir -p -- "$asset_cache"

# --- one-time asset cache population (proxy env used only here) -------------
# The geo assets are fetched once and then reused from the cache on every run.
# The fetch needs outbound network access; curl honors the standard *_PROXY
# environment variables, so export them before running if your network
# requires a proxy. To avoid any fetch, place geoip.dat and geosite.dat into
# $asset_cache yourself beforehand.
if [[ ! -s $asset_cache/geoip.dat || ! -s $asset_cache/geosite.dat ]]; then
    echo "populating asset cache in $asset_cache (one-time fetch; needs network," >&2
    echo "honors your *_PROXY environment if one is required)" >&2
    curl -fLsS --retry 3 -o "$asset_cache/geoip.dat" \
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"
    curl -fLsS --retry 3 -o "$asset_cache/geosite.dat" \
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"
fi

# --- environment metadata ----------------------------------------------------
commit=$(git rev-parse HEAD)
binary_sha256=$(sha256sum "$rust_bin" | awk '{print $1}')

# Binary identity: binaries built via scripts/build-release.sh embed the git
# commit (RUST_REALITY_GIT_COMMIT, surfaced as git_commit in the benchmark
# report). Confirm the measured binary matches the recorded HEAD so the
# evidence cannot silently mix a stale binary with a newer tree.
embedded_commit=""
if grep -qF -- "$commit" "$rust_bin" 2>/dev/null; then
    embedded_commit=$commit
fi
# No fallback extraction: a binary built with plain `cargo build --release`
# does not embed the commit (only scripts/build-release.sh sets
# RUST_REALITY_GIT_COMMIT), and harvesting any standalone 40-hex string can
# match unrelated rodata constants, which would false-fail a correct binary.
# Note: after docs-only commits the embedded commit lags HEAD by design;
# rebuild (or set IDENTITY_STRICT=0) in that case.
identity_note=""
if [[ -z $embedded_commit ]]; then
    identity_note="no git commit embedded in the binary; identity not verified (build with scripts/build-release.sh to embed RUST_REALITY_GIT_COMMIT)"
    echo "warning: $identity_note" >&2
elif [[ $embedded_commit != "$commit" ]]; then
    identity_note="embedded commit $embedded_commit does not match recorded HEAD $commit"
    echo "warning: binary/HEAD identity mismatch: $identity_note" >&2
    if [[ ${IDENTITY_STRICT:-1} == 1 ]]; then
        echo "refusing to measure a stale binary; rebuild from this tree, or set IDENTITY_STRICT=0 to only warn" >&2
        exit 1
    fi
fi
jq -n \
    --arg commit "$commit" \
    --arg binary "$rust_bin" \
    --arg binary_sha256 "$binary_sha256" \
    --arg binary_embedded_commit "$embedded_commit" \
    --arg identity_note "$identity_note" \
    --arg output_root "$out_root" \
    --arg asset_cache_dir "$asset_cache" \
    --arg xray "$("$xray" version 2>/dev/null | head -1)" \
    --arg kernel "$(uname -r)" \
    --arg host "$(nproc) CPUs, $(awk '/MemTotal/{print int($2/1024)" MiB"}' /proc/meminfo)" \
    --arg date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{commit: $commit, binary: $binary, binarySha256: $binary_sha256,
      binaryEmbeddedCommit: $binary_embedded_commit, identityNote: $identity_note,
      outputRoot: $output_root, assetCacheDirectory: $asset_cache_dir,
      xray: $xray, kernel: $kernel, host: $host, dateUtc: $date,
      note: "server CPU via /proc/pid/stat utime+stime (perf stat unusable on this host)"}' \
    > "$out_root/environment.json"

free_port() {
    python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_port() {
    python3 - "$1" "$2" <<'PY'
import socket, sys, time
port, deadline_s = int(sys.argv[1]), float(sys.argv[2])
deadline = time.monotonic() + deadline_s
while time.monotonic() < deadline:
    with socket.socket() as sock:
        sock.settimeout(0.2)
        if sock.connect_ex(("127.0.0.1", port)) == 0:
            raise SystemExit(0)
    time.sleep(0.05)
raise SystemExit(f"port {port} did not become ready within {deadline_s}s")
PY
}

# --- origin + payloads -------------------------------------------------------
python3 -c "open('$work/payload.bin','wb').write(bytes(range(256)))"
python3 - "$work/payload-512.bin" <<'PY'
from pathlib import Path
import sys
remaining = 512 * 1024 * 1024
chunk = bytes(range(256)) * 4096
with Path(sys.argv[1]).open("wb") as out:
    while remaining:
        part = chunk[:min(len(chunk), remaining)]
        out.write(part)
        remaining -= len(part)
PY
(cd scripts/bench-origin && "${CLEANENV[@]}" go build -buildvcs=false -o "$work/bench-origin" .)
http_port=$(free_port)
https_port=$(free_port)
"${CLEANENV[@]}" "$work/bench-origin" --port "$http_port" --payload-dir "$work" \
    --put-log "$work/put.jsonl" >"$work/origin.log" 2>&1 &
origin_pid=$!
client_pids+=("$origin_pid")
register_pid "$origin_pid"
# TLS 1.3 origin acts as the REALITY cover target: the server mirrors the
# cover's certificate chain, so the cover must speak TLS (a plain-HTTP cover
# makes every authenticated handshake fall back and fail).
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/origin.key" \
    -out "$work/origin.crt" -days 1 -subj "/CN=localhost" >/dev/null 2>&1
"${CLEANENV[@]}" "$work/bench-origin" --port "$https_port" --payload-dir "$work" \
    --put-log "$work/https-put.jsonl" --tls-cert "$work/origin.crt" --tls-key "$work/origin.key" \
    >"$work/https-origin.log" 2>&1 &
tls_origin_pid=$!
client_pids+=("$tls_origin_pid")
register_pid "$tls_origin_pid"
wait_port "$http_port" 10
wait_port "$https_port" 10
origin_url="http://127.0.0.1:$http_port/payload-512.bin"

# --- helpers -----------------------------------------------------------------

# make_configs <server_port> <mode> <prefix>
# Writes <prefix>-nogeo.json and <prefix>-geo.json plus <prefix>.client.env.
make_configs() {
    local port=$1 mode=$2 prefix=$3
    "${CLEANENV[@]}" "$rust_bin" config generate standalone \
        --listen 127.0.0.1 --port "$port" \
        --target "127.0.0.1:$https_port" --server-name localhost \
        > "$prefix.raw.json" 2> "$prefix.generate.log"
    jq --arg cache "$asset_cache" --arg mode "$mode" '
        .log.level = "info"
        | .assets.cacheDirectory = $cache
        | .assets.requestTimeoutSeconds = 5
        | .runtime.resourceMode = $mode
    ' "$prefix.raw.json" > "$prefix-nogeo.json"
    jq '.routing.globalRules = [{
            name: "geo-direct", outbound: "direct",
            domain: ["geosite:cn"], ip: ["geoip:cn", "geoip:private"]
        }]' "$prefix-nogeo.json" > "$prefix-geo.json"
    # Tuned variant for the capacity ladder: lift the default admission
    # ceilings (128 crypto ops / 1024 handshakes / 2048 session-lifetime
    # direct-barrier permits / 16384 connections) so the ladder reaches the
    # memory- or fd-limited breaking point instead of the policy defaults.
    jq '.policy.resourceGovernor.maxConnections = 65536
        | .policy.resourceGovernor.maxHandshakes = 8192
        | .policy.resourceGovernor.maxCryptoOperations = 4096
        | .policy.directBarrier.maxConcurrent = 65536
        | .policy.directBarrier.maxPerSecond = 65536' \
        "$prefix-geo.json" > "$prefix-tuned.json"
    {
        sed -n 's/^REALITY public key for the client: /PUBLIC_KEY=/p' "$prefix.generate.log"
        jq -r '"UUID=" + .inbounds[0].settings.clients[0].id' "$prefix.raw.json"
        jq -r '"SHORT_ID=" + .inbounds[0].settings.clients[0].shortIds[0]' "$prefix.raw.json"
    } > "$prefix.client.env"
}

# make_xray_client <server_port> <socks_port> <env_file> <output>
make_xray_client() {
    local server_port=$1 socks_port=$2 env_file=$3 output=$4
    local PUBLIC_KEY UUID SHORT_ID
    # shellcheck disable=SC1090
    source "$env_file"
    jq -n --arg uuid "$UUID" --arg pk "$PUBLIC_KEY" --arg sid "$SHORT_ID" \
        --argjson sp "$server_port" --argjson cp "$socks_port" \
        '{log:{loglevel:"warning"},inbounds:[{listen:"127.0.0.1",port:$cp,protocol:"socks",settings:{auth:"noauth",udp:false}}],outbounds:[{protocol:"vless",settings:{vnext:[{address:"127.0.0.1",port:$sp,users:[{id:$uuid,encryption:"none",flow:"xtls-rprx-vision"}]}]},streamSettings:{network:"tcp",security:"reality",realitySettings:{fingerprint:"chrome",serverName:"localhost",publicKey:$pk,shortId:$sid,spiderX:"/"}}}]}' \
        > "$output"
}

server_pid=""
cgroup_dir=""

# start_scoped_server <class> <run> <cpuquota_percent> <memmax> <config> <logfile>
start_scoped_server() {
    local class=$1 run=$2 cpu=$3 mem=$4 config=$5 logfile=$6
    local unit="rrprof-${class}-${run}-$$.scope"
    local runner_pid load_state
    load_state=$(systemctl show -p LoadState --value "$unit" 2>/dev/null || true)
    if [[ -n $load_state && $load_state != not-found ]]; then
        echo "refusing to reuse pre-existing scope name $unit (LoadState=$load_state)" >&2
        return 1
    fi
    sudo -n systemd-run --scope --collect -q --unit="$unit" \
        -p "CPUQuota=${cpu}%" -p "MemoryMax=${mem}" \
        -- setpriv --reuid="$uid" --regid="$gid" --clear-groups \
           env -i PATH=/usr/local/bin:/usr/bin:/bin \
           "$rust_bin" serve --config "$config" >"$logfile" 2>&1 &
    runner_pid=$!
    runner_pids+=("$runner_pid")
    register_pid "$runner_pid"
    server_pid=""
    cgroup_dir=""
    local deadline=$((SECONDS + 15)) cg p
    while (( SECONDS < deadline )); do
        cg=$(systemctl show -p ControlGroup --value "$unit" 2>/dev/null) || continue
        [[ -n $cg && -d /sys/fs/cgroup$cg ]] || { sleep 0.1; continue; }
        if [[ -z ${unit_cgroups[$unit]:-} ]]; then
            unit_cgroups[$unit]=$cg
            unit_runner_pids[$unit]=$runner_pid
            if ! unit_is_registered "$unit"; then
                unset 'unit_cgroups[$unit]' 'unit_runner_pids[$unit]'
                echo "scope $unit failed exact unit/cgroup/runner registration" >&2
                return 1
            fi
            active_units+=("$unit")
        elif [[ ${unit_cgroups[$unit]} != "$cg" ]]; then
            echo "scope $unit changed cgroup while starting" >&2
            return 1
        fi
        for p in $(cat "/sys/fs/cgroup$cg/cgroup.procs" 2>/dev/null); do
            if [[ $(cat "/proc/$p/comm" 2>/dev/null) == rust-reality ]]; then
                server_pid=$p
                cgroup_dir="/sys/fs/cgroup$cg"
                break
            fi
        done
        [[ -n $server_pid ]] && break
        sleep 0.1
    done
    [[ -n $server_pid ]] || { echo "server did not appear in scope $unit" >&2; return 1; }
    register_pid "$server_pid"
}

# stop_scoped_server
stop_scoped_server() {
    local unit=${active_units[-1]} runner_pid
    runner_pid=${unit_runner_pids[$unit]:-}
    [[ -n $runner_pid ]] || {
        echo "scope $unit has no registered systemd-run PID" >&2
        return 1
    }
    if [[ ${runner_pids[-1]:-} != "$runner_pid" ]]; then
        echo "runner PID stack mismatch while stopping $unit" >&2
        return 1
    fi
    local stopped_server=$server_pid
    # The exact unit name is accepted only while its ControlGroup still equals
    # the value observed at creation.  A recycled name can therefore never be
    # stopped by this harness.
    stop_registered_unit "$unit" || return 1
    signal_registered_pid TERM "$stopped_server"
    for _ in $(seq 1 50); do
        pid_is_registered "$stopped_server" || break
        sleep 0.1
    done
    signal_registered_pid KILL "$stopped_server"
    forget_pid "$stopped_server"
    terminate_registered_pid "$runner_pid"
    runner_pids=("${runner_pids[@]:0:${#runner_pids[@]}-1}")
    unset 'unit_cgroups[$unit]' 'unit_runner_pids[$unit]'
    active_units=("${active_units[@]:0:${#active_units[@]}-1}")
    server_pid=""
    cgroup_dir=""
}

# start_sampler <tag> <outfile>
start_sampler() {
    local tag=$1 outfile=$2 pid=$server_pid cg=$cgroup_dir
    (
        while pid_is_registered "$pid"; do
            rss=$(awk '/VmRSS:/{print $2*1024}' "/proc/$pid/status" 2>/dev/null || echo 0)
            fds=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)
            cur=$(cat "$cg/memory.current" 2>/dev/null || echo 0)
            printf '%s\t%s\t%s\t%s\n' "$(date +%s)" "${rss:-0}" "${fds:-0}" "${cur:-0}"
            sleep 1
        done
    ) > "$outfile" &
    local sampler_pid=$!
    sampler_pids+=("$sampler_pid")
    register_pid "$sampler_pid"
}

stop_sampler() {
    local pid=${sampler_pids[-1]}
    terminate_registered_pid "$pid"
    sampler_pids=("${sampler_pids[@]:0:${#sampler_pids[@]}-1}")
}

stop_last_client() {
    local pid=${client_pids[-1]}
    terminate_registered_pid "$pid"
    client_pids=("${client_pids[@]:0:${#client_pids[@]}-1}")
}

# emit_cell <classdir> <json>  — appends one record to cells.jsonl
emit_cell() {
    printf '%s\n' "$2" >> "$1/cells.jsonl"
}

# sample_now — prints a JSON object with the live process/cgroup numbers
sample_now() {
    local rss fds cur peak oom
    rss=$(awk '/VmRSS:/{print $2*1024}' "/proc/$server_pid/status" 2>/dev/null || echo null)
    fds=$(ls "/proc/$server_pid/fd" 2>/dev/null | wc -l)
    cur=$(cat "$cgroup_dir/memory.current" 2>/dev/null || echo null)
    peak=$(cat "$cgroup_dir/memory.peak" 2>/dev/null || echo null)
    oom=$(awk '/^oom_kill /{print $2}' "$cgroup_dir/memory.events" 2>/dev/null || echo null)
    jq -n --argjson rss "${rss:-null}" --argjson fds "${fds:-0}" \
        --argjson cur "${cur:-null}" --argjson peak "${peak:-null}" --argjson oom "${oom:-null}" \
        '{serverRssBytes: $rss, serverFdCount: $fds, cgroupMemoryCurrent: $cur,
          cgroupMemoryPeak: $peak, cgroupOomKills: $oom}'
}

# startup_cell <logfile> — extracts the one-shot startup reports from the log
startup_cell() {
    jq -sc '
        def pick($e): map(select(.event == $e)) | last;
        {
          machineReport: pick("machine_report"),
          descriptorBudgetReport: pick("descriptor_budget_report"),
          relayBackendReport: pick("relay_backend_report"),
          configurationPublished: (pick("configuration_published") != null)
        }' "$1"
}

# run_driver <classdir> <logfile> <subcommand> <args...> -> cells.jsonl
run_driver() {
    local classdir=$1 logfile=$2 sub=$3
    shift 3
    "${CLEANENV[@]}" python3 scripts/profile-driver.py "$sub" \
        --server-pid "$server_pid" --server-log "$logfile" --cgroup "$cgroup_dir" \
        "$@" >> "$classdir/cells.jsonl"
}

# --- per-class flow ----------------------------------------------------------

run_class() {
    local class=$1 cpu=$2 mem=$3 mode=$4
    local classdir="$out_root/$class"
    mkdir -p "$classdir"
    if [[ ${SKIP_A:-0} != 1 || ${SKIP_B:-0} != 1 ]]; then
        : > "$classdir/cells.jsonl"
    fi
    local ladder_levels
    local varname="LADDER_LEVELS_${class//-/_}"
    ladder_levels=${!varname:-${LADDER_LEVELS:-}}
    if [[ -z $ladder_levels ]]; then
        case $class in
            # Extend past the default maxConnections=16384 on the largest
            # class to demonstrate the admission governor engaging.
            4c8g) ladder_levels="100,500,1000,2000,4000,8000,16000,20000" ;;
            *)    ladder_levels="100,500,1000,2000,4000,8000" ;;
        esac
    fi
    echo "== class $class (CPUQuota=${cpu}% MemoryMax=$mem mode=$mode, ladder $ladder_levels)" >&2

    # ----- run A: no-geo config, startup + idle only -----
    if [[ ${SKIP_A:-0} != 1 ]]; then
    local port_a
    port_a=$(free_port)
    make_configs "$port_a" "$mode" "$work/$class-a"
    start_scoped_server "$class" "nogeo" "$cpu" "$mem" \
        "$work/$class-a-nogeo.json" "$classdir/server-nogeo.log"
    wait_port "$port_a" 60
    start_sampler nogeo "$classdir/samples-nogeo.tsv"
    sleep 3
    emit_cell "$classdir" "$(jq -nc --argjson startup "$(startup_cell "$classdir/server-nogeo.log")" \
        --argjson sample "$(sample_now)" \
        '{cell: "startup", run: "nogeo"} + $startup + {idle: $sample}')"
    stop_sampler
    stop_scoped_server
    fi

    # ----- run B: geo assets loaded, full measurement -----
    if [[ ${SKIP_B:-0} != 1 ]]; then
    local port_b socks_b
    port_b=$(free_port)
    socks_b=$(free_port)
    make_configs "$port_b" "$mode" "$work/$class-b"
    make_xray_client "$port_b" "$socks_b" "$work/$class-b.client.env" "$work/$class-b.xray.json"
    start_scoped_server "$class" "geo" "$cpu" "$mem" \
        "$work/$class-b-geo.json" "$classdir/server-geo.log"
    wait_port "$port_b" 120
    "${CLEANENV[@]}" "$xray" run -config "$work/$class-b.xray.json" \
        > "$classdir/xray-client.log" 2>&1 &
    local xray_pid=$!
    client_pids+=("$xray_pid")
    register_pid "$xray_pid"
    wait_port "$socks_b" 30
    # Fail fast when the tunnel path is broken instead of recording garbage cells.
    if ! "${CLEANENV[@]}" python3 - "$socks_b" "$http_port" <<'PY'
import socket, sys
socks, origin = int(sys.argv[1]), int(sys.argv[2])
with socket.create_connection(("127.0.0.1", socks), timeout=15) as sock:
    sock.settimeout(15)
    sock.sendall(b"\x05\x01\x00")
    assert sock.recv(2) == b"\x05\x00", "socks greeting failed"
    sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + origin.to_bytes(2, "big"))
    reply = sock.recv(10)
    assert len(reply) == 10 and reply[1] == 0, f"socks connect rejected: {reply!r}"
    sock.sendall(b"GET /payload.bin HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
    assert sock.recv(4096), "tunnel returned no data"
PY
    then
        echo "TUNNEL SANITY PROBE FAILED for class $class; last server log lines:" >&2
        tail -5 "$classdir/server-geo.log" >&2
        exit 1
    fi
    start_sampler geo "$classdir/samples-geo.tsv"
    sleep 3
    emit_cell "$classdir" "$(jq -nc --argjson startup "$(startup_cell "$classdir/server-geo.log")" \
        --argjson sample "$(sample_now)" \
        '{cell: "startup", run: "geo"} + $startup + {idle: $sample}')"

    run_driver "$classdir" "$classdir/server-geo.log" churn \
        --socks "$socks_b" --origin-port "$http_port" \
        --concurrency 8 32 --conns "$conns" --samples "$samples_churn"

    run_driver "$classdir" "$classdir/server-geo.log" download \
        --socks "$socks_b" --url "$origin_url" --expected-bytes "$((512*1024*1024))" \
        --concurrency 1 --samples "$samples_download"

    run_driver "$classdir" "$classdir/server-geo.log" download \
        --socks "$socks_b" --url "$origin_url" --expected-bytes "$((512*1024*1024))" \
        --concurrency 32 --samples "$samples_download"

    run_driver "$classdir" "$classdir/server-geo.log" ladder \
        --socks "$socks_b" --origin-port "$http_port" \
        --levels "$ladder_levels" --settle "$settle" --hold "$hold"

    emit_cell "$classdir" "$(jq -nc --argjson sample "$(sample_now)" \
        '{cell: "cgroup_final", run: "geo"} + $sample')"
    stop_sampler
    stop_scoped_server
    stop_last_client
    fi

    # ----- run C: tuned policy, capacity ladder only -----
    local tuned_levels varname_t="TUNED_LEVELS_${class//-/_}"
    tuned_levels=${!varname_t:-${TUNED_LEVELS:-}}
    if [[ -z $tuned_levels ]]; then
        case $class in
            1c1g|1c1g-standard) tuned_levels="2000,4000,8000,12000,16000" ;;
            1c2g|2c2g)          tuned_levels="2000,4000,8000,12000,16000,24000" ;;
            # 24000 is the practical harness ceiling: three loopback legs per
            # session share the host's ~28.2k ephemeral ports (32768-60999),
            # so higher levels measure port exhaustion, not the server.
            2c4g|4c4g|4c8g)     tuned_levels="2000,4000,8000,12000,16000,24000" ;;
            *)                  tuned_levels="2000,4000,8000,12000" ;;
        esac
    fi
    if [[ ${SKIP_TUNED:-0} != 1 ]]; then
        echo "== class $class tuned ladder ($tuned_levels)" >&2
        local port_c socks_c
        port_c=$(free_port)
        socks_c=$(free_port)
        make_configs "$port_c" "$mode" "$work/$class-c"
        make_xray_client "$port_c" "$socks_c" "$work/$class-c.client.env" "$work/$class-c.xray.json"
        start_scoped_server "$class" "tuned" "$cpu" "$mem" \
            "$work/$class-c-tuned.json" "$classdir/server-tuned.log"
        wait_port "$port_c" 120
        "${CLEANENV[@]}" "$xray" run -config "$work/$class-c.xray.json" \
            > "$classdir/xray-client-tuned.log" 2>&1 &
        local xray_tuned_pid=$!
        client_pids+=("$xray_tuned_pid")
        register_pid "$xray_tuned_pid"
        wait_port "$socks_c" 30
        start_sampler tuned "$classdir/samples-tuned.tsv"
        sleep 2
        emit_cell "$classdir" "$(jq -nc --argjson startup "$(startup_cell "$classdir/server-tuned.log")" \
            --argjson sample "$(sample_now)" \
            '{cell: "startup", run: "tuned"} + $startup + {idle: $sample}')"
        run_driver "$classdir" "$classdir/server-tuned.log" ladder \
            --socks "$socks_c" --origin-port "$http_port" \
            --levels "$tuned_levels" --settle "$settle" --hold "$hold" --tag tuned
        emit_cell "$classdir" "$(jq -nc --argjson sample "$(sample_now)" \
            '{cell: "cgroup_final", run: "tuned"} + $sample')"
        stop_sampler
        stop_scoped_server
        stop_last_client
    fi

    local summary_status=0
    if "${CLEANENV[@]}" python3 scripts/profile-summarize.py "$classdir" \
        --class "$class" --mode "$mode" --cpu-quota "$cpu" --mem-max "$mem"
    then
        summary_status=0
    else
        summary_status=$?
    fi
    if (( summary_status != 0 )); then
        echo "== class $class failed its summary gate; continuing for aggregate evidence" >&2
    fi
    class_summaries+=("$classdir/summary.json")
    class_summary_statuses+=("$summary_status")
    echo "== class $class done -> $classdir/summary.json" >&2
}

for spec in $classes; do
    class=${spec%%:*}
    rest=${spec#*:}
    cpu=${rest%%:*}
    mem=${rest#*:}
    if [[ -n $only && $class != "$only" ]]; then
        :
    else
        run_class "$class" "$cpu" "$mem" dedicated
    fi
    if [[ $standard_comparison == 1 && $class == 1c1g \
        && ( -z $only || $comparison_name == "$only" ) ]]; then
        run_class "$comparison_name" "$cpu" "$mem" standard
    fi
done

aggregate_args=()
for index in "${!class_summaries[@]}"; do
    aggregate_args+=("${class_summaries[$index]}" "${class_summary_statuses[$index]}")
done
python3 - "$out_root/summary.json" "${aggregate_args[@]}" <<'PY'
import json
from pathlib import Path
import sys

output = Path(sys.argv[1])
values = sys.argv[2:]
if len(values) % 2:
    raise SystemExit("internal error: summary path/status arguments are unbalanced")
rows = []
for raw_path, raw_status in zip(values[::2], values[1::2]):
    path = Path(raw_path)
    try:
        status = int(raw_status)
    except ValueError:
        status = -1
    try:
        summary = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        rows.append({"path": str(path), "class": None, "pass": False,
                     "summarizerExitStatus": status, "error": str(error)})
        continue
    rows.append({"path": str(path), "class": summary.get("class"),
                 "summarizerExitStatus": status,
                 "pass": status == 0 and summary.get("pass") is True})

passed = bool(rows) and all(row["pass"] for row in rows)
output.write_text(json.dumps({"pass": passed, "classes": rows}, indent=2) + "\n")
if not passed:
    failed = [row.get("class") or row["path"] for row in rows if not row["pass"]]
    if not rows:
        failed = ["no selected classes produced a summary"]
    raise SystemExit("profile validation aggregate failed: " + ", ".join(failed))
PY

echo "all classes done; evidence under $out_root" >&2
