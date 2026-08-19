#!/usr/bin/env bash
# Formal production-fallback A/B benchmark.  Both pinned binaries run the same
# relay policy.  Measurements are made in alternating balanced ABBA blocks;
# every slot owns a fresh server, port, log, perf output and raw sample file.
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
baseline_sha_expected=${RUST_REALITY_BASELINE_SHA256:-}
candidate_sha_expected=${RUST_REALITY_SHA256:-}
baseline_commit=${RUST_REALITY_BASELINE_COMMIT:-}
candidate_commit=${RUST_REALITY_COMMIT:-}
baseline_identity=${RUST_REALITY_BASELINE_IDENTITY:-}
blocks=${BLOCKS:-3}
samples=${SAMPLES:-3}
concurrencies=${CONCURRENCIES:-1 4 32}
payload_mib=${PAYLOAD_MIB:-32}
abba_start=${ABBA_START:-baseline}
splice=${RELAY_SPLICE:-true}
pipe_pool=${RELAY_PIPE_POOL:-true}
buffer_kib=${RELAY_BUFFER_KIB:-32}
measure_mode=${MEASURE_MODE:-perf}
self_test=${SELF_TEST:-0}

die() { printf 'benchmark-fallback-ab: %s\n' "$*" >&2; exit 2; }


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
with open(output, "x", encoding="utf-8") as handle:
    json.dump({"schemaVersion": 1, "events": events,
               "taskClockMilliseconds": events["task-clock"]["value"]},
              handle, indent=2, sort_keys=True)
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
    blocks=3 abba_start=baseline
    [[ $(block_order 1 | paste -sd '') == ABBA ]]
    [[ $(block_order 2 | paste -sd '') == BAAB ]]
    [[ $(block_order 3 | paste -sd '') == ABBA ]]
    abba_start=candidate
    [[ $(block_order 1 | paste -sd '') == BAAB ]]
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
    printf 'benchmark-fallback-ab self-test: PASS\n'
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
for name in OUT_DIR TMPDIR RUST_REALITY_BASELINE_BIN RUST_REALITY_BIN RUST_REALITY_BASELINE_IDENTITY; do
    value=${!name:-}; [[ $value == /* ]] || die "$name must be an absolute path"
done
[[ ! -e $out_dir && ! -L $out_dir ]] || die "OUT_DIR already exists: $out_dir"
[[ -d $temporary_root && ! -L $temporary_root ]] || die 'TMPDIR must be an existing, non-symlink directory'
[[ $port_base =~ ^[0-9]+$ ]] || die 'PORT_BASE is required'
[[ $blocks =~ ^[1-9][0-9]*$ ]] && ((blocks >= 3 && blocks <= 20)) || die 'BLOCKS must be in 3..20'
[[ $samples =~ ^[1-9][0-9]*$ ]] || die 'SAMPLES must be positive'
[[ $payload_mib =~ ^[1-9][0-9]*$ ]] && ((payload_mib <= 4096)) || die 'PAYLOAD_MIB must be in 1..4096'
[[ $buffer_kib =~ ^[1-9][0-9]*$ ]] || die 'RELAY_BUFFER_KIB must be positive'
[[ $splice == true || $splice == false ]] || die 'RELAY_SPLICE must be true or false'
[[ $pipe_pool == true || $pipe_pool == false ]] || die 'RELAY_PIPE_POOL must be true or false'
[[ $abba_start == baseline || $abba_start == candidate ]] || die 'ABBA_START must be baseline or candidate'
[[ $measure_mode == perf ]] || die 'MEASURE_MODE must be perf; use SELF_TEST=1 for a non-authoritative harness check'
for value in $concurrencies; do [[ $value =~ ^[1-9][0-9]*$ ]] || die "invalid concurrency: $value"; done
for name in RUST_REALITY_BASELINE_SHA256 RUST_REALITY_SHA256; do
    value=${!name:-}; [[ $value =~ ^[0-9a-fA-F]{64}$ ]] || die "$name must be a 64-digit SHA-256"
done
[[ $baseline_commit =~ ^[0-9a-fA-F]{40}$ ]] || die 'RUST_REALITY_BASELINE_COMMIT must be a full commit ID'
[[ $candidate_commit =~ ^[0-9a-fA-F]{7,40}$ ]] || die 'RUST_REALITY_COMMIT must identify a commit'
for program in curl git go jq perf python3 readelf realpath sha256sum stat sudo; do
    command -v "$program" >/dev/null 2>&1 || die "required program unavailable: $program"
done
case "$(realpath -m "$out_dir")/" in "$REPOSITORY"/*) die 'OUT_DIR must be outside the Git worktree' ;; esac
case "$(realpath "$temporary_root")/" in "$REPOSITORY"/*) die 'TMPDIR must be outside the Git worktree' ;; esac
[[ $measure_mode != perf ]] || sudo -n true >/dev/null 2>&1 || die 'passwordless sudo is required for perf'
for binary in "$baseline_bin" "$candidate_bin"; do [[ -x $binary ]] || die "binary is not executable: $binary"; done
baseline_bin=$(realpath "$baseline_bin"); candidate_bin=$(realpath "$candidate_bin")
[[ -f $baseline_identity && ! -L $baseline_identity ]] || die 'RUST_REALITY_BASELINE_IDENTITY must be a regular non-symlink file'
baseline_identity=$(realpath "$baseline_identity")
baseline_sha=$(sha256sum "$baseline_bin" | awk '{print $1}'); candidate_sha=$(sha256sum "$candidate_bin" | awk '{print $1}')
[[ ${baseline_sha_expected,,} == "$baseline_sha" ]] || die 'baseline SHA-256 mismatch'
[[ ${candidate_sha_expected,,} == "$candidate_sha" ]] || die 'candidate SHA-256 mismatch'
baseline_build_id=$(readelf -n "$baseline_bin" | awk '/Build ID:/ {print $3; exit}')
candidate_build_id=$(readelf -n "$candidate_bin" | awk '/Build ID:/ {print $3; exit}')
[[ -n $baseline_build_id && -n $candidate_build_id ]] || die 'both binaries need a GNU Build ID'
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

slot_count=$((blocks * 4)); port_count=$((1 + slot_count))
((port_base >= 1024 && port_base + port_count - 1 <= 65535)) || die 'PORT_BASE does not leave a large enough block'
python3 - "$port_base" "$port_count" <<'PY'
import socket,sys
base,count=map(int,sys.argv[1:]); sockets=[]
try:
    for port in range(base,base+count):
        sock=socket.socket(); sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,0); sock.bind(("127.0.0.1",port)); sockets.append(sock)
finally:
    for sock in sockets: sock.close()
PY

mkdir -m 700 -p "$(dirname "$out_dir")"; mkdir -m 700 "$out_dir"
work=$(mktemp -d "$temporary_root/rust-reality-fallback-ab.XXXXXX")
declare -a tracked_pids=() tracked_starts=() tracked_names=()
last_pid=
pid_start_time() {
    python3 - "$1" <<'PY'
from pathlib import Path
import sys
raw=Path(f"/proc/{sys.argv[1]}/stat").read_text(); end=raw.rfind(")"); print(raw[end+2:].split()[19])
PY
}
pid_owned() { local observed; [[ -r /proc/$1/stat ]] || return 1; observed=$(pid_start_time "$1" 2>/dev/null) || return 1; [[ $observed == "$2" ]]; }
track_last() {
    local start; start=$(pid_start_time "$2") || die "$1 exited before registration"
    tracked_names+=("$1"); tracked_pids+=("$2"); tracked_starts+=("$start"); last_pid=$2
}
stop_tracked() {
    local pid=$1 index
    for index in "${!tracked_pids[@]}"; do
        [[ ${tracked_pids[index]} == "$pid" ]] || continue
        if pid_owned "$pid" "${tracked_starts[index]}"; then
            kill -TERM "$pid" 2>/dev/null || true
            for _ in {1..50}; do pid_owned "$pid" "${tracked_starts[index]}" || break; sleep .02; done
            pid_owned "$pid" "${tracked_starts[index]}" && kill -KILL "$pid" 2>/dev/null || true
        fi
        wait "$pid" 2>/dev/null || true; tracked_pids[index]=; return
    done
}
cleanup() {
    local status=$? index pid lock_status=0 publication_status=0; trap - EXIT INT TERM; set +e
    for ((index=${#tracked_pids[@]}-1;index>=0;index--)); do pid=${tracked_pids[index]}; [[ -n $pid ]] && stop_tracked "$pid"; done
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
                "$out_dir/environment.json" "$run_id" benchmark-fallback-ab ||
                publication_status=1
        fi
        (( publication_status != 0 )) || printf 'fallback ABBA complete: %s\n' "$out_dir"
    fi
    rm -f -- "$out_dir/.environment.complete.json"
    [[ -d $work && $work == "$temporary_root"/rust-reality-fallback-ab.* ]] && rm -rf -- "$work"
    (( status == 0 && (lock_status != 0 || publication_status != 0) )) && status=2
    exit "$status"
}
trap cleanup EXIT; trap 'exit 130' INT; trap 'exit 143' TERM
wait_port() {
    local start; start=$(pid_start_time "$2") || return 1
    python3 - "$1" "$2" "$start" <<'PY'
import socket,sys,time
port,pid,expected=int(sys.argv[1]),int(sys.argv[2]),sys.argv[3]; deadline=time.monotonic()+10
while time.monotonic()<deadline:
    try:
        raw=open(f"/proc/{pid}/stat").read(); observed=raw[raw.rfind(")")+2:].split()[19]
    except OSError: raise SystemExit('registered process exited')
    if observed!=expected: raise SystemExit('PID identity changed')
    with socket.socket() as sock:
        sock.settimeout(.1)
        if sock.connect_ex(('127.0.0.1',port))==0: raise SystemExit(0)
    time.sleep(.02)
raise SystemExit(f'port {port} did not become ready')
PY
}

cat >"$work/driver.py" <<'PY'
import concurrent.futures,json,os,subprocess,sys,time
samples,mib,server=map(int,sys.argv[1:4]); concurrencies=[int(x) for x in sys.argv[4].split()]
output,implementation,block,position=sys.argv[5],sys.argv[6],int(sys.argv[7]),int(sys.argv[8]); expected=mib*1024*1024
env={k:v for k,v in os.environ.items() if not k.lower().endswith('_proxy')}; url=f'http://127.0.0.1:{server}/payload-{mib}.bin'
def transfer(_):
    done=subprocess.run(['curl','--fail','--silent','--show-error','--max-time','300','--output',os.devnull,'--write-out','%{size_download} %{time_total}',url],capture_output=True,text=True,env=env)
    if done.returncode: return {'ok':False,'error':done.stderr[:160]}
    try: size,elapsed=done.stdout.split(); size=int(size); elapsed=float(elapsed)
    except Exception: return {'ok':False,'error':'malformed curl output'}
    return {'ok':size==expected,'bytes':size,'seconds':elapsed,'error':None if size==expected else 'short read'}
if samples == 0:
    for _ in range(3):
        if not transfer(0)['ok']: raise SystemExit('warm-up failed')
    with open(output,'x') as handle: json.dump([],handle)
    raise SystemExit(0)
rows=[]
for conc in concurrencies:
    for sample in range(samples):
        started=time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as pool: results=list(pool.map(transfer,range(conc)))
        wall=time.perf_counter()-started; failed=sum(not r['ok'] for r in results)
        rows.append({'block':block,'position':position,'implementation':implementation,'concurrency':conc,'sampleIndex':sample,
                     'requests':len(results),'failed':failed,'bytesExpectedPerRequest':expected,
                     'bytesObserved':[r.get('bytes') for r in results],'wallSeconds':wall,
                     'throughputMiBPerSecond':mib*sum(r['ok'] for r in results)/wall,'perRequestSeconds':[r.get('seconds') for r in results if r['ok']]})
with open(output,'x') as handle: json.dump(rows,handle,indent=2)
if len(rows)!=samples*len(concurrencies) or any(r['failed'] or r['requests']!=r['concurrency'] or any(v!=expected for v in r['bytesObserved']) for r in rows):
    raise SystemExit('incomplete or corrupt fallback samples')
PY

cd "$REPOSITORY"
python3 - "$work/payload-$payload_mib.bin" "$payload_mib" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1]); remaining=int(sys.argv[2])*1024*1024; chunk=bytes(range(256))*4096
with path.open('xb') as out:
    while remaining: part=chunk[:min(remaining,len(chunk))]; out.write(part); remaining-=len(part)
PY
payload_sha=$(sha256sum "$work/payload-$payload_mib.bin" | awk '{print $1}')
(cd scripts/bench-origin && go build -o "$work/bench-origin" .)
origin_port=$port_base
"$work/bench-origin" --port "$origin_port" --payload-dir "$work" --put-log "$work/http-put.jsonl" >"$out_dir/origin.log" 2>&1 &
track_last origin "$!"; origin_pid=$last_pid; wait_port "$origin_port" "$origin_pid"

python3 - "$out_dir/order.json" "$blocks" "$abba_start" "$port_base" <<'PY'
import json,sys
path,blocks,start,base=sys.argv[1],int(sys.argv[2]),sys.argv[3],int(sys.argv[4]); rows=[]
for block in range(1,blocks+1):
    bf=(block%2==1)==(start=='baseline'); order=['baseline','candidate','candidate','baseline'] if bf else ['candidate','baseline','baseline','candidate']
    for position,impl in enumerate(order,1): rows.append({'block':block,'position':position,'implementation':impl,'serverPort':base+1+(block-1)*4+position-1})
json.dump({'schemaVersion':1,'method':'alternating balanced ABBA blocks','slots':rows},open(path,'x'),indent=2)
PY
jq -n --arg runId "$run_id" --arg startedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg baselineBin "$baseline_bin" --arg baselineSha "$baseline_sha" --arg baselineBuildId "$baseline_build_id" --arg baselineCommit "$baseline_commit" --arg baselineIdentity "$baseline_identity" --arg baselineIdentitySha "$baseline_identity_sha" \
    --arg candidateBin "$candidate_bin" --arg candidateSha "$candidate_sha" --arg candidateBuildId "$candidate_build_id" --arg candidateCommit "$candidate_commit" \
    --arg scriptPath "$script_path" --arg scriptSha "$script_sha" --arg benchOriginTree "$bench_origin_tree" --arg benchOriginManifest "$bench_origin_manifest_sha" --argjson benchOriginFiles "$bench_origin_file_count" \
    --arg contractPath "$host_contract_path" --arg contractSha "$host_contract_sha" --arg helperPath "$host_helper_path" --arg helperSha "$host_helper_sha" --argjson hostLock "$host_lock_evidence" \
    --arg repositoryHead "$repository_head" --argjson repositoryDirty "$repository_dirty" --arg payloadSha "$payload_sha" --arg concurrencies "$concurrencies" --argjson blocks "$blocks" --argjson samples "$samples" --argjson payloadMiB "$payload_mib" \
    --argjson portBase "$port_base" --argjson portCount "$port_count" --argjson splice "$splice" --argjson pool "$pipe_pool" --argjson bufferKiB "$buffer_kib" --arg measureMode "$measure_mode" \
    '{schemaVersion:2,runId:$runId,startedAt:$startedAt,repository:{head:$repositoryHead,dirty:$repositoryDirty},method:"balanced block ABBA",blocks:$blocks,samplesPerSlot:$samples,concurrencies:$concurrencies,payloadMiB:$payloadMiB,payloadSha256:$payloadSha,measureMode:$measureMode,ports:{address:"127.0.0.1",base:$portBase,count:$portCount},relay:{splice:$splice,pipePool:$pool,bufferKiB:$bufferKiB},baseline:{path:$baselineBin,sha256:$baselineSha,buildId:$baselineBuildId,commit:$baselineCommit,identity:{path:$baselineIdentity,sha256:$baselineIdentitySha}},candidate:{path:$candidateBin,sha256:$candidateSha,buildId:$candidateBuildId,commit:$candidateCommit},harness:{entrypoint:{path:$scriptPath,sha256:$scriptSha},contract:{path:$contractPath,sha256:$contractSha},keeperHelper:{path:$helperPath,sha256:$helperSha},benchOrigin:{path:$benchOriginTree,manifestSha256:$benchOriginManifest,fileCount:$benchOriginFiles}},hostExclusiveLock:$hostLock}' >"$out_dir/environment.json"

while IFS=$'\t' read -r block position implementation server_port; do
    slot=$(printf 'block-%02d-slot-%02d-%s' "$block" "$position" "$implementation"); slot_dir="$out_dir/slots/$slot"; mkdir -p "$slot_dir"
    if [[ $implementation == baseline ]]; then binary=$baseline_bin; binary_sha=$baseline_sha; binary_build_id=$baseline_build_id; else binary=$candidate_bin; binary_sha=$candidate_sha; binary_build_id=$candidate_build_id; fi
    "$binary" config generate standalone --listen 127.0.0.1 --port "$server_port" --target "127.0.0.1:$origin_port" --server-name localhost \
        >"$work/$slot.raw.json" 2>"$slot_dir/generate.log"
    # The two implementations speak different configuration generations:
    # the v1.5 baseline knows only the `policy` object, while the v1.6
    # candidate rejects `policy`/`resourceMode` and reads the canonical
    # `advanced.limits` location. Both filters pin the same effective relay
    # settings, so the comparison stays symmetric.
    if [[ $implementation == baseline ]]; then
        relay_filter='.policy.relay.splice=$splice|.policy.relay.pipePool=$pool|.policy.relay.bufferBytes=($kib*1024)'
    else
        relay_filter='del(.policy)|del(.runtime.resourceMode)|.advanced.limits.relay.splice=$splice|.advanced.limits.relay.pipePool=$pool|.advanced.limits.relay.bufferBytes=($kib*1024)'
    fi
    jq --arg cache "$work/assets-$slot" --argjson splice "$splice" --argjson pool "$pipe_pool" --argjson kib "$buffer_kib" \
        ".log.level=\"warn\"|.assets.cacheDirectory=\$cache|$relay_filter" \
        "$work/$slot.raw.json" >"$work/$slot.server.json"
    "$binary" serve --config "$work/$slot.server.json" >"$slot_dir/server.log" 2>&1 &
    track_last "$slot-server" "$!"; server_pid=$last_pid; wait_port "$server_port" "$server_pid"
    [[ $(sha256sum "/proc/$server_pid/exe" | awk '{print $1}') == "$binary_sha" ]] || die "server ELF mismatch in $slot"
    curl_env=(env -u ALL_PROXY -u all_proxy -u HTTP_PROXY -u http_proxy -u HTTPS_PROXY -u https_proxy -u NO_PROXY -u no_proxy)
    "${curl_env[@]}" curl --fail --silent --show-error --max-time 300 "http://127.0.0.1:$server_port/payload-$payload_mib.bin" -o "$slot_dir/integrity.bin"
    [[ $(stat -c %s "$slot_dir/integrity.bin") == $((payload_mib*1024*1024)) ]] || die "integrity length mismatch in $slot"
    [[ $(sha256sum "$slot_dir/integrity.bin" | awk '{print $1}') == "$payload_sha" ]] || die "integrity hash mismatch in $slot"
    rm -f -- "$slot_dir/integrity.bin"
    python3 "$work/driver.py" 0 "$payload_mib" "$server_port" "$concurrencies" "$slot_dir/warmup.json" "$implementation" "$block" "$position"
    if [[ $measure_mode == perf ]]; then
        sudo -n perf stat --no-big-num -x, -e task-clock,instructions,context-switches -p "$server_pid" -o "$slot_dir/perf.csv" -- \
            python3 "$work/driver.py" "$samples" "$payload_mib" "$server_port" "$concurrencies" "$slot_dir/samples.json" "$implementation" "$block" "$position"
        validate_perf_csv "$slot_dir/perf.csv" "$slot_dir/perf.json"
    else
        python3 "$work/driver.py" "$samples" "$payload_mib" "$server_port" "$concurrencies" "$slot_dir/samples.json" "$implementation" "$block" "$position"
    fi
    [[ -s $slot_dir/perf.json ]] || die "missing validated perf evidence in $slot"
    jq -n --arg implementation "$implementation" --arg binary "$binary" --arg sha "$binary_sha" --arg buildId "$binary_build_id" \
        --argjson block "$block" --argjson position "$position" --argjson serverPid "$server_pid" --argjson serverPort "$server_port" --arg integritySha "$payload_sha" \
        '{block:$block,position:$position,implementation:$implementation,binary:{path:$binary,sha256:$sha,buildId:$buildId},process:{serverPid:$serverPid},ports:{server:$serverPort},integrity:{sha256:$integritySha,match:true}}' >"$slot_dir/identity.json"
    stop_tracked "$server_pid"
    [[ $(sha256sum "$binary" | awk '{print $1}') == "$binary_sha" ]] || die "$implementation binary changed after $slot"
done < <(jq -r '.slots[]|[.block,.position,.implementation,.serverPort]|@tsv' "$out_dir/order.json")

python3 - "$out_dir" "$blocks" "$samples" "$payload_mib" "$concurrencies" <<'PY'
import json,pathlib,random,statistics,sys
root=pathlib.Path(sys.argv[1]); blocks,samples,mib=int(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4]); cs=[int(x) for x in sys.argv[5].split()]
order=json.load(open(root/'order.json'))['slots']; dirs=sorted((root/'slots').iterdir()); rows=[]; identities=[]; perf_rows=[]
if len(dirs)!=blocks*4: raise SystemExit('missing ABBA slots')
for slot in dirs:
    ident=json.load(open(slot/'identity.json')); identities.append(ident); current=json.load(open(slot/'samples.json'))
    perf=json.load(open(slot/'perf.json')); perf_rows.append({**ident,**perf})
    if not ident['integrity']['match'] or len(current)!=samples*len(cs): raise SystemExit(f'incomplete slot: {slot}')
    expected=mib*1024*1024
    if any(r['failed'] or r['requests']!=r['concurrency'] or any(v!=expected for v in r['bytesObserved']) for r in current): raise SystemExit(f'corrupt sample: {slot}')
    rows.extend(current)
expected={(row['block'],row['position']):(row['implementation'],row['serverPort']) for row in order}
observed={(row['block'],row['position']):(row['implementation'],row['ports']['server']) for row in identities}
if observed != expected: raise SystemExit('slot identity/order does not match order manifest')
with open(root/'raw-samples.jsonl','x') as out:
    for row in rows: out.write(json.dumps(row,sort_keys=True)+'\n')
cells={}
for conc in cs:
    ratios=[]; details=[]
    for block in range(1,blocks+1):
        values={}
        for impl in ('baseline','candidate'):
            observed=[r['throughputMiBPerSecond'] for r in rows if r['block']==block and r['implementation']==impl and r['concurrency']==conc]
            if len(observed)!=2*samples: raise SystemExit('unbalanced block')
            values[impl]=statistics.median(observed)
        ratio=values['candidate']/values['baseline']; ratios.append(ratio); details.append({**values,'candidateVsBaseline':ratio})
    rng=random.Random(0x464200+conc); boot=sorted(statistics.median(rng.choices(ratios,k=len(ratios))) for _ in range(20000))
    cells[str(conc)]={'blocks':details,'medianCandidateVsBaseline':statistics.median(ratios),'bootstrap95':[boot[500],boot[19499]]}
transferred_gib=samples*sum(cs)*mib/1024
if transferred_gib <= 0: raise SystemExit('invalid measured transfer volume')
cpu_blocks=[]; cpu_ratios=[]
for block in range(1,blocks+1):
    values={}
    for impl in ('baseline','candidate'):
        observed=[r['taskClockMilliseconds']/1000/transferred_gib for r in perf_rows if r['block']==block and r['implementation']==impl]
        if len(observed)!=2: raise SystemExit('unbalanced perf block')
        values[impl]=statistics.median(observed)
    ratio=values['candidate']/values['baseline']; cpu_ratios.append(ratio); cpu_blocks.append({**values,'candidateVsBaseline':ratio})
rng=random.Random(0x4642C0); cpu_boot=sorted(statistics.median(rng.choices(cpu_ratios,k=len(cpu_ratios))) for _ in range(20000))
cpu_summary={'unit':'secondsPerGiB','blocks':cpu_blocks,'medianCandidateVsBaseline':statistics.median(cpu_ratios),'bootstrap95':[cpu_boot[500],cpu_boot[19499]]}
summary={'schemaVersion':2,'status':'COMPLETE','performanceVerdict':'NOT_EVALUATED','method':'alternating balanced ABBA blocks; block bootstrap','slotCount':len(dirs),'rawSampleCount':len(rows),'cells':cells,'serverCpuPerGiB':cpu_summary,'failures':0}
json.dump(summary,open(root/'summary.json','x'),indent=2); print(json.dumps(summary))
PY
[[ $(sha256sum "$baseline_bin" | awk '{print $1}') == "$baseline_sha" ]] || die 'baseline changed during run'
[[ $(sha256sum "$candidate_bin" | awk '{print $1}') == "$candidate_sha" ]] || die 'candidate changed during run'
verify_harness_inputs
jq -e --argjson slots "$slot_count" '.status=="COMPLETE" and .slotCount==$slots and .failures==0' "$out_dir/summary.json" >/dev/null || die 'aggregate gate failed'
host_lock_evidence=$(rr_host_lock_evidence_complete "$host_lock_evidence") ||
    die 'host-exclusive lock identity changed before completion'
jq --argjson hostLock "$host_lock_evidence" '.hostExclusiveLock=$hostLock' \
    "$out_dir/environment.json" >"$out_dir/.environment.complete.json"
rr_host_lock_verify || die 'host-exclusive lock failed final verification'
