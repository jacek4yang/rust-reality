#!/usr/bin/env bash
# Formal production-fallback A/B benchmark.  Both pinned binaries run the same
# relay policy.  Measurements are made in alternating balanced ABBA blocks;
# every slot owns a fresh server, port, log, perf output and raw sample file.
set -Eeuo pipefail

readonly REPOSITORY="$({ cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."; pwd; })"
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
    printf 'benchmark-fallback-ab self-test: PASS\n'
    exit 0
fi

[[ $run_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || die 'RUN_ID is required and must be one safe component'
for name in OUT_DIR TMPDIR RUST_REALITY_BASELINE_BIN RUST_REALITY_BIN; do
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
for name in RUST_REALITY_BASELINE_COMMIT RUST_REALITY_COMMIT; do
    value=${!name:-}; [[ $value =~ ^[0-9a-fA-F]{7,40}$ ]] || die "$name must identify a commit"
done
for program in curl git go jq perf python3 readelf realpath sha256sum stat sudo; do
    command -v "$program" >/dev/null 2>&1 || die "required program unavailable: $program"
done
case "$(realpath -m "$out_dir")/" in "$REPOSITORY"/*) die 'OUT_DIR must be outside the Git worktree' ;; esac
case "$(realpath "$temporary_root")/" in "$REPOSITORY"/*) die 'TMPDIR must be outside the Git worktree' ;; esac
[[ $measure_mode != perf ]] || sudo -n true >/dev/null 2>&1 || die 'passwordless sudo is required for perf'
for binary in "$baseline_bin" "$candidate_bin"; do [[ -x $binary ]] || die "binary is not executable: $binary"; done
baseline_bin=$(realpath "$baseline_bin"); candidate_bin=$(realpath "$candidate_bin")
baseline_sha=$(sha256sum "$baseline_bin" | awk '{print $1}'); candidate_sha=$(sha256sum "$candidate_bin" | awk '{print $1}')
[[ ${baseline_sha_expected,,} == "$baseline_sha" ]] || die 'baseline SHA-256 mismatch'
[[ ${candidate_sha_expected,,} == "$candidate_sha" ]] || die 'candidate SHA-256 mismatch'
baseline_build_id=$(readelf -n "$baseline_bin" | awk '/Build ID:/ {print $3; exit}')
candidate_build_id=$(readelf -n "$candidate_bin" | awk '/Build ID:/ {print $3; exit}')
[[ -n $baseline_build_id && -n $candidate_build_id ]] || die 'both binaries need a GNU Build ID'
repository_head=$(git -C "$REPOSITORY" rev-parse --verify HEAD)
repository_dirty=false
[[ -z $(git -C "$REPOSITORY" status --porcelain=v1 --untracked-files=normal) ]] || repository_dirty=true
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
    local status=$? index pid; trap - EXIT INT TERM; set +e
    for ((index=${#tracked_pids[@]}-1;index>=0;index--)); do pid=${tracked_pids[index]}; [[ -n $pid ]] && stop_tracked "$pid"; done
    [[ -d $work && $work == "$temporary_root"/rust-reality-fallback-ab.* ]] && rm -rf -- "$work"
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
    --arg baselineBin "$baseline_bin" --arg baselineSha "$baseline_sha" --arg baselineBuildId "$baseline_build_id" --arg baselineCommit "$baseline_commit" \
    --arg candidateBin "$candidate_bin" --arg candidateSha "$candidate_sha" --arg candidateBuildId "$candidate_build_id" --arg candidateCommit "$candidate_commit" \
    --arg repositoryHead "$repository_head" --argjson repositoryDirty "$repository_dirty" --arg payloadSha "$payload_sha" --arg concurrencies "$concurrencies" --argjson blocks "$blocks" --argjson samples "$samples" --argjson payloadMiB "$payload_mib" \
    --argjson portBase "$port_base" --argjson portCount "$port_count" --argjson splice "$splice" --argjson pool "$pipe_pool" --argjson bufferKiB "$buffer_kib" --arg measureMode "$measure_mode" \
    '{schemaVersion:2,runId:$runId,startedAt:$startedAt,repository:{head:$repositoryHead,dirty:$repositoryDirty},method:"balanced block ABBA",blocks:$blocks,samplesPerSlot:$samples,concurrencies:$concurrencies,payloadMiB:$payloadMiB,payloadSha256:$payloadSha,measureMode:$measureMode,ports:{address:"127.0.0.1",base:$portBase,count:$portCount},relay:{splice:$splice,pipePool:$pool,bufferKiB:$bufferKiB},baseline:{path:$baselineBin,sha256:$baselineSha,buildId:$baselineBuildId,commit:$baselineCommit},candidate:{path:$candidateBin,sha256:$candidateSha,buildId:$candidateBuildId,commit:$candidateCommit}}' >"$out_dir/environment.json"

while IFS=$'\t' read -r block position implementation server_port; do
    slot=$(printf 'block-%02d-slot-%02d-%s' "$block" "$position" "$implementation"); slot_dir="$out_dir/slots/$slot"; mkdir -p "$slot_dir"
    if [[ $implementation == baseline ]]; then binary=$baseline_bin; binary_sha=$baseline_sha; binary_build_id=$baseline_build_id; else binary=$candidate_bin; binary_sha=$candidate_sha; binary_build_id=$candidate_build_id; fi
    "$binary" config generate standalone --listen 127.0.0.1 --port "$server_port" --target "127.0.0.1:$origin_port" --server-name localhost \
        >"$work/$slot.raw.json" 2>"$slot_dir/generate.log"
    jq --arg cache "$work/assets-$slot" --argjson splice "$splice" --argjson pool "$pipe_pool" --argjson kib "$buffer_kib" \
        '.log.level="warn"|.assets.cacheDirectory=$cache|.policy.relay.splice=$splice|.policy.relay.pipePool=$pool|.policy.relay.bufferBytes=($kib*1024)' \
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
        sudo -n perf stat -e task-clock,instructions,context-switches -p "$server_pid" -o "$slot_dir/perf.txt" -- \
            python3 "$work/driver.py" "$samples" "$payload_mib" "$server_port" "$concurrencies" "$slot_dir/samples.json" "$implementation" "$block" "$position"
    else
        python3 "$work/driver.py" "$samples" "$payload_mib" "$server_port" "$concurrencies" "$slot_dir/samples.json" "$implementation" "$block" "$position"
    fi
    [[ -s $slot_dir/perf.txt ]] || die "missing perf evidence in $slot"
    jq -n --arg implementation "$implementation" --arg binary "$binary" --arg sha "$binary_sha" --arg buildId "$binary_build_id" \
        --argjson block "$block" --argjson position "$position" --argjson serverPid "$server_pid" --argjson serverPort "$server_port" --arg integritySha "$payload_sha" \
        '{block:$block,position:$position,implementation:$implementation,binary:{path:$binary,sha256:$sha,buildId:$buildId},process:{serverPid:$serverPid},ports:{server:$serverPort},integrity:{sha256:$integritySha,match:true}}' >"$slot_dir/identity.json"
    stop_tracked "$server_pid"
    [[ $(sha256sum "$binary" | awk '{print $1}') == "$binary_sha" ]] || die "$implementation binary changed after $slot"
done < <(jq -r '.slots[]|[.block,.position,.implementation,.serverPort]|@tsv' "$out_dir/order.json")

python3 - "$out_dir" "$blocks" "$samples" "$payload_mib" "$concurrencies" <<'PY'
import json,pathlib,random,statistics,sys
root=pathlib.Path(sys.argv[1]); blocks,samples,mib=int(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4]); cs=[int(x) for x in sys.argv[5].split()]
order=json.load(open(root/'order.json'))['slots']; dirs=sorted((root/'slots').iterdir()); rows=[]; identities=[]
if len(dirs)!=blocks*4: raise SystemExit('missing ABBA slots')
for slot in dirs:
    ident=json.load(open(slot/'identity.json')); identities.append(ident); current=json.load(open(slot/'samples.json'))
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
summary={'schemaVersion':2,'status':'COMPLETE','method':'alternating balanced ABBA blocks; block bootstrap','slotCount':len(dirs),'rawSampleCount':len(rows),'cells':cells,'failures':0}
json.dump(summary,open(root/'summary.json','x'),indent=2); print(json.dumps(summary))
PY
[[ $(sha256sum "$baseline_bin" | awk '{print $1}') == "$baseline_sha" ]] || die 'baseline changed during run'
[[ $(sha256sum "$candidate_bin" | awk '{print $1}') == "$candidate_sha" ]] || die 'candidate changed during run'
jq -e --argjson slots "$slot_count" '.status=="COMPLETE" and .slotCount==$slots and .failures==0' "$out_dir/summary.json" >/dev/null || die 'aggregate gate failed'
printf 'fallback ABBA complete: %s\n' "$out_dir"
