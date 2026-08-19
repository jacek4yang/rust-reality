#!/usr/bin/env bash
# Routing-rule scaling comparison (README gap G5): 10 / 100 / 1000 / 10000
# explicit domain rules on both implementations, no geosite/geoip external
# files, measuring connection setup decision latency at fixed concurrency.
#
# Both servers carry semantically equivalent first-match rule lists:
#   rust-reality: routing.globalRules [{name, outbound:"direct",
#                 domain:["rule-<i>.routingbench"]}]
#   Xray:         routing.rules [{type:"field", domain:["rule-<i>.routingbench"],
#                 outboundTag:"direct"}]
# The measured destination is rule-<N-1>.routingbench — the LAST rule — so
# every connection walks the full list (worst case).  The name resolves
# through the same loopback fake DNS (scripts/dns-fake-server.py) to
# 127.0.0.1; after a warm-up the answer is cached in both implementations,
# so the measured latency isolates rule evaluation, not DNS.  Blocks
# interleave rust/xray per scale point (balanced ABBA).
#
# Env: RUN_ID OUT_DIR TMPDIR PORT_BASE RUST_REALITY_BIN RUST_REALITY_SHA256
# XRAY_BIN XRAY_SHA256 RULE_SCALES (formal "10 100 1000 10000", exploratory
# "10 1000") BLOCKS (2) SAMPLES (2) CONNS (64) CONCURRENCY (8)
# EXPLORATORY=1 (wrap in `flock -x /tmp/v151-bench.lock`).
set -Eeuo pipefail
export LC_ALL=C

repository=$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$repository/scripts/benchmark-contract.sh"
rust_bin=${RUST_REALITY_BIN:-target/release/rust-reality}
xray=${XRAY_BIN:-../artifacts/xray-reference-v26.7.28}
rule_scales=${RULE_SCALES:-}
if [[ -z $rule_scales ]]; then
    if [[ ${EXPLORATORY:-0} == 1 ]]; then rule_scales="10 1000"; else rule_scales="10 100 1000 10000"; fi
fi
blocks=${BLOCKS:-2}
samples=${SAMPLES:-2}
connections=${CONNS:-64}
concurrency=${CONCURRENCY:-8}
for value in $rule_scales; do
    [[ $value =~ ^[1-9][0-9]*$ ]] || { echo "invalid rule scale: $value" >&2; exit 2; }
done
for value in "$blocks" "$samples" "$connections" "$concurrency"; do
    [[ $value =~ ^[1-9][0-9]*$ ]] || { echo "BLOCKS/SAMPLES/CONNS/CONCURRENCY must be positive integers" >&2; exit 2; }
done

# ports: http+https origins, per impl {dns-udp, dns-control, server, socks} = 10 + slack
# Default the port block above the ephemeral range (32768-60999) so the load
# driver's own outbound sockets cannot collide with it mid-run.
if [[ -z ${PORT_BASE:-} ]]; then
    PORT_BASE=$(python3 - 16 <<'PY'
import socket, sys
width = int(sys.argv[1])
for base in range(61000, 65536 - width, 37):
    sockets = []
    bound = True
    try:
        for port in range(base, base + width):
            sock = socket.socket()
            sock.bind(("127.0.0.1", port))
            sockets.append(sock)
    except OSError:
        bound = False
    finally:
        for sock in sockets:
            sock.close()
    if bound:
        print(base)
        break
else:
    raise SystemExit("no free port block above the ephemeral range")
PY
)
    export PORT_BASE
fi
rr_contract_init "$repository" benchmark-routing-comparison benchmarks/final 16
rr_register_binary rust-reality "$rust_bin" "${RUST_REALITY_SHA256:-}" rust \
    "${EXPECTED_SOURCE_COMMIT:-}"
rust_bin=${RR_BINARY_PATHS[rust-reality]}
rr_register_binary xray "$xray" "${XRAY_SHA256:-}" xray
xray=${RR_BINARY_PATHS[xray]}
rr_register_harness_file "$repository/scripts/dns-fake-server.py"
rr_register_harness_tree "$repository/scripts/bench-origin"
rr_write_contract_metadata
out_dir=$RR_OUT_DIR
temporary_root=$RR_TMPDIR

for program in go jq openssl python3 sha256sum; do
    command -v "$program" >/dev/null || { echo "missing: $program" >&2; exit 1; }
done

work=$(mktemp -d "$temporary_root/rust-reality-routing-comparison.XXXXXX")
declare -a pids=()
declare -A active_starts=()
last_pid=

pid_is_owned() {
    local pid=$1 observed
    observed=$(rr_pid_starttime "$pid" 2>/dev/null) || return 1
    [[ $observed == "${active_starts[$pid]:-}" ]]
}

start_logged() {
    local log=$1
    shift
    "$@" >"$log" 2>&1 &
    last_pid=$!
    pids+=("$last_pid")
    active_starts["$last_pid"]=$(rr_pid_starttime "$last_pid") || {
        echo "cannot identify started process PID $last_pid" >&2
        return 1
    }
    case $1 in
        "$rust_bin" | "$xray") rr_register_pid "$last_pid" "$1" ;;
        *) rr_register_pid "$last_pid" ;;
    esac
}

stop_pid() {
    local pid=$1
    pid_is_owned "$pid" && {
        kill -TERM "$pid" 2>/dev/null || true
        for _ in {1..50}; do pid_is_owned "$pid" || break; sleep 0.02; done
        pid_is_owned "$pid" && kill -KILL "$pid" 2>/dev/null || true
    }
    wait "$pid" 2>/dev/null || true
    unset "active_starts[$pid]"
}

cleanup() {
    local original_status=$? final_status pid
    trap - EXIT INT TERM
    set +e
    for pid in "${pids[@]:-}"; do stop_pid "$pid"; done
    if [[ -d $work && $work == "$temporary_root"/rust-reality-routing-comparison.* ]]; then
        rm -rf -- "$work"
    fi
    final_status=$original_status
    rr_contract_verify_on_exit "$original_status"
    final_status=$?
    exit "$final_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_port() {
    local port=$1 pid=$2 proto=${3:-tcp}
    python3 - "$port" "$pid" "${active_starts[$pid]}" "$proto" "${WAIT_PORT_DEADLINE:-20}" <<'PY'
import socket, sys, time
port, pid, expected, proto = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
deadline = time.monotonic() + float(sys.argv[5]) if len(sys.argv) > 5 else time.monotonic() + 20
while time.monotonic() < deadline:
    try:
        raw = open(f"/proc/{pid}/stat").read()
        observed = raw[raw.rfind(")") + 2:].split()[19]
    except OSError:
        raise SystemExit(f"process {pid} exited before port {port}/{proto} became ready")
    if observed != expected:
        raise SystemExit(f"process {pid} identity changed before port {port}/{proto} became ready")
    if proto == "tcp":
        with socket.socket() as sock:
            sock.settimeout(0.1)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                raise SystemExit(0)
    else:
        import struct
        query = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        query += b"\x09readiness\x07invalid\x00" + struct.pack(">HH", 1, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.2)
            try:
                sock.sendto(query, ("127.0.0.1", port))
                sock.recvfrom(512)
                raise SystemExit(0)
            except OSError:
                pass
    time.sleep(0.02)
raise SystemExit(f"port {port}/{proto} did not become ready")
PY
}

cat >"$work/driver.py" <<'PY'
import concurrent.futures, json, socket, sys, time
socks, origin, concurrency, conns, name = (int(sys.argv[1]), int(sys.argv[2]),
    int(sys.argv[3]), int(sys.argv[4]), sys.argv[5])
encoded = name.encode()
def exact(sock, n):
    out = b""
    while len(out) < n:
        part = sock.recv(n - len(out))
        if not part: raise OSError("short SOCKS reply")
        out += part
    return out
def one(_):
    started = time.perf_counter()
    try:
        with socket.create_connection(("127.0.0.1", socks), timeout=30) as sock:
            sock.sendall(b"\x05\x01\x00")
            if exact(sock, 2) != b"\x05\x00": return None
            sock.sendall(b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded
                         + origin.to_bytes(2, "big"))
            reply = exact(sock, 4)
            if reply[1] != 0: return None
            atyp = reply[3]
            if atyp == 1: exact(sock, 4)
            elif atyp == 4: exact(sock, 16)
            else: exact(sock, exact(sock, 1)[0])
            exact(sock, 2)
            sock.sendall(f"GET /payload.bin HTTP/1.0\r\nHost: {name}\r\n\r\n".encode())
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
wall0 = time.perf_counter()
with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
    values = list(pool.map(one, range(conns)))
wall = time.perf_counter() - wall0
good = sorted(x for x in values if x is not None)
result = {"requested": conns, "failed": len(values) - len(good),
          "wallSeconds": wall, "latenciesSeconds": good}
print(json.dumps(result))
if result["failed"] or len(good) != conns:
    raise SystemExit(1)
PY

cd "$repository"
printf '%s' "$(printf 'x%.0s' {1..256})" >"$work/payload.bin"
(cd scripts/bench-origin && GOFLAGS=-buildvcs=false go build -o "$work/bench-origin" .)
http_port=$(rr_next_port)
start_logged "$out_dir/origin-http.log" "$work/bench-origin" --port "$http_port" \
    --payload-dir "$work" --put-log "$work/http-put.jsonl"
origin_pid=$last_pid
# REALITY cover must be a real TLS 1.3 endpoint (plain HTTP silently breaks
# every REALITY handshake).
https_port=$(rr_next_port)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
    -keyout "$work/origin.key" -out "$work/origin.crt" >/dev/null 2>&1
start_logged "$out_dir/origin-https.log" "$work/bench-origin" --port "$https_port" \
    --payload-dir "$work" --put-log "$work/https-put.jsonl" \
    --tls-cert "$work/origin.crt" --tls-key "$work/origin.key"
https_origin_pid=$last_pid
wait_port "$http_port" "$origin_pid"
wait_port "$https_port" "$https_origin_pid"

# Per-implementation fake DNS + key material are scale-independent; servers
# and clients are rebuilt per scale point.
declare -A dns_port=() control_port=() server_port=() socks_port=()
declare -A public_key=() uuid=() short_id=()
"$rust_bin" config generate standalone --listen 127.0.0.1 --port 1 \
    --target "127.0.0.1:$https_port" --server-name localhost \
    >"$work/rust.base.json" 2>"$work/rust-generate.log"
public_key[rust]=$(sed -n 's/^REALITY public key for the client: //p' "$work/rust-generate.log")
uuid[rust]=$(jq -er '.inbounds[0].settings.clients[0].id' "$work/rust.base.json")
short_id[rust]=$(jq -er '.inbounds[0].settings.clients[0].shortIds[0]' "$work/rust.base.json")
"$xray" x25519 >"$work/xray.keys"
xray_private_key=$(sed -n 's/^PrivateKey: //p' "$work/xray.keys")
public_key[xray]=$(sed -n 's/^Password (PublicKey): //p' "$work/xray.keys")
uuid[xray]=$(python3 -c 'import uuid; print(uuid.uuid4())')
short_id[xray]=$(openssl rand -hex 8)
for impl in rust xray; do
    dns_port[$impl]=$(rr_next_port); control_port[$impl]=$(rr_next_port)
    server_port[$impl]=$(rr_next_port); socks_port[$impl]=$(rr_next_port)
    start_logged "$out_dir/fake-dns-$impl.log" python3 \
        "$repository/scripts/dns-fake-server.py" \
        --listen-port "${dns_port[$impl]}" --control-port "${control_port[$impl]}" --ttl 300
    wait_port "${control_port[$impl]}" "$last_pid"
    wait_port "${dns_port[$impl]}" "$last_pid" udp
done

build_server_config() { # <rust|xray> <rule-count> <output>
    local impl=$1 count=$2 output=$3 rules
    # Large rule counts exceed the single-argument length limit, so the
    # rule list travels through a file instead of --argjson.
    local rules_file="$work/rules-$count.json"
    python3 -c "import json,sys; json.dump([f'rule-{index}.routingbench' for index in range($count)], open(sys.argv[1],'w'))" "$rules_file"
    if [[ $impl == rust ]]; then
        jq --arg cache "$work/assets-rust" --arg dns "127.0.0.1:${dns_port[rust]}" \
            --argjson port "${server_port[rust]}" --slurpfile rules "$rules_file" \
            '.log.level="warn" | .assets.cacheDirectory=$cache
             | .inbounds[0].port=$port
             | .dns.servers=[$dns] | .routing.domainStrategy="AsIs"
             | .routing.globalRules=[$rules[0] | to_entries[]
                 | {name:("r" + (.key|tostring)), outbound:"direct", domain:[.value]}]' \
            "$work/rust.base.json" >"$output"
    else
        jq -n --arg uuid "${uuid[xray]}" --arg pk "$xray_private_key" --arg sid "${short_id[xray]}" \
            --argjson port "${server_port[xray]}" --argjson dns "${dns_port[xray]}" \
            --arg target "127.0.0.1:$https_port" --slurpfile rules "$rules_file" \
            '{log:{loglevel:"warning"},
              dns:{servers:[{address:"127.0.0.1",port:$dns}],queryStrategy:"UseIPv4"},
              inbounds:[{listen:"127.0.0.1",port:$port,protocol:"vless",
                settings:{clients:[{id:$uuid,flow:"xtls-rprx-vision"}],decryption:"none"},
                streamSettings:{network:"tcp",security:"reality",
                  realitySettings:{show:false,target:$target,xver:0,
                    serverNames:["localhost"],privateKey:$pk,shortIds:[$sid]}}}],
              outbounds:[{tag:"direct",protocol:"freedom",
                settings:{domainStrategy:"UseIP",finalRules:[{action:"allow"}]}}],
              routing:{domainStrategy:"AsIs",
                rules:[$rules[0] | to_entries[] | {type:"field",domain:[.value],outboundTag:"direct"}]}}' \
            >"$output"
    fi
}

results="$work/results.jsonl"
: >"$results"
for scale in $rule_scales; do
    target_name="rule-$((scale - 1)).routingbench"
    declare -A slot_pids=()
    for impl in rust xray; do
        build_server_config "$impl" "$scale" "$work/$impl.server.json"
        cp "$work/$impl.server.json" "$out_dir/server-config-$impl-$scale.json"
        jq -n --arg uuid "${uuid[$impl]}" --arg pk "${public_key[$impl]}" --arg sid "${short_id[$impl]}" \
            --argjson server "${server_port[$impl]}" --argjson socks "${socks_port[$impl]}" \
            '{log:{loglevel:"warning"},inbounds:[{listen:"127.0.0.1",port:$socks,protocol:"socks",settings:{auth:"noauth",udp:false}}],outbounds:[{protocol:"vless",settings:{vnext:[{address:"127.0.0.1",port:$server,users:[{id:$uuid,encryption:"none",flow:"xtls-rprx-vision"}]}]},streamSettings:{network:"tcp",security:"reality",realitySettings:{fingerprint:"chrome",serverName:"localhost",publicKey:$pk,shortId:$sid,spiderX:"/"}}}]}' \
            >"$work/$impl.client.json"
        cp "$work/$impl.client.json" "$out_dir/client-config-$impl-$scale.json"
        if [[ $impl == rust ]]; then
            start_logged "$out_dir/server-$impl-$scale.log" \
                "$rust_bin" serve --config "$work/$impl.server.json"
        else
            start_logged "$out_dir/server-$impl-$scale.log" \
                "$xray" run -config "$work/$impl.server.json"
        fi
        slot_pids[$impl-server]=$last_pid
        start_logged "$out_dir/client-$impl-$scale.log" \
            "$xray" run -config "$work/$impl.client.json"
        slot_pids[$impl-client]=$last_pid
        wait_port "${server_port[$impl]}" "${slot_pids[$impl-server]}"
        wait_port "${socks_port[$impl]}" "${slot_pids[$impl-client]}"
    done
    # Balanced interleave per scale: block 1 rust,xray — block 2 xray,rust,
    # alternating; SAMPLES measured rounds per slot.
    for ((block = 1; block <= blocks; block++)); do
        if ((block % 2 == 1)); then order="rust xray"; else order="xray rust"; fi
        for impl in $order; do
            # Warm-up: also primes the server-side DNS cache for the target
            # name, so measured rounds isolate rule evaluation.
            python3 "$work/driver.py" "${socks_port[$impl]}" "$http_port" 1 1 \
                "$target_name" >/dev/null
            for ((sample = 0; sample < samples; sample++)); do
                python3 "$work/driver.py" "${socks_port[$impl]}" "$http_port" \
                    "$concurrency" "$connections" "$target_name" >"$work/run.json"
                jq -nc --arg impl "$impl" --argjson scale "$scale" \
                    --argjson block "$block" --argjson sample "$sample" \
                    --arg name "$target_name" --argjson run "$(cat "$work/run.json")" \
                    '{implementation:$impl,ruleCount:$scale,block:$block,
                      sampleIndex:$sample,targetName:$name,run:$run}' >>"$results"
            done
        done
    done
    stop_pid "${slot_pids[rust-client]}"
    stop_pid "${slot_pids[rust-server]}"
    stop_pid "${slot_pids[xray-client]}"
    stop_pid "${slot_pids[xray-server]}"
    unset slot_pids
    declare -A slot_pids=()
done
cp "$results" "$out_dir/raw-samples.jsonl"

python3 - "$out_dir" <<'PY'
import json, pathlib, statistics, sys
root = pathlib.Path(sys.argv[1])
rows = [json.loads(line) for line in (root / "raw-samples.jsonl").read_text().splitlines()]


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


scales = {}
for scale in sorted({r["ruleCount"] for r in rows}):
    per_impl = {}
    for impl in ("rust", "xray"):
        subset = [r for r in rows if r["ruleCount"] == scale and r["implementation"] == impl]
        latencies = [v for r in subset for v in r["run"]["latenciesSeconds"]]
        rates = [r["run"]["requested"] / r["run"]["wallSeconds"] for r in subset]
        per_impl[impl] = {
            "samples": len(subset),
            "connections": len(latencies),
            "connectionsPerSecondMedian": statistics.median(rates),
            "p50Seconds": percentile(latencies, 0.50),
            "p95Seconds": percentile(latencies, 0.95),
            "p99Seconds": percentile(latencies, 0.99),
        }
    scales[str(scale)] = {
        **per_impl,
        "xrayVsRustP50LatencyRatio":
            per_impl["xray"]["p50Seconds"] / per_impl["rust"]["p50Seconds"],
        "rustVsXrayConnPerSecondRatio":
            per_impl["rust"]["connectionsPerSecondMedian"]
            / per_impl["xray"]["connectionsPerSecondMedian"],
    }
report = {
    "schemaVersion": 1,
    "harness": "benchmark-routing-comparison",
    "status": "COMPLETE",
    "performanceVerdict": "NOT_EVALUATED",
    "method": {
        "rules": "explicit domain rules, first-match, all -> direct outbound; no geosite/geoip files",
        "targetName": "rule-<N-1>.routingbench (LAST rule: worst-case full walk)",
        "dns": "loopback fake DNS, answer cached after warm-up; latency isolates rule evaluation",
        "client": "identical Xray SOCKS5 client; DOMAIN destination resolved server-side",
        "interleave": "balanced ABBA blocks per scale point",
    },
    "scales": scales,
    "limitations": [
        "single-host loopback includes the same Xray client, fake DNS, and origin in both paths",
        "rust-reality domain semantics match Xray plain-domain (exact + subdomain) conditions",
        "results are measurements of this host and are not a universal performance claim",
    ],
}
json.dump(report, open(root / "summary.json", "x"), indent=2)
print(json.dumps(report))
PY

rr_finalize_contract
printf 'routing comparison complete: %s\n' "$out_dir"
