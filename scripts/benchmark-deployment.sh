#!/usr/bin/env bash
# benchmark-deployment.sh — deployment-characterization harness for
# rust-reality 1.x. Measures what a deployer needs to know, not hot-path
# microbenchmarks:
#
#   routing   Routing correctness proof: 4 UUIDs in 2 user groups, direct /
#             blackhole / socks5 outbounds, global + per-group rules mixing
#             domain / geosite / IP / port matchers, a late-match rule, and a
#             restrictive default. Every (uuid, destination) case is verified
#             by byte content or by confirmed refusal -> PASS/FAIL per case.
#   cost      Routing decision cost: simple (1 UUID, no rules) / medium (100
#             UUIDs, 16+4 rules) / complex (1000 UUIDs, 64+8 rules) plus two
#             DNS variants (IPIfNonMatch, IPOnDemand) that force resolution by
#             using a domain destination. accept->first-payload p50/p95/p99
#             and connections/sec at c8/c32 via a raw-python SOCKS5 client.
#   nxr       Topologies A-D, same origin/payloads/logging/concurrency:
#             A  client -> rust-reality (VLESS+REALITY+Vision) -> direct origin
#             B  client -> rust-reality line -> NXR -> rust-reality landing -> origin
#             C  client -> rust-reality line -> SOCKS5 -> local SOCKS5 -> origin
#             D  client -> Xray line -> SOCKS5 -> same local SOCKS5 -> origin
#             Setup rate + CPU/connection + throughput at 32 MiB c1/c32 and
#             512 MiB c32, byte integrity per cell.
#   rtt       RTT sweep (only with REQUIRE_NETEM=1): the line<->landing hop is
#             moved onto a veth pair across a network namespace, shaped by
#             tc netem at 0/20/50/100 ms RTT, rerunning the B vs C setup
#             comparison. All host network state is recorded before/after and
#             restored (trap on EXIT/INT/TERM); every change is logged.
#   longflow  Long-flow relay verification: after NXR auth on the landing the
#             debug log must show a relay backend (expect splice) carrying the
#             steady state — splice can only run on a raw TCP boundary, so its
#             presence is log-level proof that no NXR/Vision framing persists
#             past authentication. The landing here is the ONLY server run at
#             debug level (connection_completed is a debug event); every other
#             server in this harness runs at warn.
#
# The SOCKS5 server used in C/D and in the routing proof is
# `deployment_driver.py socks-server` — a minimal threaded no-auth CONNECT
# server (stdlib Python, documented as the harness's local SOCKS5 server).
# In the routing proof it runs with --fixed-target (every CONNECT rewritten
# to origin B), so bytes arriving from origin B prove the socks5 outbound
# carried them regardless of the requested destination.
#
# Clients are unmodified Xray SOCKS5 entries (same pattern as
# scripts/benchmark-matrix.sh): one Xray client process per UUID / per
# server under test.
#
# Output in OUT_DIR (default benchmarks/final/deployment-<UTC timestamp>):
#   environment.json                binary sha256s, git sha, host, kernel
#   routing-correctness.jsonl       one record per (uuid, destination) case
#   summary-routing.json            routing PASS/FAIL verdict
#   setup-<label>.jsonl             setup-latency samples (JSONL)
#   tput-<label>-<mib>mib-c<n>.jsonl  throughput samples (JSONL)
#   cpu-<label>.json                server CPU seconds for the measured phase
#   perf-<label>.txt                perf stat output when perf is usable
#   summary-longflow.json           relay-backend verdict
#   rtt/netstate.txt + rtt/rtts.txt recorded netns/qdisc state (rtt section)
#   summary.json                    aggregated medians + overall verdict
#
# Env: RUST_REALITY_BIN (server under test, default target/release/rust-reality),
#      XRAY_BIN (default ../artifacts/xray-reference),
#      SECTIONS ("routing cost nxr longflow"; add "rtt" — it also needs
#      REQUIRE_NETEM=1), OUT_DIR, SMOKE (0; 1 = tiny-scale harness self-test),
#      SAMPLES (3), CONNS (96), CONCURRENCIES ("8 32"), TPUT_SAMPLES (3),
#      TPUT_CELLS ("32:1 32:32 512:32"), LONGFLOW_MIB (512),
#      RTTS ("0 20 50 100"), KEEP_WORK (0), REQUIRE_NETEM (0), TMPDIR
#      (optional external work root for generated payloads and secrets).
#
# Exit status: 0 when the run completed and every verdict is PASS, 1 when any
# section verdict is FAIL (gate semantics), 2 on harness misuse.
#
# Proxy hygiene: ALL_PROXY/HTTP_PROXY/HTTPS_PROXY/NO_PROXY (both cases) are
# unset for the whole process group at startup, and the python driver strips
# them again for every curl it spawns. Loopback traffic MUST go through the
# tunnel; if anything bypasses it, the byte-content checks fail loudly.
set -Eeuo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository"

# --------------------------------------------------------------------------
# Proxy hygiene: nothing spawned below may see a proxy variable.
# --------------------------------------------------------------------------
unset ALL_PROXY HTTP_PROXY HTTPS_PROXY NO_PROXY all_proxy http_proxy https_proxy no_proxy

rust_bin=${RUST_REALITY_BIN:-target/release/rust-reality}
xray=${XRAY_BIN:-../artifacts/xray-reference}
sections=${SECTIONS:-routing cost nxr longflow}
out_dir=${OUT_DIR:-benchmarks/final/deployment-$(date -u +%Y%m%dT%H%M%SZ)}
[[ ! -e $out_dir ]] || {
    echo "OUT_DIR already exists; refusing to overwrite evidence: $out_dir" >&2
    exit 2
}
smoke=${SMOKE:-0}
samples=${SAMPLES:-3}
conns=${CONNS:-96}
concurrencies=${CONCURRENCIES:-8 32}
tput_samples=${TPUT_SAMPLES:-3}
tput_cells=${TPUT_CELLS:-32:1 32:32 512:32}
longflow_mib=${LONGFLOW_MIB:-512}
rtts=${RTTS:-0 20 50 100}
require_netem=${REQUIRE_NETEM:-0}
driver="$repository/scripts/deployment_driver.py"

if [[ $smoke == 1 ]]; then
    samples=1
    conns=2
    concurrencies="8"
    tput_samples=1
    tput_cells="1:2"
    longflow_mib=1
    rtts="20"
fi

temporary_root=${TMPDIR:-$repository/benchmarks}
work=$(mktemp -d "$temporary_root/rust-reality-deployment.XXXXXX")
pids=()
ns_pidfiles=()
netns_name=""

log() { printf '[deployment %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

# --------------------------------------------------------------------------
# Cleanup: every spawned process, then network state, then the work dir.
# --------------------------------------------------------------------------
netns_teardown() {
    if [[ -n $netns_name ]]; then
        log "netns: tearing down $netns_name (veth pair is destroyed with it)"
        for pidfile in "${ns_pidfiles[@]:-}"; do
            [[ -f $pidfile ]] && kill "$(cat "$pidfile")" 2>/dev/null || true
        done
        sudo -n ip netns del "$netns_name" 2>/dev/null || true
        sudo -n ip link del veth-rd0 2>/dev/null || true
        netns_name=""
        log "netns: teardown done; remaining namespaces: $(sudo -n ip netns list 2>/dev/null)"
    fi
}

cleanup() {
    netns_teardown
    for pid in "${pids[@]:-}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    if [[ ${KEEP_WORK:-0} == 1 ]]; then
        log "work dir retained: $work"
    else
        rm -rf -- "$work"
    fi
}
trap cleanup EXIT INT TERM

for program in curl jq python3 go openssl sha256sum; do
    command -v "$program" >/dev/null || { echo "missing: $program" >&2; exit 2; }
done
[[ -x $rust_bin ]] || { echo "RUST_REALITY_BIN not executable: $rust_bin" >&2; exit 2; }
[[ -x $xray ]] || { echo "XRAY_BIN not executable: $xray" >&2; exit 2; }
rust_bin=$(readlink -f "$rust_bin")
xray=$(readlink -f "$xray")

mkdir -p "$out_dir"
log "servers log at warn level (longflow landing at debug, by design); out: $out_dir"

free_port() {
    python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_port() {
    python3 - "$1" "$2" "${3:-10}" <<'PY'
import socket, sys, time
host, port, budget = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
deadline = time.monotonic() + budget
while time.monotonic() < deadline:
    with socket.socket() as sock:
        sock.settimeout(0.2)
        if sock.connect_ex((host, port)) == 0:
            raise SystemExit(0)
    time.sleep(0.02)
raise SystemExit(f"port {host}:{port} did not become ready")
PY
}

# start_logged <logfile> <command...>: spawn with output captured to a file.
start_logged() {
    local logfile=$1; shift
    "$@" > "$logfile" 2>&1 &
    pids+=("$!")
}

# --------------------------------------------------------------------------
# CPU measurement: perf stat when usable, /proc/<pid>/stat deltas otherwise.
# --------------------------------------------------------------------------
cpu_method=proc
if command -v perf >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    if sudo -n perf stat -e task-clock -p $$ -- sleep 0.05 >/dev/null 2>&1; then
        cpu_method=perf
    fi
fi
log "CPU measurement method: $cpu_method"

proc_jiffies() {
    python3 - "$@" <<'PY'
import sys
total = 0
for pid in sys.argv[1:]:
    try:
        with open(f"/proc/{pid}/stat") as fh:
            rest = fh.read()
        fields = rest[rest.rfind(")") + 2:].split()
        total += int(fields[11]) + int(fields[12])  # utime + stime
    except (FileNotFoundError, IndexError, ValueError):
        pass
print(total)
PY
}

# run_measured <label> <pid...> -- <command...>
# Runs the command while measuring combined CPU of the given server pids.
run_measured() {
    local label=$1; shift
    local measure_pids=()
    while [[ $1 != -- ]]; do measure_pids+=("$1"); shift; done
    shift
    if [[ $cpu_method == perf ]]; then
        local joined ms
        joined=$(IFS=,; echo "${measure_pids[*]}")
        sudo -n perf stat -e task-clock -p "$joined" \
            -o "$out_dir/perf-$label.txt" -- "$@"
        ms=$(awk '/task-clock/ {gsub(",", "", $1); print $1; exit}' "$out_dir/perf-$label.txt")
        jq -n --arg label "$label" --arg method perf \
            --argjson seconds "$(python3 -c "print(${ms:-0} / 1000)")" \
            '{label: $label, method: $method, cpuSeconds: $seconds}' \
            > "$out_dir/cpu-$label.json"
    else
        local before after
        before=$(proc_jiffies "${measure_pids[@]}")
        "$@"
        after=$(proc_jiffies "${measure_pids[@]}")
        jq -n --arg label "$label" --arg method proc \
            --argjson seconds "$(python3 -c "print(($after - $before) / $(getconf CLK_TCK))")" \
            '{label: $label, method: $method, cpuSeconds: $seconds}' \
            > "$out_dir/cpu-$label.json"
    fi
}

# --------------------------------------------------------------------------
# Shared fixtures: payloads, plain origins A/B, TLS cover origin.
# --------------------------------------------------------------------------
http_port=$(free_port)      # origin A (shared by every section)
http_b_port=$(free_port)    # origin B (distinct bytes; routing proof)
https_port=$(free_port)     # TLS cover target for REALITY

needed_mibs="1 $longflow_mib"
for cell in $tput_cells; do needed_mibs+=" ${cell%%:*}"; done
python3 - "$work" $needed_mibs <<'PY'
import os
import sys
work = sys.argv[1]
chunk = bytes(range(256)) * 4096  # 1 MiB deterministic pattern
os.makedirs(f"{work}/payload-a")
os.makedirs(f"{work}/payload-b")
with open(f"{work}/payload-b/payload-1.bin", "wb") as fh:
    fh.write(bytes(255 - b for b in range(256)) * 4096)
# Tiny payload for setup-rate probes: the whole body fits one read, so the
# probe's close never resets a pending transfer.
with open(f"{work}/payload-a/payload-0.bin", "wb") as fh:
    fh.write(bytes(range(256)))
for mib in sorted({int(m) for m in sys.argv[2:]}):
    with open(f"{work}/payload-a/payload-{mib}.bin", "wb") as fh:
        for _ in range(mib):
            fh.write(chunk)
PY

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/cover.key" \
    -out "$work/cover.crt" -days 1 -subj "/CN=localhost" >/dev/null 2>&1
(cd scripts/bench-origin && go build -buildvcs=false -o "$work/bench-origin" .)
start_logged "$work/origin-a.log" "$work/bench-origin" --port "$http_port" \
    --payload-dir "$work/payload-a" --put-log "$work/put-a.jsonl"
start_logged "$work/origin-b.log" "$work/bench-origin" --port "$http_b_port" \
    --payload-dir "$work/payload-b" --put-log "$work/put-b.jsonl"
start_logged "$work/origin-cover.log" "$work/bench-origin" --port "$https_port" \
    --payload-dir "$work/payload-a" --put-log "$work/put-cover.jsonl" \
    --tls-cert "$work/cover.crt" --tls-key "$work/cover.key"
wait_port 127.0.0.1 "$http_port"
wait_port 127.0.0.1 "$http_b_port"
wait_port 127.0.0.1 "$https_port"

payload_sha() { sha256sum "$work/payload-a/payload-$1.bin" | cut -d' ' -f1; }
sha_b_1=$(sha256sum "$work/payload-b/payload-1.bin" | cut -d' ' -f1)

# --------------------------------------------------------------------------
# Config / process helpers. These set globals instead of echoing so the pids
# array is mutated in the current shell (command substitution would lose it).
# --------------------------------------------------------------------------

# generate_base <port> <prefix> -> <prefix>.base.json + <prefix>.base.env
generate_base() {
    local port=$1 prefix=$2
    "$rust_bin" config generate standalone --listen 127.0.0.1 --port "$port" \
        --target "127.0.0.1:$https_port" --server-name localhost \
        > "$prefix.base.json" 2> "$prefix.generate.log"
    {
        sed -n 's/^REALITY public key for the client: /PUBLIC_KEY=/p' "$prefix.generate.log"
        jq -r '"SHORT_ID=" + .inbounds[0].settings.clients[0].shortIds[0]' \
            "$prefix.base.json"
    } > "$prefix.base.env"
}

# make_client <server_port> <socks_port> <public_key> <uuid> <short_id> <output>
make_client() {
    jq -n \
        --argjson server_port "$1" --argjson socks_port "$2" \
        --arg public_key "$3" --arg uuid "$4" --arg short_id "$5" \
        '{
          log: {loglevel: "warning"},
          inbounds: [{
            listen: "127.0.0.1",
            port: $socks_port,
            protocol: "socks",
            settings: {auth: "noauth", udp: false}
          }],
          outbounds: [{
            protocol: "vless",
            settings: {vnext: [{
              address: "127.0.0.1",
              port: $server_port,
              users: [{id: $uuid, encryption: "none", flow: "xtls-rprx-vision"}]
            }]},
            streamSettings: {
              network: "tcp",
              security: "reality",
              realitySettings: {
                fingerprint: "chrome",
                serverName: "localhost",
                publicKey: $public_key,
                shortId: $short_id,
                spiderX: "/"
              }
            }
          }]
        }' > "$6"
}

# start_server <config> <label> [wait budget] -> sets SERVER_PID
SERVER_PID=""
start_server() {
    local config=$1 label=$2 budget=${3:-30}
    "$rust_bin" check --config "$config" >/dev/null
    start_logged "$work/server-$label.log" "$rust_bin" serve --config "$config"
    SERVER_PID=${pids[-1]}
    if ! wait_port 127.0.0.1 "$(jq -r '.inbounds[0].port' "$config")" "$budget"; then
        tail -20 "$work/server-$label.log" >&2
        return 1
    fi
}

# start_nxr_landing <config> <label> <port> -> sets SERVER_PID
start_nxr_landing() {
    local config=$1 label=$2 port=$3
    "$rust_bin" check --config "$config" >/dev/null
    start_logged "$work/server-$label.log" "$rust_bin" serve --config "$config"
    SERVER_PID=${pids[-1]}
    wait_port 127.0.0.1 "$port"
}

# start_client <server_port> <public_key> <uuid> <short_id> <label>
#   -> sets CLIENT_SOCKS
CLIENT_SOCKS=""
start_client() {
    local server_port=$1 public_key=$2 uuid=$3 short_id=$4 label=$5
    CLIENT_SOCKS=$(free_port)
    make_client "$server_port" "$CLIENT_SOCKS" "$public_key" "$uuid" "$short_id" \
        "$work/client-$label.json"
    start_logged "$work/client-$label.log" "$xray" run -config "$work/client-$label.json"
    if ! wait_port 127.0.0.1 "$CLIENT_SOCKS" 30; then
        tail -20 "$work/client-$label.log" >&2
        return 1
    fi
}

# ==========================================================================
# Section 1: routing correctness proof.
# ==========================================================================
section_routing() {
    log "section routing: building 4-UUID / 2-group proof config"
    local server_port socks_b_port blocked_port=9666
    server_port=$(free_port)
    socks_b_port=$(free_port)

    # Fixed-target SOCKS5: every CONNECT is rewritten to origin B, so bytes
    # from origin B prove the via-socks-b outbound carried them.
    start_logged "$work/socks-b.log" python3 "$driver" socks-server \
        --port "$socks_b_port" --fixed-target "127.0.0.1:$http_b_port"
    wait_port 127.0.0.1 "$socks_b_port"

    # Geo assets: the community DATs are fetched once per repository into a
    # shared cache and copied into this run's asset dir together with their
    # validator metadata, so the server's startup revalidation is a fast
    # conditional request (304) — and a dead network degrades to the cache
    # within requestTimeoutSeconds. The geosite proof domain is extracted
    # from the real DAT.
    local asset_cache="$repository/benchmarks/.asset-cache"
    mkdir -p "$asset_cache" "$work/assets-routing"
    local dat url
    for dat in geosite geoip; do
        url="https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/$dat.dat"
        if [[ ! -s $asset_cache/$dat.dat ]]; then
            log "section routing: downloading $dat.dat (one-time, community asset)"
            curl -fSs --retry 3 -D "$asset_cache/$dat.headers" \
                -o "$asset_cache/$dat.dat" "$url"
            local etag last_modified
            etag=$(sed -n 's/^[Ee][Tt][Aa][Gg]: //p' "$asset_cache/$dat.headers" | tr -d '\r' | head -1)
            last_modified=$(sed -n 's/^[Ll]ast-[Mm]odified: //p' "$asset_cache/$dat.headers" | tr -d '\r' | head -1)
            jq -n --arg source "$url" --arg etag "$etag" --arg lm "$last_modified" \
                '{source: $source}
                 + (if $etag == "" then {} else {etag: $etag} end)
                 + (if $lm == "" then {} else {last_modified: $lm} end)' \
                > "$asset_cache/$dat.dat.metadata.json"
        fi
        cp "$asset_cache/$dat.dat" "$work/assets-routing/$dat.dat"
        [[ -f $asset_cache/$dat.dat.metadata.json ]] && \
            cp "$asset_cache/$dat.dat.metadata.json" "$work/assets-routing/$dat.dat.metadata.json"
    done
    local geo_label geo_domain
    read -r geo_label geo_domain < <(
        python3 "$driver" pick-domain --dat "$work/assets-routing/geosite.dat" \
            --labels google,github,microsoft,apple,cloudflare,bing)
    log "section routing: geosite proof uses geosite:$geo_label via $geo_domain"

    mapfile -t uuids < <("$rust_bin" uuid 4)
    generate_base "$server_port" "$work/routing"
    python3 "$driver" gen-routing-config \
        --base "$work/routing.base.json" \
        --uuids "$(IFS=,; echo "${uuids[*]}")" \
        --origin-a-port "$http_port" \
        --socks-b-port "$socks_b_port" \
        --blocked-port "$blocked_port" \
        --geosite-label "$geo_label" \
        --assets "$work/assets-routing" \
        --log-level warn \
        --out "$work/routing.json"
    # shellcheck disable=SC1090
    source "$work/routing.base.env"
    start_server "$work/routing.json" routing 60
    local server_pid=$SERVER_PID

    # One Xray SOCKS entry per UUID, using the short ID owned by that UUID.
    local socks_ports=() routing_short_ids=() i
    mapfile -t routing_short_ids < <(
        jq -r '.inbounds[0].settings.clients[].shortIds[0]' "$work/routing.json"
    )
    if (( ${#routing_short_ids[@]} != ${#uuids[@]} )); then
        echo "routing config did not assign one client short ID per UUID" >&2
        return 1
    fi
    for i in 0 1 2 3; do
        start_client "$server_port" "$PUBLIC_KEY" "${uuids[$i]}" \
            "${routing_short_ids[$i]}" "routing-$i"
        socks_ports+=("$CLIENT_SOCKS")
    done

    # Case matrix. alpha (uuid 0/1): default block, allows origin A by
    # domain+port and by ip+port, late-match loopback block. beta (uuid 2/3):
    # geoip:private block, default via-socks-b.
    python3 - "$work/routing-plan.json" \
        "$http_port" "$http_b_port" "$blocked_port" "$geo_domain" \
        "$(payload_sha 1)" "$sha_b_1" \
        "${uuids[0]}" "${socks_ports[0]}" "${uuids[1]}" "${socks_ports[1]}" \
        "${uuids[2]}" "${socks_ports[2]}" "${uuids[3]}" "${socks_ports[3]}" <<'PY'
import json
import sys

(out, pa, pb, blocked_port, geo_domain, sha_a, sha_b,
 ua, sa, ua2, sa2, ub, sb, ub2, sb2) = sys.argv[1:16]
pa, pb, blocked_port = int(pa), int(pb), int(blocked_port)


def case(uuid, socks, group, label, host, port, expect):
    return {"uuid": uuid, "socksPort": int(socks), "group": group,
            "label": label, "host": host, "port": port,
            "path": "/payload-1.bin", "expect": expect}


cases = []
for uuid, socks in ((ua, sa), (ua2, sa2)):
    cases += [
        case(uuid, socks, "alpha", "allow-domain-port-rule", "localhost", pa, sha_a),
        case(uuid, socks, "alpha", "allow-ip-port-rule", "127.0.0.1", pa, sha_a),
        case(uuid, socks, "alpha", "late-match-loopback-block", "127.0.0.1", pb, "blocked"),
        case(uuid, socks, "alpha", "global-port-block", "127.0.0.1", blocked_port, "blocked"),
        case(uuid, socks, "alpha", "global-domain-block", "blocked.example", 80, "blocked"),
        case(uuid, socks, "alpha", "global-geosite-block", geo_domain, 80, "blocked"),
        case(uuid, socks, "alpha", "group-default-block", "198.51.100.23", 80, "blocked"),
    ]
# 8.8.8.8 is the certainly-public destination: it is never in geoip:private,
# and a direct dial to it is never attempted because the fixed-target socks
# server rewrites the CONNECT to origin B.
for uuid, socks in ((ub, sb), (ub2, sb2)):
    cases += [
        case(uuid, socks, "beta", "default-via-socks-b", "8.8.8.8", 80, sha_b),
        case(uuid, socks, "beta", "group-geoip-private-block-loopback", "127.0.0.1", pb, "blocked"),
        case(uuid, socks, "beta", "group-geoip-private-block-rfc1918", "10.255.255.1", pa, "blocked"),
        case(uuid, socks, "beta", "global-domain-block", "blocked.example", 80, "blocked"),
        case(uuid, socks, "beta", "global-geosite-block", geo_domain, 80, "blocked"),
        case(uuid, socks, "beta", "global-port-block", "8.8.8.8", blocked_port, "blocked"),
    ]
with open(out, "w") as fh:
    json.dump({"cases": cases}, fh)
PY

    if python3 "$driver" route-probe --plan "$work/routing-plan.json" \
        --out "$out_dir/routing-correctness.jsonl" \
        --summary "$out_dir/summary-routing.json"; then
        log "section routing: PASS"
    else
        log "section routing: FAIL (see routing-correctness.jsonl)"
    fi
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
}

# ==========================================================================
# Section 2: routing decision cost.
# ==========================================================================
section_cost() {
    log "section cost: simple/medium/complex + DNS variants"
    # name uuids rules global strategy dest with_ip
    local variants=(
        "simple 1 0 0 AsIs 127.0.0.1 no"
        "medium 100 16 4 AsIs 127.0.0.1 yes"
        "complex 1000 64 8 AsIs 127.0.0.1 yes"
        "complex-ipifnonmatch 1000 64 8 IPIfNonMatch localhost yes"
        "complex-ipondemand 1000 64 8 IPOnDemand localhost yes"
    )
    local variant
    for variant in "${variants[@]}"; do
        read -r name nuuids nrules nglobal strategy dest with_ip <<< "$variant"
        log "section cost: $name (uuids=$nuuids rules=$nrules+$nglobal strategy=$strategy dest=$dest)"
        local server_port
        server_port=$(free_port)
        "$rust_bin" uuid "$nuuids" > "$work/cost-$name.uuids"
        generate_base "$server_port" "$work/cost-$name"
        local with_ip_flag=()
        [[ $with_ip == yes ]] && with_ip_flag=(--with-ip)
        local measured_uuid
        measured_uuid=$(python3 "$driver" gen-scale-config \
            --base "$work/cost-$name.base.json" \
            --uuid-file "$work/cost-$name.uuids" \
            --uuids "$nuuids" --rules "$nrules" --global-rules "$nglobal" \
            "${with_ip_flag[@]}" --strategy "$strategy" \
            --assets "$work/assets-cost-$name" --log-level warn \
            --out "$work/cost-$name.json")
        # shellcheck disable=SC1090
        source "$work/cost-$name.base.env"
        start_server "$work/cost-$name.json" "cost-$name" 30
        local server_pid=$SERVER_PID
        start_client "$server_port" "$PUBLIC_KEY" "$measured_uuid" "$SHORT_ID" "cost-$name"
        local socks_port=$CLIENT_SOCKS
        run_measured "cost-$name" "$server_pid" -- \
            python3 "$driver" setup-rate --path /payload-0.bin --label "cost-$name" \
                --socks-port "$socks_port" --host "$dest" --port "$http_port" \
                --samples "$samples" --conns "$conns" \
                --concurrencies "$concurrencies" \
                --out "$out_dir/setup-cost-$name.jsonl"
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    done
}

# ==========================================================================
# Section 3: NXR topologies A-D.
# ==========================================================================
section_nxr() {
    log "section nxr: A (direct) B (NXR line+landing) C (line+socks5) D (xray line+socks5)"
    local nxr_key
    nxr_key=$("$rust_bin" node-keygen | jq -r .preSharedKey)

    # --- A: standalone -> direct -------------------------------------------
    local port_a
    port_a=$(free_port)
    generate_base "$port_a" "$work/topo-a"
    jq --arg cache "$work/assets-a" \
        '.log.level = "warn" | .assets.cacheDirectory = $cache' \
        "$work/topo-a.base.json" > "$work/topo-a.json"

    # --- B: line -> NXR -> landing -> origin --------------------------------
    local port_line_b port_landing
    port_line_b=$(free_port)
    port_landing=$(free_port)
    "$rust_bin" config generate line --listen 127.0.0.1 --port "$port_line_b" \
        --target "127.0.0.1:$https_port" --server-name localhost \
        --nxr-address 127.0.0.1 --nxr-port "$port_landing" --nxr-key "$nxr_key" \
        > "$work/topo-b.line.base.json" 2> "$work/topo-b.line.generate.log"
    jq --arg cache "$work/assets-b-line" \
        '.log.level = "warn" | .assets.cacheDirectory = $cache' \
        "$work/topo-b.line.base.json" > "$work/topo-b.line.json"
    "$rust_bin" config generate landing --listen 127.0.0.1 --port "$port_landing" \
        --nxr-key "$nxr_key" 2>/dev/null | \
        jq --arg cache "$work/assets-b-landing" \
            '.log.level = "warn" | .assets.cacheDirectory = $cache' \
        > "$work/topo-b.landing.json"

    # --- C: line -> socks5 -> local SOCKS5 -> origin ------------------------
    local port_line_c port_socks_t
    port_line_c=$(free_port)
    port_socks_t=$(free_port)
    "$rust_bin" config generate line --listen 127.0.0.1 --port "$port_line_c" \
        --target "127.0.0.1:$https_port" --server-name localhost \
        --nxr-address 127.0.0.1 --nxr-port 9 --nxr-key "$nxr_key" \
        > "$work/topo-c.line.base.json" 2> "$work/topo-c.line.generate.log"
    jq --arg cache "$work/assets-c-line" --argjson sport "$port_socks_t" \
        '.log.level = "warn" | .assets.cacheDirectory = $cache
         | .outbounds += [{protocol: "socks5", tag: "via-socks",
                           settings: {address: "127.0.0.1", port: $sport}}]
         | .routing.users[0].defaultOutbound = "via-socks"' \
        "$work/topo-c.line.base.json" > "$work/topo-c.line.json"
    # Transparent local SOCKS5 forwarder (driver socks-server, stdlib Python).
    start_logged "$work/socks-transparent.log" python3 "$driver" socks-server \
        --port "$port_socks_t"

    # --- D: xray line -> socks5 -> same SOCKS5 -> origin --------------------
    local port_line_d
    port_line_d=$(free_port)
    "$xray" x25519 > "$work/topo-d.keys"
    local xpriv xpub xuuid xsid="0123456789abcdef"
    xpriv=$(sed -n 's/^PrivateKey: //p' "$work/topo-d.keys")
    xpub=$(sed -n 's/^Password (PublicKey): //p' "$work/topo-d.keys")
    xuuid=$("$rust_bin" uuid 1)
    jq -n --arg uuid "$xuuid" --arg pk "$xpriv" --arg sid "$xsid" \
        --arg target "127.0.0.1:$https_port" --argjson port "$port_line_d" \
        --argjson sport "$port_socks_t" \
        '{log: {loglevel: "warning"},
          inbounds: [{listen: "127.0.0.1", port: $port, protocol: "vless",
            settings: {clients: [{id: $uuid, flow: "xtls-rprx-vision"}], decryption: "none"},
            streamSettings: {network: "tcp", security: "reality",
              realitySettings: {show: false, target: $target, xver: 0,
                serverNames: ["localhost"], privateKey: $pk, shortIds: [$sid]}}}],
          outbounds: [{protocol: "socks",
            settings: {servers: [{address: "127.0.0.1", port: $sport}]}}]}' \
        > "$work/topo-d.xray.json"

    # --- start everything ----------------------------------------------------
    start_server "$work/topo-a.json" topo-a
    local pid_a=$SERVER_PID
    start_server "$work/topo-b.line.json" topo-b-line
    local pid_line_b=$SERVER_PID
    start_nxr_landing "$work/topo-b.landing.json" topo-b-landing "$port_landing"
    local pid_landing=$SERVER_PID
    start_server "$work/topo-c.line.json" topo-c-line
    local pid_line_c=$SERVER_PID
    start_logged "$work/server-topo-d.log" "$xray" run -config "$work/topo-d.xray.json"
    local pid_line_d=${pids[-1]}
    wait_port 127.0.0.1 "$port_line_d"
    wait_port 127.0.0.1 "$port_socks_t"

    # shellcheck disable=SC1090
    source "$work/topo-a.base.env"
    local pub_a=$PUBLIC_KEY sid_a=$SHORT_ID uuid_a
    uuid_a=$(jq -r '.inbounds[0].settings.clients[0].id' "$work/topo-a.base.json")
    local pub_b sid_b uuid_b pub_c sid_c uuid_c
    pub_b=$(sed -n 's/^REALITY public key for the client: //p' "$work/topo-b.line.generate.log")
    sid_b=$(jq -r '.inbounds[0].settings.clients[0].shortIds[0]' "$work/topo-b.line.base.json")
    uuid_b=$(jq -r '.inbounds[0].settings.clients[0].id' "$work/topo-b.line.base.json")
    pub_c=$(sed -n 's/^REALITY public key for the client: //p' "$work/topo-c.line.generate.log")
    sid_c=$(jq -r '.inbounds[0].settings.clients[0].shortIds[0]' "$work/topo-c.line.base.json")
    uuid_c=$(jq -r '.inbounds[0].settings.clients[0].id' "$work/topo-c.line.base.json")

    start_client "$port_a" "$pub_a" "$uuid_a" "$sid_a" topo-a
    local socks_a=$CLIENT_SOCKS
    start_client "$port_line_b" "$pub_b" "$uuid_b" "$sid_b" topo-b
    local socks_b=$CLIENT_SOCKS
    start_client "$port_line_c" "$pub_c" "$uuid_c" "$sid_c" topo-c
    local socks_c=$CLIENT_SOCKS
    start_client "$port_line_d" "$xpub" "$xuuid" "$xsid" topo-d
    local socks_d=$CLIENT_SOCKS

    # --- setup rate + CPU/connection -----------------------------------------
    run_measured "topo-a" "$pid_a" -- \
        python3 "$driver" setup-rate --path /payload-0.bin --label topo-a --socks-port "$socks_a" \
            --host 127.0.0.1 --port "$http_port" --samples "$samples" \
            --conns "$conns" --concurrencies "$concurrencies" \
            --out "$out_dir/setup-topo-a.jsonl"
    run_measured "topo-b" "$pid_line_b" "$pid_landing" -- \
        python3 "$driver" setup-rate --path /payload-0.bin --label topo-b --socks-port "$socks_b" \
            --host 127.0.0.1 --port "$http_port" --samples "$samples" \
            --conns "$conns" --concurrencies "$concurrencies" \
            --out "$out_dir/setup-topo-b.jsonl"
    run_measured "topo-c" "$pid_line_c" -- \
        python3 "$driver" setup-rate --path /payload-0.bin --label topo-c --socks-port "$socks_c" \
            --host 127.0.0.1 --port "$http_port" --samples "$samples" \
            --conns "$conns" --concurrencies "$concurrencies" \
            --out "$out_dir/setup-topo-c.jsonl"
    run_measured "topo-d" "$pid_line_d" -- \
        python3 "$driver" setup-rate --path /payload-0.bin --label topo-d --socks-port "$socks_d" \
            --host 127.0.0.1 --port "$http_port" --samples "$samples" \
            --conns "$conns" --concurrencies "$concurrencies" \
            --out "$out_dir/setup-topo-d.jsonl"

    # --- throughput cells with byte integrity --------------------------------
    local cell mib conc topo
    for cell in $tput_cells; do
        mib=${cell%%:*}
        conc=${cell##*:}
        for topo in a b c d; do
            local socks_var="socks_$topo"
            python3 "$driver" throughput --label "topo-$topo" \
                --socks-port "${!socks_var}" \
                --url "http://127.0.0.1:$http_port/payload-$mib.bin" \
                --mib "$mib" --samples "$tput_samples" \
                --concurrencies "$conc" --expected-sha256 "$(payload_sha "$mib")" \
                --out "$out_dir/tput-topo-$topo-${mib}mib-c${conc}.jsonl"
        done
    done
}

# ==========================================================================
# Section 4: RTT sweep behind netem (REQUIRE_NETEM=1 only).
# ==========================================================================
section_rtt() {
    if [[ $require_netem != 1 ]]; then
        log "section rtt: SKIPPED (requires REQUIRE_NETEM=1; it modifies host network state)"
        return 0
    fi
    log "section rtt: REQUIRE_NETEM=1 — creating a namespace pair; every host change is logged"
    local tc
    tc=$(command -v tc || echo /sbin/tc)
    [[ -x $tc ]] || { echo "rtt section needs tc (iproute2)" >&2; return 1; }
    for tool in ping setpriv; do
        command -v "$tool" >/dev/null || { echo "rtt section needs: $tool" >&2; return 1; }
    done
    sudo -n true || { echo "rtt section needs passwordless sudo (netns/tc only)" >&2; return 1; }
    netns_name="rrdeploy-gate"
    if sudo -n ip netns list | grep -qx "$netns_name"; then
        echo "netns $netns_name already exists; refusing to touch it" >&2
        return 1
    fi

    local state="$out_dir/rtt"
    mkdir -p "$state"
    {
        echo "=== before: ip netns list"; sudo -n ip netns list
        echo "=== before: tc qdisc show"; sudo -n "$tc" qdisc show
        echo "=== before: ip link show"; sudo -n ip link show
    } | tee "$state/netstate.txt"

    log "netns: ip netns add $netns_name"
    sudo -n ip netns add "$netns_name"
    log "netns: veth pair veth-rd0 (host, 10.203.0.1/30) <-> veth-rd1 ($netns_name, 10.203.0.2/30)"
    sudo -n ip link add veth-rd0 type veth peer name veth-rd1
    sudo -n ip link set veth-rd1 netns "$netns_name"
    sudo -n ip addr add 10.203.0.1/30 dev veth-rd0
    sudo -n ip link set veth-rd0 up
    sudo -n ip netns exec "$netns_name" ip addr add 10.203.0.2/30 dev veth-rd1
    sudo -n ip netns exec "$netns_name" ip link set veth-rd1 up
    sudo -n ip netns exec "$netns_name" ip link set lo up

    # start_ns_process <pidfile> <logfile> <command...>: the sudo/netns entry
    # is dropped back to the invoking user by setpriv before exec — no server
    # runs as root.
    start_ns_process() {
        local pidfile=$1 logfile=$2; shift 2
        sudo -n ip netns exec "$netns_name" \
            setpriv --reuid "$(id -u)" --regid "$(id -g)" --clear-groups \
            bash -c 'echo $$ > "$1"; shift; exec "$@"' _ "$pidfile" "$@" \
            > "$logfile" 2>&1 &
        pids+=("$!")
        ns_pidfiles+=("$pidfile")
    }

    # wait_ns_port <port>: probe the namespace loopback from inside (the host
    # cannot see it).
    wait_ns_port() {
        local attempt
        for attempt in $(seq 1 100); do
            if sudo -n ip netns exec "$netns_name" \
                bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null; then
                return 0
            fi
            sleep 0.1
        done
        echo "namespace port 127.0.0.1:$1 did not become ready" >&2
        return 1
    }

    # Origin, landing, and transparent SOCKS5 all live inside the namespace,
    # so the landing->origin leg stays on the namespace loopback and only the
    # line<->landing hop crosses the shaped veth pair. Measurement requests
    # address the origin as 127.0.0.1:<port>: the line node forwards that
    # destination and the in-namespace hop resolves it on ITS loopback.
    local ns_origin_port ns_landing_port ns_socks_port
    ns_origin_port=$(free_port)
    ns_landing_port=$(free_port)
    ns_socks_port=$(free_port)
    start_ns_process "$work/ns-origin.pid" "$work/ns-origin.log" "$work/bench-origin" \
        --port "$ns_origin_port" --payload-dir "$work/payload-a" \
        --put-log "$work/put-ns.jsonl"
    local nxr_key
    nxr_key=$("$rust_bin" node-keygen | jq -r .preSharedKey)
    "$rust_bin" config generate landing --listen 0.0.0.0 --port "$ns_landing_port" \
        --nxr-key "$nxr_key" 2>/dev/null | \
        jq --arg cache "$work/assets-rtt-landing" \
            '.log.level = "warn" | .assets.cacheDirectory = $cache' \
        > "$work/rtt.landing.json"
    start_ns_process "$work/ns-landing.pid" "$work/ns-landing.log" \
        "$rust_bin" serve --config "$work/rtt.landing.json"
    start_ns_process "$work/ns-socks.pid" "$work/ns-socks.log" python3 "$driver" \
        socks-server --port "$ns_socks_port"
    wait_ns_port "$ns_origin_port"
    wait_port 10.203.0.2 "$ns_landing_port" 20
    wait_port 10.203.0.2 "$ns_socks_port" 20

    # Line B: NXR into the namespace; line C: SOCKS5 into the namespace.
    local port_line_b port_line_c
    port_line_b=$(free_port)
    port_line_c=$(free_port)
    "$rust_bin" config generate line --listen 127.0.0.1 --port "$port_line_b" \
        --target "127.0.0.1:$https_port" --server-name localhost \
        --nxr-address 10.203.0.2 --nxr-port "$ns_landing_port" --nxr-key "$nxr_key" \
        2> "$work/rtt-b.generate.log" | \
        jq --arg cache "$work/assets-rtt-b" \
            '.log.level = "warn" | .assets.cacheDirectory = $cache' \
        > "$work/rtt-b.line.json"
    "$rust_bin" config generate line --listen 127.0.0.1 --port "$port_line_c" \
        --target "127.0.0.1:$https_port" --server-name localhost \
        --nxr-address 10.203.0.2 --nxr-port 9 --nxr-key "$nxr_key" \
        2> "$work/rtt-c.generate.log" | \
        jq --arg cache "$work/assets-rtt-c" --argjson sport "$ns_socks_port" \
            '.log.level = "warn" | .assets.cacheDirectory = $cache
             | .outbounds += [{protocol: "socks5", tag: "via-socks",
                               settings: {address: "10.203.0.2", port: $sport}}]
             | .routing.users[0].defaultOutbound = "via-socks"' \
        > "$work/rtt-c.line.json"

    start_server "$work/rtt-b.line.json" rtt-b-line
    start_server "$work/rtt-c.line.json" rtt-c-line
    local pub_b sid_b uuid_b pub_c sid_c uuid_c
    pub_b=$(sed -n 's/^REALITY public key for the client: //p' "$work/rtt-b.generate.log")
    sid_b=$(jq -r '.inbounds[0].settings.clients[0].shortIds[0]' "$work/rtt-b.line.json")
    uuid_b=$(jq -r '.inbounds[0].settings.clients[0].id' "$work/rtt-b.line.json")
    pub_c=$(sed -n 's/^REALITY public key for the client: //p' "$work/rtt-c.generate.log")
    sid_c=$(jq -r '.inbounds[0].settings.clients[0].shortIds[0]' "$work/rtt-c.line.json")
    uuid_c=$(jq -r '.inbounds[0].settings.clients[0].id' "$work/rtt-c.line.json")
    start_client "$port_line_b" "$pub_b" "$uuid_b" "$sid_b" rtt-b
    local socks_b=$CLIENT_SOCKS
    start_client "$port_line_c" "$pub_c" "$uuid_c" "$sid_c" rtt-c
    local socks_c=$CLIENT_SOCKS

    local rtt half observed
    for rtt in $rtts; do
        half=$((rtt / 2))
        log "netns: tc qdisc replace dev veth-rd0/veth-rd1 root netem delay ${half}ms (target RTT ${rtt}ms)"
        sudo -n "$tc" qdisc replace dev veth-rd0 root netem delay "${half}ms"
        sudo -n ip netns exec "$netns_name" "$tc" qdisc replace dev veth-rd1 root netem delay "${half}ms"
        observed=$(ping -n -c 3 -i 0.2 -w 5 10.203.0.2 | awk -F'/' '/^rtt/ {print $5}')
        log "netns: measured RTT ${observed:-?} ms (target ${rtt} ms)"
        echo "rtt=$rtt half_delay_ms=$half observed_rtt_ms=$observed" >> "$state/rtts.txt"
        python3 "$driver" setup-rate --path /payload-0.bin --label "rtt${rtt}-nxr" \
            --socks-port "$socks_b" --host 127.0.0.1 --port "$ns_origin_port" \
            --samples "$samples" --conns "$conns" \
            --concurrencies "$concurrencies" \
            --out "$out_dir/setup-rtt${rtt}-nxr.jsonl"
        python3 "$driver" setup-rate --path /payload-0.bin --label "rtt${rtt}-socks" \
            --socks-port "$socks_c" --host 127.0.0.1 --port "$ns_origin_port" \
            --samples "$samples" --conns "$conns" \
            --concurrencies "$concurrencies" \
            --out "$out_dir/setup-rtt${rtt}-socks.jsonl"
    done

    echo "=== after: tc qdisc show (before teardown)" | tee -a "$state/netstate.txt"
    sudo -n "$tc" qdisc show | tee -a "$state/netstate.txt"
    netns_teardown
    {
        echo "=== after: ip netns list"; sudo -n ip netns list
        echo "=== after: ip link show"; sudo -n ip link show
    } | tee -a "$state/netstate.txt"
}

# ==========================================================================
# Section 5: long-flow relay verification. The landing runs at debug level —
# the only debug server in this harness — because the evidence events are
# debug events. The landing is NOT port-probed (a bare TCP probe would be an
# NXR auth failure and pollute the rejection evidence); readiness comes from
# its listener_started log line.
# ==========================================================================
section_longflow() {
    log "section longflow: NXR landing relay-backend evidence (${longflow_mib} MiB flow)"
    local nxr_key port_line port_landing
    nxr_key=$("$rust_bin" node-keygen | jq -r .preSharedKey)
    port_line=$(free_port)
    port_landing=$(free_port)
    "$rust_bin" config generate line --listen 127.0.0.1 --port "$port_line" \
        --target "127.0.0.1:$https_port" --server-name localhost \
        --nxr-address 127.0.0.1 --nxr-port "$port_landing" --nxr-key "$nxr_key" \
        > "$work/lf.line.base.json" 2> "$work/lf.line.generate.log"
    jq --arg cache "$work/assets-lf-line" \
        '.log.level = "warn" | .assets.cacheDirectory = $cache' \
        "$work/lf.line.base.json" > "$work/lf.line.json"
    "$rust_bin" config generate landing --listen 127.0.0.1 --port "$port_landing" \
        --nxr-key "$nxr_key" 2>/dev/null | \
        jq --arg cache "$work/assets-lf-landing" \
            '.log.level = "debug" | .assets.cacheDirectory = $cache' \
        > "$work/lf.landing.json"

    start_server "$work/lf.line.json" lf-line
    "$rust_bin" check --config "$work/lf.landing.json" >/dev/null
    start_logged "$work/server-lf-landing.log" "$rust_bin" serve --config "$work/lf.landing.json"
    local pid_landing=${pids[-1]}
    local attempt
    for attempt in $(seq 1 100); do
        grep -q '"event":"listener_started"' "$work/server-lf-landing.log" 2>/dev/null && break
        sleep 0.1
    done

    local pub sid uuid
    pub=$(sed -n 's/^REALITY public key for the client: //p' "$work/lf.line.generate.log")
    sid=$(jq -r '.inbounds[0].settings.clients[0].shortIds[0]' "$work/lf.line.base.json")
    uuid=$(jq -r '.inbounds[0].settings.clients[0].id' "$work/lf.line.base.json")
    start_client "$port_line" "$pub" "$uuid" "$sid" lf
    local socks=$CLIENT_SOCKS

    python3 "$driver" throughput --label longflow --socks-port "$socks" \
        --url "http://127.0.0.1:$http_port/payload-$longflow_mib.bin" \
        --mib "$longflow_mib" --samples 1 --concurrencies 1 \
        --expected-sha256 "$(payload_sha "$longflow_mib")" \
        --out "$out_dir/tput-longflow-${longflow_mib}mib-c1.jsonl"
    sleep 1  # let the landing flush its events
    kill "$pid_landing" 2>/dev/null || true
    wait "$pid_landing" 2>/dev/null || true

    if python3 "$driver" relay-evidence \
        --log "$work/server-lf-landing.log" \
        --expect-backend splice \
        --out "$out_dir/summary-longflow.json"; then
        log "section longflow: PASS"
    else
        log "section longflow: FAIL (see summary-longflow.json)"
    fi
    cp "$work/server-lf-landing.log" "$out_dir/longflow-landing.log"
}

# --------------------------------------------------------------------------
# Environment metadata.
# --------------------------------------------------------------------------
write_environment() {
    jq -n \
        --arg rustBin "$rust_bin" --arg rustSha "$(sha256sum "$rust_bin" | cut -d' ' -f1)" \
        --arg xrayBin "$xray" --arg xraySha "$(sha256sum "$xray" | cut -d' ' -f1)" \
        --arg rustVersion "$("$rust_bin" --version 2>&1 | head -1)" \
        --arg xrayVersion "$("$xray" version 2>&1 | head -1)" \
        --arg gitSha "$(git rev-parse HEAD)" \
        --arg gitBranch "$(git rev-parse --abbrev-ref HEAD)" \
        --arg kernel "$(uname -srmo)" \
        --arg cpu "$(sed -n 's/^model name\s*: //p' /proc/cpuinfo | head -1)" \
        --argjson cpus "$(nproc)" \
        --arg dateUtc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg sections "$sections" --argjson smoke "$smoke" \
        --arg cpuMethod "$cpu_method" \
        '{
          rustRealityBin: $rustBin, rustRealitySha256: $rustSha,
          rustRealityVersion: $rustVersion,
          xrayBin: $xrayBin, xraySha256: $xraySha, xrayVersion: $xrayVersion,
          gitSha: $gitSha, gitBranch: $gitBranch,
          kernel: $kernel, cpu: $cpu, logicalCpus: $cpus,
          dateUtc: $dateUtc, sections: $sections, smoke: $smoke,
          cpuMeasurement: $cpuMethod
        }' > "$out_dir/environment.json"
}

# --------------------------------------------------------------------------
# Section dispatch.
# --------------------------------------------------------------------------
write_environment
for section in $sections; do
    case "$section" in
        routing) section_routing ;;
        cost) section_cost ;;
        nxr) section_nxr ;;
        rtt) section_rtt ;;
        longflow) section_longflow ;;
        *) echo "unknown section: $section" >&2; exit 2 ;;
    esac
done

verdict=0
python3 "$driver" summarize --out-dir "$out_dir" || verdict=1
log "done; results in $out_dir (overall verdict: $(jq -r .overallVerdict "$out_dir/summary.json"))"
exit "$verdict"
