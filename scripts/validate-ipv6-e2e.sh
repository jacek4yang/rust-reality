#!/usr/bin/env bash
# validate-ipv6-e2e.sh — REAL IPv6 end-to-end validation for rust-reality v1.5.0.
#
# Covers the worker-D validation matrix:
#   phase 0  environment capture
#   phase 1  listener modes (auto/dualStack/ipv4Only/ipv6Only) bind + acceptance
#   phase 2  VLESS+REALITY+Vision sessions with Xray-core client over IPv6
#   phase 3  host-global IPv6 inbound + real IPv6 Internet egress
#   phase 4  >=64 MiB upload/download/full-duplex with SHA-256 verification
#   phase 5  resilience: netem latency/loss, route loss/recovery, fast fallback
#
# Every check appends one JSON object to results.jsonl with an honest
# classification: loopback | namespace | host-global | external.
#
# Usage: validate-ipv6-e2e.sh [--artifacts DIR] [--phases 012345] [--work DIR]
# Env:   RUST_REALITY_BIN (default target/debug/rust-reality)
#        XRAY_BIN         (default tmp/bin/xray)
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RR_BIN=${RUST_REALITY_BIN:-$REPO/target/debug/rust-reality}
XRAY=${XRAY_BIN:-$REPO/tmp/bin/xray}
HELPERS=$REPO/scripts/ipv6-e2e
ARTIFACTS=$(cd "$REPO/../.." && pwd)/artifacts/v1.5.0/ipv6
PHASES=012345
WORK=
BENCH_LOCK=/tmp/v150-bench.lock
GLOBAL_V6=${GLOBAL_V6:-240e:391:9016:690::b47}

while [[ $# -gt 0 ]]; do
    case $1 in
        --artifacts) ARTIFACTS=$2; shift 2 ;;
        --phases) PHASES=$2; shift 2 ;;
        --work) WORK=$2; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

ARTIFACTS=$(mkdir -p "$ARTIFACTS" && cd "$ARTIFACTS" && pwd)
WORK=${WORK:-$ARTIFACTS/run-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$WORK"
WORK=$(cd "$WORK" && pwd)
RESULTS=$ARTIFACTS/results.jsonl
: >"$WORK/curl.log"

# The ambient shell proxy is IPv4-only and breaks direct IPv6; no test
# process may see it. NO_PROXY must be empty too: a wildcard NO_PROXY makes
# curl bypass the explicit --socks5-hostname proxy for every destination.
unset ALL_PROXY HTTP_PROXY HTTPS_PROXY all_proxy http_proxy https_proxy \
      CARGO_HTTP_PROXY NO_PROXY no_proxy || true

for program in "$RR_BIN" "$XRAY" curl jq python3 openssl sha256sum ss flock; do
    command -v "$program" >/dev/null 2>&1 || { echo "missing: $program" >&2; exit 1; }
done

SUDO_OK=0
if sudo -n true 2>/dev/null; then SUDO_OK=1; fi
HAS_TC=0
if [[ $SUDO_OK == 1 ]] && sudo -n /sbin/tc -V >/dev/null 2>&1; then HAS_TC=1; fi

# Collision-free port pool: one python process holds all sockets while
# printing, so no two allocations can return the same port.
mapfile -t PORT_POOL < <(python3 - <<'PY'
import socket
socks, ports = [], []
for _ in range(64):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.bind(("::1", 0))
    socks.append(s)
    ports.append(s.getsockname()[1])
print("\n".join(str(p) for p in ports))
PY
)
PORT_IDX_FILE=$WORK/.portidx
echo 0 >"$PORT_IDX_FILE"
# Safe inside command substitution: the index lives in a locked state file.
alloc_port() {
    (
        flock -x 200
        idx=$(cat "$PORT_IDX_FILE")
        echo $((idx + 1)) >"$PORT_IDX_FILE"
        echo "${PORT_POOL[$idx]}"
    ) 200>"$PORT_IDX_FILE.lock"
}

log() { printf '[validate-ipv6] %s\n' "$*" >&2; }

record() { # matrix case classification status detail-json [evidence]
    jq -cn --arg ts "$(date -Is)" --arg matrix "$1" --arg case "$2" \
        --arg class "$3" --arg status "$4" --argjson detail "${5:-null}" \
        --arg evidence "${6:-}" \
        '{ts:$ts,matrix:$matrix,case:$case,classification:$class,status:$status,detail:$detail,evidence:$evidence}' \
        >>"$RESULTS"
    log "$1/$2: $4"
}

RUN_DIR="run/$(basename "$WORK")"

tcp_check() { # addr port — exit 0 when connect(2) succeeds
    python3 - "$1" "$2" <<'PY'
import ipaddress, socket, sys
addr, port = sys.argv[1], int(sys.argv[2])
family = socket.AF_INET6 if ipaddress.ip_address(addr).version == 6 else socket.AF_INET
sock = socket.socket(family, socket.SOCK_STREAM)
sock.settimeout(1.5)
rc = sock.connect_ex((addr, port))
sock.close()
sys.exit(0 if rc == 0 else 1)
PY
}

wait_listen() { # addr port [seconds]
    local deadline=$((SECONDS + ${3:-10}))
    while (( SECONDS < deadline )); do
        tcp_check "$1" "$2" && return 0
        sleep 0.1
    done
    return 1
}

ss_has() { # addr port — exit 0 when a listener is visible on this host
    local needle
    if [[ $1 == *:* ]]; then needle="[$1]:$2"; else needle="$1:$2"; fi
    ss -lntH | grep -qF "$needle"
}

sha() { sha256sum "$1" | awk '{print $1}'; }

# --- process management -------------------------------------------------

declare -a BG_PIDS=()
start_bg() { # logfile cmd...
    local logfile=$1; shift
    nohup "$@" >"$logfile" 2>&1 &
    BG_PIDS+=("$!")
}

NETNS_NAMES=()
ns_exec() { local ns=$1; shift; sudo -n ip netns exec "$ns" "$@"; }
ns_add() { sudo -n ip netns add "$1" && NETNS_NAMES+=("$1"); }
ns_bg() { # ns logfile cmd... — echoes guest-side pid
    local ns=$1 logfile=$2; shift 2
    local pidfile; pidfile=$(mktemp "$WORK/nspid.XXXXXX")
    sudo -n ip netns exec "$ns" bash -c 'echo $$ >"$1"; shift; exec "$@"' _ "$pidfile" "$@" \
        >"$logfile" 2>&1 &
    local i
    for i in $(seq 1 50); do [[ -s $pidfile ]] && break; sleep 0.1; done
    cat "$pidfile"
}
ns_drop() { # ns — delete now and forget
    sudo -n ip netns del "$1" 2>/dev/null || true
    local kept=() n
    for n in ${NETNS_NAMES[@]+"${NETNS_NAMES[@]}"}; do [[ $n == "$1" ]] || kept+=("$n"); done
    NETNS_NAMES=(${kept[@]+"${kept[@]}"})
}

cleanup() {
    set +e
    for pid in ${BG_PIDS[@]+"${BG_PIDS[@]}"}; do kill "$pid" 2>/dev/null; done
    for pidfile in "$WORK"/nspid.*; do
        [[ -f $pidfile ]] && sudo -n kill "$(cat "$pidfile" 2>/dev/null)" 2>/dev/null
    done
    for ns in ${NETNS_NAMES[@]+"${NETNS_NAMES[@]}"}; do
        sudo -n ip netns del "$ns" 2>/dev/null
    done
    wait 2>/dev/null
}
trap cleanup EXIT

# --- config generation ---------------------------------------------------

# gen_server name port listen-json target sni dial-json [extra-jq]
# Writes $WORK/<name>.server.json plus .pubkey/.uuid/.sid
gen_server() {
    local name=$1 port=$2 listen=$3 target=$4 sni=$5 dial=$6 extra=${7:-.}
    "$RR_BIN" config generate standalone \
        --listen 127.0.0.1 --port 1 --target "$target" --server-name "$sni" \
        >"$WORK/$name.raw.json" 2>"$WORK/$name.gen.log"
    sed -n 's/^REALITY public key for the client: //p' "$WORK/$name.gen.log" | head -1 \
        >"$WORK/$name.pubkey"
    jq --argjson listen "$listen" --arg target "$target" --arg cache "$WORK/assets-$name" \
        --argjson dial "$dial" --argjson port "$port" "
        .inbounds[0].listen = \$listen
        | .inbounds[0].port = \$port
        | .inbounds[0].streamSettings.realitySettings.target = \$target
        | .assets.cacheDirectory = \$cache
        | .assets.requestTimeoutSeconds = 5
        | .network.dial = (.network.dial + \$dial)
        | $extra
    " "$WORK/$name.raw.json" >"$WORK/$name.server.json"
    jq -r '.inbounds[0].settings.clients[0].id' "$WORK/$name.server.json" >"$WORK/$name.uuid"
    jq -r '.inbounds[0].settings.clients[0].shortIds[0]' "$WORK/$name.server.json" >"$WORK/$name.sid"
}

xray_leg() { # socks-port server-name vnext port — prints one leg JSON object
    jq -cn --argjson socksPort "$1" --arg vnext "$3" --argjson port "$4" \
        --rawfile pubkey "$WORK/$2.pubkey" --rawfile uuid "$WORK/$2.uuid" \
        --rawfile sid "$WORK/$2.sid" \
        '{socksPort:$socksPort,vnext:$vnext,port:$port,
          pubkey:($pubkey|rtrimstr("\n")),uuid:($uuid|rtrimstr("\n")),sid:($sid|rtrimstr("\n"))}'
}

# gen_xray name leg-json... — each leg from xray_leg
gen_xray() {
    local name=$1; shift
    local legs; legs=$(printf '%s\n' "$@" | jq -s .)
    jq -n --argjson legs "$legs" '
        {
          log: {loglevel: "warning"},
          inbounds: [$legs[] | {tag: ("s" + (.socksPort|tostring)), listen: "127.0.0.1",
                                port: .socksPort, protocol: "socks",
                                settings: {auth: "noauth", udp: false}}],
          outbounds: [$legs[] | {tag: ("v" + (.socksPort|tostring)), protocol: "vless",
            settings: {vnext: [{address: .vnext, port: .port,
                                users: [{id: .uuid, encryption: "none",
                                         flow: "xtls-rprx-vision"}]}]},
            streamSettings: {network: "tcp", security: "reality",
              realitySettings: {fingerprint: "chrome", serverName: "cover.test",
                                publicKey: .pubkey, shortId: .sid, spiderX: "/"}}}],
          routing: {domainStrategy: "AsIs",
            rules: [$legs[] | {type: "field", inboundTag: [("s" + (.socksPort|tostring))],
                               outboundTag: ("v" + (.socksPort|tostring))}]}
        }' >"$WORK/$name.xray.json"
}

# fetch socks-port url outfile [max-time] — prints "http_code time_total"
# NOTE: never pass --noproxy here; it would bypass the explicit SOCKS proxy.
# The ambient proxy env is unset at script start, so --socks5-hostname rules.
fetch() {
    curl -sS --socks5-hostname "127.0.0.1:$1" \
        --max-time "${4:-30}" -o "$3" -w '%{http_code} %{time_total}' "$2" \
        2>>"$WORK/curl.log"
}

# upload socks-port url source-file [max-time]
upload() {
    curl -sS --socks5-hostname "127.0.0.1:$1" \
        --max-time "${4:-300}" -T "$3" -o /dev/null -w '%{http_code} %{time_total}' "$2" \
        2>>"$WORK/curl.log"
}

expect_serve_fails() { # config logfile [ns] — exit 0 when serve refuses to start
    local config=$1 logfile=$2 ns=${3:-} rc
    set +e
    if [[ -n $ns ]]; then
        ns_exec "$ns" env SSL_CERT_FILE="$WORK/cover-ca.crt" \
            timeout --signal=TERM 8 "$RR_BIN" serve --config "$config" >"$logfile" 2>&1
    else
        env SSL_CERT_FILE="$WORK/cover-ca.crt" \
            timeout --signal=TERM 8 "$RR_BIN" serve --config "$config" >"$logfile" 2>&1
    fi
    rc=$?
    set -e
    # 124 = still running when the timeout fired = unexpectedly started
    [[ $rc -ne 0 && $rc -ne 124 ]]
}

bench_lock() { exec 9>"$BENCH_LOCK"; flock -x 9; log "acquired $BENCH_LOCK"; }
bench_unlock() { flock -u 9 2>/dev/null || true; exec 9>&-; }

# The REALITY cover-dial TLS client verifies the cover certificate chain
# (see scripts/test-openssl-no-ccs-interop.sh): an ephemeral CA signs the
# cover leaf, and only the rust-reality server child receives SSL_CERT_FILE.
make_cover_cert() {
    [[ -f $WORK/cover.crt ]] && return 0
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
        -subj "/CN=rust-reality ipv6 validation CA" \
        -addext 'basicConstraints=critical,CA:TRUE' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign' \
        -keyout "$WORK/cover-ca.key" -out "$WORK/cover-ca.crt" 2>/dev/null
    openssl req -new -newkey rsa:2048 -nodes -sha256 \
        -subj "/CN=cover.test" \
        -addext 'basicConstraints=critical,CA:FALSE' \
        -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
        -addext 'extendedKeyUsage=serverAuth' \
        -addext 'subjectAltName=DNS:cover.test,IP:127.0.0.1,IP:::1' \
        -keyout "$WORK/cover.key" -out "$WORK/cover.csr" 2>/dev/null
    openssl x509 -req -sha256 -days 2 \
        -in "$WORK/cover.csr" -CA "$WORK/cover-ca.crt" -CAkey "$WORK/cover-ca.key" \
        -CAcreateserial -copy_extensions copy -out "$WORK/cover.crt" 2>/dev/null
}

# start_server logfile config — every server child gets the ephemeral CA.
start_server() {
    start_bg "$1" env SSL_CERT_FILE="$WORK/cover-ca.crt" \
        "$RR_BIN" serve --config "$2"
}

start_cover() { # addr port
    start_bg "$WORK/cover-$2.log" python3 "$HELPERS/tls_cover_server.py" \
        --bind "$1" --port "$2" --cert "$WORK/cover.crt" --key "$WORK/cover.key"
    wait_listen "$1" "$2"
}

start_origin() { # name addr port dir
    mkdir -p "$4"
    start_bg "$WORK/origin-$1.log" python3 "$HELPERS/transfer_server.py" \
        --bind "$2" --port "$3" --directory "$4" --label "$1"
    wait_listen "$2" "$3"
}

# ======================================================================
phase0() {
    {
        echo "=== date ==="; date -Is
        echo "=== uname ==="; uname -a
        echo "=== rust-reality ==="; "$RR_BIN" --version 2>&1 || true
        echo "=== xray ==="; "$XRAY" version 2>&1 | head -2
        echo "=== git ==="; git -C "$REPO" log --oneline -1; git -C "$REPO" branch --show-current
        echo "=== ip -6 addr ==="; ip -6 addr
        echo "=== ip -6 route ==="; ip -6 route
        echo "=== ip -6 rule ==="; ip -6 rule
        echo "=== ip -4 route ==="; ip -4 route
        echo "=== sysctl ==="; /sbin/sysctl net.ipv6.conf.all.disable_ipv6 \
            net.ipv6.conf.default.disable_ipv6 net.ipv6.bindv6only \
            net.ipv6.conf.all.forwarding net.ipv4.ip_forward 2>&1
        echo "=== resolv.conf ==="; cat /etc/resolv.conf
        echo "=== hosts ==="; grep -v '^#' /etc/hosts
        echo "=== direct IPv6 internet ==="
        curl -6 --noproxy '*' -sS -o /dev/null --max-time 15 \
            -w 'http=%{http_code} remote=%{remote_ip} total=%{time_total}\n' \
            https://example.com/ || echo "direct IPv6 FAILED"
        echo "=== sudo ==="; echo "sudo -n: $SUDO_OK, tc: $HAS_TC"
    } >"$ARTIFACTS/environment.txt" 2>&1
    record 0-environment capture loopback pass "$(jq -n '{path:"environment.txt"}')" environment.txt
}

# ======================================================================
phase1() {
    log "phase 1: listener modes"
    make_cover_cert
    local target="[::1]:1" sni=cover.test mode

    # --- 1a: each mode binds the expected sockets on dual-stack loopback
    for mode in auto dualStack ipv4Only ipv6Only; do
        local name="l1-$mode" port
        port=$(alloc_port)
        gen_server "$name" "$port" \
            "{\"mode\":\"$mode\",\"ipv4\":\"127.0.0.1\",\"ipv6\":\"::1\"}" \
            "$target" "$sni" '{}'
        start_server "$WORK/$name.rust.log" "$WORK/$name.server.json"
        sleep 1
        local v4_listen=absent v6_listen=absent v4_accept=refused v6_accept=refused
        ss_has 127.0.0.1 "$port" && v4_listen=present
        ss_has ::1 "$port" && v6_listen=present
        tcp_check 127.0.0.1 "$port" && v4_accept=accepted
        tcp_check ::1 "$port" && v6_accept=accepted
        local expect_v4 expect_v6
        case $mode in
            auto|dualStack) expect_v4=yes; expect_v6=yes ;;
            ipv4Only) expect_v4=yes; expect_v6=no ;;
            ipv6Only) expect_v4=no; expect_v6=yes ;;
        esac
        local got_v4=no got_v6=no
        [[ $v4_listen == present && $v4_accept == accepted ]] && got_v4=yes
        [[ $v6_listen == present && $v6_accept == accepted ]] && got_v6=yes
        local detail
        detail=$(jq -n --arg mode "$mode" --argjson port "$port" \
            --arg v4_listen "$v4_listen" --arg v6_listen "$v6_listen" \
            --arg v4_accept "$v4_accept" --arg v6_accept "$v6_accept" \
            --arg e4 "$expect_v4" --arg e6 "$expect_v6" \
            --arg topo "$(grep -o '"event":"listener_topology_active".*' "$WORK/$name.rust.log" | head -1)" \
            '{mode:$mode,port:$port,v4Listen:$v4_listen,v6Listen:$v6_listen,
              v4Accept:$v4_accept,v6Accept:$v6_accept,
              expectV4:$e4,expectV6:$e6,topologyLog:$topo}')
        local status=fail
        [[ $got_v4 == "$expect_v4" && $got_v6 == "$expect_v6" ]] && status=pass
        record 1-listeners "mode-$mode" loopback "$status" "$detail" "$RUN_DIR/$name.rust.log"
        kill "${BG_PIDS[-1]}" 2>/dev/null || true
        unset "BG_PIDS[-1]"
        sleep 0.3
    done

    # --- 1b: concrete unassigned IPv6 address is fatal even in auto mode
    local name=l1-badaddr
    gen_server "$name" "$(alloc_port)" \
        '{"mode":"auto","ipv4":"127.0.0.1","ipv6":"2001:db8::ffff"}' "$target" "$sni" '{}'
    local status=fail
    expect_serve_fails "$WORK/$name.server.json" "$WORK/$name.rust.log" && status=pass
    record 1-listeners auto-concrete-unassigned-v6-fatal loopback "$status" \
        "$(jq -n '{expect:"serve exits non-zero: EADDRNOTAVAIL on a concrete address is fatal"}')" \
        "$RUN_DIR/$name.rust.log"

    # --- 1c: EADDRINUSE is fatal, not degraded
    local namea=l1-busy-a nameb=l1-busy-b porta
    porta=$(alloc_port)
    gen_server "$namea" "$porta" '{"mode":"ipv6Only","ipv4":"0.0.0.0","ipv6":"::1"}' \
        "$target" "$sni" '{}'
    start_server "$WORK/$namea.rust.log" "$WORK/$namea.server.json"
    wait_listen ::1 "$porta"
    jq --argjson port "$porta" '
        .inbounds[0].port = $port
        | .inbounds[0].listen = {"mode":"auto","ipv4":"127.0.0.1","ipv6":"::1"}' \
        "$WORK/$namea.server.json" >"$WORK/$nameb.server.json"
    status=fail
    expect_serve_fails "$WORK/$nameb.server.json" "$WORK/$nameb.rust.log" && status=pass
    record 1-listeners addr-in-use-fatal loopback "$status" \
        "$(jq -n --argjson port "$porta" '{port:$port,expect:"EADDRINUSE fatal even in auto mode"}')" \
        "$RUN_DIR/$nameb.rust.log"
    kill "${BG_PIDS[-1]}" 2>/dev/null || true
    unset "BG_PIDS[-1]"
    sleep 0.3

    # --- 1d: namespace with IPv6 disabled (disable_ipv6=1)
    if [[ $SUDO_OK == 1 ]]; then
        local ns=rrv1no6
        ns_add "$ns"
        ns_exec "$ns" ip link set lo up
        ns_exec "$ns" /sbin/sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 \
            net.ipv6.conf.default.disable_ipv6=1 >/dev/null
        # ipv6Only concrete ::1 -> EADDRNOTAVAIL -> must fail
        local namen=l1-no6-v6only
        gen_server "$namen" "$(alloc_port)" \
            '{"mode":"ipv6Only","ipv4":"0.0.0.0","ipv6":"::1"}' "$target" "$sni" '{}'
        status=fail
        expect_serve_fails "$WORK/$namen.server.json" "$WORK/$namen.rust.log" "$ns" && status=pass
        record 1-listeners no-ipv6-ns-ipv6only-fails namespace "$status" \
            "$(jq -n '{ns:"disable_ipv6=1",expect:"EADDRNOTAVAIL on concrete ::1 is fatal"}')" \
            "$RUN_DIR/$namen.rust.log"
        # auto in the same ns: this kernel still allows the wildcard v6 bind,
        # so the server must start and serve IPv4
        local namea2=l1-no6-auto portna pidna
        portna=$(alloc_port)
        gen_server "$namea2" "$portna" '{"mode":"auto","ipv4":"127.0.0.1","ipv6":"::"}' \
            "$target" "$sni" '{}'
        pidna=$(ns_bg "$ns" "$WORK/$namea2.rust.log" env SSL_CERT_FILE="$WORK/cover-ca.crt" "$RR_BIN" serve --config "$WORK/$namea2.server.json")
        sleep 1.5
        status=fail
        if sudo -n kill -0 "$pidna" 2>/dev/null && \
           ns_exec "$ns" python3 -c "
import socket, sys
s = socket.socket(); s.settimeout(1.5)
sys.exit(0 if s.connect_ex(('127.0.0.1', $portna)) == 0 else 1)"; then
            status=pass
        fi
        record 1-listeners no-ipv6-ns-auto-serves-v4 namespace "$status" \
            "$(jq -n --argjson port "$portna" \
                '{port:$port,note:"wildcard [::] bind succeeds even with disable_ipv6=1 on this kernel; IPv4 acceptance verified"}')" \
            "$RUN_DIR/$namea2.rust.log"
        sudo -n kill "$pidna" 2>/dev/null || true
        ns_drop "$ns"
    else
        record 1-listeners no-ipv6-ns namespace skip "$(jq -n '{reason:"no passwordless sudo"}')"
    fi
}

# ======================================================================
phase2() {
    log "phase 2: Xray client sessions over IPv6 (loopback)"
    make_cover_cert
    local cp op
    cp=$(alloc_port); op=$(alloc_port)
    start_cover ::1 "$cp"
    local origin=$WORK/origin2
    start_origin origin-v4 127.0.0.1 "$op" "$origin"
    start_origin origin-v6 ::1 "$op" "$origin"
    head -c 1048576 /dev/urandom >"$origin/payload.bin"
    local payload_sha; payload_sha=$(sha "$origin/payload.bin")

    local listen_dual='{"mode":"dualStack","ipv4":"127.0.0.1","ipv6":"::1"}'
    local pa pb pc pd
    pa=$(alloc_port); pb=$(alloc_port); pc=$(alloc_port); pd=$(alloc_port)
    gen_server s2auto "$pa" "$listen_dual" "[::1]:$cp" cover.test '{}'
    gen_server s2pref6 "$pb" "$listen_dual" "[::1]:$cp" cover.test '{"mode":"preferIpv6"}'
    gen_server s2pref4 "$pc" "$listen_dual" "[::1]:$cp" cover.test '{"mode":"preferIpv4"}'
    gen_server s2dial6 "$pd" "$listen_dual" "[::1]:$cp" cover.test '{"mode":"ipv6Only"}'

    local s6a s4a s6p6 s6p4 s6d6
    s6a=$(alloc_port); s4a=$(alloc_port); s6p6=$(alloc_port); s6p4=$(alloc_port); s6d6=$(alloc_port)
    gen_xray x2 \
        "$(xray_leg "$s6a" s2auto ::1 "$pa")" \
        "$(xray_leg "$s4a" s2auto 127.0.0.1 "$pa")" \
        "$(xray_leg "$s6p6" s2pref6 ::1 "$pb")" \
        "$(xray_leg "$s6p4" s2pref4 ::1 "$pc")" \
        "$(xray_leg "$s6d6" s2dial6 ::1 "$pd")"

    local s
    for s in s2auto s2pref6 s2pref4 s2dial6; do
        start_server "$WORK/$s.rust.log" "$WORK/$s.server.json"
    done
    start_bg "$WORK/x2.xray.log" "$XRAY" run -config "$WORK/x2.xray.json"
    wait_listen ::1 "$pa"; wait_listen ::1 "$pb"; wait_listen ::1 "$pc"; wait_listen ::1 "$pd"
    wait_listen 127.0.0.1 "$s6a"; wait_listen 127.0.0.1 "$s6d6"

    # Egress-family attribution: per-file line marks. Concatenating both logs
    # and tailing one window misattributes whenever the new lines land in the
    # first file of the pair, so mark each origin log separately.
    local MARK4=1 MARK6=1
    origin_mark() {
        MARK4=$(( $(wc -l <"$WORK/origin-origin-v4.log" 2>/dev/null || echo 0) + 1 ))
        MARK6=$(( $(wc -l <"$WORK/origin-origin-v6.log" 2>/dev/null || echo 0) + 1 ))
    }
    origin_family_hits() { # → JSON string: unique GET server labels since the marks
        { tail -n +"$MARK4" "$WORK/origin-origin-v4.log" 2>/dev/null
          tail -n +"$MARK6" "$WORK/origin-origin-v6.log" 2>/dev/null
        } | { grep '^{' || true; } \
          | jq -s '[.[] | select(.method == "GET") | .server] | unique | join(",")'
    }

    local dl=$WORK/dl2; mkdir -p "$dl"
    local case_rc detail out

    run_case() { # case-name socks-port url [max-time] → sets case_rc detail
        local case_name=$1 sp=$2 url=$3 mt=${4:-30}
        out=$dl/$case_name.bin
        local w t0=$SECONDS
        set +e
        w=$(fetch "$sp" "$url" "$out" "$mt")
        case_rc=$?
        set -e
        local got_sha=none
        [[ $case_rc == 0 && -f $out ]] && got_sha=$(sha "$out")
        detail=$(jq -n --arg url "$url" --arg curl "${w:-}" --argjson rc "$case_rc" \
            --arg sha "$got_sha" --arg expect "$payload_sha" \
            --argjson elapsed $((SECONDS - t0)) \
            '{url:$url,curl:$curl,rc:$rc,sha256:$sha,expectSha256:$expect,elapsedS:$elapsed,
              byteExact:($sha==$expect)}')
    }

    byte_exact() { [[ $case_rc == 0 && $(jq -r .byteExact <<<"$detail") == true ]]; }

    # (a) IPv6 client → IPv6 inbound → IPv6 literal egress
    run_case 2a "$s6a" "http://[::1]:$op/payload.bin"
    local status=fail; byte_exact && status=pass
    record 2-sessions a-v6in-v6egress-literal loopback "$status" "$detail" "$RUN_DIR/x2.xray.log"

    # (b) IPv6 inbound → IPv4 egress (origin label proves the family)
    local fam
    origin_mark
    run_case 2b "$s6a" "http://127.0.0.1:$op/payload.bin"
    sleep 0.3; fam=$(origin_family_hits)
    status=fail
    [[ $(byte_exact && echo y) == y && $fam == '"origin-v4"' ]] && status=pass
    record 2-sessions b-v6in-v4egress loopback "$status" \
        "$(jq -cn --argjson d "$detail" --argjson fam "$fam" '$d+{egressServer:$fam}')" \
        "$RUN_DIR/x2.xray.log"

    # (c) IPv4 inbound → IPv6 literal egress
    origin_mark
    run_case 2c "$s4a" "http://[::1]:$op/payload.bin"
    sleep 0.3; fam=$(origin_family_hits)
    status=fail
    [[ $(byte_exact && echo y) == y && $fam == '"origin-v6"' ]] && status=pass
    record 2-sessions c-v4in-v6egress loopback "$status" \
        "$(jq -cn --argjson d "$detail" --argjson fam "$fam" '$d+{egressServer:$fam}')" \
        "$RUN_DIR/x2.xray.log"

    # (d) mixed A/AAAA destination (localhost → ::1 + 127.0.0.1), dial auto
    run_case 2d "$s6a" "http://localhost:$op/payload.bin"
    status=fail; byte_exact && status=pass
    record 2-sessions d-mixed-a-aaaa loopback "$status" "$detail" "$RUN_DIR/x2.xray.log"

    # (e) DNS-selected family: preferIpv6 must hit the v6 origin, preferIpv4 the v4 one
    origin_mark
    run_case 2e6 "$s6p6" "http://localhost:$op/payload.bin"
    sleep 0.3; fam=$(origin_family_hits)
    status=fail
    [[ $(byte_exact && echo y) == y && $fam == '"origin-v6"' ]] && status=pass
    record 2-sessions e-dns-selected-v6 loopback "$status" \
        "$(jq -cn --argjson d "$detail" --argjson fam "$fam" '$d+{egressServer:$fam,dial:"preferIpv6"}')" \
        "$RUN_DIR/x2.xray.log"

    origin_mark
    run_case 2e4 "$s6p4" "http://localhost:$op/payload.bin"
    sleep 0.3; fam=$(origin_family_hits)
    status=fail
    [[ $(byte_exact && echo y) == y && $fam == '"origin-v4"' ]] && status=pass
    record 2-sessions e-dns-selected-v4-control loopback "$status" \
        "$(jq -cn --argjson d "$detail" --argjson fam "$fam" '$d+{egressServer:$fam,dial:"preferIpv4"}')" \
        "$RUN_DIR/x2.xray.log"

    # (f) explicit IPv6 literal under dial ipv6Only + negative v4 control
    run_case 2f "$s6d6" "http://[::1]:$op/payload.bin"
    local f_ok=fail; byte_exact && f_ok=pass
    local f_detail=$detail
    run_case 2fneg "$s6d6" "http://127.0.0.1:$op/payload.bin" 15
    local neg_ok=fail
    [[ $case_rc != 0 ]] && neg_ok=pass # dial ipv6Only must refuse an IPv4 destination
    status=fail
    [[ $f_ok == pass && $neg_ok == pass ]] && status=pass
    record 2-sessions f-literal-v6-dial-ipv6only loopback "$status" \
        "$(jq -n --argjson f "$f_detail" --argjson neg "$detail" \
            '{literalV6:$f, v4UnderIpv6OnlyDial:$neg,
              note:"v4 destination under ipv6Only dial must fail (rc!=0)"}')" \
        "$RUN_DIR/x2.xray.log"

    # (g) bracketed-IPv6 cover: fallback bytes == direct cover bytes
    # (--http1.1: the cover offers h2 ALPN for REALITY shape reasons but the
    # python cover can only serve HTTP/1.1 to direct probes)
    local fb_direct fb_proxy
    set +e
    fb_direct=$(curl --noproxy '*' --http1.1 -sk --max-time 10 "https://[::1]:$cp/" 2>>"$WORK/curl.log")
    fb_proxy=$(curl --noproxy '*' --http1.1 -sk --max-time 10 "https://[::1]:$pa/" 2>>"$WORK/curl.log")
    set -e
    status=fail
    [[ -n $fb_direct && $fb_direct == "$fb_proxy" ]] && status=pass
    record 2-sessions g-bracketed-v6-cover-fallback loopback "$status" \
        "$(jq -n --arg target "[::1]:$cp" --arg direct "$fb_direct" --arg via "$fb_proxy" \
            '{coverTarget:$target,directBody:$direct,fallbackBody:$via,
              fallbackMatchesDirect:($direct==$via and $via!=""),
              note:"every phase-2 session also verifies against this bracketed-v6 cover"}')" \
        "$RUN_DIR/s2auto.rust.log"

    # (h) negative control: a wrong shortId must fail. If this fetch ever
    # succeeds the test harness is bypassing the REALITY tunnel (as happened
    # with --noproxy/NO_PROXY mistakes) and every pass above is meaningless.
    local spbad badsid sid0 first rep
    spbad=$(alloc_port)
    sid0=$(cat "$WORK/s2auto.sid")
    first=${sid0:0:1}; rep=0; [[ $first == 0 ]] && rep=1
    badsid="$rep${sid0:1}"
    gen_xray x2bad "$(jq -cn --argjson socksPort "$spbad" --arg vnext "::1" --argjson port "$pa" \
        --rawfile pubkey "$WORK/s2auto.pubkey" --rawfile uuid "$WORK/s2auto.uuid" \
        --arg sid "$badsid" \
        '{socksPort:$socksPort,vnext:$vnext,port:$port,
          pubkey:($pubkey|rtrimstr("\n")),uuid:($uuid|rtrimstr("\n")),sid:$sid}')"
    start_bg "$WORK/x2bad.xray.log" "$XRAY" run -config "$WORK/x2bad.xray.json"
    wait_listen 127.0.0.1 "$spbad"
    run_case 2h "$spbad" "http://[::1]:$op/payload.bin" 15
    status=fail
    [[ $case_rc != 0 ]] && status=pass
    record 2-sessions h-negative-auth-control loopback "$status" \
        "$(jq -cn --argjson d "$detail" --arg sid "$badsid" \
            '$d+{wrongShortId:$sid,expect:"fetch fails: REALITY auth rejects the session"}')" \
        "$RUN_DIR/x2bad.xray.log"
}

# ======================================================================
phase3() {
    log "phase 3: host-global IPv6 + real IPv6 Internet egress"
    make_cover_cert
    local cp; cp=$(alloc_port)
    start_cover ::1 "$cp"
    local name=s3glob port sp
    port=$(alloc_port); sp=$(alloc_port)
    gen_server "$name" "$port" \
        "{\"mode\":\"ipv6Only\",\"ipv4\":\"0.0.0.0\",\"ipv6\":\"$GLOBAL_V6\"}" \
        "[::1]:$cp" cover.test '{"mode":"ipv6Only"}'
    gen_xray x3 "$(xray_leg "$sp" "$name" "$GLOBAL_V6" "$port")"
    start_server "$WORK/$name.rust.log" "$WORK/$name.server.json"
    start_bg "$WORK/x3.xray.log" "$XRAY" run -config "$WORK/x3.xray.json"
    wait_listen "$GLOBAL_V6" "$port" && wait_listen 127.0.0.1 "$sp"

    # listener visible on the global address?
    local status=fail
    ss_has "$GLOBAL_V6" "$port" && status=pass
    record 3-global bind-global-address host-global "$status" \
        "$(jq -n --arg addr "$GLOBAL_V6" --argjson port "$port" '{addr:$addr,port:$port}')" \
        "$RUN_DIR/$name.rust.log"

    # proxied example.com via the global address; dial ipv6Only ⇒ egress must be IPv6
    local direct_rc proxy_rc w
    set +e
    curl -6 --noproxy '*' -sS --max-time 20 -o "$WORK/example.direct" \
        https://example.com/ 2>>"$WORK/curl.log"
    direct_rc=$?
    w=$(fetch "$sp" https://example.com/ "$WORK/example.proxied" 30)
    proxy_rc=$?
    set -e
    local d_sha=none p_sha=none
    [[ $direct_rc == 0 ]] && d_sha=$(sha "$WORK/example.direct")
    [[ $proxy_rc == 0 ]] && p_sha=$(sha "$WORK/example.proxied")
    status=fail
    [[ $direct_rc == 0 && $proxy_rc == 0 && $d_sha == "$p_sha" ]] && status=pass
    record 3-global real-internet-v6-egress host-global "$status" \
        "$(jq -n --arg curl "${w:-}" --argjson directRc "$direct_rc" --argjson proxyRc "$proxy_rc" \
            --arg d "$d_sha" --arg p "$p_sha" \
            '{curl:$curl,directRc:$directRc,proxyRc:$proxyRc,directSha256:$d,proxiedSha256:$p,
              byteExact:($d==$p and $d!="none"),
              note:"same-host client to host global address; server dial ipv6Only forces AAAA egress to the real Internet"}')" \
        "$RUN_DIR/x3.xray.log"

    record 3-global external-ingress external skip \
        "$(jq -n '{reason:"no external host under our control; only same-host ingress to the global address was tested"}')"
}

# ======================================================================
phase4() {
    log "phase 4: large transfers over IPv6 (loopback, bench lock)"
    bench_lock
    make_cover_cert
    local cp op
    cp=$(alloc_port); op=$(alloc_port)
    start_cover ::1 "$cp"
    local origin=$WORK/origin4
    start_origin origin4-v6 ::1 "$op" "$origin"
    local name=s4 port sp
    port=$(alloc_port); sp=$(alloc_port)
    gen_server "$name" "$port" '{"mode":"ipv6Only","ipv4":"0.0.0.0","ipv6":"::1"}' \
        "[::1]:$cp" cover.test '{}'
    gen_xray x4 "$(xray_leg "$sp" "$name" ::1 "$port")"
    start_server "$WORK/$name.rust.log" "$WORK/$name.server.json"
    start_bg "$WORK/x4.xray.log" "$XRAY" run -config "$WORK/x4.xray.json"
    wait_listen ::1 "$port"; wait_listen 127.0.0.1 "$sp"

    local mib=64
    head -c $((mib * 1048576)) /dev/urandom >"$WORK/up64.bin"
    head -c $((mib * 1048576)) /dev/urandom >"$origin/dl64.bin"
    head -c $((mib * 1048576)) /dev/urandom >"$WORK/up64b.bin"
    local up_sha dl_sha upb_sha
    up_sha=$(sha "$WORK/up64.bin"); dl_sha=$(sha "$origin/dl64.bin"); upb_sha=$(sha "$WORK/up64b.bin")

    # upload
    local w rc got_sha status
    set +e
    w=$(upload "$sp" "http://[::1]:$op/up64.received" "$WORK/up64.bin" 600)
    rc=$?
    set -e
    got_sha=none
    [[ -f $origin/up64.received ]] && got_sha=$(sha "$origin/up64.received")
    status=fail
    [[ $rc == 0 && $got_sha == "$up_sha" ]] && status=pass
    record 4-transfer upload-64mib-v6 loopback "$status" \
        "$(jq -n --arg curl "${w:-}" --argjson rc "$rc" --arg expect "$up_sha" --arg got "$got_sha" \
            --argjson mib "$mib" \
            '{curl:$curl,rc:$rc,mib:$mib,expectSha256:$expect,gotSha256:$got,byteExact:($expect==$got)}')" \
        "$RUN_DIR/x4.xray.log"

    # download
    set +e
    w=$(fetch "$sp" "http://[::1]:$op/dl64.bin" "$WORK/dl64.out" 600)
    rc=$?
    set -e
    got_sha=none
    [[ -f $WORK/dl64.out ]] && got_sha=$(sha "$WORK/dl64.out")
    status=fail
    [[ $rc == 0 && $got_sha == "$dl_sha" ]] && status=pass
    record 4-transfer download-64mib-v6 loopback "$status" \
        "$(jq -n --arg curl "${w:-}" --argjson rc "$rc" --arg expect "$dl_sha" --arg got "$got_sha" \
            --argjson mib "$mib" \
            '{curl:$curl,rc:$rc,mib:$mib,expectSha256:$expect,gotSha256:$got,byteExact:($expect==$got)}')" \
        "$RUN_DIR/x4.xray.log"

    # full-duplex: concurrent second upload + download
    local urc drc
    upload "$sp" "http://[::1]:$op/up64b.received" "$WORK/up64b.bin" 600 \
        >"$WORK/dup.up" 2>>"$WORK/curl.log" &
    local upid=$!
    fetch "$sp" "http://[::1]:$op/dl64.bin" "$WORK/dl64b.out" 600 \
        >"$WORK/dup.dl" 2>>"$WORK/curl.log" &
    local dwid=$!
    set +e
    wait "$upid"; urc=$?
    wait "$dwid"; drc=$?
    set -e
    local got_up=none got_dl=none
    [[ -f $origin/up64b.received ]] && got_up=$(sha "$origin/up64b.received")
    [[ -f $WORK/dl64b.out ]] && got_dl=$(sha "$WORK/dl64b.out")
    status=fail
    [[ $urc == 0 && $drc == 0 && $got_up == "$upb_sha" && $got_dl == "$dl_sha" ]] && status=pass
    record 4-transfer full-duplex-64mib-v6 loopback "$status" \
        "$(jq -n --argjson urc "$urc" --argjson drc "$drc" \
            --arg eup "$upb_sha" --arg gup "$got_up" --arg edl "$dl_sha" --arg gdl "$got_dl" \
            --arg wu "$(cat "$WORK/dup.up")" --arg wd "$(cat "$WORK/dup.dl")" \
            --argjson mib "$mib" \
            '{mib:$mib,concurrent:true,curlUpload:$wu,curlDownload:$wd,
              upload:{rc:$urc,byteExact:($eup==$gup)},
              download:{rc:$drc,byteExact:($edl==$gdl)}}')" \
        "$RUN_DIR/x4.xray.log"

    rm -f "$WORK/up64.bin" "$WORK/up64b.bin" "$WORK/dl64.out" "$WORK/dl64b.out" \
        "$origin/dl64.bin" "$origin/up64.received" "$origin/up64b.received"
    bench_unlock
}

# ======================================================================
phase5() {
    log "phase 5: resilience"
    bench_lock
    make_cover_cert

    if [[ $SUDO_OK == 1 ]]; then
        # --- topology: cli <-> srv <-> orig, IPv6-only links
        local nscli=rrv5cli nssrv=rrv5srv nsorig=rrv5orig ns
        for ns in $nscli $nssrv $nsorig; do ns_add "$ns"; done
        sudo -n ip link add veth-cli type veth peer name veth-srv0
        sudo -n ip link set veth-cli netns $nscli
        sudo -n ip link set veth-srv0 netns $nssrv
        sudo -n ip link add veth-orig type veth peer name veth-srv1
        sudo -n ip link set veth-orig netns $nsorig
        sudo -n ip link set veth-srv1 netns $nssrv
        ns_exec $nscli bash -c 'ip link set lo up; ip -6 addr add 2001:db8:a::1/64 dev veth-cli; ip link set veth-cli up'
        ns_exec $nssrv bash -c 'ip link set lo up; ip -6 addr add 2001:db8:a::2/64 dev veth-srv0; ip link set veth-srv0 up; ip -6 addr add 2001:db8:b::2/64 dev veth-srv1; ip link set veth-srv1 up'
        ns_exec $nsorig bash -c 'ip link set lo up; ip -6 addr add 2001:db8:b::1/64 dev veth-orig; ip link set veth-orig up'

        # New IPv6 addresses are tentative until Duplicate Address Detection
        # finishes; binding a concrete tentative address fails EADDRNOTAVAIL.
        local dad_deadline=$((SECONDS + 15)) tentative=1
        while (( SECONDS < dad_deadline )); do
            tentative=0
            for ns in $nscli $nssrv $nsorig; do
                tentative=$((tentative + $(ns_exec $ns ip -6 addr show tentative | wc -l)))
            done
            (( tentative == 0 )) && break
            sleep 0.3
        done
        if (( tentative != 0 )); then
            record 5-resilience netns-address-dad namespace fail \
                "$(jq -n '{reason:"addresses still tentative after 15s"}')"
        fi

        local cp5 op5 sp5
        cp5=$(alloc_port); op5=$(alloc_port); sp5=$(alloc_port)
        local origin5=$WORK/origin5; mkdir -p "$origin5"
        head -c 1048576 /dev/urandom >"$origin5/payload.bin"
        local p5sha; p5sha=$(sha "$origin5/payload.bin")

        ns_bg $nssrv "$WORK/cover5.log" python3 "$HELPERS/tls_cover_server.py" \
            --bind ::1 --port "$cp5" --cert "$WORK/cover.crt" --key "$WORK/cover.key" >/dev/null
        ns_bg $nsorig "$WORK/origin5.log" python3 "$HELPERS/transfer_server.py" \
            --bind 2001:db8:b::1 --port "$op5" --directory "$origin5" \
            --label origin5-v6 >/dev/null

        local name=s5 port5 srv_pid
        port5=$(alloc_port)
        gen_server "$name" "$port5" \
            '{"mode":"ipv6Only","ipv4":"0.0.0.0","ipv6":"2001:db8:a::2"}' \
            "[::1]:$cp5" cover.test \
            '{"mode":"auto","routeRefreshSeconds":2,"hardFailurePenaltySeconds":3}'
        srv_pid=$(ns_bg $nssrv "$WORK/$name.rust.log" env SSL_CERT_FILE="$WORK/cover-ca.crt" "$RR_BIN" serve --config "$WORK/$name.server.json")
        gen_xray x5 "$(xray_leg "$sp5" "$name" 2001:db8:a::2 "$port5")"
        ns_bg $nscli "$WORK/x5.xray.log" "$XRAY" run -config "$WORK/x5.xray.json" >/dev/null
        sleep 2

        fetch5() { # url out [max-time] — curl inside the client namespace
            ns_exec $nscli curl -sS --socks5-hostname "127.0.0.1:$sp5" \
                --max-time "${3:-60}" -o "$2" -w '%{http_code} %{time_total}' "$1" \
                2>>"$WORK/curl.log"
        }

        # 5a: netem 100ms / 1% loss on the client leg
        if [[ $HAS_TC == 1 ]]; then
            ns_exec $nscli /sbin/tc qdisc add dev veth-cli root netem delay 100ms loss 1%
            local w rc got
            set +e
            w=$(fetch5 "http://[2001:db8:b::1]:$op5/payload.bin" "$WORK/p5a.out" 120)
            rc=$?
            set -e
            got=none; [[ -f $WORK/p5a.out ]] && got=$(sha "$WORK/p5a.out")
            ns_exec $nscli /sbin/tc qdisc del dev veth-cli root 2>/dev/null || true
            local status=fail
            [[ $rc == 0 && $got == "$p5sha" ]] && status=pass
            record 5-resilience netem-100ms-1pct-session namespace "$status" \
                "$(jq -n --arg curl "${w:-}" --argjson rc "$rc" --arg expect "$p5sha" --arg got "$got" \
                    '{netem:"delay 100ms loss 1% (client-leg egress)",curl:$curl,rc:$rc,
                      byteExact:($expect==$got)}')" \
                "$RUN_DIR/x5.xray.log"
        else
            record 5-resilience netem-100ms-1pct-session namespace skip \
                "$(jq -n '{reason:"tc unavailable"}')"
        fi

        # 5b: route loss and recovery, server process keeps running
        local w0 rc0 w1 rc1
        set +e
        w0=$(fetch5 "http://[2001:db8:b::1]:$op5/payload.bin" "$WORK/p5b0.out" 60)
        rc0=$?
        set -e
        local status=fail
        [[ $rc0 == 0 && -f $WORK/p5b0.out && $(sha "$WORK/p5b0.out") == "$p5sha" ]] && status=pass
        record 5-resilience route-loss-baseline namespace "$status" \
            "$(jq -n --arg curl "${w0:-}" --argjson rc "$rc0" '{curl:$curl,rc:$rc}')" \
            "$RUN_DIR/x5.xray.log"

        ns_exec $nssrv ip -6 route del 2001:db8:b::/64 dev veth-srv1
        set +e
        w1=$(fetch5 "http://[2001:db8:b::1]:$op5/payload.bin" "$WORK/p5b1.out" 30)
        rc1=$?
        set -e
        status=fail
        [[ $rc1 != 0 ]] && status=pass
        record 5-resilience route-loss-fails-fast namespace "$status" \
            "$(jq -n --arg curl "${w1:-}" --argjson rc "$rc1" \
                '{expect:"fetch fails while the egress route is deleted",curl:$curl,rc:$rc}')" \
            "$RUN_DIR/s5.rust.log"

        ns_exec $nssrv ip -6 route add 2001:db8:b::/64 dev veth-srv1
        local recovered=fail attempt=0 w2= rc2=1 deadline=$((SECONDS + 45))
        while (( SECONDS < deadline )); do
            attempt=$((attempt + 1))
            set +e
            w2=$(fetch5 "http://[2001:db8:b::1]:$op5/payload.bin" "$WORK/p5b2.out" 30)
            rc2=$?
            set -e
            if [[ $rc2 == 0 && -f $WORK/p5b2.out && $(sha "$WORK/p5b2.out") == "$p5sha" ]]; then
                recovered=pass; break
            fi
            sleep 2
        done
        local srv_alive=dead
        sudo -n kill -0 "$srv_pid" 2>/dev/null && srv_alive=alive
        record 5-resilience route-recovery-while-running namespace "$recovered" \
            "$(jq -n --argjson attempts "$attempt" --arg curl "${w2:-}" --argjson rc "$rc2" \
                --arg srv "$srv_alive" \
                '{attempts:$attempts,curl:$curl,rc:$rc,serverProcess:$srv,
                  note:"routeRefreshSeconds=2, hardFailurePenaltySeconds=3"}')" \
            "$RUN_DIR/s5.rust.log"
        status=fail
        [[ $srv_alive == alive ]] && status=pass
        record 5-resilience server-process-stability namespace "$status" \
            "$(jq -n --arg pid "$srv_pid" '{pid:$pid}')" "$RUN_DIR/s5.rust.log"

        sudo -n kill "$srv_pid" 2>/dev/null || true
        for ns in $nscli $nssrv $nsorig; do ns_drop "$ns"; done
    else
        record 5-resilience netem-and-route-loss namespace skip \
            "$(jq -n '{reason:"no passwordless sudo"}')"
    fi

    # --- 5c: immediate family failure falls back fast (loopback)
    # localhost → ::1 + 127.0.0.1; origin only on 127.0.0.1; dial preferIpv6.
    # ::1:<port> is connection-refused immediately; fallback must be fast.
    local cp6 op6
    cp6=$(alloc_port); op6=$(alloc_port)
    start_cover ::1 "$cp6"
    local origin6=$WORK/origin6
    start_origin origin6-v4only 127.0.0.1 "$op6" "$origin6"
    head -c 262144 /dev/urandom >"$origin6/payload.bin"
    local p6sha; p6sha=$(sha "$origin6/payload.bin")
    local name6=s5c port6 sp6
    port6=$(alloc_port); sp6=$(alloc_port)
    gen_server "$name6" "$port6" '{"mode":"dualStack","ipv4":"127.0.0.1","ipv6":"::1"}' \
        "[::1]:$cp6" cover.test '{"mode":"preferIpv6"}'
    gen_xray x5c "$(xray_leg "$sp6" "$name6" ::1 "$port6")"
    start_server "$WORK/$name6.rust.log" "$WORK/$name6.server.json"
    start_bg "$WORK/x5c.xray.log" "$XRAY" run -config "$WORK/x5c.xray.json"
    wait_listen ::1 "$port6"; wait_listen 127.0.0.1 "$sp6"
    local w6 rc6
    set +e
    w6=$(fetch "$sp6" "http://localhost:$op6/payload.bin" "$WORK/p5c.out" 30)
    rc6=$?
    set -e
    local got6=none; [[ -f $WORK/p5c.out ]] && got6=$(sha "$WORK/p5c.out")
    local t_total; t_total=$(awk '{print $2}' <<<"${w6:-0 99}")
    local status=fail
    if [[ $rc6 == 0 && $got6 == "$p6sha" ]] && \
       awk -v t="$t_total" 'BEGIN{exit !(t < 3.0)}'; then
        status=pass
    fi
    record 5-resilience refused-v6-fast-fallback loopback "$status" \
        "$(jq -n --arg curl "${w6:-}" --argjson rc "$rc6" --arg t "$t_total" \
            --arg expect "$p6sha" --arg got "$got6" \
            '{dial:"preferIpv6",v6:"connection-refused",curl:$curl,rc:$rc,
              timeTotalS:($t|tonumber),thresholdS:3.0,byteExact:($expect==$got)}')" \
        "$RUN_DIR/s5c.rust.log"
    bench_unlock
}

for ((i = 0; i < ${#PHASES}; i++)); do
    "phase${PHASES:i:1}"
done
log "results: $RESULTS"
log "workdir: $WORK"
