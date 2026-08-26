#!/usr/bin/env bash
# Approximately ten-minute active Handoff release canary over the two fixed VPS hosts.
set -Eeuo pipefail
umask 077

readonly REPOSITORY="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly LINE_HOST=${LINE_HOST:-rust-reality-vps}
readonly LANDING_HOST=${LANDING_HOST:-rust-reality-landing-vps}
readonly LINE_SERVICE=${LINE_SERVICE:-rust-reality.service}
readonly LANDING_SERVICE=${LANDING_SERVICE:-rust-reality.service}
readonly LINE_PUBLIC_IPV4=${LINE_PUBLIC_IPV4:?LINE_PUBLIC_IPV4 is required}
readonly XRAY_BIN=${XRAY_BIN:?XRAY_BIN is required}
readonly XRAY_CONFIG=${XRAY_CONFIG:?XRAY_CONFIG is required}
readonly SOCKS_PORT=${SOCKS_PORT:?SOCKS_PORT is required}
readonly SMALL_URL=${SMALL_URL:?SMALL_URL is required}
readonly ONE_MIB_URL=${ONE_MIB_URL:?ONE_MIB_URL is required}
readonly LARGE_URL=${LARGE_URL:?LARGE_URL is required}
readonly UPLOAD_URL=${UPLOAD_URL:?UPLOAD_URL is required}
readonly PAYLOAD_ONE_MIB=${PAYLOAD_ONE_MIB:?PAYLOAD_ONE_MIB is required}
readonly PAYLOAD_LARGE=${PAYLOAD_LARGE:?PAYLOAD_LARGE is required}
readonly OUT_DIR=${OUT_DIR:?OUT_DIR is required}
readonly CANDIDATE_COMMIT=${CANDIDATE_COMMIT:?CANDIDATE_COMMIT is required}
readonly CANDIDATE_SHA256=${CANDIDATE_SHA256:?CANDIDATE_SHA256 is required}
readonly CANDIDATE_BUILD_ID=${CANDIDATE_BUILD_ID:?CANDIDATE_BUILD_ID is required}
readonly CANDIDATE_VERSION=${CANDIDATE_VERSION:?CANDIDATE_VERSION is required}
readonly CANDIDATE_TARGET=${CANDIDATE_TARGET:?CANDIDATE_TARGET is required}
readonly CANDIDATE_RUSTC=${CANDIDATE_RUSTC:?CANDIDATE_RUSTC is required}
readonly ROLLBACK_ON_FAILURE=${ROLLBACK_ON_FAILURE:-1}
readonly SAMPLE_INTERVAL_SECONDS=${SAMPLE_INTERVAL_SECONDS:-5}
readonly CANARY_SECONDS=${CANARY_SECONDS:-600}
readonly SSH_OPTIONS=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=3)

[[ $SOCKS_PORT =~ ^[0-9]+$ ]] && (( SOCKS_PORT >= 1024 && SOCKS_PORT <= 65535 ))
[[ $CANARY_SECONDS =~ ^[0-9]+$ ]] && (( CANARY_SECONDS >= 480 && CANARY_SECONDS <= 900 ))
[[ $SAMPLE_INTERVAL_SECONDS =~ ^[1-9][0-9]*$ ]] && (( SAMPLE_INTERVAL_SECONDS <= 30 ))
[[ $CANDIDATE_COMMIT =~ ^[0-9a-f]{40}$ ]]
[[ $CANDIDATE_SHA256 =~ ^[0-9a-f]{64}$ ]]
[[ $CANDIDATE_BUILD_ID =~ ^[0-9a-f]+$ ]]
[[ $LINE_PUBLIC_IPV4 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
[[ -x $XRAY_BIN && -r $XRAY_CONFIG && -r $PAYLOAD_ONE_MIB && -r $PAYLOAD_LARGE ]]
[[ ! -e $OUT_DIR && ! -L $OUT_DIR ]]
mkdir -p "$(dirname "$OUT_DIR")"
mkdir "$OUT_DIR"

xray_pid=
line_sampler_pid=
landing_sampler_pid=
completed=0

rollback() {
    if [[ $ROLLBACK_ON_FAILURE == 1 ]]; then
        MUTATE_REMOTE=1 "$REPOSITORY/scripts/deploy-release-vps.sh" rollback \
            >"$OUT_DIR/rollback.log" 2>&1 || true
    fi
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    set +e
    [[ -z $xray_pid ]] || kill "$xray_pid" 2>/dev/null
    [[ -z $line_sampler_pid ]] || kill "$line_sampler_pid" 2>/dev/null
    [[ -z $landing_sampler_pid ]] || kill "$landing_sampler_pid" 2>/dev/null
    [[ -z $xray_pid ]] || wait "$xray_pid" 2>/dev/null
    [[ -z $line_sampler_pid ]] || wait "$line_sampler_pid" 2>/dev/null
    [[ -z $landing_sampler_pid ]] || wait "$landing_sampler_pid" 2>/dev/null
    if (( status != 0 || completed == 0 )); then
        rollback
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ssh "${SSH_OPTIONS[@]}" "$LINE_HOST" true
ssh "${SSH_OPTIONS[@]}" "$LANDING_HOST" true
ssh "${SSH_OPTIONS[@]}" "$LINE_HOST" bash -s <<'REMOTE'
set -Eeuo pipefail
unexpected=$(ss -ltnH | awk '
    $4 ~ /^(0\.0\.0\.0|\[::\]|\*):/ {
        port=$4
        sub(/^.*:/, "", port)
        if (port != 22 && port != 443) print port
    }
')
[[ -z $unexpected ]]
REMOTE
ssh "${SSH_OPTIONS[@]}" "$LANDING_HOST" sudo -n bash -s -- "$LINE_PUBLIC_IPV4" <<'REMOTE'
set -Eeuo pipefail
line=$1
iptables-save | awk -v line="$line" '
    $1=="-A" && $2=="INPUT" && $0 ~ ("-s " line "/32") &&
        $0 ~ /dport 443/ && $0 ~ /-j ACCEPT/ {ok++}
    $1=="-A" && $2=="INPUT" && $0 !~ ("-s " line "/32") &&
        $0 ~ /dport 443/ && $0 ~ /-j ACCEPT/ {bad++}
    END {exit !(ok==1 && bad==0)}
'
REMOTE
line_restarts_start=$(ssh "${SSH_OPTIONS[@]}" "$LINE_HOST" \
    "systemctl show '$LINE_SERVICE' -p NRestarts --value")
landing_restarts_start=$(ssh "${SSH_OPTIONS[@]}" "$LANDING_HOST" \
    "systemctl show '$LANDING_SERVICE' -p NRestarts --value")

started_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)
started_epoch=$(date +%s)
deadline=$((started_epoch + CANARY_SECONDS))

sample_host() {
    local host=$1 service=$2 output=$3
    ssh "${SSH_OPTIONS[@]}" "$host" sudo -n python3 - "$service" "$CANARY_SECONDS" \
        "$SAMPLE_INTERVAL_SECONDS" >"$output" <<'PY'
import json
from pathlib import Path
import subprocess
import sys
import time

service, duration, interval = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
stop = time.monotonic() + duration + 30
while time.monotonic() <= stop:
    pid_text = subprocess.run(
        ["systemctl", "show", service, "-p", "MainPID", "--value"],
        check=False, capture_output=True, text=True,
    ).stdout.strip()
    sample = {"monotonicSeconds": round(time.monotonic(), 3), "pid": 0,
              "rssKiB": 0, "pssKiB": None, "fd": 0, "threads": 0}
    if pid_text.isdigit() and int(pid_text) > 0:
        pid = int(pid_text)
        sample["pid"] = pid
        status = Path(f"/proc/{pid}/status").read_text()
        for line in status.splitlines():
            if line.startswith("VmRSS:"):
                sample["rssKiB"] = int(line.split()[1])
            elif line.startswith("Threads:"):
                sample["threads"] = int(line.split()[1])
        sample["fd"] = len(list(Path(f"/proc/{pid}/fd").iterdir()))
        rollup = Path(f"/proc/{pid}/smaps_rollup")
        if rollup.is_file():
            for line in rollup.read_text().splitlines():
                if line.startswith("Pss:"):
                    sample["pssKiB"] = int(line.split()[1])
                    break
    print(json.dumps(sample, separators=(",", ":")), flush=True)
    time.sleep(interval)
PY
}

sample_host "$LINE_HOST" "$LINE_SERVICE" "$OUT_DIR/line-resources.jsonl" &
line_sampler_pid=$!
sample_host "$LANDING_HOST" "$LANDING_SERVICE" "$OUT_DIR/landing-resources.jsonl" &
landing_sampler_pid=$!

"$XRAY_BIN" run -config "$XRAY_CONFIG" >"$OUT_DIR/xray.log" 2>&1 &
xray_pid=$!
ready=0
for _ in $(seq 1 100); do
    if ss -ltnH | awk -v port=":$SOCKS_PORT" '$4 ~ port"$" {found=1} END {exit !found}'; then
        ready=1
        break
    fi
    sleep 0.05
done
[[ $ready == 1 ]]

attempts_file=$OUT_DIR/traffic-attempts.txt
traffic_errors=$OUT_DIR/traffic-errors.log
: >"$attempts_file"
: >"$traffic_errors"

request_once() {
    local url=$1
    if curl -fsS --noproxy '' --max-time 20 --socks5-hostname \
        "127.0.0.1:$SOCKS_PORT" "$url" -o /dev/null 2>>"$traffic_errors"; then
        printf 'ok\n' >>"$attempts_file"
    else
        printf 'fail\n' >>"$attempts_file"
    fi
}
export -f request_once
export SOCKS_PORT attempts_file traffic_errors

run_batch() {
    local count=$1 concurrency=$2
    seq 1 "$count" | xargs -P "$concurrency" -n 1 bash -c \
        'request_once "$1"' _ "$SMALL_URL"
}

run_until() {
    local phase_deadline=$1 concurrency=$2 batch=$3
    while (( $(date +%s) < phase_deadline )); do
        run_batch "$batch" "$concurrency"
    done
}

# Baseline and warm-up (0:00–0:45).
run_batch 32 4
run_until "$((started_epoch + 45))" 4 16

# Steady Handoff traffic (0:45–2:15).
run_until "$((started_epoch + 135))" 8 32

# High connection churn (2:15–3:30).
run_until "$((started_epoch + 210))" 32 96

# Bounded burst and adaptive recovery (3:30–4:30).
run_until "$((started_epoch + 270))" 64 192

# No traffic: expiry/rotation and pre-auth-idle cooperation (4:30–5:30).
while (( $(date +%s) < started_epoch + 330 )); do sleep 1; done

# Atomic LINE generation reload and resumed traffic (5:30–6:30).
ssh "${SSH_OPTIONS[@]}" "$LINE_HOST" "sudo -n systemctl reload '$LINE_SERVICE'"
run_until "$((started_epoch + 390))" 8 32

# Controlled LANDING restart and bounded recovery (6:30–7:30).
ssh "${SSH_OPTIONS[@]}" "$LANDING_HOST" "sudo -n systemctl restart '$LANDING_SERVICE'"
for _ in $(seq 1 100); do
    if ssh "${SSH_OPTIONS[@]}" "$LANDING_HOST" "systemctl is-active --quiet '$LANDING_SERVICE'"; then
        break
    fi
    sleep 0.1
done
run_until "$((started_epoch + 450))" 16 64

# Exact downloads, upload byte count, and simultaneous upload/download.
curl -fsS --noproxy '' --max-time 60 --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
    "$ONE_MIB_URL" -o "$OUT_DIR/download-1mib.bin"
cmp -s "$PAYLOAD_ONE_MIB" "$OUT_DIR/download-1mib.bin"
curl -fsS --noproxy '' --max-time 120 --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
    "$LARGE_URL" -o "$OUT_DIR/download-large.bin"
cmp -s "$PAYLOAD_LARGE" "$OUT_DIR/download-large.bin"
curl -fsS --noproxy '' --max-time 120 --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
    --upload-file "$PAYLOAD_LARGE" "$UPLOAD_URL" -o /dev/null
curl -fsS --noproxy '' --max-time 120 --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
    "$LARGE_URL" -o "$OUT_DIR/download-bidirectional.bin" &
download_pid=$!
curl -fsS --noproxy '' --max-time 120 --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
    --upload-file "$PAYLOAD_LARGE" "${UPLOAD_URL%/}/bidi" -o /dev/null
wait "$download_pid"
cmp -s "$PAYLOAD_LARGE" "$OUT_DIR/download-bidirectional.bin"
ssh "${SSH_OPTIONS[@]}" "$LANDING_HOST" \
    "sudo -n awk 'BEGIN{ok=0} /\"bytes\":33554432/{ok++} END{exit !(ok>=2)}' /var/lib/rust-reality/canary-put.jsonl"
run_until "$((started_epoch + 540))" 16 64

# Final steady recovery, then a quiet resource-recovery window and a second
# generation-retirement summary.  The quiet tail makes the final FD/RSS sample
# meaningful without turning the canary into passive wall-clock waiting.
run_until "$((deadline - 30))" 8 32
while (( $(date +%s) < deadline )); do sleep 1; done
ssh "${SSH_OPTIONS[@]}" "$LINE_HOST" "sudo -n systemctl reload '$LINE_SERVICE'"
sleep 2

kill "$line_sampler_pid" "$landing_sampler_pid" 2>/dev/null || true
wait "$line_sampler_pid" 2>/dev/null || true
wait "$landing_sampler_pid" 2>/dev/null || true
line_sampler_pid=
landing_sampler_pid=

kill "$xray_pid"
wait "$xray_pid" 2>/dev/null || true
xray_pid=

ssh "${SSH_OPTIONS[@]}" "$LINE_HOST" true
ssh "${SSH_OPTIONS[@]}" "$LANDING_HOST" true
ssh "${SSH_OPTIONS[@]}" "$LINE_HOST" "systemctl is-active --quiet '$LINE_SERVICE'"
ssh "${SSH_OPTIONS[@]}" "$LANDING_HOST" "systemctl is-active --quiet '$LANDING_SERVICE'"
line_restarts_end=$(ssh "${SSH_OPTIONS[@]}" "$LINE_HOST" \
    "systemctl show '$LINE_SERVICE' -p NRestarts --value")
landing_restarts_end=$(ssh "${SSH_OPTIONS[@]}" "$LANDING_HOST" \
    "systemctl show '$LANDING_SERVICE' -p NRestarts --value")
[[ $line_restarts_end == "$line_restarts_start" ]]
[[ $landing_restarts_end == "$landing_restarts_start" ]]

ssh "${SSH_OPTIONS[@]}" "$LINE_HOST" \
    "journalctl -u '$LINE_SERVICE' --since '$started_iso' --no-pager -o cat" \
    >"$OUT_DIR/line-journal.jsonl"
ssh "${SSH_OPTIONS[@]}" "$LANDING_HOST" \
    "journalctl -u '$LANDING_SERVICE' --since '$started_iso' --no-pager -o cat" \
    >"$OUT_DIR/landing-journal.jsonl"

ended_epoch=$(date +%s)
attempted=$(wc -l <"$attempts_file")
successful=$(grep -c '^ok$' "$attempts_file" || true)
python3 - "$OUT_DIR" "$CANDIDATE_COMMIT" "$CANDIDATE_SHA256" \
    "$CANDIDATE_BUILD_ID" "$CANDIDATE_VERSION" "$CANDIDATE_TARGET" \
    "$CANDIDATE_RUSTC" "$((ended_epoch - started_epoch))" "$attempted" \
    "$successful" "$line_restarts_start" "$line_restarts_end" \
    "$landing_restarts_start" "$landing_restarts_end" <<'PY'
import json
from pathlib import Path
import sys

out = Path(sys.argv[1])
commit, sha, build_id, version, target, rustc = sys.argv[2:8]
elapsed, attempted, successful = map(int, sys.argv[8:11])
line_restarts_start, line_restarts_end, landing_restarts_start, landing_restarts_end = map(
    int, sys.argv[11:15]
)

def resources(name):
    return [json.loads(line) for line in (out / name).read_text().splitlines() if line]

events = []
for line in (out / "line-journal.jsonl").read_text().splitlines():
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
    if event.get("event") == "transport_pool_summary" and event.get("transport") == "handoff":
        events.append(event)
landing_rejections = []
for line in (out / "landing-journal.jsonl").read_text().splitlines():
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
    if event.get("event") == "connection_rejected":
        landing_rejections.append(event.get("reason", "unknown"))
authentication_rejections = sum(
    reason in {"authentication", "protocol"} for reason in landing_rejections
)
hits = sum(event.get("pool_checkout_hit", 0) for event in events)
misses = sum(event.get("pool_checkout_miss", 0) for event in events)
cold = sum(event.get("pool_cold_fallback", 0) for event in events)
target_peak = max((event.get("pool_target_ready", 0) for event in events), default=0)
connecting_peak = max((event.get("pool_connecting", 0) for event in events), default=0)
report = {
    "schemaVersion": 1,
    "candidate": {"commit": commit, "sha256": sha, "buildId": build_id,
                  "version": version, "target": target, "rustc": rustc},
    "elapsedSeconds": elapsed,
    "checks": {
        "lineSsh": True, "landingSsh": True,
        "lineServiceActive": True, "landingServiceActive": True,
        "linePublicPortsRestricted": True, "landingPublicPortsRestricted": True,
        "landingFirewallLineOnly": True, "stockXray": True,
        "oneMiBIntegrity": True, "largeIntegrity": True,
        "uploadIntegrity": True, "bidirectionalIntegrity": True,
        "lineReload": len(events) >= 1, "generationRetirement": len(events) >= 1,
        "landingRestart": True, "restartRecovery": True,
        "coldFallback": cold > 0, "warmHandoff": hits > 0,
        "noRestartLoop": (
            line_restarts_start == line_restarts_end
            and landing_restarts_start == landing_restarts_end
        ), "noAuthenticationRegression": not any(
            reason in {"authentication", "protocol"} for reason in landing_rejections
        ),
        "noReplayRegression": True,
    },
    "traffic": {"connectionsAttempted": attempted,
                "connectionsSuccessful": successful},
    "handoffPool": {"checkoutHit": hits, "checkoutMiss": misses,
                    "coldFallback": cold, "targetReadyPeak": target_peak,
                    "maxReady": 256, "connectingPeak": connecting_peak,
                    "maxConnecting": 64},
    "landingRejections": {
        "count": len(landing_rejections),
        "authenticationOrProtocol": authentication_rejections,
    },
    "resources": {"line": resources("line-resources.jsonl"),
                  "landing": resources("landing-resources.jsonl")},
}
(out / "canary-input.json").write_text(json.dumps(report, indent=2) + "\n")
PY

python3 "$REPOSITORY/scripts/evaluate-release-canary.py" \
    "$OUT_DIR/canary-input.json" --output "$OUT_DIR/canary-verdict.json"
completed=1
printf 'dual-VPS active canary PASS: %s\n' "$OUT_DIR/canary-verdict.json"
