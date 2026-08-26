#!/usr/bin/env bash
# Fail-closed CURRENT/PREVIOUS deployment for the permanent rust-reality VPS.
# Configuration and identity remain root-owned state outside binary releases.
set -Eeuo pipefail
umask 077

readonly REPOSITORY="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly HOST=${RUST_REALITY_VPS_HOST:-rust-reality-vps}
readonly SERVICE=${RUST_REALITY_VPS_SERVICE:-rust-reality.service}
readonly RELEASE_ROOT=/opt/rust-reality/releases
readonly CONFIG_ROOT=/etc/rust-reality/releases
readonly CURRENT_BINARY_LINK=/opt/rust-reality/current
readonly PREVIOUS_BINARY_LINK=/opt/rust-reality/previous
readonly CURRENT_CONFIG_LINK=/etc/rust-reality/current
readonly PREVIOUS_CONFIG_LINK=/etc/rust-reality/previous
readonly STATE_ROOT=/var/lib/rust-reality/deployment
readonly MUTATE_REMOTE=${MUTATE_REMOTE:-0}

usage() {
    cat >&2 <<'USAGE'
usage: scripts/deploy-release-vps.sh COMMAND

Commands and required environment:
  preflight
  bootstrap  RELEASE_ID, BASELINE_BINARY, BASELINE_CONFIG, MUTATE_REMOTE=1
  stage      RELEASE_ID, BINARY, CONFIG, EXPECTED_SHA256, EXPECTED_VERSION,
             MUTATE_REMOTE=1
  cutover    RELEASE_ID, MUTATE_REMOTE=1
  rollback   MUTATE_REMOTE=1
  promote    RELEASE_ID, MUTATE_REMOTE=1; PRUNE_OLD_RELEASES=1 is optional

The canonical host is rust-reality-vps. No command changes SSH, firewall, or
public ports. stage validates before mutation; cutover rolls back on failed
startup/listener health. Application-level canary failure must invoke rollback.
USAGE
}

die() {
    printf 'deployment error: %s\n' "$*" >&2
    exit 1
}

require_mutation_authority() {
    [[ $MUTATE_REMOTE == 1 ]] || die 'remote mutation requires MUTATE_REMOTE=1'
}

validate_release_id() {
    [[ ${RELEASE_ID:-} =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$ ]] \
        || die 'RELEASE_ID is missing or invalid'
}

ssh_host() {
    ssh -o BatchMode=yes -o ConnectTimeout=10 "$HOST" "$@"
}

verify_ssh() {
    ssh_host true
}

preflight() {
    verify_ssh
    ssh_host "SERVICE='$SERVICE' bash -s" <<'REMOTE'
set -Eeuo pipefail
state=$(systemctl is-active "$SERVICE" 2>/dev/null || true)
pid=$(systemctl show "$SERVICE" -p MainPID --value 2>/dev/null || true)
exe=
version=
sha=
if [[ $pid =~ ^[1-9][0-9]*$ && -e /proc/$pid/exe ]]; then
    exe=$(readlink -f "/proc/$pid/exe")
    sha=$(sha256sum "$exe" | awk '{print $1}')
    version=$($exe --version 2>&1 | head -n 1)
fi
public_ports=$(ss -ltnH | awk '$4 ~ /(^|\]|:)22$/ || $4 ~ /(^|\]|:)443$/ {print $4}' | sort -u | paste -sd, -)
printf 'service=%s\nstate=%s\npid=%s\nexecutable=%s\nversion=%s\nsha256=%s\nexpected_public_listeners=%s\n' \
    "$SERVICE" "$state" "$pid" "$exe" "$version" "$sha" "$public_ports"
REMOTE
}

bootstrap() {
    require_mutation_authority
    validate_release_id
    [[ -n ${BASELINE_BINARY:-} && ${BASELINE_BINARY:0:1} == / ]] \
        || die 'BASELINE_BINARY must be an absolute remote path'
    [[ -n ${BASELINE_CONFIG:-} && ${BASELINE_CONFIG:0:1} == / ]] \
        || die 'BASELINE_CONFIG must be an absolute remote path'
    verify_ssh
    ssh_host "sudo -n bash -s -- '$RELEASE_ID' '$BASELINE_BINARY' '$BASELINE_CONFIG' '$SERVICE'" <<'REMOTE'
set -Eeuo pipefail
release_id=$1
baseline_binary=$2
baseline_config=$3
service=$4
release_root=/opt/rust-reality/releases
config_root=/etc/rust-reality/releases
state_root=/var/lib/rust-reality/deployment
[[ -x $baseline_binary && -r $baseline_config ]]
install -d -m 0755 "$release_root/$release_id"
install -d -m 0750 -o root -g rust-reality "$config_root/$release_id"
install -d -m 0750 -o root -g rust-reality "$state_root"
install -m 0755 "$baseline_binary" "$release_root/$release_id/rust-reality"
install -m 0640 -o root -g rust-reality "$baseline_config" "$config_root/$release_id/config.json"
binary_sha=$(sha256sum "$release_root/$release_id/rust-reality" | awk '{print $1}')
config_sha=$(sha256sum "$config_root/$release_id/config.json" | awk '{print $1}')
printf 'legacyBinary=%s\nlegacyBinarySha256=%s\nlegacyConfig=%s\nlegacyConfigSha256=%s\n' \
    "$baseline_binary" "$binary_sha" "$baseline_config" "$config_sha" \
    >"$state_root/bootstrap"
chmod 0600 "$state_root/bootstrap"
ln -sfn "$release_root/$release_id" /opt/rust-reality/current.next
mv -Tf /opt/rust-reality/current.next /opt/rust-reality/current
ln -sfn "$release_root/$release_id" /opt/rust-reality/previous.next
mv -Tf /opt/rust-reality/previous.next /opt/rust-reality/previous
ln -sfn "$config_root/$release_id" /etc/rust-reality/current.next
mv -Tf /etc/rust-reality/current.next /etc/rust-reality/current
ln -sfn "$config_root/$release_id" /etc/rust-reality/previous.next
mv -Tf /etc/rust-reality/previous.next /etc/rust-reality/previous
systemctl is-active --quiet "$service"
REMOTE
    local unit_staging
    unit_staging=$(mktemp)
    trap 'rm -f -- "$unit_staging"' RETURN
    install -m 0644 "$REPOSITORY/deploy/rust-reality-vps.service" "$unit_staging"
    scp -q "$unit_staging" "$HOST:/tmp/rust-reality-vps.service.$$.new"
    ssh_host "sudo -n install -m 0644 /tmp/rust-reality-vps.service.$$.new /etc/systemd/system/$SERVICE && rm -f /tmp/rust-reality-vps.service.$$.new && sudo -n systemctl daemon-reload"
    printf 'bootstrapped %s as protected CURRENT/PREVIOUS; running process was not restarted\n' "$RELEASE_ID"
}

stage() {
    require_mutation_authority
    validate_release_id
    [[ -x ${BINARY:-} ]] || die 'BINARY must name an executable local candidate'
    [[ -r ${CONFIG:-} ]] || die 'CONFIG must name a readable local candidate config'
    [[ ${EXPECTED_SHA256:-} =~ ^[0-9a-f]{64}$ ]] || die 'EXPECTED_SHA256 is invalid'
    [[ ${EXPECTED_VERSION:-} =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9.]+)?$ ]] \
        || die 'EXPECTED_VERSION is invalid'
    local observed_sha observed_version remote_staging
    observed_sha=$(sha256sum "$BINARY" | awk '{print $1}')
    [[ $observed_sha == "$EXPECTED_SHA256" ]] || die 'local binary SHA-256 mismatch'
    observed_version=$($BINARY --version | awk 'NR == 1 {print $2}')
    [[ $observed_version == "$EXPECTED_VERSION" ]] || die 'local binary version mismatch'
    "$BINARY" check --config "$CONFIG" >/dev/null
    "$BINARY" self-test --config "$CONFIG" >/dev/null
    verify_ssh
    remote_staging=$(ssh_host 'mktemp -d /tmp/rust-reality-deploy.XXXXXXXX')
    [[ $remote_staging == /tmp/rust-reality-deploy.* ]] || die 'unsafe remote staging path'
    trap 'ssh_host "rm -rf -- $remote_staging" >/dev/null 2>&1 || true' RETURN
    scp -q "$BINARY" "$HOST:$remote_staging/rust-reality"
    scp -q "$CONFIG" "$HOST:$remote_staging/config.json"
    ssh_host "sudo -n bash -s -- '$RELEASE_ID' '$EXPECTED_SHA256' '$EXPECTED_VERSION' '$remote_staging'" <<'REMOTE'
set -Eeuo pipefail
release_id=$1
expected_sha=$2
expected_version=$3
staging=$4
[[ $staging == /tmp/rust-reality-deploy.* && -f $staging/rust-reality && -f $staging/config.json ]]
observed_sha=$(sha256sum "$staging/rust-reality" | awk '{print $1}')
[[ $observed_sha == "$expected_sha" ]]
chmod 0755 "$staging/rust-reality"
[[ $($staging/rust-reality --version | awk 'NR == 1 {print $2}') == "$expected_version" ]]
$staging/rust-reality check --config "$staging/config.json" >/dev/null
$staging/rust-reality self-test --config "$staging/config.json" >/dev/null
install -d -m 0755 "/opt/rust-reality/releases/$release_id"
install -d -m 0750 -o root -g rust-reality "/etc/rust-reality/releases/$release_id"
install -m 0755 "$staging/rust-reality" "/opt/rust-reality/releases/$release_id/rust-reality"
install -m 0640 -o root -g rust-reality "$staging/config.json" "/etc/rust-reality/releases/$release_id/config.json"
[[ $(sha256sum "/opt/rust-reality/releases/$release_id/rust-reality" | awk '{print $1}') == "$expected_sha" ]]
rm -rf -- "$staging"
REMOTE
    trap - RETURN
    printf 'staged %s without changing CURRENT\n' "$RELEASE_ID"
}

remote_switch() {
    local release_id=$1
    ssh_host "sudo -n bash -s -- '$release_id' '$SERVICE'" <<'REMOTE'
set -Eeuo pipefail
release_id=$1
service=$2
release_root=/opt/rust-reality/releases
config_root=/etc/rust-reality/releases
state_root=/var/lib/rust-reality/deployment
new_binary=$release_root/$release_id
new_config=$config_root/$release_id
[[ -x $new_binary/rust-reality && -r $new_config/config.json ]]
install -d -m 0750 -o root -g rust-reality "$state_root"
old_binary=$(readlink -f /opt/rust-reality/current)
old_config=$(readlink -f /etc/rust-reality/current)
[[ $old_binary == "$release_root/"* && $old_config == "$config_root/"* ]]
unexpected_public_listeners() {
    ss -ltnH | awk '
        $4 ~ /^(0\.0\.0\.0|\[::\]|\*):/ {
            port=$4
            sub(/^.*:/, "", port)
            if (port != 22 && port != 443) print $4
        }
    ' | sort -u
}
# Some hosts have an unrelated, firewall-blocked daemon which already binds a
# wildcard address. A rust-reality deployment must not introduce another
# public listener, but disabling unrelated host services is outside this
# deployment tool's authority. Snapshot the pre-cutover set and reject only
# ports newly introduced during the cutover.
preexisting_unexpected=$(unexpected_public_listeners)
rollback() {
    set +e
    systemctl stop "$service"
    ln -sfn "$old_binary" /opt/rust-reality/current.rollback
    mv -Tf /opt/rust-reality/current.rollback /opt/rust-reality/current
    ln -sfn "$old_config" /etc/rust-reality/current.rollback
    mv -Tf /etc/rust-reality/current.rollback /etc/rust-reality/current
    systemctl start "$service"
    systemctl is-active --quiet "$service"
}
trap 'status=$?; trap - ERR; rollback; exit "$status"' ERR
ln -sfn "$old_binary" /opt/rust-reality/previous.next
mv -Tf /opt/rust-reality/previous.next /opt/rust-reality/previous
ln -sfn "$old_config" /etc/rust-reality/previous.next
mv -Tf /etc/rust-reality/previous.next /etc/rust-reality/previous
systemctl stop "$service"
ln -sfn "$new_binary" /opt/rust-reality/current.next
mv -Tf /opt/rust-reality/current.next /opt/rust-reality/current
ln -sfn "$new_config" /etc/rust-reality/current.next
mv -Tf /etc/rust-reality/current.next /etc/rust-reality/current
systemctl start "$service"
for _ in $(seq 1 100); do
    pid=$(systemctl show "$service" -p MainPID --value)
    if systemctl is-active --quiet "$service" \
        && [[ $pid =~ ^[1-9][0-9]*$ ]] \
        && [[ $(readlink -f "/proc/$pid/exe" 2>/dev/null || true) == "$new_binary/rust-reality" ]] \
        && ss -ltnH | awk '$4 ~ /(^|\]|:)443$/ {found=1} END {exit !found}'; then
        break
    fi
    sleep 0.1
done
systemctl is-active --quiet "$service"
pid=$(systemctl show "$service" -p MainPID --value)
[[ $(readlink -f "/proc/$pid/exe") == "$new_binary/rust-reality" ]]
ss -ltnH | awk '$4 ~ /(^|\]|:)443$/ {found=1} END {exit !found}'
observed_unexpected=$(unexpected_public_listeners)
introduced_unexpected=
while IFS= read -r listener; do
    [[ -z $listener ]] && continue
    if ! grep -Fqx -- "$listener" <<<"$preexisting_unexpected"; then
        introduced_unexpected+="${introduced_unexpected:+,}$listener"
    fi
done <<<"$observed_unexpected"
[[ -z $introduced_unexpected ]]
printf 'pendingRelease=%s\npreviousBinary=%s\npreviousConfig=%s\n' \
    "$release_id" "$old_binary" "$old_config" >"$state_root/pending"
chmod 0600 "$state_root/pending"
trap - ERR
REMOTE
}

cutover() {
    require_mutation_authority
    validate_release_id
    verify_ssh
    remote_switch "$RELEASE_ID"
    verify_ssh
    printf 'cut over to %s; PREVIOUS is ready for canary rollback\n' "$RELEASE_ID"
}

rollback() {
    require_mutation_authority
    verify_ssh
    ssh_host "sudo -n bash -s -- '$SERVICE'" <<'REMOTE'
set -Eeuo pipefail
service=$1
previous_binary=$(readlink -f /opt/rust-reality/previous)
previous_config=$(readlink -f /etc/rust-reality/previous)
[[ $previous_binary == /opt/rust-reality/releases/* ]]
[[ $previous_config == /etc/rust-reality/releases/* ]]
systemctl stop "$service"
ln -sfn "$previous_binary" /opt/rust-reality/current.next
mv -Tf /opt/rust-reality/current.next /opt/rust-reality/current
ln -sfn "$previous_config" /etc/rust-reality/current.next
mv -Tf /etc/rust-reality/current.next /etc/rust-reality/current
systemctl start "$service"
systemctl is-active --quiet "$service"
ss -ltnH | awk '$4 ~ /(^|\]|:)443$/ {found=1} END {exit !found}'
rm -f /var/lib/rust-reality/deployment/pending
REMOTE
    verify_ssh
    printf 'rollback restored PREVIOUS and verified service/443/SSH\n'
}

promote() {
    require_mutation_authority
    validate_release_id
    local prune=${PRUNE_OLD_RELEASES:-0}
    [[ $prune == 0 || $prune == 1 ]] || die 'PRUNE_OLD_RELEASES must be 0 or 1'
    verify_ssh
    ssh_host "sudo -n bash -s -- '$RELEASE_ID' '$SERVICE' '$prune'" <<'REMOTE'
set -Eeuo pipefail
release_id=$1
service=$2
prune=$3
current_binary=$(readlink -f /opt/rust-reality/current)
current_config=$(readlink -f /etc/rust-reality/current)
previous_binary=$(readlink -f /opt/rust-reality/previous)
previous_config=$(readlink -f /etc/rust-reality/previous)
[[ $current_binary == "/opt/rust-reality/releases/$release_id" ]]
[[ $current_config == "/etc/rust-reality/releases/$release_id" ]]
systemctl is-active --quiet "$service"
pid=$(systemctl show "$service" -p MainPID --value)
[[ $(readlink -f "/proc/$pid/exe") == "$current_binary/rust-reality" ]]
printf 'current=%s\nprevious=%s\npromotedAt=%s\n' \
    "$current_binary" "$previous_binary" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >/var/lib/rust-reality/deployment/current
chmod 0600 /var/lib/rust-reality/deployment/current
rm -f /var/lib/rust-reality/deployment/pending
if [[ $prune == 1 ]]; then
    python3 - "$current_binary" "$previous_binary" "$current_config" "$previous_config" <<'PY'
from pathlib import Path
import shutil
import sys

keep_binary = {Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()}
keep_config = {Path(sys.argv[3]).resolve(), Path(sys.argv[4]).resolve()}
for root, keep in ((Path('/opt/rust-reality/releases'), keep_binary),
                   (Path('/etc/rust-reality/releases'), keep_config)):
    assert root.is_dir()
    for child in root.iterdir():
        resolved = child.resolve()
        assert child.parent == root and resolved != root
        if resolved not in keep:
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
PY
fi
REMOTE
    printf 'promoted %s; CURRENT and PREVIOUS retained\n' "$RELEASE_ID"
}

command=${1:-}
case $command in
    preflight) preflight ;;
    bootstrap) bootstrap ;;
    stage) stage ;;
    cutover) cutover ;;
    rollback) rollback ;;
    promote) promote ;;
    *) usage; exit 2 ;;
esac
