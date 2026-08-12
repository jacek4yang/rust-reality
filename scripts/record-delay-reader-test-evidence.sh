#!/usr/bin/env bash
set -Eeuo pipefail
readonly REPOSITORY="$({ cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."; pwd; })"
readonly TEST_NAME='protocol::reality::tls13::target_read::tests::tcp_record_delay_matrix_covers_fifth_probe_timing'
readonly EXPECTED=${EXPECTED_SOURCE_COMMIT:?EXPECTED_SOURCE_COMMIT is required}
readonly DESTINATION=${OUT_DIR:?OUT_DIR is required}
readonly GIT_COMMON_DIR="$(git -C "$REPOSITORY" rev-parse --path-format=absolute --git-common-dir)"
readonly PROJECT_ROOT="$(dirname -- "$(dirname -- "$GIT_COMMON_DIR")")"
# This helper is the sole host-exclusive owner for its targeted Cargo run.
# The later TLS benchmark only consumes evidence.json and must not wrap this
# helper in another flock. Non-blocking acquisition fails closed if an outer
# job already owns the formal host lock; there is deliberately no env bypass.
readonly LOCK="$PROJECT_ROOT/.coord/v1.5.0/locks/host-exclusive.lock"
[[ $EXPECTED =~ ^[0-9a-f]{40}$ ]] || { echo 'EXPECTED_SOURCE_COMMIT must be a full lowercase SHA' >&2; exit 2; }
[[ $DESTINATION == /* && ! -e $DESTINATION ]] || { echo 'OUT_DIR must be an absent absolute path' >&2; exit 2; }
mkdir -p -- "$(dirname -- "$LOCK")" "$DESTINATION"
exec 9>"$LOCK"
flock -n 9 || { echo 'host-exclusive lock is busy' >&2; exit 3; }
head=$(git -C "$REPOSITORY" rev-parse HEAD)
[[ $head == "$EXPECTED" ]] || { echo "HEAD $head != EXPECTED_SOURCE_COMMIT $EXPECTED" >&2; exit 4; }
if pgrep -x cargo >/dev/null || pgrep -x rustc >/dev/null; then
    echo 'cargo/rustc already running despite host-exclusive lock' >&2; exit 5
fi
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
set +e
(cd "$REPOSITORY" && cargo test --lib "$TEST_NAME" -- --exact --nocapture) >"$DESTINATION/cargo-test.log" 2>&1
status=$?
set -e
completed=$(date -u +%Y-%m-%dT%H:%M:%SZ)
output_sha=$(sha256sum "$DESTINATION/cargo-test.log" | awk '{print $1}')
passed=false
if ((status == 0)) && grep -Fq "test $TEST_NAME ... ok" "$DESTINATION/cargo-test.log" && grep -Eq 'test result: ok\. 1 passed; 0 failed;' "$DESTINATION/cargo-test.log"; then passed=true; fi
jq -n --arg head "$head" --arg expected "$EXPECTED" --arg test "$TEST_NAME" --arg started "$started" --arg completed "$completed" --arg output "$DESTINATION/cargo-test.log" --arg output_sha "$output_sha" --argjson exit_code "$status" --argjson ok "$passed" '{schemaVersion:1,gate:"production-cover-reader-single-probe-present",repositoryHead:$head,expectedSourceCommit:$expected,testName:$test,command:["cargo","test","--lib",$test,"--","--exact","--nocapture"],startedAt:$started,completedAt:$completed,cargoExitCode:$exit_code,output:{path:$output,sha256:$output_sha},ok:$ok}' >"$DESTINATION/evidence.json"
jq -e '.ok == true and .cargoExitCode == 0 and .repositoryHead == .expectedSourceCommit' "$DESTINATION/evidence.json" >/dev/null
printf 'Production cover reader evidence: %s\n' "$DESTINATION/evidence.json"
