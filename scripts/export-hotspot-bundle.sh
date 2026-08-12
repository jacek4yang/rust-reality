#!/usr/bin/env bash
# Export one perf hotspot through DWARF, IDALib, LLVM, and symbol-offset samples.
set -Eeuo pipefail

readonly REPOSITORY="$({ cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."; pwd; })"

binary=${BIN:-}
perf_data=${PERF_DATA:-}
out_dir=${OUT_DIR:-}
run_id=${RUN_ID:-}
label=
address=
idalib_python=${IDALIB_PYTHON:-}
timeout_seconds=${IDALIB_TIMEOUT_SECONDS:-300}

usage() {
    cat <<'EOF'
Usage: scripts/export-hotspot-bundle.sh --binary PATH --perf-data PATH \
  --out-dir PATH --run-id ID --label LABEL --address STATIC_ELF_ADDRESS \
  --idalib-python PATH

OUT_DIR/RUN_ID must be an existing profile-forensics run. The hotspot path
must not exist. IDA receives a private copy of the exact ELF so concurrent
exports cannot share or corrupt an .i64 database.
EOF
}

die() {
    printf 'export-hotspot-bundle: %s\n' "$*" >&2
    exit 2
}

need_argument() {
    [[ $# -ge 2 ]] || die "missing value for $1"
}

while (($#)); do
    case "$1" in
        --binary) need_argument "$@"; binary=$2; shift 2 ;;
        --perf-data) need_argument "$@"; perf_data=$2; shift 2 ;;
        --out-dir) need_argument "$@"; out_dir=$2; shift 2 ;;
        --run-id) need_argument "$@"; run_id=$2; shift 2 ;;
        --label) need_argument "$@"; label=$2; shift 2 ;;
        --address) need_argument "$@"; address=$2; shift 2 ;;
        --idalib-python) need_argument "$@"; idalib_python=$2; shift 2 ;;
        --timeout-seconds) need_argument "$@"; timeout_seconds=$2; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ -n $binary ]] || die '--binary is required'
[[ -n $perf_data ]] || die '--perf-data is required'
[[ -n $out_dir ]] || die '--out-dir is required'
[[ $run_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die 'unsafe --run-id'
[[ $label =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die 'unsafe --label'
[[ $address =~ ^0[xX][0-9a-fA-F]+$ ]] || die '--address must be hexadecimal'
[[ -n $idalib_python ]] || die '--idalib-python is required'
[[ $timeout_seconds =~ ^[1-9][0-9]*$ ]] || die 'invalid --timeout-seconds'

for program in addr2line llvm-objdump perf python3 readelf sha256sum timeout; do
    command -v "$program" >/dev/null 2>&1 || die "required tool unavailable: $program"
done
[[ -x $binary ]] || die "binary is not executable: $binary"
[[ -r $perf_data ]] || die "perf data is unreadable: $perf_data"
[[ -x $idalib_python ]] || die "IDALib Python is not executable: $idalib_python"
binary=$(realpath "$binary")
perf_data=$(realpath "$perf_data")
out_dir=$(realpath "$out_dir")
run_dir="$out_dir/$run_id"
[[ -d $run_dir ]] || die "profile run does not exist: $run_dir"
hotspot_dir="$run_dir/hotspots/$label"
[[ ! -e $hotspot_dir ]] || die "hotspot output already exists: $hotspot_dir"
mkdir -m 700 -p -- "$hotspot_dir/ida-work"

binary_sha256=$(sha256sum -- "$binary" | awk '{print $1}')
binary_build_id=$(readelf -n -- "$binary" | awk '/Build ID:/ {print $3; exit}')
[[ -n $binary_build_id ]] || die 'binary has no GNU build ID'
perf buildid-list -i "$perf_data" >"$hotspot_dir/perf-buildids.txt"
grep -Fqi -- "$binary_build_id" "$hotspot_dir/perf-buildids.txt" ||
    die "perf data does not contain binary build ID $binary_build_id"

# IDALib creates a database adjacent to its input. Keep both private to this
# hotspot so parallel jobs never share an .i64 path.
ida_input="$hotspot_dir/ida-work/$(basename -- "$binary")"
cp --reflink=auto -- "$binary" "$ida_input"
[[ $(sha256sum -- "$ida_input" | awk '{print $1}') == "$binary_sha256" ]] ||
    die 'isolated IDA input SHA-256 mismatch'

addr2line -e "$binary" -f -C -i "$address" >"$hotspot_dir/dwarf.txt"
timeout -k 5s "$timeout_seconds" "$idalib_python" \
    "$REPOSITORY/scripts/idalib-export-address.py" \
    "$ida_input" "$address" "$hotspot_dir/ida"

mapfile -t function_fields < <(
    python3 - "$hotspot_dir/ida/summary.json" <<'PY'
import json
import sys
summary = json.load(open(sys.argv[1], encoding="utf-8"))
print(summary["function"]["start"])
print(summary["function"]["end"])
print(summary["function"]["name"])
PY
)
function_start=${function_fields[0]}
function_end=${function_fields[1]}
raw_symbol=${function_fields[2]}

llvm-objdump --disassemble --demangle --source --line-numbers -M intel \
    --start-address="$function_start" --stop-address="$function_end" \
    "$binary" >"$hotspot_dir/llvm-disassembly.txt"

perf_events="$hotspot_dir/perf-script-events.txt"
perf script -G --no-demangle -i "$perf_data" \
    -F hw:ip,sym,symoff,period,dso >"$perf_events" \
    2>"$hotspot_dir/perf-script-events.stderr"

samples="$hotspot_dir/perf-symbol-samples.txt"
python3 - "$perf_events" "$samples" "$raw_symbol" "$(basename -- "$binary")" \
    "$binary_sha256" "$binary_build_id" <<'PY'
import sys
from pathlib import Path

events, output, raw_symbol, dso_basename, sha256, build_id = sys.argv[1:]
rows = []
prefix = raw_symbol + "+0x"
for line in Path(events).read_text(encoding="utf-8").splitlines():
    parts = line.strip().split(maxsplit=3)
    if len(parts) != 4 or not parts[2].startswith(prefix):
        continue
    dso = Path(parts[3].strip().strip("()[]")).name
    if dso != dso_basename:
        continue
    rows.append(line.strip())
if not rows:
    raise SystemExit(f"no perf samples resolved to {raw_symbol} in {dso_basename}")
with open(output, "x", encoding="utf-8") as handle:
    handle.write(f"# binary_sha256={sha256}\n")
    handle.write(f"# binary_build_id={build_id}\n")
    handle.write(f"# raw_symbol={raw_symbol}\n")
    handle.write(f"# dso_basename={dso_basename}\n")
    handle.write("# fields=period ip raw_symbol+offset dso\n")
    handle.write("\n".join(rows) + "\n")
print(f"resolved sample rows: {len(rows)}")
PY

python3 - "$hotspot_dir/metadata.json" "$label" "$address" "$binary" \
    "$binary_sha256" "$binary_build_id" "$perf_data" "$raw_symbol" \
    "$function_start" "$function_end" <<'PY'
import hashlib
import json
import sys

(
    output, label, address, binary, binary_sha256, build_id, perf_data,
    raw_symbol, function_start, function_end,
) = sys.argv[1:]

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

record = {
    "schemaVersion": 1,
    "label": label,
    "requestedStaticAddress": address,
    "binary": binary,
    "binarySha256": binary_sha256,
    "binaryBuildId": build_id,
    "perfData": perf_data,
    "perfDataSha256": sha256_file(perf_data),
    "rawSymbol": raw_symbol,
    "functionStart": function_start,
    "functionEnd": function_end,
}
with open(output, "x", encoding="utf-8") as handle:
    json.dump(record, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

python3 "$REPOSITORY/scripts/aggregate-hotspot-samples.py" "$hotspot_dir"
sha256sum -- "$hotspot_dir"/metadata.json "$hotspot_dir"/dwarf.txt \
    "$hotspot_dir"/ida/summary.json "$hotspot_dir"/ida/disassembly.json \
    "$hotspot_dir"/ida/pseudocode.c "$hotspot_dir"/llvm-disassembly.txt \
    "$samples" "$hotspot_dir"/instruction-hotspots.* \
    >"$hotspot_dir/SHA256SUMS"
printf 'hotspot bundle complete: %s\n' "$hotspot_dir"
