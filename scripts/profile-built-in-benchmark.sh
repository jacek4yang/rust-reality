#!/usr/bin/env bash
# Compatibility name for the single versioned forensic profiling engine.
set -Eeuo pipefail

readonly SCRIPT_DIRECTORY="$({ cd -- "$(dirname -- "${BASH_SOURCE[0]}")"; pwd; })"
exec "$SCRIPT_DIRECTORY/profile-forensics.sh" "$@"
