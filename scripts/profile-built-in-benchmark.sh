#!/usr/bin/env bash
# Compatibility name for the single versioned forensic profiling engine.
set -Eeuo pipefail

readonly SCRIPT_PATH="$(readlink -f -- "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIRECTORY="$(dirname -- "$SCRIPT_PATH")"
exec "$SCRIPT_DIRECTORY/profile-forensics.sh" "$@"
