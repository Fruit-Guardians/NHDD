#!/usr/bin/env bash
set -euo pipefail

# Build Android-side NHDD binary for arm64 devices.
# Usage:
#   NDK=/path/to/android-ndk-r27 ./scripts/build_nhdd_android.sh
# Optional:
#   API=34 OUT=nhdd ./scripts/build_nhdd_android.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARGS=()
if [[ -n "${NDK:-${NDK_PATH:-}}" ]]; then
  ARGS+=(--ndk "${NDK:-${NDK_PATH:-}}")
fi
ARGS+=(--api "${API:-34}" --out "${OUT:-${ROOT_DIR}/nhdd}")
python3 "${ROOT_DIR}/scripts/build_nhdd_android.py" "${ARGS[@]}"
