#!/usr/bin/env bash
set -euo pipefail

# Build Android-side NHDD binary for arm64 devices.
# Usage:
#   NDK=/path/to/android-ndk-r27 ./scripts/build_nhdd_android.sh
# Optional:
#   API=34 OUT=nhdd ./scripts/build_nhdd_android.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NDK="${NDK:-/lina_android/android-ndk-r27}"
API="${API:-34}"
OUT="${OUT:-${ROOT_DIR}/nhdd}"
HOST_TAG="linux-x86_64"
CC="${NDK}/toolchains/llvm/prebuilt/${HOST_TAG}/bin/aarch64-linux-android${API}-clang"

if [[ ! -x "${CC}" ]]; then
  echo "ERROR: clang not found: ${CC}" >&2
  echo "Set NDK=/path/to/android-ndk-r27" >&2
  exit 1
fi

"${CC}" -O2 -static -Wall -Wextra -o "${OUT}" "${ROOT_DIR}/nhdd.c"
ls -lh "${OUT}"
file "${OUT}" || true
