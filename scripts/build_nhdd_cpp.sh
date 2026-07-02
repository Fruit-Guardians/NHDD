#!/usr/bin/env bash
set -euo pipefail

# Build Android-side NHDD C++ binary for arm64 devices.
# Usage:
#   ./scripts/build_nhdd_cpp.sh
# Optional:
#   API=34 OUT=nhdd ./scripts/build_nhdd_cpp.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NDK="${NDK:-/mnt/c/Users/19678/AppData/Local/Android/Sdk/ndk/27.2.12479018}"
API="${API:-34}"
OUT="${OUT:-${ROOT_DIR}/nhdd}"
HOST_TAG="windows-x86_64"
CXX="${NDK}/toolchains/llvm/prebuilt/${HOST_TAG}/bin/aarch64-linux-android${API}-clang++"

if [[ ! -x "${CXX}" ]]; then
  echo "ERROR: clang++ not found: ${CXX}" >&2
  echo "Set NDK=/path/to/android-ndk" >&2
  exit 1
fi

echo "[*] Building NHDD C++ version..."
echo "[*] Compiler: ${CXX}"
echo "[*] Source: ${ROOT_DIR}/NHDD-cpp-modular/src/main.cpp"
echo "[*] Output: ${OUT}"

cd "${ROOT_DIR}/NHDD-cpp-modular/src"
"${CXX}" -O2 -std=c++17 -Wall -Wextra -static-libstdc++ -o "${OUT}" main.cpp

ls -lh "${OUT}"
file "${OUT}" || true
echo "[+] Build complete!"
