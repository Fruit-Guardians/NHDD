#!/usr/bin/env bash
set -euo pipefail
# Cross-build dependency-free web GUI wrapper for Windows from Linux.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "${ROOT_DIR}/dist"
cd "${ROOT_DIR}/gui_web"
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -ldflags='-s -w -H windowsgui' \
  -o "${ROOT_DIR}/dist/nhdd-gui-web-windows-amd64.exe" .
ls -lh "${ROOT_DIR}/dist/nhdd-gui-web-windows-amd64.exe"
