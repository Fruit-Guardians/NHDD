#!/usr/bin/env bash
set -euo pipefail
# Cross-build native Fyne GUI for Windows from Linux.
# Requirements: Go 1.21+, gcc-mingw-w64, working network/proxy for Go modules.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "${ROOT_DIR}/dist"
cd "${ROOT_DIR}/gui"
go mod tidy
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc \
  go build -trimpath -ldflags='-s -w -H windowsgui' \
  -o "${ROOT_DIR}/dist/nhdd-gui-fyne-windows-amd64.exe" .
ls -lh "${ROOT_DIR}/dist/nhdd-gui-fyne-windows-amd64.exe"
