# Build dependency-free web GUI wrapper on Windows.
# Requirements: Go 1.21+. No Fyne, no GCC, no cgo.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
New-Item -ItemType Directory -Force "$Root\dist" | Out-Null
Set-Location "$Root\gui_web"
$env:GOOS = "windows"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
go build -trimpath -ldflags="-s -w -H windowsgui" -o "$Root\dist\nhdd-gui-web-windows-amd64.exe" .
Write-Host "Built: $Root\dist\nhdd-gui-web-windows-amd64.exe"
