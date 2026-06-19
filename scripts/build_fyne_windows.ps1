# Build native Fyne GUI on Windows.
# Requirements: Go 1.21+, MSYS2 MinGW-w64 gcc in PATH, internet/proxy for Go modules.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location "$Root\gui"
go mod tidy
$env:CGO_ENABLED = "1"
go build -trimpath -ldflags="-s -w -H windowsgui" -o "$Root\dist\nhdd-gui-fyne-windows-amd64.exe" .
Write-Host "Built: $Root\dist\nhdd-gui-fyne-windows-amd64.exe"
