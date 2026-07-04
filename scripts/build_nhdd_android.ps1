param(
    [string]$Ndk = "",
    [int]$Api = 34,
    [string]$Out = ""
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Builder = Join-Path $RootDir "scripts\build_nhdd_android.py"

if (-not $Ndk) {
    if ($env:NDK) {
        $Ndk = $env:NDK
    } elseif ($env:NDK_PATH) {
        $Ndk = $env:NDK_PATH
    }
}
if ($env:API -and $Api -eq 34) {
    $Api = [int]$env:API
}
if (-not $Out -and $env:OUT) {
    $Out = $env:OUT
}

$BuildArgs = @("--api", "$Api")
if ($Ndk) {
    $BuildArgs += @("--ndk", $Ndk)
}
if ($Out) {
    $BuildArgs += @("--out", $Out)
}

python $Builder @BuildArgs
