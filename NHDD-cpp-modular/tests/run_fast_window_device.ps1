param(
    [Parameter(Mandatory=$true)][string]$Name,
    [ValidateSet('auto','off')][string]$FastCapture = 'auto',
    [ValidateRange(0,500)][int]$RegionDelay = 0,
    [ValidateRange(4,8192)][int]$FastMaxKB = 1024,
    [switch]$Wide,
    [Parameter(Mandatory=$true)][string]$Destination,
    [string]$Serial = ''
)
$ErrorActionPreference = 'Stop'
if ($Name -notmatch '^nhdd_fast_[a-z0-9_]+$') { throw 'Name must be a unique nhdd_fast_* test prefix' }
$adbArgs = @(); if ($Serial) { $adbArgs += @('-s',$Serial) }
function Remote([string]$command) {
    $result = & adb @adbArgs shell "su -c '$command'"
    if ($LASTEXITCODE -ne 0) { throw "adb failed: $command" }
    return ($result -join "`n")
}
$prefix = "/data/local/tmp/$Name"
$exists = Remote "ls $prefix.probe.log 2>/dev/null || true"
if ($exists) { throw 'Test prefix already exists; choose a new name (never overwrite prior evidence)' }
New-Item -ItemType Directory -Force -Path $Destination | Out-Null
$wideArgument=''; if($Wide) { $wideArgument='wide' }
Remote "/data/local/tmp/nhdd_fast_probe $prefix $wideArgument > $prefix.probe.log 2>&1 < /dev/null &" | Out-Null
$ready = ''
for ($attempt=0; $attempt -lt 50; ++$attempt) {
    $ready = Remote "cat $prefix.probe.log"
    if ($ready -match 'READY pid=(\d+)') { break }
    Start-Sleep -Milliseconds 100
}
if ($ready -notmatch 'READY pid=(\d+)') { throw 'Probe did not become ready' }
$probePid = $Matches[1]
Remote "/data/local/tmp/nhdd_fast $probePid ${prefix}_out --dex --art-dex off --events tracefs --fast-capture $FastCapture --fast-max-kb $FastMaxKB --region-delay $RegionDelay --monitor-duration 4 > $prefix.scan.log 2>&1 < /dev/null &" | Out-Null
for ($attempt=0; $attempt -lt 50; ++$attempt) {
    $log = Remote "cat $prefix.scan.log"
    if ($log -match 'Running initial full scan') { break }
    Start-Sleep -Milliseconds 100
}
if ($log -notmatch 'Running initial full scan') { throw 'Scanner failed to arm and start baseline' }
Remote "touch $prefix.go" | Out-Null
Write-Output "Triggered $Name pid=$probePid fast=$FastCapture region_delay=$RegionDelay"
for ($attempt=0; $attempt -lt 120; ++$attempt) {
    $log = Remote "cat $prefix.scan.log"
    if ($log -match '\[\*\] Done\.') { break }
    Start-Sleep -Milliseconds 250
}
if ($log -notmatch '\[\*\] Done\.') { throw 'Scanner did not finish; preserve device logs and inspect' }
Remote "chmod -R a+rX ${prefix}_out" | Out-Null # Only this fixture's generated evidence.
& adb @adbArgs pull "$prefix.probe.log" $Destination
if ($LASTEXITCODE -ne 0) { throw 'Could not pull probe log' }
& adb @adbArgs pull "$prefix.scan.log" $Destination
if ($LASTEXITCODE -ne 0) { throw 'Could not pull scanner log' }
& adb @adbArgs pull "${prefix}_out" $Destination
if ($LASTEXITCODE -ne 0) { throw 'Could not pull captures' }
for ($trial=0; $trial -lt 40; ++$trial) {
    & adb @adbArgs pull "${prefix}_${trial}.dex" $Destination 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Missing golden trial $trial" }
}
Write-Output ($log -split "`n" | Select-Object -Last 7)
# Probe exits on its own; never kill app_process or unrelated app processes.
