param(
    [Parameter(Mandatory=$true)][string]$Name,
    [ValidateSet('normal','outside','remap','multi','conflict','multi-outside','multi-remap','burst','short-burst')][string]$Mode='normal',
    [ValidateSet('auto','off')][string]$ArtRefill='auto',
    [ValidateSet('auto','off')][string]$ArtMerge='auto',
    [ValidateSet('tracefs','poll')][string]$Events='tracefs',
    [Parameter(Mandatory=$true)][string]$Destination,
    [string]$Serial='',
    [string]$Binary='/data/local/tmp/nhdd_art_refill',
    [string]$Helper='/data/local/tmp/libnhdd_art_refill_probe.so',
    [string]$Probe='/data/local/tmp/nhdd_art_refill_probe.dex',
    [string]$Payload='/data/local/tmp/nhdd_art_refill_payload.dex'
)
$ErrorActionPreference='Stop'
if($Name -notmatch '^nhdd_refill_[a-z0-9_]+$') {throw 'Use a new unique nhdd_refill_* prefix'}
if($Binary -notmatch '^/data/local/tmp/[A-Za-z0-9_.-]+$'){throw 'Binary must be an explicit /data/local/tmp executable'}
if($Helper -notmatch '^/data/local/tmp/[A-Za-z0-9_.-]+$'){throw 'Helper must be an explicit /data/local/tmp library'}
foreach($path in @($Probe,$Payload)){if($path -notmatch '^/data/local/tmp/[A-Za-z0-9_.-]+$'){throw 'Fixture must be an explicit /data/local/tmp file'}}
$adbArgs=@();if($Serial){$adbArgs=@('-s',$Serial)}
function Remote([string]$command) {
    $result=& adb @adbArgs shell "su -c '$command'"
    if($LASTEXITCODE -ne 0){throw "adb failed: $command"}
    return ($result -join "`n")
}
$prefix="/data/local/tmp/$Name"
if(Remote "ls $prefix.probe.log 2>/dev/null || true"){throw 'Prefix already exists; preserving previous evidence'}
New-Item -ItemType Directory -Force $Destination | Out-Null
Remote "CLASSPATH=$Probe app_process /system/bin ArtRefillProbe $Payload $Helper $prefix $Mode > $prefix.probe.log 2>&1 < /dev/null &" | Out-Null
for($attempt=0;$attempt -lt 100;++$attempt) {
    $ready=Remote "cat $prefix.probe.log"
    if($ready -match 'READY pid=(\d+) payload_address=(0x[0-9a-f]+)'){break}
    Start-Sleep -Milliseconds 50
}
if($ready -notmatch 'READY pid=(\d+) payload_address=(0x[0-9a-f]+)'){throw "Fixture not ready: $ready"}
$probePid=$Matches[1];$address=$Matches[2]
$duration=8;if($Mode -like 'multi*' -or $Mode -in @('conflict','burst','short-burst')){$duration=12}
Remote "$Binary $probePid ${prefix}_out --dex --art-dex only --events $Events --art-refill $ArtRefill --art-merge $ArtMerge --monitor-duration $duration > $prefix.scan.log 2>&1 < /dev/null &" | Out-Null
$armed=$false
for($attempt=0;$attempt -lt 160;++$attempt) {
    $log=Remote "cat $prefix.scan.log"
    if($ArtRefill -eq 'auto' -and $Events -eq 'tracefs') {
        $armed=$log -match ('\[ART-REFILL\] armed pid='+$probePid+' address='+[regex]::Escape($address)+' ')
    } else {
        $armed=($log -match ('\[ART\] DEX object=0x[0-9a-f]+ begin='+[regex]::Escape($address)+' ')) -and
            ($log -match '\[ART\] status=profile_verified')
    }
    if($armed){break}
    Start-Sleep -Milliseconds 50
}
if(!$armed){throw "ART payload candidate not armed: $log"}
Remote "touch $prefix.go" | Out-Null
Write-Output "Triggered $Name pid=$probePid address=$address mode=$Mode ART-refill=$ArtRefill"
for($attempt=0;$attempt -lt 200;++$attempt) {
    $log=Remote "cat $prefix.scan.log"
    if($log -match '\[\*\] Done\.'){break}
    Start-Sleep -Milliseconds 100
}
if($log -notmatch '\[\*\] Done\.'){throw 'Scanner did not finish; preserve logs and inspect'}
Remote "chmod -R a+rX ${prefix}_out" | Out-Null
foreach($file in @("$prefix.probe.log","$prefix.scan.log","$prefix.golden.dex","$prefix.baseline.dex","${prefix}_out")) {
    & adb @adbArgs pull $file $Destination
    if($LASTEXITCODE -ne 0){throw "Could not pull $file"}
}
Write-Output ($log -split "`n" | Where-Object {$_ -match 'ART refill:|ART merge:|ART schedule:|ART coalesce:|Fast merge flush:|Fast schedule:|Fast contention:|Fast policy:|Fast capture:|Trace collector:|Event diagnostics:'})
# Payload methods are never executed. Probe exits itself, no unrelated process is killed.
