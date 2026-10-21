param([Parameter(Mandatory=$true)][string]$Directory)
$ErrorActionPreference='Stop'
$probe=Get-ChildItem $Directory -Filter '*.probe.log' | Select-Object -First 1
$prefix=$probe.Name -replace '\.probe\.log$',''
$lines=Get-Content $probe.FullName
$ready=$lines | Where-Object {$_ -match '^READY '} | Select-Object -First 1
if($ready -notmatch 'pid=(\d+) payload_address=(0x[0-9a-f]+) size=(\d+)'){throw 'No fixture identity'}
$probePid=[int]$Matches[1];$address=[Convert]::ToUInt64(($Matches[2] -replace '^0x',''),16)
$methods=@($lines | ForEach-Object {
    if($_ -match '^METHOD index=(\d+) offset=(\d+) bytes=(\d+) name=(marker\d+)') {
        [pscustomobject]@{offset=[int]$Matches[2];length=[int]$Matches[3];name=$Matches[4]}
    }
})
$windows=@($lines | ForEach-Object {
    if($_ -match '^WINDOW trial=(\d+) us=(\d+) begin=([\d.]+) end=([\d.]+) method=(\d+) offset=(\d+) alternate=(\d+)') {
        [pscustomobject]@{trial=[int]$Matches[1];us=[int]$Matches[2];begin=[double]$Matches[3];end=[double]$Matches[4];
            method=[int]$Matches[5];offset=[int]$Matches[6];alternate=[int]$Matches[7]}
    }
})
$golden=[IO.File]::ReadAllBytes((Join-Path $Directory "$prefix.golden.dex"))
$fast=Join-Path $Directory "${prefix}_out/fast"
$sha=[Security.Cryptography.SHA256]::Create()
function Digest([byte[]]$bytes,[int]$off,[int]$n){[BitConverter]::ToString($sha.ComputeHash($bytes,$off,$n))}
function Percentile($values,[double]$p) {
    $sorted=@($values | Sort-Object);if(!$sorted.Count){return $null}
    return [Math]::Round($sorted[[Math]::Max(0,[int][Math]::Ceiling($sorted.Count*$p)-1)],3)
}
function Covered($m,[int]$off,[int]$length) {
    foreach($page in $m.pages){
        $a=[Math]::Max($off,$page.offset);$b=[Math]::Min($off+$length,$page.offset+$page.length)
        if($a -lt $b -and ($b -gt $page.offset+$page.first_read -or $b -gt $page.offset+$page.second_read)){return $false}
    }
    return $true
}
$rawHits=@{};$verifiedHits=@{};$verifiedMethods=@{};$waits=@{};$attempts=@{};$eventDelay=@();$queueWait=@();$refills=0
foreach($file in Get-ChildItem $fast -Filter '*.json') {
    $m=Get-Content $file.FullName -Raw | ConvertFrom-Json
    if($m.pid -ne $probePid){continue}
    if($m.source -eq 'early_tracefs_local_capture') {
        $base=[Convert]::ToUInt64(($m.address -replace '^0x',''),16)
        if($base -lt $address -or $base -ge $address+$golden.Length){continue}
        $first=[IO.File]::ReadAllBytes((Join-Path $fast $m.artifacts.first))
        $second=[IO.File]::ReadAllBytes((Join-Path $fast $m.artifacts.second))
        $eventDelay+= $m.event_to_read_ms
        if($null -ne $m.queue_wait_ms){$queueWait+= $m.queue_wait_ms}
        foreach($method in $methods) {
            $off=[long]$address+$method.offset-[long]$base
            if($off -lt 0 -or $off+$method.length -gt $first.Length -or $off+$method.length -gt $second.Length -or
                !(Covered $m $off $method.length)){continue}
            foreach($w in $windows | Where-Object {$_.offset -eq $method.offset -and
                $m.read_end_boot_seconds -ge $_.begin -and $m.read_begin_boot_seconds -le $_.end}) {
                $bytes=[byte[]]::new($method.length);[Array]::Copy($golden,$method.offset,$bytes,0,$method.length)
                if($w.alternate){$bytes[$method.length-3]=$bytes[$method.length-3] -bxor 1}
                $digest=Digest $bytes 0 $bytes.Length
                if((Digest $first $off $method.length) -eq $digest -and (Digest $second $off $method.length) -eq $digest){$rawHits[$w.trial]=$true}
            }
        }
    } elseif($m.status -eq 'reconstructed_method_composite') {
        if([Convert]::ToUInt64(($m.dex_address -replace '^0x',''),16) -ne $address){continue}
        ++$refills;$attempt=1;if($null -ne $m.verification_attempt){$attempt=[int]$m.verification_attempt}
        if(!$attempts.ContainsKey("$attempt")){$attempts["$attempt"]=0};++$attempts["$attempt"]
        foreach($patch in $m.patches){$verifiedMethods[[long]$patch.offset]=$true;foreach($w in $windows | Where-Object {$_.offset -eq $patch.offset -and
            $m.capture_end_boot -ge $_.begin -and $m.capture_begin_boot -le $_.end}) {
            $verifiedHits[$w.trial]=$true;$delay=1000*($m.verification_begin_boot-$m.capture_end_boot)
            if(!$waits.ContainsKey($w.trial) -or $delay -lt $waits[$w.trial]){$waits[$w.trial]=$delay}
        }}
    }
}
$rows=@(foreach($us in 1000,5000,20000,50000){
    $group=@($windows | Where-Object {$_.us -eq $us -and !$_.alternate})
    [pscustomobject]@{ms=$us/1000;trials=$group.Count;raw_double_match_windows=@($group | Where-Object {$rawHits.ContainsKey($_.trial)}).Count;
        independently_verified_windows=@($group | Where-Object {$verifiedHits.ContainsKey($_.trial)}).Count;
        independently_verified_methods=@($group | Select-Object -ExpandProperty offset -Unique | Where-Object {$verifiedMethods.ContainsKey([long]$_)}).Count}
})
[pscustomobject]@{name=$prefix;windows=$windows.Count;raw_double_match_windows=$rawHits.Count;verified_windows=$verifiedHits.Count;
    exposed_methods=$methods.Count;independently_verified_methods=$verifiedMethods.Count;refills=$refills;successful_attempts=$attempts;per_window_verification_wait_p50_ms=(Percentile $waits.Values .50);
    per_window_verification_wait_p95_ms=(Percentile $waits.Values .95);queue_wait_p50_ms=(Percentile $queueWait .50);
    queue_wait_p95_ms=(Percentile $queueWait .95);event_to_read_p95_ms=(Percentile $eventDelay .95);by_duration=$rows} | ConvertTo-Json -Depth 6
