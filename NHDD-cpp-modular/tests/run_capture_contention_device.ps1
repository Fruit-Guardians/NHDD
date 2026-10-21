param(
    [Parameter(Mandatory=$true)][string]$Serial,
    [string]$Destination='',
    [string]$RunId='',
    [string]$Candidate='.test-bin/nhdd-contention-fixed-arm64',
    [string]$Baseline='.test-bin/nhdd-art-schedule-arm64',
    [ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedBaselineSha256='3384af4442e8e85e85ecaac918559d6f915e8090314d6fb7948824201d10e485',
    [string]$Helper='.test-bin/libnhdd-contention-probe.so',
    [string]$Probe='.test-bin/contention/probe/classes.dex',
    [string]$Payload='.test-bin/art-refill/payload-dex/classes.dex',
    [string]$Verifier='.test-bin/contention/verify/classes.dex',
    [switch]$SkipRegressions
)
$ErrorActionPreference='Stop'
if(!$RunId){$RunId=(Get-Date -Format 'yyyyMMddHHmmss')+'_'+[guid]::NewGuid().ToString('N').Substring(0,6)}
if($RunId -notmatch '^[a-z0-9_]{1,40}$'){throw 'RunId must be unique lowercase alphanumeric/underscore'}
if(!$Destination){$Destination=".test-bin/device-smoke/capture-contention-$RunId"}
if(Test-Path $Destination){throw 'Destination exists; preserve previous evidence'}
# adb on Windows still encounters MAX_PATH in recursively pulled artifacts.
# Refuse BEFORE launching any process, rather than leave an incomplete ABBA.
$longestName="nhdd_refill_cont_${RunId}_conflict"
if($env:OS -eq 'Windows_NT' -and ([IO.Path]::GetFullPath($Destination).Length+13+$longestName.Length+4+5+128) -ge 260){
    throw 'Evidence path may exceed Windows adb MAX_PATH; use a short -RunId and -Destination (for example .test-bin/w01)'
}
foreach($file in @($Candidate,$Baseline,$Helper,$Probe,$Payload,$Verifier)){if(!(Test-Path -LiteralPath $file -PathType Leaf)){throw "Missing artifact: $file"}}
$baselineHash=(Get-FileHash -LiteralPath $Baseline -Algorithm SHA256).Hash.ToLowerInvariant()
if($baselineHash -ne $ExpectedBaselineSha256){throw 'Baseline does not match the explicitly pinned expected SHA-256'}
if((Get-FileHash -LiteralPath $Payload -Algorithm SHA256).Hash.ToLowerInvariant() -ne '66578c116d16c70627e2ea861ed8808018d0319b5f7a01cd1f33ec7507795596'){throw 'Unrecognized own payload'}
$adbArgs=@();if($Serial){$adbArgs=@('-s',$Serial)}
function Remote([string]$command) {
    $result=& adb @adbArgs shell "su -c '$command'"
    if($LASTEXITCODE -ne 0){throw "Remote command failed: $command"}
    return ($result -join "`n")
}
if((Remote 'id -u').Trim() -ne '0'){throw 'Root device required'}
$before=[ordered]@{fingerprint=(Remote 'getprop ro.build.fingerprint');sdk=(Remote 'getprop ro.build.version.sdk');
    selinux=(Remote 'getenforce');buffer_percent=(Remote 'cat /sys/kernel/tracing/buffer_percent');instances=(Remote 'ls /sys/kernel/tracing/instances')}
New-Item -ItemType Directory $Destination | Out-Null
$remote=@{baseline="/data/local/tmp/nhdd_cont_${RunId}_old";candidate="/data/local/tmp/nhdd_cont_${RunId}_new";
    helper="/data/local/tmp/libnhdd_cont_${RunId}.so";probe="/data/local/tmp/nhdd_cont_${RunId}_probe.dex";
    payload="/data/local/tmp/nhdd_cont_${RunId}_payload.dex";verifier="/data/local/tmp/nhdd_cont_${RunId}_verify.dex"}
foreach($role in @('baseline','candidate','helper','probe','payload','verifier')) {
    $local=@{baseline=$Baseline;candidate=$Candidate;helper=$Helper;probe=$Probe;payload=$Payload;verifier=$Verifier}[$role]
    if(Remote "ls $($remote[$role]) 2>/dev/null || true"){throw 'Remote run prefix exists; refuse overwrite'}
    & adb @adbArgs push $local $remote[$role]
    if($LASTEXITCODE -ne 0){throw "Push failed: $role"}
}
Remote "chmod 755 $($remote.baseline) $($remote.candidate)" | Out-Null
$runs=@();$runtime=@()
# Alternating order reduces a systematic first-run warmup bias. Same helper,
# payload and short-burst windows for both executables; no target modification.
foreach($role in @('baseline','candidate','candidate','baseline')) {
    $i=$runs.Count+1;$name="nhdd_refill_cont_${RunId}_${i}";$dir=Join-Path $Destination "${i}_$role"
    & "$PSScriptRoot/run_art_refill_device.ps1" -Name $name -Mode short-burst -Destination $dir -Serial $Serial `
        -Binary $remote[$role] -Helper $remote.helper -Probe $remote.probe -Payload $remote.payload
    $provenance=& "$PSScriptRoot/analyze_art_merge.ps1" -Directory $dir -Expected short-burst | ConvertFrom-Json
    $timing=& "$PSScriptRoot/analyze_fast_schedule.ps1" -Directory $dir | ConvertFrom-Json
    $log=Get-Content (Join-Path $dir "$name.scan.log") -Raw
    $runs+=[pscustomobject]@{role=$role;name=$name;verified_methods=$timing.independently_verified_methods;
        merged_methods=$provenance.max_merged_methods;full_body_composites=$provenance.full_three_method_revisions;timing=$timing;
        diagnostics=@($log -split "`n" | Where-Object {$_ -match 'Fast capture:|ART refill:|ART coalesce:|Fast merge flush:|Fast schedule:|Fast contention:|Fast policy:|Trace collector:|Event diagnostics:'})}
    if($role -eq 'candidate' -and $provenance.full_three_method_revisions -gt 0) {
        $fast=Join-Path $dir "${name}_out/fast"
        $complete=Get-ChildItem $fast -Filter '*.merge.json' | Where-Object {
            (Get-Content $_.FullName -Raw | ConvertFrom-Json).method_count -eq 64
        } | Select-Object -First 1
        if(!$complete){throw 'Full body reported without a 64-method manifest'}
        $manifest=Get-Content $complete.FullName -Raw | ConvertFrom-Json
        $fixed=Join-Path $fast $manifest.artifacts.fixed
        $markers=@(Get-Content (Join-Path $dir "$name.probe.log") | ForEach-Object {if($_ -match '^METHOD .* name=(marker\d+)'){$Matches[1]}}) -join ' '
        $verifyFile="/data/local/tmp/nhdd_cont_${RunId}_${i}_complete.dex"
        & adb @adbArgs push $fixed $verifyFile
        if($LASTEXITCODE -ne 0){throw 'Could not push own complete verification artifact'}
        Remote "chmod 444 $verifyFile" | Out-Null
        $result=Remote "CLASSPATH=$($remote.verifier) app_process /system/bin ArtRefillVerify $verifyFile /data/local/tmp/nhdd_cont_${RunId}_${i}_cache $markers"
        if(@($result -split "`n" | Where-Object {$_ -match '^ART_VERIFY_PASS '}).Count -ne 64){throw 'Not all 64 methods executed successfully'}
        $runtime+=[pscustomobject]@{run=$name;sha256=(Get-FileHash $fixed -Algorithm SHA256).Hash;result=$result}
    }
}
$regressions=@()
if(!$SkipRegressions) {
    foreach($case in @(@('conflict','conflict'),@('multi-outside','outside'),@('multi-remap','remap'))) {
        $name="nhdd_refill_cont_${RunId}_$($case[1])";$dir=Join-Path $Destination $case[1]
        & "$PSScriptRoot/run_art_refill_device.ps1" -Name $name -Mode $case[0] -Destination $dir -Serial $Serial `
            -Binary $remote.candidate -Helper $remote.helper -Probe $remote.probe -Payload $remote.payload
        $regressions+= & "$PSScriptRoot/analyze_art_merge.ps1" -Directory $dir -Expected $case[1] | ConvertFrom-Json
    }
}
$after=[ordered]@{selinux=(Remote 'getenforce');buffer_percent=(Remote 'cat /sys/kernel/tracing/buffer_percent');
    instances=(Remote 'ls /sys/kernel/tracing/instances');payload_hash=(Remote "sha256sum $($remote.payload)")}
$summary=[ordered]@{run=$RunId;baseline_sha256=$baselineHash;candidate_sha256=(Get-FileHash -LiteralPath $Candidate -Algorithm SHA256).Hash.ToLowerInvariant();
    helper_sha256=(Get-FileHash -LiteralPath $Helper -Algorithm SHA256).Hash.ToLowerInvariant();before=$before;after=$after;runs=$runs;regressions=$regressions;runtime=$runtime}
$summary | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $Destination 'summary.json') -Encoding utf8
if($after.buffer_percent -ne $before.buffer_percent -or $after.selinux -ne $before.selinux){throw 'Global tracing/SELinux state changed; inspect without overwriting it'}
if($after.payload_hash -notmatch '^66578c116d16c70627e2ea861ed8808018d0319b5f7a01cd1f33ec7507795596 '){throw 'Own on-disk payload changed'}
$runs | Select-Object role,name,verified_methods | Format-Table
Write-Output "Evidence: $Destination/summary.json (no common binary replaced; no data deleted)"
