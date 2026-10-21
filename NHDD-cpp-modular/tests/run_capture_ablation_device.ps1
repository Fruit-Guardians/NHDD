param(
    [Parameter(Mandatory=$true)][string]$Serial,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-z0-9_]{1,24}$')][string]$RunId,
    [string]$BinaryPrefix='.test-bin/nhdd-ablate-',
    [string]$Destination=''
)
$ErrorActionPreference='Stop'
if(!$Destination){$Destination=".test-bin/device-smoke/capture-ablation-$RunId"}
if(Test-Path -LiteralPath $Destination){throw 'Preserve previous evidence: destination exists'}
$baseline="${BinaryPrefix}all"
foreach($role in @('all','no_yield','no_nice','no_pool')) {
    if(!(Test-Path -LiteralPath "${BinaryPrefix}$role" -PathType Leaf)){throw "Missing variant: $role"}
}
$baselineHash=(Get-FileHash -LiteralPath $baseline -Algorithm SHA256).Hash.ToLowerInvariant()
New-Item -ItemType Directory $Destination | Out-Null
$results=@()
# Each comparison switches exactly one scheduling/storage factor. The paired
# old/new/new/old runs retain raw/provenance evidence and do not skip any checks.
foreach($factor in @('no_yield','no_nice','no_pool')) {
    $path=Join-Path $Destination $factor
    & "$PSScriptRoot/run_capture_contention_device.ps1" -Serial $Serial -RunId "${RunId}_$factor" `
        -Destination $path -Baseline $baseline -ExpectedBaselineSha256 $baselineHash `
        -Candidate "${BinaryPrefix}$factor" -SkipRegressions
    $summary=Get-Content (Join-Path $path 'summary.json') -Raw | ConvertFrom-Json
    foreach($run in $summary.runs) {
        $policy='background_yield=1 nice_delta=3 pool_slots=32'
        if($run.role -eq 'candidate') {
            $policy=switch($factor){
                'no_yield' {'background_yield=0 nice_delta=3 pool_slots=32'}
                'no_nice' {'background_yield=1 nice_delta=0 pool_slots=32'}
                'no_pool' {'background_yield=1 nice_delta=3 pool_slots=0'}
            }
        }
        if(!@($run.diagnostics | Where-Object {$_ -like "*Fast policy: $policy*"}).Count){throw "Wrong factor policy in $($run.name)"}
        $results+=[pscustomobject]@{factor=$factor;role=$run.role;name=$run.name;policy=$policy;
            methods=$run.verified_methods;merged=$run.merged_methods;timing=$run.timing;diagnostics=$run.diagnostics}
    }
}
[ordered]@{baseline_sha256=$baselineHash;runs=$results} | ConvertTo-Json -Depth 12 | Set-Content (Join-Path $Destination 'ablation.json') -Encoding utf8
$results | Select-Object factor,role,methods,merged | Format-Table
Write-Output "Ablation evidence: $Destination/ablation.json; no common executable replaced"
