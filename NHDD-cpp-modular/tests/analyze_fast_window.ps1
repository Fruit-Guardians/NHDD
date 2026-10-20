param([Parameter(Mandatory=$true)][string]$Directory)
$ErrorActionPreference='Stop'
$probe = Get-ChildItem $Directory -Filter '*.probe.log' | Select-Object -First 1
if (!$probe) { throw 'Missing probe log' }
$prefix=$probe.Name -replace '\.probe\.log$',''
$windows=@(Get-Content $probe.FullName | ForEach-Object {
    if ($_ -match 'WINDOW trial=(\d+) us=(\d+) address=(0x[0-9a-f]+) begin=([\d.]+) end=([\d.]+)') {
        [pscustomobject]@{ trial=[int]$Matches[1]; us=[int]$Matches[2]; address=$Matches[3];
            begin=[double]$Matches[4]; end=[double]$Matches[5] }
    }
})
if ($windows.Count -ne 40) { throw "Expected 40 windows, found $($windows.Count)" }
$golden=@{}
foreach ($w in $windows) {
    $golden[$w.trial]=(Get-FileHash (Join-Path $Directory "${prefix}_$($w.trial).dex") -Algorithm SHA256).Hash
}
$rawHashes=@{}
foreach ($raw in Get-ChildItem (Join-Path $Directory "${prefix}_out/dex") -Filter '*.raw.dex') {
    if ($raw.Name -match '_([a-f0-9]{16})\.raw\.dex$') {
        $rawHashes[$Matches[1]]=(Get-FileHash $raw.FullName -Algorithm SHA256).Hash
    }
}
$mainHits=@{}; $fastHits=@{}; $stableHits=@{}; $lags=@(); $changedObservations=0
foreach ($meta in Get-ChildItem (Join-Path $Directory "${prefix}_out/dex") -Filter '*.meta.json') {
    $m=Get-Content $meta.FullName -Raw | ConvertFrom-Json
    foreach ($w in $windows) {
        if ($m.address -eq $w.address -and $m.coverage.read_bytes -eq $m.declared_size -and
            $rawHashes[$m.content_hash] -eq $golden[$w.trial]) { $mainHits[$w.trial]=$true }
    }
}
$fastDir=Join-Path $Directory "${prefix}_out/fast"
if (Test-Path $fastDir) {
    foreach ($meta in Get-ChildItem $fastDir -Filter '*.json') {
        $m=Get-Content $meta.FullName -Raw | ConvertFrom-Json
        if ($m.consistency -eq 'changed_between_reads') { ++$changedObservations }
        foreach ($d in $m.dex_observations) {
            $address=[Convert]::ToUInt64(($m.address -replace '^0x',''),16)+[uint64]$d.offset
            $sha=(Get-FileHash (Join-Path $fastDir $d.raw) -Algorithm SHA256).Hash
            foreach ($w in $windows) {
                if ($address -eq [Convert]::ToUInt64(($w.address -replace '^0x',''),16) -and
                    $sha -eq $golden[$w.trial] -and $d.semantic_raw.status -eq 'structural_checks_passed') {
                    $fastHits[$w.trial]=$true
                    if ($d.consistency -eq 'two_reads_match') { $stableHits[$w.trial]=$true }
                    $lags += [double]$m.event_to_read_ms
                }
            }
        }
    }
}
$rows=@(foreach ($us in 1000,5000,20000,50000) {
    $group=@($windows | Where-Object us -eq $us)
    [pscustomobject]@{window_ms=$us/1000;trials=$group.Count;
        main_hits=@($group | Where-Object {$mainHits.ContainsKey($_.trial)}).Count;
        fast_hits=@($group | Where-Object {$fastHits.ContainsKey($_.trial)}).Count;
        matching_double_read_hits=@($group | Where-Object {$stableHits.ContainsKey($_.trial)}).Count;
        combined_hits=@($group | Where-Object {$fastHits.ContainsKey($_.trial) -or $mainHits.ContainsKey($_.trial)}).Count}
})
$sorted=@($lags | Sort-Object)
[pscustomobject]@{name=$prefix;windows=$rows;fast_changed_observations=$changedObservations;
    positive_observation_lag_ms_p50=$(if($sorted.Count){$sorted[[int][Math]::Floor(($sorted.Count-1)*0.5)]}else{$null});
    positive_observation_lag_ms_p95=$(if($sorted.Count){$sorted[[int][Math]::Floor(($sorted.Count-1)*0.95)]}else{$null})
} | ConvertTo-Json -Depth 5
