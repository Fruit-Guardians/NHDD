param(
    [string[]]$Summaries=@(),
    [string]$ExpectedCandidateSha256='',
    [ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedBaselineSha256='3384af4442e8e85e85ecaac918559d6f915e8090314d6fb7948824201d10e485',
    [string]$Output='',
    [switch]$SelfTest
)
$ErrorActionPreference='Stop'
function CheckBlock($summary) {
    $failures=@();$old=@($summary.runs | Where-Object role -eq 'baseline');$new=@($summary.runs | Where-Object role -eq 'candidate')
    if($old.Count -ne 2 -or $new.Count -ne 2){throw 'Each block must contain baseline/candidate/candidate/baseline'}
    if(($summary.runs.role -join ',') -ne 'baseline,candidate,candidate,baseline'){throw 'Unexpected run order'}
    foreach($run in $summary.runs) {
        if($run.timing.exposed_methods -ne 64 -or $run.timing.windows -ne 64){throw 'Not the single-exposure 64-method fixture'}
        $split=0
        foreach($ms in 1,5) {
            $row=@($run.timing.by_duration | Where-Object ms -eq $ms)
            if($row.Count -ne 1 -or $row[0].trials -ne 32 -or $null -eq $row[0].independently_verified_methods){throw 'Missing duration method metrics; reanalyze with current analyzer'}
            $split+=$row[0].independently_verified_methods
        }
        if($split -ne $run.verified_methods){throw 'Duration/total method counts disagree'}
        if($run.verified_methods -gt 1 -and $run.merged_methods -ne $run.verified_methods){$failures+="$($run.name): final merge did not retain all independently verified methods"}
        $diag=$run.diagnostics -join "`n"
        foreach($m in [regex]::Matches($diag,'\b(queue_drops|budget_drops|generation_rejected|unreadable|early_trace_losses|disk_drops|write_failures|verification_drops|output_drops|lost|malformed|remaining|worker_failed|priority_failures|collector_priority_failures|restore_failed)=(\d+)')) {
            if([long]$m.Groups[2].Value -ne 0){$failures+="$($run.name): $($m.Value)"}
        }
        if($diag -notmatch 'remaining=0' -or $diag -notmatch 'worker_failed=0' -or $diag -notmatch 'Event diagnostics: lost=0 malformed=0'){
            $failures+="$($run.name): missing successful drain/trace diagnostics"
        }
        foreach($m in [regex]::Matches($diag,'\bpeak_(items|bytes)=(\d+)')) {
            $limit=if($m.Groups[1].Value -eq 'items'){512}else{32*1024*1024}
            if([long]$m.Groups[2].Value -gt $limit){$failures+="$($run.name): outstanding limit exceeded"}
        }
    }
    $durations=@(foreach($ms in 1,5) {
        $a=@($old | ForEach-Object {$_.timing.by_duration | Where-Object ms -eq $ms})
        $b=@($new | ForEach-Object {$_.timing.by_duration | Where-Object ms -eq $ms})
        $oldMethods=($a | Measure-Object independently_verified_methods -Sum).Sum
        $newMethods=($b | Measure-Object independently_verified_methods -Sum).Sum
        $oldRaw=($a | Measure-Object raw_double_match_windows -Sum).Sum
        $newRaw=($b | Measure-Object raw_double_match_windows -Sum).Sum
        if($newMethods -lt $oldMethods){$failures+="${ms}ms independently verified methods regressed"}
        if($newRaw -lt $oldRaw){$failures+="${ms}ms raw double-match windows regressed"}
        [pscustomobject]@{ms=$ms;baseline_methods=$oldMethods;candidate_methods=$newMethods;baseline_raw=$oldRaw;candidate_raw=$newRaw}
    })
    $oldMinimum=($old | Measure-Object verified_methods -Minimum).Minimum
    $newMinimum=($new | Measure-Object verified_methods -Minimum).Minimum
    if($newMinimum -lt $oldMinimum){$failures+='Minimum recovered method count regressed'}
    foreach($run in $summary.runs){if($null -eq $run.timing.queue_wait_p95_ms){throw 'Missing queue metric'}}
    $oldQueue=($old | ForEach-Object {$_.timing.queue_wait_p95_ms} | Measure-Object -Average).Average
    $newQueue=($new | ForEach-Object {$_.timing.queue_wait_p95_ms} | Measure-Object -Average).Average
    if($newQueue -gt $oldQueue){$failures+='Mean per-run publication-start queue P95 regressed'}
    [pscustomobject]@{run=$summary.run;passed=($failures.Count -eq 0);failures=$failures;durations=$durations;
        baseline_min_methods=$oldMinimum;candidate_min_methods=$newMinimum;baseline_queue_p95_mean_ms=$oldQueue;candidate_queue_p95_mean_ms=$newQueue}
}
if($SelfTest) {
    function Fixture {
        [pscustomobject]@{run='synthetic';runs=@(foreach($role in 'baseline','candidate','candidate','baseline'){
            [pscustomobject]@{role=$role;name=$role;verified_methods=64;merged_methods=64;
                timing=[pscustomobject]@{windows=64;exposed_methods=64;queue_wait_p95_ms=$(if($role -eq 'baseline'){100}else{90});
                    by_duration=@(foreach($ms in 1,5){[pscustomobject]@{ms=$ms;trials=32;independently_verified_methods=32;raw_double_match_windows=32}})};
                diagnostics=@('Fast schedule: peak_items=512 peak_bytes=33554432 remaining=0 worker_failed=0','Event diagnostics: lost=0 malformed=0','priority_failures=0')}
        })}
    }
    $s=Fixture;if(!(CheckBlock $s).passed){throw 'Passing fixture failed'}
    $s=Fixture;$s.runs[1].timing.by_duration[0].independently_verified_methods=31;$s.runs[1].verified_methods=63
    if((CheckBlock $s).passed){throw 'Method regression was accepted'}
    $s=Fixture;$s.runs[1].timing.queue_wait_p95_ms=120
    if((CheckBlock $s).passed){throw 'Queue regression was accepted'}
    $s=Fixture;$s.runs[1].diagnostics+= 'queue_drops=1'
    if((CheckBlock $s).passed){throw 'Queue drop was accepted'}
    $s=Fixture;$s.runs[1].diagnostics+= 'priority_failures=1'
    if((CheckBlock $s).passed){throw 'Priority failure was accepted'}
    $s=Fixture;$s.runs[1].diagnostics+= 'collector_priority_failures=1'
    if((CheckBlock $s).passed){throw 'Collector priority failure was accepted'}
    $s=Fixture;$s.runs[1].diagnostics+= 'restore_failed=1'
    if((CheckBlock $s).passed){throw 'Collector restoration failure was accepted'}
    $s=Fixture;$s.runs[1].merged_methods=63
    if((CheckBlock $s).passed){throw 'Missing final merged method was accepted'}
    $s=Fixture;$s.runs[1].timing.by_duration[0].raw_double_match_windows=31
    if((CheckBlock $s).passed){throw 'Raw capture regression was accepted'}
    'check_capture_performance: OK (pass/method/queue/drop/priority failure gates)';return
}
if($Summaries.Count -lt 3){throw 'Need at least three fresh ABBA blocks; do not select only successful blocks'}
if($ExpectedCandidateSha256 -notmatch '^[0-9a-f]{64}$'){throw 'Pin the final candidate SHA-256'}
if($Output -and (Test-Path -LiteralPath $Output)){throw 'Preserve previous gate output'}
$blocks=@();$runtimeCount=0
$seenPaths=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$seenRuns=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach($path in $Summaries) {
    if(!$seenPaths.Add([IO.Path]::GetFullPath($path))){throw 'Duplicate evidence path is not an independent block'}
    $s=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if(!$s.run -or !$seenRuns.Add($s.run)){throw 'Duplicate or missing run identity'}
    if($s.baseline_sha256 -ne $ExpectedBaselineSha256 -or $s.candidate_sha256 -ne $ExpectedCandidateSha256){throw 'Unpinned or mixed binaries'}
    if($s.before.selinux -ne $s.after.selinux -or $s.before.buffer_percent -ne $s.after.buffer_percent -or $s.before.instances -ne $s.after.instances){throw 'Global environment changed'}
    foreach($r in $s.runtime){if(@($r.result -split "`n" | Where-Object {$_ -match '^ART_VERIFY_PASS '}).Count -ne 64){throw 'Incomplete ART execution record'}}
    $blocks+=CheckBlock $s;$runtimeCount+=@($s.runtime).Count
}
$passed=(@($blocks | Where-Object {-not $_.passed}).Count -eq 0) -and $runtimeCount -gt 0
$report=[ordered]@{passed=$passed;baseline_sha256=$ExpectedBaselineSha256;candidate_sha256=$ExpectedCandidateSha256;blocks=$blocks;complete_art_verified_runs=$runtimeCount;
    scope='Finite own-fixture validation, not a statistical or commercial-shell guarantee; safety regressions/native tests also required'}
$json=$report | ConvertTo-Json -Depth 10
if($Output){$json | Set-Content -LiteralPath $Output -Encoding utf8}
$json
if(!$passed){throw 'Performance gate failed; do not commit/push as a verified improvement'}
