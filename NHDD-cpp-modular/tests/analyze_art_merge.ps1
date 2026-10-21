param(
    [Parameter(Mandatory=$true)][string]$Directory,
    [ValidateSet('multi','conflict','outside','remap','off','burst','short-burst')][string]$Expected='multi'
)
$ErrorActionPreference='Stop'
$probe=Get-ChildItem $Directory -Filter '*.probe.log' | Select-Object -First 1
if(!$probe){throw 'Missing probe log'}
$prefix=$probe.Name -replace '\.probe\.log$',''
$lines=Get-Content $probe.FullName
$ready=$lines | Where-Object {$_ -match '^READY '} | Select-Object -First 1
if($ready -notmatch 'pid=(\d+) payload_address=(0x[0-9a-f]+) size=(\d+)'){throw 'Missing identity'}
$probePid=[int]$Matches[1];$address=$Matches[2];$size=[int]$Matches[3]
$selected=@($lines | ForEach-Object {
    if($_ -match '^METHOD index=(\d+) offset=(\d+) bytes=(\d+) name=(marker\d+)') {
        [pscustomobject]@{index=[int]$Matches[1];offset=[int]$Matches[2];length=[int]$Matches[3];name=$Matches[4]}
    }
})
if($selected.Count -ne $(if($Expected -eq 'short-burst'){64}elseif($Expected -eq 'burst'){32}else{3})){throw 'Unexpected selected method count'}
$windows=@($lines | ForEach-Object {
    if($_ -match '^WINDOW trial=(\d+) us=(\d+) begin=([\d.]+) end=([\d.]+) method=(\d+) offset=(\d+) alternate=(\d+)') {
        [pscustomobject]@{trial=[int]$Matches[1];us=[int]$Matches[2];begin=[double]$Matches[3];end=[double]$Matches[4];
            method=[int]$Matches[5];offset=[int]$Matches[6];alternate=[int]$Matches[7]}
    }
})
if($windows.Count -ne $(if($Expected -eq 'conflict'){130}elseif($Expected -eq 'short-burst'){64}elseif($Expected -eq 'burst'){32}else{120})){throw 'Incomplete window schedule'}
for($i=0;$i -lt $windows.Count;++$i) {
    $w=$windows[$i]
    if($w.trial -ne $i -or $w.offset -ne $selected[$w.method].offset -or
        ($i -gt 0 -and $w.begin -lt $windows[$i-1].end)){throw 'Invalid or overlapping method windows'}
}
$golden=[IO.File]::ReadAllBytes((Join-Path $Directory "$prefix.golden.dex"))
$fixtureBaseline=[IO.File]::ReadAllBytes((Join-Path $Directory "$prefix.baseline.dex"))
if($golden.Length -ne $size -or $fixtureBaseline.Length -ne $size){throw 'Bad fixture size'}
$fast=Join-Path $Directory "${prefix}_out/fast"
$sha256=[Security.Cryptography.SHA256]::Create();$sha1=[Security.Cryptography.SHA1]::Create()
function Digest([byte[]]$bytes,[int]$off,[int]$n){[BitConverter]::ToString($sha256.ComputeHash($bytes,$off,$n))}
function ReadJson([string]$name){Get-Content (Join-Path $fast $name) -Raw | ConvertFrom-Json}
function ReadBytes([string]$name){return ,([IO.File]::ReadAllBytes((Join-Path $fast $name)))}
function AssertSame([byte[]]$a,[byte[]]$b,[string]$label) {
    if($a.Length -ne $b.Length -or (Digest $a 0 $a.Length) -ne (Digest $b 0 $b.Length)){throw "Byte mismatch: $label"}
}
$refills=0;$merges=@();$conflicts=@();$fullSingles=0;$fullMerges=0;$hits=@{};$headless=0
foreach($file in Get-ChildItem $fast -Filter '*.reuse.json') {
    $m=ReadJson $file.Name
    if($m.dex_address -ne $address -or $m.pid -ne $probePid){continue}
    if($m.this_observation_verified -ne $false -or $m.status -ne 'duplicate_method_bytes_not_revalidated'){throw 'Duplicate was marked verified'}
    $rawSource=ReadJson $m.source;$capture=[IO.File]::ReadAllBytes((Join-Path $fast $rawSource.artifacts.first))
    $captureAddress=[Convert]::ToUInt64(($rawSource.address -replace '^0x',''),16)
    $dexAddress=[Convert]::ToUInt64(($address -replace '^0x',''),16)
    foreach($r in $m.references) {
        $proof=ReadJson $r.verified_source;$proofRaw=ReadBytes $proof.artifacts.raw
        if($proof.baseline_revision -ne $m.baseline_revision -or $proof.pid -ne $m.pid -or
           $proof.dex_address -ne $m.dex_address -or $proof.process_start_time_ticks -ne $m.process_start_time_ticks){throw 'Reuse crossed generation'}
        $offset=[int]($dexAddress+$r.offset-$captureAddress)
        if((Digest $capture $offset $r.length) -ne (Digest $proofRaw $r.offset $r.length)){throw 'Reuse bytes differ'}
        if([BitConverter]::ToString($sha1.ComputeHash($proofRaw,$r.offset,$r.length)).Replace('-','').ToLowerInvariant() -ne $r.sha1){throw 'Reuse digest differs'}
    }
}
foreach($file in Get-ChildItem $fast -Filter '*.refill.json') {
    $m=ReadJson $file.Name;if($m.dex_address -ne $address -or $m.pid -ne $probePid){continue}
    ++$refills;$raw=ReadBytes $m.artifacts.raw;$baseline=ReadBytes $m.artifacts.baseline
    if($Expected -ne 'remap'){AssertSame $baseline $fixtureBaseline 'immutable armed fixture baseline'}
    $expectedRaw=[byte[]]$baseline.Clone()
    foreach($patch in $m.patches) {
        $known=@($selected | Where-Object {$_.offset -eq $patch.offset -and $_.length -eq $patch.length})
        if($known.Count -ne 1){throw 'Unexpected method patch'}
        $matchesWindow=@($windows | Where-Object {$_.offset -eq $patch.offset -and
            $m.capture_end_boot -ge $_.begin -and $m.capture_begin_boot -le $_.end})
        $expectedMethod=[byte[]]::new($patch.length)
        [Array]::Copy($golden,$patch.offset,$expectedMethod,0,$patch.length)
        if(@($matchesWindow | Where-Object alternate -eq 1).Count){$expectedMethod[$patch.length-3]=$expectedMethod[$patch.length-3] -bxor 1}
        if((Digest $raw $patch.offset $patch.length) -ne (Digest $expectedMethod 0 $expectedMethod.Length)){throw 'Unexpected method bytes/window'}
        [Array]::Copy($raw,$patch.offset,$expectedRaw,$patch.offset,$patch.length)
        foreach($w in $matchesWindow){$hits[$w.trial]=$true}
    }
    AssertSame $raw $expectedRaw 'single-event non-method complement'
    if((Digest $raw 44 ($size-44)) -eq (Digest $golden 44 ($size-44))){++$fullSingles}
    if($m.method_double_read -ne 'match' -or $m.complement_passes -ne 2){throw 'Missing single-event checks'}
    $src=ReadJson $m.artifacts.source
    if([Convert]::ToUInt64(($src.address -replace '^0x',''),16) -gt [Convert]::ToUInt64(($address -replace '^0x',''),16)+112){++$headless}
}
foreach($file in Get-ChildItem $fast -Filter '*.json') {
    $m=ReadJson $file.Name
    if($m.schema -ne 'nhdd-art-method-merge-v1' -or $m.dex_address -ne $address -or $m.pid -ne $probePid){continue}
    if(!$m.temporal_composite -or $m.atomic_snapshot -or $m.plaintext_proven -or !$m.cross_event_patch_accumulation){throw 'Incorrect composite flags'}
    $expectedRaw=$null
    if(!$m.conflicted){
        $raw=ReadBytes $m.artifacts.raw;$baseline=ReadBytes $m.artifacts.baseline;$expectedRaw=[byte[]]$baseline.Clone()
        if($m.complement_passes -ne 2 -or $m.semantic_fixed.status -ne 'structural_checks_passed'){throw 'Missing aggregate checks'}
    }
    foreach($method in $m.methods) {
        $known=@($selected | Where-Object {$_.offset -eq $method.offset -and $_.length -eq $method.length})
        if($known.Count -ne 1){throw 'Unexpected aggregate method'}
        $digests=@()
        foreach($v in $method.variants) {
            $source=ReadJson $v.source;$sourceRaw=ReadBytes $source.artifacts.raw
            if($source.baseline_revision -ne $m.baseline_revision -or $source.pid -ne $m.pid -or
                $source.dex_address -ne $m.dex_address -or $source.process_start_time_ticks -ne $m.process_start_time_ticks -or
                $source.baseline_content_hash -ne $m.baseline_content_hash -or
                $source.art_object -ne $m.art_object -or $source.art_vtable -ne $m.art_vtable -or
                $source.libdexfile_build_id -ne $m.libdexfile_build_id -or
                @($source.patches | Where-Object {$_.method_index -eq $method.method_index -and
                    $_.offset -eq $method.offset -and $_.length -eq $method.length}).Count -ne 1 -or
                $v.verified_boot -lt $source.verification_end_boot -or
                $source.capture_begin_boot -ne $v.capture_begin_boot -or $source.capture_end_boot -ne $v.capture_end_boot){throw 'Cross-generation or missing provenance'}
            $digest=[BitConverter]::ToString($sha1.ComputeHash($sourceRaw,$method.offset,$method.length)).Replace('-','').ToLowerInvariant()
            if($digest -ne $v.sha1){throw 'Variant source digest mismatch'}
            $digests+= $digest
            if(!$m.conflicted){[Array]::Copy($sourceRaw,$method.offset,$expectedRaw,$method.offset,$method.length)}
        }
        if($method.conflict -and @($digests | Select-Object -Unique).Count -lt 2){throw 'Conflict did not preserve different variants'}
    }
    if($m.conflicted){
        if($m.artifacts -or !$m.supersedes_all_prior_revisions -or @($m.methods | Where-Object conflict).Count -lt 1){throw 'Conflict selected a winner'}
        $conflicts+= $m
    } else {
        AssertSame $raw $expectedRaw 'aggregate provenance/complement'
        if(@($raw[0..43] | Where-Object {$_ -ne 0}).Count){throw 'Erased header changed in raw'}
        if((Digest $raw 44 ($size-44)) -eq (Digest $golden 44 ($size-44))){++$fullMerges}
        $merges+= $m
    }
}
foreach($c in $conflicts){if(@($merges | Where-Object {$_.session -eq $c.session -and $_.merge_revision -ge $c.merge_revision}).Count){throw 'Published after generation conflict'}}
$scan=Get-Content (Join-Path $Directory "$prefix.scan.log") -Raw
switch($Expected) {
    'multi' {if(!$fullMerges -or $conflicts.Count -or $fullSingles){throw 'No exclusive-window full reconstruction'}}
    'conflict' {if(!$fullMerges -or !$conflicts.Count -or $fullSingles){throw 'Expected reconstruction then conflict freeze'}}
    'outside' {if($refills -or $merges.Count -or $conflicts.Count){throw 'Outside mutation was accepted'}}
    'remap' {if($fullMerges -or $scan -notmatch 'mapping_invalidations=[1-9]'){throw 'Generation crossed remap'}}
    'off' {if($merges.Count -or $conflicts.Count -or !$refills){throw 'Merge-off control failed'}}
    'burst' {if(!$merges.Count -or $conflicts.Count -or $fullSingles){throw 'Burst provenance/composite failed'}}
    'short-burst' {if($conflicts.Count -or $fullSingles){throw 'Short-burst provenance/composite failed'}}
}
$rows=@(foreach($method in 0..($selected.Count-1)){foreach($us in 1000,5000,20000,50000){
    $group=@($windows | Where-Object {$_.method -eq $method -and $_.us -eq $us -and !$_.alternate})
    [pscustomobject]@{method=$selected[$method].name;ms=$us/1000;trials=$group.Count;hits=@($group | Where-Object {$hits.ContainsKey($_.trial)}).Count}
}})
[pscustomobject]@{name=$prefix;expected=$Expected;single_refills=$refills;single_full_body_matches=$fullSingles;
    headless_sources=$headless;merged_revisions=$merges.Count;full_three_method_revisions=$fullMerges;
    conflict_records=$conflicts.Count;exposed_methods=$selected.Count;max_merged_methods=($merges | Measure-Object method_count -Maximum).Maximum;
    methods=$selected;windows=$rows} | ConvertTo-Json -Depth 6
