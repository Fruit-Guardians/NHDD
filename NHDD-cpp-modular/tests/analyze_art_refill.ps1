param([Parameter(Mandatory=$true)][string]$Directory)
$ErrorActionPreference='Stop'
$probe=Get-ChildItem $Directory -Filter '*.probe.log' | Select-Object -First 1
if(!$probe){throw 'Missing fixture log'}
$prefix=$probe.Name -replace '\.probe\.log$',''
$text=Get-Content $probe.FullName
$ready=$text | Where-Object {$_ -match '^READY '} | Select-Object -First 1
if($ready -notmatch 'payload_address=(0x[0-9a-f]+) size=(\d+) method_offset=(\d+) method_bytes=(\d+)'){throw 'Missing fixture identity'}
$address=[Convert]::ToUInt64(($Matches[1] -replace '^0x',''),16)
$size=[int]$Matches[2];$offset=[int]$Matches[3];$length=[int]$Matches[4]
$windows=@($text | ForEach-Object {
    if($_ -match 'WINDOW trial=(\d+) us=(\d+) begin=([\d.]+) end=([\d.]+)') {
        [pscustomobject]@{trial=[int]$Matches[1];us=[int]$Matches[2];begin=[double]$Matches[3];end=[double]$Matches[4]}
    }
})
$golden=[IO.File]::ReadAllBytes((Join-Path $Directory "$prefix.golden.dex"))
$hash=[Security.Cryptography.SHA256]::Create()
function Digest([byte[]]$bytes,[int]$start,[int]$count) {return [BitConverter]::ToString($hash.ComputeHash($bytes,$start,$count))}
$goldenBody=Digest $golden 44 ($golden.Length-44)
$fast=Join-Path $Directory "${prefix}_out/fast"
$hits=@{};$refills=0;$bad=0;$afterErase=0;$sourcesWithoutHeader=0;$planning=@{}
if(Test-Path $fast) {
    foreach($file in Get-ChildItem $fast -Filter '*.json') {
        $m=Get-Content $file.FullName -Raw | ConvertFrom-Json
        foreach($a in $m.art_associations) {
            if(!$planning.ContainsKey($a.planning_status)){$planning[$a.planning_status]=0}
            ++$planning[$a.planning_status]
        }
        if($m.status -ne 'reconstructed_method_composite'){continue}
        ++$refills
        $raw=[IO.File]::ReadAllBytes((Join-Path $fast $m.artifacts.raw))
        $baseline=[IO.File]::ReadAllBytes((Join-Path $fast $m.artifacts.baseline))
        $source=Get-Content (Join-Path $fast $m.artifacts.source) -Raw | ConvertFrom-Json
        $zeroHeader=@($raw[0..43] | Where-Object {$_ -ne 0}).Count -eq 0
        $valid=$raw.Length -eq $size -and $zeroHeader -and (Digest $raw 44 ($size-44)) -eq $goldenBody -and
            $m.patches.Count -eq 1 -and $m.patches[0].offset -eq $offset -and $m.patches[0].length -eq $length -and
            $m.semantic_fixed.status -eq 'structural_checks_passed' -and $m.method_double_read -eq 'match' -and
            (Digest $raw 0 $offset) -eq (Digest $baseline 0 $offset) -and
            (Digest $raw ($offset+$length) ($size-$offset-$length)) -eq (Digest $baseline ($offset+$length) ($size-$offset-$length))
        if(!$valid){++$bad;continue}
        if([Convert]::ToUInt64(($source.address -replace '^0x',''),16) -gt $address+112){++$sourcesWithoutHeader}
        foreach($w in $windows) {
            if($m.capture_end_boot -ge $w.begin -and $m.capture_begin_boot -le $w.end) {
                $hits[$w.trial]=$true
                if($m.verification_begin_boot -gt $w.end){++$afterErase}
            }
        }
    }
}
$rows=@(foreach($us in 1000,5000,20000,50000) {
    $group=@($windows | Where-Object us -eq $us)
    [pscustomobject]@{window_ms=$us/1000;trials=$group.Count;verified_refill_hits=@($group | Where-Object {$hits.ContainsKey($_.trial)}).Count}
})
[pscustomobject]@{name=$prefix;payload_size=$size;method_offset=$offset;method_bytes=$length;refill_observations=$refills;
    invalid_derivatives=$bad;sources_without_dex_header=$sourcesWithoutHeader;verified_after_reerase_observations=$afterErase;
    windows=$rows;planning_status=$planning} | ConvertTo-Json -Depth 6
if($bad){throw 'A derivative failed provenance/body/patch checks'}
