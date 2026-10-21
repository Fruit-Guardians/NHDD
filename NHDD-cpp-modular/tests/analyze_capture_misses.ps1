param([string]$Directory,[switch]$SelfTest)
$ErrorActionPreference='Stop'
if($SelfTest){
    $dir=Join-Path ([IO.Path]::GetTempPath()) ('nhdd-misses-'+[guid]::NewGuid().ToString('N'))
    $name='self';$fast=Join-Path $dir 'self_out/fast';New-Item -ItemType Directory $fast | Out-Null
    @('READY pid=42 payload_address=0x1000 size=64',
        'METHOD index=0 offset=0 bytes=2 name=marker0','METHOD index=1 offset=4 bytes=2 name=marker1',
        'METHOD index=2 offset=8 bytes=2 name=marker2','METHOD index=3 offset=12 bytes=2 name=marker3',
        'WINDOW trial=0 us=1000 begin=100.000 end=100.001 method=0 offset=0 alternate=0',
        'WINDOW trial=1 us=1000 begin=100.000 end=100.001 method=1 offset=4 alternate=0',
        'WINDOW trial=2 us=5000 begin=100.000 end=100.005 method=2 offset=8 alternate=0',
        'WINDOW trial=3 us=5000 begin=100.000 end=100.005 method=3 offset=12 alternate=0') | Set-Content (Join-Path $dir "$name.probe.log")
    $golden=[byte[]](1..64);[IO.File]::WriteAllBytes((Join-Path $dir "$name.golden.dex"),$golden)
    $first=[byte[]]::new(12);$second=[byte[]]::new(12)
    [Array]::Copy($golden,$first,6);[Array]::Copy($golden,$second,2)
    [IO.File]::WriteAllBytes((Join-Path $fast 'first.bin'),$first);[IO.File]::WriteAllBytes((Join-Path $fast 'second.bin'),$second)
    @{pid=42;source='early_tracefs_local_capture';address='0x1000';read_begin_boot_seconds=100.0001;read_end_boot_seconds=100.0002;
        event_boot_seconds=100;line_received_boot=100.00002;acquire_begin_boot=100.00004;anchors_done_boot=100.00008;event_to_read_ms=.1;
        artifacts=@{first='first.bin';second='second.bin'};pages=@(@{offset=0;length=12;first_read=12;second_read=12})} |
        ConvertTo-Json -Depth 5 | Set-Content (Join-Path $fast 'capture.json')
    $r=& $PSCommandPath -Directory $dir | ConvertFrom-Json
    if(($r.misses.category -join ',') -ne 'raw_match_not_verified,only_one_read_matches,overlapping_capture_no_matching_bytes,no_capture_overlaps_window'){
        throw 'Miss categorization self-test failed'
    }
    if($r.raw_observations -ne 1 -or $r.verified_methods -ne 0 -or $r.stage_p95_ms.prepare_anchors -le 0){throw 'Miss timing self-test failed'}
    $path=Join-Path $fast 'capture.json';$m=Get-Content $path -Raw | ConvertFrom-Json;$m.pages[0].first_read=1
    $m | ConvertTo-Json -Depth 5 | Set-Content $path
    $r=& $PSCommandPath -Directory $dir | ConvertFrom-Json
    if($r.misses[0].category -ne 'only_one_read_matches'){throw 'Short prefix accepted as full double read'}
    $m.pages=@();$m | ConvertTo-Json -Depth 5 | Set-Content $path
    $r=& $PSCommandPath -Directory $dir | ConvertFrom-Json
    if($r.misses[0].raw -ne 0 -or $r.misses[0].single_read -ne 0){throw 'Missing coverage accepted'}
    Write-Output "analyze_capture_misses: OK (four categories/timing); retained synthetic evidence: $dir";return
}
if(!$Directory){throw 'Directory required'}
$probe=Get-ChildItem -LiteralPath $Directory -Filter '*.probe.log' | Select-Object -First 1
if(!$probe){throw 'Missing own fixture log'}
$prefix=$probe.Name -replace '\.probe\.log$',''
$lines=Get-Content -LiteralPath $probe.FullName
$ready=$lines | Where-Object {$_ -match '^READY '} | Select-Object -First 1
if($ready -notmatch 'pid=(\d+) payload_address=(0x[0-9a-f]+) size=(\d+)'){throw 'Missing fixture identity'}
$probePid=[int]$Matches[1];$address=[Convert]::ToUInt64($Matches[2].Substring(2),16);$declaredSize=[long]$Matches[3]
$golden=[IO.File]::ReadAllBytes((Join-Path $Directory "$prefix.golden.dex"))
if($golden.Length -ne $declaredSize){throw 'Fixture size mismatch'}
$methods=@{};$windows=@()
foreach($line in $lines) {
    if($line -match '^METHOD index=(\d+) offset=(\d+) bytes=(\d+) name=(marker\d+)'){
        $methods[[long]$Matches[2]]=[int]$Matches[3]
    }
    if($line -match '^WINDOW trial=(\d+) us=(\d+) begin=([\d.]+) end=([\d.]+) method=(\d+) offset=(\d+) alternate=(\d+)'){
        $windows+=[pscustomobject]@{trial=[int]$Matches[1];us=[int]$Matches[2];begin=[double]$Matches[3];end=[double]$Matches[4];
            offset=[long]$Matches[6];alternate=[int]$Matches[7];raw=0;verified=0;overlaps=0;single_read=0;nearest_begin_ms=$null;nearest_event_delay_ms=$null}
    }
}
if(@($windows | Where-Object alternate -ne 0).Count){throw 'Use single-exposure, non-conflict fixture only'}
if(!$windows.Count -or $windows.Count -ne $methods.Count -or @($windows.offset | Select-Object -Unique).Count -ne $windows.Count){throw 'Require one exposure per selected method'}
foreach($w in $windows){if(!$methods.ContainsKey($w.offset) -or $methods[$w.offset] -le 0 -or $w.offset -lt 0 -or
    $w.offset+$methods[$w.offset] -gt $golden.Length -or $w.end -lt $w.begin){throw 'Invalid fixture method/window bounds'}}
$fast=Join-Path $Directory "${prefix}_out/fast"
$verified=@{};$rejections=@{};$rawCount=0;$receiveDelays=@();$resolveDelays=@();$anchorDelays=@();$readDelays=@()
foreach($file in Get-ChildItem -LiteralPath $fast -Filter '*.json') {
    $m=Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    if($m.status -eq 'rejected'){
        if(!$rejections.ContainsKey($m.reason)){$rejections[$m.reason]=0};++$rejections[$m.reason];continue
    }
    if($m.pid -ne $probePid){continue}
    if($m.status -eq 'reconstructed_method_composite'){
        if([Convert]::ToUInt64($m.dex_address.Substring(2),16) -ne $address){continue}
        foreach($p in $m.patches){$verified[[long]$p.offset]=$true};continue
    }
    if($m.source -ne 'early_tracefs_local_capture'){continue}
    $base=[Convert]::ToUInt64($m.address.Substring(2),16)
    if($base -lt $address -or $base -ge $address+$golden.Length){continue}
    ++$rawCount
    if($m.line_received_boot){
        $receiveDelays+=1000*($m.line_received_boot-$m.event_boot_seconds)
        $resolveDelays+=1000*($m.acquire_begin_boot-$m.line_received_boot)
        $anchorDelays+=1000*($m.anchors_done_boot-$m.acquire_begin_boot)
        $readDelays+=1000*($m.read_end_boot_seconds-$m.read_begin_boot_seconds)
    }
    $first=[IO.File]::ReadAllBytes((Join-Path $fast $m.artifacts.first))
    $second=[IO.File]::ReadAllBytes((Join-Path $fast $m.artifacts.second))
    foreach($w in $windows) {
        $off=[long]$address+$w.offset-[long]$base;$len=$methods[$w.offset]
        if($off -lt 0 -or $off+$len -gt $first.Length -or $off+$len -gt $second.Length){continue}
        $delta=1000*($m.read_begin_boot_seconds-$w.begin)
        if($null -eq $w.nearest_begin_ms -or [Math]::Abs($delta) -lt [Math]::Abs($w.nearest_begin_ms)){
            $w.nearest_begin_ms=$delta;$w.nearest_event_delay_ms=$m.event_to_read_ms
        }
        if($m.read_end_boot_seconds -lt $w.begin -or $m.read_begin_boot_seconds -gt $w.end){continue}
        ++$w.overlaps;$one=$true;$two=$true;$cursor=$off
        foreach($page in @($m.pages | Sort-Object offset)){
            $a=[Math]::Max($off,$page.offset);$b=[Math]::Min($off+$len,$page.offset+$page.length)
            if($a -lt $b){
                if($a -gt $cursor){$one=$false;$two=$false};$cursor=[Math]::Max($cursor,$b)
                if($b -gt $page.offset+$page.first_read){$one=$false};if($b -gt $page.offset+$page.second_read){$two=$false}
            }
        }
        if($cursor -lt $off+$len){$one=$false;$two=$false}
        for($i=0;$i -lt $len -and ($one -or $two);++$i){
            if($first[$off+$i] -ne $golden[$w.offset+$i]){$one=$false}
            if($second[$off+$i] -ne $golden[$w.offset+$i]){$two=$false}
        }
        if($one -and $two){++$w.raw}elseif($one -or $two){++$w.single_read}
    }
}
foreach($w in $windows){if($verified.ContainsKey($w.offset)){$w.verified=1}}
$misses=@(foreach($w in $windows | Where-Object verified -eq 0){
    $category=if($w.raw){'raw_match_not_verified'}elseif($w.single_read){'only_one_read_matches'}elseif($w.overlaps){'overlapping_capture_no_matching_bytes'}else{'no_capture_overlaps_window'}
    [pscustomobject]@{trial=$w.trial;us=$w.us;offset=$w.offset;category=$category;raw=$w.raw;single_read=$w.single_read;overlaps=$w.overlaps;
        nearest_begin_ms=$w.nearest_begin_ms;nearest_event_delay_ms=$w.nearest_event_delay_ms}
})
function P95($values){$s=@($values | Sort-Object);if($s.Count){return $s[[int][Math]::Ceiling(.95*$s.Count)-1]};return $null}
[pscustomobject]@{name=$prefix;raw_observations=$rawCount;windows=$windows.Count;verified_methods=$verified.Count;misses=$misses;rejections=$rejections;
    stage_p95_ms=[pscustomobject]@{event_to_line=(P95 $receiveDelays);line_to_acquire=(P95 $resolveDelays);prepare_anchors=(P95 $anchorDelays);double_read=(P95 $readDelays)}} | ConvertTo-Json -Depth 8
