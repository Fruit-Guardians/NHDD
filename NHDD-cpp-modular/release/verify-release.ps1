param([Parameter(Mandatory=$true)][string]$Directory,[ValidatePattern('^[0-9a-f]{40}$')][string]$ExpectedCommit)
$ErrorActionPreference='Stop'
$dir=(Resolve-Path -LiteralPath $Directory).Path
$manifest=Get-Content -LiteralPath (Join-Path $dir 'build-manifest.json') -Raw | ConvertFrom-Json
if(@($manifest).Count -ne 2){throw 'Expected two ABI manifests'}
$commits=@($manifest.source_commit | Select-Object -Unique)
if($commits.Count -ne 1 -or ($ExpectedCommit -and $commits[0] -ne $ExpectedCommit)){throw 'Mixed or unexpected source commit'}
$licenseTexts=@()
$hashes=@{}
foreach($line in Get-Content -LiteralPath (Join-Path $dir 'SHA256SUMS.txt')){
    if($line -notmatch '^([0-9a-f]{64})  ([A-Za-z0-9_.-]+\.zip)$'){throw 'Malformed asset checksum'}
    $name=$Matches[2];$hash=$Matches[1]
    if($hashes.ContainsKey($name)){throw 'Duplicate asset checksum'}
    if((Get-FileHash -LiteralPath (Join-Path $dir $name) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash){throw "Asset checksum mismatch: $name"}
    $hashes[$name]=$hash
}
if($hashes.Count -ne 3 -or @(Get-ChildItem -LiteralPath $dir -Filter '*.zip' -File).Count -ne 3){throw 'Expected two binary ZIPs and one source ZIP'}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('nhdd-release-verify-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $temp | Out-Null
foreach($m in $manifest){
    if(!$m.project_license_present -or $m.project_license -ne 'MIT' -or $m.license_sha256 -notmatch '^[0-9a-f]{64}$'){throw 'Missing MIT license metadata'}
    $name="NHDD-v$($m.version)-android-$($m.abi).zip"
    $zip=[IO.Compression.ZipFile]::OpenRead((Join-Path $dir $name))
    try {
        $allowed=@('nhdd','README.md','BUILD-INFO.json','SHA256SUMS.txt','THIRD-PARTY/LLVM-NOTICE.txt','THIRD-PARTY/ANDROID-SYSROOT-NOTICE.txt')
        $allowed+='LICENSE'
        foreach($entry in $zip.Entries){if($entry.FullName -notin $allowed){throw "Unexpected ZIP entry: $($entry.FullName)"}}
        if($zip.Entries.Count -ne $allowed.Count){throw 'Missing or duplicate binary package entries'}
    } finally {$zip.Dispose()}
    $out=Join-Path $temp $m.abi;[IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $dir $name),$out)
    foreach($line in Get-Content -LiteralPath (Join-Path $out 'SHA256SUMS.txt')){
        if($line -notmatch '^([0-9a-f]{64})  (.+)$'){throw 'Malformed internal checksum'}
        $expected=$Matches[1];$relative=$Matches[2]
        if($relative -notin $allowed -or $relative -eq 'SHA256SUMS.txt'){throw 'Unexpected internal checksum target'}
        if((Get-FileHash -LiteralPath (Join-Path $out $relative) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected){throw "Internal checksum mismatch: $relative"}
    }
    if(@(Get-Content -LiteralPath (Join-Path $out 'SHA256SUMS.txt')).Count -ne $allowed.Count-1){throw 'Incomplete internal checksums'}
    $info=Get-Content -LiteralPath (Join-Path $out 'BUILD-INFO.json') -Raw | ConvertFrom-Json
    if($info.source_commit -ne $commits[0] -or $info.abi -ne $m.abi -or $info.binary_sha256 -ne $m.binary_sha256){throw 'Internal build info mismatch'}
    if($info.project_license -ne 'MIT' -or $info.license_sha256 -ne $m.license_sha256 -or
       (Get-FileHash -LiteralPath (Join-Path $out 'LICENSE') -Algorithm SHA256).Hash.ToLowerInvariant() -ne $m.license_sha256){throw 'Bundled MIT license mismatch'}
    $licenseTexts+=(Get-Content -LiteralPath (Join-Path $out 'LICENSE') -Raw).Replace("`r`n","`n")
    $binary=Join-Path $out 'nhdd';$bytes=[IO.File]::ReadAllBytes($binary)
    if($bytes.Length -lt 64 -or $bytes[0] -ne 127 -or $bytes[1] -ne 69 -or $bytes[2] -ne 76 -or $bytes[3] -ne 70){throw 'Not an ELF binary'}
    $machine=[BitConverter]::ToUInt16($bytes,18)
    if(($m.abi -eq 'arm64-v8a' -and ($bytes[4] -ne 2 -or $machine -ne 183)) -or
       ($m.abi -eq 'armeabi-v7a' -and ($bytes[4] -ne 1 -or $machine -ne 40))){throw 'ELF ABI mismatch'}
    if((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant() -ne $m.binary_sha256){throw 'Extracted binary hash mismatch'}
    if((Get-Content -LiteralPath (Join-Path $out 'README.md') -Raw) -match '@(COMMIT|VERSION|ABI|API|BINARY_SHA|LICENSE_STATUS)@'){throw 'Unresolved README placeholder'}
    Write-Output "Verified $name (ABI, source commit, internal/asset SHA-256, notices, exact file whitelist)"
}
$source="NHDD-v$($manifest[0].version)-source.zip"
$zip=[IO.Compression.ZipFile]::OpenRead((Join-Path $dir $source))
try {
    $prefix="NHDD-v$($manifest[0].version)-source/"
    foreach($entry in $zip.Entries){
        if(!$entry.FullName.StartsWith($prefix) -or $entry.FullName -match '(^|/)(\.git|\.test-bin|dist|nhdd_auto_test)(/|$)'){
            throw "Unexpected source archive path: $($entry.FullName)"
        }
    }
    if(@($zip.Entries | Where-Object FullName -eq "${prefix}NHDD-cpp-modular/src/main.cpp").Count -ne 1){throw 'Missing source entry point'}
    $licenseEntry=$zip.GetEntry("${prefix}LICENSE");if(!$licenseEntry){throw 'Source archive missing LICENSE'}
    $reader=[IO.StreamReader]::new($licenseEntry.Open())
    try {$sourceLicense=$reader.ReadToEnd().Replace("`r`n","`n")} finally {$reader.Dispose()}
    foreach($text in $licenseTexts){if($text -cne $sourceLicense){throw 'Source and binary package licenses differ'}}
} finally {$zip.Dispose()}
Write-Output "Release verification passed; retained extracted files: $temp"
