param(
    [Parameter(Mandatory=$true)][string]$ReleaseDirectory,
    [Parameter(Mandatory=$true)][string]$Go
)
$ErrorActionPreference='Stop'
$root=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$dest=(Resolve-Path -LiteralPath $ReleaseDirectory).Path
$manifest=Get-Content -LiteralPath (Join-Path $dest 'build-manifest.json') -Raw | ConvertFrom-Json
$arm=@($manifest | Where-Object abi -eq 'arm64-v8a')
if($arm.Count -ne 1){throw 'Expected one ARM64 engine manifest'}
$version=$arm[0].version;$commit=$arm[0].source_commit
$engine=Join-Path $dest "NHDD-v$version-android-arm64-v8a"
if((Get-FileHash -LiteralPath (Join-Path $engine 'nhdd') -Algorithm SHA256).Hash.ToLowerInvariant() -ne $arm[0].binary_sha256){throw 'Engine checksum mismatch'}
if((& git -C $root rev-parse HEAD).Trim() -ne $commit){throw 'Desktop and engine source commits differ'}
& git -C $root diff --quiet HEAD -- .
if($LASTEXITCODE -ne 0){throw 'Commit all source before packaging'}
$gui=Join-Path $root 'gui'
$priorPath=$env:Path;$priorFlags=$env:GOFLAGS
try {
    $env:Path=(Split-Path (Resolve-Path -LiteralPath $Go).Path -Parent)+';'+$env:Path
    $env:GOFLAGS='-buildvcs=false'
    Push-Location -LiteralPath $gui
    try {
        & $Go tool wails build -trimpath -ldflags '-s -w -buildid=' -m
        if($LASTEXITCODE -ne 0){throw 'Wails build failed'}
    } finally {Pop-Location}
    $exe=Join-Path $gui 'build/bin/nhdd-gui.exe'
    $buildInfo=(& $Go version -m $exe) -join "`n"
    if($LASTEXITCODE -ne 0 -or $buildInfo -notmatch '-trimpath=true'){throw 'GUI does not confirm trimpath'}
    $depPaths=@($buildInfo -split "`n" | ForEach-Object {if($_ -match '^\s+dep\s+(\S+)\s+'){ $Matches[1] }})
    if(!$depPaths.Count){throw 'No embedded Go dependency inventory'}
    Push-Location -LiteralPath $gui
    try {
        $modules=@(& $Go list -m -f '{{.Path}}|{{.Version}}|{{.Dir}}' @depPaths)
        if($LASTEXITCODE -ne 0){throw 'Go dependency inventory failed'}
    } finally {Pop-Location}
    foreach($kind in @('tui','windows-amd64-gui')){
        $stem="NHDD-v$version-$kind";$folder=Join-Path $dest $stem
        if(Test-Path -LiteralPath $folder){throw 'Preserve existing desktop staging folder'}
        New-Item -ItemType Directory -Path (Join-Path $folder 'THIRD-PARTY') | Out-Null
        Copy-Item -LiteralPath (Join-Path $engine 'nhdd'),(Join-Path $root 'LICENSE') -Destination $folder
        Copy-Item -LiteralPath (Join-Path $engine 'THIRD-PARTY/LLVM-NOTICE.txt'),(Join-Path $engine 'THIRD-PARTY/ANDROID-SYSROOT-NOTICE.txt') -Destination (Join-Path $folder 'THIRD-PARTY')
        if($kind -eq 'tui'){
            foreach($file in @('nhdd_tui.py','fix_dex_checksum.py','fix_so.py')){Copy-Item -LiteralPath (Join-Path $root $file) -Destination $folder}
            New-Item -ItemType Directory -Path (Join-Path $folder 'scripts') | Out-Null
            foreach($file in @('repack_apk_fast.py','repack_apk.py')){Copy-Item -LiteralPath (Join-Path $root "scripts/$file") -Destination (Join-Path $folder 'scripts')}
        } else {
            Copy-Item -LiteralPath $exe -Destination $folder
            $goLicense=Join-Path (Split-Path (Split-Path (Resolve-Path -LiteralPath $Go).Path -Parent) -Parent) 'LICENSE'
            Copy-Item -LiteralPath $goLicense -Destination (Join-Path $folder 'THIRD-PARTY/GO-STDLIB-LICENSE.txt')
            $noticeIndex=@()
            foreach($line in $modules){
                $parts=$line.Split('|');if($parts.Count -ne 3 -or !$parts[1] -or !$parts[2]){throw 'Missing embedded module metadata'}
                $licenses=@(Get-ChildItem -LiteralPath $parts[2] -File | Where-Object Name -Match '^(LICENSE|LICENCE|COPYING|NOTICE|PATENTS)(\.|$)')
                if(!$licenses.Count){throw "Missing dependency license: $($parts[0])"}
                $noticeDir=Join-Path $folder ('THIRD-PARTY/GO/'+$parts[0]+'@'+$parts[1])
                New-Item -ItemType Directory -Path $noticeDir -Force | Out-Null
                foreach($file in $licenses){Copy-Item -LiteralPath $file.FullName -Destination $noticeDir}
                $noticeIndex+=($parts[0]+' '+$parts[1])
            }
            $nodeModules=Join-Path $gui 'frontend/node_modules'
            foreach($file in Get-ChildItem -LiteralPath $nodeModules -Recurse -File | Where-Object Name -Match '^(LICENSE|LICENCE|COPYING|NOTICE)(\.|$)'){
                $relative=[IO.Path]::GetRelativePath($nodeModules,$file.FullName)
                $target=Join-Path $folder ('THIRD-PARTY/NPM/'+$relative)
                New-Item -ItemType Directory -Path (Split-Path $target -Parent) -Force | Out-Null
                Copy-Item -LiteralPath $file.FullName -Destination $target
            }
            Copy-Item -LiteralPath (Join-Path $gui 'frontend/src/assets/fonts/OFL.txt') -Destination (Join-Path $folder 'THIRD-PARTY/FONT-OFL.txt')
            $noticeIndex | Set-Content -LiteralPath (Join-Path $folder 'THIRD-PARTY/GO-MODULES.txt') -Encoding utf8
        }
        (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'desktop-README.template.md') -Raw).
            Replace('@VERSION@',$version).Replace('@KIND@',$kind).Replace('@COMMIT@',$commit) |
            Set-Content -LiteralPath (Join-Path $folder 'README.md') -Encoding utf8
        [ordered]@{version=$version;component=$kind;source_commit=$commit;engine_abi='arm64-v8a';engine_api=34;
            engine_sha256=$arm[0].binary_sha256;gui_trimpath=($kind -ne 'tui');
            go_version=(& $Go version);gui_flags='-trimpath -ldflags "-s -w -buildid="; GOFLAGS=-buildvcs=false';
            project_license='MIT'} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $folder 'BUILD-INFO.json') -Encoding utf8
        $checks=@(Get-ChildItem -LiteralPath $folder -Recurse -File | Sort-Object FullName | ForEach-Object {
            (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()+'  '+[IO.Path]::GetRelativePath($folder,$_.FullName).Replace('\','/')
        })
        $checks | Set-Content -LiteralPath (Join-Path $folder 'SHA256SUMS.txt') -Encoding ascii
        [IO.Compression.ZipFile]::CreateFromDirectory($folder,(Join-Path $dest "$stem.zip"))
    }
    Get-ChildItem -LiteralPath $dest -File -Filter '*.zip' | Sort-Object Name | ForEach-Object {
        (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()+'  '+$_.Name
    } | Set-Content -LiteralPath (Join-Path $dest 'SHA256SUMS.txt') -Encoding ascii
} finally {$env:Path=$priorPath;$env:GOFLAGS=$priorFlags}
Write-Output 'Prepared desktop ZIPs with trimmed GUI paths; run verify-release.ps1 and the privacy gate before upload.'
