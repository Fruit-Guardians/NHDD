param(
    [Parameter(Mandatory=$true)][string]$Ndk,
    [ValidatePattern('^9\.0\.\d+$')][string]$Version='9.0.1',
    [string]$Destination='',
    [ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedArm64Sha256='e785d6ce3d6121be2eb4829f6c5e47559b5fe0f55c7afb49fb126c742cb28180',
    [ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedArmv7Sha256='d5b6c3ac34a9ada6f46af98f5666a95761ae7b602b30068970e6fa5cd0571234'
)
$ErrorActionPreference='Stop'
$module=Split-Path $PSScriptRoot -Parent
Push-Location -LiteralPath $module
try {
    $commit=(& git rev-parse HEAD).Trim();if($LASTEXITCODE -ne 0){throw 'Run from a Git checkout'}
    & git diff --quiet HEAD -- ..
    if($LASTEXITCODE -ne 0){throw 'Commit source, release templates and license before packaging'}
    $bin=Join-Path $Ndk 'toolchains/llvm/prebuilt/windows-x86_64/bin'
    foreach($required in @('aarch64-linux-android34-clang++.cmd','armv7a-linux-androideabi23-clang++.cmd','llvm-readelf.exe')){
        if(!(Test-Path -LiteralPath (Join-Path $bin $required))){throw "Missing NDK tool: $required"}
    }
    if(!$Destination){$Destination=Join-Path $module "dist/v$Version"}
    $dest=[IO.Path]::GetFullPath($Destination,$module)
    if(Test-Path -LiteralPath $dest){throw 'Destination already exists; preserve prior release artifacts'}
    $llvmNotice=Join-Path $Ndk 'toolchains/llvm/prebuilt/windows-x86_64/NOTICE'
    $sysrootNotice=Join-Path $Ndk 'toolchains/llvm/prebuilt/windows-x86_64/sysroot/NOTICE'
    foreach($notice in $llvmNotice,$sysrootNotice){if(!(Test-Path -LiteralPath $notice)){throw "Missing notice: $notice"}}
    $license=Join-Path (Split-Path $module -Parent) 'LICENSE'
    & git ls-files --error-unmatch ../LICENSE | Out-Null
    if($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $license)){throw 'A committed project LICENSE is required for release'}
    $licenseText=Get-Content -LiteralPath $license -Raw
    if($licenseText -notmatch '^MIT License\r?\n' -or $licenseText -notmatch 'Permission is hereby granted, free of charge'){
        throw 'Expected the owner-approved MIT license'
    }
    $licenseHash=(Get-FileHash -LiteralPath $license -Algorithm SHA256).Hash.ToLowerInvariant()
    $licenseStatus='MIT (see bundled LICENSE)'
    New-Item -ItemType Directory $dest | Out-Null
    $flags=@('-O2','-std=c++17','-Wall','-Wextra','-Werror')
    $records=@()
    foreach($arch in @(
        @{abi='arm64-v8a';api=34;compiler='aarch64-linux-android34-clang++.cmd';expected=$ExpectedArm64Sha256;machine='AArch64';verified='Root Pixel 6 / Android 16, controlled fixture'},
        @{abi='armeabi-v7a';api=23;compiler='armv7a-linux-androideabi23-clang++.cmd';expected=$ExpectedArmv7Sha256;machine='ARM';verified='Cross-compile only; no ARMv7 device validation; ARM64 ART profile unsupported'}
    )) {
        $stem="NHDD-v$Version-android-$($arch.abi)";$folder=Join-Path $dest $stem
        New-Item -ItemType Directory (Join-Path $folder 'THIRD-PARTY') | Out-Null
        $executable=Join-Path $folder 'nhdd'
        & (Join-Path $bin $arch.compiler) @flags src/main.cpp -o $executable -static-libstdc++ -pthread
        if($LASTEXITCODE -ne 0){throw "Compilation failed: $($arch.abi)"}
        $hash=(Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
        if($hash -ne $arch.expected){throw "Binary differs from validated build ($($arch.abi)): $hash"}
        $elf=(& (Join-Path $bin 'llvm-readelf.exe') -h -l -d $executable) -join "`n"
        if($LASTEXITCODE -ne 0 -or $elf -notmatch ('Machine:\s+'+$arch.machine+'\s') -or $elf -match 'libc\+\+_shared\.so'){
            throw 'Unexpected ELF ABI or external libc++ dependency'
        }
        $readme=(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'README.template.md') -Raw).
            Replace('@VERSION@',$Version).Replace('@ABI@',$arch.abi).Replace('@API@',"$($arch.api)").
            Replace('@BINARY_SHA@',$hash).Replace('@COMMIT@',$commit).Replace('@LICENSE_STATUS@',$licenseStatus)
        $readme | Set-Content -LiteralPath (Join-Path $folder 'README.md') -Encoding utf8
        Copy-Item -LiteralPath $llvmNotice -Destination (Join-Path $folder 'THIRD-PARTY/LLVM-NOTICE.txt')
        Copy-Item -LiteralPath $sysrootNotice -Destination (Join-Path $folder 'THIRD-PARTY/ANDROID-SYSROOT-NOTICE.txt')
        Copy-Item -LiteralPath $license -Destination (Join-Path $folder 'LICENSE')
        $info=[ordered]@{version=$Version;component='NHDD-cpp-modular CLI';source_commit=$commit;abi=$arch.abi;minimum_build_api=$arch.api;
            ndk_revision=((Get-Content (Join-Path $Ndk 'source.properties') | Select-String '^Pkg.Revision = ').Line -replace '^Pkg.Revision = ','');
            compile_flags=$flags+@('-static-libstdc++','-pthread');binary_sha256=$hash;stripped=$false;
            validation=$arch.verified;project_license='MIT';project_license_present=$true;license_sha256=$licenseHash;internal_help_version='v9.0-cpp-class'}
        $info | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $folder 'BUILD-INFO.json') -Encoding utf8
        $checks=@(Get-ChildItem -LiteralPath $folder -File -Recurse | Sort-Object FullName | ForEach-Object {
            $relative=[IO.Path]::GetRelativePath($folder,$_.FullName).Replace('\','/')
            (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()+'  '+$relative
        })
        $checks | Set-Content -LiteralPath (Join-Path $folder 'SHA256SUMS.txt') -Encoding ascii
        [IO.Compression.ZipFile]::CreateFromDirectory($folder,(Join-Path $dest "$stem.zip"))
        $records+=[pscustomobject]$info
    }
    $source=Join-Path $dest "NHDD-v$Version-source.zip"
    & git -C (Split-Path $module -Parent) archive --format=zip "--prefix=NHDD-v$Version-source/" "--output=$source" $commit
    if($LASTEXITCODE -ne 0){throw 'Source archive failed'}
    $notes=(Get-Content -LiteralPath (Join-Path $PSScriptRoot "notes-v$Version.md") -Raw).
        Replace('@COMMIT@',$commit).Replace('@ARM64_SHA@',$ExpectedArm64Sha256).Replace('@ARMV7_SHA@',$ExpectedArmv7Sha256).
        Replace('@LICENSE_STATUS@',$licenseStatus)
    $notes | Set-Content -LiteralPath (Join-Path $dest 'RELEASE-NOTES.md') -Encoding utf8
    Get-ChildItem -LiteralPath $dest -File -Filter '*.zip' | Sort-Object Name | ForEach-Object {
        (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()+'  '+$_.Name
    } | Set-Content -LiteralPath (Join-Path $dest 'SHA256SUMS.txt') -Encoding ascii
    $records | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $dest 'build-manifest.json') -Encoding utf8
    Write-Output "Prepared $dest from $commit. No tag, upload, or publication performed."
} finally {Pop-Location}
