# NHDD Windows / Linux Build Notes

The desktop GUI is built with Go + Wails v2, providing a native window with a Web frontend. Windows builds do not need a separate GCC installation.

Both the desktop GUI and the command-line TUI are controllers. Put the Android ARM64 engine named `nhdd` next to the GUI executable. Current releases bundle the C++ engine; the `nhdd.c` commands below build the older C baseline, not the current ART-assisted capture implementation.

## 1. Build Android-side `nhdd`

### Cross-platform

```bash
python scripts/build_nhdd_android.py
python scripts/build_nhdd_android.py --ndk C:\Android\android-ndk-r27 --api 34 --out nhdd
```

The Python builder auto-detects NDK installs under the normal Android SDK
locations on Windows, macOS, and Linux. You can still use the shell wrappers:

```bash
# macOS / Linux
NDK=/path/to/android-ndk-r27 ./scripts/build_nhdd_android.sh
```

```powershell
# Windows PowerShell
powershell -ExecutionPolicy Bypass -File scripts\build_nhdd_android.ps1 -Ndk C:\Android\android-ndk-r27
```

Equivalent manual Windows command:

```powershell
& "C:\Android\android-ndk-r27\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android34-clang.cmd" `
  -O2 -static -Wall -Wextra -o nhdd nhdd.c
```

Equivalent manual Linux command:

```bash
/path/to/android-ndk-r27/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang \
  -O2 -static -Wall -Wextra -o nhdd nhdd.c
```

## 1.5. Diagnose environment

```bash
python scripts/doctor.py
python scripts/doctor.py --su-cmd "su -c"
```

## 2. Build the Wails desktop GUI

### Prerequisites

- Go 1.26+ (release validation uses Go 1.26.10)
- Wails CLI: pinned in gui/go.mod; use `go tool wails`, not an independently installed old CLI
- Node.js 20.19+ / 22.12+ (release validation uses Node 24)
- Android platform-tools for `adb`

### From Windows

```powershell
cd gui
$env:GOFLAGS='-buildvcs=false'
go tool wails build -trimpath -ldflags "-s -w -buildid="
```

Output:

```text
gui/build/bin/nhdd-gui.exe
```

### From Linux

```bash
cd gui
GOFLAGS=-buildvcs=false go tool wails build -trimpath -ldflags '-s -w -buildid='
```

If Go module downloads are blocked, configure proxy first:

```bash
go env -w GOPROXY=https://goproxy.cn,direct
```

## 3. Runtime layout

Put files like this:

```text
NHDD-run/
├── nhdd-gui.exe   # Wails desktop GUI
└── nhdd           # Android ARM64 engine, not a Windows executable
```

Make sure `adb.exe` is in PATH, or fill the absolute adb path in the GUI.

Root command examples:

```text
su -c
kp -c
ksud -c
su 0 -c
```

The GUI also supports a custom placeholder form:

```text
/path/to/root-wrapper {cmd}
```

`{cmd}` will be replaced with the quoted nhdd command.

## 4. Important limitations

The desktop UI does not expose every v9 ART / event / spawn option. Use the standalone C++ CLI for those features. ART-assisted method recovery requires a supported Build ID; it is not a universal unpacker or a guarantee of a runnable repacked APK.

For release ZIPs, use `NHDD-cpp-modular/release/build-release.ps1` followed by
`build-desktop.ps1`, `verify-release.ps1` and `scripts/audit_release.py`.
The privacy gate checks actual ZIP/EXE contents, not just the frontend source.
Keep project and third-party license notices. Linux GUI builds still need their
normal Wails system dependencies; the Windows release does not validate Linux.
