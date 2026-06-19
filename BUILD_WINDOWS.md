# NHDD Windows / Linux Build Notes

This repository has two desktop GUI options:

1. `gui/` — original native GUI based on Go + Fyne.
2. `gui_web/` — dependency-free Go standard-library GUI wrapper. It starts a local web UI in the browser. This is the easiest Windows build path.

Both desktop GUIs are only controllers. The Android-side scanner is `nhdd.c`; you still need to compile it into an Android ARM64 binary named `nhdd` and put it next to the GUI executable.

## 1. Build Android-side `nhdd`

### Linux

```bash
export NDK=/path/to/android-ndk-r27
./scripts/build_nhdd_android.sh
```

Equivalent manual command:

```bash
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang \
  -O2 -static -Wall -Wextra -o nhdd nhdd.c
```

### Windows

Use the Windows NDK prebuilt clang path:

```powershell
$NDK="C:\Android\android-ndk-r27"
& "$NDK\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android34-clang.cmd" `
  -O2 -static -Wall -Wextra -o nhdd nhdd.c
```

## 2. Build the dependency-free Windows GUI

This is recommended when you only need a working Windows controller.

### From Windows

```powershell
.\scripts\build_webgui_windows.ps1
```

Output:

```text
dist\nhdd-gui-web-windows-amd64.exe
```

### From Linux

```bash
./scripts/build_webgui_windows_from_linux.sh
```

This does not need MinGW or Fyne because it uses only Go standard library.

## 3. Build the original Fyne native Windows GUI

### From Windows

Install:

- Go 1.21+
- MSYS2 MinGW-w64 toolchain, with `gcc` visible in PATH
- Android platform-tools for `adb`

Then:

```powershell
.\scripts\build_fyne_windows.ps1
```

Manual commands:

```powershell
cd gui
go mod tidy
$env:CGO_ENABLED="1"
go build -trimpath -ldflags="-s -w -H windowsgui" -o nhdd-gui.exe .
```

### From Linux

```bash
sudo apt update
sudo apt install -y gcc-mingw-w64
./scripts/build_fyne_windows_from_linux.sh
```

If Go module downloads are blocked in your VM, configure proxy first, for example:

```bash
go env -w GOPROXY=https://goproxy.cn,direct
# or, if your host proxy is available:
export HTTPS_PROXY=http://192.168.238.1:7897
export HTTP_PROXY=http://192.168.238.1:7897
```

## 4. Runtime layout

Put files like this:

```text
NHDD-run/
├── nhdd-gui-web-windows-amd64.exe   # or nhdd-gui-fyne-windows-amd64.exe
└── nhdd                             # Android ARM64 binary compiled from nhdd.c
```

Make sure `adb.exe` is in PATH, or fill the absolute adb path in the GUI.

Root command examples:

```text
su -c
kp -c
ksud -c
su 0 -c
```

The patched GUI also supports a custom placeholder form:

```text
/path/to/root-wrapper {cmd}
```

`{cmd}` will be replaced with the quoted nhdd command.

## 5. Important limitations

NHDD is a no-hook memory scanner. It can quickly dump DEX/SO files already resident in memory, but it does not solve method-body extraction or CodeItem backfill. For second-generation extraction shells, use it as a low-intrusion auxiliary scanner, not as a replacement for a DefineClass + LoadMethod/FART-style pipeline.
