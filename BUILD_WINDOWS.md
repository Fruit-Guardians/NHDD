# NHDD Windows / Linux Build Notes

The desktop GUI is built with Go + Wails v2, providing a native window with a Web frontend. No CGO or GCC required.

Both the desktop GUI and the command-line TUI are only controllers. The Android-side scanner is `nhdd.c`; you still need to compile it into an Android ARM64 binary named `nhdd` and put it next to the GUI executable.

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

## 2. Build the Wails desktop GUI

### Prerequisites

- Go 1.21+
- Wails CLI: `go install github.com/wailsapp/wails/v2/cmd/wails@latest`
- Node.js (for frontend build)
- Android platform-tools for `adb`

### From Windows

```powershell
cd gui
wails build
```

Output:

```text
gui/build/bin/nhdd-gui.exe
```

### From Linux

```bash
cd gui
wails build
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
└── nhdd           # Android ARM64 binary compiled from nhdd.c
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

NHDD is a no-hook memory scanner. It can quickly dump DEX/SO files already resident in memory, but it does not solve method-body extraction or CodeItem backfill. For second-generation extraction shells, use it as a low-intrusion auxiliary scanner, not as a replacement for a DefineClass + LoadMethod/FART-style pipeline.
