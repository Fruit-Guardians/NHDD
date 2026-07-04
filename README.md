# NHDD — No-Hook DEX/SO Dumper
English | [简体中文](./README.zh-CN.md)

NHDD is an Android **external-memory DEX/SO dumping tool** for authorized reverse engineering, malware analysis, app debugging, and mobile security research. The Android-side scanner, `nhdd`, runs as an independent root process. It reads `/proc/<pid>/maps` and `/proc/<pid>/mem` (or uses `process_vm_readv` in stealth2 mode), scans the target process memory for DEX/ELF magic, and writes resident DEX or SO images to disk.

Unlike Frida/Xposed/FART/fdex2-style approaches, NHDD does **not** inject code into the target app, does **not** patch method entries, and does **not** require ART hooks. This reduces exposure to common in-process hook indicators such as injected libraries, suspicious threads, method-entry trampolines, and runtime framework modifications.

> Important: no-hook does not mean “impossible to detect.” A target app, system policy, packer, or root environment can still affect results through process termination, permission restrictions, SELinux policy, root detection, or other side effects. NHDD’s practical advantage is low intrusiveness and simple deployment, not a guarantee of universal or risk-free dumping.

## Scope

NHDD works best when:

- The protected app loads a complete or near-complete DEX into memory at runtime.
- You need a fast root-based scanner for DEX/SO files already resident in an app process.
- You want to avoid Frida agents, Xposed modules, Zygisk modules, or ART patching in the target process.

NHDD alone is not enough when:

- The packer decrypts method bodies only on demand.
- CodeItem data is erased, virtualized, or restored only during execution.
- You need full method-body recovery and backfilling.

For second-generation extraction shells, use NHDD with `--stealth2 --relaxed` mode. The `--stealth2` flag uses `process_vm_readv(2)` instead of opening `/proc/<pid>/mem`, which avoids detection by packers that monitor file descriptor access. The `--relaxed` flag validates DEX headers by `endian_tag` (0x12345678) and structure rather than relying on the `dex\n` magic that packers may erase. Full method-body recovery usually requires DefineClass/LoadMethod hooks, CodeItem capture/backfill, or a FART-style pipeline.

## Repository status

| Component | Status | Notes |
|---|---:|---|
| `nhdd.c` | Ready | Core Android ARM64 scanner. v8.0: supports DEX/SO, package multi-process scanning, snapshots, watch mode, de-duplication, DEX checksum repair, stealth2 (process_vm_readv), relaxed DEX validation, and anonymous mapping scan. |
| `nhdd_tui.py` | Recommended | Terminal UI with root-command configuration, watch progress, and result pulling. Best daily entry point in this snapshot. |
| `gui/` | Wails GUI | Go + Wails v2 desktop GUI with Web frontend. No CGO required. |
| `fix_dex_checksum.py` | Ready | Standalone DEX header, SHA-1, and Adler32 repair tool. |

## Features

- **External memory reading**: reads target process memory via `/proc/<pid>/mem` or `process_vm_readv(2)` (stealth2); no target-process injection.
- **DEX dumping**: scans for `dex\n` magic (or `endian_tag` in relaxed mode), reads DEX `file_size`, and exports data page by page.
- **SO dumping**: scans ELF ET_DYN mappings and optionally repairs dumps with SoFixer.
- **Package multi-process scan**: when given a package name, scans all matching processes, including `:remote` child processes.
- **Snapshot mode**: `--snapshot N --interval T` performs repeated fixed-round scans.
- **Watch mode**: `--watch [K]` scans until K consecutive dry rounds, useful for lazy-loaded DEX while you navigate the app.
- **Content de-duplication**: DEX files are de-duplicated by recomputed SHA-1 signature across processes and scan rounds.
- **DEX auto-repair**: fixes `file_size`, `header_size`, `endian_tag`, SHA-1 signature, and Adler32 checksum.
- **Output isolation**: old `.dex/.so` files are removed by default before a run; use `--keep` for incremental runs.
- **Low-intrusion runtime options**: `--region-delay`, `--stealth`, `--stealth2`, `--relaxed`, `--anon`, and `--name` can adjust scan timing, memory access method, DEX validation strategy, and the scanner's visible process name. These are not detection-bypass guarantees.

## How it works

```text
Target app process
├── Packer/protection logic
├── ART/ClassLoader
├── Resident DEX memory regions
└── Mapped SO regions

Independent root process: nhdd
├── Reads /proc/<pid>/maps
├── Opens /proc/<pid>/mem  (default mode)
│   OR uses process_vm_readv(2)  (--stealth2 mode, no fd opened)
├── Scans readable pages for DEX/ELF magic
│   OR scans for endian_tag 0x12345678  (--relaxed mode)
├── Computes dump ranges from DEX headers or ELF program headers
├── Writes files under out_dir/dex and out_dir/so
└── Repairs DEX checksums and optionally invokes SoFixer
```

`pread(/proc/<pid>/mem, ..., virtual_address)` uses the target process virtual address as the file offset. If root permissions and system policy allow it, the scanner can read bytes from the target process address space without executing code inside that process.

## Build Android-side `nhdd`

Requirements: Android NDK r25+ and an ARM64 Android target.

```bash
# Recommended cross-platform builder (Windows/macOS/Linux)
python3 scripts/build_nhdd_android.py

# Explicit NDK / API / output path
python3 scripts/build_nhdd_android.py --ndk /path/to/android-ndk-r27 --api 34 --out nhdd

# macOS / Linux shell wrapper
NDK=/path/to/android-ndk-r27 API=34 ./scripts/build_nhdd_android.sh

# Windows PowerShell wrapper
powershell -ExecutionPolicy Bypass -File scripts/build_nhdd_android.ps1 -Ndk C:\Android\android-ndk-r27

# Manual command
/path/to/android-ndk-r27/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang \
  -O2 -static -Wall -Wextra -o nhdd nhdd.c
```

Push to the device:

```bash
adb push ./nhdd /data/local/tmp/nhdd
adb shell chmod 755 /data/local/tmp/nhdd
```

If you want automatic SO repair, also push a SoFixer binary:

```bash
adb push ./sofixer /data/local/tmp/sofixer
adb shell chmod 755 /data/local/tmp/sofixer
```

## Environment doctor

Before the first run, or after moving to a new machine, run:

```bash
make doctor
```

The doctor checks:

- Local dependencies: `adb`, `sdkmanager`, Android NDK, Node/npm, Wails, Python rich, frontend dependencies, and the SoFixer submodule.
- Device state: whether an authorized Android device is connected.
- Root command: it auto-probes `su -c`, `kp -c`, and `ksud -c`, or you can provide one explicitly.
- Device binary: verifies `/data/local/tmp/nhdd` exists, pulls it back, and checks that it is an ELF64 AArch64 binary.

Common overrides:

```bash
make doctor NDK_PATH="$ANDROID_HOME/ndk/27.2.12479018"
make doctor SU_CMD="kp -c"
make doctor ADB=/path/to/adb HOST_PORT=192.168.238.1:5037 SU_CMD="ksud -c"
python3 scripts/doctor.py --ndk /path/to/android-ndk-r27 --su-cmd "su -c"
```

When a check fails, the `fix:` line gives the next command to run, such as installing the NDK, initializing submodules, connecting a device, or running `make android push` again.

## Command-line usage

### 1. Recommended: scan a running app with watch mode

Open the target app manually and let it reach a stable state, then run:

```bash
adb shell su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --watch 3 --max-seconds 120'
```

While NHDD is running, navigate through important app pages such as login, home, search, profile, payment, order, or plugin-related screens. Lazy-loaded DEX files can be captured as they enter memory.

Pull results:

```bash
adb pull /data/local/tmp/nhdd_dump ./nhdd_output/com.example.app
```

Output layout:

```text
nhdd_dump/
├── dex/
│   ├── dump_<pid>_1.dex
│   └── dump_<pid>_2.dex
└── so/
    ├── libxxx.so
    └── libyyy.so
```

### 2. Fixed wait after cold launch

```bash
adb shell am force-stop com.example.app
adb shell monkey -p com.example.app -c android.intent.category.LAUNCHER 1
sleep 4
adb shell su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --dex'
```

Fixed waits are simple, but not always stable against aggressive packers. In many cases, scanning an already running process with watch mode is more reliable than force-stopping and relying on a 4-second window.

### 3. Snapshot mode

```bash
adb shell su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --snapshot 5 --interval 1'
```

This scans five rounds with a one-second interval between rounds.

### 4. Dump both DEX and SO

```bash
adb shell su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --all'
```

### 5. KernelSU / APatch / other root commands

Different root setups may expose different command wrappers:

```bash
adb shell su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --watch'
adb shell ksud -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --watch'
adb shell kp -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --watch'
```

### 6. Second-generation extraction shells (anti-detection mode)

For packers that detect `/proc/<pid>/mem` being opened and kill the process, use `--stealth2` to read memory via `process_vm_readv(2)` instead. Combine with `--relaxed` for packers that erase DEX magic:

```bash
adb shell kp -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --stealth2 --relaxed --stealth'
```

- `--stealth2`: Uses `process_vm_readv(2)` instead of opening `/proc/<pid>/mem`. No file descriptor is created, making it harder for packers to detect memory access.
- `--relaxed`: Validates DEX headers by `endian_tag` (0x12345678) and header structure, instead of relying on `dex\n` magic that packers may erase.
- `--anon`: Only scans anonymous memory mappings (no file-backed regions). Useful when DEX is loaded into anonymous mmap regions.
- `--stealth`: Adds region delay and disguises the scanner process name.

**Tip**: For aggressive packers, scan a single PID instead of the full package name to minimize the detection window:

```bash
adb shell kp -c '/data/local/tmp/nhdd 12345 /data/local/tmp/nhdd_dump --stealth2 --relaxed --stealth'
```

## `nhdd` options

| Option | Description |
|---|---|
| `<pid\|package>` | Numeric PID scans one process; package name scans all matching processes. |
| `[output_dir]` | Output directory. Default: `/data/local/tmp/nhdd_dump`. |
| `--dex` | Dump DEX only. Default mode. |
| `--so` | Dump SO only. |
| `--all` | Dump both DEX and SO. |
| `--snapshot N` | Run N fixed scan rounds. |
| `--interval T` | Seconds between rounds. Default: 1. |
| `--watch [K]` | Keep scanning until K consecutive dry rounds. Default K: 3. |
| `--max-rounds N` | Maximum rounds in watch mode. Default: 60. |
| `--max-seconds S` | Maximum wall time in watch mode. Default: 120. |
| `--keep` | Do not remove old `.dex/.so` files before scanning. |
| `--stealth` | Enable a default region delay and a default disguised process name. |
| `--stealth2` | Use `process_vm_readv(2)` instead of opening `/proc/<pid>/mem`. Avoids FD-based detection by packers. Recommended for second-generation shells. |
| `--relaxed` | Validate DEX by `endian_tag` (0x12345678) and header structure instead of `dex\n` magic. For packers that erase DEX magic. |
| `--anon` | Only scan anonymous memory mappings (skip file-backed regions). |
| `--region-delay MS` | Sleep MS milliseconds between memory map regions. |
| `--name NAME` / `--disguise NAME` | Change the scanner’s visible `/proc/self/comm` and `/proc/self/cmdline` name. |
| `--sofixer PATH` | Specify SoFixer path. Defaults to `/data/local/tmp/sofixer` or `/data/local/tmp/SoFixer64`. |

## Recommended TUI workflow

Install dependency:

```bash
python3 -m pip install rich
```

Run:

```bash
python3 nhdd_tui.py
python3 nhdd_tui.py com.example.app -o ./nhdd_output
```

If your ADB server runs on another host or on the Windows host from a VM:

```bash
NHDD_ADB='adb -H 192.168.238.1 -P 5037' python3 nhdd_tui.py com.example.app -o ./nhdd_output
```

The TUI lets you configure:

- Whether to restart the app.
- Whether to use watch mode.
- Root command: `su -c`, `kp -c`, `ksud -c`, or empty.
- Dump mode: DEX, SO, or ALL.
- Local output directory.

## Desktop GUI workflow

The desktop GUI is built with Go + Wails v2, providing a native window with a Web frontend. No CGO or GCC required.

Build:

```bash
cd gui
wails build
```

Place the Android ARM64 `nhdd` binary next to the GUI executable:

```text
NHDD-run/
├── nhdd-gui.exe
└── nhdd
```

The GUI supports: ADB connection, app list, root command configuration, dump mode (DEX/SO/ALL), watch mode, and result pulling.

## Standalone DEX repair

`nhdd` already repairs DEX files during dumping. To repair existing dumps manually:

```bash
python3 fix_dex_checksum.py path/to/classes.dex
```

Repair order:

1. `header_size -> 0x70`
2. `endian_tag -> 0x12345678`
3. `file_size -> actual file length`
4. SHA-1 signature over `data[0x20:]`
5. Adler32 checksum over `data[0x0c:]`

## FAQ

### Why is package-name mode recommended over PID mode?

Many Android apps run multiple processes. The actual decrypted DEX may live in a `:remote`, `:push`, or sandbox child process. Package-name mode scans all matching cmdline entries. PID mode scans only one process and may miss the important one.

### Why can the GUI produce fewer results than command line or TUI?

The GUI may use a fixed-wait flow in some scenarios. For multi-process or lazy-load targets, use:

```bash
adb shell su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --watch'
```

or use `nhdd_tui.py`.

### Why can a dumped DEX open but still have incomplete code?

NHDD exports according to the DEX `file_size`. If some pages cannot be read, the current implementation keeps the file size and zero-fills missing pages. This helps preserve structure and offsets, but it does not guarantee that every method body is present. Extraction shells may require method-level capture and backfill.

### Why did NHDD find zero DEX files?

Common causes:

- The app is not running or is killed during scanning.
- Your root command does not actually allow reading `/proc/<pid>/mem`.
- The DEX exists only briefly and a single scan missed it.
- The real DEX is in a child process, but you passed a single PID.
- The packer is not a full-resident-DEX model and uses method-level extraction or virtualization.
- **The packer detected `/proc/<pid>/mem` being opened and killed the process.** Use `--stealth2` mode.

Start with package-name watch mode:

```bash
adb shell su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --watch 3 --max-seconds 120'
```

If the app crashes during scanning, try anti-detection mode:

```bash
adb shell kp -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --stealth2 --relaxed --stealth'
```

### Can the Android app module be built directly?

Not in this snapshot. The `app/` module is not included in this repository.

## Project layout

```text
NHDD/
├── nhdd.c                         # Android-side core scanner
├── fix_dex_checksum.py            # Standalone DEX repair tool
├── nhdd_tui.py                    # Recommended TUI controller
├── scripts/
│   ├── build_nhdd_android.sh      # Build Android ARM64 nhdd
│   ├── build_fyne_windows.ps1
│   └── build_fyne_windows_from_linux.sh
├── gui/                           # Go/Wails v2 desktop GUI
└── BUILD_WINDOWS.md               # Windows/Linux GUI build notes
```

## Authors

- **漫宿骄盛**
- **weixiao**

Repository: https://github.com/mansujiaosheng/NHDD

## Authorized use only

This project is intended for:

- Debugging and analyzing your own apps.
- Authorized mobile security testing.
- Malware analysis, packer evaluation, reverse-engineering education, and research.

Do not use this project for unauthorized access, bypassing commercial licensing, stealing code or data, or violating third-party rights. Users are responsible for complying with applicable laws, permissions, and testing boundaries. The authors are not responsible for misuse.

## License

MIT
