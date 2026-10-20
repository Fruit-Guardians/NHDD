<p align="center">
  <img src="./NHDD-cpp-modular/assets/nhdd-mark.svg" alt="NHDD" width="104" height="104">
</p>

<h1 align="center">NHDD</h1>

<p align="center"><strong>No-Hook DEX / SO Dumper</strong></p>

<h3 align="center">Runtime capture. No in-process injection.</h3>

<p align="center">
  A focused DEX / SO extraction tool for rooted Android devices.<br>
  Multi-pass DEX capture. PT_LOAD reconstruction. Event-driven scanning.
</p>

<p align="center">
  <img alt="Android · Root" src="./NHDD-cpp-modular/assets/badges/nhdd-root.svg">
  <img alt="ABI · ARM64 / ARMv7" src="./NHDD-cpp-modular/assets/badges/nhdd-abi.svg">
  <img alt="Capture · No Hook" src="./NHDD-cpp-modular/assets/badges/nhdd-no-hook.svg">
  <img alt="C++ · 17" src="./NHDD-cpp-modular/assets/badges/nhdd-cpp.svg">
</p>

<p align="center">
  <a href="./NHDD-cpp-modular/README.md#快速上手">Quick Start</a> &nbsp;·&nbsp;
  <a href="./NHDD-cpp-modular/README.md#功能介绍">Features</a> &nbsp;·&nbsp;
  <a href="./NHDD-cpp-modular/README.md#常用命令">Usage</a> &nbsp;·&nbsp;
  <a href="./NHDD-cpp-modular/README.md#输出说明">Outputs</a> &nbsp;·&nbsp;
  <a href="./NHDD-cpp-modular/docs/design.md">Design</a> &nbsp;·&nbsp;
  <a href="https://github.com/Fruit-Guardians/NHDD/issues">Issues</a>
</p>

<p align="center"><sub>One binary. No injected agent. For authorized research only.</sub></p>

---

English | [简体中文](./README.zh-CN.md)

> **Current Root CLI:** start with the [C++ tool's feature and usage guide](./NHDD-cpp-modular/README.md) for DEX multi-round capture, PT_LOAD-based SO reconstruction, cold launch/process following, syscall-driven incremental capture, and OAT 279 checks. Its command examples and limits are authoritative for the C++ binary; the controller and legacy workflows below are not a feature-parity guarantee. [Implementation details](./NHDD-cpp-modular/docs/design.md) · [How these badges work](./NHDD-cpp-modular/docs/badges.md).

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
| `NHDD-cpp-modular/` | **Recommended Root CLI** | C++17 standalone binary: multi-round DEX coverage/revisions, PT_LOAD/load-bias ELF32/64 reconstruction, no-hook JNI candidates, cold launch and process following, tracefs/poll incremental capture, and offline DEX/CDEX/VDEX/OAT checks including OAT 279. See its [usage guide](./NHDD-cpp-modular/README.md) for current options and boundaries. |
| `nhdd.c` | Ready (v8 baseline) | Single-file static ARM64 scanner: DEX/SO, package multi-process scanning, snapshots, watch mode, de-duplication, built-in DEX checksum repair, built-in SoFixer-style ELF repair, stealth2 (process_vm_readv), relaxed DEX validation, anonymous mapping scan. |
| `nhdd_tui.py` | Recommended | Terminal controller (v9.0-cpp-class): device/app selection, watch live progress (v8/v9 output formats), result pulling, local DEX/SO repair, APK repack. Best daily entry point. |
| `gui/` | Wails GUI | Go + Wails v2 desktop GUI with Web frontend. No CGO required. Mirrors the TUI flow including built-in DEX/SO repair and APK repack. |
| `fix_dex_checksum.py` / `fix_so.py` | Ready | Standalone repair libraries + CLIs. Their classification semantics (OK / fixed / moved to `bad/`) are deliberately aligned with the Go GUI ports (`gui/dexfix.go`, `gui/sofix.go`) and the on-device C/C++ repair — keep all three in sync when changing repair logic. |

## Features

- **External memory reading**: reads target process memory via `/proc/<pid>/mem` or `process_vm_readv(2)` (stealth2); no target-process injection.
- **DEX dumping**: scans for `dex\n` magic (or `endian_tag` in relaxed mode), reads DEX `file_size`, and exports data page by page.
- **SO dumping**: maps-driven ELF scan (grouped by path+inode), system libraries and non-app objects are skipped by policy, app SOs are dumped and repaired in-process (p_offset alignment, ELF magic restore). An external SoFixer binary is **no longer required** — the repair is built in (GUI/Python ports keep the same semantics; the `third_party/SoFixer` submodule is a legacy/optional dependency).
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
└── Repairs DEX checksums and ELF layout in-process (no external repair step)
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

If SO repair is built in (v8/v9 both repair ELF layout on-device), pushing an external SoFixer is **optional/legacy**. If you still want the external tool:

```bash
adb push ./sofixer /data/local/tmp/sofixer
adb shell chmod 755 /data/local/tmp/sofixer
```

## Build the C++ v9 scanner (recommended device binary)

`NHDD-cpp-modular/` is a class-modular C++17 rewrite of `nhdd.c` with the same scan semantics plus JNIMAP/analyze-so/continuous capabilities. The TUI and GUI prefer its output when present.

```bash
# Auto-discovers NDK and builds (output defaults under NHDD-cpp-modular/)
./scripts/build_nhdd_cpp.sh

# Or with make (single translation unit: src/main.cpp includes all *.hpp)
make android -C NHDD-cpp-modular CXX=/path/to/ndk/.../bin/aarch64-linux-android34-clang++

# Push
make push -C NHDD-cpp-modular   # adb push nhdd /data/local/tmp/nhdd
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

### v9-only options (`NHDD-cpp-modular`, not available in `nhdd.c` v8)

| Option | Description |
|---|---|
| `--jnimap` | No-hook JNI binding scan: externally recovers registered `JNINativeMethod` tables (both `JNI_OnLoad`-registered and static `RegisterNatives` form) and writes `jnimap_<pid>.jsonl` mapping `className + methodName + signature -> fnPtr / SO offset`. |
| `--analyze-so` | One-shot SO analysis mode (dump + deep ELF analysis + JNIMAP targeting the dumped libraries). |
| `--jni-lib NAME` / `--jni-min N` / `--jni-full` / `--jni-max-region N` | Restrict/tune JNI table scanning (target library, minimum entries, full-table mode, region cap). |
| `--fnptrs` | Also record raw function-pointer candidates. |
| `--continuous` | Continuous maps monitoring with timeline output (detects SOs that appear dynamically). |
| `--monitor-duration S` / `--monitor-interval T` / `--monitor-verbose` | Tuning for `--continuous` mode. |
| `--save-maps` | Persist each round's `/proc/<pid>/maps` snapshot for offline diffing. |
| `--target-so PATH` / `--dump-target-so` / `--no-deep-so` | Target specific SO files; control deep ELF handling. |
| `--apk` | APK-aware mode (used by TUI default flow: also pulls the original APK for carrier-based SO repair and repack). |

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
- Dump mode: DEX, SO, ALL, or APK-aware (default `apk`).
- Local output directory.

On-device flow: the TUI pushes the **v9 C++ binary** (`NHDD-cpp-modular` build output) to `/data/local/tmp/nhdd` and falls back to the root `nhdd` (v8) if not found, uses `/data/local/tmp/nhdd_dump` as the device output directory — the same location the raw CLI and the GUI use (the TUI wipes and recreates it via the root command before each run, so the latest run wins) — then pulls with `adb root` when available (fallback: root `chmod`/`chcon`).

After pulling, the TUI automatically repairs results using `fix_dex_checksum.py` / `fix_so.py` (same classification as the GUI), writes a `log.txt`, and can repack the dump into an APK with `scripts/repack_apk_fast.py` (unsigned, jadx-analysis only).

Each TUI run gets an isolated run id. Results are saved under:

```text
nhdd_output/<package>/<YYYYMMDD-HHMMSS>/
├── dex/
├── so/
└── log.txt
```

This keeps repeated tests for the same app from mixing old files into the current run statistics.

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

The GUI searches for the device binary in this order: executable directory → parent directory → `NHDD-cpp-modular/` build output → repository root. The v9 build is preferred when present.

The GUI supports: ADB connection (local or remote `host:port`), app list, root command configuration, dump mode (DEX/SO/ALL), watch mode with live progress, result pulling, built-in DEX/SO repair (`gui/dexfix.go` / `gui/sofix.go`, Go ports of the Python repair semantics), and APK repack (replace `classes*.dex` / SO inside a copy of the original APK, strip old signatures; output is unsigned and intended for static analysis only).

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
├── nhdd.c                         # v8 single-file Android ARM64 scanner (baseline)
├── NHDD-cpp-modular/              # v9 C++17 class-modular scanner (recommended device binary)
│   ├── Makefile                   #   make android / host / push
│   └── src/                       #   main.cpp + *.hpp header modules (scanner, JNIMAP, SO, config…)
├── nhdd_tui.py                    # Recommended host-side controller (rich TUI)
├── fix_dex_checksum.py            # Standalone DEX repair library + CLI
├── fix_so.py                      # Standalone dumped-SO ELF repair library + CLI
├── scripts/
│   ├── build_nhdd_android.py      # Cross-platform v8 builder (auto-discovers NDK)
│   ├── build_nhdd_android.sh/.ps1 # Shell/PowerShell wrappers
│   ├── build_nhdd_cpp.sh          # v9 C++ builder
│   ├── doctor.py                  # Environment health check (make doctor)
│   └── repack_apk_fast.py         # APK repack used by the TUI
├── gui/                           # Go/Wails v2 desktop GUI (+ Vue 3 frontend, Go repair ports)
├── third_party/SoFixer            # Optional legacy submodule (repair is built in now)
└── BUILD_WINDOWS.md               # Windows/Linux GUI build notes
```

## Authors

- **漫宿骄盛**
- **weixiao**

Repository: https://github.com/Fruit-Guardians/NHDD

## Authorized use only

This project is intended for:

- Debugging and analyzing your own apps.
- Authorized mobile security testing.
- Malware analysis, packer evaluation, reverse-engineering education, and research.

Do not use this project for unauthorized access, bypassing commercial licensing, stealing code or data, or violating third-party rights. Users are responsible for complying with applicable laws, permissions, and testing boundaries. The authors are not responsible for misuse.

## License

MIT
