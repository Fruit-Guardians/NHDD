# NHDD — No-Hook DEX/SO Dumper

> An Android DEX / SO memory dumping tool for **authorized security research, reverse engineering, and debugging of your own applications**.
>
> NHDD runs as an independent root process. It scans a target process from the outside via `/proc/<pid>/maps` and `/proc/<pid>/mem`, looking for DEX and ELF data in memory. It does not inject code into the target process and does not install runtime hooks.

English | [简体中文](./README.zh-CN.md)

---

## Important Notice

NHDD should only be used in the following scenarios:

- Devices, applications, and test environments that you own or are explicitly authorized to analyze;
- Mobile application security research, hardening assessment, compatibility analysis, vulnerability reproduction, and defensive validation;
- Internal enterprise security testing or educational lab environments.

Do not use this tool against unauthorized applications, commercial software, copyrighted content, or in any way that violates local laws, platform rules, or contractual terms. The authors are not responsible for unauthorized use, legal consequences, data leakage, business losses, or any other damages.

---

## Overview

Many Android unpacking tools rely on Frida, Xposed, Zygisk, ART hooks, or ClassLoader hooks. These approaches are powerful, but they also introduce detectable artifacts inside the target process, such as injected libraries, modified method entries, suspicious threads, abnormal call stacks, or runtime state changes.

NHDD takes a different approach:

1. It does not enter the target process;
2. It does not modify ART, ClassLoader, or application method entries;
3. It does not inject Frida / Xposed / Zygisk agents;
4. It reads the target process virtual memory externally with root privileges;
5. It scans memory for DEX magic and ELF magic;
6. It dumps matched DEX / SO data to files;
7. It automatically fixes DEX headers, SHA-1 signatures, and Adler32 checksums;
8. It can dump in-memory SO files and work with SoFixer for reconstruction.

NHDD is designed for cases where the real DEX / SO is already decrypted and mapped into memory at runtime. It is not a universal unpacker and does not guarantee complete recovery across all protectors, devices, ROMs, or Android versions.

---

## Tested Environments

NHDD has been tested on:

- OnePlus 9 + LineageOS 21 / Android 14;
- Pixel devices running Android 14;
- Pixel devices running Android 16.

Other devices, ROMs, kernels, root solutions, and Android versions may behave differently. In theory, NHDD can work when the device has usable root privileges and allows reading the target process via `/proc/<pid>/mem`, but compatibility is not guaranteed.

---

## Scope and Limitations

NHDD is suitable when:

- The real DEX / SO appears in memory in plaintext or in a parseable form;
- The corresponding memory pages can be read with root privileges;
- The DEX pages are still resident or readable when dumping;
- The DEX structure is not severely corrupted, or can be repaired later.

NHDD may not fully handle cases where:

- The real code only exists as interpreter-private structures, JIT code, native bridge code, or a custom VM format;
- DEX headers are intentionally damaged, or critical fields such as `file_size`, `map_off`, or `class_data_off` point to invalid regions;
- The protector loads, decrypts, and unloads DEX fragments very quickly;
- The target monitors `/proc` access, suspicious timing, system calls, or process state changes;
- The kernel, SELinux policy, root solution, or ROM restricts cross-process memory reads.

---

## How It Works

### Why many traditional approaches are detectable

| Approach | Common implementation | Possible detection surface |
|----------|-----------------------|-----------------------------|
| Frida | Injects an agent into the target process | Injected libraries, threads, ports, symbols, call stacks, memory artifacts |
| Xposed / LSPosed | Modifies Java / ART call paths | Framework traces, method entry changes, module lists |
| Zygisk modules | Loads modules during Zygote / app lifecycle | Module traces, maps entries, abnormal native stacks |
| FART-style tools | Modify or hook ART internals | ART symbols, entry instructions, system component differences |
| ClassLoader hooks | Intercept DEX loading | Java hooks, native hooks, abnormal call paths |

NHDD does not claim to be “undetectable”. Its advantage is that it avoids installing hooks or injected libraries inside the target process, which reduces common in-process hook / injection detection surfaces. Cross-process memory reading can still be indirectly observed by system policy, behavior monitoring, or anti-debugging logic.

### External memory scanning model

```text
┌─────────────────────────────────────────────────────────┐
│  Target process: protected app                           │
│                                                         │
│  ┌───────────────────────────────────────────────────┐  │
│  │ Protector / packer logic                           │  │
│  │                                                   │  │
│  │ Runtime-decrypted DEX / SO                         │  │
│  │ 0x7f8a001000: "dex\n035\0..."                    │  │
│  │ 0x7f8b200000: "\x7fELF..."                        │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  Inside target: no Frida agent, no Xposed hook,          │
│  no method entry patch                                  │
└─────────────────────────────────────────────────────────┘
                         │
                         │ root process reads /proc/<pid>/mem
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Independent NHDD process                                │
│                                                         │
│  1. Read /proc/<pid>/maps for memory layout              │
│  2. Scan readable memory regions page by page            │
│  3. Match DEX / ELF magic                                │
│  4. Parse headers and size fields                         │
│  5. Dump DEX / SO to output directory                    │
│  6. Fix DEX checksum / signature                          │
│  7. Deduplicate and clean invalid outputs                 │
└─────────────────────────────────────────────────────────┘
```

### Page-by-page scanning

```text
for each readable region in /proc/<pid>/maps:
    for addr in region.start .. region.end step 4096:
        page = pread(mem_fd, 4096, addr)

        if page starts with "dex\n":
            parse DEX header
            validate version, header_size, file_size, endian_tag
            dump DEX
            fix SHA-1 and Adler32

        if page starts with "\x7fELF":
            parse ELF header and program headers
            estimate mapped SO size
            dump SO
```

Advantages of page-by-page scanning:

- Small read size per operation;
- No need to read huge memory regions at once;
- Easier handling of unreadable or sparse pages;
- Better fit for demand-paged and short-lived DEX mappings.

---

## Features

- **Out-of-process scanning**: no injection and no runtime hook inside the target process;
- **DEX dumping**: scans in-memory DEX files and fixes header / SHA-1 / Adler32 automatically;
- **SO dumping**: scans ELF magic and exports decrypted in-memory shared objects;
- **Multi-process support**: scans the main process and `:remote` child processes when a package name is provided;
- **PID mode**: scans a single process when a numeric PID is provided;
- **Snapshot polling**: uses `--snapshot` to scan multiple rounds and catch short-lived DEX mappings;
- **Watch mode**: uses `--watch` to support lazy-loaded or feature-triggered DEX files;
- **Content deduplication**: deduplicates DEX files across processes and rounds based on fixed SHA-1;
- **Output cleanup**: filters obviously small or malformed DEX files;
- **SO repair integration**: can work with `third_party/SoFixer` for post-dump reconstruction;
- **Multiple frontends**: command line, Python controller, TUI, GUI, and Android controller app.

---

## Project Layout

```text
NHDD/
├── nhdd.c              # Core engine, C implementation, statically built for Android ARM64
├── Makefile            # Build configuration
├── nhdd_ctrl.py        # PC-side Python controller
├── nhdd_tui.py         # Terminal TUI with rich output and watch progress
├── fix_dex_checksum.py # Standalone DEX checksum fixer
├── nhddctl.sh          # Shell controller script
├── gui/                # Desktop GUI, implemented with Go / Fyne
│   ├── main.go
│   ├── adb.go
│   └── dexfix.go
├── app/                # Android controller app, Java / libsu
│   └── src/main/
│       ├── AndroidManifest.xml
│       └── java/com/nhdd/app/MainActivity.java
└── third_party/
    └── SoFixer/        # SO reconstruction tool
```

---

## Build

### 1. Build the core `nhdd` binary

Android NDK r25 or later is required.

```bash
export NDK=/path/to/android-ndk-r27
export CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang

$CC -O2 -static -o nhdd nhdd.c
```

Or use the Makefile:

```bash
make
```

### 2. Build the desktop GUI

Go 1.21+ and Fyne dependencies are required.

```bash
cd gui
go build -o nhdd-gui .
```

### 3. Build the Android controller app

Android SDK and JDK 17+ are required.

```bash
./gradlew assembleDebug
```

Or use the project script:

```bash
./build_manual.sh
```

---

## Usage

### Option 1: ADB command line

#### 1. Push the binary

```bash
adb push nhdd /data/local/tmp/nhdd
adb shell chmod 755 /data/local/tmp/nhdd
```

#### 2. Launch the target app

```bash
adb shell monkey -p com.example.app -c android.intent.category.LAUNCHER 1
```

#### 3. Basic DEX dump

```bash
adb shell "/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump"
```

Output layout:

```text
/data/local/tmp/nhdd_dump/
├── dex/
│   ├── *.dex
│   └── ...
└── so/
    ├── *.so
    └── ...
```

#### 4. Snapshot polling mode

Useful when DEX files only appear in memory for a short time.

```bash
adb shell "monkey -p com.example.app -c android.intent.category.LAUNCHER 1 ; \
           /data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump \
           --snapshot 5 --interval 1"
```

Parameters:

- `--snapshot 5`: scan 5 rounds;
- `--interval 1`: wait 1 second between rounds;
- the process list is resolved again in every round;
- useful when main and child processes change frequently.

#### 5. Watch mode

Useful for applications that lazy-load DEX files only after specific features are opened.

```bash
adb shell "monkey -p com.example.app -c android.intent.category.LAUNCHER 1 ; \
           /data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --watch"
```

Recommended workflow:

1. Start `--watch`;
2. Open important feature pages on the device, such as login, home, payment, settings, WebView, IM, or media playback;
3. NHDD captures newly appeared DEX files in each scan round;
4. It stops automatically after several rounds with no new results.

Optional parameters:

```bash
--watch [K]          # stop after K consecutive rounds with no new results, default 3
--max-rounds N       # maximum scan rounds, default 60
--max-seconds N      # maximum running time in seconds, default 120
--interval SECS      # interval between rounds, default 1
```

#### 6. Dump SO files

```bash
adb shell "/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --so"
```

#### 7. Dump both DEX and SO files

```bash
adb shell "/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --all"
```

#### 8. Pull results

```bash
adb pull /data/local/tmp/nhdd_dump ./output
```

---

## Python Controller

```bash
python3 nhdd_ctrl.py
python3 nhdd_ctrl.py com.example.app
```

The controller usually handles:

1. Checking ADB connectivity;
2. Pushing `nhdd` to the device;
3. Launching or restarting the target app;
4. Running the dump command;
5. Pulling results to the host;
6. Fixing or cleaning output files.

---

## Terminal TUI

```bash
python3 nhdd_tui.py
```

This is useful when you want to observe scan rounds, hit counts, and output paths in real time.

---

## Desktop GUI

```bash
cd gui
./nhdd-gui
```

Typical workflow:

1. Enter or select an ADB device;
2. Select the target package name;
3. Choose DEX / SO / ALL mode;
4. Click DUMP;
5. Wait for results to be pulled to the host.

---

## Common Options

| Option | Description |
|--------|-------------|
| `<package>` | Target package name. Scans all matching processes. |
| `<pid>` | Target PID. Scans only that process. |
| `<out_dir>` | Output directory on the device. |
| `--dex` | Dump DEX only. |
| `--so` | Dump SO only. |
| `--all` | Dump both DEX and SO. |
| `--snapshot N` | Scan N rounds and exit. |
| `--interval SECS` | Interval between scan rounds. |
| `--watch [K]` | Keep scanning and stop after K rounds with no new results. |
| `--max-rounds N` | Maximum rounds in watch mode. |
| `--max-seconds N` | Maximum running time in watch mode. |
| `--stealth` | Add a default delay between memory regions to reduce abrupt scan behavior. |
| `--region-delay MS` | Customize delay between memory regions. |

---

## DEX Fixing

Relevant DEX header fields:

```text
0x08    Adler32 checksum    covers 0x0C to EOF
0x0C    SHA-1 signature     covers 0x20 to EOF
0x20    file_size
0x24    header_size
0x28    endian_tag
```

NHDD fixes DEX files in this order:

1. Set `header_size` to `0x70`;
2. Set `endian_tag` to `0x12345678`;
3. Set `file_size` to the actual dumped size;
4. Recalculate the SHA-1 signature;
5. Recalculate the Adler32 checksum.

The order matters because the Adler32 range includes the SHA-1 signature.

You can also run the fixer manually:

```bash
python3 fix_dex_checksum.py classes.dex
```

---

## FAQ

### Q: No DEX files were dumped. What should I check?

Check the following first:

1. Whether the target app was launched successfully;
2. Whether the device has usable root privileges;
3. Whether `/proc/<pid>/mem` is readable;
4. Whether the real DEX exists only in a child process;
5. Whether the DEX is loaded and then quickly unloaded;
6. Whether a specific feature page must be opened to trigger lazy loading;
7. Whether `--snapshot` or `--watch` should be used.

Recommended command:

```bash
adb shell "monkey -p com.example.app -c android.intent.category.LAUNCHER 1 ; \
           /data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump \
           --snapshot 8 --interval 1"
```

### Q: jadx cannot open the dumped DEX. Why?

Possible reasons:

- The DEX pages were incomplete during dumping;
- The header was damaged by the protector;
- fields such as `map_off`, `class_data_off`, or `string_ids_off` point to invalid regions;
- the dumped file is only a stub DEX, while the real code is in another dynamically loaded DEX;
- the file needs deeper DEX repair, not only checksum fixing.

Try first:

```bash
python3 fix_dex_checksum.py your.dex
```

### Q: Why is package-name mode recommended over PID mode?

Many apps run multiple processes, for example:

```text
com.example.app
com.example.app:remote
com.example.app:push
com.example.app:worker
```

The decrypted DEX is not always in the main process. When a package name is provided, NHDD scans all matching processes. When a PID is provided, it only scans that single process.

### Q: Do I need to wait exactly 4 seconds after launch?

Relying on a fixed delay is not recommended. Loading timing varies across protectors, devices, and launch paths. Older workflows often used “dump 3–5 seconds after launch” as a rule of thumb, but the recommended approaches are now:

- `--snapshot`: covers a short time window;
- `--watch`: covers lazy-loaded scenarios;
- manually open important feature pages to bring lazy-loaded DEX files into memory.

### Q: Does it work with APatch, Magisk, or KernelSU?

It depends on the root shell permissions, mount namespace, SELinux policy, and ROM restrictions. If the Android controller app cannot access `/data/local/tmp/nhdd`, use ADB instead:

```bash
adb shell su -c "/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --watch"
```

### Q: Can NHDD replace FART?

Not directly. They target different layers:

- NHDD is good at scanning DEX / SO files that are already present in memory;
- FART-style tools are better at collecting fine-grained information during ART method loading, resolution, and invocation;
- protectors based on method-level extraction, dynamic restoration, interpreter-private structures, or heavily damaged DEX layouts may require CodeItem dumping, DEX repair, ART hooks, or other analysis techniques.

---

## Test Report Template

To avoid exposing unnecessary third-party application information in the README, use a generic template in issues or reports:

| Sample type | Protection type | DEX count | SO count | jadx readable | Core logic visible | Notes |
|-------------|-----------------|-----------|----------|---------------|--------------------|-------|
| Authorized sample A | Commercial protector / extraction shell | 76 | 4 | Yes | Yes | Needs watch mode and feature-page triggering |
| Authorized sample B | Custom protection | 28 | 1 | Yes | Partial | Needs further DEX repair |
| Authorized sample C | Hotfix / plugin framework | 79 | 0 | Yes | Yes | Hit in multiple processes |

---

## Positioning Compared with Common Approaches

| Dimension | NHDD | Frida-dexdump | FART-style tools | fdex2 / ClassLoader hooks |
|----------|------|---------------|------------------|---------------------------|
| Core method | External memory read | Target-process injection | ART modification / hook | ClassLoader hook |
| Enters target process | No | Yes | Yes | Yes |
| Requires root | Yes | Usually | Usually | Usually |
| DEX dump | Yes | Yes | Yes | Yes |
| SO dump | Yes | Usually no | Usually no | Usually no |
| Lazy-load support | Watch mode | Depends on script | Strong | Depends on hook point |
| In-process detection surface | Low | High | Medium to high | High |
| Dependence on DEX repair | Medium | Medium | Low to medium | Medium |

This table describes technical positioning only. It is not a guarantee of stable bypass capability against any specific protector.

---

## Roadmap

- [ ] Improve DEX structure validation and corrupted-field diagnostics;
- [ ] Generate more complete scan reports;
- [ ] Add DEX coverage statistics;
- [ ] Improve automatic SO reconstruction after dumping;
- [ ] Test more Android versions and root solutions;
- [ ] Improve GUI / TUI device selection and log rendering;
- [ ] Add more fine-grained failure reason classification.

---

## License

MIT License

---

## Authors

- Authors: mansujiaosheng, weixiao
- GitHub: `https://github.com/mansujiaosheng/NHDD`

