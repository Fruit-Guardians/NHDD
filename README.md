<p align="center"><img src="./NHDD-cpp-modular/assets/nhdd-mark.svg" alt="NHDD" width="96"></p>
<h1 align="center">NHDD</h1>
<p align="center"><strong>Runtime DEX / SO capture for rooted Android. No in-process injection.</strong></p>
<p align="center">
  <img alt="Android · Root" src="./NHDD-cpp-modular/assets/badges/nhdd-root.svg">
  <img alt="ARM64 / ARMv7" src="./NHDD-cpp-modular/assets/badges/nhdd-abi.svg">
  <img alt="No Hook" src="./NHDD-cpp-modular/assets/badges/nhdd-no-hook.svg">
  <img alt="C++17" src="./NHDD-cpp-modular/assets/badges/nhdd-cpp.svg">
</p>

<p align="center">
  <a href="https://github.com/Fruit-Guardians/NHDD/releases/latest">Download</a> ·
  <a href="./NHDD-cpp-modular/README.md">Usage</a> ·
  <a href="./NHDD-cpp-modular/docs/design.md">Design</a> ·
  <a href="./README.zh-CN.md">简体中文</a>
</p>

## What it does

- Captures resident DEX across rounds, with coverage, holes and content revisions.
- Discovers DEX through supported ART object layouts; safely combines short-lived method windows with provenance and conflict detection.
- Reconstructs ELF32/64 SO files using PT_LOAD and load bias.
- Supports cold launch, package process following, tracefs events and incremental maps scanning.
- Preserves CompactDex / VDEX / OAT evidence, including OAT 279; provides offline structural checks.
- Offers a standalone Android CLI, a Python TUI and a Windows desktop GUI. Controllers do not expose every advanced CLI option.

## Quick start

Download the matching package from Releases and check SHA256SUMS.txt. The main device target is ARM64, built for API 34+. ADB, Root and permission to read the target process are required.

~~~bash
adb shell "su -c id"
adb push nhdd /data/local/tmp/nhdd
adb shell chmod 755 /data/local/tmp/nhdd
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_run01 --all --watch 3'"
adb pull /data/local/tmp/nhdd_run01 ./nhdd_run01
~~~

Replace com.example.app with your own or explicitly authorized app. Use a fresh output directory: default runs may clear earlier artifacts. See the [full guide](./NHDD-cpp-modular/README.md) for ART, spawn, event modes and output semantics.

## Interface

### Windows GUI

![NHDD desktop GUI](./NHDD-cpp-modular/assets/screenshots/gui.png)

Built GUI frontend in a browser preview, before connecting a device; no private device identifiers or dumps are shown. This does not substitute for native WebView2 testing.

### Python TUI

![NHDD TUI live progress dashboard](./NHDD-cpp-modular/assets/screenshots/tui.svg)

App selection → configuration → live watch dashboard → results. Install rich and run `python nhdd_tui.py`, or select a target directly with `python nhdd_tui.py com.example.app`.

<details>
<summary>App selection and configuration</summary>

![NHDD TUI app selection and configuration](./NHDD-cpp-modular/assets/screenshots/tui-setup.svg)
</details>

Both TUI views use the real Rich UI functions with synthetic packages, input and logs—not Root device results. Reproduce them with `python scripts/capture_tui.py`.

## Architecture

~~~mermaid
flowchart LR
  UI["TUI / GUI"] -->|"ADB + su"| CLI["Root C++ CLI"]
  CLI --> CAP["Fast capture / DEX-SO-JNI scans"]
  APP["App memory / ART"] -->|"External reads"| CAP
  EV["tracefs / maps diff"] --> CAP
  CAP --> CHECK["Identity / coverage / format checks"]
  CHECK --> REC["PT_LOAD rebuild / safe ART merge"]
  REC --> OUT["DEX / SO / metadata / timeline"]
~~~

The scanner runs outside the target app. Checks are path-specific; recovered method composites are recorded as cross-time evidence, not atomic snapshots. [Implementation and safety boundaries](./NHDD-cpp-modular/docs/design.md).

## Packages and documentation

| Component | Start here |
|---|---|
| Android CLI | [Features, commands and outputs](./NHDD-cpp-modular/README.md) |
| Python TUI | Install Python 3.10+ and rich; run nhdd_tui.py |
| Windows GUI | ADB + WebView2 Runtime; keep the bundled Android engine beside the EXE |
| Build / security | [Build notes](./BUILD_WINDOWS.md) · [Dependency audit](./NHDD-cpp-modular/docs/dependency-security.md) |

ARMv7 is cross-compiled only; 16KiB-page devices are not validated. ART recovery requires a supported Build ID, and short windows can still be missed. No-hook is not undetectable; structural validity is not proof of decrypted methods or a runnable APK.

[MIT](./LICENSE). Third-party notices are preserved. Project: [Fruit-Guardians/NHDD](https://github.com/Fruit-Guardians/NHDD). Authorized research and your own apps only.
