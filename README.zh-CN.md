<p align="center">
  <img src="./NHDD-cpp-modular/assets/nhdd-mark.svg" alt="NHDD" width="104" height="104">
</p>

<h1 align="center">NHDD</h1>

<p align="center"><strong>No-Hook DEX / SO Dumper</strong></p>

<h3 align="center">运行时提取，不向进程注入。</h3>

<p align="center">
  面向 Android Root 的 DEX / SO 提取工具。<br>
  多轮捕获 DEX，按段重建 SO，持续跟随运行时变化。
</p>

<p align="center">
  <img alt="Android · Root" src="./NHDD-cpp-modular/assets/badges/nhdd-root.svg">
  <img alt="ABI · ARM64 / ARMv7" src="./NHDD-cpp-modular/assets/badges/nhdd-abi.svg">
  <img alt="Capture · No Hook" src="./NHDD-cpp-modular/assets/badges/nhdd-no-hook.svg">
  <img alt="C++ · 17" src="./NHDD-cpp-modular/assets/badges/nhdd-cpp.svg">
</p>

<p align="center">
  <a href="https://github.com/Fruit-Guardians/NHDD/releases/tag/v9.0.0">下载 v9.0.0</a> &nbsp;·&nbsp;
  <a href="./NHDD-cpp-modular/README.md#快速上手">快速上手</a> &nbsp;·&nbsp;
  <a href="./NHDD-cpp-modular/README.md#功能介绍">功能介绍</a> &nbsp;·&nbsp;
  <a href="./NHDD-cpp-modular/README.md#常用命令">使用说明</a> &nbsp;·&nbsp;
  <a href="./NHDD-cpp-modular/README.md#输出说明">产物说明</a> &nbsp;·&nbsp;
  <a href="./NHDD-cpp-modular/docs/design.md">技术设计</a> &nbsp;·&nbsp;
  <a href="https://github.com/Fruit-Guardians/NHDD/issues">问题反馈</a>
</p>

<p align="center"><sub>一个二进制，无需注入 Agent。仅用于自有或已获授权的应用。</sub></p>

---

> 当前 Root CLI 的功能、安装、冷启动捕获、参数与输出说明，请优先阅读 [C++ 工具使用指南](./NHDD-cpp-modular/README.md)。该指南覆盖多轮 DEX 合并、PT_LOAD SO 重建、事件驱动捕获及 OAT 279 检查；下文旧版与控制端工作流不代表所有组件功能一致。[技术设计](./NHDD-cpp-modular/docs/design.md) · [README 徽章制作](./NHDD-cpp-modular/docs/badges.md)。

NHDD 是一个面向 Android 逆向分析与授权安全研究的 **外部内存 DEX/SO Dump 工具**。它的核心程序 `nhdd` 以独立 root 进程运行，通过读取目标进程的 `/proc/<pid>/maps` 和 `/proc/<pid>/mem`（或使用 `process_vm_readv` 的 stealth2 模式），在内存中扫描 DEX/ELF magic，并将已加载到内存中的 DEX 或 SO 导出到文件。

和 Frida/Xposed/FART/fdex2 这类"进程内 Hook/注入"路线不同，NHDD 的核心思路是：**不向目标 App 注入代码，不修改目标进程方法入口，不依赖 ART Hook**。这可以显著降低由进程内 Hook、注入库、异常线程名、方法入口跳转等特征带来的暴露面。

> 重要说明：No-Hook 不等于"绝对无法检测"。目标 App、系统策略或加固方案仍可能通过进程状态变化、外部访问副作用、root 环境、SELinux 策略、进程被杀等方式影响结果。NHDD 的优势是低侵入、外部读取、部署简单，而不是承诺零风险或万能脱壳。

## 适用范围

适合：

- 运行时会把完整或接近完整 DEX 放入内存的一代壳、普通加固壳、热修复/插件化加载场景。
- 需要快速从真机 root 环境中批量扫描 DEX/SO 的逆向分析流程。
- 不希望在目标进程内加载 Frida agent、Xposed 模块或修改 ART 的场景。

不适合单独解决：

- 只在方法调用时临时解密 CodeItem 的二代抽取壳。
- DEX 结构存在大量空洞、方法体被擦除、仅动态恢复指令的场景。
- 需要完整方法体回填、ClassLinker/LoadMethod 级别采集的场景。

对于二代抽取壳，建议使用 `--stealth2 --relaxed` 模式。`--stealth2` 使用 `process_vm_readv(2)` 替代打开 `/proc/<pid>/mem`，避免壳通过监控文件描述符检测到内存访问；`--relaxed` 通过 `endian_tag` (0x12345678) 和 header 结构验证 DEX，不依赖被壳抹除的 `dex\n` magic。完整方法体恢复通常还需要 DefineClass、LoadMethod、CodeItem backfill 或 FART 类流水线配合。

## 当前仓库状态

| 模块 | 状态 | 说明 |
|---|---|---|
| `NHDD-cpp-modular/` | **v9,推荐设备端二进制** | `nhdd.c` 的 C++17 类模块化重写(v9.0-cpp-class)。保留 v8 全部扫描语义(stealth2/relaxed/anon/watch),新增无 Hook **JNIMAP 扫描**(`--jnimap`,外部还原 `JNINativeMethod` 注册表,输出 `jnimap_<pid>.jsonl`)、`--analyze-so` 一键分析、`--continuous` maps 持续监控。TUI/GUI 推送时优先使用其构建产物,找不到才回退根目录 `nhdd`(v8)。 |
| `nhdd.c` | 可用(v8 基线) | 单文件静态 ARM64 扫描器:支持 DEX/SO、包名多进程、快照、watch、去重、内置 DEX 校验修复、内置 SoFixer 风格 ELF 修复、stealth2 (process_vm_readv)、relaxed DEX 验证、匿名映射扫描。 |
| `nhdd_tui.py` | 推荐 | 终端控制器(v9.0-cpp-class):设备/应用选择、watch 实时进度(兼容 v8/v9 两代输出)、结果拉取、本地 DEX/SO 修复、APK 重打包。当前最适合作为日常入口。 |
| `gui/` | Wails GUI | Go + Wails v2 桌面 GUI,Web 前端,不需要 CGO。复刻 TUI 全流程,含内建 DEX/SO 修复与 APK 重打包。 |
| `fix_dex_checksum.py` / `fix_so.py` | 可用 | 独立修复库 + CLI。分类口径(OK / 已修复 / 移入 `bad/`)与 GUI 的 Go 端口(`gui/dexfix.go`、`gui/sofix.go`)及设备端 C/C++ 修复**刻意保持对齐**——修改任一处修复语义时必须同步其余两处。 |

## 核心特性

- **外部读取**：通过 `/proc/<pid>/mem` 或 `process_vm_readv(2)` (stealth2) 读取目标虚拟地址空间，不注入目标进程。
- **DEX dump**：扫描 `dex\n` magic（或 relaxed 模式下的 endian_tag），读取 header 中的 `file_size` 并按页导出。
- **SO dump**：基于 maps 的 ELF 扫描(按 path+inode 聚合)，按策略自动跳过系统库与非 App 对象；App SO 导出后由内置逻辑完成修复(p_offset 对齐、补回 ELF magic)。**不再需要外部 SoFixer 二进制**——修复已内建(v8/v9 及 GUI/Python 端口口径一致)，`third_party/SoFixer` submodule 属于遗留/可选依赖。
- **包名多进程扫描**：传入包名时，会扫描所有 cmdline 匹配的进程，包括 `:remote` 等子进程。
- **快照轮询**：`--snapshot N --interval T` 多轮扫描，适合捕获短暂存在的 DEX。
- **watch 模式**：`--watch [K]` 持续扫描，连续 K 轮没有新 DEX 后停止，适合手动点开功能页捕获 lazy-load DEX。
- **内容去重**：DEX 按重算后的 SHA-1 signature 去重，跨进程、跨轮次重复命中不会重复写入。
- **DEX 自动修复**：修复 `file_size`、`header_size`、`endian_tag`、SHA-1 signature 和 Adler32 checksum。
- **输出隔离**：默认清理旧的 `.dex/.so` 输出，避免多次运行结果混在一起；可用 `--keep` 保留。
- **低侵入运行选项**：`--region-delay`、`--stealth`、`--stealth2`、`--relaxed`、`--anon`、`--name` 可调整扫描节奏、内存访问方式、DEX 验证策略和自身进程名，但不保证规避所有检测。

## 原理概览

```text
目标 App 进程
├── 壳/加固逻辑
├── ART/ClassLoader
├── 已加载的 DEX 内存区域
└── 已加载的 SO 映射区域

独立 root 进程：nhdd
├── 读取 /proc/<pid>/maps 获取可读内存区间
├── 打开 /proc/<pid>/mem  (默认模式)
│   或使用 process_vm_readv(2)  (--stealth2 模式，不打开 fd)
├── 按页扫描 DEX/ELF magic
│   或扫描 endian_tag 0x12345678  (--relaxed 模式)
├── 根据 DEX header 或 ELF program header 计算导出范围
├── 写入 out_dir/dex 或 out_dir/so
└── 修复 DEX header/checksum 与 ELF 布局(全部内建,无外部修复步骤)
```

关键点：`pread(/proc/<pid>/mem, ..., virtual_address)` 的 offset 是目标进程虚拟地址。只要 root/系统策略允许读取，就可以从外部读取目标进程地址空间中的内容。

## 构建 Android 端 `nhdd`

要求：Android NDK r25+，目标设备为 ARM64。

```bash
# 推荐：跨平台 Python 构建入口（Windows/macOS/Linux）
python3 scripts/build_nhdd_android.py

# 指定 NDK / API / 输出路径
python3 scripts/build_nhdd_android.py --ndk /path/to/android-ndk-r27 --api 34 --out nhdd

# macOS / Linux shell 包装
NDK=/path/to/android-ndk-r27 API=34 ./scripts/build_nhdd_android.sh

# Windows PowerShell 包装
powershell -ExecutionPolicy Bypass -File scripts/build_nhdd_android.ps1 -Ndk C:\Android\android-ndk-r27

# 或手动编译
/path/to/android-ndk-r27/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang \
  -O2 -static -Wall -Wextra -o nhdd nhdd.c
```

推送到设备：

```bash
adb push ./nhdd /data/local/tmp/nhdd
adb shell chmod 755 /data/local/tmp/nhdd
```

SO 修复已由扫描器内建完成(v8/v9 均在设备端直接修复 ELF 布局),推送外部 SoFixer 属于**可选/遗留**方案:

```bash
adb push ./sofixer /data/local/tmp/sofixer
adb shell chmod 755 /data/local/tmp/sofixer
```

## 构建 C++ v9 扫描器(推荐设备端二进制)

`NHDD-cpp-modular/` 是 `nhdd.c` 的 C++17 类模块化重写,扫描语义一致,并新增 JNIMAP / analyze-so / continuous 能力。TUI 与 GUI 在存在其产物时优先使用。

```bash
# 自动发现 NDK 并构建(输出默认位于 NHDD-cpp-modular/ 下)
./scripts/build_nhdd_cpp.sh

# 或使用 make(单翻译单元:src/main.cpp include 全部 *.hpp)
make android -C NHDD-cpp-modular CXX=/path/to/ndk/.../bin/aarch64-linux-android34-clang++

# 推送到设备
make push -C NHDD-cpp-modular   # adb push nhdd /data/local/tmp/nhdd
```

## 环境诊断（doctor）

首次使用或换机器后，建议先跑：

```bash
make doctor
```

doctor 会检查：

- 本地依赖：`adb`、`sdkmanager`、Android NDK、Node/npm、Wails、Python rich、前端依赖、SoFixer submodule。
- 设备状态：是否有已授权 Android 设备连接。
- root 命令：自动尝试 `su -c`、`kp -c`、`ksud -c`，也可以手动指定。
- 设备端二进制：检查 `/data/local/tmp/nhdd` 是否存在，并拉回本地验证是否为 ELF64 AArch64。

常用覆盖参数：

```bash
make doctor NDK_PATH="$ANDROID_HOME/ndk/27.2.12479018"
make doctor SU_CMD="kp -c"
make doctor ADB=/path/to/adb HOST_PORT=192.168.238.1:5037 SU_CMD="ksud -c"
python3 scripts/doctor.py --ndk /path/to/android-ndk-r27 --su-cmd "su -c"
```

如果某项失败，doctor 会在 `fix:` 行给出对应修复命令，例如安装 NDK、初始化 submodule、连接设备、重新 `make android push`。

## 命令行使用

### 1. 推荐：扫已运行 App + watch

先手动打开目标 App，让它进入稳定运行状态，然后执行：

```bash
adb shell su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --watch 3 --max-seconds 120'
```

运行过程中，在手机上手动进入登录、首页、搜索、个人中心、支付/订单等功能页。按需加载的 DEX 进入内存后会被 watch 模式捕获。

拉取结果：

```bash
adb pull /data/local/tmp/nhdd_dump ./nhdd_output/com.example.app
```

输出结构：

```text
nhdd_dump/
├── dex/
│   ├── dump_<pid>_1.dex
│   └── dump_<pid>_2.dex
└── so/
    ├── libxxx.so
    └── libyyy.so
```

### 2. 冷启动后固定等待扫描

```bash
adb shell am force-stop com.example.app
adb shell monkey -p com.example.app -c android.intent.category.LAUNCHER 1
sleep 4
adb shell su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --dex'
```

固定等待适合简单场景，但对强对抗壳不一定稳定。很多时候"扫已运行进程 + watch"比"强制重启 + 等 4 秒"更稳。

### 3. 快照轮询

```bash
adb shell su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --snapshot 5 --interval 1'
```

表示扫描 5 轮，每轮间隔 1 秒。

### 4. 同时导出 DEX 和 SO

```bash
adb shell su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --all'
```

### 5. KernelSU / APatch / 其他 root 命令

不同 root 方案的命令可能不同：

```bash
adb shell su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --watch'
adb shell ksud -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --watch'
adb shell kp -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --watch'
```

### 6. 二代抽取壳（反检测模式）

对于检测 `/proc/<pid>/mem` 被打开后杀死进程的壳，使用 `--stealth2` 通过 `process_vm_readv(2)` 读取内存，不需要打开 mem 文件。配合 `--relaxed` 处理壳抹除 DEX magic 的情况：

```bash
adb shell kp -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --stealth2 --relaxed --stealth'
```

- `--stealth2`：使用 `process_vm_readv(2)` 替代打开 `/proc/<pid>/mem`，不创建文件描述符，壳更难检测到内存访问。
- `--relaxed`：通过 `endian_tag` (0x12345678) 和 header 结构验证 DEX，不依赖被壳抹除的 `dex\n` magic。
- `--anon`：仅扫描匿名内存映射（跳过有文件路径的映射），适用于 DEX 被加载到匿名 mmap 区域的场景。
- `--stealth`：添加区域间延时和伪装扫描器进程名。

**技巧**：对于强对抗壳，扫描单个 PID 而非包名可以缩小检测窗口：

```bash
adb shell kp -c '/data/local/tmp/nhdd 12345 /data/local/tmp/nhdd_dump --stealth2 --relaxed --stealth'
```

## `nhdd` 参数

| 参数 | 说明 |
|---|---|
| `<pid\|package>` | 数字 PID 表示只扫单进程；包名表示扫描所有匹配进程。 |
| `[output_dir]` | 输出目录，默认 `/data/local/tmp/nhdd_dump`。 |
| `--dex` | 只导出 DEX，默认模式。 |
| `--so` | 只导出 SO。 |
| `--all` | 同时导出 DEX 和 SO。 |
| `--snapshot N` | 固定扫描 N 轮。 |
| `--interval T` | 每轮间隔秒数，默认 1。 |
| `--watch [K]` | 持续扫描，连续 K 轮无新增 DEX 后停止，默认 K=3。 |
| `--max-rounds N` | watch 最大轮数，默认 60。 |
| `--max-seconds S` | watch 最大运行秒数，默认 120。 |
| `--keep` | 不清理输出目录中旧的 `.dex/.so`。 |
| `--stealth` | 启用默认区域延时，并使用默认伪装进程名。 |
| `--stealth2` | 使用 `process_vm_readv(2)` 替代打开 `/proc/<pid>/mem`，避免壳通过 FD 检测到内存访问。二代壳推荐。 |
| `--relaxed` | 通过 `endian_tag` (0x12345678) 和 header 结构验证 DEX，不依赖被壳抹除的 `dex\n` magic。 |
| `--anon` | 仅扫描匿名内存映射（跳过有文件路径的映射）。 |
| `--region-delay MS` | 每个 maps 区域之间延迟 MS 毫秒。 |
| `--name NAME` / `--disguise NAME` | 修改自身 `/proc/self/comm` 和 `/proc/self/cmdline` 展示名。 |

### v9 专属参数(仅 `NHDD-cpp-modular`,v8 `nhdd.c` 不支持)

| 参数 | 说明 |
|---|---|
| `--jnimap` | 无 Hook JNI 绑定扫描:从外部还原已注册的 `JNINativeMethod` 表(`JNI_OnLoad` 注册与静态 `RegisterNatives` 两种形态),输出 `jnimap_<pid>.jsonl`,映射 `className + methodName + signature -> fnPtr / SO offset`。 |
| `--analyze-so` | 一键 SO 分析模式(dump + 深度 ELF 分析 + 对导出的库做 JNIMAP 定位)。 |
| `--jni-lib NAME` / `--jni-min N` / `--jni-full` / `--jni-max-region N` | 限定/调优 JNI 扫描(目标库、最少条目数、全表模式、区域上限)。 |
| `--fnptrs` | 额外记录原始函数指针候选。 |
| `--continuous` | maps 持续监控 + timeline 输出,捕获动态加载的 SO。 |
| `--monitor-duration S` / `--monitor-interval T` / `--monitor-verbose` | `--continuous` 模式调优参数。 |
| `--save-maps` | 每轮保存 `/proc/<pid>/maps` 快照,供离线对比。 |
| `--target-so PATH` / `--dump-target-so` / `--no-deep-so` | 指定目标 SO;控制深度 ELF 处理行为。 |
| `--apk` | APK 感知模式(TUI 默认流程使用:同时拉取原始 APK,供 carrier 方式 SO 修复与重打包)。 |

## TUI 使用方式（推荐）

安装依赖：

```bash
python3 -m pip install rich
```

运行：

```bash
python3 nhdd_tui.py
python3 nhdd_tui.py com.example.app -o ./nhdd_output
```

如果 ADB server 在宿主机或远程机器上：

```bash
NHDD_ADB='adb -H 192.168.238.1 -P 5037' python3 nhdd_tui.py com.example.app -o ./nhdd_output
```

TUI 会提示：

- 是否重启 App。
- 是否启用 watch。
- root 命令使用 `su -c`、`kp -c`、`ksud -c` 还是留空。
- dump 模式选择 DEX、SO 或 ALL。
- 本地输出目录。

设备端流程：TUI 会优先把 **v9 C++ 版二进制**（`NHDD-cpp-modular` 构建产物）推送到 `/data/local/tmp/nhdd`，找不到才回退根目录的 v8 `nhdd`；设备端输出目录统一为 `/data/local/tmp/nhdd_dump`（与命令行默认值和 GUI 相同），TUI 每次运行前用 root 命令清理重建该目录，即“最近一次运行优先”；拉取时优先 `adb root`，不可用则回退 root `chmod`/`chcon`。

拉取后 TUI 会自动用 `fix_dex_checksum.py` / `fix_so.py` 修复结果（分类口径与 GUI 一致），写入 `log.txt`，并可用 `scripts/repack_apk_fast.py` 把 dump 重打包进 APK（不签名，仅供 jadx 静态分析）。

TUI 每次运行都会生成独立 run id，结果保存到：

```text
nhdd_output/<package>/<YYYYMMDD-HHMMSS>/
├── dex/
├── so/
└── log.txt
```

这样重复测试同一个 App 时不会把旧结果混入本次统计。

## 桌面 GUI 使用方式

桌面 GUI 基于 Go + Wails v2，提供原生窗口 + Web 前端，不需要 CGO 或 GCC。

构建：

```bash
cd gui
wails build
```

运行时把 Android ARM64 版 `nhdd` 放在 GUI 可执行文件同目录：

```text
NHDD-run/
├── nhdd-gui.exe
└── nhdd
```

GUI 支持：ADB 连接（本机或远程 `host:port`）、应用列表、root 命令配置、dump 模式（DEX/SO/ALL）、watch 实时进度、结果拉取、内建 DEX/SO 修复（`gui/dexfix.go` / `gui/sofix.go`，与 Python 修复口径一致的 Go 端口）、APK 重打包（在原 APK 副本中替换 `classes*.dex` / SO、剥离旧签名；产物不签名，仅供静态分析）。GUI 查找设备端二进制的顺序：可执行文件同目录 → 上级目录 → `NHDD-cpp-modular/` 构建产物 → 仓库根目录；存在 v9 产物时优先使用。

## 独立修复 DEX

`nhdd` 已经内置 DEX 修复。如果需要对已有 dump 文件重新修复：

```bash
python3 fix_dex_checksum.py path/to/classes.dex
```

修复内容包括：

1. `header_size -> 0x70`
2. `endian_tag -> 0x12345678`
3. `file_size -> 实际文件长度`
4. SHA-1 signature，覆盖 `data[0x20:]`
5. Adler32 checksum，覆盖 `data[0x0c:]`

## 常见问题

### 1. 为什么传包名比传 PID 更推荐？

很多 App 会有多个进程，真实解密后的 DEX 可能在 `:remote`、`:push`、`:sandbox` 等子进程里。传包名时，`nhdd` 会根据 `/proc/*/cmdline` 匹配所有相关进程；传单个 PID 只会扫描一个进程，容易漏。

### 2. 为什么 GUI 结果比命令行/TUI 少？

GUI 在某些场景下可能使用固定等待流程。遇到多进程壳或 lazy-load 场景，建议用：

```bash
adb shell su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --watch'
```

或直接使用 `nhdd_tui.py`。

### 3. 为什么 dump 出来的 DEX 可以打开，但代码不完整？

`nhdd` 会按 header 中的 `file_size` 导出 DEX。如果某些页在读取时不可读，当前实现会保留文件大小并将缺失页填 0。这样有利于保留结构和偏移，但并不代表方法体一定完整。二代抽取壳常需要方法级采集与回填。

### 4. 为什么没有扫到 DEX？

常见原因：

- App 未运行或刚启动即被杀。
- root 命令没有真正获得读取 `/proc/<pid>/mem` 的权限。
- 目标 DEX 只短暂存在，单轮扫描错过了时机。
- 真实 DEX 在子进程，但你传入了单个 PID。
- 壳不是"完整 DEX 驻留内存"模型，而是方法级抽取/动态恢复。
- **壳检测到 `/proc/<pid>/mem` 被打开后杀死了进程。** 使用 `--stealth2` 模式。

建议先用包名 + watch：

```bash
adb shell su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --watch 3 --max-seconds 120'
```

如果扫描时 App 崩溃，尝试反检测模式：

```bash
adb shell kp -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --stealth2 --relaxed --stealth'
```

### 5. Android App 能直接编译吗？

当前仓库不包含 `app/` 模块。

## 项目结构

```text
NHDD/
├── nhdd.c                         # v8 单文件 Android ARM64 扫描器（基线）
├── NHDD-cpp-modular/              # v9 C++17 类模块化扫描器（推荐设备端二进制）
│   ├── Makefile                   #   make android / host / push
│   └── src/                       #   main.cpp + *.hpp 头文件模块（scanner、JNIMAP、SO、config 等）
├── nhdd_tui.py                    # 推荐主机端控制器（rich TUI）
├── fix_dex_checksum.py            # 独立 DEX 修复库 + CLI
├── fix_so.py                      # 独立内存 dump SO 的 ELF 修复库 + CLI
├── scripts/
│   ├── build_nhdd_android.py      # 跨平台 v8 构建入口（自动发现 NDK）
│   ├── build_nhdd_android.sh/.ps1 # Shell/PowerShell 包装
│   ├── build_nhdd_cpp.sh          # v9 C++ 构建脚本
│   ├── doctor.py                  # 环境体检（make doctor）
│   └── repack_apk_fast.py         # TUI 重打包实际执行者
├── gui/                           # Go/Wails v2 桌面 GUI（Vue 3 前端 + Go 修复端口）
├── third_party/SoFixer            # 可选遗留 submodule（修复现已内建）
└── BUILD_WINDOWS.md               # Windows/Linux GUI 构建说明
```

## 作者

- **漫宿骄盛**
- **weixiao**

仓库地址：https://github.com/Fruit-Guardians/NHDD

## 合法使用声明

本项目仅用于：

- 自有 App 调试与兼容性分析。
- 获得明确授权的移动安全测试。
- 恶意样本分析、加固评估、逆向学习与研究。

请勿将本项目用于未授权访问、绕过商业授权、窃取代码或数据、侵犯第三方权益等行为。使用者需要自行确认所在地法律法规、目标授权范围和测试边界。项目作者不对任何未授权使用造成的后果负责。

## License

[MIT](./LICENSE)。第三方组件保留各自的许可证与 notices。
