# NHDD — No-Hook DEX/SO Dumper

NHDD 是一个面向 Android 逆向分析与授权安全研究的 **外部内存 DEX/SO Dump 工具**。它的核心程序 `nhdd` 以独立 root 进程运行，通过读取目标进程的 `/proc/<pid>/maps` 和 `/proc/<pid>/mem`，在内存中扫描 DEX/ELF magic，并将已加载到内存中的 DEX 或 SO 导出到文件。

和 Frida/Xposed/FART/fdex2 这类“进程内 Hook/注入”路线不同，NHDD 的核心思路是：**不向目标 App 注入代码，不修改目标进程方法入口，不依赖 ART Hook**。这可以显著降低由进程内 Hook、注入库、异常线程名、方法入口跳转等特征带来的暴露面。

> 重要说明：No-Hook 不等于“绝对无法检测”。目标 App、系统策略或加固方案仍可能通过进程状态变化、外部访问副作用、root 环境、SELinux 策略、进程被杀等方式影响结果。NHDD 的优势是低侵入、外部读取、部署简单，而不是承诺零风险或万能脱壳。

## 适用范围

适合：

- 运行时会把完整或接近完整 DEX 放入内存的一代壳、普通加固壳、热修复/插件化加载场景。
- 需要快速从真机 root 环境中批量扫描 DEX/SO 的逆向分析流程。
- 不希望在目标进程内加载 Frida agent、Xposed 模块或修改 ART 的场景。

不适合单独解决：

- 只在方法调用时临时解密 CodeItem 的二代抽取壳。
- DEX 结构存在大量空洞、方法体被擦除、仅动态恢复指令的场景。
- 需要完整方法体回填、ClassLinker/LoadMethod 级别采集的场景。

对于二代抽取壳，NHDD 更适合作为 **低侵入辅助扫描器**，用来捕获已经驻留内存的 DEX/SO；完整恢复通常还需要 DefineClass、LoadMethod、CodeItem backfill 或 FART 类流水线配合。

## 当前仓库状态

| 模块 | 状态 | 说明 |
|---|---:|---|
| `nhdd.c` | 可用 | 核心 Android ARM64 扫描器，支持 DEX/SO、包名多进程、快照、watch、去重、DEX 校验修复。 |
| `nhdd_tui.py` | 推荐 | 终端交互版，支持 root 命令配置、watch 实时进度、拉取结果。当前最适合作为日常入口。 |
| `nhdd_ctrl.py` | 可用但简单 | 电脑端 Python 控制脚本，默认 force-stop、启动、watch；root 包装能力弱，复杂 root 环境建议用 TUI。 |
| `gui_web/` | 可用 | Go 标准库 Web GUI，适合 Windows 打包；当前是固定等待模型，不是完整 watch/TUI 能力。 |
| `gui/` | 可选 | Go/Fyne 原生 GUI，需要补齐/生成 `go.sum` 并安装 Fyne 依赖。 |
| `fix_dex_checksum.py` | 可用 | 独立 DEX header、SHA-1、Adler32 修复工具。 |
| `app/` | 未完成 | 当前仓库只有 Manifest 和资源，缺少 `MainActivity.java`，不应按“可直接构建 Android App”宣传。 |

## 核心特性

- **外部读取**：通过 `/proc/<pid>/mem` 读取目标虚拟地址空间，不注入目标进程。
- **DEX dump**：扫描 `dex\n` magic，读取 header 中的 `file_size` 并按页导出。
- **SO dump**：扫描 ELF magic，识别 ET_DYN，共享库导出后可调用 SoFixer 修复。
- **包名多进程扫描**：传入包名时，会扫描所有 cmdline 匹配的进程，包括 `:remote` 等子进程。
- **快照轮询**：`--snapshot N --interval T` 多轮扫描，适合捕获短暂存在的 DEX。
- **watch 模式**：`--watch [K]` 持续扫描，连续 K 轮没有新 DEX 后停止，适合手动点开功能页捕获 lazy-load DEX。
- **内容去重**：DEX 按重算后的 SHA-1 signature 去重，跨进程、跨轮次重复命中不会重复写入。
- **DEX 自动修复**：修复 `file_size`、`header_size`、`endian_tag`、SHA-1 signature 和 Adler32 checksum。
- **输出隔离**：默认清理旧的 `.dex/.so` 输出，避免多次运行结果混在一起；可用 `--keep` 保留。
- **低侵入运行选项**：`--region-delay`、`--stealth`、`--name` 可调整扫描节奏和自身进程名，但不保证规避所有检测。

## 原理概览

```text
目标 App 进程
├── 壳/加固逻辑
├── ART/ClassLoader
├── 已加载的 DEX 内存区域
└── 已加载的 SO 映射区域

独立 root 进程：nhdd
├── 读取 /proc/<pid>/maps 获取可读内存区间
├── 打开 /proc/<pid>/mem
├── 按页扫描 DEX/ELF magic
├── 根据 DEX header 或 ELF program header 计算导出范围
├── 写入 out_dir/dex 或 out_dir/so
└── 修复 DEX header/checksum，必要时调用 SoFixer
```

关键点：`pread(/proc/<pid>/mem, ..., virtual_address)` 的 offset 是目标进程虚拟地址。只要 root/系统策略允许读取，就可以从外部读取目标进程地址空间中的内容。

## 构建 Android 端 `nhdd`

要求：Android NDK r25+，目标设备为 ARM64。

```bash
# 推荐：使用仓库脚本
NDK=/path/to/android-ndk-r27 API=34 ./scripts/build_nhdd_android.sh

# 或手动编译
/path/to/android-ndk-r27/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang \
  -O2 -static -Wall -Wextra -o nhdd nhdd.c
```

推送到设备：

```bash
adb push ./nhdd /data/local/tmp/nhdd
adb shell chmod 755 /data/local/tmp/nhdd
```

如果使用 SoFixer 修复 SO，也需要把 SoFixer 的 Android 可执行文件放到设备上，例如：

```bash
adb push ./sofixer /data/local/tmp/sofixer
adb shell chmod 755 /data/local/tmp/sofixer
```

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

固定等待适合简单场景，但对强对抗壳不一定稳定。很多时候“扫已运行进程 + watch”比“强制重启 + 等 4 秒”更稳。

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
| `--region-delay MS` | 每个 maps 区域之间延迟 MS 毫秒。 |
| `--name NAME` / `--disguise NAME` | 修改自身 `/proc/self/comm` 和 `/proc/self/cmdline` 展示名。 |
| `--sofixer PATH` | 指定 SoFixer 路径，默认查找 `/data/local/tmp/sofixer` 或 `/data/local/tmp/SoFixer64`。 |

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

## Web GUI 使用方式

`gui_web/` 是基于 Go 标准库的本地 Web GUI，适合 Windows 打包，不依赖 Fyne。

构建：

```bash
cd gui_web
go build -trimpath -ldflags='-s -w' -o nhdd-gui-web .
```

运行时把 Android ARM64 版 `nhdd` 放在 GUI 可执行文件同目录：

```text
NHDD-run/
├── nhdd-gui-web.exe
└── nhdd
```

说明：当前 Web GUI 主要是“force-stop → launch → wait → dump → pull”的固定等待流程，不等价于 TUI 的完整 watch 交互能力。若目标存在多进程或 lazy-load，优先使用命令行或 `nhdd_tui.py`。

## Fyne GUI 使用方式（可选）

```bash
cd gui
go mod tidy
go build -o nhdd-gui .
```

如果构建时报 `missing go.sum entry`，先执行 `go mod tidy`。Fyne 版本需要 CGO 和图形依赖，Windows 打包可参考 `BUILD_WINDOWS.md`。

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

当前 `gui/` 和 `gui_web/` 的流程偏固定等待，并且部分逻辑会优先使用 `pidof` 返回的第一个 PID。这样可能绕过 `nhdd` 的包名多进程扫描能力。遇到多进程壳或 lazy-load 场景，建议用：

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
- 壳不是“完整 DEX 驻留内存”模型，而是方法级抽取/动态恢复。

建议先用包名 + watch：

```bash
adb shell su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --watch 3 --max-seconds 120'
```

### 5. Android App 能直接编译吗？

当前仓库快照中 `app/` 缺少 `app/src/main/java/com/nhdd/app/MainActivity.java`，因此 Android App 模块不是可直接构建状态。README 不建议把它作为当前可用入口宣传。

## 项目结构

```text
NHDD/
├── nhdd.c                         # Android 端核心扫描器
├── fix_dex_checksum.py            # 独立 DEX 修复工具
├── nhdd_tui.py                    # 推荐 TUI 控制器
├── nhdd_ctrl.py                   # 简单 Python 控制器
├── nhddctl.sh                     # 设备端 shell 包装脚本
├── scripts/
│   ├── build_nhdd_android.sh      # 构建 Android ARM64 nhdd
│   ├── build_webgui_windows.ps1
│   ├── build_webgui_windows_from_linux.sh
│   ├── build_fyne_windows.ps1
│   └── build_fyne_windows_from_linux.sh
├── gui_web/                       # Go 标准库 Web GUI
├── gui/                           # Go/Fyne 原生 GUI
├── app/                           # Android App 脚手架，当前缺 MainActivity.java
└── BUILD_WINDOWS.md               # Windows/Linux GUI 构建说明
```

## 合法使用声明

本项目仅用于：

- 自有 App 调试与兼容性分析。
- 获得明确授权的移动安全测试。
- 恶意样本分析、加固评估、逆向学习与研究。

请勿将本项目用于未授权访问、绕过商业授权、窃取代码或数据、侵犯第三方权益等行为。使用者需要自行确认所在地法律法规、目标授权范围和测试边界。项目作者不对任何未授权使用造成的后果负责。

## License

MIT
