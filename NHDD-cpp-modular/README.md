<p align="center">
  <img src="assets/nhdd-mark.svg" alt="NHDD" width="104" height="104">
</p>

<h1 align="center">NHDD</h1>

<p align="center"><strong>No-Hook DEX / SO Dumper</strong></p>

<h3 align="center">运行时提取，不向进程注入。</h3>

<p align="center">
  面向 Android Root 的 DEX / SO 提取工具。<br>
  多轮捕获 DEX，按段重建 SO，持续跟随运行时变化。
</p>

<p align="center">
  <img alt="Android · Root" src="assets/badges/nhdd-root.svg">
  <img alt="ABI · ARM64 / ARMv7" src="assets/badges/nhdd-abi.svg">
  <img alt="Capture · No Hook" src="assets/badges/nhdd-no-hook.svg">
  <img alt="C++ · 17" src="assets/badges/nhdd-cpp.svg">
</p>

<p align="center">
  <a href="#快速上手">快速上手</a> &nbsp;·&nbsp;
  <a href="#功能介绍">功能介绍</a> &nbsp;·&nbsp;
  <a href="#常用命令">使用说明</a> &nbsp;·&nbsp;
  <a href="#输出说明">产物说明</a> &nbsp;·&nbsp;
  <a href="docs/design.md">技术设计</a> &nbsp;·&nbsp;
  <a href="https://github.com/Fruit-Guardians/NHDD/issues">问题反馈</a>
</p>

<p align="center"><sub>一个二进制，无需注入 Agent。仅用于自有或已获授权的应用。</sub></p>

---

本页介绍 `NHDD-cpp-modular` 中的 C++17 CLI。默认在目标进程外读取内存，不修改方法入口，不依赖 Frida、Xposed 或 ART Hook。旧版 C 程序及 TUI / GUI 不保证支持本页全部参数。

> 无注入不等于不可检测；字节完整也不等于方法已经解密。使用前请阅读[能力边界](#常见问题)。

## 功能介绍

| 功能 | 可以做什么 |
|---|---|
| DEX 提取与修复 | 标准扫描或 `--relaxed` 弱化 magic 依赖；跨轮补齐缺页，保留不同内容 revision，导出 raw / fixed 副本 |
| ART 辅助 DEX 发现 | 对已适配的 libdexfile Build ID 扫描 StandardDexFile 对象特征，通过运行时长度、缓存表与 map_list 交叉发现擦头 DEX；不注入、不调用目标方法 |
| 完整度与结构检查 | 记录字节覆盖率、缺失区间；检查 DEX 表、索引、class_data、code/debug 边界以及 SHA-1 / Adler32 |
| SO 重建 | 支持 ELF32/64，按 `PT_LOAD / load bias` 恢复文件布局；区分完整重建和缺页残件 |
| 冷启动与多进程跟随 | 启动前布置事件源，跟随包名进程、子进程及已经发现的改名后代；隔离 PID 复用 |
| 事件驱动增量捕获 | 结合 mmap / mprotect / munmap / mremap、映射与权限变化、内容采样触发扫描 |
| 快速局部捕获 | tracefs 采集线程先抢救事件范围，再异步落盘；两遍读取记录匹配、变化、缺页与时延，不依赖先发现 DEX 头 |
| JNI 绑定发现 | 无 Hook 扫描 `JNINativeMethod` 表，导出候选绑定和函数指针；支持按 SO 筛选 |
| ART 格式识别 | 保留 CompactDex / VDEX / OAT 原生证据，包含 OAT 279 头部与偏移检查 |
| 离线校验 | `--verify FILE` 输出 JSON，不启动或执行待检代码 |

“字节完整”“静态结构检查通过”“ART 可装载”“业务方法已解密”不是同一件事。NHDD 会分别表达已知状态，不把格式识别当作完整脱壳。

## 快速上手

### 1. 准备环境与二进制

- 主机安装 Android Platform Tools，能通过 `adb devices` 看到设备。
- 设备已 Root，且授权 `adb shell` 使用 `su`；系统策略允许访问目标进程内存。
- 准备与设备 ABI 匹配的 **C++ CLI** 二进制 `nhdd`；没有二进制时见[从源码构建](#从源码构建)。
- ARM64 是主要真机验证环境；ARMv7 已通过交叉编译检查，JNI 扫描主要面向 ARM64。

```bash
adb devices
adb shell "su -c id"
adb push nhdd /data/local/tmp/nhdd
adb shell chmod 755 /data/local/tmp/nhdd
adb shell /data/local/tmp/nhdd --help
```

最后一条应能看到 `--spawn`、`--events`、`--verify` 等参数，否则可能部署了旧版二进制。

### 2. 提取正在运行的应用

手动打开自己的测试 App，将下例 `com.example.app` 替换为真实包名：

```bash
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_demo --all --watch 3 --relaxed'"
```

随后在 App 中进入需要分析的页面，触发功能或动态模块加载。命令同时提取 DEX 和 SO；`--watch 3` 在连续 3 轮没有新产物或 DEX 覆盖进展后停止，默认还受 60 轮 / 120 秒上限约束。

### 3. 拉取结果

```bash
adb pull /data/local/tmp/nhdd_demo ./nhdd_demo
```

若提示 `Permission denied`，Root 写出的产物可能不允许 shell 用户读取。确认路径仅是本次输出目录后，再授予读取权限并重试：

```bash
adb shell "su -c 'chmod -R a+rX /data/local/tmp/nhdd_demo'"
adb pull /data/local/tmp/nhdd_demo ./nhdd_demo
```

产物可能包含应用私有数据，请妥善保存。优先查看 `dex/*.meta.json`、`so/*.json`，再选择完整副本进行分析。

## 常用命令

下面每条命令使用独立输出目录。复用旧目录前请阅读 [`--keep` 说明](#参数速查)。

### 只提取 DEX 或 SO

```bash
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dex --dex --watch 3 --relaxed'"
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_so --so --snapshot 2 --interval 1'"
```

也可用 PID 替换包名，例如 `12345`。PID 模式不会自动跟随其他进程；continuous 中目标退出或 PID 世代变化后停止。

### ART 辅助发现（默认启用）

ART 辅助发现默认以 `--art-dex auto` 随 DEX 扫描启用；当前只适配已真机核对的 ARM64 libdexfile 构建，**不是所有 Android 16 都支持**。普通扫描与 ART 路径互补；未知 Build ID 时会明确记录原因，继续原有扫描。

仅验证 ART 路径时可使用：

```bash
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_art --dex --art-dex only --art-scan-mb 64 --snapshot 2 --interval 1'"
```

`only` 跳过 magic / endian / runtime-container 搜索；不支持的构建不会退回普通扫描。看日志的 `[ART] status` 和 metadata 的 `discovery` 判断是否命中，不能只以程序退出或导出文件数量判断成功。使用 `--art-dex off` 可关闭辅助路径。具体兼容范围、擦头测试和复现方法见 [ART 辅助发现](docs/art-discovery.md)。

### 冷启动并持续捕获

应用尚未运行时：

```bash
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_spawn --spawn --all --relaxed --events auto --monitor-duration 30'"
```

应用已经运行、且允许强制重启时：

```bash
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_restart --spawn-restart --all --relaxed --events auto --monitor-duration 30'"
```

`--spawn-restart` 会 force-stop 指定应用，可能打断当前任务。两种启动方式都要求包具有 launcher activity；`--spawn` 只提前布置事件源，不会冻结新进程。

### 对运行中的应用做增量捕获

```bash
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_live --all --continuous --relaxed --events auto --monitor-duration 60'"
```

`auto` 优先尝试 tracefs，失败时明确提示并退回轮询。必须使用内核事件时选 `--events tracefs`；主动关闭内核事件时选 `--events poll`。`--monitor-duration 0` 表示持续运行，可用 Ctrl+C 正常结束。

快速路径默认随 continuous 的 tracefs 后端开启，在主扫描忙时也尝试立即保存事件范围。输出位于 `fast/`，包含两次读取的局部原始字节、逐页覆盖和一致性标记；只有完全包含在某一次读取中的标准 DEX 才另存 raw/fixed 副本。默认每事件取前 1MiB，可用 `--fast-max-kb 4..8192` 调整；用 `--fast-capture off` 做关闭对照。双读相同不等于原子快照，轮询回退不具备该能力。预算、输出说明及真机对照见[快速捕获说明](docs/fast-capture.md)。

### 查找 JNI 绑定

先写目标与输出目录，再写可选的 JNI 模块筛选参数：

```bash
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_jni --jnimap libexample.so --save-maps'"
```

需要同时提取 DEX、SO 和 JNI 候选时使用 `--all --jnimap libexample.so`。扫描到的表是候选证据，不等于完整记录所有 RegisterNatives 调用。

### 离线检查已有产物

```bash
adb shell "/data/local/tmp/nhdd --verify /data/local/tmp/nhdd_demo/dex/example.fixed.dex"
adb shell "/data/local/tmp/nhdd --verify /data/local/tmp/example.vdex"
adb shell "/data/local/tmp/nhdd --verify /data/local/tmp/example.odex"
```

替换成真实文件名；待检文件需对执行用户可读，必要时用 `su -c`。支持 ELF 中的 OAT payload；JSON 会报告 `payload_offset`。

| 退出码 | `--verify` 含义 |
|---|---|
| `0` | 声明范围内的检查通过；标准 DEX 还要求 SHA-1 / Adler32 通过 |
| `1` | I/O 等运行错误 |
| `2` | 无效或不完整 |
| `3` | 未知格式或不支持的版本 |

## 参数速查

基本形式：`nhdd <pid|package> [output_dir] [options]`。默认仅扫描 DEX、执行 1 轮，输出到 `/data/local/tmp/nhdd_dump`。

| 主要参数 | 说明 |
|---|---|
| `--dex / --so / --all` | 选择 DEX、SO 或两者；`--all` 不代表重打包 APK |
| `--jnimap [LIB]` | 扫描 JNI 表；可追加到 `--all`，LIB 为可选 SO 筛选 |
| `--snapshot N --interval T` | 固定轮数与轮间隔，间隔单位为秒 |
| `--watch [K]` | 连续 K 轮无进展后停止，默认 K=3 |
| `--max-rounds N --max-seconds S` | watch 上限，默认 60 轮 / 120 秒 |
| `--continuous` | 长时间跟随映射、权限和采样内容变化 |
| `--spawn / --spawn-restart` | 启动前布置事件；后者先强制停止应用；均自动开启 continuous |
| `--spawn-timeout S` | 等待首次发现目标进程，默认 15 秒，范围 1–300 |
| `--events auto\|tracefs\|poll` | 选择事件后端，自动开启 continuous |
| `--fast-capture auto\|off` | 默认 auto；continuous + tracefs 的采集线程局部双读，不另行开启 continuous |
| `--fast-max-kb N` | 每事件读取前缀上限，默认 1024 KiB，范围 4–8192；两遍共用 8ms 软预算 |
| `--monitor-interval T` | continuous 周期检查间隔，默认 2 秒 |
| `--monitor-duration S` | continuous 调度时长，默认 0，即不限时 |
| `--monitor-verbose` | 输出详细监控日志 |
| `--relaxed` | 不依赖 DEX magic，但仍需可验证的 endian 和结构 |
| `--art-dex auto\|off\|only` | 默认 auto；已确认构建的 ART 对象特征发现 / 关闭 / 仅 ART 路径 |
| `--art-scan-mb N` | 每进程每轮 native-heap 读取预算，默认 64 MiB，范围 1–512；耗尽记录游标并在后续轮继续，不保证一轮扫完 |
| `--stealth2` | 改用 `process_vm_readv`，不是权限绕过 |
| `--save-maps` | 保存进程映射快照 |
| `--keep` | 不清理既有产物，timeline 改为追加；不恢复上次内存缓存或累计状态 |
| `--verify FILE` | 只执行离线校验，不需要指定目标 |
| `--help` | 查看内置帮助 |

默认复用输出目录会清理所选模式的旧产物；建议每次使用新目录。监控时长限制不是硬超时，正在进行的扫描会完成后退出。

`fast/` 是按捕获会话与时刻命名的追加证据，不参与上述旧产物清理。快速路径每次运行最多发布约 256MiB，复用目录仍会累计，建议每次换新目录并及时归档。

<details>
<summary>更多扫描、JNI 与读取选项</summary>

| 参数 | 说明 |
|---|---|
| `--anon` | DEX 只扫描 path 为空的映射，可能漏掉 named-anon、memfd 和文件映射 |
| `--no-deep-so` | 关闭额外的深度 SO 搜索 |
| `--stealth` | 增加区域读取间隔，并设置默认进程名伪装；不保证不可检测 |
| `--region-delay MS` | 每个扫描区域之间的等待时间，单位毫秒 |
| `--name NAME` | 设置工具进程名，不改变读取权限 |
| `--jni-lib LIB` | 设置 JNI 函数指针的模块筛选 |
| `--jni-min N` | 最小连续 JNI 表项数，默认 2 |
| `--jni-max-region MB` | JNI 普通区域大小上限，默认 64 MiB |
| `--jni-full` | 扩大 JNI 扫描范围，耗时更高 |
| `--analyze-so LIB` | 组合目标库 JNI 分析、maps、函数指针及目标 SO 导出 |
| `--target-so LIB` | 指定目标 SO，并启用 maps、目标库导出及函数指针输出 |
| `--dump-target-so / --fnptrs` | 启用目标库导出 / 额外函数指针输出 |

</details>

## 输出说明

```text
nhdd_demo/
├── dex/
│   ├── *.partial.dex            # 有缺页的残件
│   ├── *.raw.dex                # 字节完整的原始内容
│   ├── *.fixed.dex              # header / checksum 修复副本
│   ├── *.meta.json              # 覆盖率、holes、raw/fixed 结构检查
│   ├── runtime_*.cdex / *.vdex  # 原生 ART 格式证据，另有 JSON
│   └── *.oat-header.bin         # 仅 OAT header/KV，另有 JSON
├── so/
│   ├── *.reconstructed.so       # 按 PT_LOAD 重建，字节覆盖完整
│   ├── *.partial.so             # 存在缺失字节
│   ├── *.raw.bin                # 可用时附带的原始 load-layout
│   └── *.json                   # segments、holes、load bias、manifest 等
├── maps/                       # 使用 --save-maps 等选项时生成
├── fast/                       # 局部双读 .bin / .json，完全包含的 DEX 另存 raw/fixed
├── jnimap/                     # JNI 候选绑定及函数指针 JSONL
└── timeline.jsonl              # continuous 的映射与系统调用时间线
```

- `partial`：先看 holes，不能当作完整 DEX/SO。
- `raw / fixed`：分别保留原始字节与修复副本，便于比较；fixed 不代表方法已经全部解密。
- `structural_checks_passed`：仅静态检查通过；`art_accepted: null` 表示未进行 ART 装载验证。
- `discovery.source`：区分 `header_scan` 与 `art_standard_dexfile` 首次发现来源；后者记录对象地址、虚表地址与 libdexfile Build ID，不表示已通过 ART 类型验证。
- `reconstructed.so`：恢复文件布局，不承诺可重新加载；运行中的读取不是冻结快照。
- `oat-header.bin`：明确只有头部证据，不能作为完整 OAT 使用。
- `manifest_<pid>_g<starttime>.json`：记录 SO 发布状态；continuous 同时记录会话累计和最近一次扫描。
- `timeline.jsonl`：判断变化、捕获时机、事件丢失与采样状态；丢失后补扫不能补回已经消失的明文。
- `fast/*.json`：`two_reads_match / changed_between_reads / partial_reads` 分别表达双读相同、变化与不完整；同时看 `truncated`、逐页长度与 DEX 子项的独立一致性。二进制中不可读部分补零，只能按页覆盖解释，不能视为有效原始字节。该路径不与多轮 DEX 缓存盲拼，计数见 `Fast capture`，不并入主扫描的唯一 DEX 数。

### 当前格式支持

| 格式 | 支持范围 |
|---|---|
| 标准 DEX | 035 / 037 / 038 / 039 / 040 的静态结构检查；041 暂不支持 |
| CompactDex | 001 的头、ID 表与共享数据范围；不转标准 DEX |
| VDEX | 006 / 010 / 019 / 021 / 027 的版本化布局与内嵌 DEX/CDEX 检查 |
| OAT | 170 / 195 / 230 / 259 / 262 / 265 / 275 / 279 的头、KV 与相应偏移检查 |

OAT 279 已在 Root Pixel 6 的真实 ART 文件与只读映射上验证。当前不提供反 quickening、完整 OAT→DEX 转换、方法级回填或 VMP 自动还原；版本兼容不等于对所有壳有效。详细验证边界见[技术设计](docs/design.md)。

## 从源码构建

以下命令都在 `NHDD-cpp-modular` 目录执行；若从仓库根目录开始，先 `cd NHDD-cpp-modular`。需要 Android NDK、C++17 编译器；GNU make 命令适用于 Linux / WSL / MSYS2。

**Linux / WSL（ARM64，API 34）：**

```bash
make android ANDROID_CXX="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang++"
```

**Windows PowerShell（ARM64，API 34）：**

```powershell
$nhddNdk = "C:/Android/android-ndk-r27"
& "$nhddNdk/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android34-clang++.cmd" -O2 -std=c++17 -Wall -Wextra -static-libstdc++ -pthread src/main.cpp -o nhdd
```

修改 NDK 路径；macOS 使用对应主机工具链目录。ARMv7 可改用 `armv7a-linux-androideabi23-clang++`（Windows 后缀 `.cmd`）。输出的 `nhdd` 是 Android ELF，不是 Windows 可执行文件。

**宿主逻辑测试：**

```bash
make test
```

九组测试覆盖 DEX 合并、ELF 重建、maps 变化、manifest、进程跟随、syscall、格式检查、ART 对象发现与局部双读反例。设备夹具和实现细节见[源码说明](src/README.md)与[技术设计](docs/design.md)。

## 常见问题

**没有 Root 可以用吗？**

当前重点是 Root standalone 场景。未 Root 下仅可能对 debuggable 自有应用通过 `run-as` 获得同 UID 访问，仍受系统策略限制；未实现进程内 self 模式。离线 `--verify` 本身不要求 Root。

**开启 `--stealth2` 还是 Permission denied？**

它只切换内存读取方式，不绕过 ptrace、UID 或 SELinux 检查。先检查 Root 授权、目标 PID 是否存活、设备策略；不要把关闭 SELinux 作为默认操作。

**tracefs 不可用怎么办？**

使用 `--events auto` 自动回退，或显式 `--events poll`。轮询仍能检测映射、权限和采样内容变化，但更容易漏掉短暂映射。要求 tracefs 时失败会直接报错。

**DEX 完整、checksum 正确，为什么仍有方法无法反编译？**

字节可能仍是密文、占位方法体或虚拟化逻辑；只修 checksum 无法恢复原始代码。按需解密、方法体外置和执行后重新加密还需要方法级恢复能力。

**为什么没有“完整 OAT”或所有系统库？**

OAT 只导出明确标记的头部证据；系统/APEX/vendor 的 runtime 格式默认不额外导出。SO 也有目标与来源筛选，不是设备全内存备份工具。

## 更多说明

- [技术设计与验证边界](docs/design.md)
- [ART 辅助 DEX 发现与真机复现](docs/art-discovery.md)
- [快速局部捕获、一致性与短窗口真机对照](docs/fast-capture.md)
- [源码模块与维护约束](src/README.md)
- [README 徽章制作方法](docs/badges.md)
- [提交问题](https://github.com/Fruit-Guardians/NHDD/issues)：建议附设备 ABI、Android/ART 版本、命令、错误日志和脱敏 metadata，不要公开未授权 APK 或私有内存产物。
