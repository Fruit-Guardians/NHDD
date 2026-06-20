# NHDD — No-Hook DEX/SO Dumper

> 一个面向**授权安全研究、逆向分析与自有应用调试**场景的 Android DEX / SO 内存转储工具。
>
> NHDD 以独立 root 进程运行，通过 `/proc/<pid>/maps` 与 `/proc/<pid>/mem` 从目标进程外部扫描内存中的 DEX / ELF 数据，不向目标进程注入代码，也不安装运行时 Hook。

[English README](./README.md) | 简体中文

---

## 重要声明

NHDD 仅应在以下场景中使用：

- 自有设备、自有应用或已获得明确授权的测试环境；
- 移动应用安全研究、加固效果评估、兼容性分析、漏洞复现与防护验证；
- 企业内部安全审计或教学实验环境。

请勿将本工具用于未授权应用、商业软件、受版权保护内容或任何违反当地法律法规、平台条款及合同约定的行为。作者不对任何未授权使用造成的法律责任、数据泄露、业务损失或其他后果负责。

---

## 项目简介

传统 Android 脱壳工具通常依赖 Frida、Xposed、Zygisk、ART Hook 或 ClassLoader Hook。这类方案能力很强，但会在目标进程内留下注入库、Hook 指令、线程名、调用栈或运行时状态变化，容易被现代加固方案纳入检测面。

NHDD 的设计思路是：

1. 不进入目标进程；
2. 不修改 ART、ClassLoader 或应用方法入口；
3. 不通过 Frida / Xposed / Zygisk 注入 agent；
4. 以 root 权限从进程外部读取目标进程虚拟内存；
5. 扫描内存中的 DEX magic 与 ELF magic，并将命中的内容 dump 到文件；
6. 对 DEX 自动修复 header、SHA-1 signature 与 Adler32 checksum；
7. 对 SO 支持从内存 dump，并可结合 SoFixer 进行修复。

这使 NHDD 更适合用于研究“运行时已经解密并映射到内存”的 DEX / SO。它不是万能脱壳器，也不保证所有加固、所有机型、所有 Android 版本都能完整还原。

---

## 已测试环境

目前已在以下环境中进行过测试：

- OnePlus 9 + LineageOS 21 / Android 14；
- Pixel 系列 Android 14；
- Pixel 系列 Android 16。

其他设备、ROM、内核策略、root 方案和 Android 版本可能存在差异。理论上，只要设备具备可用 root 权限并允许读取目标进程 `/proc/<pid>/mem`，NHDD 就有机会工作，但不做兼容性保证。

---

## 能力边界

NHDD 适用于满足以下条件的壳或运行时保护方案：

- 真实 DEX / SO 会在运行过程中以明文或可解析形态出现在内存中；
- 目标进程的相关内存区域可通过 root 权限读取；
- DEX 页面在 dump 时仍然驻留或可被读取；
- 输出 DEX 的结构没有被严重破坏，或可通过后续修复工具恢复。

NHDD 可能无法完整处理以下情况：

- 真实代码仅以解释器私有结构、JIT 代码、native bridge 或自定义 VM 形态存在；
- 加固方案按需加载、快速卸载、分段解密，导致内存中没有完整 DEX；
- 目标应用主动监控 `/proc` 访问、异常时序、系统调用行为或进程状态；
- 内核、SELinux、root 方案或 ROM 限制跨进程内存读取。

---

## 工作原理

### 为什么许多传统方案容易被检测

| 方案 | 常见实现方式 | 可能暴露的检测面 |
|------|--------------|------------------|
| Frida | 向目标进程注入 agent | 注入库、线程名、端口、符号、调用栈、内存特征 |
| Xposed / LSPosed | 修改 Java / ART 调用路径 | Hook 框架特征、方法入口变化、模块列表 |
| Zygisk 模块 | 在 Zygote / App 进程生命周期中加载模块 | 模块痕迹、maps 特征、native 栈异常 |
| FART 类方案 | 修改 ART 或 Hook 关键函数 | ART 符号、入口指令、系统组件差异 |
| ClassLoader Hook | 拦截 DEX 加载流程 | Java Hook、native Hook、调用路径异常 |


### 外部内存扫描模型

```text
┌─────────────────────────────────────────────────────────┐
│  目标进程：受保护 App                                     │
│                                                         │
│  ┌───────────────────────────────────────────────────┐  │
│  │ 壳 / 加固逻辑                                      │  │
│  │                                                   │  │
│  │ 运行时解密后的 DEX / SO                            │  │
│  │ 0x7f8a001000: "dex\n035\0..."                    │  │
│  │ 0x7f8b200000: "\x7fELF..."                        │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  目标进程内：无 Frida agent、无 Xposed Hook、无方法入口补丁 │
└─────────────────────────────────────────────────────────┘
                         │
                         │ root 进程读取 /proc/<pid>/mem
                         ▼
┌─────────────────────────────────────────────────────────┐
│  NHDD 独立进程                                           │
│                                                         │
│  1. 读取 /proc/<pid>/maps 获取内存布局                    │
│  2. 按页扫描可读内存区域                                  │
│  3. 匹配 DEX / ELF magic                                  │
│  4. 解析 header 与大小信息                                 │
│  5. dump DEX / SO 到输出目录                              │
│  6. 修复 DEX checksum / signature                          │
│  7. 对结果去重、清理无效文件                               │
└─────────────────────────────────────────────────────────┘
```

### 逐页扫描算法

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

按页扫描的优点：

- 单次读取小，失败面更可控；
- 不需要一次性读取大段内存；
- 方便跳过不可读页或空洞页；
- 更适合应对按需分页和短暂映射的 DEX。

---

## 功能特性

- **进程外扫描**：不注入目标进程，不安装运行时 Hook；
- **DEX dump**：扫描内存中的 DEX，并自动修复 header / SHA-1 / Adler32；
- **SO dump**：扫描 ELF magic，支持从内存中导出解密后的 SO；
- **多进程支持**：传入包名时自动扫描主进程和 `:remote` 等子进程；
- **PID 模式**：也可直接指定单个 PID；
- **快照轮询**：通过 `--snapshot` 多轮扫描，捕获短暂存在的 DEX；
- **watch 模式**：通过 `--watch` 持续扫描，适配 lazy-load / 按需加载场景；
- **内容去重**：基于修复后的 DEX SHA-1 跨进程、跨轮次去重；
- **结果清理**：自动过滤明显过小或结构异常的 DEX；
- **SO 修复集成**：可结合 `third_party/SoFixer` 对 dump 后的 SO 进行重建；
- **多种入口**：命令行、Python 控制台、TUI、GUI、Android App 控制端。

---

## 项目结构

```text
NHDD/
├── nhdd.c              # 核心引擎，C 实现，面向 Android ARM64 静态编译
├── Makefile            # 编译配置
├── nhdd_ctrl.py        # PC 端 Python 控制脚本
├── nhdd_tui.py         # 终端 TUI，支持 rich 彩色界面与 watch 进度
├── fix_dex_checksum.py # 独立 DEX 校验和修复工具
├── nhddctl.sh          # Shell 控制脚本
├── gui/                # 桌面 GUI，Go / Fyne 实现
│   ├── main.go
│   ├── adb.go
│   └── dexfix.go
├── app/                # Android 控制 App，Java / libsu
│   └── src/main/
│       ├── AndroidManifest.xml
│       └── java/com/nhdd/app/MainActivity.java
└── third_party/
    └── SoFixer/        # SO 修复工具
```

---

## 编译

### 1. 编译核心引擎 `nhdd`

需要 Android NDK r25 或更高版本。

```bash
export NDK=/path/to/android-ndk-r27
export CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang

$CC -O2 -static -o nhdd nhdd.c
```

或使用 Makefile：

```bash
make
```

### 2. 编译桌面 GUI

需要 Go 1.21+ 与 Fyne 依赖。

```bash
cd gui
go build -o nhdd-gui .
```

### 3. 编译 Android 控制 App

需要 Android SDK 与 JDK 17+。

```bash
./gradlew assembleDebug
```

或使用项目内脚本：

```bash
./build_manual.sh
```

---

## 使用方法

### 方式一：ADB 命令行

#### 1. 推送二进制文件

```bash
adb push nhdd /data/local/tmp/nhdd
adb shell chmod 755 /data/local/tmp/nhdd
```

#### 2. 启动目标 App

```bash
adb shell monkey -p com.example.app -c android.intent.category.LAUNCHER 1
```

#### 3. 基础 DEX dump

```bash
adb shell "/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump"
```

输出目录：

```text
/data/local/tmp/nhdd_dump/
├── dex/
│   ├── *.dex
│   └── ...
└── so/
    ├── *.so
    └── ...
```

#### 4. 快照轮询模式

适合 DEX 短暂出现在内存中的场景。

```bash
adb shell "monkey -p com.example.app -c android.intent.category.LAUNCHER 1 ; \
           /data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump \
           --snapshot 5 --interval 1"
```

参数说明：

- `--snapshot 5`：扫描 5 轮；
- `--interval 1`：每轮间隔 1 秒；
- 每一轮都会重新解析包名对应的进程列表；
- 适合主进程和子进程频繁变化的目标。

#### 5. watch 监听模式

适合按需加载、点击功能页后才加载真实 DEX 的应用。

```bash
adb shell "monkey -p com.example.app -c android.intent.category.LAUNCHER 1 ; \
           /data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --watch"
```

使用建议：

1. 启动 `--watch`；
2. 在手机上逐个打开登录、首页、支付、设置、WebView、IM、视频播放等功能页；
3. NHDD 会在每轮扫描中捕获新出现的 DEX；
4. 连续若干轮没有新 DEX 后自动停止。

可选参数：

```bash
--watch [K]          # 连续 K 轮无新增结果后停止，默认 3
--max-rounds N       # 最大扫描轮数，默认 60
--max-seconds N      # 最大运行秒数，默认 120
--interval SECS      # 每轮间隔秒数，默认 1
```

#### 6. dump SO

```bash
adb shell "/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --so"
```

#### 7. 同时 dump DEX 和 SO

```bash
adb shell "/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --all"
```

#### 8. 拉取结果

```bash
adb pull /data/local/tmp/nhdd_dump ./output
```

---

## Python 控制台

```bash
python3 nhdd_ctrl.py
python3 nhdd_ctrl.py com.example.app
```

控制脚本通常会自动完成：

1. 检查 ADB 连接；
2. 推送 `nhdd`；
3. 启动或重启目标 App；
4. 执行 dump；
5. 拉取结果；
6. 修复或清理输出文件。

---

## TUI 终端界面

```bash
python3 nhdd_tui.py
```

适合需要实时观察扫描轮次、命中数量和输出目录的场景。

---

## 桌面 GUI

```bash
cd gui
./nhdd-gui
```

典型流程：

1. 输入或选择 ADB 设备；
2. 选择目标包名；
3. 选择 DEX / SO / ALL 模式；
4. 点击 DUMP；
5. 等待结果自动拉取到本地。

---

## 常用参数

| 参数 | 说明 |
|------|------|
| `<package>` | 目标包名。传入包名时扫描所有匹配进程。 |
| `<pid>` | 目标 PID。传入数字时只扫描该进程。 |
| `<out_dir>` | 设备端输出目录。 |
| `--dex` | 只 dump DEX。 |
| `--so` | 只 dump SO。 |
| `--all` | 同时 dump DEX 和 SO。 |
| `--snapshot N` | 扫描 N 轮后退出。 |
| `--interval SECS` | 每轮扫描间隔。 |
| `--watch [K]` | 持续扫描，连续 K 轮无新增结果后停止。 |
| `--max-rounds N` | watch 模式最大轮数。 |
| `--max-seconds N` | watch 模式最大运行时间。 |
| `--stealth` | 在区域扫描之间加入默认延时，降低扫描突兀性。 |
| `--region-delay MS` | 自定义区域间延时。 |

---

## DEX 修复说明

DEX header 中的 checksum 与 signature 通常覆盖以下区域：

```text
0x08    Adler32 checksum    覆盖 0x0C 到文件末尾
0x0C    SHA-1 signature     覆盖 0x20 到文件末尾
0x20    file_size
0x24    header_size
0x28    endian_tag
```

NHDD 的修复顺序：

1. 修复 `header_size` 为 `0x70`；
2. 修复 `endian_tag` 为 `0x12345678`；
3. 修复 `file_size` 为实际 dump 大小；
4. 重新计算 SHA-1 signature；
5. 重新计算 Adler32 checksum。

顺序不能反，因为 Adler32 覆盖范围包含 SHA-1 signature。

也可以单独修复：

```bash
python3 fix_dex_checksum.py classes.dex
```

---

## 常见问题

### Q: dump 结果里没有 DEX？

优先检查以下问题：

1. 目标是否真的启动成功；
2. 设备是否具备 root 权限；
3. `/proc/<pid>/mem` 是否可读；
4. 真实 DEX 是否只存在于子进程；
5. DEX 是否加载后很快被卸载；
6. 是否需要进入特定业务页面才会 lazy-load；
7. 是否应改用 `--snapshot` 或 `--watch`。

推荐命令：

```bash
adb shell "monkey -p com.example.app -c android.intent.category.LAUNCHER 1 ; \
           /data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump \
           --snapshot 8 --interval 1"
```

### Q: jadx 打不开 dump 出来的 DEX？

可能原因：

- dump 时 DEX 页面不完整；
- header 被壳破坏；
- `map_off`、`class_data_off`、`string_ids_off` 等字段指向无效区域；
- 目标本身是 stub DEX，真实代码在其他动态 DEX 中；
- 需要进一步做 DEX repair，而不只是 checksum 修复。

可先尝试：

```bash
python3 fix_dex_checksum.py your.dex
```

### Q: 为什么传包名比传 PID 更推荐？

很多应用存在多个进程，例如：

```text
com.example.app
com.example.app:remote
com.example.app:push
com.example.app:worker
```

真实解密后的 DEX 不一定在主进程中。传入包名时，NHDD 会扫描所有匹配进程；传入 PID 时只扫描单个进程。

### Q: 是否必须精确等待 4 秒？

不建议依赖固定等待时间。不同壳、不同设备、不同启动路径的加载时机都不同。早期版本常用“启动后 3~5 秒 dump”的经验值，但现在更推荐：

- `--snapshot`：覆盖短时间窗口；
- `--watch`：覆盖按需加载场景；
- 手动打开关键业务页面，让 lazy-load DEX 进入内存。

### Q: APatch / Magisk / KernelSU 下都能用吗？

取决于 root shell 的权限、mount namespace、SELinux 策略和 ROM 限制。若 Android App 控制端无法访问 `/data/local/tmp/nhdd`，可以改用 ADB 执行：

```bash
adb shell su -c "/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --watch"
```

### Q: 这个工具能替代 FART 吗？

不能简单替代。NHDD 和 FART 的定位不同：

- NHDD 擅长在进程外扫描已经落入内存的 DEX / SO；
- FART 类方案擅长在 ART 方法解析、调用、加载阶段捕获更细粒度信息；
- 对于按方法抽取、动态恢复、解释器私有结构或严重破坏 DEX 结构的壳，可能需要结合 CodeItem dump、DEX repair、ART Hook 或其他分析手段。

---

## 测试记录模板

为了避免 README 暴露不必要的第三方应用信息，建议在 issue 或报告中使用以下模板描述测试结果：

| 样本类型 | 保护类型 | DEX 数量 | SO 数量 | jadx 可读 | 核心逻辑可见 | 备注 |
|----------|----------|----------|---------|-----------|--------------|------|
| 授权样本 A | 商业加固 / 抽取壳 | 76 | 4 | 是 | 是 | 需 watch 进入功能页 |
| 授权样本 B | 自研保护 | 28 | 1 | 是 | 部分 | 需后续 DEX repair |
| 授权样本 C | 热修复 / 插件化 | 79 | 0 | 是 | 是 | 多进程命中 |

---

## 与常见方案的定位对比

| 维度 | NHDD | Frida-dexdump | FART 类方案 | fdex2 / ClassLoader Hook |
|------|------|---------------|-------------|--------------------------|
| 核心方式 | 进程外读内存 | 注入目标进程 | 修改 / Hook ART | Hook ClassLoader |
| 是否进入目标进程 | 否 | 是 | 是 | 是 |
| 是否需要 root | 是 | 通常需要 | 通常需要 | 通常需要 |
| DEX dump | 是 | 是 | 是 | 是 |
| SO dump | 是 | 通常不支持 | 通常不支持 | 通常不支持 |
| 适合 lazy-load | watch 模式适配 | 取决于脚本 | 较强 | 取决于 Hook 点 |
| 进程内检测暴露面 | 低 | 高 | 中到高 | 高 |
| 对 DEX repair 依赖 | 中 | 中 | 低到中 | 中 |

该表仅描述技术定位，不代表对任何具体加固产品的稳定绕过能力保证。

---


---

## License

MIT License

---

## 作者

- 作者：漫宿骄盛，weixiao
- GitHub: `https://github.com/mansujiaosheng/NHDD`

