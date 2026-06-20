# NHDD — No-Hook DEX/SO Dumper

**无需注入、无需 Hook 的 Android DEX/SO 内存脱壳工具**

已在一加lineage OS 21 ，pixel的安卓14，安卓16版本测试过，其他手机及型号未测试，不过理论上都是可行的，只要手机能root

nhdd 以独立 root 进程运行，通过读取 `/proc/<pid>/mem` 直接扫描目标进程内存，找到 DEX/SO 文件并 dump。由于不注入任何代码到目标进程，加固方案无法检测到脱壳行为。

**能力边界**：本工具只适用于会将dex放到内存的壳，经过测试，市面上大多数壳都是如此，因此这个工具能解决大多数商业壳

## 原理

### 为什么传统脱壳工具会被检测？

常见的脱壳方案（Frida、Xposed、FART 等）需要在目标进程中安装 hook：

| 方案 | 原理 | 被检测原因 |
|------|------|-----------|
| Frida | 注入 agent.so 到目标进程 | ptrace 注入、agent.so 内存特征、线程名 frida-* |
| Xposed | 修改 ART 运行时 | 方法入口被替换为跳转指令 |
| FART | 修改系统框架 | Zygisk 模块可被枚举 |
| fdex2 | Hook ClassLoader | DEX 加载回调被劫持 |

加固方案（邦邦加固、360加固、腾讯乐固等）通过以下方式检测：
- 扫描 `/proc/self/maps` 查找注入的 SO
- 检测方法入口是否被修改
- 监控 `ptrace` 系统调用
- 检查线程名和栈回溯

### NHDD 的核心思路

NHDD 完全不触碰目标进程，而是从**外部**以 root 身份读取其内存：

```
┌─────────────────────────────────────────────────┐
│  目标进程 (被加固的 App)                           │
│  ┌─────────────────────────────────────────────┐ │
│  │  壳 (邦邦/360/腾讯)                          │ │
│  │  ┌─────────────────────────────────────────┐ │ │
│  │  │  解密后的 DEX (运行时才存在)              │ │ │
│  │  │  0x7f8a001000: "dex\n035\0..."          │ │ │
│  │  └─────────────────────────────────────────┘ │ │
│  │  检测: /proc/self/maps 无异常 ✓              │ │
│  │  检测: 无 hook 跳转指令 ✓                    │ │
│  │  检测: 无 frida 线程 ✓                       │ │
│  └─────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘
         │
         │ /proc/<pid>/mem (root 只读访问)
         ▼
┌─────────────────────────────────────────────────┐
│  NHDD (独立 root 进程)                            │
│  1. 读取 /proc/<pid>/maps 获取内存布局             │
│  2. 逐页扫描 /proc/<pid>/mem 寻找 DEX magic       │
│  3. 读取完整 DEX 数据                              │
│  4. 自动修复 SHA-1 + Adler32 校验和               │
│  5. 写入文件                                       │
└─────────────────────────────────────────────────┘
```

**关键点：** `pread(/proc/<pid>/mem)` 是内核提供的合法接口，root 进程可以读取任何其他进程的内存。目标进程内部完全感知不到被读取。

### 逐页扫描算法

```
for each 可读内存区域 in /proc/<pid>/maps:
    for addr from 区域起始 to 区域结束, step=4096:
        data = pread(mem_fd, 4096, addr)
        if data 以 "dex\n" 开头:          # DEX magic
            读取 DEX header 获取 file_size
            dump 完整 DEX
            修复 checksum
        if data 以 "\x7fELF" 开头:         # ELF magic
            解析 ELF header 获取段信息
            dump 完整 SO
```

逐页扫描（而非整区域读取）的优势：
- 内存占用低（只需 4KB 缓冲区）
- 不会因单次读取过大而失败
- 不会遗漏跨页边界的 DEX

### DEX 校验和修复

壳在内存中修改了 DEX 数据（解密），但没有更新 DEX header 中的校验和。修复顺序：

```
1. 修复 header_size → 0x70 (标准 DEX header 大小)
2. 修复 endian_tag → 0x12345678 (小端序标记)
3. 修复 file_size → 实际 dump 的大小
4. 重新计算 SHA-1 signature (offset 0x0C, 覆盖 0x20 到文件末尾)
5. 重新计算 Adler32 checksum (offset 0x08, 覆盖 0x0C 到文件末尾)
```

**顺序很重要**：Adler32 覆盖的范围包含 SHA-1，所以必须先算 SHA-1 再算 Adler32。

### SO dump 原理

SO 文件在内存中可能被壳解密后与磁盘版本不同。NHDD 扫描 ELF magic (`\x7fELF`)，通过解析 ELF program headers 计算完整 SO 大小，然后从内存 dump。

## 功能特性

- **零检测风险** — 不注入、不 hook、不 ptrace，目标进程完全无感知
- **多进程扫描** — 给定包名时扫描**所有**匹配进程（主进程 + `:remote` 子进程），真实解密 DEX 常在子进程
- **DEX 内容去重** — 按重算的 SHA-1 签名跨进程/跨快照去重，同一 DEX 只写一份
- **快照轮询** — `--snapshot N` 在启动后多轮重扫，捕获时序敏感、短暂存在的 DEX
- **watch 监听** — `--watch` 持续扫描直到稳定，配合手动点开功能页可捕获**按需 lazy-load** 的 DEX，是达到一代壳 ~100% 覆盖的关键
- **反检测容错** — 壳杀进程后自动重新解析新 PID 继续扫；`--stealth` 区域间延时降低被注意概率
- **DEX 真校验** — 命中后校验 version 标签 + header 字段，过滤 random 数据里的假阳性 magic
- **DEX dump** — 自动扫描内存中的 DEX 文件，修复校验和
- **SO dump** — 从内存 dump 解密后的 SO 文件，跨连续映射段读取，自动调用 SoFixer 修复
- **包名解析** — 支持传入包名自动查找 PID
- **自动修复** — DEX: SHA-1 + Adler32 + header_size + endian_tag + file_size；SO: shdr + phdr + 重定位
- **无效文件清理** — 自动删除过小或损坏的 DEX
- **三种使用方式** — 命令行 / Python 控制台 / GUI 桌面程序

## 测试结果

| 应用 | 加固方案 | DEX 数量 | jadx 可读 | 核心业务可见 |
|------|---------|---------|----------|------------|
| 风行视频 | 邦邦加固 (KADP) | 76 | ✓ | 视频播放、推荐算法 |
| 中国银行 | 自研壳 | 28 | ✓ | 私人银行、信用卡挂失、移动支付 |
| 工商银行 | 自研壳 | 26 | ✓ | 我的账户、ISP 下载 |
| 理想汽车 | 热修复壳 | 79 | ✓ | 登录拦截、社区 API、充电桩签名 |
| 腾讯混元 | DTMP 框架 | 74 | ✓ | 平台通道、ViewModel、CGI 请求 |
| 闲鱼 | 阿里加固 | - | ✓ | 交易、发布、IM |

## 项目结构

```
NHDD/
├── nhdd.c              # 核心脱壳引擎 (C, 静态编译) — 多进程扫描/去重/快照
├── Makefile             # 编译配置
├── nhdd_ctrl.py         # 电脑端 Python 控制程序（终端脚本）
├── nhdd_tui.py          # 电脑端终端版 TUI（rich 彩色界面 + watch 实时进度）
├── fix_dex_checksum.py  # 独立 DEX 校验和修复工具
├── gui/                 # 桌面 GUI (Go/Fyne)
│   ├── main.go          # 主界面
│   ├── adb.go           # ADB 通信 + 脱壳流程
│   └── dexfix.go        # DEX 修复 (Go 实现)
├── app/                 # Android App (Java/libsu)
│   └── src/main/
│       ├── AndroidManifest.xml
│       └── java/com/nhdd/app/MainActivity.java
├── third_party/
│   └── SoFixer/         # SO 文件修复工具 (F8LEFT)
│       ├── ElfReader.cpp
│       ├── ElfRebuilder.cpp
│       └── ...
└── nhddctl.sh           # Shell 控制脚本
```

## 编译

### nhdd (核心引擎)

需要 Android NDK (r25+):

```bash
# 设置 NDK 路径
export NDK=/path/to/android-ndk-r27
export CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang

# 编译
$CC -O2 -static -o nhdd nhdd.c

# 或使用 Makefile
make
```

### GUI 桌面程序

需要 Go 1.21+ 和 Fyne 依赖:

```bash
cd gui
go build -o nhdd-gui .
```

### Android App

需要 Android SDK + JDK 17:

```bash
./gradlew assembleDebug
```

或手动构建:

```bash
./build_manual.sh
```

## 使用方法

### 方式一：命令行（最简单）

```bash
# 1. 推送到手机
adb push nhdd /data/local/tmp/nhdd
adb shell chmod 755 /data/local/tmp/nhdd

# 2. 启动目标 app
adb shell monkey -p com.example.app -c android.intent.category.LAUNCHER 1

# 3. 等待 4 秒后 dump（关键！太长壳会卸载 DEX）
sleep 4
adb shell "/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump"

# 3b. 推荐用法：快照轮询，不依赖精确的 4 秒时机
#     多轮扫描，DEX 在内存里短暂存在也能抓到，自动跨子进程去重。
adb shell "monkey -p com.example.app -c android.intent.category.LAUNCHER 1 ; \
           /data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump \
           --snapshot 5 --interval 1"

# 4. 拉到本地（DEX 在 nhdd_dump/dex/，SO 在 nhdd_dump/so/）
adb pull /data/local/tmp/nhdd_dump/dex ./output

# 5. dump SO 文件
adb shell "/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --so"

# 6. 同时 dump DEX + SO
adb shell "/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --all"
```

nhdd 把结果分目录存放：`{out_dir}/dex/*.dex` 与 `{out_dir}/so/*.so`。
给定包名时会扫描所有匹配进程（主进程 + `:remote` 子进程）；给定数字 PID 时只扫该进程。

`--snapshot ROUNDS`：重复扫描 ROUNDS 轮（默认 1，即旧行为）。`--interval SECS`：每轮间隔秒数（默认 1）。快照模式下每轮会重新解析进程列表，能捕捉壳短暂加载的 DEX，且全程自动去重。

**推荐用法：`--watch` 监听模式（一代壳 ~100% 覆盖的关键）**
```bash
# 启动 app 后持续扫描，同时在手机上逐个点开各功能页
adb shell "monkey -p com.example.app -c android.intent.category.LAUNCHER 1 ; \
           /data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --watch"
```
`--watch [K]`：循环扫描，连续 K 轮（默认 3）无新 DEX 自动停。按需 lazy-load 的 DEX 会在你点开对应功能页时进内存、被自动捕获。安全上限 `--max-rounds`（默认 60）、`--max-seconds`（默认 120）。

**反检测**：对会杀进程的壳（如零跑），加 `--stealth`（区域间延时），或 `--region-delay MS` 自定延时；进程被杀后 watch 会自动重新解析新 PID 继续扫，不丢已抓结果。

### 方式二：Python 控制台

```bash
python3 nhdd_ctrl.py                    # 交互式选择 app
python3 nhdd_ctrl.py com.example.app    # 直接指定包名
```

自动完成：force-stop → 启动 → 4 秒等待 → dump → pull 到本地 → 修复校验和

### 方式三：GUI 桌面程序

```bash
cd gui && ./nhdd-gui
```

图形界面操作：输入 ADB 地址 → 选择 app → 点击 DUMP → 自动完成全流程

## 关键参数：等待时间

**等待时间必须控制在 4 秒左右**，这是脱壳成败的关键：

```
0s ──── 2s ──── 4s ──── 6s ──── 8s ──── 10s
  │       │       │       │       │        │
  │    壳开始解密  │    壳开始卸载 DEX   │
  │       │    ★ 最佳时机 ★      │        │
  │       │       │       │    DEX 已被清除 │
```

- **< 2 秒**：壳还没解密完，dump 出来的是加密数据
- **4 秒左右**：壳刚解密完，DEX 完整存在于内存中
- **> 6 秒**：邦邦加固等壳开始 dlclose 卸载 DEX，内存中找不到了

不同加固方案的卸载时机不同，建议 3-5 秒之间测试。

NHDD 的应对：
- **不注入** → 不触发 hook 检测
- **4 秒时机** → 在 dlclose 之前 dump
- **独立进程** → 不在目标进程内活动

## 与其他脱壳工具对比

| 特性 | NHDD | Frida-dexdump | FART | fdex2 |
|------|------|---------------|------|-------|
| 原理 | 外部读内存 | 注入 JS | 修改系统框架 | Hook ClassLoader |
| 被检测风险 | 无 | 高 | 中 | 高 |
| 需要 Root | 是 | 是 | 是 (Magisk) | 是 |
| 需要 Xposed | 否 | 否 | 是 (Zygisk) | 是 |
| 自动修复校验和 | 是 | 否 | 否 | 否 |
| SO dump | 是 | 否 | 否 | 否 |
| 邦邦加固 | ✓ | ✗ (被检测) | 部分 | ✗ |
| 360 加固 | ✓ | ✗ | 部分 | ✗ |
| 腾讯乐固 | ✓ | ✗ | 部分 | ✗ |

## 常见问题

### Q: dump 出来 0 个 DEX？

最常见原因：**等待时间太长**。壳在 app 启动后几秒内就会卸载 DEX。解决办法：
1. 改用快照轮询，不依赖精确时机：`nhdd <pkg> <dir> --snapshot 5 --interval 1`，它会从启动后立即多轮扫描，DEX 短暂存在也能抓到。
2. 若已用快照仍为 0，说明真实 DEX 可能装在子进程——给定包名时 nhdd 会自动扫所有子进程，确认传的是包名而非主进程 PID。

### Q: jadx 打开 DEX 报错？

NHDD 会自动修复校验和，但某些壳会修改 DEX 的其他字段。可以尝试：
```bash
python3 fix_dex_checksum.py your_dex.dex
```

### Q: pidof 返回多个 PID？

某些 app 有多个进程（主进程 + `:remote` 子进程）。给定包名时 nhdd 会**扫描所有匹配进程**（包括子进程，因为加固壳常把真实解密 DEX 装在子进程里）。也可以直接传入单个数字 PID 只扫该进程：
```bash
nhdd 12345 /data/local/tmp/nhdd_dump
```

### Q: APatch 下 libsu 无法执行 nhdd？

APatch 的 root shell 运行在 app 的 mount namespace 中，可能无法访问 `/data/local/tmp/`。解决方案：使用 `su -c` 在 root namespace 中执行，或通过 ADB 从电脑端操作。

### Q: 邦邦加固杀进程？

邦邦加固会间歇性检测 `/proc/PID/mem` 被读取。如果被杀，可以：
1. 多试几次（检测是间歇性的）
2. 缩短等待时间
3. 先启动 app，等它完全加载后再 dump（不用 force-stop 重启）

## 技术细节

### /proc/<pid>/mem 读取原理

Linux 内核为每个进程提供 `/proc/<pid>/mem` 接口，允许有权限的进程读取目标进程的虚拟地址空间。读取方式：

```c
int mem_fd = open("/proc/<pid>/mem", O_RDONLY);
pread(mem_fd, buffer, size, virtual_address);
```

`pread` 的 offset 参数是目标进程的虚拟地址，内核会将其转换为物理地址并返回数据。

### /proc/<pid>/maps 格式

```
7f8a001000-7f8a100000 r-xp 00000000 fd:00 12345 /data/app/.../base.apk
7f8a200000-7f8a300000 r--p 00000000 00:00 0      [anon:dalvik-...]
```

每行格式：`起始地址-结束地址 权限 偏移 设备 节点 路径`

NHDD 只扫描 `r`（可读）权限的区域，跳过不可读区域。

### DEX 文件格式

```
Offset  Size  Description
0x00    4     magic: "dex\n"
0x04    4     version: "035\0" 或 "037\0" 等
0x08    4     Adler32 checksum (覆盖 0x0C 到文件末尾)
0x0C    20    SHA-1 signature (覆盖 0x20 到文件末尾)
0x20    4     file_size
0x24    4     header_size = 0x70
0x28    4     endian_tag = 0x12345678
```

### ELF 文件格式

```
Offset  Size  Description
0x00    4     magic: \x7fELF
0x04    1     class: 1=32bit, 2=64bit
0x05    1     data: 1=LE, 2=BE
0x10    2     e_type: 3=ET_DYN (shared object)
0x20    8     e_phoff (64bit) / 0x1C 4B (32bit)
```

## License

MIT

## 作者与免责声明

- 作者：漫宿骄盛，weixiao
- GitHub：https://github.com/mansujiaosheng/NHDD

免责声明：本工具仅用于合法授权的安全研究、逆向分析与自有应用调试。使用者需确保已取得目标应用和设备授权。作者不对任何未授权使用、数据泄露、业务损失或法律责任负责。

