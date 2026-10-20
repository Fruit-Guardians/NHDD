# NHDD C++ Modular

NHDD 是一个面向 Android 进程内存的无注入 DEX / SO / JNI 提取工具。当前版本仍然保持单二进制、命令行工作流；本轮重点提升提取结果本身，不引入平台化组件。

## 本轮核心能力

### 1. DEX 多轮合并与完整度标记

- 以 `PID + 进程启动时间 + 地址 + maps backing/range 指纹 + DEX 大小 + 稳定头指纹` 标识候选，避免 PID 或虚拟地址复用串数据。
- 跨轮补齐缺失字节，并复查已覆盖页面；若壳在原地址继续解密，会生成新的内容寻址 revision，已落盘的旧 revision 不被覆盖。
- DEX magic/version、checksum、signature 与 file_size（`0x00..0x23`）的擦除或恢复只刷新这些易变头字节，不丢弃已捕获的正文覆盖；`0x24` 之后结构字段或正文的重叠变化仍会启动新字节世代，防止跨代拼接。
- 未完整时发布 `*.partial.dex` 和 `*.meta.json`；metadata 包含精确 hole 范围、字节覆盖率和页面完整度。
- 只有全部字节捕获完成后，才发布带内容哈希的 `*.raw.dex`、修复 checksum/header 的 `*.fixed.dex`，并参与内容去重；metadata 明确说明“完整”指字节覆盖完整。
- 候选缓存默认限制为 256 项、512 MiB，采用“完整且已处理候选优先、其余按 LRU”的分层淘汰；每个候选的 revision 去重历史同样有界，防止长时间扫描无界增长。

### 2. 基于 PT_LOAD / load bias 的 SO 重建

- 同时支持 little-endian ELF32 和 ELF64。
- 从内存 ELF header 和最低 `PT_LOAD` 推导 load bias。
- 按 `load_bias + p_vaddr` 读取远端内存，按 `p_offset` 写入重建文件。
- 输出大小取 `max(p_offset + p_filesz)`；不会把 BSS 的 `p_memsz - p_filesz` 错写入文件。
- 可跨多个 maps 恢复 segment，不再依赖 path/inode 聚合，因此能区分同一 APK 中的多个 SO 和同路径多实例。
- 每个对象输出重建 SO 和 JSON metadata，并在 PT_LOAD 远端跨度不超过 256 MiB 时附带原始 load-layout；稀疏地址布局超过该上限时只省略可选 raw 文件，不影响按受控 `p_offset + p_filesz` 范围生成重建结果。完整覆盖才命名为 `*.reconstructed.so`，存在缺页时只发布 `*.partial.so`，不会把残件伪装成完整结果。
- ELF header 和 program header table 本身属于强制恢复范围；metadata 以 `coverage_complete` 标记字节覆盖，并明确记录 live 读取的一致性模型。
- Section table 只有在 section 0、所有条目范围、非 `SHT_NOBITS` 数据、`shstrtab` 及名称都可验证时才保留；否则将 `e_shoff/e_shnum/e_shstrndx` 归零，同时在 metadata 保留归一化前的 header 哈希和原始三字段作为证据身份。
- SO 产物身份和文件名包含 `PID + process_starttime + ELF 地址 + evidence hash`；即使数字 PID、地址和内容被新进程复用，也不会误命中旧世代。raw layout 可用时，evidence hash 会混入其哈希；稀疏布局降级时则以 reconstructed hash 作为该分量的 fallback。两种情况都会继续混入归一化前的 ELF header/SHT 身份、恢复字节数与 holes，避免 section 字段被规范化后发生证据碰撞。
- SO 发布去重采用有界 LRU；命中会提升为 MRU，容量淘汰会计数并输出节流日志，长期 continuous 运行不会因表满后停止记忆而反复发布同一产物。

### 3. Continuous 增量扫描

- 结构与权限快照覆盖所有 maps，包括匿名、named-anon、memfd、APK-backed 和普通文件映射。
- 检测映射新增/删除、backing identity、权限变化、W→X，以及有预算的内容采样指纹变化。
- 进程身份使用 `PID + /proc/<pid>/stat starttime`；maps 快照在采集前后复核，扫描器在打开 maps/mem 后及扫描结束时再次校验，避免 PID 重用把不同进程世代混入同一轮。
- 包名目标可以跟随该包新启动的进程世代；直接指定数字 PID 时则固定在基线世代，目标退出或 PID 被复用后立即停止 continuous，绝不自动接管新进程。
- 同一轮中每个 PID 最多触发一次扫描，DEX / SO / JNI 共用合并后的变化范围。
- maps 差分中的删除事件不启动读取；tracefs 的 `munmap` entry 可额外尝试一次解除映射前读取，但目标不停顿，因此不保证地址在读取时仍存在。
- 内容变化检测优先采样匿名/memfd/APK、`[heap]`、ashmem、`/data/` 和可执行/XOM 映射，预算有剩余时再覆盖普通可读映射；默认每次快照总预算 256 KiB、每个位置 64 B，并显式标记为 sampled，不会被误报成全映射哈希。
- 每次快照和变化集记录内容采样是否请求/尝试、后端是否打开、是否实际可读、尝试与成功字节数、读取失败数和最后 errno。后端不可用或全部读取失败时会明确告警，但 maps 结构与权限监控仍继续运行。
- `timeline.jsonl` 为每个事件同时记录 before/after backing identity（range、权限、path、inode、device、offset）及本轮采样状态；写入会检查 `fflush`、`ferror` 和 `fclose`，失败会在控制台报告。新 continuous 会话默认先截断旧时间线，只有 `--keep` 才追加。

### 4. Root 冷启动、多进程与系统调用事件

- `--spawn` 为已停止的包解析 launcher activity，先启用事件源再执行 ActivityManager 启动；如果包已运行会报错。需要主动重启时使用 `--spawn-restart`，它会 force-stop 指定包。
- 两者自动启用 continuous；等待首个进程默认 15 秒，可用 `--spawn-timeout 1..300` 调整。没有 launcher activity 的包会明确失败。
- 包名按完整名称或 `package:subprocess` 边界匹配，每次调度最多间隔 100ms 重新发现进程；已经观测到的后代即使改名或被 reparent 也继续跟踪。世代由 PID/starttime 固定；从未观测到就已经退出的进程、在首次观测前改名且失去亲缘链的进程仍可能漏掉。
- `--events auto`（continuous 默认）尝试在 tracefs 创建专用 `instances/nhdd_<writer_pid>`，订阅 `raw_syscalls` 的 mmap/mprotect/munmap/mremap；不修改全局 tracer 或其他实例。`--events tracefs` 要求内核后端成功，否则返回错误；`--events poll` 显式使用轮询。
- 启动前尚无目标 PID 时会临时收集这些系统调用，再按目标进程身份筛选；发现目标后配置线程 PID 过滤，并使用 `event-fork` 继承新线程/后代。Android ARM64 支持原生及兼容 ARM32 syscall 编号；ARMv7 构建支持 ARM32，Linux x86_64 支持原生 syscall。
- 成功 syscall 的 entry/exit 按 TID、TGID/starttime 和 boot 时间配对，失败返回值不产生成功事件。相邻范围合并成一次增量扫描；即使 maps 恢复原状且抽样哈希未变，也保留 syscall 触发范围。mmap 重用、munmap、mremap 旧地址会失效对应 DEX 合并缓存。
- 专用读取线程在大对象扫描期间继续排空内核缓冲；用户态队列上限 16MiB、单批输出最多 8192 个事件。丢失/溢出会报告并执行全量补扫，不能补回已经消失的短暂明文窗口。
- 时间线增加 `memory_syscall` 事件，记录 syscall、enter_best_effort/exit_success、boot 时间、地址、权限及旧映射范围。SIGINT/SIGTERM 正常退出时停止并移除本工具 tracing instance；SIGKILL/系统崩溃无法执行清理，可能留下本工具实例。

### 5. DEX 结构检查与 ART 格式识别

- 完整 DEX 的 metadata schema 为 2，同时记录原始和 fixed 副本的 `semantic`。验证标准 DEX 035/037/038/039/040 的 header/map_list、表范围/重叠、索引、MUTF-8 字符串、type_list、class_data/成员归属、code_item/try/catch 和 debug_info 引用边界，并分别核对 SHA-1/Adler32。
- 结构检查有独立工作预算，耗尽时明确失败。`structural_checks_passed` 仅表示这些静态检查通过，不包含完整指令/类型验证、完整 annotation/encoded-value 图验证或 ART 装载验证；`art_accepted` 始终为 null，`bytecode_type_verified` 为 false。DEX 041 container 暂标 unsupported，不猜测解释为旧格式。
- DEX 扫描同时识别并保留应用/匿名内存中的 CompactDex、VDEX 和 OAT 证据。CompactDex 001 检查扩展头、ID 表与共享数据范围；不转换为标准 DEX。VDEX 006/010/019/021/027 检查版本对应的 section 布局，并列出内嵌 DEX/CDEX 偏移和检查结果；普通 DEX 扫描也会提取其中的 DEX。
- OAT 170/195/230/259/262/265/275/279 检查版本对应的 header、key/value 和可验证的偏移；运行时只保存明确命名的 `*.oat-header.bin`，不将 header 片段冒充完整 OAT。OAT 编译代码通常还需要配套 VDEX/DEX，当前不做反编译还原或反 quickening。
- OAT 279 按实机确认的 72 字节固定头解析；处理 `apex-versions`（1024 B）、`dex2oat-cmdline`（2048 B）的值预留区，检查终止符、长度及零填充。检查 ISA、DEX 目录最小范围、代码区/BCP/trampoline 偏移；完整 ELF 输入还核对 `base_file_offset` 与实际 payload 位置。JSON 的 `oat_header` 输出头长、KV 长度/实际键值对数、目录和代码偏移；偏移基准为 OAT header，换算 ELF 文件偏移需加 `base_file_offset`。这些检查不验证完整 OatDexFile 目录、编译指令或重定位语义。
- 未知版本保留有限 header 证据并标记 unsupported；单个 runtime-format 声明范围超过 64MiB 时降级 header-only。内存缺页会标记 invalid/incomplete，不能成为格式验证成功。系统/APEX/vendor runtime 格式默认不额外导出；普通 DEX/SO 行为沿用原策略。
- `--verify FILE` 不需要设备或 root，输出 JSON：退出码 0 为所声明检查通过、2 为无效/不完整、3 为未知格式/版本、1 为 I/O 错误。标准 DEX 的退出码还要求 SHA-1 和 Adler32 均通过；metadata 的结构状态和这两个完整性标志独立表达，便于识别运行时合法修改。支持 ELF 文件中的 OAT payload 定位，报告其 payload_offset；不执行待检代码。

对应布局依据：[AOSP DEX 格式](https://source.android.com/docs/core/runtime/dex-format)、[CompactDex](https://android.googlesource.com/platform/art/+/refs/heads/main/libdexfile/dex/compact_dex_file.h)、[VDEX](https://android.googlesource.com/platform/art/+/refs/heads/main/runtime/vdex_file.h)、[OAT](https://android.googlesource.com/platform/art/+/refs/heads/main/runtime/oat/oat.h)、[Linux tracefs](https://docs.kernel.org/trace/ftrace.html)。

## 构建与测试

Android ARM64：

```bash
make android ANDROID_CXX="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang++"
```

Android ARMv7 可改用 `armv7a-linux-androideabi23-clang++`。默认链接参数为 `-static-libstdc++`。

宿主逻辑测试：

```bash
make test
```

`make test` 需要 GNU make 和 POSIX shell（Linux、WSL 或 MSYS2）；在原生 PowerShell 中也可直接用同等的 `g++` 命令编译 `tests/*.cpp`。

七组宿主测试覆盖原有 DEX/ELF/maps/manifest，以及包名边界/后代改名/PID 复用、syscall 配对/失败返回/范围溢出、DEX 引用损坏、格式版本与截断输入。`tests/device_capture_probe.cpp` 是单独编译到设备的受控 mmap/mprotect/mremap/munmap 与改名子进程测试夹具。`tests/oat279_device_probe.cpp` 只读映射设备实际 OAT 279，并以排他创建方式另存头部及三种损坏副本（KV 长度、base offset、trampoline），不改写原文件；输出前缀必须未使用，映射保留 20 秒供扫描。

2026-10-20 在已连接的 Root Pixel 6 上验证真实 ART `boot.oat`：`--verify` 通过，payload offset 1592、固定头 72 B、KV 3979 B / 11 对、DEX 数量 21，与设备自带 `oatdump --header-only` 一致；只读映射的跨进程捕获完整保存 4051 B header/KV，并与源文件头部逐字节一致。三种真实文件损坏副本均以退出码 2 拒绝。此记录证明该设备样本的布局兼容，不等于所有厂商 OAT 279 变体均已验证。原始日志和 JSON 位于本地 `.test-bin/device-smoke/oat279-20261020/`（不纳入 Git）。

## 常用命令

```bash
# DEX
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --dex --watch 3 --relaxed --stealth2'"

# DEX + SO
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --all --watch 3 --relaxed --stealth2'"

# 映射、权限或采样内容变化时增量扫描
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --all --continuous --monitor-interval 2 --stealth2'"

# DEX / SO / JNI 一起增量扫描
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_dump --all --jnimap libjiagu.so --continuous --stealth2'"

# 冷启动并跟随包内多进程，要求真实内核事件后端
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_spawn --spawn --all --events tracefs --monitor-duration 30'"

# 正在运行的包：明确要求 force-stop 后重新启动
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_restart --spawn-restart --dex --events auto --monitor-duration 30'"

# 离线检查（也可在 Android 上运行）
./nhdd --verify captured.fixed.dex
./nhdd --verify captured.vdex
```

`--monitor-duration 0` 表示持续运行；非零秒数限制监控调度时长，但正在进行的对象扫描会完成后再退出。100ms 发现间隔也不是实时延迟保证，大对象扫描/调度压力会增加延迟。

## 权限边界

当前 standalone CLI 扫描任意 release 第三方应用通常需要 root。`--stealth2` 只把内存读取后端切换为 `process_vm_readv()`，不会绕过 ptrace、UID 或 SELinux 权限检查。未 root 环境仅可能对 debuggable 自有应用通过 `run-as` 以同 UID 运行；当前版本尚未实现 JNI / in-process self 模式。

## 输出

```text
nhdd_dump/
├── dex/
│   ├── *.partial.dex        # 未完整，hole 以占位字节保存
│   ├── *.raw.dex            # 完整原始内存内容
│   ├── *.fixed.dex          # 完整且已修复 header/checksum 的分析副本
│   ├── *.meta.json          # 状态、覆盖率、页面统计、holes、raw/fixed 结构检查
│   ├── runtime_*.cdex / *.vdex # 原生 ART 格式证据（不反 quickening）
│   └── runtime_*.oat-header.bin / *.json # OAT header 证据及格式检查
├── so/
│   ├── *.raw.bin            # 内存 load-layout 证据
│   ├── *.reconstructed.so   # 按 PT_LOAD 文件布局重建
│   ├── *.partial.so         # 存在未恢复 hole 的重建残件
│   ├── *.json               # load bias、segments、holes、进程世代、证据哈希
│   ├── anon_<pid>_g<starttime>_<addr>.bin # 可选的匿名可执行段证据
│   └── manifest_<pid>_g<starttime>.json   # 世代隔离；continuous 保留累计与 last_scan
├── maps/
│   └── maps_<pid>_g<starttime>.txt        # 启用 maps 保存时生成
├── jnimap/
│   ├── jnimap_<pid>_g<starttime>.jsonl
│   └── fnptrs_<pid>_g<starttime>.jsonl
└── timeline.jsonl           # continuous 变化时间线
```

`manifest_<pid>_g<starttime>.json` 的顶层计数字段在当前 `nhdd-so-scan-v3` schema 内保持单轮/continuous 兼容：普通 snapshot/watch 表示当前单轮；continuous 表示同一 `PID + process_starttime` 会话累计发布数，其中 `maps` 始终是最近一次实际扫描的映射数。continuous 另外提供 `session.totals` 和 `last_scan`：前者是会话累计，后者记录最近一次实际扫描的序号、增量范围和本轮发布数。只有 removed 事件而没有可读当前范围时不会启动扫描，因此也不会增加 `scans_completed`。

扫描期间一旦 starttime 消失或变化，本轮不会提交 manifest，计数会回滚，后续候选也会停止发布。扫描轮不是覆盖全部输出的全局事务：在较早检查仍稳定时，已经通过读前/读后及发布前/发布后守卫的独立证据产物会保留，并带有其 PID/starttime 身份。SO/DEX 产物 stem 中的 starttime 使用十六进制；manifest、maps、JNIMAP metadata 与 timeline 中使用十进制 ticks。

## 代码结构

核心实现为 C++17 header-based 单翻译单元：

- `src/dex_capture.hpp`：多轮 DEX 覆盖合并与候选缓存。
- `src/dex_semantics.hpp`：有预算的 DEX 结构/引用/code/debug 边界检查。
- `src/runtime_formats.hpp`：CompactDex/VDEX/OAT 版本与布局检查。
- `src/syscall_events.hpp`：独立 tracefs instance、读取线程、syscall 配对与事件时间线。
- `src/process_tracking.hpp`：包名边界与进程世代/后代关系跟踪。
- `src/elf_reconstructor.hpp`：ELF 校验、load bias 计算与 PT_LOAD 重建。
- `src/so_artifact_identity.hpp`：SO 进程世代隔离、证据哈希与安全文件名。
- `src/so_manifest.hpp`：跨平台的 SO 会话累计模型与原子 manifest 发布。
- `src/process_generation_guard.hpp`：扫描期间黏性的 PID/starttime 世代校验与发布守卫。
- `src/maps_monitor.hpp`：进程世代快照、变化检测和增量范围生成。
- `src/nhdd_scanner.hpp`：DEX / SO / JNI 单 PID 扫描编排。
- `src/nhdd_app.hpp`：CLI、多进程、watch 和 continuous 调度。
- `tests/`：不依赖 Android 设备的核心逻辑测试。

## 已知边界

- SO 重建需要内存中仍保留可验证的 ELF header 和 program headers；完全擦头后的对象暂不做猜测式恢复。
- SO 不反向撤销 GOT/动态重定位，也不虚构 section headers；metadata 会保留缺失范围。
- SO 采用运行中进程读取；metadata 的 `snapshot_consistency: "best_effort_live"` 表示 `coverage_complete=true` 只证明目标字节均被读到，不承诺这些字节来自冻结后的单一时刻。
- Continuous 对所有 maps 做结构/权限 diff；内容检测按上述优先级采用首/中/尾位置的有预算采样，预算耗尽后可能有映射未被采样，不等价于逐字节全图比较。
- Continuous 的内容采样失败不会阻止结构/权限事件检测；请以日志与 timeline 中的 `content_sampling.available`/`sampled_bytes` 判断该轮是否具备内容变化观测能力。
- `--keep` 只保留既有产物并追加 timeline，不会恢复上次进程内的 monitor baseline、DEX capture、去重表或 manifest 累计，也无法观测工具停机期间的变化。
- JNIMAP 的主要目标仍是 Android ARM64；DEX/ELF 核心逻辑和主程序同时通过了 ARM64、ARMv7 交叉编译检查。
