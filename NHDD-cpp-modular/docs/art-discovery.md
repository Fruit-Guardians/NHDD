# ART 辅助 DEX 发现

返回[使用说明](../README.md)。该路径在目标进程外只读运行时信息，不注入、不 Hook，也不主动加载类或执行目标业务方法。

## 本版实现

1. 从目标 maps 找到 ARM64 `libdexfile.so`，读取内存中的 ELF / PT_NOTE，提取 GNU Build ID。
2. 仅对已确认的 Build ID 启用布局适配：当前为 `6c74f468d6ad7d6bfeb957fe266a05b0`。当前设备 Android 16 / SDK 36；**不能据此推断所有 Android 16、同 OAT 版本或所有 ARM64 设备都兼容**。
3. 虚表符号 `_ZTVN3art15StandardDexFileE` 在该二进制的相对地址为 `0x3c2d8`，对象虚表 address point 为 `+16`。用实际 ELF 基址换算 ASLR 地址，验证虚表位于该库的非可写映射，前两个函数指针指向该库的可执行映射。
4. 有预算地扫描 writable native heap 的对齐指针，优先 scudo primary。匹配虚表后，交叉检查对象基址、data range、header 指针，以及六张缓存表指针与 DEX 的 ID 表偏移。
5. 验证声明范围由可读映射覆盖、表范围、map_list 自引用/排序/唯一性，以及 map/header 表项一致性。对象和头部均重复读取，变动时拒绝该候选。
6. 将原始内存字节交给现有 DEX 多轮捕获和 raw/fixed 发布流程。发布前后的对象检查沿用 PID/starttime 世代守卫；每次重读 ART 候选也复核当前库 profile。

这是 **StandardDexFile 原生对象特征扫描**，不是 ClassLinker / DexCache / ClassLoader 注册链的完整枚举。它不能证明对象仍被注册或方法已解密；已释放但内容尚未被覆盖的对象也可能留下符合条件的候选。metadata 使用 `discovery.source: art_standard_dexfile` 表达发现证据，而非 ART 装载或业务语义验证结果。

## 降低了哪些头部依赖

在运行时对象仍提供可信范围、其余结构仍可交叉验证时，可以发现 magic / version / checksum / signature / file_size / header_size / endian 被置零的 DEX；真机夹具覆盖前 `0x2c`（44）字节全部置零。

仍要求 map_off、ID 表、class_defs、data 范围及 map_list 等结构保留，至少三张非空 ID 表可交叉验证。**不支持 112 字节头全部擦除、脱离文件范围的方法体、CompactDex 或 DEX 041 container 的 ART 对象恢复**。支持标准 DEX 的独立、连续 data range；长度上限 256 MiB。

raw 保留擦除状态；fixed 由现有修复流程填写 file_size/header_size/endian 和校验值。若版本丢失，分析副本合成为 039，并标记 `magic_version_synthesized: true`；这不是恢复了原始版本。所有修复只发生在导出副本中，目标内存不被写入。

## 运行与预算

```bash
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_art --dex --art-dex auto --snapshot 3'"
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_art_only --dex --art-dex only --snapshot 2'"
```

- `auto`（默认）：先尝试 ART 发现，再执行原有扫描。未知 profile、32 位读取端或未映射 libdexfile 会明确记录原因。
- `off`：不启用 ART 发现。
- `only`：不执行 magic/endian/container 搜索，适合对照验证；无兼容 profile 时没有该路径产物，不自动 fallback。
- `--art-scan-mb 1..512`：native-heap 扫描预算，默认每进程每轮 64 MiB。对象检查和候选 DEX 读取不计入这个堆扫描预算。
- 预算耗尽时记录 `budget_exhausted=true`；按 PID/starttime 保留游标，并交替重访高优先级堆与继续剩余映射。单轮 snapshot 不保证遍历全部 native heap。
- 日志记录 build_id、heap_read、匹配/拒绝/接受数、读取失败和预算状态；接受数是对象数，可能多个对象指向同一 DEX，不等于唯一 DEX 数。
- continuous 沿用现有事件/采样触发调度，不保证纯堆写入立即触发扫描。需要持续复查时可选多轮 snapshot/watch；现阶段仍不能保证短暂明文窗口。

ART 候选首次接入时记录对象、虚表与 Build ID。已由 header 扫描发现的候选保持原始来源，不追改已有 metadata。所有内存读取仍是 best-effort live，不是冻结快照。

continuous + tracefs 下可将已发现的完整 ART 候选用于[快速片段关联回填](art-refill.md)，默认 `--art-refill auto`。此路径另存方法级 temporal composite，不将其冒充原始整份内存观测；只验证发现能力时使用 snapshot，或额外 `--fast-capture off`。

默认 `--art-merge auto` 在同一不可变 ART 基线上继续积累多个窗口的完整方法证据，并记录来源/冲突；对象、映射或进程代际失效后不得沿用旧片段。它不会扩大支持的 ART Build ID 或恢复已破坏的方法布局。

## Root 真机验证

2026-10-20，当前 Root Pixel 6：

- 现有 App 的只读 ART-only 扫描命中 27 个应用侧 StandardDexFile 候选对象（包含指向相同 DEX 的多个对象），得到 23 个地址候选、22 份去重且字节完整的 DEX。其中 21 份 fixed 通过当前静态检查，1 份记录 `debug_special_pc_bounds/class_definition` 失败，保留证据但不计为验证通过。该结果说明真实 ART 布局和虚表锚点有效，不代表这些 App 有壳。
- 自建夹具先通过真实 `dalvik.system.DexFile` 打开 744 B 的 payload，再仅擦除该进程私有映射前 44 B。普通扫描（含 `--relaxed`）未命中该地址；auto 找到并完整发布。
- 最终二进制以 `--art-dex only --snapshot 2` 再次捕获擦头 payload，第二轮仍可复核同一对象。未擦头对照也通过。整个流程没有使用伪造的运行时对象冒充真机证据。
- raw 的前 44 B 全为零；fixed 的第 44 B 之后与原始 payload 逐字节相同；fixed 的独立 `--verify` 通过。原始磁盘 DEX 的 SHA256 未变。
- 宿主反例覆盖未知 Build ID、错误虚表映射/函数指针、错配缓存表、无效范围、损坏 map、带 tag 指针、对象读间变动与预算续扫；ART 测试同时在 ARM64 设备运行。

日志与导出样本位于本地 `.test-bin/device-smoke/art-discovery-20261020/`（不提交）。这些测试不等同于商业壳覆盖率评估。

## 受控夹具复现

源码：`tests/ArtDiscoveryProbe.java`、`tests/ArtDiscoveryPayload.java`、`tests/art_discovery_probe.cpp`。需要 JDK、Android SDK 的 android.jar / d8，以及 NDK。

1. 将两个 Java 文件编译到临时 classes 目录，并分别用 d8 生成 probe 与 payload DEX。
2. 将 native helper 编译为 ARM64 shared library，使用 `-fPIC -shared -static-libstdc++`，避免依赖设备没有的 `libc++_shared.so`。
3. 将它们分别部署为 `/data/local/tmp/nhdd_art_probe.dex`、`/data/local/tmp/nhdd_art_payload.dex`、`/data/local/tmp/libnhdd_art_probe.so`。
4. 启动下面的独立测试进程；它打印 PID / payload 地址并保留对象 90 秒。用该 PID 扫描。`normal` 参数代替 `erase` 则是不擦头对照。

```bash
adb shell "su -c 'CLASSPATH=/data/local/tmp/nhdd_art_probe.dex app_process /system/bin ArtDiscoveryProbe /data/local/tmp/nhdd_art_payload.dex /data/local/tmp/libnhdd_art_probe.so erase'"
```

helper 仅在自己的进程内匹配指定文件的 private 映射，临时开放写权限并置零前 44 B，再恢复为只读。不修改原始文件，也不接触第三方 App。不要把该测试 helper 注入其他应用。

布局参考：[AOSP DexFile](https://android.googlesource.com/platform/art/+/refs/heads/main/libdexfile/dex/dex_file.h)、[AOSP DexFile 实现](https://android.googlesource.com/platform/art/+/refs/heads/main/libdexfile/dex/dex_file.cc)。当前 profile 另经设备实际 Build ID、导出符号、构造函数反汇编与真实对象交叉核对；不能只看 AOSP main 就套到设备上。
