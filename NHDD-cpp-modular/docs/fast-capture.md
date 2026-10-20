# 快速局部捕获与一致性检查

## 解决什么问题

原路径的线程只接收 trace 文本，主线程完成全量扫描后才解析事件并读目标内存。现在在采集线程先独立配对、校验目标 TGID/starttime，立即尝试两遍局部读取；主线程稍后只处理已经冻结在本工具内存中的字节，不需要原地址继续存活。

该路径不注入、不写目标内存、不暂停目标线程。不做平台，也不自动把不同时间的明文页拼成“完整 DEX”。

## 使用

```bash
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_fast_run --dex --continuous --events tracefs --fast-capture auto --fast-max-kb 1024 --monitor-duration 30'"
```

- `--fast-capture auto|off`，默认 auto，仅 continuous 的 tracefs 后端生效。不改变单轮 snapshot/watch。
- `--fast-max-kb 4..8192`，默认 1024。只取事件地址起始的有界前缀，**不是对整个 DEX 的大小承诺**。
- 配合 `--spawn` 在启动前布置；新进程仍需有可观测的包名/父子关系，不能保证跟上从未被发现的短命后代。
- `--events poll` 或 auto 回退轮询时，明确提示快速路径不可用。

## 时序与安全边界

1. 隔离 tracefs instance 设置 `buffer_percent=0`；采集线程最多等待 2ms 后也尝试非阻塞读取，避免依赖高水位唤醒。调度、内核缓冲和用户态读取仍可能更慢，2ms 不是时延保证。不修改全局 tracer、水位或 SELinux。
2. 可读 mmap / mprotect 成功退出、mremap 成功退出尝试读新范围；mprotect / munmap / mremap 进入阶段尝试读旧范围。entry 只是 best-effort 机会，既不保证系统调用成功，也不保证在 syscall 执行前完成读取。
3. 两遍各按 4KiB 块读取；优先 `process_vm_readv`，失败时尝试只读 `/proc/PID/mem`。后者在权限允许时也可能读到 PROT_NONE 页面，不应把“读到”解释为目标当时允许执行/读取。
4. 两遍读取前、两遍之间和完成后核对进程 starttime；数字 PID 固定在最初世代。失配整份拒绝。不是映射世代锁，metadata 明确 `mapping_identity_verified:false`。
5. 两遍共用 8ms **软**预算：在下一块读取前检查。单次系统调用、身份读取或调度等待可能超过它，不是硬超时。
6. 每秒最多安排 32MiB 双读字节；排队上限 32MiB / 512 份，主线程取走的批次最多另占 32MiB，另有当前观测与校验缓冲。单次运行快速产物上限 256MiB，接近上限时按保守预留提前拒绝。原有 DEX/SO 缓存、产物不计入这些限额。
7. raw trace 丢失、快速队列满、读取字节预算、进程失配、全不可读、磁盘限额和发布失败分别计数。`Event diagnostics: lost=0` 不代表快速路径没有丢弃；同时检查 `Fast capture`。

读取和少量页比较发生在采集线程；格式校验、修复、fsync、回滚式多文件发布都留在主线程。采集线程不是实时线程，高负载下仍可能错过窗口或导致 trace 缓冲溢出。

## 产物与一致性

`fast/fast_<进程世代/地址/采集器/时刻/序号>.*`：

- `.first.bin / .second.bin`：两遍局部原始观测，长度为实际安排的前缀。没有读到的字节填零，但只有 `pages[].first_read / second_read` 所列有效前缀是证据，不能把补零算覆盖。
- `.json`：触发 syscall/阶段、boot 时间、读开始/结束、event-to-read 时延、请求与截断长度、页级读取长度/变化字节数、进程校验和产物引用。
- 若某一遍**独立、完整包含**结构可识别的标准 DEX，另存 `.raw.dex / .fixed.dex`，记录两份的静态检查。单份 metadata 最多提取 64 个非重叠候选；不会读回现场补尾部，也不会把缺页补零当 DEX。

一致性按整个捕获前缀和每个 DEX 子范围分别标记：

| 标记 | 含义 |
|---|---|
| `two_reads_match` | 该范围两遍均完整且逐字节相同 |
| `changed_between_reads` | 该范围两遍完整，但至少一字节不同；两份原始证据都保留 |
| `partial_reads` | 至少一遍该范围有未读到的字节；页级仍记录共同有效部分的变化数 |

`truncated` 和 `deadline_hit` 是独立状态；“截取前缀双读相同”不等于“整个事件范围完整”。任何情况都标 `atomic_snapshot:false`、`cross_event_merge:false`。即便两遍相同，也不能排除每遍内部撕裂、映射 ABA 或两遍之间改变又恢复。

原始读取不依赖 DEX 头部，所以擦头/方法页也能作为 `.bin` 留证；**自动 DEX 提取仍需足够的标准头和结构，未接入 ART 候选局部回填或 CodeItem 语义重组**。`--art-dex only` 控制主扫描；独立快速路径仍可从冻结字节识别标准 DEX，纯 ART 对照请同时 `--fast-capture off`。

`DEX-observations` 是事件里的 DEX 观测数，不是去重 DEX 数，不并入主扫描的 `DEX=` 汇总。fast 证据按会话/时刻追加，不随常规旧产物清理；256MiB 是每次运行的发布上限，复用目录会累计。

## 受控真机复现

夹具 `tests/fast_window_probe.cpp` 只写自己的匿名页面：每轮放入独有 SHA-256 的 368B 有效测试 DEX，切成只读，维持约 1/5/20/50ms 后覆写并解除映射；每档 10 次。源堆中可能也存在 DEX，但统计必须同时匹配**窗口地址和完整字节 SHA-256**，不能拿堆副本或普通未加壳 APK 冒充短窗口命中。

1. 用 NDK ARM64 C++17 编译主程序和夹具（后者同样需 `-static-libstdc++`），部署为 `/data/local/tmp/nhdd_fast`、`/data/local/tmp/nhdd_fast_probe`，赋执行权限。
2. Windows PowerShell 在本目录运行（替换 serial；Name 必须新建、不与旧证据重名）：

```powershell
./tests/run_fast_window_device.ps1 -Name nhdd_fast_repro_on -FastCapture auto -Destination .test-bin/repro-on -Serial DEVICE_SERIAL
./tests/analyze_fast_window.ps1 -Directory .test-bin/repro-on
./tests/run_fast_window_device.ps1 -Name nhdd_fast_repro_off -FastCapture off -Destination .test-bin/repro-off -Serial DEVICE_SERIAL
./tests/analyze_fast_window.ps1 -Directory .test-bin/repro-off
```

加 `-RegionDelay 100` 可对照主扫描繁忙的压力条件，不能当作普通运行参数或行业捕获率基准。夹具自动退出，不需要结束其他 App 或按名字杀 app_process。

九组宿主测试覆盖稳定/变化/短读/洞/大小截断/世代失配/溢出/截止预算等反例。ARM64 设备也运行局部观测逻辑测试；ARMv7 只做交叉编译验证。

## 2026-10-20 Root Pixel 6 对照结果

Android 16 / SDK 36、KernelSU Root，SELinux 始终 Enforcing。最终 ARM64 二进制 SHA-256：`d5e861761f7c4a478be9848008480f14f395ad32f71dabcf34e4caf9e59ecbe0`，已部署 `/data/local/tmp/nhdd_root_next`。未向第三方 App 注入或改写内存。

每列是一轮独立运行、每档 10 次；“命中”要求地址与该轮 golden SHA-256 同时相符，不是数导出文件：

| 名义窗口 | 普通：快速关闭 | 普通：最终快速开启 | 延迟压力：快速关闭 | 延迟压力：最终快速开启 |
|---|---:|---:|---:|---:|
| 1ms | 0/10 | 10/10 | 0/10 | 8/10（其中 7 个有双读匹配副本） |
| 5ms | 0/10 | 10/10 | 0/10 | 10/10 |
| 20ms | 8/10 | 10/10 | 0/10 | 10/10 |
| 50ms | 10/10 | 10/10 | 0/10 | 10/10 |

普通最终运行的 40 个窗口均存在双读匹配副本，压力运行共 38 个字节哈希命中、37 个存在双读匹配副本；剩余 1 个只作变化中的原始证据，不算一致副本。压力条件为 `--region-delay 100`，用于让主线程忙于基线扫描。两次最终快速运行的 queue/budget/early-trace/disk/write failure 均为 0；全不可读尝试分别 122 / 153 次，包含已完成擦除/解除映射等时机，明确保留计数。

正向 DEX 观测的 event-to-read 时延 P50 / P95：普通 0.651 / 2.214ms，压力 1.313 / 5.336ms。它们只统计**成功观测**且一次窗口可贡献多个事件，不能推导全部事件的时延上界或真实壳成功率。夹具记录实际 begin/end；名义 1ms 不保证实际正好 1ms。开发中的其他轮次已出现 1ms 漏捕，不能将本轮 10/10 宣称为稳定保证。

另有两个反例：

- 最终普通运行实际记录到 2 份双读变化观测；压力运行也有 2 份，均保留 `atomic_snapshot:false / cross_event_merge:false`。某个变化范围中的独立完整 DEX 仍按其自身子范围标记，不把它升级成一致副本。
- `-Wide -FastMaxKB 4` 把 368B DEX 放在 8KiB 事件范围的 +3968，跨出 4KiB 前缀。155 份局部观测全部标截断，最大只保留 4096B，**快速路径没有发布任何 DEX**，没有把头部和零填充误报为完整文件。常规扫描另有自己的结果，不与快速片段混淆。

普通最终运行的 154 份 raw、154 份 fixed 事件 DEX 副本全部在设备上独立 `--verify` 返回 0，属于重复观测而非 154 份唯一 DEX。九组宿主测试、ARM64 设备逻辑测试、ARM64/ARMv7 严格交叉编译通过。

证据保存在本地 `.test-bin/device-smoke/fast-capture-20261020/`：`normal-off`、`normal-release`、`busy-off`、`busy-release` 和 `cap-wide`；源码提交不包含二进制和进程内存。该目录也保留了队列上限调整与限流回归的中间轮次，统计时不要混用它们。

技术依据：[Linux ftrace 水位与 trace_pipe](https://www.kernel.org/doc/html/next/trace/ftrace.html)。这里只使用本工具的隔离 instance；内核支持不等于实时捕获保证。
