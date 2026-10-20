# NHDD 源码模块

主项目说明见 [`../README.md`](../README.md)。源码保持 C++17 header-based 单翻译单元部署方式，入口为 `main.cpp`。

## 主要模块

| 文件 | 职责 |
|---|---|
| `nhdd_app.hpp` | CLI、多进程、watch / continuous 调度 |
| `nhdd_scanner.hpp` | 单 PID 的 DEX / SO / JNI 扫描编排与增量 scope 接线 |
| `dex_capture.hpp` | DEX 候选身份、多轮字节覆盖合并、holes 与页面完整度 |
| `art_dex_discovery.hpp` | Build ID 绑定的 ARM64 StandardDexFile 对象特征发现、运行时缓存表交叉校验与有界堆扫描 |
| `dex_validator.hpp` | DEX 校验、大小恢复、SHA-1 / Adler32 修复 |
| `dex_semantics.hpp` | DEX raw/fixed 结构和引用检查，明确不等价于 ART 验证 |
| `runtime_formats.hpp` | 版本化 CompactDex/VDEX/OAT 检查及内嵌对象偏移；含实机验证的 OAT 279 头/KV/偏移检查 |
| `process_tracking.hpp` | 包名精确边界、改名后代和 PID/starttime 世代跟随 |
| `syscall_events.hpp` | tracefs 独立实例、后台采集、系统调用 entry/exit 配对 |
| `fast_capture.hpp` | 可注入读取器的两遍局部观测、逐页有效前缀、变化与缺页检查 |
| `fast_capture_service.hpp` | 采集线程读取、独立目标身份校验、有界队列与主线程证据发布 |
| `art_refill.hpp` | 保守 code_item/指令布局、方法片段规划、双遍补集核对与映射 backing 对比 |
| `art_refill_service.hpp` | 不可变 ART 基线注册、捕获锚点、映射/丢失失效、带来源的跨时刻重建发布 |
| `art_method_merge.hpp` | 代际绑定的多窗口方法证据、内容去重、版本冲突冻结、已知版本补集核对 |
| `art_merge_publication.hpp` | 跨窗口副本/冲突清单的预算与回滚式发布，保留逐方法来源 |
| `elf_reconstructor.hpp` | ELF32/64 program header 校验、load bias、PT_LOAD 重建与 metadata |
| `so_artifact_identity.hpp` | SO 的 PID/starttime 世代身份、raw/header evidence hash 与产物命名 |
| `so_manifest.hpp` | 与 Android 内存 API 解耦的 SO manifest 会话累计和跨平台原子发布 |
| `dedup_table.hpp` | DEX/SO/JNI 去重表；SO 使用命中提升的有界 LRU 并统计淘汰 |
| `maps_monitor.hpp` | 全 maps 快照、权限/W→X/采样内容变化检测和增量范围生成 |
| `maps_parser.hpp` | `/proc/<pid>/maps` 解析 |
| `jnimap_scanner.hpp` | 无 hook `JNINativeMethod` 表扫描 |
| `process_memory.hpp` | `pread` / `process_vm_readv` 远程内存读取 |
| `common_types.hpp` | 公共类型、变化原因和 `ScanScope` |

`so_dumper.hpp` 是旧实现的兼容保留源码，当前扫描流程不再调用它；实际 SO 输出统一经过 `ElfReconstructor`，不会再对 raw dump 做原地“修复”。

## 关键不变量

1. Partial DEX 绝不修 checksum，也不作为完整结果参与内容去重。
2. DEX 候选按进程世代与映射身份隔离；单轮观测先暂存，内容换代时丢弃旧世代未复验字节，再继续跨轮补洞。旧的完整 revision 保留；缓存采用 complete-first 的有界分层 LRU。
3. ELF 远端地址使用 `load_bias + p_vaddr`，文件写入位置使用 `p_offset`。
4. ELF 文件范围使用 `p_filesz`，BSS 不写入重建文件。
5. ELF header / program headers 属于完整度范围；有 hole 的产物只能命名为 `*.partial.so`，metadata 的 `snapshot_consistency: "best_effort_live"` 表明 `coverage_complete` 不代表冻结快照一致性。稀疏 PT_LOAD 的远端跨度超过 raw 上限时，仅禁用连续 raw-layout 文件，受输出上限约束的 reconstructed image 仍正常生成。
6. ELF section table 仅在结构、引用和所需文件字节均可安全解析时保留；无法证明时归一化 SHT 三字段，并保留归一化前 header 身份供 evidence hash 使用。
7. SO 产物按 `PID + process_starttime + 地址 + evidence hash` 隔离；raw layout 可用时 evidence 包含其哈希，稀疏降级时该分量使用 reconstructed fallback；归一化前 header/SHT 身份、恢复字节数和 holes 始终参与 evidence，SO 去重表采用有界 LRU。
8. Continuous 周期性对全 maps 做结构/权限 diff，并由 syscall 事件额外唤醒；内容指纹必须标明 sampled。munmap 的进入阶段仅提供 best-effort 读取机会，完成后的删除事件只失效缓存。
9. tracefs 使用专用实例，不修改 root tracer；失败/溢出显式报告。未成功的系统调用不发布成功事件，事件丢失后补扫无法恢复已消失的明文。
10. 字节完整、静态结构检查、ART 运行时验证分别表达。未知格式版本不猜测；CDEX/VDEX 不冒充已转换/反 quickening 的标准 DEX，OAT header 不冒充完整 OAT。
11. 快速路径先保存两次独立观测，不跨事件拼接。双读一致不是原子快照，缺页补零不算有效字节；单次读到的完整 DEX 可留证，但必须保留它自己的双读一致性和 raw/fixed 检查结果。该路径不改变主扫描去重计数。
12. ART 关联回填是独立的 temporal composite：同一对象/结构世代固定首次基线，普通正文刷新不换基线；每个片段须来自单个事件中双读匹配的完整 insns，补集双遍重验。跨窗口合并仅接纳已落盘的独立回填证据；相同内容去重，不同版本冻结整个代际，保留两种来源且不选赢家。合并发布另作两遍结构/已知方法版本检查；映射事件或已观测 trace 丢失使旧基线和所附合并状态一起失效。原始片段和单事件副本不被覆盖，不反写主缓存或目标。全零替换拒绝，其他字节也不自动认作明文。

## 验证

在仓库根目录执行：

```bash
make test
```

交叉编译请使用根目录 Makefile 的 `ANDROID_CXX` 参数。
