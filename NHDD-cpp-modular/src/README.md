# NHDD v9.0-cpp-class — C++ Class-Based Modular Architecture

No-Hook DEX/SO/JNI Dumper for Android ARM64. 无注入 · 反检测 · 壳对抗。

## 架构升级

| 维度 | v8.0 (C 单体) | v8.1-cpp (inc模块) | **v9.0-cpp-class (本次)** |
|---|---|---|---|
| 语言 | C99 | C++17 | C++17 |
| 代码组织 | 单文件 2003行 | 1 main + 9 inc | **11 类, 11个头文件** |
| 职责分离 | 函数级别 | 模块级别 | **类级别 (封装+接口)** |
| 可测试性 | 低 | 中等 | **高 (类可独立测试)** |
| 扩展性 | 低 | 中等 | **高 (继承/组合)** |

## 类层次结构

```
NhddApp (CLI调度)
  ├── NhddScanner (PID扫描编排)
  │     ├── ProcessMemory (远程内存读取: pread / process_vm_readv)
  │     ├── MapsParser (解析 /proc/pid/maps)
  │     ├── ObjectClassifier (路径分组 → 来源/类型/策略分类)
  │     ├── DexValidator (DEX校验/修复/大小恢复)
  │     ├── SHA1 (SHA-1 哈希, header-only)
  │     ├── SoDumper (SO dump + ELF修复 + SHT重建 + manifest)
  │     └── JniMapScanner (无hook JNINativeMethod扫描)
  ├── DedupTable (三个独立去重表: DexDedup/SoDedup/JniDedup)
  ├── ProcessManager (进程查找/伪装/cmdline读取)
  └── NhddConfig (全局配置单例)
```

## 核心类说明

### `NhddConfig` (单例)
全局配置：stealth延迟、vm_readv开关、relaxed模式、JNIMAP过滤等。

### `ProcessMemory`
封装两种远程内存读取方式：
- `pread_retry()` — 传统 `/proc/pid/mem` 读取 (重试+分页)
- `vm_readv_retry()` — `process_vm_readv(2)` 系统调用 (stealth2)

### `MapsParser`
解析 `/proc/<pid>/maps` → `MapsRegion[]` 数组，自动分组匿名/文件映射。

### `ObjectClassifier`
三步分类：
1. **group_by_path_inode** — 按 path+inode 聚合为 MappedObject
2. **classify_origin** — 路径推断来源 (APP_APK/DATA/ANON/SYSTEM/APEX/VENDOR)
3. **classify_kind** — 文件头推断类型 (ELF_SO/DEX/OAT/APK_ZIP/...)
4. **decide_policy** — 决策dump策略 (SKIP/DUMP_MERGE/DUMP_AND_FIX)

### `DexValidator`
全静态方法：DEX格式校验、大小恢复 (map_list遍历)、header校验、SHA-1/Adler32修复。

### `SoDumper`
SO dump + 内建ELF修复：
- `dump_by_maps()` — 按maps偏移读取SO分段
- `repair_basic()` — 修复 p_offset=p_vaddr、e_type、SHT重建
- `extend_to_cover_load_segments()` — 覆盖所有PT_LOAD段
- `write_manifest()` — 输出 JSON manifest

### `JniMapScanner`
无hook JNINativeMethod扫描器。在可读写内存区域扫描 JNINativeMethod 三元组 (name/signature/fnPtr)，输出 JSONL 格式。

### `NhddScanner`
单PID扫描编排器。协调 DEX/SO/JNI 三种扫描模式，处理去重和汇总。

### `NhddApp`
CLI入口 + 参数解析 + 多轮/多进程调度循环。

## 构建

### 前置条件
- Android NDK r27+ (aarch64-linux-android34-clang++)

### Android 交叉编译
```bash
# 设置 NDK 路径
export NDK=$HOME/Android/Sdk/ndk/27.2.12479018
export CXX=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang++

# 编译
make android
# 或直接:
$CXX -O2 -std=c++17 -Wall -Wextra main.cpp -o nhdd -static-libstdc++
```

### Host 语法检查 (Linux)
```bash
make host
# 或: g++ -O2 -std=c++17 -Wall -Wextra main.cpp -o nhdd_host
```

### 推送与测试
```bash
make push          # 推送到 /data/local/tmp/nhdd
adb shell /data/local/tmp/nhdd    # 查看用法
```

## 使用示例

```bash
# 按包名 DEX dump
/data/local/tmp/nhdd com.example.app /data/local/tmp/dump --dex

# SO dump (stealth2 + relaxed)
/data/local/tmp/nhdd com.example.app /data/local/tmp/dump --so --stealth2

# 全量 dump (DEX + SO)
/data/local/tmp/nhdd com.example.app /data/local/tmp/dump --all --stealth2 --relaxed

# JNI map 扫描 (过滤特定库)
/data/local/tmp/nhdd com.example.app /data/local/tmp/dump --jnimap libnative-lib.so

# Watch 模式 (持续扫描直到3轮无新增)
/data/local/tmp/nhdd com.example.app /data/local/tmp/dump --all --watch 3 --stealth2

# 直接按 PID 扫描
/data/local/tmp/nhdd 12345 /data/local/tmp/dump --dex

# 反检测全开
/data/local/tmp/nhdd com.example.app /data/local/tmp/dump \
  --all --stealth --stealth2 --relaxed --anon \
  --region-delay 5 --name "kworker/u16:2"
```

## 命令行参数

| 参数 | 说明 |
|---|---|
| `--dex` | 仅 DEX dump |
| `--so` | 仅 SO dump |
| `--all` | DEX + SO 全量 dump |
| `--jnimap [LIB]` | JNI method 扫描, 可选库名过滤 |
| `--stealth` | 区域延时 + 自动伪装 |
| `--stealth2` | process_vm_readv 读取 (避免 /proc/pid/mem) |
| `--relaxed` | 宽松 DEX 扫描 (endian_tag 替代 magic 检测) |
| `--anon` | 仅扫描匿名映射 |
| `--watch [K]` | 持续扫描到 K 轮无新增 |
| `--region-delay MS` | 区域间延时 (ms) |
| `--name NAME` | 伪装进程名 |

## 测试结果

真机测试 (OnePlus 9 / LineageOS 21 / ARM64):

```
目标: com.dahua.leapmotor (零跑)
进程: 2 个 (21118, 28654)
DEX: 1 唯一 (27987844 bytes), 8 命中 / 7 去重
SO:  10 个 dump, 10/10 ELF 修复成功
状态: 无崩溃, 无内存泄漏
```

## 文件清单

```
src_oop/
├── main.cpp              # 入口
├── common_types.hpp      # 公共类型/枚举
├── nhdd_config.hpp       # 全局配置单例
├── sha1.hpp              # SHA-1 实现
├── dedup_table.hpp       # DEX/SO/JNI 去重表
├── process_memory.hpp    # 远程内存 I/O
├── dex_validator.hpp     # DEX 格式校验修复
├── process_manager.hpp   # 进程管理
├── maps_parser.hpp       # maps 解析
├── object_classifier.hpp # 对象分类
├── so_dumper.hpp         # SO dump + ELF 修复
├── jnimap_scanner.hpp    # JNI 扫描
├── nhdd_scanner.hpp      # PID 扫描编排
├── nhdd_app.hpp          # CLI 应用
└── Makefile              # 构建配置
```

## 设计决策

1. **Header-only**: 所有类实现在 .hpp 中, main.cpp 单次 include 编译。避免链接复杂性, 保持单二进制部署。
2. **静态方法为主**: 多数类使用纯静态方法 (无状态工具类), 仅在需要保持状态的类中实例化 (如 DedupTable, ProcessMemory)。
3. **C++17**: 使用 `constexpr`、`static inline`、structured bindings 等现代特性。
4. **向后兼容**: CLI 接口与原 C 版本完全一致, TUI 无需修改即可使用。

## 后续计划

- [ ] 单独的 .cpp 实现文件 (拆分编译单元)
- [ ] CMake 构建系统
- [ ] 单元测试 (Google Test)
- [ ] CDEX 格式支持
- [ ] Carrier 模式 SO 修复 (以原 APK SO 为骨架)
