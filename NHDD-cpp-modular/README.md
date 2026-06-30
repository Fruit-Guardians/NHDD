# NHDD C++ Modular

这是基于当前 `nhdd_jnimap.c` 迁移出来的 C++17 模块化版本。核心目标是：**先保留原有稳定行为，再按功能拆分，方便后续继续工程化重构。**

本版本保留：

- DEX 扫描与 dump
- DEX header / SHA-1 / Adler32 修复
- SO maps 分类、dump、基础 ELF 修复
- watch / snapshot / stealth / stealth2 / relaxed / anon
- 新增的无 hook `JNIMAP` 扫描：外部扫描 `JNINativeMethod` 表，恢复 `methodName + signature -> fnPtr / so offset`

## 目录结构

```text
src/
├── main.cpp                     # 单翻译单元入口，include 各功能模块
└── core/
    ├── nhdd_common.hpp           # 公共结构、常量、全局配置
    ├── dedup.inc.cpp             # DEX/SO/JNI 去重表
    ├── memory_io.inc.cpp         # /proc/<pid>/mem 与 process_vm_readv 读取
    ├── dex_format.inc.cpp        # DEX 校验、大小恢复、checksum 修复
    ├── process_utils.inc.cpp     # 包名/PID 解析、自伪装
    ├── maps_classifier.inc.cpp   # /proc/<pid>/maps 解析与对象分类
    ├── so_dump_repair.inc.cpp    # SO dump、ELF repair、manifest
    ├── jnimap_scanner.inc.cpp    # 无 hook JNINativeMethod 扫描
    ├── scanner.inc.cpp           # 单 PID 扫描主流程
    └── app_main.inc.cpp          # CLI 参数解析与多进程/轮询调度
```

> 说明：现在采用“单翻译单元 + 功能 include 文件”的迁移方式。这样可以最大限度保留原始 C 版调用顺序和 `static` 作用域，减少因为拆成多翻译单元导致的符号依赖问题。后续可以继续把 `.inc.cpp` 逐步改成真正的 `.cpp/.hpp` 类模块。

## Android 编译

推荐：

```bash
export ANDROID_NDK_HOME=~/Android/Sdk/ndk/<你的NDK版本>
./build_scripts/build_android.sh
```

或者直接用 Makefile：

```bash
make android CXX=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang++
```

如果 `-static-libstdc++` 在你的 NDK 环境报错，可以去掉：

```bash
make android LDFLAGS=
```

## Host 语法检查

```bash
make host
./nhdd_host
```

我已在 Linux host 上用 `g++ -std=c++17` 做过编译检查和 `--help` smoke test。

## 常用命令

DEX 默认扫描：

```bash
adb shell "su -c '/data/local/tmp/nhdd com.xxx.xxx /data/local/tmp/nhdd_dump --watch 3 --relaxed --stealth2'"
```

DEX + SO：

```bash
adb shell "su -c '/data/local/tmp/nhdd com.xxx.xxx /data/local/tmp/nhdd_dump --all --watch 3 --relaxed --stealth2'"
```

无 hook JNIMAP，针对 360 / libjiagu：

```bash
adb shell "su -c '/data/local/tmp/nhdd com.xxx.xxx /data/local/tmp/nhdd_dump --jnimap libjiagu.so --stealth2 --jni-min 20'"
```

DEX/SO/JNIMAP 一起跑：

```bash
adb shell "su -c '/data/local/tmp/nhdd com.xxx.xxx /data/local/tmp/nhdd_dump --all --jnimap libjiagu.so --watch 3 --relaxed --stealth2 --jni-min 20'"
```

JNIMAP 输出：

```text
/data/local/tmp/nhdd_dump/jnimap/jnimap_<pid>.jsonl
```

示例字段：

```json
{"name":"sendDynamic","sig":"(...)Ljava/lang/Object;","fn":"0x7a1234b9ec","module":"libjiagu.so","offset":"0xb9ec"}
```

## 当前迁移原则

这不是推倒重写，而是第一阶段 C++ 化：

1. 保留原始算法和行为；
2. 先按功能拆分；
3. 用 C++17 编译通过；
4. 后续再逐步引入 `std::string`、`std::vector`、RAII 文件句柄、真正的类模块。

这样可以避免一次性重构破坏你现在已经能稳定复现的脱壳能力。

## 2026-06-25 fix note

This package fixes a regression in the C++ refactor that could make DEX/SO scanning incomplete:

- corrected DEX header strong validation field order;
- made remote reads retry-aware in the main DEX scanner;
- fixed anonymous/inode-zero SO matching after synthetic `anon_xxx` grouping;
- preserved `--jnimap` when `--dex/--so/--all` appears later in CLI arguments;
- fixed `src/Makefile` source path for building inside `src/`.

## JNIMAP performance notes

This build optimizes `--jnimap` by filtering `fnPtr` against executable ranges before reading remote strings, caching repeated C strings, limiting generic table-region size, and printing progress while scanning.

Recommended fast command:

```bash
adb shell "su -c '/data/local/tmp/nhdd com.xxx.xxx /data/local/tmp/nhdd_dump --jnimap libjiagu.so --jni-min 20 --stealth2 --snapshot 1'"
```

If the table is dynamically allocated in a large heap and the fast scan misses it, broaden the scan:

```bash
adb shell "su -c '/data/local/tmp/nhdd com.xxx.xxx /data/local/tmp/nhdd_dump --jnimap libjiagu.so --jni-min 1 --jni-max-region 128 --jni-full --stealth2 --snapshot 1'"
```
