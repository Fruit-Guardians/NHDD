# NHDD @VERSION@ — Android Root CLI

No-Hook DEX / SO Dumper：进程外捕获 DEX、按 PT_LOAD 重建 SO，并对已适配 ART 构建做跨窗口方法恢复。仅用于自有或明确获授权的应用。

## 选择版本

本包 ABI：**@ABI@**，构建最低 API：**@API@**。

- arm64-v8a：Android 14 / API 34 起构建；Root Pixel 6 / Android 16 已验证。
- armeabi-v7a：Android 6 / API 23 起构建；仅完成交叉编译，未做 ARMv7 真机验证，不支持本轮 ARM64 ART profile。
- 这是 Android 设备上的独立 CLI，不是 Windows EXE、APK、Magisk 模块或 GUI/TUI 套件。不需要 Frida/Xposed；仍需要 Root 和系统允许读取目标内存。
- 按 ABI/API 构建不等于所有符合版本的设备都验证通过。ART 辅助发现依赖匹配的 libdexfile Build ID，未适配构建不能承诺擦头方法恢复。
- 本次 ELF 为 4KiB 页面布局构建；16KiB 页设备未适配/验证，不作兼容承诺。

## 校验与安装

先核对下载页的 SHA256SUMS.txt；本包内的 SHA256SUMS.txt 校验解压后的文件。二进制 SHA-256：`@BINARY_SHA@`。

Windows PowerShell：

```powershell
Get-FileHash ./nhdd -Algorithm SHA256
adb devices
adb shell "su -c id"
adb push ./nhdd /data/local/tmp/nhdd
adb shell chmod 755 /data/local/tmp/nhdd
adb shell /data/local/tmp/nhdd --help
```

上传会覆盖设备同路径的旧 nhdd；需要保留旧版时请更换安装路径。ZIP 解压后仍须 chmod，Windows 生成的 ZIP 不保证保存 Unix 可执行位。帮助页沿用内部版本名 `v9.0-cpp-class`，精确来源以 BUILD-INFO.json 的 commit 和二进制摘要为准。

## 常用命令

把 com.example.app 换成你自己或已获授权的应用包名；每次使用新的输出目录，避免默认清理旧产物：

```bash
# 基础 DEX / SO 提取
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_run01 --all'"

# 启动前布置事件并跟随包内进程；应用应先处于停止状态
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_run02 --dex --spawn --events auto --monitor-duration 60'"

# 已运行进程：快速局部捕获 + 已适配 ART 方法恢复
adb shell "su -c '/data/local/tmp/nhdd com.example.app /data/local/tmp/nhdd_run03 --dex --events auto --art-dex auto --monitor-duration 60'"

# 拉取结果
adb pull /data/local/tmp/nhdd_run03 ./nhdd_run03

# 离线结构校验，不执行待检代码
adb shell "/data/local/tmp/nhdd --verify /data/local/tmp/result.dex"
```

若 adb pull 权限不足，可在确认路径正确后用 Root 调整本次输出目录的读取权限。tracefs 不可用时 auto 会降级到 poll；快速捕获及安全 ART 回填不会在 poll 下假装生效。监测时长不是正在进行扫描的硬超时。

## 能力与限制

- DEX 多轮页面覆盖、缺页/revision 标记；ELF32/64 的 PT_LOAD/load bias 文件布局重建。
- mmap/mprotect/munmap/mremap 事件驱动捕获，`--spawn`、包内进程跟随。
- Build ID 绑定的 ART DEX 发现、擦头候选关联、完整方法双读、安全补集检查、多方法来源记录与冲突冻结。
- CompactDex/VDEX/OAT（含 OAT 279）格式检查与证据输出，不宣称通用还原为标准 DEX。
- 无注入不等于不可检测；双读相同不是原子快照；结构有效不等于方法已解密、SO 可重载或 APK 可重打包运行。
- 当前受控 Root 对照：1ms 方法 182/192→189/192；5ms 192/192→192/192，仍漏 3 个 1ms 方法。250µs 重试有额外空闲 CPU 成本；不是商业壳成功率保证。

源码 commit：`@COMMIT@`。

- [完整使用说明](https://github.com/Fruit-Guardians/NHDD/blob/@COMMIT@/NHDD-cpp-modular/README.md)
- [真机验证与剩余短板](https://github.com/Fruit-Guardians/NHDD/blob/@COMMIT@/NHDD-cpp-modular/docs/short-window-misses.md)
- [问题反馈](https://github.com/Fruit-Guardians/NHDD/issues)

项目许可证状态：**@LICENSE_STATUS@**。第三方运行库 notices 单独保存在 THIRD-PARTY/，不以它们替代项目自身许可证。
