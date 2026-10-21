# NHDD v9.0.0 — Android Root CLI

本次发布聚焦独立 C++17 脱壳/运行时提取工具，不包含旧 GUI/TUI，也不是平台。

## 主要能力

- DEX 多轮页面补齐、完整度与内容 revision 记录。
- ELF32/64 按 PT_LOAD / load bias 重建 SO 文件布局。
- 启动前事件跟踪、包内多进程跟随；映射、权限、内容变化增量扫描。
- 快速局部双读、ART 辅助擦头 DEX 发现与关联回填。
- 同 DEX 多方法跨窗口安全合并，冲突冻结与逐方法来源记录。
- CompactDex / VDEX / OAT 格式证据与离线校验，含 OAT 279。

## 下载与使用

| 包 | 用途 |
|---|---|
| NHDD-v9.0.0-android-arm64-v8a.zip | 首选；API 34 起构建，Root Pixel 6 / Android 16 真机验证 |
| NHDD-v9.0.0-android-armeabi-v7a.zip | API 23 起构建；仅交叉编译，未做 ARMv7 真机验证，不支持本轮 ARM64 ART profile |
| NHDD-v9.0.0-source.zip | 本次 C++ CLI 源码快照，不包含本地设备转储或旧 GUI 套件 |
| SHA256SUMS.txt | 下载资产校验值；各 ZIP 内另含文件级校验与 BUILD-INFO.json |

解压后按包内 README 安装：`adb push nhdd /data/local/tmp/nhdd`、`adb shell chmod 755 /data/local/tmp/nhdd`，再用 `su -c` 运行。无需 Frida/Xposed，仍需 Root 和目标内存读取权限。

本次二进制为 4KiB 页面布局构建，16KiB 页设备未适配/验证。

## 已验证的范围

三组共 12 轮受控测试：1ms 方法恢复 182/192→189/192；5ms 保持 192/192；逐轮发布排队 P95 均值 2484ms→2367ms。安全负例、15 组宿主测试、9 组原生测试通过；三份完整自建副本在新 ART 进程执行全部 64 个方法。

仍有 3 个 1ms 方法漏捕，250µs 重试增加空闲 CPU 开销。ART 路径依赖已适配 Build ID；不保证全 Android/全壳兼容，不把双读、结构校验或格式识别当作完整脱壳。

源码 commit：@COMMIT@。ARM64 二进制 SHA-256：@ARM64_SHA@；ARMv7：@ARMV7_SHA@。

项目许可证：@LICENSE_STATUS@。

仅用于自有或明确获授权的应用；遵守适用法律及第三方权利。无注入不等于不可检测。

草稿检查项：确认项目许可证；决定是否先把 dev 合并到 main；确认 About description 管理员设置。完成前不正式发布。
