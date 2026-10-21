# NHDD v9.0.1 — Privacy cleanup

本次为发布隐私清理补丁，不修改 Android 采集、ART 回填或一致性安全检查。

- 移除 TUI、GUI 和项目 README 中的个人署名及旧个人仓库入口，统一到 Fruit-Guardians/NHDD。
- 删除硬编码开发者主目录；GUI 采用 Go/Wails `-trimpath` 构建，并扫描最终 EXE 和 ZIP。
- 新增源码元数据回归测试、二进制 UTF-8/UTF-16 隐私检查及可选私有拒绝列表。
- 保留 MIT LICENSE、字体及 Go/Wails/Vue/Android 运行库的第三方许可通知。

## 下载

| 包 | 用途 |
|---|---|
| NHDD-v9.0.1-android-arm64-v8a.zip | Root Android ARM64 CLI；API 34 起构建，沿用已验证引擎 |
| NHDD-v9.0.1-android-armeabi-v7a.zip | API 23 起构建；仅交叉编译，未做 ARMv7 真机验证 |
| NHDD-v9.0.1-tui.zip | Python 终端界面、修复/重打包辅助脚本和 ARM64 引擎；需 Python、rich、ADB |
| NHDD-v9.0.1-windows-amd64-gui.zip | Windows x64 GUI 和 ARM64 引擎；需 ADB、WebView2 Runtime |
| NHDD-v9.0.1-source.zip | 清理后的全仓库源码快照，不含 Git 历史、本地凭据或设备转储 |
| SHA256SUMS.txt | 全部 ZIP 的 SHA-256；各二进制/桌面包另有文件级校验与 BUILD-INFO.json |

GUI/TUI 未暴露所有 ART / event / spawn 参数，高级捕获请使用独立 CLI。
详见各包 README。Android 端仍需 Root 和目标内存读取权限；仅用于自有或明确获授权应用。

## 验证范围与限制

ARM64 引擎 SHA-256：`@ARM64_SHA@`；ARMv7：`@ARMV7_SHA@`。
引擎摘要与 v9.0.0 已验证构建一致，未以本次打包替代新的性能对照测试。
现有受控结果仍有 1ms 窗口漏捕；ART 依赖已适配 Build ID；16KiB 页设备未验证。
GUI 路径裁剪、构建元数据、发布 ZIP 内容及内部校验均需通过发布门禁；隐私扫描是启发式检查，不是绝对无泄露保证。

旧版本发布入口将按维护者确认的撤回方案处理；不会把新内容冒充旧版本构建，也不移动旧标签到新提交。
已被下载、fork、缓存的内容以及历史 Git author 信息不会因新版本发布自动消失。

源码 commit：`@COMMIT@`。项目许可证：@LICENSE_STATUS@。
