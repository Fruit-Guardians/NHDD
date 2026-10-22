# NHDD v9.0.2 — Dependency security & concise docs

本次为主机端依赖安全补丁。优先修复基线中的 7 条 Critical，并覆盖其余 Go/npm 告警；不改动 Android 采集、ART 方法恢复或安全一致性规则。

- x/crypto 0.58.0、x/net 0.61.0、Echo 4.16.0；Wails 构建工具共用已修复模块图。
- Vue 3.5.44、Vite 7.3.7、plugin-vue 6.0.10，刷新存在漏洞的传递依赖。
- npm audit、Go 模块与 GUI EXE 扫描无已知命中；新增 6 项 GUI 浏览器交互回归及持续安全检查。
- 根 README 从约 470 行精简到 81 行，加入架构图、真实前端预览和终端入口图；详细用法仍保留。
- 保留 MIT、字体及 Go/Wails/Vue/Android 所需第三方通知，不包含私有设备转储。

## 下载

| 包 | 用途 |
|---|---|
| NHDD-v9.0.2-android-arm64-v8a.zip | Root Android ARM64 CLI；API 34 起构建 |
| NHDD-v9.0.2-android-armeabi-v7a.zip | API 23 起构建；仅交叉编译，未做 ARMv7 真机验证 |
| NHDD-v9.0.2-tui.zip | Python TUI、辅助脚本和 ARM64 引擎；需要 Python、rich、ADB |
| NHDD-v9.0.2-windows-amd64-gui.zip | 重建的 Windows x64 GUI 和 ARM64 引擎；需要 ADB、WebView2 Runtime |
| NHDD-v9.0.2-source.zip | 全仓库源码；GUI 构建需要 Go 1.26+、Node 20.19+ / 22.12+ |
| SHA256SUMS.txt | 所有 ZIP 的摘要；包内另含文件级校验和 BUILD-INFO.json |

Android 引擎摘要保持不变：ARM64 `@ARM64_SHA@`；ARMv7 `@ARMV7_SHA@`。本轮不是新的 1ms/5ms 真机性能对照，原有 ART Build ID、短窗口漏捕及 16KiB 页设备限制仍适用。

GUI/TUI 未暴露全部高级 CLI 参数。截图及浏览器测试不替代原生 WebView2 或真实设备捕获验证。旧版本下载不会自动获得此次修复。

源码 commit：`@COMMIT@`。项目许可证：@LICENSE_STATUS@。仅用于自有或明确获授权的应用。
