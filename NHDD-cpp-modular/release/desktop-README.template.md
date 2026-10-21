# NHDD @VERSION@ — @KIND@

仅用于自有或明确获授权的应用。项目：<https://github.com/Fruit-Guardians/NHDD>。

包内 `nhdd` 是 **Android ARM64 / API 34+ 的 Root CLI**，不是 Windows 程序。
Windows GUI/TUI 通过 ADB 操作该引擎；不需要 Frida/Xposed，不代表不可检测。
高级 ART / events / spawn 参数尚未全部接入桌面 UI，请使用独立 CLI。

## 校验与准备

核对 Release 的 SHA256SUMS.txt；包内另有文件级 SHA256SUMS.txt。
从官方 Android SDK Platform-Tools 获取 ADB 并放到 PATH。连接自有 Root 设备，确认：

```powershell
adb devices
adb shell "su -c id"
```

GUI：Windows x64，安装 Microsoft Edge WebView2 Runtime 后启动 `nhdd-gui.exe`。
选定 ADB、设备和获授权的应用，再启动提取。GUI 会上传包内引擎。

TUI：安装 Python 3.10+ 和 rich，先手动上传引擎，再运行终端界面：

```powershell
python -m pip install rich
adb push ./nhdd /data/local/tmp/nhdd
adb shell chmod 755 /data/local/tmp/nhdd
python ./nhdd_tui.py --version
python ./nhdd_tui.py
```

上传会覆盖设备上同路径的旧工具。不要把本包文件与旧版引擎混用。
生成的分析 APK 不签名，不承诺可重打包运行；结构有效也不代表所有方法已经解密。
本包不附带 Python、ADB、WebView2 安装器或设备转储。ARMv7、16KiB 页设备未验证。

GUI 使用 `-trimpath` 构建，移除本机源码路径；保留依赖模块路径和合法第三方署名。
不是隐藏所有函数名或匿名化 Git 历史的保证。

源码 commit：`@COMMIT@`。项目采用 MIT，见 LICENSE；第三方许可见 THIRD-PARTY/。
