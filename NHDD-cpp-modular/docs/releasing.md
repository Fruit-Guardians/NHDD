# Release 与 GitHub About

发布包含两个 Android ABI 包、TUI、Windows GUI 和全仓库源码。控制端不代表已覆盖 CLI 全部高级参数。保持已验证的 Android 引擎摘要，不临时更改捕获策略；桌面依赖升级后重新构建、扫描和验证。所有包记录 commit、ABI/API、hash、使用说明和所需第三方 notices。

## 构建

Windows PowerShell 7、Git、Android NDK 27.0.12077973、Go 1.26+、Node 24：先提交本次打包文件，确保工作树源码无未提交修改。设置 ANDROID_NDK_ROOT 指向自己的 NDK，再执行：

```powershell
./release/build-release.ps1 -Ndk $env:ANDROID_NDK_ROOT -Version 9.0.2 -Destination dist/v9.0.2
./release/build-desktop.ps1 -ReleaseDirectory dist/v9.0.2 -Go (Get-Command go).Source
./release/verify-release.ps1 -Directory dist/v9.0.2 -ExpectedCommit FULL_SOURCE_COMMIT
```

输出目录必须是新的忽略目录，拒绝覆盖已有证据。ARM64/ARMv7 SHA 必须等于已验证构建，变化直接失败；不要用改 hash 参数绕过测试。源码 ZIP 从精确 Git 提交导出，包含当前 GUI/TUI 和许可证，不打包 .test-bin、设备转储、凭据或未跟踪文件。GUI 使用 Go tool Wails 和 trimpath，禁止回退到独立旧 CLI。

verify-release 会核对资产和包内 hash、ELF ABI、来源 commit、文件白名单及 notice，解压到独立临时目录并保留供检查。SHA-256 仅用于完整性核对，本轮没有给资产做独立密码学签名。

发布前：核对 ZIP 解压后的内部校验、安装后 help/verify、精确 target commit、许可证及第三方 notices。ARMv7 未实机验证，必须保留这一说明；API 起点是构建下限，不是跨设备测试承诺。本次用户已确认 MIT，并要求先合并 dev 到 main；正式包、tag 和 Release target 必须统一指向合并后的 main 提交。

## About

Description：

> No-hook DEX/SO dumper for rooted Android. ART-assisted DEX discovery, multi-window method recovery, and PT_LOAD ELF reconstruction.

Topics：android、android-security、reverse-engineering、dex、elf、memory-dump、unpacking、cpp17。

无独立官网时 Website 留空，不填写不存在的地址。当前 API 账号是 Maintain、不是 Admin；topics 可以更新，但 description PATCH 返回 404。请管理员在仓库首页右侧 About 齿轮填写上面的 description。不要为了此项扩大令牌权限或切换别人的账号。

## 许可证与正式发布

用户已选择 MIT，根目录 LICENSE 是项目授权，第三方组件保留各自的许可证与 notices。构建器要求已提交的 MIT LICENSE，两个二进制包、源码包和 BUILD-INFO 都必须带有匹配授权信息；旧的未指定许可证草稿包仅留作本地历史，不正式发布。

先更新 Draft 的 target、说明与全部资产，核对远端 digest，再创建指向 main 的 v9.0.0 tag 并发布。仅替换本次未发布草稿的同名资产，不改动 v8.0。正式发布后不覆盖已发布资产或移动 tag，应发新版本。
