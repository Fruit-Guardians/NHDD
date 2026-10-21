# Release 与 GitHub About

发布只打包当前 C++ Root CLI，不把旧 GUI/TUI 当作已适配新版的产品分发。保留真机验证的二进制，不临时 strip 或更改捕获策略；包内包含精确源码 commit、ABI/API、NDK、hash、使用说明及 NDK 运行库 notices。

## 构建

Windows PowerShell 7、Git、Android NDK 27.0.12077973：先提交本次打包文件，确保 src 没有未提交修改，再执行：

```powershell
./release/build-release.ps1 -Ndk E:/android/Sdk/ndk/27.0.12077973
./release/verify-release.ps1 -Directory dist/v9.0.0 -ExpectedCommit FULL_SOURCE_COMMIT
```

输出到忽略的 dist/v9.0.0，拒绝覆盖既有目录。ARM64/ARMv7 SHA 必须等于已验证构建，变化会直接失败。新版本需先验证新二进制，再显式传入预期 hash；不要用改 hash 参数绕过测试。源码 ZIP 从 Git 提交白名单导出，仅 C++ 模块及存在时的项目 LICENSE，不打包 .test-bin、设备内存、APK、凭据或未跟踪文件。

verify-release 会核对资产和包内 hash、ELF ABI、来源 commit、文件白名单及 notice，解压到独立临时目录并保留供检查。SHA-256 仅用于完整性核对，本轮没有给资产做独立密码学签名。

发布前：核对 ZIP 解压后的内部校验、安装后 help/verify、精确 target commit、许可证及第三方 notices。ARMv7 未实机验证，必须保留这一说明；API 起点是构建下限，不是跨设备测试承诺。正式发布前再决定是否先同步 main，不能把最新 dev 功能套到旧 main 的源码标签上。

## About

Description：

> No-hook DEX/SO dumper for rooted Android. ART-assisted DEX discovery, multi-window method recovery, and PT_LOAD ELF reconstruction.

Topics：android、android-security、reverse-engineering、dex、elf、memory-dump、unpacking、cpp17。

无独立官网时 Website 留空，不填写不存在的地址。当前 API 账号是 Maintain、不是 Admin；topics 可以更新，但 description PATCH 返回 404。请管理员在仓库首页右侧 About 齿轮填写上面的 description。不要为了此项扩大令牌权限或切换别人的账号。

## 许可证与草稿

项目 LICENSE 需由权利人明确选择，不能用运行库 notices 代替。未选择时包会标记未指定，只准备 Draft，不正式发布。现有 release/notes-v9.0.0.md 的草稿检查项也必须在确认完成后移除再发布。不要改动或覆盖已有 v8.0 资产。
