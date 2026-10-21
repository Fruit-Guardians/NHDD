# 发布前隐私与署名检查

2026-10-21 的检查区分“个人公开署名/本机路径”和“凭据泄露”，不把公开第三方许可证作者信息当成密钥，不删除必要的版权或许可通知。

## 本轮已清理的工作树内容

- TUI Logo、普通启动 banner 及 `--version / -v` 不再输出个人作者信息；仓库入口统一为 Fruit-Guardians/NHDD。
- GUI 页脚移除个人署名和旧个人仓库链接，Wails 配置不再带个人 author 字段。
- 中英文根 README 的个人作者列表改为项目入口；MIT LICENSE 和第三方署名保留。
- 删除 Go 模块配置里的本机路径注释；C++ Shell 构建脚本改读 NDK / ANDROID_NDK_HOME / ANDROID_NDK_ROOT，不再默认某个开发者的主目录。
- 增加本地环境文件、签名材料、运行日志的忽略规则，不追溯删除既有文件，也不把测试 APK/转储加入版本控制。

显示测试不会连接真实 ADB；覆盖 Logo、版本、帮助输出、GUI 配置与文档入口。GUI 前端编译成功；Shell 脚本语法、缺少 NDK 的明确失败路径通过。

## 审计结果和限制

初次清理后的 184 个已跟踪工作树文件，在本轮启发式规则中未发现常见 GitHub/AWS/Slack/API key、私钥格式、可疑硬编码密码/密钥赋值或硬编码个人主目录。新增审计/测试代码另有自检，不在测试中重新写入已移除的身份。发布前会对实际纳入提交的全部文件重扫，数量以当次工具输出为准。

本地全部 refs 可达历史包含 89 个提交、517 个 blob；命中 49 处旧个人作者字段或主目录路径（同一文件在不同 blob 中分别计数），还存在 7 组 Git author 姓名/邮箱身份。未命中上述凭据格式，但不是完整密钥扫描，也不能证明没有未知格式或外部存储中的泄露。工具只输出类别、文件/行号、blob 短标识，不回显匹配值。

另检查 GUI Logo 的 PNG/XMP：有编辑软件元数据，无 EXIF 标签，未命中本机主目录或 GPS 字段；不据此宣称已识别所有图像元数据中的潜在个人信息。第三方字体许可与 Wails runtime 包中的公开作者/邮箱未删除。

GitHub v8.0 发布说明仍有旧 Authors 段和旧个人仓库地址；v9.0.0 发布说明未发现这两类信息。但既有 v9.0.0 tag、GitHub 自动生成的源码归档仍指向修改前快照，不能因为当前文件清理而声称所有已发布下载已匿名化。手工上传的 v9 C++ 源码包不包含 TUI/GUI，与 GitHub 全仓库自动归档不是同一个范围。

### v9.0.1 发布补丁

- `build-desktop.ps1` 固定 Wails `-trimpath`、`-s -w` 和禁用本机 VCS 构建标记，读取最终 EXE 的 Go build info 确认去路径选项，而非只检查源码。
- TUI 包包含修复与重打包所需脚本；GUI 包带 Go/Wails/Vue、字体和 Android 运行库 notices。两者使用同一经过摘要校验的 ARM64 引擎，不改变采集逻辑。
- `audit_release.py` 只读 ZIP 和二进制 UTF-8/UTF-16 内容；`--deny-file` 可传入不入库的已知身份/构建根目录列表。报告不显示匹配值；不执行被检查的 EXE，也不解压 ZIP。
- 每个二进制/桌面 ZIP 有完整文件级 SHA-256，Release 有资产级 SHA-256；源码包由提交快照生成，不包含 `.git` 历史。
- 旧发布的说明、附件及标签按维护者明确确认的撤回范围处理；不把补丁内容替换到旧标签上。Git 历史未改写，既有 fork、下载及外部缓存不能保证删除。不能把发布清理称为全历史匿名化。

若今后发现真实凭据，应先撤销/轮换，而不是仅删文件。公开第三方作者/模块路径以及 MIT 通知保留，不属于本轮删除目标。

## 复查

在仓库根目录、装有 rich 的 Python 环境运行：

```bash
python3 tests/test_public_metadata.py
python3 scripts/audit_publication.py
python3 scripts/audit_publication.py --history
python3 tests/test_release_privacy.py
python3 scripts/audit_release.py path/to/release.zip
```

Windows 可用 `py -3.12` 替代 python3。`--history` 当前会因为旧公开信息而返回 1，不意味着新修改失败；不要为了通过检测删改规则或直接重写历史。可加 `--json` 获取不含匹配值的结构化报告。

该工具不连接外部服务、不验证凭据是否有效、不扫描本地忽略的设备转储、不自动修改任何文件。日志、maps、设备列表和原始 dump 可能包含目标包名、设备序列号、内存或私有路径，分享 issue/测试证据前仍需单独脱敏。
