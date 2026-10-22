# 依赖安全修复与验证

审计日期：2026-10-22。基线为默认分支的 39 条开放 Dependabot 告警：7 Critical、10 High、20 Medium、2 Low。它们集中在少数依赖，不是 39 个独立组件。[逐项 GHSA、包和最低修复版本](dependency-advisories.json)已脱敏保存。

## 优先级与实际暴露面

7 条 Critical 全部位于 golang.org/x/crypto 的 SSH 路径，基线版本 0.33.0，最低修复版本 0.52.0。本次统一升至 0.58.0。

模块存在不等于正式 GUI 提供可利用的 SSH 服务。本次 desktop,production 依赖枚举未包含 crypto/ssh、Echo 或 Wails devserver；它们仍影响开发或构建依赖，所以没有忽略或手工 dismiss 告警。

| 依赖 | 基线 | 本次版本 |
|---|---|---|
| golang.org/x/crypto | 0.33.0 | 0.58.0 |
| golang.org/x/net | 0.35.0 | 0.61.0 |
| Echo v4 | 4.13.3 | 4.16.0 |
| Vue | 3.2.x | 3.5.44 |
| Vite / plugin-vue | 3.x / 3.x | 7.3.7 / 6.0.10 |
| PostCSS / nanoid | 旧锁文件版本 | 8.5.31 / 3.3.20 |
| source-map-js / esbuild | 旧锁文件版本 | 1.2.2 / 0.28.2 |

Echo 上游公告将完整修复标为 4.15.4，本次没有停在旧告警所列的 4.15.3。前端保留 Vite 7 主线，未为这次修复引入 Vite 8 打包器迁移。最低 Go 升为 1.26，Node 要求 20.19+ / 22.12+；验证环境为 Go 1.26.10、Node 24。

Wails CLI 固定为 Go tool，与 GUI 共用已修复模块图；发布脚本不再调用独立安装的旧 Wails CLI。

上游依据：[x/crypto 公告](https://github.com/advisories/GHSA-vgwf-h737-ff37)、[Echo 公告](https://github.com/labstack/echo/security/advisories/GHSA-vfp3-v2gw-7wfq)、[Vite 环境要求](https://vite.dev/guide/)。

## 回归与复查

- npm audit（包括开发依赖）：0；Go 模块级 govulncheck：0 findings；正式 Windows GUI EXE 二进制扫描：0 findings。结果对应扫描时的数据库，不是永久安全保证。
- 6 项 GUI 浏览器交互回归覆盖启动、连接与应用筛选、watch/JNI 参数、目录选择、完成/重打包显示、错误恢复。仅 Wails transport 使用测试替身，不连接真实 ADB。
- Go/Python 的 17 个修复样例和 7 个独立 CLI 样例保持冻结基线；Linux CI 另覆盖 C/C++ 宿主契约。
- Android 采集、ART 回填和安全一致性检查未改动；两个 ABI 的发布引擎仍严格匹配既有已验证摘要。
- Windows GUI 生产构建和去路径检查单独验证。README 截图为构建后前端的无设备浏览器预览，不冒充原生 WebView2 实测。

在 gui/frontend 运行：

```bash
npm ci --ignore-scripts
npm audit --audit-level=low
npm run build
npx playwright install chromium
npm run test:e2e
```

在 gui 运行：

```bash
go mod verify
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 -scan=module
go tool wails build -trimpath -ldflags "-s -w -buildid=" -m
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 -mode=binary build/bin/nhdd-gui.exe
```

不要通过关闭 Dependabot、降级扫描范围或手工标记修复来消除告警。推送后以 GitHub 对默认分支的重新分析为准。旧 Git 提交和旧下载不会因为新版本发布而自动升级。

## Go 依赖图提交

完整图刷新后，旧基线 39 项全部被 GitHub 标记为 `fixed`，同时新检出 18 项既有工具/间接依赖告警（6 High、8 Medium、4 Low），不是引入了 18 个新依赖。[新增 GHSA 基线](dependency-advisories-tools.json)单独保留，不改写旧基线。针对这组告警升级如下，并将版本下限加入回归检查：

| 模块 | 原版本 | 修复版本 |
|---|---|---|
| go-git/v5 | 5.13.2 | 5.19.2 |
| go-billy/v5 | 5.6.2 | 5.9.0 |
| x/image | 0.12.0 | 0.41.0 |
| CIRCL | 1.3.7 | 1.6.3 |
| Logrus | 1.9.0 | 1.9.3 |

这些版本覆盖 High 的路径越界、对象解析、图像解码资源消耗和日志 DoS，以及同组 Medium/Low 修复。不因依赖只用于工具/测试就将其排除。Go 漏洞库扫描与 GitHub Advisory/Dependabot 的覆盖及更新时间并不相同，前者 0 findings 不能替代后者的逐项核对。

如果 GitHub 的 Go 图任务仍停在旧提交，`.github/workflows/dependency-graph.yml` 会在默认分支的模块文件变更时，或手动运行时，提交与当前提交 SHA 绑定的完整模块快照。解析器使用 `go list -m -json all` 的 MVS 选定版本，并从 `go mod graph` 建立依赖关系；包含工具、测试和间接模块，不以生产 GUI 的 import 列表缩小范围。

任务先执行模块校验和漏洞扫描，再通过 [Dependency Submission API](https://docs.github.com/en/rest/dependency-graph/dependency-submission) 提交 `gui/go.mod` 的真实依赖，保存原始快照作为 CI 附件。只授予该任务 `contents: write`，不授予告警管理权限；缺失模块、解析错误、本地替换、未提交模块文件和非默认分支均拒绝提交。最终以 Dependabot 返回 `state: fixed` 和 `fixed_at` 为关闭证据，而不是以快照提交成功代替告警关闭。
