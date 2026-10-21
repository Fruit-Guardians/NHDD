# 1ms / 5ms 漏捕定位与多方法恢复

2026-10-21，Root Pixel 6 / Android 16 / SDK 36。沿用自建 DexFile/JNI 夹具：64 个不同方法各只解密一次（32 个 1ms、32 个 5ms），间隔 2ms，头部前 44B 擦除。不执行被修改的现场 DEX，不注入其他应用。

## 证据与改动

重查[上轮](capture-contention-fix.md)六个新版测试的六个未恢复方法：全部缺少 golden 方法字节的完整双读。两个记录区间没有捕获覆盖，四个虽相交却没有匹配字节；不是累计合并丢掉了已证明方法。新增 `analyze_capture_misses.ps1` 区分无覆盖、相交但字节不匹配、仅单读匹配、双读匹配却未恢复四类。它是自建夹具诊断；逐字节来源/合并验证仍由 `analyze_art_merge.ps1` 完成。

fixture begin 记录在写入及 mprotect 返回之后，end 在擦除之后；相交不证明实际读到明文，边沿之前也可能已有有效观测。新增 JSON `line_received_boot / acquire_begin_boot / anchors_done_boot / acquire_end_boot`，结合已有读起止时刻分离各阶段延迟。line_received 是单行回调开始，event→line 包含内核交付、调度和前序回调，不能据此认定某个内核函数是唯一根因。

本轮只改采集开销和调度：

- 早期采集用 `ppoll` 做 250µs 有界空读重试，替代可能跨过整个 1ms 窗口的 2ms 重试；非早期事件源仍为 100ms。不是实际唤醒时延保证。
- 仅工具自己的采集 TID nice 比继承值提高 2（最低 -20），退出恢复。查询/调整失败告警并继续原权限采集。不使用实时调度，不改目标、主线程、发布线程或 CPU affinity。
- 数值 PID 固定世代后，每条事件新打开 `/proc/<leader>/task/<tid>/stat` 验证成员关系；仍新鲜核对 leader starttime、cmdline、目标集合及 ELF ABI。没有 TGID/身份/FD 缓存；包名及包内多进程仍用原 status/父进程/包名路径。
- `process_vm_readv` 失败后才打开本次观测的 mem FD，保留 pread 降级、短读前缀及全部 guard；观测结束关闭 FD。
- fresh 队列仍至少 32 项才归并中间累计发布，revision 批次从 8 改为 16；每个方法独立证明仍立即完整校验并提交。空闲 flush、冲突立即冻结和每次实际发布的实时检查均不变。

没有删减锚点、双读、双遍补集、ART profile、实时映射/身份、未知版本拒绝、事务 guard/fsync/回滚。统一 512 项/32MiB 在途、32MiB/s 捕获、64MiB 校验周期、256MiB 输出、四次尝试不变。`atomic_snapshot / plaintext_proven / mapping_aba_excluded` 仍为 false。

## 探索结果不删除

每组均为旧/新/新/旧，目录在 `.test-bin/` 下；不是最终验收数据：

| 目录 | 比较 | 对照两轮恢复 | 候选两轮恢复 |
|---|---|---|---|
| w250a | 已发布版 vs 仅重试+计时 | 64、61 | 62、63 |
| wmem1 | 已发布版 vs 再加成员查找/延迟打开 mem | 62、62 | 63、62 |
| wn2a | 上一候选 vs 再加采集 nice -2 | 63、61 | 64、63 |

候选 SHA-256 依次为 `ef6bf3a3ab9d4da4fb3320ec9f4e1231f274856b879ba6fe19cf8ccdcfe3ae27`、`69a19104fccccb2a110c7695ce22f605e8b0008a2bf615d99467245dcef120ac`、`94cfa2da4b1cec30ac0d3d138e130307aca97099824d2b5d5a3a9f60b24ef17c`。仅缩短重试未改善总数；后两项仍有排队波动，不能单独验收或将组合结果归因于某一项。

更早的 `device-smoke/capture-contention-20261021_retry250_explore/` 首轮因 Windows adb MAX_PATH 拉取失败，未完成 ABBA；远端及部分本地证据保留，不计作通过或漏捕。脚本现启动前估算路径长度，要求短 RunId/证据目录。

## 冻结构建的三组验收

基线是已发布 `dfe3c5a`（main 的 `fc0d88b` 同源码），二进制 SHA-256 `6424bfcc0143cdaec199bc4bfa17d83fb6628c33975e95735a6db3459d2de5b0`。最终默认 ARM64 候选为 `e785d6ce3d6121be2eb4829f6c5e47559b5fe0f55c7afb49fb126c742cb28180`。启动前固定 wf1/wf2/wf3 三组，12 轮没有筛选，均使用相同候选。

| 组 | 旧版两轮恢复 | 新版两轮恢复 | 旧版每轮排队 P95 均值 | 新版每轮排队 P95 均值 |
|---|---|---|---:|---:|
| wf1 | 64、63 | 64、63 | 2526.352ms | 2388.395ms |
| wf2 | 61、62 | 64、63 | 2450.695ms | 2375.986ms |
| wf3 | 63、61 | 63、64 | 2474.111ms | 2336.977ms |

1ms 独立方法 **182/192 → 189/192**，5ms **192/192 → 192/192**，总计 **374/384 → 381/384**。六轮各自仍可能漏捕，不保证每轮严格优于旧版。逐轮排队 P95 的总体均值 **2483.719ms → 2367.119ms**；不是全事件混合 P95，也不是 fsync 完成时延。

12 轮各保留 512 个原始观测，queue/budget/generation/read/trace/disk/write failure 为 0，remaining=0、worker_failed=0。每轮最大累计合并数等于独立方法证明数。原始区间双读命中 374→380；新版另一个有效方法捕获落在 fixture begin 记录边沿之前，故不计区间命中，不将 reuse 算新证明。

剩余三个漏失均为 1ms：wf1/3 trial32、wf2/3 trial8、wf3/2 trial26。首尾没有捕获区间相交，中间一个虽相交却无匹配字节；均无 golden 双读可回填。校验失败仍记录并按原预算重试，不能靠单读或忽略其他方法变化凑满。

三份完整 64 方法副本由新的 ART 进程实际加载并执行全部 marker，fixed SHA-256 均为 `bf96304a08fe571a3efe00d08904af5e482f013dc389e23ec60bd16c65a404f9`。不因此修改通用 `art_accepted / plaintext_proven`。

原门禁逐组检查恢复/原始命中/最低单轮/累计保留/排队/额度/drain；仅增加显式固定新基线 hash、采集 nice 调整/恢复失败检查，未放宽验收。`.test-bin/window-performance-gate.json` 三组 passed。这是有限自建样本，不是统计非劣性检验或商业壳、无事件解密、其他设备上的保证。

## CPU 取舍和回归

250µs 重试并非免费。只过滤自身 PID 的 2 秒空载 ABBA：旧 2ms/nice0 CPU 为 71.995、81.039ms，新 250µs/nice-2 为 139.849、120.607ms。约增加 54ms CPU/2s，即一个核心约 2.7 个百分点；不是整机利用率，没有测整机耗电，不能声称 CPU/功耗不退化。最终短窗口轮采集 CPU 为 768.559–867.993ms（约 12 秒监测，含空闲和采集）。本次以有界额外唤醒换取恢复率，长时间低活跃的自适应等待仍待优化。

- 同 hash 的 Root wf3 安全回归：冲突四份独立证明、一个冲突记录并冻结；方法外持续变化 0 回填/0 合并；重映射一次失效、新代际最多两个方法、不夹带旧方法。
- 15 组最终宿主测试、PS 四类诊断反例、门禁自测和全部 PS 语法通过。
- 八组 ARM64 原生测试：缓冲池、协调、101 份观测发布及 idle flush、合并事务、stat、身份/成员关系、syscall 配对，以及 VM 失败→mem 降级/短读/不可读/世代拒绝。故障注入只存在于测试可执行文件，不是生产开关。另验证外来子进程拒绝、错误世代、死亡线程、空 cmdline，以及包名已发现进程和父进程跟随原路径。
- 第九组原生生命周期/空载测试覆盖 tracefs 自身 PID 过滤、清理/重复 stop、主线程 nice 不变及采集线程恢复。合并测试首次漏传必需 payload 参数，argc 断言失败日志保留；传入相同自建 payload 后预算/回滚/重试/冲突通过。
- 同 hash 的 wp1 poll 降级：worker=0、armed=0、retained=0、pool_slots=0，快速/回填/合并均为 0。
- 最终 CLI 对完整自建副本 `--verify` 通过结构、checksum/signature 检查；`art_accepted:null`、`bytecode_type_verified:false` 保留，不把静态检查冒充 ART 或字节码类型验证。
- ARM64/ARMv7 均用 C++17、`-Wall -Wextra -Werror` 构建。ARMv7 SHA-256 `d5b6c3ac34a9ada6f46af98f5666a95761ae7b602b30068970e6fa5cd0571234`，不宣称支持该 ARM64 ART profile；没有新增 sanitizer 通过声明。
- 每组前后 global buffer_percent=50、SELinux Enforcing、既有 bootreceiver/wifi 实例及磁盘 payload hash 不变。不替换常用 nhdd_root_next，不启动重连任务。

证据为 `.test-bin/wf1/`、`wf2/`、`wf3/`、`wnative/`、`wp1/`，大体积产物不入 Git，留本地及设备。最终独立设备二进制为 `/data/local/tmp/nhdd_cont_wf3_new`，不是默认安装路径。

## 复现

按 Makefile 严格构建当前源码为 `.test-bin/nhdd-window-final-arm64`，准备[自建夹具](capture-contention.md)，固定旧二进制 hash。使用新的短目录，不覆盖证据：

```powershell
./tests/run_capture_contention_device.ps1 -Serial DEVICE_SERIAL -RunId w01 -Destination .test-bin/w01 `
  -Candidate .test-bin/nhdd-window-final-arm64 -Baseline .test-bin/nhdd-contention-fixed-arm64 `
  -ExpectedBaselineSha256 6424bfcc0143cdaec199bc4bfa17d83fb6628c33975e95735a6db3459d2de5b0
./tests/analyze_capture_misses.ps1 -Directory .test-bin/w01/2_candidate
./tests/analyze_capture_misses.ps1 -SelfTest
```

编译期消融：NHDD_TRACE_RETRY_US=50..2000（默认250）、NHDD_TRACE_NICE_DELTA=0..3（默认2）、NHDD_CAPTURE_MERGE_BATCH=8/16（默认16），均非安全开关。原生 art_merge_publication_test 必须传自建 payload DEX 路径；其余八个原生测试不需要该参数。
