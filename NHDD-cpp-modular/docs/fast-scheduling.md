# 快速发布与回填校验调度

目标是减少冻结片段等待发布/校验的积压，不扩展 ART profile，不放宽现有捕获、身份、结构、补集或冲突规则。

## 调度与边界

- 采集线程仍只负责事件解析、进程世代和前后锚点、局部双读；不做磁盘 I/O。独立发布线程在观测到达时唤醒，串行写入 `fast/`，不等主线程完成全量扫描或批次。主线程仍负责普通扫描与基线布置。
- 一个发布者独占回填/合并状态和产物计数。基线只读，失效标志为 atomic；注册/目标/观测队列使用各自 mutex。停机先 join trace 采集，再 drain 发布与重试，再输出诊断；提前返回以 RAII 保持同一顺序。
- 32MiB/512 份额度同时覆盖排队、在途和待重试观测，取出/重排不释放额度；原始采集、快照 scratch、ART 基线等预算另计。仍不保证实时性或进程总内存上限。
- 新观测和到期重试公平调度：连续四个 fresh 任务后，若有到期 retry 则先执行一个；没有 fresh 时直接执行到期 retry。尚未到期的 retry 不阻塞 fresh。
- 每个任务最多四次尝试，退避 25/100/300ms；补集读取额度不足则至少等待到下一 1s 额度周期。回填/合并共用每周期 64MiB 的计划双遍读取额度，不缓存之前的身份/补集通过结果，不靠增加线程绕开限额。
- 只有原始证据成功落盘后才开始回填。实时补集失败而新鲜身份核对仍匹配时，可对**同一冻结观测、同一基线引用**重试；每次重新规划、重读 maps/profile/锚点、双遍补集、静态验证及提交 guard。失效代际不被重新激活；不从未来窗口读方法来填补旧观测。
- 单事件成功、合并尚未成功时，后续仅重试合并自己的完整检查，不重复生成或重写已被其他清单引用的单事件文件。发布失败不推进合并 `published_revision`。四次不是成功承诺，任务仍可能耗尽；退出也不会无限等待。

## 已知字节去重不等于新证明

`--art-merge auto` 时，发布者对已经规划通过的完整方法片段，逐字节比较同一基线中已成功提交的版本。若所有拟替换方法字节都已知，保留原始 `.first.bin / .second.bin / .json`，另写 `.reuse.json`，不重复执行昂贵的完整 DEX 回填/落盘。

引用 schema 为 `nhdd-art-reuse-v1`：

```json
{
  "status": "duplicate_method_bytes_not_revalidated",
  "this_observation_verified": false,
  "references": [{"method_index": 67, "offset": 8212, "length": 10,
                  "sha1": "...", "verified_source": "fast_...art0.refill.json"}]
}
```

这只是“新观测字节与历史证明相同”，不说明新观测时的其他字节、live complement 或完整身份已重新校验。不能据此增加独立回填、明文窗口验证或 ART 接受计数，也不更新累加器中的独立证明次数。不同方法或不同内容不会复用旧结果，仍须全部检查；同方法第二个独立验证版本仍冻结整个代际，不选赢家。

如果累加器还有待发布 revision，即使触发者是重复引用，合并也必须独立执行完整实时一致性检查。`--art-merge off` 不建立这层已知版本状态，因此也不走这种复用，保留逐事件完整回填行为。原始快速产物的 `cross_event_merge:false` 和单事件 `cross_event_patch_accumulation:false` 不变。

## 诊断与统计

- 源 JSON 新增 `publication_begin_boot / queue_wait_ms / publication_worker`，是开始写入时刻，不是 fsync 完成时间或硬时延保证。
- 独立回填 JSON 新增 `verification_attempt / capture_to_verification_ms`；前者是最终成功的尝试序号，后者包含之前的排队和退避。失败原因按 `*_attemptN.rejected.json` 保留，成功不会擦掉失败历史。
- `ART schedule: reused_unverified / reuse_records`：减少的重复重建及成功保存的引用数量，**不是校验通过数**。
- `Fast schedule: peak_items / peak_bytes / remaining / retry_attempts / retry_exhausted / queue_wait_max_ms / worker_failed`：峰值覆盖在途及待重试；`remaining=0` 才表示 drain 完成，不表示所有任务成功。
- `ART refill.rejected` 含未变化事件及失败尝试，重试可使它大于原始观测数。仍应检查独立的 queue/read/trace/output/IO 丢弃和失败计数。文件引用及摘要不是防篡改认证。

`analyze_fast_schedule.ps1` 区分原始双读命中窗口、独立验证方法、独立验证窗口和成功尝试序号。窗口命中使用源捕获区间与 fixture 的 `[begin,end]` 相交；fixture 的 begin 记录在写入明文和 mprotect 返回之后，边沿可能已有有效观测，因此区间命中是保守计数，不等于独立方法恢复总数。去重后不能拿独立文件数减少当作恢复能力倒退，也不能把 reuse 当作新的通过。

## 当前 Root 设备验证

受控夹具只改自己的私有映射，不执行被修改的现场 DEX，不注入或改写其他应用。Pixel 6 / Android 16 / SDK 36、KernelSU，ART profile 与原来相同。始终保留原始磁盘 payload 和每轮独立证据目录。

交付 ARM64 二进制 SHA-256：`3384af4442e8e85e85ecaac918559d6f915e8090314d6fb7948824201d10e485`，测试路径 `/data/local/tmp/nhdd_art_refill`；本地 `.test-bin/nhdd-art-schedule-arm64`。旧版对照为 `667c867` 对应的 `ba57d944…`，设备保留 `/data/local/tmp/nhdd_schedule_baseline_667c867`。验证结束后设备断开，尚未将常用 `/data/local/tmp/nhdd_root_next` 替换为新版。

新增 `burst` 模式：32 个不同完整方法各只开放一次，1/5/20/50ms 交替、每档 8 个，方法间仅 2ms 间隔；随后归零。原始 ART DEX 前 44B 和这 32 个 insns 预先清零，只有单个方法在自己的窗口恢复。仍用真正的 `dalvik.system.DexFile` 建立对象。

```powershell
./tests/run_art_refill_device.ps1 -Name nhdd_refill_burst_old -Mode burst -Binary /data/local/tmp/nhdd_schedule_baseline_667c867 -Destination .test-bin/burst-old -Serial DEVICE_SERIAL
./tests/run_art_refill_device.ps1 -Name nhdd_refill_burst_new -Mode burst -Destination .test-bin/burst-new -Serial DEVICE_SERIAL
./tests/analyze_art_merge.ps1 -Directory .test-bin/burst-new -Expected burst
./tests/analyze_fast_schedule.ps1 -Directory .test-bin/burst-new
```

`-Expected burst` 检查全部产物的逐方法来源、原始擦头保留和补集字节，不强制所有窗口必捕获；看 `exposed_methods / max_merged_methods` 判断恢复了多少方法，看完整正文 SHA-256 是否等于 golden 判断本轮是否全部恢复。`full_three_method_revisions` 是兼容旧脚本的历史字段名，在 burst 中同样表示正文完整匹配，不专指三个方法。

32 方法验证中，已经得到一份 raw 正文与 golden 全文相同的合并副本；fixed 的 SHA-256 为 `bf96304a08fe571a3efe00d08904af5e482f013dc389e23ec60bd16c65a404f9`。新 ART 进程经 DexClassLoader 实际加载，并逐个执行全部 32 个 marker，输入 11 的返回值均与 Java 源码预期一致；另有 `--verify` 通过。这只证明自建样本，不自动把任意结果的 `art_accepted` 或 `plaintext_proven` 改为 true。

首轮只拆发布线程的中间版触及更严格的统一 512 额度，丢弃 162 次，未作为交付结果。增加已知字节复用后，三方法 120 个窗口仍有 120 个原始双读一致命中，只做 3 个独立方法证明；独立证明开始校验的 P50/P95 约 3.130/3.373ms。旧版同夹具 321 份重复证明的 111 个命中窗口，按每窗口最早成功证明算 P50/P95 为 2558.649/6846.392ms。这是不同内容去重策略下的调度对照，不将 3 个新证明宣传成 120 次独立校验。

历史对照 `burst-before-a`：原始双读 32/32，独立方法恢复 19/32，按命中窗口最早成功证明计校验等待 P50/P95 为 1709.224/3279.984ms。第一轮完整恢复 `burst-final-a`：原始双读 32/32，32/32 方法独立验证并合并，6 个方法的证明依赖第二/第三次尝试；区间相交只数到 29 个窗口，原因见上述边沿定义。另一开发轮 `burst-after-b` 只恢复 30/32，其中一个窗口没有原始双读一致片段，说明不能保证 1ms/短窗口完全恢复。

同一 fixture/helper、同一 payload 的最终对照如下；各行为独立一轮，不将漏捕隐藏在平均值中：

| 轮次 | 原始双读一致窗口 | 独立验证并合并的方法 | 成功窗口校验等待 P95 |
|---|---:|---:|---:|
| 旧版 `burst-before-a` | 32/32 | 19/32 | 3279.984ms |
| 旧版 `burst-before-b` | 32/32 | 20/32 | 3154.616ms |
| 交付版 `burst-release` | 32/32 | 32/32 | 2069.599ms |
| 交付版 `burst-release-b` | 29/32 | 29/32 | 1857.642ms |

交付版两轮都保留 256 份原始观测，queue/byte-budget/trace/output/write failure 均为 0。后轮的原始双读窗口仍漏 1 个 1ms、2 个 5ms，发布线程与扫描/采集仍争用资源，并未消除窗口采样风险；另有一个任务耗尽重试上限，但对应方法已有其他独立证明。P95 只统计成功且与记录区间相交的窗口，不包含失败窗口，不是全事件时延上界。`burst-release` 的 5 个方法证明依赖第二至第四次尝试，说明收益不只是减少重复文件。

最终重复窗口轮 `multi-release`：3/3 方法恢复、960 份原始观测、420 份未重新校验引用、3 份独立证明，原始双读命中 118/120；去重后的首次方法校验等待 P50/P95 为 6.386/8.445ms，原始落盘启动排队 P95 为 102.158ms、峰值在途 56 份，未发生队列/trace/输出丢弃。前述 `after-b` 的 120/120 是开发轮，不与该交付轮混用。

冲突负例仍只保存两种版本证据并冻结；persistent 方法外字节变化不产生回填/合并；原址 munmap/mmap 后，新代际不夹带旧方法。源/引用/合并均按真实目标地址、PID/starttime、基线和来源字节交叉校验。全部日志保留 `.test-bin/device-smoke/art-schedule-20261020/`，中间轮与交付轮分目录。

`conflict-final` 只有 4 份独立证明（三方法加第二版本）和一份冲突清单；`outside-final` 为 0 回填/0 合并；`remap-final` 观测到一次失效，新代际最多两个方法，未带入旧方法。上述三轮为前一构建 `6cdab626…`，与交付版的成功/拒绝检查相同；交付版随后仅修正失败事务的输出额度计数和首次额度周期初始化。

关闭/降级对照并非无代价：`off-release` 的 `--art-merge off` 仍输出 326 份完整校验的独立回填、0 合并/0 引用，但高重复压力触及统一 512 上限，明确记录 179 次 queue drop、最长排队 8313.183ms。新版没有靠放宽上限隐藏积压；不使用复用时，这一吞吐短板仍存在。`poll-release` 为 worker=0、armed=0、retained=0、快速/回填/合并均为 0，没有悄悄降级成不可靠回填。

12 组宿主逻辑测试通过，含统一额度、在途/重试不释放、fresh/retry 公平性及次数上限。Android `fast_publication_worker_test.cpp` 合成事件只读自身页面，验证 100 份观测完整 drain、重复 stop、拒绝二次 start；`art_merge_publication_test.cpp` 继续覆盖预算、发布中断回滚和 dirty revision 重试。ARM64/ARMv7 均用 C++17、`-Wall -Wextra -Werror` 编译；ARMv7 不宣称支持 ARM64 ART profile。
