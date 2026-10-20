# ART 候选关联与安全局部回填

目的：快速事件范围即使不含 DEX 头，也能用**事先发现的真实 ART 候选**解释其方法指令字节，在原地址再次归零/加密后保留可分析副本。不是平台，不注入、不 Hook、不暂停目标，也不向目标内存写回。

## 使用

```bash
adb shell "su -c '/data/local/tmp/nhdd_root_next com.example.app /data/local/tmp/nhdd_refill_run --dex --continuous --events tracefs --art-dex auto --art-refill auto --monitor-duration 30'"
```

`--art-refill auto|off` 默认 auto，须同时具备 continuous、tracefs、快速捕获和兼容的 ART 发现。`off` 仅关闭候选关联，不关闭原始局部双读或普通 ART 扫描。snapshot/watch 不启用此路径。未知 Build ID 不猜偏移；兼容范围与 [ART 发现](art-discovery.md) 相同，当前为已核对的 ARM64 `libdexfile` Build ID。

## 校验顺序

1. 主扫描读到字节完整的 ART 候选后，交出只读副本，记录 PID/starttime、地址/长度、对象/虚表/Build ID、112B 头部和映射 backing。仅从静态结构检查通过的 normalized 副本提取方法布局；原始基线仍保留擦头状态。
2. 方法必须来自可解析的 class_data、位于 map_list 的 code_item 区域，code_item 范围不得互相重叠；只允许替换完整 `insns` 数组。CodeItem 头、try/catch、debug、索引表、字符串和文件头不在回填范围。
3. 同一对象/结构世代固定首次基线，主扫描偶然读到的其他正文 revision 不重置基线。新对象、结构/头部改变、进程换代或已观测的 backing 事件使旧基线失效，排队片段持有的旧引用也随之失效。
4. 采集线程只对相交的 mprotect 事件关联候选，分别在局部双读之前/之后核对对象 128B、头部 112B、虚表地址点 16B。事件必须晚于基线布置；候选未发现前的片段不追认关联。
5. 方法指令区须完整包含在一个事件观测中，双读均完整、逐字节相同且有变化。片段中其他已覆盖的 DEX 字节须与基线相同。短读、方法截断、双读变化、锚点变化都会拒绝；全零方法替换也拒绝，不把擦除视为修复。
6. 主线程再读取实时 maps，复核 backing、Build ID profile、ART 对象和头部。允许纯权限变化引起的 VMA 拆分，不接受文件/inode/device/路径、私有属性或文件偏移变化。
7. 对**除本事件拟替换 insns 区域以外的全部 DEX 字节**进行两遍实时重读，均须与固定基线逐字节一致。拟替换区域可以已经恢复密文/零值：采用的是此前已冻结的双读片段，而不是此刻的现场字节。
8. 只在新的导出缓冲里组合基线与这些方法字节，再做静态结构检查、修 header/checksum 和回滚式文件组发布。发布阶段继续复核进程、对象、profile/backing 与基线有效状态。原主扫描缓存和已经发布的 DEX 不变。

没有同一事件里的完整方法、不满足任何一个检查，就保留局部片段/原因，不发布回填 DEX。观察到 mmap/munmap/mremap 与 DEX、对象或 libdexfile 依赖范围相交，或观察到 trace 丢失，会撤销相关基线；失效后须重新发现。

## 这不是哪些保证

- 结果是 **temporal composite（跨时刻重建）**，不是同一时刻的内存快照。双读、前后锚点和 backing 检查不能排除读内撕裂、未观测的映射 ABA 或改变后恢复；`atomic_snapshot:false / mapping_aba_excluded:false` 始终明确。
- `plaintext_proven:false`：工具不知道每个字节何时是明文。全零排除和固定基线减少常见反向回填，但不能普遍区分有效指令、其他密文、VMP 字节或语义错误。静态结构检查不等于完整 opcode/控制流/类型验证。
- 已释放但内存尚完整的 StandardDexFile 存储仍可能形成候选，不是 ClassLinker/DexCache 注册链的严格枚举或对象存活证明。
- 当前要求完整覆盖的基线及可解析方法布局；支持已验证构建上的前 44B 擦除场景，不承诺 112B 头全部擦除、CodeItem 头/结构表破坏、脱离原 DEX 的代码区、CompactDex/DEX041 或 VMP 恢复。
- 不累积多个事件的补丁。若多个方法仅在互斥窗口明文，当前保留各自的单事件重建副本，不把它们拼成未经共同验证的“全明文 DEX”。其他未替换方法仍可能是密文。
- 普通扫描仍可能独立捕获完整明文，关联回填的观测数/窗口命中数不是整个工具的脱壳成功率。

## 预算与输出

- 每候选基线最多 16MiB、4096 个方法、128 个依赖映射；注册上限 32 个，保守基线内存预留总额 64MiB，包含排队片段仍引用的旧基线。原有 DEX 缓存、临时校验缓冲不计入此额度。
- 每个事件最多关联 4 个候选；过多时不任取前几个。捕获原有前缀上限和 8ms 软预算不变，新增前后锚点读取另有开销，不保证总时延 8ms。
- 主线程每批最多安排 64MiB 的双遍补集读取；profile/身份读取另计。超预算不发布该副本，但保留已经落盘的原始片段。
- 回填副本、基线、metadata 计入快速路径每次运行 256MiB 发布上限。复用 `fast/` 仍会累计，多次运行应使用新目录。

原有 `fast_<...>.first.bin / .second.bin / .json` 不变，源 JSON 新增 `art_associations`，记录关联基线、对象、捕获前后锚点和 `planning_status`。成功时另存：

```text
fast_<...>_art0.baseline.raw.dex     # 固定的原始基线，包括擦头/原始方法状态
fast_<...>_art0.refilled.raw.dex     # 仅 insns 回填，擦头状态保留
fast_<...>_art0.refilled.fixed.dex   # 分析用修复副本，版本丢失时合成 039
fast_<...>_art0.refill.json          # 来源文件、完整补丁范围、基线 hash、校验时刻、检查结果
```

`status: reconstructed_method_composite` 与普通 `byte_complete` 不混用。metadata 同时记录 `cross_event_patch_accumulation:false`、`method_double_read:match`、`complement_passes:2`。raw 可能因擦头被静态检查判 invalid；fixed 只修导出副本。完整 DEX 提取/ART 回填均不计入主扫描的去重 DEX 汇总，分别看 `Fast capture` 与 `ART refill`。

规划阶段拒绝可查看源 JSON 的 `planning_status`，例如 `candidate_invalidated`、`method_changed_between_reads`、`fragment_holes`、`fragment_non_method_changed`、`zero_instruction_replacement`。`no_complete_changed_method` 包含没有方法变化的普通事件，不等于异常。补集/profile/backing 校验失败另存 `*.rejected.json`；后端输出、内存、候选数和校验预算失败有独立计数。

## Root 真机验证与复现

夹具只操作自己的文件私有映射，不向第三方 App 注入或改写内存：

- `ArtRefillPayload.java` 经真实 D8 生成 28,996B DEX，包含 513 个 code_item。
- Java 先用真实 `dalvik.system.DexFile` 打开 payload；JNI helper 将该进程私有映射的前 44B 及一个方法 insns 置零。磁盘原始 DEX 不变，测试不执行这些被改坏的方法。
- 选中方法 `marker065`，指令位于 DEX +8212、长度 10B。mprotect 事件范围从 +8192 开始，**没有 DEX 头**。
- 等日志确认该地址 ART 基线已布置，才触发 1/5/20/50ms 明文窗口，每档 10 次；结束后方法再次归零。
- 分析脚本按源捕获时间与窗口相交统计，不拿 helper 的 golden 堆副本冒充目标方法页面命中；每份重建 raw 的第 44B 以后须与 golden 全文 SHA-256 相同、头部仍为零，基线外的变化严格限于所报方法范围。

部署主程序为 `/data/local/tmp/nhdd_art_refill`；将两个 Java 文件分别 javac/d8，部署为 `nhdd_art_refill_probe.dex / nhdd_art_refill_payload.dex`；NDK 编译 `art_refill_probe.cpp` 为 `-fPIC -shared -static-libstdc++` helper，部署 `libnhdd_art_refill_probe.so`。

```powershell
./tests/run_art_refill_device.ps1 -Name nhdd_refill_demo_on -Destination .test-bin/demo-on -Serial DEVICE_SERIAL
./tests/analyze_art_refill.ps1 -Directory .test-bin/demo-on
./tests/run_art_refill_device.ps1 -Name nhdd_refill_demo_off -ArtRefill off -Destination .test-bin/demo-off -Serial DEVICE_SERIAL
./tests/run_art_refill_device.ps1 -Name nhdd_refill_demo_outside -Mode outside -Destination .test-bin/demo-outside -Serial DEVICE_SERIAL
./tests/run_art_refill_device.ps1 -Name nhdd_refill_demo_remap -Mode remap -Destination .test-bin/demo-remap -Serial DEVICE_SERIAL
```

Name 必须唯一，脚本不覆盖旧证据、不按进程名杀进程。`outside` 在目标方法所在页之外持久改变一个字节，测试补集拒绝；`remap` 解除并在原址重新映射，测试旧候选和排队片段失效。

独立运行时验证器 `ArtRefillVerify.java` 通过单独的 DexClassLoader 加载**本项目自己的**恢复副本、调用选中 marker，11 的预期返回值为 161。这只证明该测试副本通过实际加载及选中方法执行，不给其他产物批量设置 `art_accepted:true`。

### 2026-10-20 当前设备结果

Root Pixel 6 / Android 16 / SDK 36，SELinux 全程 Enforcing。最终 ARM64 SHA-256：`30b33a105b9876a180a1e28097d2f2011904c4982c896fbe5dc1e219274b7de7`。

| 名义方法明文窗口 | 每档次数 | 最终版本的已验证关联回填窗口 |
|---|---:|---:|
| 1ms | 10 | 9 |
| 5ms | 10 | 10 |
| 20ms | 10 | 10 |
| 50ms | 10 | 10 |

最终普通运行产生 150 份重复的单事件回填观测，对应 39/40 个时间窗口；150 份源片段全部不含 DEX 头，raw 保留前 44B 为零、正文与 golden 全文 SHA-256 相同，所有方法外字节均与所附基线相同。147 份的补集校验开始时间已晚于相应窗口结束，说明不靠事后重读方法原址恢复。150 份 fixed 在设备上独立 `--verify` 均通过；选一份在新 ART 进程实际加载并调用 `marker065(11)`，返回 `161`。

回归轮次曾实际记录方法双读变化并拒绝回填；最终普通轮未遇到这一反例，宿主和 ARM64 逻辑测试另作确定性覆盖。候选基线只布置 2 个（probe 和 payload），没有因普通正文的明文/零值切换反复换基线。另测首次基线已经是明文时的全零替换拒绝，以及仅版本字段擦除的 synthesized 标记。

两个负例均保留原始片段，没有发布回填 DEX：

- `outside-final-release`：143 份方法片段本身通过双读规划，但未替换部分的一个字节持久改变，全部被实时补集/身份核对拒绝，记录 `live_complement_or_identity_changed`。
- `remap-final-release`：观测到 1 次映射失效，8 份旧候选关联的排队观测全部变为 `candidate_invalidated`；后续重新发现可布置新基线，但不会追认先前失效的片段。

三轮的 queue/budget/trace-loss/verification-budget/output/write-failure 计数均为 0。十组宿主测试通过，回填逻辑测试同时在 ARM64 真机通过；主程序通过 ARM64/ARMv7 `-Wall -Wextra -Werror` 编译。ARMv7 不宣称支持本次 ARM64 profile 的 ART 发现。

关闭关联的对照仍保留了 320 份快速片段，未产生关联回填副本；**原有完整 ART 扫描也独立命中过一次方法明文 revision**，因此不能把“关闭关联没有回填文件”宣传成旧工具完全不能恢复，也不能把上表当作总脱壳率。1ms 在回归轮次中为 8–10/10，最终仍漏 1 次，不保证瞬时窗口。轮询降级对照不建立关联基线（armed=0、retained_baseline_bytes=0），也不产生快速/回填副本。

磁盘原始 payload SHA-256 始终为 `66578c116d16c70627e2ea861ed8808018d0319b5f7a01cd1f33ec7507795596`。日志、基线、片段和所有副本位于本地 `.test-bin/device-smoke/art-refill-20261020/`，最终取 `normal-final-release / outside-final-release / remap-final-release`；`off-c` 为关闭对照，`poll-verified` 为轮询降级。中间 `normal-b` 用于发现基线随正文换代导致反向候选的问题，已修复，勿与最终结果混用。
