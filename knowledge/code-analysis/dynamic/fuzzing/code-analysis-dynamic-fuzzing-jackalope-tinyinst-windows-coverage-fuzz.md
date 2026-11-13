---
id: code-analysis-dynamic-fuzzing-jackalope-tinyinst-windows-coverage-fuzz
title: Jackalope + TinyInst 黑盒覆盖率引导 fuzz Windows 闭源模块：调试器式动态插桩、shmem 交付与 gdiplus harness
type: scenario
domain: code-analysis
path: code-analysis/dynamic/fuzzing
technique: jackalope-tinyinst-windows-blackbox-coverage-guided-fuzz-shmem-harness
aliases:
- Jackalope fuzz Windows
- TinyInst 动态插桩
- TinyInst 覆盖率
- Jackalope shmem 交付
- gdiplus harness fuzz
- 无源码 Windows 覆盖率 fuzz
- -cmp_coverage
- -target_offset fuzz
tags:
- fuzzing
- jackalope
- tinyinst
- windows
- coverage-guided
- dynamic-instrumentation
- blackbox
- shmem
- gdiplus
- emf
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V552
  verified_at: '2026-11-11T22:52:53+08:00'
  notes: 已对照原文与29张截图核对：litecov命令、Debugger/TinyInst/LiteCov类函数（OnModuleLoaded/HandleExceptionInternal/HandleTargetEnded/FixCrossModuleLink/InitGlobalJumptable/CommitCode/TranslateBasicBlockRecursive/TryExecuteInstrumented/InstrumentModule）、fuzzer.exe test.exe与gdiplus命令、shmem交付4字节长度头（sampleDelivery.h）、crash文件名access_violation_<异常地址>_<访问地址>_<序号>与控制台摘要、mpengine因x86内存限制转x64（img29原文）均一致；卡片未宣称具体漏洞，定位为工作流正确。dedup仅自匹配，其余为Rust/libFuzzer/Android/go-fuzz等其它fuzzer，无同链。未验证点：未实际编译运行Jackalope。
---

## 一句话结论

Jackalope 是 Project Zero 的覆盖率引导 fuzzer，内嵌 TinyInst 做**运行时动态二进制插桩**；对没有源码的 Windows 模块（exe/dll），只要写一个"把输入喂给目标函数"的 harness，用 `fuzzer.exe -delivery shmem -instrument_module <目标模块> -target_module <宿主> -target_method <函数>`（或 `-target_offset <偏移>`）即可做边缘/基本块/比较覆盖率引导 fuzz，crash 按异常类型落在 `<out>/crashes/` 下。

## 原理

- **TinyInst 为什么不需要源码/重编译**：它自带一个调试器（`Debugger` 类），把被检测模块的所有可执行区域改为**不可执行**但保留读写权限；控制流一进入该模块就触发异常，调试器捕获后用重写过的等价代码继续执行。重写代码放在模块地址范围 2GB 内新分配的远程可执行内存里（x64 `RemoteAllocateNear`），原模块里 `[rip+offset]` 形式的寻址指令被替换成 `[rip+fixed_offset]` 以适配代码搬家——这就是"动态插桩"能作用于任意闭源 PE 的原因。
- **控制流处理**：`TranslateBasicBlockRecursive` 递归翻译基本块并修正跳转偏移，`InitGlobalJumptable` 建全局跳转表处理间接跳转/调用；跨模块调用靠 `FixCrossModuleLink` 在原模块的链接位置写入"原目标地址 + 插桩后地址"两个指针，由 `CommitCode` 用 `RemoteWrite` 从调试器本地缓冲区写进目标进程。
- **目标函数模式**：`-target_module`+`-target_method` 时，模块加载回调 `OnModuleLoaded` 解析出函数地址并下 `BREAKPOINT_TARGET` 断点；命中后 `HandleExceptionInternal` 返回 `DEBUGGER_TARGET_START`，函数返回时在返回地址处恢复上下文（`-loop` 持久化模式下恢复寄存器与栈，让同一进程反复执行目标函数而不重启）。崩溃（访问冲突等非预期异常且不匹配结束地址）返回 `DEBUGGER_CRASHED`，样本被落盘。
- **Jackalope 的 fuzz 循环**：`Fuzzer::RunSampleAndGetCoverage` 交付样本并收集覆盖率；`-delivery shmem` 用共享内存传样本（`SHMSampleDelivery`：头部 4 字节长度 + 数据，目标参数 `@@` 被替换为共享内存名），比文件交付少了 per-exec 的文件 I/O；`-cmp_coverage` 利用比较覆盖率（类似 compare tracing）给变异更多反馈；`-persist -loop` 通过 TinyInst 的目标函数断点机制复用进程，吞吐高。

## 触发条件

- Windows（x86/x64，64 位构建可测 32 位目标）；VS2019 + CMake 构建 TinyInst 与 Jackalope。
- 目标是可执行模块，且能定位到一个"接收输入"的函数入口：有符号用 `-target_method`，没有则用 `-target_offset <函数 RVA>`。
- 需要一个 harness 可执行文件：负责读取输入（文件或共享内存）并调用目标函数。
- 种子目录 `-in` 需自备；Jackalope 不提供高质量变异种子生成，种子深度直接影响效果。

## 利用步骤

1. 构建（先构建 TinyInst，再把它作为 Jackalope 的子模块一起编）：
   - TinyInst：`mkdir build && cd build && cmake -G "Visual Studio 16 2019" -A x64 .. && cmake --build . --config Release`
   - Jackalope：在源码树 `git clone --recurse-submodules <TinyInst 仓库> ` 后同样 CMake 构建，产物含 `fuzzer.exe` 与自带测试目标 `test.exe`。
2. 先用自带的 `test.exe`（导出 `fuzz` 函数、1 个参数）验证工具链：
   ```
   fuzzer.exe -in in -out out -t 1000 -delivery shmem -instrument_module test.exe \
     -target_module test.exe -target_method fuzz -nargs 1 -iterations 10000 \
     -persist -loop -cmp_coverage -- test.exe -m @@
   ```
   参数要点：`-in/-out` 种子与输出目录；`-t` 单样本超时（ms）；`-delivery file|shmem`（默认 file，file 模式下 `@@` 替换为样本文件路径）；`-instrument_module` 指定收集覆盖率的模块；`-target_module/-target_method` 指定从哪个函数进入（配合 `-persist -loop` 反复调用）；`-nargs` 参数个数；`-iterations` 迭代上限；`-cmp_coverage` 比较覆盖率。
3. 对闭源目标写 harness（以 gdiplus 为例）：`GdiplusStartup` 初始化后，从普通文件或共享内存取出样本，调用内部处理函数（原文用的调用点偏移 `0x1170`，即 `-target_offset 0x1170 -target_method fuzz` 的组合），最后 `GdiplusShutdown`。harness 用 `-m <name>`/`-f <file>` 区分共享内存与文件输入。
   ```
   fuzzer.exe -in inGDI -out outGDI -t 1000 -delivery shmem -instrument_module gdiplus.dll \
     -target_module ConsoleApplication9.exe -target_offset 0x1170 -target_method fuzz -nargs 1 \
     -iterations 10000 -persist -loop -cmp_coverage -- ConsoleApplication9.exe -m @@
   ```
4. 种子：可用业务语法（如 EMF 图元文件语料）做初版语料，靠覆盖率反馈筛选。
5. 结果：`<out>/crashes/` 下文件名形如 `access_violation_<异常地址>_<访问地址>_<序号>`；控制台摘要含 `Exception at address ...`、`Access address ...`、`Crashes: N (M unique)`。拿到 crash 后用调试器复现分析，转化为具体漏洞（本篇作者未做此步）。
6. 自定义 fuzzer（可选）：继承 `BinaryFuzzer : public Fuzzer`，重写 `CreateMutator`（变异器组合，如 `ByteFlip/Arithmetic/Append/BlockInsert/BlockFlip/BlockDuplicate` 按权重）、`TrackHotOffsets`、`CreateInstrumentation`、`CreatePRNG`。

## PoC

最小 harness 骨架（GDI+ 场景，伪代码，原文 harness 自认"还有些许 bug 但能跑"）：

```c
GdiplusStartupInput in; ULONG_PTR token;
GdiplusStartup(&token, &in, NULL);
wchar_t *filename = charToWChar(argv[2]);
if (use_shared_memory) setup_shmem(argv[2]);   // 映射 @@ 给出的共享内存
FuzzMe(filename);                              // 目标函数：内部调 gdiplus 解析样本
clear_shmem();
GdiplusShutdown(token);
```

`FuzzMe` 内即调用 gdiplus.dll 中对应偏移（如 `0x1170`）的处理函数；`-nargs 1` 对应 `FuzzMe` 的一个参数。原文未给出 `FuzzMe` 源码，故完整 PoC 以命令行为准，函数体为无 PoC。

## 变体与关联

- **交付方式变体**：`-delivery shmem`（共享内存，样本头 4 字节长度）vs `-delivery file`（每样本一个文件，`@@` 为路径）。
- **入口定位变体**：有符号导出/可解析符号用 `-target_method`；stripped 模块用 `-target_offset` 直接给函数 RVA。
- **检测与调试参数**：TinyInst 自带 `litecov.exe -instrument_module <mod> -coverage_file <txt> -- <cmd>` 可单独验证覆盖率；调试期可加 `-trace_debug_events`、`-trace_basic_blocks`、`-trace_module_entries`、`-full_address_map` 观察插桩行为。
- **同类玩法**：用同一套路写 harness 去 fuzz Defender 的 `mpengine.dll`（需 x64，因 mpengine 内存占用超 x86 限制），以天/周为单位长跑可出 crash；与 AFL 系（源码/编译器插桩、Linux 为主）相比，Jackalope 的优势是**无源码、Windows 黑盒、进程内持久化**。与 libFuzzer/go-fuzz 等源码内建 fuzzer 互补。

## 检测与防御

- 该方法本身是漏洞挖掘手段而非攻击链；防御视角关注：
  - 目标进程被以调试方式创建（TinyInst 以调试器身份 `CreateProcess`/`DebugActiveProcess`），可检测非预期调试器父进程与 `DEBUG_PROCESS` 标志；
  - 进程内出现执行原模块代码区之外、位于模块 2GB 范围内的新可执行内存（插桩代码缓冲），可做内存扫描/EDR 规则；
  - 安全产品模块（如 mpengine）被第三方进程高频调用同一导出/内部函数，属异常调用模式。
- 对被测应用：把 fuzz 出的 access violation 修复掉，才是对该挖掘手法的实际防御。

## 备注

- 原文为工具学习笔记，fuzz 出的 crash 未分析成具体漏洞；本卡只沉淀"无源码 Windows 覆盖率引导 fuzz"的可复用工作流，不宣称任何具体漏洞。
- 原文把 TinyInst 误写为 "Tinylnst"，此处统一为正确名称。
