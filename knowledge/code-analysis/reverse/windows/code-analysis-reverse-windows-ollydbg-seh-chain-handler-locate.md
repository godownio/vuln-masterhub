---
id: code-analysis-reverse-windows-ollydbg-seh-chain-handler-locate
title: OllyDbg 定位并跟踪 SEH 异常处理程序：FS:[0] 链遍历、handler 断点与 Shift+F9 异常放行
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: ollydbg-seh-chain-handler-locate-trace
aliases:
- SEH 链定位
- FS:[0] 异常处理链
- OllyDbg SEH 链
- 异常处理程序断点
- Shift+F9 放行异常
- SEH handler 跟踪
- AeDebug Auto
tags:
- windows
- reverse
- seh
- exception-handling
- ollydbg
- debugging
- fs-register
- pe
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V373
  verified_at: '2026-11-09T06:20:49+08:00'
  notes: 已对照原文全文与 28/28 张可用截图核对：img01/18 OD 调试选项（仅勾选忽略 KERNEL32 内存访问异常）、img12/13 默认 SEH（0012FFE0→kernel32）、img14/15/16 注册序言与 SEH 链（0012FFB0→smartmou.004066D8、0012FFE0→kernel32.7C839A90）、img17/19 handler 入口 004066D8、img20 UEF 后进程退出、img21/22 AeDebug Auto=1 与弹框、img23-29 SDUE1 加壳提示/删除分析/异常后 handler 009F0054 命中/最终进入程序登录框，均与卡一致；[esp+4]/[esp+12] 参数偏移与 32 位 SEH 约定相符。已知限制：队列缺 08.png，正文该处为站外资源（异常处理.assets/image-20240527092613896.png，内容应为 NT 头 BaseImage/EntryPoint），无法读取，但卡片未依赖该图信息。原文为教学文章、无组件版本，affected_versions 已 --clear。PoC 为示意未编译运行。
---

## 一句话结论

在 OllyDbg 中通过 `FS:[0]`/“SEH 链”窗口读出当前线程的 `_EXCEPTION_REGISTRATION_RECORD` 链表，从注册序言（`push handler; push fs:[0]; mov fs:[0], esp`）或链表中拿到自定义 handler 地址并下断，制造一个可预期的故障（写 0 地址、除零、INT3），在调试器不忽略该类异常的前提下用 Shift+F8/F9 把异常放行给程序，即可观察 SEH 处理器是否修复异常、如何修改 `_CONTEXT`，从而还原异常驱动的控制流。

## 原理

- **每线程一条 SEH 链**：x86 Windows 的线程环境块中 `FS:[0]` 指向栈上的 `_EXCEPTION_REGISTRATION_RECORD` 链表头；记录只有两个字段 `Next` 与 `Handler`（函数指针），链表末尾是系统默认处理（kernel32 的 `UnhandledExceptionFilter`，UEF）。异常发生时系统从链头向链尾依次调用 handler，直到某个 handler 返回“已处理”。
- **注册与卸载**：编译器/开发者把记录建在当前栈上，注册序言为 `push Handler; push dword ptr fs:[0]; mov dword ptr fs:[0], esp`（新记录入链头）；卸载为 `pop dword ptr fs:[0]; add esp,4`。因此注册后栈上就能看到 handler 地址与 Next 指针，OD 的 SEH 链窗口正是解析这条链。
- **handler 约定**：x86 SEH handler 形如 `EXCEPTION_DISPOSITION handler(PEXCEPTION_RECORD, PVOID EstablisherFrame, PCONTEXT, PVOID DispatcherContext)`。返回 `ExceptionContinueExecution(0)` 表示已处理，系统用 `_CONTEXT` 恢复执行（handler 可改 `Context->Eip` 跳过故障指令）；返回 `ExceptionContinueSearch(1)` 表示不处理，继续向链尾传递。`_CONTEXT` 里保存 Eip、Esp、通用寄存器等全部现场，是判断“异常从哪来、要回到哪去”的关键。
- **调试器优先级**：异常先以“第一次机会”通知调试器。若 OD 的调试选项把该异常类型勾成“忽略”，调试器会自行吞掉/直接传给程序或被调试器默认处理，程序自己的 SEH 可能看不到；要观察程序 handler，必须取消对应异常类型的忽略（INT3、单步、访问违规、整数除零、非法/特权指令、FPU 等），再用 Shift+F8/F9 放行，让异常按程序自身的 SEH 路径派发。
- **未处理路径**：所有 handler 都不处理时进入 UEF；UEF 读取注册表 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug` 的 `Auto` 值——为 1 时不弹错误对话框（直接结束/交给调试器），为其他值（如 0）时弹出“应用程序错误”对话框。这也解释了为什么有时放行异常后进程静默退出，有时弹框。
- **为什么可复现**：SEH 链是内存中的可读结构，handler 地址在注册代码里是立即数；异常触发点可以人为构造（补一条写 `[0]` 或 `div 0` 的指令），派发过程完全由系统与程序决定，不依赖运气。

## 触发条件

- 目标为 32 位 Windows PE，使用结构化异常处理（MSVC `__try/__except` 或手写 SEH 注册）；64 位程序使用基于 `.pdata`/`UNWIND_INFO` 的表驱动异常，不存在 `FS:[0]` 链，方法不适用。
- 使用 OllyDbg/x64dbg 等能显示 SEH 链、能配置“忽略异常”选项的调试器。
- 调试选项未把要观察的异常类型设为忽略；或已显式使用 Shift+F8/F9 放行第一次机会异常。
- 能构造/定位一个可预期故障指令（访问违规、除零、INT3 等），且该异常发生时尚在目标 SEH 记录的作用域内。
- 若要在只读代码段打补丁做实验，需要能修改节属性（PE `Characteristics` 60000020→E0000020 增加可写位并保存，或运行时 `VirtualProtect`）。

## 利用步骤

1. 载入程序，打开“查看 → SEH 链”。链头地址应与 `FS:[0]` 指向一致；链尾通常是 `kernel32` 的默认处理器。若只有默认处理器，说明程序尚未注册自定义 SEH 或还没执行到注册代码。
2. 在反汇编中搜索注册序言：`push <imm32>`（handler 地址）后紧跟 `push dword ptr fs:[0]`、`mov dword ptr fs:[0], esp`；或在栈窗口跟随 `FS:[0]` 找到 `{Next, Handler}` 记录。记录 handler 地址。
3. 在 handler 入口下断点（也可在注册后的第一条指令下断，先让注册完成）。
4. 调整调试选项：取消勾选要放行的异常类型（如“非法访问内存”“整数除以 0”），保留“忽略在 KERNEL32 中的内存访问异常”以避免系统内部噪声；执行到故障指令。
5. 异常提示出现后，用 Shift+F8/F9 将异常放行给程序。若 handler 被命中，检查栈参数：`[esp+4]` 为 `_EXCEPTION_RECORD`（`ExceptionCode`、`ExceptionAddress`），`[esp+12]` 为 `_CONTEXT`；在数据窗口查看 `Context->Eip` 与 `Context->Esp`。
6. 单步执行 handler，观察返回值：返回 0（ContinueExecution）时确认 `Context->Eip` 是否被改写、程序是否从故障指令之后继续；返回 1（ContinueSearch）时继续放行，观察下一个 handler 或 UEF。
7. 对加壳/多次异常的程序（如 SDUE1）：OD 提示“代码段可能被压缩/加密”时先删除分析（右键 → 分析 → 从模块中删除分析），逐次放行异常并在 handler 断点观察；程序可能经历多次访问违规才恢复。
8. 若需补丁指令做实验：定位节表 `Characteristics`，把 `60000020`（CODE|EXECUTE|READ）改成 `E0000020`（增加 MEM_WRITE），保存后重载；或运行时用 `VirtualProtect` 改页属性。

## PoC

手写 SEH 注册与 handler 骨架（x86，示意，未编译运行）：

```asm
; 注册：记录结构 {Next, Handler} 建在栈上
push offset my_handler        ; Handler
push dword ptr fs:[0]         ; Next = 旧链头
mov  dword ptr fs:[0], esp    ; 新记录入链头

; 触发访问违规
mov  dword ptr ds:[0], 0x12345678

; 卸载
pop  dword ptr fs:[0]
add  esp, 4
```

```c
// handler 骨架：修复访问违规后跳过故障指令
EXCEPTION_DISPOSITION my_handler(PEXCEPTION_RECORD rec, void *frame,
                                  PCONTEXT ctx, void *dispatcher) {
    if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        ctx->Eip += 6;                 // 故障指令长度需按实际指令计算
        return ExceptionContinueExecution;
    }
    return ExceptionContinueSearch;    // 交给链上的下一个 handler
}
```

OD 中的检查点：SEH 链窗口应出现 `0012FFB0 -> my_handler`、`0012FFE0 -> kernel32 默认处理` 两行；在 `my_handler` 入口下断，Shift+F9 放行访问违规后应命中，`Context->Eip` 应指向故障指令地址。

## 变体与关联

- **VEH 优先于 SEH**：`AddVectoredExceptionHandler` 注册的处理器在 SEH 链之前被调用，可用于隐形断点/动态补丁；见 [[code-analysis-dynamic-debugging-veh-invisible-breakpoint-dynamic-patch]] 与 [[code-analysis-reverse-anti-debug-veh-custom-exception-debugger-detection-hijack]]。
- **SEH 隐藏校验分支**：除零异常被用作跳转，真正的校验代码在 `__except` 块；见 [[code-analysis-reverse-windows-seh-exception-logic-jump-z3-serial]]。
- **SEH 注册干扰脱壳**：PUSHAD 后栈断点被 SEH 注册改写，ESP 定律失效时的回退方法；见 [[code-analysis-reverse-unpacking-esp-law-seh-fallback-oep]]。
- **末次异常法**：统计异常次数并按次数 Shift+F9 定位 OEP；见 [[code-analysis-reverse-unpacking-last-exception-count-oep]]。
- **64 位差异**：x64 使用表驱动异常（`.pdata`/`UNWIND_INFO`），没有 `FS:[0]` 链；需用 IDA/x64dbg 的异常表视图分析。
- **反调试关联**：样本可故意注册 SEH/VEH 或制造异常判断调试器行为；分析时应区分“程序自己的异常处理”和“调试器吞异常”。

## 检测与防御

- **分析侧**：始终确认调试器没有“替程序处理”异常；出现异常循环时先看 SEH 链与 `Context->Eip`，不要盲目在故障指令上单步。对加壳样本先删分析、再逐个放行异常，记录命中次数与 handler 返回值。
- **程序侧（防护视角）**：SEH/VEH 可被用于异常驱动的控制流混淆与反调试；若产品需要健壮性，异常处理应只捕获预期异常并校验 `ExceptionCode`/`ExceptionAddress`，避免把任意异常都当作可恢复。
- **系统侧**：`AeDebug\Auto` 控制未处理异常是否弹框，排查崩溃行为时可检查该键；生产环境不建议依赖“弹框/不弹框”作为安全边界。
- **检测**：监控进程频繁触发访问违规/除零后继续运行的行为；对安全产品而言，异常风暴 + 动态改 `_CONTEXT` 是可疑的反调试/混淆特征。
