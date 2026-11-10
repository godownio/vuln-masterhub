---
id: code-analysis-reverse-anti-debug-attach-process-startup-bypass
title: IDA 附加进程调试绕过启动期反调试：先裸跑再 Attach to process，命中后 F7 步入真实函数
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: attach-process-bypass-startup-antidebug
tags:
- windows
- ida
- attach
- anti-debug
- dynamic-analysis
- debugging
- reversing
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V287
  verified_at: '2026-11-08T05:28:57+08:00'
  notes: 已对照原文与图01-19核对：Strangeprograme_ok.exe 为32位MSVC未加壳（图11），函数窗口无main（12），字符串/交叉引用定位sub_415560（13-14/19），终端裸跑停在输入（16），IDA Attach to process 附加pid7512（17），在j_memcmp下断并F7步入真实函数sub_41D250（原文代码：40字节密文+16字节密钥，魔改TEA+XOR）。卡将第一例的ZF修改归入变体（已由现有卡覆盖）合理。未验证点：未复跑附加/解密流程；无组件版本；frontmatter无sources/source_url。
url: /docs/code-analysis/reverse/anti-debug/code-analysis-reverse-anti-debug-attach-process-startup-bypass/
draft: false
kb_aliases:
- IDA Attach to process
- 附加进程调试
- 反调试绕过附加进程
- 启动期反调试绕过
- 先运行再附加
- 真实加密函数定位
- Debugger Attach 反反调试
---

## 一句话结论

当目标 EXE 在“由调试器启动”时会走反调试分支（打印假 flag、调用假/虚函数或直接退出），可以改为先在调试器外正常启动进程、让它完成启动期检测，再用 IDA 的 `Debugger -> Attach to process` 附加到已运行进程，在关键函数/字符串交叉引用处下断点，输入触发后 `F7` 步入，从而进入真实加密/校验函数（示例为魔改 TEA+XOR），拿到可解密的密文与密钥。

## 原理

- **启动期检测只在“调试器启动”路径触发**：反调试逻辑通常放在 `main` 入口或初始化阶段，通过 `IsDebugged()`/`IsDebuggerPresent` 等判断当前是否被调试；如果进程是由调试器创建，检测命中后执行假逻辑（例如把假 flag 拷贝到缓冲区并打印）或退出。先在调试器外裸跑，进程以正常状态完成这些初始化，随后再附加调试器，启动期检测不会重跑。
- **静态看到的函数可能是运行时替换的假实现**：示例中静态反编译的 `j_memcmp` 函数逻辑是“把输入字符逐个与假 flag 相减”，按该逻辑不可能得到正确输入；这本身就是反调试/混淆的一部分。附加到已运行进程后再在调用点 `F7` 步入，可进入运行期真正执行的加密函数（示例为 40 字节输入、魔改 TEA 轮函数 + XOR 比较）。
- **附加调试的时序优势**：`Attach to process` 不重新创建进程，只把调试器挂到现有进程；目标已经处于等待输入的状态，之前的所有反调试判断都已执行完毕。此时下断点、单步、读内存不会改变前面已经做出的控制流决策。
- **定位真实函数的入口**：通过字符串窗口（`shift+F12`）找到 `Please input flag`、`Right!`、`Wrong!` 等提示，交叉引用到主校验函数；在其中的比较/调用（如 `j_memcmp`）处下断点，输入任意内容触发，再 `F7` 进入被调函数。
- **边界**：若目标持续检测调试器（定期检查 `DebugPort`/`DebugObjectHandle`、检查硬件断点、拒绝附加、或使用 PPL/受保护进程），仅靠“先跑后附加”仍会被发现；附加本身也需要目标未禁用调试权限。

## 触发条件

- 目标为 Windows PE（示例为 32 位 MSVC 程序），可以在没有调试器的情况下正常启动并停在输入提示。
- 反调试检测发生在启动阶段，或“被调试启动”时会替换关键函数/执行假分支；附加后不再重复检测。
- 分析者拥有可附加的权限（同用户/管理员，目标未开启反附加保护）。
- 能在 IDA 中加载同一二进制并识别字符串/函数交叉引用。

## 利用步骤

1. 在终端直接运行目标程序（不通过 IDA 启动），让它正常运行到输入提示，例如 `Please input flag`，先不输入。
2. 在 IDA 中打开同一二进制，选择 `Debugger -> Attach to process`，在进程列表中选择正在运行的目标进程并附加。
3. `shift+F12` 打开字符串窗口，定位 `Please input flag`、`Right!`、`Wrong!`，双击后 `Ctrl+X` 查看交叉引用，进入主校验函数（示例 `sub_415560`）。
4. 在主校验函数中的比较调用（示例 `j_memcmp`）处下断点，回到终端输入任意内容并回车；断点命中后按 `F7` 步入被调函数。
5. 观察真实的加密/校验逻辑（示例：先做魔改 TEA 轮运算，再与 40 字节常量数组异或比较），记录密文数组、密钥与轮数。
6. 按该逻辑编写解密脚本或继续单步，修改输入/寄存器验证结果，最终得到通过校验的输入。
7. 若目标还有二次检测，保持附加状态重复“下断点→触发→步入”，或在关键比较处直接修改标志位/返回值。

## PoC

无独立脚本；以下为操作要点（地址/函数名按目标调整）：

```text
# 1) 调试器外正常启动，停在输入提示
Strangeprograme_ok.exe

# 2) IDA: Debugger -> Attach to process -> 选择 Strangeprograme_ok.exe
#    附加后进程仍停在输入提示

# 3) shift+F12 -> "Please input flag"/"Right!"/"Wrong!" -> Ctrl+X 交叉引用
#    进入 sub_415560（主校验函数）

# 4) 在 call j_memcmp 处下断点；终端输入任意内容触发

# 5) F7 步入真实函数；读取 40 字节比较常量 v11 与 TEA 密钥
#    示例真实逻辑：魔改 TEA(16 轮) + 按 4 字节分组 XOR

# 6) 用脚本按真实函数逆推输入，验证 Right!
```

原文示例中，附加后在真实函数内得到 40 字节密文数组与 16 字节密钥，按魔改 TEA 解密并处理 XOR 后得到可通过校验的 flag；脚本逻辑随题目而变，不属于本技术的固定 PoC。

## 变体与关联

- 变体（同一文章的另一个 EXE 例子）：不附加，直接在 `IsDebugged()`/`IsDebuggerPresentFlag()` 的条件跳转处修改 ZF 标志位，让分支走向正常逻辑；该“改 ZF 跳过条件跳转”原语已由 [[code-analysis-dynamic-debugging-crackme-password-check-patch]] 与 [[code-analysis-reverse-anti-debug-peb-fields-patch]] 覆盖，本卡不重复展开。
- 变体（附加对象）：附加到服务/后台进程、附加到 fork 出的子进程（子进程需先 patch 死循环再 `SetIP`，见 [[tools-ida-fork-child-loop-patch-attach]]）。
- 关联：[[code-analysis-reverse-anti-debug-ntquery-debug-info-argument-patch]]（NtQuery* 调试信息检测）；[[code-analysis-reverse-anti-debug-exception-timing-checksum-bypass]]（异常/时序类反调试）；[[tools-ida-appcall-debug-context-function-invocation]]（附加后直接调用样本函数）。
- 边界：持续轮询调试器、检测硬件断点/`DebugObjectHandle`、拒绝 `DebugActiveProcess` 的目标，需要配合 hook/内核调试或静态还原，不能只靠附加。

## 检测与防御

- 检测（分析侧识别点）：程序在调试器启动时打印假 flag/直接退出，但在独立运行时正常；字符串中存在 `plz_dont_debugme` 一类提示；静态函数逻辑明显不完整（如用假 flag 做减法）；主校验调用在运行期才出现真实实现。
- 防御（软件作者）：不要只在启动时检测一次；在关键校验前后、定时器和线程中持续检测 `DebugPort`/`DebugObjectHandle`、硬件断点寄存器、调试对象与父进程；对关键函数做完整性校验；对附加行为做反制（拒绝调试、检测 `DebugActiveProcess`）；关键逻辑不要以“检测到调试器就走假分支”的单一方式实现。
- 分析侧注意：附加会改变进程的调试状态，可能触发运行期二次检测；优先在关键比较处下一次性断点，避免长时间单步暴露。
