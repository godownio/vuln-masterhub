---
id: code-analysis-reverse-unpacking-ollydbg-run-trace-condition-importrec-tracer
title: OllyDbg RUN 跟踪停止条件 + ImportREC 插件/Tracer 分级修复 IAT（复杂壳/IAT 重定向）
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: ollydbg-run-trace-condition-importrec-tracer-iat-repair
tags:
- reverse
- unpacking
- ollydbg
- importrec
- run-trace
- iat
- tElock
- oep
- pe
- windows
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V284
  verified_at: '2026-11-08T04:57:33+08:00'
  notes: 已对照原文与全部58张图片核对：RUN跟踪三类暂停条件（图22-23 EIP位于范围内5D170000-7FFFFFFF；图25-27 EIP位于范围外00400000-00B12000，断在7C811752；图28-29 Condition is TRUE [ESP]==4271DC && byte[EIP]==0C3）、ImportREC插件tElock1（图30-31）、Tracer Level1(反汇编)/2(挂钩)/3(捕获标志)（图32）、OllyDump OEP 271B0/Start 400000/Size 69000（图55）、ImportREC RVA 60818/Size 710（图53-56）均与原文一致。dup-scan与14642卡(Yoda's Crypter关键跳NOP/双实例复制)判为likely_duplicate，经核对两者原子不同（本卡=RUN跟踪停止条件+ImportREC分级修复；14642=两遍写入关键跳NOP/双实例复制），属同一工作流的不同技巧，且本卡已互链，裁决为并列保留、不删除。原文未标受影响版本/区间，未设affected_versions正确；PoC未复跑。
url: /docs/code-analysis/reverse/unpacking/code-analysis-reverse-unpacking-ollydbg-run-trace-condition-importrec-tracer/
draft: false
kb_aliases:
- OllyDbg RUN 跟踪
- 暂停 RUN 跟踪条件
- EIP 位于范围内
- EIP 位于范围外
- Condition is TRUE
- ImportREC Tracer
- 跟踪级别1/2/3
- ImportREC 插件跟踪
- IAT 重定向修复
- tElock IAT
---

## 一句话结论

面对 IAT 重定向/复杂壳时，用 OllyDbg 的 RUN 跟踪（Ctrl+F11）配合“EIP 位于范围内 / 位于范围外 / 条件为真”三类暂停条件，可以在壳跳入系统 DLL、离开主程序区段，或在指定 API 返回指令处精确中断；到达 OEP 并 dump 后，再用 ImportREC 的“插件跟踪”（如 tElock1）或 Tracer Level1/2/3（反汇编/挂钩/捕获标志）逐级修复无法识别的导入项，得到可正常运行的脱壳文件。

## 原理

- **RUN 跟踪的作用**：壳的 IAT 填充往往在解压 stub 的循环里完成，单步跟踪成本高。OllyDbg 的 RUN 跟踪记录/跟入每一步，但默认不会在合适位置停下；通过“暂停 RUN 跟踪条件”可以让调试器在满足条件时中断，快速定位壳进入 API、返回主程序或写 IAT 的关键时刻。
- **条件一：EIP 位于范围内（in range）**：设置一个地址区间（示例 `5D170000 - 7FFFFFFF`），当 EIP 进入该区间（系统 DLL 区段）时暂停。用于观察壳何时调用系统 API；如果壳跳进 DLL 后需要继续跟踪，可配合断点/单步。
- **条件二：EIP 位于范围外（outside range）**：设置主程序/壳区段（示例 `00400000 - 00B12000`），当 EIP 离开该范围时暂停。用于在壳从自解压代码跳入系统 DLL 的瞬间中断（示例停在 `0x7C811752`），再回溯调用栈/返回地址。
- **条件三：条件为真（Condition is TRUE）**：当有少数壳把区段创建在系统 DLL 区段之间时，范围条件不可靠；可写表达式如 `[ESP] == 4271DC && byte [EIP] == 0C3`，含义是“栈顶返回地址为 `0x4271DC`，且当前 EIP 指向 `0xC3`（RET）”，从而在指定 API 函数的返回指令处中断。这比范围条件更精确，但需要先知道目标返回地址和 API 的 RET 字节。
- **ImportREC 修复分级**：dump 后 ImportREC 按 OEP/IAT RVA/大小解析导入；无法识别的项可右键使用：
  - **插件跟踪**：针对已知壳的插件（如 `tElock1`、`tElock v0.9x`、`Yoda Crypter` 等），按壳的 IAT 填充特征自动识别；
  - **跟踪级别1（反汇编）**：反汇编 IAT 指向的桩代码，识别 `JMP <API>`/`CALL` 目标；
  - **跟踪级别2（挂钩）**：运行时挂钩 API 调用，记录实际地址；
  - **跟踪级别3（捕获标志）**：用 Trap Flag 单步捕获，最慢但最彻底。
- **为什么需要这些**：IAT 重定向时 IAT 项指向壳的跳转桩而不是 API 地址，ImportREC 直接解析会显示无效；简单壳可用 Level1 反汇编解决，复杂壳/桩中桩需要插件或 Level2/3。修复后 `Fix dump` 把正确的导入表写回文件。
- **反调试注意**：示例 tElock 会检测硬件断点，因此对 IAT 内存写监控应使用内存写断点（OllyDbg 的内存断点）而非硬件断点；RUN 跟踪和断点也可能被壳检测，需配合反反调试/换调试器。

## 触发条件

- 目标为 Windows PE，使用 tElock、Yoda's Crypter 等会重定向 IAT 或创建异常区段的壳。
- 可在本地运行 OllyDbg（或兼容调试器），并知道主程序/系统 DLL 的大致地址范围。
- 已定位 OEP 或能在壳完成 IAT 填充前后中断；有 OllyDump/ImportREC 等 dump/修复工具。
- 壳未使用会阻止调试/破坏 dump 的强反调试（或已绕过）。

## 利用步骤

1. 用 OllyDbg 加载样本，按壳类型定位 OEP（tElock 常用最后一次异常法；UPX 可用 ESP 定律）。
2. 打开 `Debug → Set condition`（暂停 RUN 跟踪条件），根据场景选择：
   - 壳跳入系统 DLL 时停：勾选“EIP 位于范围内”，填 `5D170000 - 7FFFFFFF`；
   - 壳离开主程序区段时停：勾选“EIP 位于范围外”，填 `00400000 - 00B12000`；
   - 壳区段夹在系统 DLL 之间：勾选“条件为真”，填 `[ESP] == <返回地址> && byte [EIP] == 0C3`。
3. 按 `Ctrl+F11` 开始 RUN 跟踪；命中条件后查看 EIP、栈顶返回地址与调用栈，判断是 IAT 填充、API 调用还是返回主程序。
4. 对 IAT 重定向样本，先对比“重定向项”和“未重定向项”的写入过程（内存写断点），找到关键跳转（示例 `0x4663D2 JE 0x4664FB`），把 JE 改成 JMP（或 NOP 掉重定向写入），让 IAT 保留真实 API 地址。
5. 继续跟踪到 OEP；用 OllyDump dump 进程（示例 OEP `0x4271B0`，Start `0x400000`，Size `0x69000`）。
6. ImportREC 选择进程，填 OEP、IAT RVA/大小（示例 RVA `0x60818`、Size `0x710`），`Get Imports`。
7. 对无效项右键：先试“插件跟踪”中的对应壳插件（如 `tElock1`）；仍失败则依次尝试“跟踪级别1（反汇编）”→“跟踪级别2（挂钩）”→“跟踪级别3（捕获标志）”。
8. 全部有效后 `Fix dump` 修复 dump 文件，运行验证程序可正常启动；必要时再用 OllyDbg 查看新 IAT 是否指向真实 API。

## PoC

OllyDbg RUN 跟踪条件（原文示例）：

```text
# 进入系统 DLL 时暂停
EIP 位于范围内: 5D170000 .. 7FFFFFFF

# 离开主程序/壳区段时暂停
EIP 位于范围外: 00400000 .. 00B12000

# 指定 API 返回处暂停（[ESP] 为返回地址，byte [EIP] 为 RET 0xC3）
条件为真: [ESP] == 4271DC && byte [EIP] == 0C3
```

ImportREC 修复入口（原文示例）：

```text
OEP: 000271B0（示例 tElock0.98 UnPackMe）
RVA: 00060818
大小: 00000710
无效项右键 → 插件跟踪 → tElock1
无效项右键 → 跟踪级别1(反汇编) / 2(挂钩) / 3(捕获标志)
Get Imports → Fix dump
```

关键跳转修改（示例）：

```text
004663D2  0F84 23010000  JE 004664FB   -> 改为 JMP 004664FB（或 NOP）
```

## 变体与关联

- **同类 IAT 重定向修复**：[[code-analysis-reverse-unpacking-iat-redirect-key-jump-nop-two-instance-copy]] 讲 Yoda's Crypter 的两遍写入与 NOP 关键跳转/双实例复制；本卡补充 OllyDbg RUN 跟踪三类条件与 ImportREC 插件/Tracer 分级，是同一 IAT 修复流程的工具化细节。
- **UPX 脱壳**：[[code-analysis-reverse-unpacking-upx-manual-esp-breakpoint-scylla]]（ESP 硬件断点 + Scylla）、[[code-analysis-reverse-unpacking-esp-law-seh-fallback-oep]]（ESP 定律 + SEH 兜底）。
- **其他壳/OEP**：[[code-analysis-reverse-unpacking-fsg-conditional-log-breakpoint-oep]]（FSG 条件日志断点）、[[code-analysis-reverse-themida-unlicense-oep-rc4-tea]]（Themida）。
- **IAT 结构**：`.idata` 的 IMAGE_IMPORT_DESCRIPTOR（OriginalFirstThunk/Name/FirstThunk）、INT/IAT 在加载前后的差异；IAT 重定向时 IAT 指向壳的 JMP 桩，`Call Address-1 -> Address-2 -> API`。
- **边界**：RUN 跟踪极慢（大程序/长循环会消耗大量时间）；壳检测硬件断点/调试器时需改用内存断点或反反调试；ImportREC 插件只覆盖已知壳，未知壳需手工/Tracer；有自校验的壳在修改关键跳后可能运行失败。

## 检测与防御

- **分析侧（本卡用途）**：对可疑 PE 先查壳（DIE/ExeInfoPE），按壳类型选择 OEP 定位与 IAT 修复策略；保留原始样本、dump 文件与修复记录，便于复现。
- **防护/对抗视角**：软件保护可使用 IAT 重定向、区段异常布局、硬件断点检测、RUN 跟踪检测、自校验等提高脱壳成本；但这些都是提高门槛而非绝对阻止。
- **检测**：调试器/沙箱中观察进程被 dump、IAT 被改写、`OllyDump`/`ImportREC`/`Scylla` 等工具痕迹；对恶意样本，dump 后检查导入表是否被修复以及 OEP 处代码是否符合原始编译器特征。
- **响应**：对脱壳后的样本重新做静态/动态分析，确认 IAT 修复未掩盖恶意导入（如动态解析 API 的样本仍需看壳内解析逻辑）。
