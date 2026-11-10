---
id: code-analysis-reverse-unpacking-two-stage-section-breakpoint-oep
title: OllyDbg 二次断点法/内存镜像法定位 OEP：先断 .rsrc 再断 .text/.code，命中后单步收尾
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: two-stage-section-memory-breakpoint-oep
tags:
- reverse
- unpacking
- oep
- ollydbg
- memory-breakpoint
- pe
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V293
  verified_at: '2026-11-08T07:52:24+08:00'
  notes: 已对照原文及图 14-27 核对：UPX .rsrc断点命中0x00409D9A→UPX0断点命中0x00409DA1；ASPack .rsrc命中0x0040875F→.code命中0x00401000（执行断点）；内存镜像法特殊OD下UPX直断OEP、ASPack首断0x00401000非OEP再F9，均与原文一致。dup-scan 将该卡与本篇 last-exception 卡判 likely_duplicate，经对照两者触发事件与操作（.rsrc/.code 内存断点 vs 异常计数 m/Shift+F9）完全不同，判为并列保留、不删除。未验证点：未在本机运行 OllyDbg/样本复现。
url: /docs/code-analysis/reverse/unpacking/code-analysis-reverse-unpacking-two-stage-section-breakpoint-oep/
draft: false
kb_aliases:
- 二次断点法
- 内存镜像法
- .rsrc 断点找 OEP
- 代码段内存断点
- OllyDbg 脱壳定位入口
---

## 一句话结论

对没有明显 `PUSHAD/POPAD` 或 ESP 定律不便使用的壳，可在 OllyDbg 中先对 `.rsrc`（或改名后的资源段）下内存访问断点并运行，命中后再对资源段上方/原代码段 `.text`/`.code`（UPX 中为 `UPX0`）下断点，第二次命中通常已到解压完成附近，随后用单步追踪收尾即可定位 OEP；所谓“内存镜像法”是同一思路的特例（只下一次代码段内存访问断点，某些 OllyDbg 只在实际执行时中断，需再 F9 一次）。

## 原理

- **壳的执行顺序**：压缩/加密壳先把原程序解压到目标 section，再跳回原入口。壳在自解过程中通常会访问资源段（读取/复制资源、图标、版本信息），或至少会先触碰资源段，再写入/执行代码段。资源段访问是一个早于 OEP 的稳定事件。
- **第一次断点（.rsrc）**：在 Memory Map 中对 `.rsrc` 设置“内存访问断点”，F9/Shift+F9 运行；壳访问资源时中断，此时解压刚开始或进行到一半，位置不稳定但可作为一个“阶段点”。
- **第二次断点（.text/.code）**：在第一次命中后，对资源段上方的原代码段（`.text` 或 `.code`；UPX 压缩后常显示为 `UPX0`）设置内存访问断点，继续运行。壳写入或执行原代码段时第二次中断，通常已经在解压完成/跳向 OEP 附近；若命中的是写入而非执行，再 F9 一次即可等到执行。
- **收尾**：第二次命中后不要直接认定 OEP，继续 F8/F7 单步，观察是否出现原程序特征（函数调用、`POPAD` 后的 `JMP OEP`、VB 的 `CALL ThunRTMain` 等），确认后 dump。
- **内存镜像法为何等价**：某些 OllyDbg 版本的“内存访问断点”只在实际执行（ON EXECUTE）时触发，不区分读/写；因此只需对 `UPX0`/代码段下一次访问断点，F9 等到壳第一次执行解压后的代码段即 OEP。ASPack 等壳可能先在代码段内执行壳代码，第一次命中的不是 OEP，再 F9 一次即可。
- **为什么有效**：断点利用的是“壳必须访问资源段，且最终必须执行原代码段”这两个必然事件，不依赖壳的具体指令序列；比在解压循环里盲目单步稳定。
- **边界**：需要 OllyDbg 忽略所有异常（否则异常会打断流程）；段名可能被改（如 `.rsrc` 改名为其他名字），需在 Memory Map 中按内容/位置识别；资源段被壳加密/剥离时第一次断点可能不命中；ASPack 的第一次代码段命中可能仍在壳内，需要再次 F9。

## 触发条件

- 目标为 32 位 PE，使用压缩/加密壳（原文以 UPX、ASPack 为例）。
- 使用 OllyDbg（或支持内存断点的调试器），并将调试选项中的异常全部设为忽略。
- 资源段存在且壳会访问它；原代码段可被识别（`.text`/`.code`/`UPX0`）。
- 仅用于授权逆向分析与恶意样本分析。

## 利用步骤

1. 载入样本，Options → Debugging options → Exceptions，勾选忽略所有异常（或添加 `00000000-FFFFFFFF` 范围）。
2. 打开 Memory Map，找到 `.rsrc`（或资源段实际名称），右键 → Set memory breakpoint on access。
3. F9/Shift+F9 运行；第一次中断后记录地址（UPX 例为 `0x00409D9A`，ASPack 例为 `0x0040875F`）。
4. 在 Memory Map 中对资源段上方的代码段（`.text`/`.code`/`UPX0`）设置内存访问断点。
5. F9 继续；第二次中断（UPX 例 `0x00409DA1`；ASPack 例 `0x00401000`）。ASPack 若此时不是 OEP 内容，再 F9 一次。
6. 用 F8/F7 单步收尾，确认已进入原程序代码（如看到 `POPAD` 后的 `JMP OEP`、VB 的 `CALL ThunRTMain`、原程序 API 调用），该地址即 OEP。
7. 在 OEP 处 dump 进程内存，再用 Scylla/ImportREC 修复 IAT。

## PoC

```text
# UPX 示例
Memory Map -> .rsrc -> Set memory breakpoint on access
F9  -> 断在 0x00409D9A
Memory Map -> UPX0 -> Set memory breakpoint on access
F9  -> 断在 0x00409DA1
F8/F7 单步 -> POPAD; JMP 00401000 -> OEP

# ASPack 示例
Memory Map -> .rsrc -> Set memory breakpoint on access
F9  -> 断在 0x0040875F
Memory Map -> .code -> Set memory breakpoint on access
F9  -> 断在 0x00401000 (OEP)
```

说明：原文的“内存镜像法”使用只在实际执行时中断的特殊 OllyDbg；对 `UPX0` 下一次访问断点，UPX 直接断在 OEP；ASPack 第一次断在 `0x00401000` 但不是 OEP 内容，再 F9 一次到达 OEP。

## 变体与关联

- **ESP 定律**：入口有 `PUSHAD` 时优先用 PUSHAD 后栈顶硬件访问断点等 `POPAD`，比二次断点更精确；见 [[code-analysis-reverse-unpacking-upx-manual-esp-breakpoint-scylla]]、[[code-analysis-reverse-unpacking-esp-law-seh-fallback-oep]]。
- **FSG 等无 PUSHAD 壳**：用条件记录断点收集 `GetProcAddress`，见 [[code-analysis-reverse-unpacking-fsg-conditional-log-breakpoint-oep]]。
- **VMProtect 压缩壳**：用 Sleep 断点 + security cookie 定位，见 [[code-analysis-reverse-unpacking-vmprotect-compression-sleep-cookie-oep-import-fix]]。
- **一步直达法**：若壳尾是 `JMP/CALL OEP`，可直接搜机器码，见 [[code-analysis-reverse-unpacking-opcode-search-popad-jmp-call-oep]]。
- **IAT 修复**：OEP 只是第一步，dump 后仍需修复 IAT，见 [[code-analysis-reverse-unpacking-iat-redirect-key-jump-nop-two-instance-copy]]。

## 检测与防御

- **检测（样本侧反调试）**：检测内存断点（调试寄存器 DR0-DR3、`GetThreadContext`）、检测异常被忽略、检测调试器存在；对资源段访问加校验/混淆。
- **防御（防护方）**：壳不是安全边界；敏感逻辑应配合完整性校验、反调试与代码加密；对恶意样本分析方，二次断点是通用入口定位手段，需结合 IAT 修复。
- **注意**：断点会改变程序时序，某些壳会在检测到断点后走异常路径，需在干净快照上复现。
