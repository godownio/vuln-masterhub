---
id: code-analysis-reverse-unpacking-fsg-conditional-log-breakpoint-oep
title: 无 PUSHAD 的 FSG 壳脱壳：条件记录断点收集 GetProcAddress 地址，循环末尾条件断点跟到 OEP
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: fsg-unpack-conditional-log-breakpoint-oep
aliases:
- FSG 1.31 脱壳
- 无 PUSHAD 壳
- 条件记录断点 脱壳
- GetProcAddress 循环 OEP
- ESI 定位 IAT 边界
- FSG 手动脱壳
tags:
- reverse
- unpacking
- fsg
- oep
- ollydbg
- iat
- pe
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V285
  verified_at: '2026-11-08T05:00:55+08:00'
  notes: 已对照原文与56张图逐项核对：FSG 1.31 PEID（图42）、入口无 PUSHAD（图44）、关键跳转 0x477FD2/0x478000/0x478052（图44-46）、LoadLibraryA/GetProcAddress/MOV [ESI],EAX 循环与 JE 0x440300 跳 OEP（图45-46）、条件记录断点记录 EAX 最后值 0x73590C70（图47-48）、0x478098 条件断点 EAX==73590C70 命中后跟到 OEP 0x440300（图49-51）、IAT 0x4430F0-0x443674 大小0x584、ImportREC 修复（图53-56）均一致。本卡为单一「无PUSHAD FSG壳条件记录断点定位OEP」原子。dedup new/related（UPX ESP/Scylla 等），dup-scan 与 esp-law 卡为 related 非重复。未执行样本。
---

## 一句话结论

FSG 1.31 入口没有 `PUSHAD`，ESP 定律不适用；可单步追踪（循环 F4、`call` 先 F8 再 F7）+ 条件记录断点记录 `GetProcAddress` 写 IAT 时返回的每个 API 地址，取最后一条 API 地址作条件断点值，在填充循环末尾 `TEST EAX,EAX` 处设 `EAX == 最后API`，命中后跟随 `JE <OEP>` 跳转即可到 OEP；IAT 起止由 `MOV [ESI],EAX` 的首末 ESI 地址得到，再用 ImportREC 修复。

## 原理

- FSG 的解压 stub 不使用 `PUSHAD` 保存全部寄存器，而是在循环里逐个解析导入：`PUSH EDI`（DLL 名）→ `CALL [EBX]`（LoadLibraryA）→ `XCHG EAX,EBP`；`PUSH EDI`（API 名）→ `PUSH EBP` → `CALL [EBX+4]`（GetProcAddress）→ `MOV [ESI],EAX` 写入 IAT，ESI 递增。
- 循环结束条件：`TEST EAX,EAX; JNZ <循环>`。当最后一个 API 解析完、下一条 GetProcAddress 返回 0 时，EAX=0，JNZ 不跳，随后执行 `JE <OEP>`（本例 `0x0047808A - 0F84 7082FCFF JE 0x00440300`）跳回原程序入口。
- 为什么用条件记录断点：循环次数多（数百个 API），单步不现实；条件记录断点把每次 `GetProcAddress` 的返回值写进日志，日志最后一条即"最后一个 API 地址"。把它作为条件断点值，就能在循环最后一次迭代的末尾精确停下，而不必猜次数。
- IAT 边界：在 `MOV [ESI],EAX` 处观察第一次与最后一次写入的 ESI 值即可得到 IAT 范围（本例 `0x004430F0` 到 `0x00443670+4=0x00443674`）；ImportREC 用该 RVA 与大小修复。

## 触发条件

- 目标为 FSG 或类似的非 PUSHAD 压缩/加密壳（入口无 PUSHAD，导入在循环中解析）。
- 使用 OllyDbg/x32dbg，支持条件记录断点与条件断点。
- 程序可正常运行到 OEP（壳无强反调试，或已绕过）。
- 需要手动 dump + ImportREC/Scylla 修复导入。

## 利用步骤

1. PEID 识别壳（本例 FSG 1.31），载入 OllyDbg，入口 `0x0047806D` 附近确认没有 PUSHAD，而是 `LOADLIBRARYA/GETPROCADDRESS` 循环。
2. 单步追踪定位关键跳转：循环/回跳用 F4 跳到下一条，`CALL` 先 F8 观察是否返回，必要时 F7 跟进；本例记录关键跳转 `0x00477FD2 JNB`、`0x00478000 JE`、`0x00478052 JE`。
3. 在 `MOV [ESI],EAX`（`0x00478095`）处设条件记录断点，记录表达式 `EAX`；清空日志，F9 运行。
4. 运行结束后查看日志，最后一条 API 地址即循环最后一次迭代的返回值（本例 `0x73590C70`）。
5. 在循环末尾 `0x00478098 TEST EAX,EAX` 处设条件断点：`EAX == 73590C70`；重新运行，命中后单步到 `0x0047808A JE 0x00440300`，跟跳到 OEP。
6. 在第一次与最后一次 `MOV [ESI],EAX` 处记录 ESI：起始 `0x004430F0`、末尾 `0x00443670`，IAT 结束为 `0x00443674`。
7. OllyDump 在 OEP `0x00440300` 转储；ImportREC 填 OEP `0x00040300`、RVA `0x000430F0`、大小 `0x584`，获取导入并修正转储。
8. 运行修复后的程序验证。

## PoC

```text
样本：unpackme- FSG 1.31 - dulek.exe
EP: 0x0047806D
加载 DLL:   00478071 PUSH EDI (DLL Name); 00478072 CALL [EBX] (LoadLibraryA); 00478074 XCHG EAX,EBP
获取 API:   00478090 PUSH EDI (API Name); 00478091 PUSH EBP; 00478092 CALL [EBX+4] (GetProcAddress)
写 IAT:     00478095 MOV [ESI],EAX
循环尾:     00478098 TEST EAX,EAX; 0047809A JNZ 0x00478075
跳 OEP:     0047808A JE 0x00440300
最后 API: 0x73590C70（条件记录断点日志的最后一条）
OEP: 0x00440300
IAT: 0x004430F0 - 0x00443674（大小 0x584）
```

OllyDbg 条件记录断点（0x00478095）：`条件: 1`，`记录表达式: EAX`；循环尾条件断点（0x00478098）：`EAX == 73590C70`。

## 变体与关联

- 变体：其他壳（ASPack、PECompact 等）也用导入解析循环；同样可用"记录 GetProcAddress 返回值 + 最后一次条件断点"定位 OEP，只是寄存器/指令不同。
- 变体：循环次数固定时，可直接在日志里数次数，或用脚本（OllyScript/x64dbg 脚本）自动记录与断点。
- 变体：IAT 边界也可由 ImportREC 的 IAT Autosearch 自动找；手工 ESI 观察用于校验。
- 关联：[[code-analysis-reverse-unpacking-upx-manual-esp-breakpoint-scylla]]（有 PUSHAD 的壳用 ESP 定律）。
- 关联：[[code-analysis-reverse-unpacking-iat-redirect-key-jump-nop-two-instance-copy]]（IAT 重定向的另一种修复）。
- 关联：[[code-analysis-reverse-unpacking-esp-law-seh-fallback-oep]]（ESP 定律失效时的回退）。

## 检测与防御

- 检测（分析侧）：入口无 PUSHAD、导入表异常少、运行期 `LoadLibraryA/GetProcAddress` 循环与 `MOV [ESI],EAX` 写 IAT、最后 `TEST EAX,EAX; JNZ` 循环退出后远跳，是 FSG 类壳的典型特征。
- 检测（防护侧）：壳不是安全边界；关键逻辑放服务端，配合完整性校验、反调试与代码签名。
- 边界：若壳在 OEP 前还有多层解压/校验，条件断点可能命中多次；需结合日志与调用栈确认最后一次迭代。
