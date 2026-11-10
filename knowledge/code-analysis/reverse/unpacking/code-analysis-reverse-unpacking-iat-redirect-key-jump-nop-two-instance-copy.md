---
id: code-analysis-reverse-unpacking-iat-redirect-key-jump-nop-two-instance-copy
title: IAT 全部重定向（API Redirect）的识别与修复：NOP 关键跳转保留 API 地址，或从另一 OEP 实例二进制复制 IAT
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: iat-redirection-import-repair
aliases:
- IAT 重定向
- API Redirect 脱壳
- ImportREC 跟踪级别1
- IAT 修复 NOP 关键跳转
- 双实例复制 IAT
- Yoda's Crypter IAT
tags:
- reverse
- unpacking
- iat
- importrec
- ollydbg
- oep
- pe
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V285
  verified_at: '2026-11-08T05:00:53+08:00'
  notes: 已对照原文与56张图逐项核对：CALL [460ADC]→0x754D57 JMP 759D1C10 证实 IAT 重定向（图13-14）、IAT 0x460818-0x460F28 大小0x710（图16-18、19）、ImportREC 显示无效→跟踪级别1 修复（图19-22）、内存写断点看到 0x465730 先写API地址与 0x46579D 再写重定向地址（图24-26）、CMP EBX,70000000/JB/JBE 0x46577D 关键跳（图28、31）、NOP 后 IAT 填好且可导出（图31-35）、双实例复制 IAT（图36-41）。全部与卡片一致。原子性：IAT 重定向识别+两种修复（NOP关键跳/双实例复制）为同一场景的并列修复法，未过粗。dedup new/related。dup-scan 与 14618 卡（OllyDbg RUN 跟踪停止条件 + ImportREC 插件/Tracer 分级修复）判 likely_duplicate：裁决为并列保留——两卡核心原子不同（14618 是 RUN 跟踪条件与 ImportREC 分级工具链，本卡是两遍写 IAT 的机制识别与 NOP/双实例修复），仅『NOP 关键跳』一步重叠且本卡给出 14618 未覆盖的双实例复制；14618 已 verified，本卡有独立可复用内容，故不删除任一张，建议在变体与关联互链（本卡关联列表已含 14618 相关主题）。未执行样本。
---

## 一句话结论

壳在自解时会先往 IAT 写真实 API 地址，随后又用重定向地址（JMP 桩）覆盖，导致 ImportREC 直接获取导入表全部无效；在 IAT 地址下内存写断点可看到"两次写入"，找到控制第二次写入的关键条件跳转（`CMP EBX,70000000`/`JB`/`JBE`）并 NOP 掉，IAT 就保留 API 地址，再用 ImportREC 导出；另一种更稳妥的办法是另开一个实例跑到 OEP，把正确 IAT 的二进制复制覆盖当前实例后再 dump。

## 原理

- IAT 重定向（API Redirect）：壳不希望程序直接调用系统 API，而是让 IAT 项指向自己生成的跳转桩（`JMP <API>`），从而在调用前后插入逻辑。于是 IAT 中存储的不是 API 地址本身，而是桩地址；ImportREC 按 API 名称解析时全部失败，显示无效。
- 原文样本的写入过程是两遍：先在 `0x00465730` 附近写入 API 地址，再在 `0x0046579D` 的 `MOV DWORD PTR DS:[EDX],ESI` 写入重定向地址覆盖。两次写入之间存在条件判断：`CMP EBX,70000000; JB ...; CMP EBX,77FFFFFF; JBE 0x0046578D`，其中 `0x0046577D` 的 `JBE` 决定是否跳过重定向写入。
- 修复思路一（原地）：把 `0x0046577D` 的 `JBE` NOP 掉，让重定向写入不执行，IAT 保留 API 地址；继续运行/让壳完成填充后，用 ImportREC 以 OEP、IAT-Start、IAT-Size 导出（显示无效 → 跟踪级别1(反汇编) 修复残余项）。
- 修复思路二（双实例）：另开一个 OllyDbg 实例加载同一程序，正常运行到 OEP，此时它的 IAT 是正确的 API 地址；把该 IAT 区间的二进制复制，粘贴覆盖到当前（未到 OEP 的）实例的同一地址，再 dump + ImportREC。这样不需要修改壳代码，避免破坏完整性/触发检测。
- IAT 起止定位：从一个 `CALL DWORD PTR DS:[IAT]` 出发，跟到目标 `JMP` 桩，再回到 IAT 地址；向上/向下扫描，找到既不是 API 地址也不是重定向地址的值，边界即 IAT 起止（本例 `0x00460818`–`0x00460F28`，大小 `0x710`）。

## 触发条件

- 目标 PE 的壳会重定向 IAT（所有导入项指向壳的 JMP 桩，而非 API 函数）。
- 能运行 OllyDbg/x32dbg，并在 IAT 区间设置内存写断点（或硬件写断点）。
- 使用 ImportREC/OllyDump（或 Scylla）做转储与导入修复。
- 程序有反调试/异常检测时，NOP 关键跳转可能导致异常，需准备好双实例复制方案。

## 利用步骤

1. 在 OEP 处找到一条 `CALL DWORD PTR DS:[<IAT项>]`（本例 `0x004271D6 CALL DWORD PTR DS:[460ADC]`）。
2. 跟进该 IAT 项指向的地址；若看到 `JMP <API>`（本例 `0x00754D57 JMP 759D1C10`），说明 IAT 被重定向。
3. 确定 IAT 起止：在数据窗口以地址方式查看 IAT 项，向上/向下找到既非 API 地址也非重定向地址的值；本例起始 `0x00460818`、结束 `0x00460F28`，大小 `0x710`。
4. 对该 IAT 地址设内存写断点（内存写入断点在写入语句前中断，便于观察两遍写入）。
5. F9 观察第一次写入（API 地址，约 `0x00465730`），继续 F9 到第二次写入（`0x0046579D MOV [EDX],ESI`，重定向地址）。
6. 单步回溯，找到控制第二次写入的条件跳转；本例 `0x0046577D JBE 0x0046578D`，把它 NOP 掉，删除内存断点。
7. 继续 F9 让壳完成 IAT 填充（可能触发壳的异常检测，IAT 已填好即可终止）。
8. ImportREC：选进程、填 OEP `0x004271B0`、RVA `0x00060818`、大小 `0x000710`，获取导入表；对无效项用"显示无效 → 跟踪级别1(反汇编)"修复，修正转储到 Dump.exe。
9. 备选：另开实例跑到 OEP，复制其 IAT 二进制，粘贴覆盖当前实例 IAT，再 OllyDump + ImportREC。

## PoC

```text
样本：UnPackMe_YodasCrypter1.3.exe
OEP: 0x004271B0
IAT: 0x00460818 - 0x00460F28 (size 0x710)
第一次写入: 0x00465730 附近写入 API 地址
第二次写入: 0x0046579D  MOV DWORD PTR DS:[EDX],ESI  (重定向地址)
关键判断:
  0046576F  CMP EBX,70000000
  00465775  JB  SHORT 0046577F
  00465777  CMP EBX,77FFFFFF
  0046577D  JBE SHORT 0046578D   <-- NOP 这里，跳过重定向写入
ImportREC: OEP 000271B0 / RVA 00060818 / Size 00000710
```

双实例复制：

```text
实例 A：正常跑到 OEP 0x004271B0，IAT 为正确 API 地址
实例 B：同一程序，在 OEP 前暂停；选中 A 的 0x00460818-0x00460F24 二进制复制
       在 B 的数据窗口同地址右键 -> 二进制粘贴
       OllyDump 转储 B -> ImportREC 修正转储
```

## 变体与关联

- 变体：Scylla 的 IAT Autosearch 对 IAT 重定向的识别能力更强；先试自动，失败再手工。
- 变体：重定向地址可能是在 OEP 之后才写入（壳的延迟初始化），需要在 OEP 后再对 IAT 下写断点观察。
- 变体：IAT 项可能是加密/编码而非 JMP 桩，需要先跟踪解密循环再修复（与本卡不同）。
- 关联：[[code-analysis-reverse-unpacking-upx-manual-esp-breakpoint-scylla]]（Scylla 的 Autosearch/Get Imports/Fix Dump 流程）。
- 关联：[[code-analysis-reverse-unpacking-fsg-conditional-log-breakpoint-oep]]（通过 GetProcAddress 写 IAT 的循环定位 IAT 边界）。

## 检测与防御

- 检测（分析侧）：IAT 项指向壳内区间而非系统 DLL；IAT 区间出现 JMP 桩；导入表在静态解析时异常少/全无效；运行期对 IAT 区间的写入。
- 检测（防护侧）：加壳/重定向 IAT 只提高逆向成本，不是安全边界；关键逻辑放服务端，配合代码签名、完整性校验与反调试。
- 边界：NOP 壳代码可能破坏后续解压或触发完整性校验；优先用双实例复制或 Scylla 重建，减少对壳代码的修改。
