---
id: code-analysis-reverse-unpacking-virtualalloc-size-hwbp-pe-dump
title: OD 脱壳：VirtualAlloc 断点按分配大小筛出载荷，首字节硬件访问断点跟到 MZ 后 dump 解密 PE
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: virtualalloc-size-filter-hwbp-pe-dump
tags:
- reverse
- unpacking
- ollydbg
- virtualalloc
- hardware-breakpoint
- memory-dump
- pe
- malware-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V461
  verified_at: '2026-11-10T14:11:20+08:00'
  notes: 已对照原文与 17 张图片核对：bp VirtualAlloc、0xE0(224) 小分配 vs 0x760000 大分配筛载荷、首字节硬件访问断点、F8 跟到 4D 5A/DOS Stub、保存 884KB .mem 后 IDA 可反编译（FLIRT 命中）均与截图一致；卡内已注明 PoC 为操作流程。未验证点：未在本地复跑该样本。dup-scan.json 早于建卡且无本篇 pair；dedup 最高候选 aPLib DLL VirtualAlloc/VirtualProtect dump 卡为同族不同手法（其看 M8Z/截断、本卡按大小筛选+首字节硬件断点），非同一条链。
url: /docs/code-analysis/reverse/unpacking/code-analysis-reverse-unpacking-virtualalloc-size-hwbp-pe-dump/
draft: false
kb_aliases:
- VirtualAlloc 断点脱壳
- 分配大小筛选载荷
- 硬件访问断点跟解密
- OD dump 解密 PE
- 混淆壳手动脱壳
- 4D 5A 内存定位
---

## 一句话结论

对运行时自解密的混淆壳样本，在 `VirtualAlloc` 下断点并用“分配大小”过滤掉小型噪声分配（如 224 字节），对较大内存区的首字节下硬件访问断点，运行到壳解密循环写入后即可在内存中看到 `4D 5A`（MZ）与 DOS Stub，按分配基址 dump 整块内存即可得到可静态分析的解密 PE。

## 原理

- 加密/混淆壳在入口阶段必须先申请可写内存（`VirtualAlloc`），再把解密后的 PE 或代码写入并跳转执行；因此 `VirtualAlloc` 的返回地址就是明文载荷的落点。
- 壳运行期间会有大量小分配（字符串、COM/系统调用参数等），直接用分配大小判断可快速排除噪声：原文先遇到 `Size = 0xE0`（224 字节）的小分配，继续运行后出现 `0x760000` 的大分配，后者符合 PE 镜像的量级。
- 拿到分配地址后，在该地址首字节下**硬件访问断点**（OllyDbg 内存窗口右键 → 硬件断点 → 字节），壳一旦向该缓冲区写入就会断下；随后用 F8 单步跟进解密循环，直到缓冲区出现 `4D 5A 90` 与 ASCII `This program cannot be run in DOS mode`。
- 此时按分配基址把整块内存“保存数据到文件”（原文得到数百 KB 的 `.mem`），即得到解密后的 PE；IDA 可直接加载并恢复 `winMain` 等函数（原文 IDA 输出显示 FLIRT 签名命中、可正常反编译）。

## 触发条件

- 样本可在调试器中运行（无强反调试/反虚拟机，或已绕过）；壳使用 `VirtualAlloc` 申请可写内存并在内存中还原 PE。
- 调试器支持硬件断点（OllyDbg/x32dbg 等）。
- 壳为单层或少量层内存解密；多层壳需要按同样思路对每次新分配重复下断点。

## 利用步骤

1. 用 OllyDbg 打开样本（原文将 DLL 改后缀为 `.exe` 打开，对“代码可能被压缩/加壳”的提示选“否”继续）。
2. 命令行 `bp VirtualAlloc` 下断，F9 运行；每次断下查看栈参数（`Size`、`AllocationType`、`Protect`）与返回地址。
3. 跳过小分配（如 `0xE0`）继续 F9，直到出现符合 PE 大小的大分配（如 `0x760000`）；记录其返回地址（寄存器/栈中的分配基址）。
4. 在该地址首字节下硬件访问断点（字节），F9 运行到壳写入处；F8 单步跟进，观察内存出现 `4D 5A` 及 DOS Stub 字符串。
5. 在内存窗口按分配基址“保存数据到文件”，得到 `.mem`；用 IDA 打开验证是否为完整 PE（可正常识别函数/导入表）。
6. 若 dump 开头带壳头或多余前缀，按 `MZ`/`PE\0\0` 截断后再分析。

## PoC

无脚本 PoC；原文以 OllyDbg 操作截图演示，关键观察点为：小分配 `Size = 0xE0 (224.)` → 大分配 → 内存出现 `4D 5A`/`This program cannot be run in DOS mode` → 保存 `.mem` 后 IDA 可加载。

## 变体与关联

- **断点位置变体**：也可在 `RtlCopyMemory`/`memcpy`/`VirtualProtect` 处下断，或用 `WriteProcessMemory` 抓进程替换载荷；区别在于本卡用“分配大小 + 首字节硬件断点”定位自解密缓冲区。
- **多层壳**：新分配的内存里写入机器码再申请新内存时，对每一轮新分配重复下断点，直到出现最终 PE。
- **关联**：[[code-analysis-dynamic-debugging-multi-layer-shellcode-decrypt-dump]]（VirtualAlloc/RtlCopyMemory 断点 dump 加密 shellcode）、[[code-analysis-reverse-unpacking-dll-aplib-virtualalloc-protect-dump]]（DLL + VirtualAlloc/VirtualProtect 断点定位 aPLib 载荷）、[[code-analysis-reverse-unpacking-writeprocessmemory-memory-block-pe-carve]]（WriteProcessMemory 抓进程替换载荷与内存 PE 雕刻）。

## 检测与防御

- **分析侧**：对可疑样本优先在 `VirtualAlloc`/`VirtualProtect` 下断并观察大块可写内存，结合内存扫描（MZ/PE 头、高熵段）快速定位解密载荷。
- **防御侧**：终端侧监控异常 `VirtualAlloc` + 自解密执行行为（RW→RX 内存、无文件 PE 执行）；启用内存扫描与 ETW 行为遥测；对加壳样本结合沙箱与内存取证，避免仅凭静态特征漏判。
