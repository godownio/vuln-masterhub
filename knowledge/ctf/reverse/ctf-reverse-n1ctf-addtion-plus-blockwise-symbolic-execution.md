---
id: ctf-reverse-n1ctf-addtion-plus-blockwise-symbolic-execution
title: N1CTF 2023 addtion plus：48 字节输入按 8 字节加密/16 字节比较，patch 比较与循环次数后用 Ponce 分块符号求解
type: scenario
domain: ctf
path: ctf/reverse
technique: n1ctf-addtion-plus-blockwise-ponce-symbolic-solve
aliases:
- N1CTF addtion plus
- 分块符号执行
- 8 字节爆破
- Ponce 分块求解
- 48 字节 flag
- 加密函数指针
- patch 比较绕过
tags:
- ctf
- reverse
- ponce
- symbolic-execution
- smt
- patch
- linux
- remote-debugging
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V546
  verified_at: '2026-11-11T21:00:33+08:00'
  notes: 已对照原文与全部35张截图核对：scanf("%48s", inputflag) 48 字节输入；call qword ptr [r14+28h]/[r14+40h] 加密函数指针与 cmp r15, 0x30 循环（图30/31）；3 块 16 字节比较 var_E8/var_D8（图24/26）；图27 标注将 or rdx, rax 改为 or rax, rax，图32 已见 cmp r15, 8 与 or rax, rax 的 patch 结果；图29 前 8 字节 SymVar_0…SymVar_7；图34 弹出 30000 instructions has been traced. Do you want to execute 10000 more?；图35 Output 解出 SymVar_0-7 = n,1,c,t,f,{,c,3，即首块 n1ctf{c3，与卡片一致。远程 Linux debugger（图30）与原文'远程文件需删除后重新copy'、约20-30分钟/半小时、17-32 块从17开始等细节均出自原文。置信 medium 合理：原文仅演示首块，未给完整 flag。dedup 推荐 new，self-modifying VM/NCTF cccha 等候选题型与解法不同，非同链。无 affected_versions、无 source_url。未运行题目。
---

## 一句话结论

N1CTF 2023 “addtion plus” 要求 48 字节输入：程序把输入按 8 字节一组、共 6 组依次调用不同加密函数，再把结果按 16 字节分 3 块与目标比较。直接对 48 字节做符号执行规模太大，解法是把比较逻辑 patch 成只比较前 8 字节（`or rdx, rax` → `or rax, rax`）、把加密循环上界 `cmp r15, 0x30` 改成 8，然后用 Ponce 符号化 8 字节输入并在关键比较处 Negate/求解，逐块恢复 flag（首块解出 `n1ctf{c3`）。

## 原理

- **程序结构**：`main` 用 `scanf("%48s", inputflag)` 读入 48 字节；do-while 循环按 8 字节分组，`call qword ptr [r14+0x28]` 等不同函数指针加密每组，`r15` 计数到 `0x30`（48）；加密结果按 16 字节与内嵌目标比较（3 块，每块 `xor rax, [rsp+..var_E8]; xor rdx, [rsp+..var_E8+8]; or rdx, rax; jnz`）。
- **为什么能分块**：加密以 8 字节为单位、每组独立调用加密函数，块之间没有耦合；因此 48 字节的输入可以拆成 6 个独立的 8 字节子问题，每 16 字节比较里包含两组 8 字节，patch 掉第二组即可只针对第一组求解。
- **为什么 patch 循环**：符号执行整条 48 字节路径会让表达式规模扩大约 6 倍，求解时间不可接受；把 `cmp r15, 0x30` 改成 `cmp r15, 8` 只跑第一组加密，显著缩短模拟时间。
- **Ponce 求解**：在输入被读入后，对第一块 8 字节内存执行 Symbolize memory（得到 `SymVar_0`…`SymVar_7`）；运行到关键比较 `xor/or/jnz`，用 `SMT Solver → Negate and Inject/求解` 得到满足比较的 8 个字节；对下一块，把加密起始位置改到对应偏移（例如 17–32 字节块从 17 开始）后重复。
- **实测代价**：单块 8 字节求解约 20–30 分钟（文中“前 8 位爆破要了半小时”）；期间 Ponce 会弹出 `30000 instructions has been traced. Do you want to execute 10000 more?` 的确认框，需要持续点 Yes；Output 会打印 `Branch symbolized detected`、`Solution found! Values:` 与各 `SymVar`。
- **远程调试坑**：使用 IDA remote Linux debugger 时，本地修改后的文件要先把远程旧文件删除再重新 copy，否则调试的是旧版本（文中专门提示）。

## 触发条件

- 目标为 Linux ELF，IDA + Ponce 可用（remote Linux debug server 已配置）。
- 输入读取与关键比较可定位；加密通过函数指针调用，Ponce 能跟踪；能 patch 比较与循环指令（修改调试内存或 IDB）。
- 每块求解耗时可接受（单块约 20–30 分钟）、solver 超时与指令跟踪上限可调。
- 内嵌目标比较数据已知。

## 利用步骤

1. 定位 `main`：确认 `scanf("%48s", inputflag)`，输入长度 48。
2. 分析加密循环：8 字节一组、共 6 次、每次经 `call qword ptr [r14+0x28]` 等不同函数指针；确认比较是 3 块 16 字节（`var_E8`、`var_D8`、…）。
3. **Patch 比较**：把第二组 8 字节参与 `or` 的指令改掉——原 `or rdx, rax` 改为 `or rax, rax`，只保留第一组比较结果。
4. **Patch 循环**：把 `cmp r15, 0x30` 改为 `cmp r15, 8`，只加密第一组以节省模拟时间。
5. 运行到输入读入后，对第一块 8 字节执行 Symbolize memory（Address=输入缓冲区，Size=8）。
6. 运行到关键比较断点，右键 → SMT Solver → Negate and Inject/求解；在 Output 读取 `SymVar_0`…`SymVar_7`（首块得到 `n1ctf{c3`）。
7. 把加密起始偏移改为下一块（例如 17–32 时从 17 开始），恢复/重新 patch 循环与比较，重复 5–6 步求解后续块，拼接 6 个 8 字节块得到完整 48 字节 flag。

## PoC

无 PoC。原文为 CTF 题解，只给出反编译/调试截图与首块求解结果（`n1ctf{c3`），没有完整脚本；本文档环境不运行 IDA/Ponce 与题目二进制。

## 变体与关联

- **与 Ponce 工具卡的关系**：`[[tools-ida-ponce-symbolic-execution-smt-negate-inject]]` 是通用工作流（符号化→断点→Negate and Inject→读 SymVar）；本卡是该工作流在“分块加密+分块比较”题目上的降规模实战。
- **与脚本化约束求解对比**：`[[ctf-reverse-z3-constraint-equation-solve]]`、`[[ctf-reverse-self-modifying-vm-bytecode-z3-symbolic-execution]]` 需要先复刻加密算法；本卡不解密算法本身，直接让 Ponce 在动态执行中收集约束。
- **与分块/逐位爆破对比**：`[[ctf-reverse-vm-instrumentation-instruction-count-bruteforce]]` 用指令计数做逐位侧信道；本卡用“加密粒度小于比较粒度”的差异做分块符号求解，思路同属缩小搜索空间。
- **可复用要点**：先找“加密以 8 字节为单位、比较以 16 字节为单位”的粒度差，再 patch 比较与循环；这是把不可解的大约束拆成可解小约束的通用方法。

## 检测与防御

- 分析侧技术，主要针对 CTF/自有样本；对软件保护而言，可让块间强耦合（链式 IV、前一块密文参与下一块加密）、比较跨块、增加反调试与代码自校验，显著提高分块符号执行的代价。
- 对分析者：优先寻找加密粒度与比较粒度的差异；patch 前记录原始指令，避免破坏后续块的解密；远程调试时确认文件同步，防止调试旧版本。
