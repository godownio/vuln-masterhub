---
id: ctf-reverse-tls-callback-exception-vm-sm3-maze
title: HITCTF 2022 debug_maze 逆向：TLS 回调隐藏逻辑 + PEB 花指令反调试 + 异常分发 VM + SM3 校验迷宫
type: scenario
domain: ctf
path: ctf/reverse
technique: tls-callback-exception-vm-sm3-maze
aliases:
- HITCTF 2022 debug_maze
- TLS 回调隐藏主逻辑
- 异常处理 VM
- int3 与访问违例分发
- SM3 IV 7380166f 识别
- 迷宫逆向
tags:
- ctf
- reverse
- tls-callback
- anti-debug
- vm
- sm3
- maze
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V635
  verified_at: '2026-11-13T01:09:17+08:00'
  notes: 已对照原文与 img/16-25 核对：运行时提示 give me your flag（img/16）；TlsCallback_0 内含 printf/scanf、IsDebuggerPresent 循环（img/22 汇编）；花指令 call $+5→xor eax,3→mul eax 两次得 0x51→fs:[eax-0x21] 取 PEB（img/22）；sub_401320 按 EXCEPTION_BREAKPOINT/ACCESS_VIOLATION + ecx 位掩码分发 VM（对应原文语义表）；sub_4011F0 以 0x7380166F（SM3 IV[0]）做函数名摘要比对；输入两字符转一字节且要求奇数格，走 byte_426B90 迷宫；flag HITCTF2022{4311254395e7d3cf0b372d95b58325674d6117} 与原文一致。未取得题目二进制，flag 未独立复跑，仅做文字/截图核对。dedup：既有 TLS 回调、PEB 反调试、异常 VM 卡均为通用技巧，非同链；dup-scan 无 pair。
---

## 一句话结论

main 只是壳：真正的输入校验在 TLS 回调 `TlsCallback_0` 里，配合 `IsDebuggerPresent` 与花指令（`call $+5; xor eax,3; mul eax` 执行两次得到 `0x51`，再走 PEB 取 kernel32 导入表）隐藏逻辑；校验流程用 `int3`/访问违例两类异常事件分发自定义 VM 指令（ecx 位掩码映射 jnz/push/pop/output/mul 与 add/store/load/cmp/jmp），用 SM3（IV `0x7380166f`）对 API 名做摘要比对实现 GetProcAddress，最后把输入按字节转换为十六进制值并只允许奇数格，走 `byte_426B90` 迷宫得到 flag。

## 原理

- **TLS 回调**：PE 的 TLS 目录注册的回调在进程启动早期（早于 main）执行；本题把 `printf("give me your flag:")`、`scanf` 与主校验都放进 `TlsCallback_0`，main 里只留一个假的 `sub_401170` 提示，所以直接在 main 找字符串会扑空。
- **多层反调试/混淆**：
  - `IsDebuggerPresent()` 为真时进入无限 `__debugbreak()` 循环；
  - `sub_401170` 里的 `call $+5; xor eax,3; mul eax; cmp eax,0x51` 是花指令：`call $+5` 取当前地址后 `mul` 依赖 eax 状态被设计成执行两次，最终 eax=0x51（'Q'），随后 `fs:[eax]` 走 PEB 取 `PEB->Ldr` 链表枚举模块，按导出表哈希取函数地址（GetProcAddress 的哈希实现）。
- **异常分发 VM**：`sub_401320` 调试循环等待调试事件，`EXCEPTION_BREAKPOINT`（0x80000003）与 `EXCEPTION_ACCESS_VIOLATION`（0xC0000005）分别按 `ecx` 的位掩码（1/2/4/8/16/32）分派到不同语义：断点侧对应 jnz/push/pop/CorrectOutput/mul/WrongOutput，访问违例侧对应 add/addn/store/load/cmp/jmp；访问违例处理后 `Eip += 2` 继续。VM 字节码按 `mov ecx,imm; shl ecx,n; mov eax/ebx,imm; int 3` 的形式编码。
- **SM3 识别**：`sub_4011F0` 对字符串做哈希后与传入值比较，比较常量 `0x7380166F` 是 SM3 的 IV 第一个字（完整 IV `7380166f 4914b2b9 172442d7 ...`），由此确认是 SM3 而不是 MD5/SHA；再按 SM3 的 P0/P1、FF/GG 与 Tj 常量还原。
- **迷宫**：输入被按字符转成十六进制值（两个字符 → 一个字节），要求每个字节为奇数；程序从 `byte_426B90`/`sub_401000` 数据中按方向移动，遇到匹配的奇数格才继续，走错或数据不符则 WrongOutput。按“从 01 开始只走奇数格”的规则在网格上寻路即可得到 `HITCTF2022{4311254395e7d3cf0b372d95b58325674d6117}`。
- **为什么成立**：TLS 回调 + 异常分发把真实控制流藏到调试器/静态分析默认看不到的位置；识别出 VM 语义与 SM3 常量后，静态翻译字节码 + 走迷宫即可还原。

## 触发条件

- PE 程序在 TLS 目录注册了回调（`TlsCallback_0`），或 main 逻辑异常简单、字符串在 main 中找不到。
- 存在 `IsDebuggerPresent`/PEB 走查/花指令等反调试，静态分析需 patch 或绕过。
- 校验逻辑由异常事件驱动的 VM 或等价的自定义指令流实现。
- 校验使用 SM3（可通过 IV/Tj 常量识别）或其它哈希。

## 利用步骤

1. 检查 PE TLS 目录与 `TlsCallback_0`，把分析入口从 main 移到回调；对 `IsDebuggerPresent` 分支 patch/跳过。
2. 识别花指令：`call $+5` 后配合 `mul` 两次得到 `0x51`，`fs:[eax]` 为 PEB 基址，继续跟到导出表哈希解析。
3. 在 `sub_401320` 下断/跟踪调试事件，记录 `ecx` 位掩码与 `eax/ebx` 参数，把 VM 字节码翻译成高层指令序列（可用脚本解析 `mov ecx,imm; shl ecx,n; ...; int 3` 模式）。
4. 在 `sub_4011F0` 看到 `0x7380166F`，确认 SM3，还原哈希校验逻辑与目标。
5. 提取 `byte_426B90/sub_401000` 迷宫数据，按“只走奇数格”的规则 BFS/DFS 求路径。
6. 把路径编码为输入（十六进制字符对 → 字节，均为奇数），提交得到 flag。

## PoC

```python
# VM 字节码翻译（原文思路）：解析 mov ecx,imm; shl ecx,n; mov eax/ebx,imm; int 3 序列
ins = ['mov','ecx','1','shl','ecx','3','mov','eax','2','mov','ebx','9','xor','edx','edx',
       'mov','edx','[edx]','mov','ecx','1','shl','ecx','1','int','3','popa']
# ecx 位掩码 -> 断点侧/访问违例侧语义，翻译后得到
# sub_D33610(2,9); sub_D336D0(4); ... CorrectOutput()/WrongOutput()
print('HITCTF2022{4311254395e7d3cf0b372d95b58325674d6117}')
```

```text
# 关键识别点：
# 1) TlsCallback_0 中执行 scanf 与校验（main 只调用假的 sub_401170）
# 2) call $+5; xor eax,3; mul eax; cmp eax,0x51 -> PEB walk
# 3) 0x7380166F = SM3 IV[0]，不是 MD5/SHA
# 4) 迷宫从 01 开始只走奇数格
```

## 变体与关联

- 变体：TLS 回调也可用于反调试（在回调里检测调试器并改行为），绕过方式见关联卡。
- 变体：异常分发 VM 可换成 SEH/VEH、`int 2Dh`、硬件断点等方式；核心是“调试事件即指令流”。
- 关联：[[code-analysis-reverse-anti-debug-tls-callback-pe-null-patch]]（TLS 回调反调试与 patch）、[[code-analysis-reverse-anti-debug-peb-fields-patch]]（PEB 检测绕过）、[[code-analysis-reverse-crypto-encoding-identification-decrypt]]（SM3 常量识别）、[[ctf-reverse-fixed-grid-wasd-maze-bfs-path-md5]]（迷宫 BFS 题型）。
- 边界：不同编译器/保护下花指令形态与 VM 编码不同；SM3 也可能被换成国密变体，需按 IV/Tj 常量确认。

## 检测与防御

- CTF/开发视角：TLS 回调与异常分发只能提高分析成本；关键校验不要放客户端，哈希也不能替代授权。
- 逆向视角：main 无逻辑时先查 TLS 目录；遇到调试事件分发的程序，优先把“事件 + 上下文寄存器”翻译成指令流，再按常量识别哈希。
