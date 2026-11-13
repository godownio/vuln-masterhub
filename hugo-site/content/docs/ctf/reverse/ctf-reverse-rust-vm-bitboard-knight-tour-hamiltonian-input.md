---
id: ctf-reverse-rust-vm-bitboard-knight-tour-hamiltonian-input
title: TetCTF2024 rust_vm：Rust 自定义 VM 逆向，识别 8×8 位矩阵马步校验后用骑士巡游（Hamiltonian 路径）构造输入
type: scenario
domain: ctf
path: ctf/reverse
technique: rust-custom-vm-knight-tour-bitboard
tags:
- ctf
- reverse
- vm
- rust
- bytecode
- disassembler
- knight-tour
- hamiltonian-path
- bitboard
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V565
  verified_at: '2026-11-12T07:56:28+08:00'
  notes: 已对照原文全文与12张图核对：主函数/switch分派(unwrap/Unknown ops code)、反汇编器opcode表(0..28)逐条与原文代码一致；起点reg7=2/reg8=6对应mem[0xa0+6] bit2（图06）、终局sum==0x7f8且reg7==7/reg8==2（图08/09/10手绘盘与PoC chess矩阵一致：1在C2、64在H6）；原文伪代码把0x1ac求和写成0xa8个元素，按反汇编实际为mem[0xa0..0xa8)共8字节，卡内已修正（8×0xff=0x7f8）；PoC的(y<<4)|x编码与range(2,65)逻辑同原文，图12显示Seem correct/flag TetCTF{TheRe_i$...}一致。dedup：除自身外最高为ctf-reverse-custom-python-vm-bytecode-disassembler等VM题卡，均为related/new，题目与解题模型不同，非同链；关联的4张卡均存在。CTF题无组件版本，未设versions；未实际连远程复现（服务已下线），但矩阵逻辑经手算核对自洽。
url: /docs/ctf/reverse/ctf-reverse-rust-vm-bitboard-knight-tour-hamiltonian-input/
draft: false
kb_aliases:
- TetCTF2024 rust_vm
- Rust VM 逆向
- 自定义 VM 反汇编器
- 骑士巡游校验
- Knight's tour VM
- 8x8 位矩阵马步
- Hamiltonian 路径输入构造
---

## 一句话结论

TetCTF2024 的 `rust_vm` 用 Rust 实现了一个自定义字节码 VM：主循环把输入按"低 4 位 x、高 4 位 y"逐个解释为棋盘坐标，要求每一步都是相对当前位置的合法马步（knight move）且不能落在已点亮的格子，最终点亮 8×8 棋盘全部 64 位（8 字节和 = 0x7f8）并停在 (7,2)。逆向时先识别 VM 的 opcode/寄存器/内存/栈布局、写 switch-case 反汇编器，再从字节码还原出"位矩阵 + 马步校验"，最后用一条满足起点 (2,6)、终点 (7,2) 的骑士巡游路径（Hamiltonian 路径）编码成输入即可通关。

## 原理

- **自定义 VM 结构**：程序分配一块内存 `mem`，输入放在 `mem` 头部；堆栈位于 `&mem + 0x1000`，9 个 16 位寄存器位于 `&mem + 0x3000`。指令以第一个字节为 opcode，长度可变（2/3/4 字节），主循环 `switch(opcode)` 分派。
- **opcode 语义**（由反汇编器恢复）：`0 mov reg,reg`、`1 mov reg,imm16`、`2 add`、`3 sub`、`4/5 mov reg,BYTE/WORD [reg]`、`6 mul`、`7 div`、`8 mod`、`9 xor`、`10 not`、`11 and`、`12 or`、`13 shl`、`14 shr`、`15 push`、`16 pop`、`17 cmp`、`18 jmp`、`19 je`、`20 jne`、`21 jl`、`22 jge`、`23 final check`、`24/25 mov BYTE/WORD [reg],reg`、`26 call`、`27 ret`、`28 exit`。条件跳转/相对寻址按低字节+高字节拼 16 位偏移。
- **反汇编器**：因为指令少，直接用 Python `match opcode` 的 switch-case 解析 `code` 字节流即可，边解析边打印伪指令与地址标签，得到 5 个函数：`0x168` 置位、`0x18c` 取位、`0xf1` 校验马步、`0x1ac` 终局判定、主函数。
- **还原出的校验逻辑**：
  - 初始化在 `mem[0xa0..0xa8)`（8 字节 = 8×8 位矩阵）中置起点 bit：主函数先 `mov reg7,2; mov reg8,6; call 0x168`，即起点 (x=2, y=6)；`0x168` 执行 `mem[0xa0+reg8] |= 1<<reg7`。
  - `0x70/0x80` 两张表存 8 组马步偏移（±1/±2 组合）；`0xf1` 要求输入坐标在 0..7 且 `(reg3+reg7, reg3'+reg8)` 命中某一组偏移——即**合法马步**。
  - 主循环逐字节读输入：`reg1 = b & 0xf`（x）、`reg2 = b >> 4`（y）；先 `0xf1` 校验是否合法马步，再 `0x18c` 检查目标位是否已为 1（重复访问则失败），然后 `0x168` 置位并把当前位置更新为 (x,y)。
- **终局判定**：`0x1ac` 把 `mem[0xa0..0xa8)` 8 个字节求和，要求 `sum == 0x7f8`（即每字节 0xff，64 位全亮），同时 `reg7==7 && reg8==2`（终点 (7,2)），返回 1 即 WIN。
- **为什么是骑士巡游**：64 个格子只能各走一次、每步必须是马步、走满全盘——这正是 8×8 棋盘上的 open knight's tour（Hamiltonian 路径），带固定起点/终点约束。找到一条路径后，把第 2..64 步的坐标按 `(y<<4)|x` 编码成字节串发送即可。作者用现成的巡游序列手工对照棋盘，再脚本映射为输入。

## 触发条件

- CTF 逆向题/自定义字节码 VM 程序，输入从 `mem` 头部读入、以位图/矩阵作为校验状态。
- 主循环存在 opcode 分派与可变长指令；无符号表/调试信息（Rust release）。
- 校验逻辑可还原为图上的路径问题（马步、迷宫、邻接矩阵等）。

## 利用步骤

1. 静态定位主处理函数与 `switch(opcode)` 分派，确认 `mem`、寄存器区、栈区、ip 的布局与输入位置。
2. 按 opcode 语义写 Python 反汇编器（switch-case + 地址标签），解析内嵌字节码 `unk_4B170`。
3. 还原 5 个函数：置位、取位、马步校验、终局判定、主循环；把伪代码翻译成等价 Python 模拟器验证。
4. 识别语义：8×8 位矩阵 + 8 组马步偏移 + 全位点亮 + 固定终点 → 骑士巡游；起点由主函数 `reg7=2, reg8=6` 确定。
5. 求一条从 (2,6) 出发、覆盖 64 格、终点为 (7,2) 的马步路径（可用已知巡游序列映射、Warnsdorff 启发式或带约束的 DFS/ILP）。
6. 按第 2..64 步顺序生成字节 `(y<<4)|x`，作为输入发送；收到 `Seem correct. Here is your flag` 即成功。

## PoC

```python
from pwn import *
# 已求得的巡游顺序：数字 1..64 表示访问次序，矩阵下标即棋盘坐标
chess = [
    [39,22,59,8,35,26,63,10],
    [58,7,38,23,62,9,34,27],
    [21,40,5,60,25,36,11,64],
    [6,57,24,37,12,61,28,33],
    [41,20,53,4,45,32,51,14],
    [56,3,44,17,52,13,48,29],
    [19,42,1,54,31,46,15,50],
    [2,55,18,43,16,49,30,47],
]
flat = [v for row in chess for v in row]
to_send = []
for i in range(2, 65):          # 第 1 步是起点 (2,6)，不发送
    pos = flat.index(i)
    x, y = pos % 8, pos // 8
    to_send.append((y << 4) | x)  # 高 4 位 y，低 4 位 x
io = remote('139.162.1.95', 31337)
io.recv()
io.sendline(bytes(to_send))
io.interactive()
# Seem correct. Here is your flag
# TetCTF{TheRe_i$_4_KNighT_iN$iD3_VirTu41_w0RLd}
```

## 变体与关联

- 同类 VM 逆向：[[ctf-reverse-custom-stack-vm-bytecode-constraint-recovery]]（栈式 VM + 跳转表 + 逐字符约束）、[[ctf-reverse-custom-python-vm-bytecode-disassembler]]（Python VM 反汇编 + 变换逆推）、[[ctf-reverse-vm-opcode-low2-format-high6-dispatch]]（opcode 位域分派）、[[code-analysis-reverse-vm-binary-ninja-custom-isa-architecture-plugin]]（Binary Ninja 自定义 ISA 插件）。
- 变体：位图校验换成迷宫/邻接矩阵/数独约束时，同样是"还原状态转移 + 图搜索"；带固定起终点时 BFS/DFS 可能找不到，需 Warnsdorff、回溯或 ILP/CP-SAT。
- 变体：Rust VM 若把 opcode 表加密或字节码运行时解密，先动态 dump 解密后的字节码再写反汇编器。
- 边界：若校验加入哈希/真实密码学或路径不唯一且无法判定，需另找约束；本题是 open tour，路径可手工/离线求解。

## 检测与防御

- **CTF/验证**：用还原的 Python 模拟器正向跑输入，应看到 64 位全亮且终局返回 1；远程返回 flag 即路径正确。
- **防御**：客户端校验不能作为安全边界；自定义 VM 只提高逆向成本，密钥/授权应放服务端。
- **检测信号**：二进制存在 `Unknown opscode`/`called Result::unwrap() on an Err value` 等 Rust VM 特征串；大块字节码常量；主循环 `switch` 分派 + 可变长指令。
