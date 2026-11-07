---
id: ctf-reverse-linux-junk-xor-embedded-elf-nand-circuit-z3
title: LinuxChal 多层逆向：花指令修复 + XOR 0x27 内嵌 ELF + 魔改 RC4 数组 + z3 解 NAND 电路
type: scenario
domain: ctf
path: ctf/reverse
technique: linux-junk-embedded-elf-nand-circuit-z3
tags:
- ctf
- reverse
- linux
- anti-disassembly
- embedded-elf
- rc4
- nand
- z3
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:37:24+08:00'
  notes: 已对照原文与图47-60核对：00->90花指令、XOR 0x27内嵌ELF、KeyKEyKeY...、v194三元组NAND、0x3F0条、CIPH/TAIL与z3 flag一致
url: /docs/ctf/reverse/ctf-reverse-linux-junk-xor-embedded-elf-nand-circuit-z3/
draft: false
kb_aliases:
- LinuxChal
- 花指令修复
- 00 改 90
- XOR 0x27 内嵌 ELF
- NAND 电路
- mem[c]=~(mem[b]&mem[a])
- z3 约束求解 flag
---

## 一句话结论

`chal` 先用大量 `00` 花指令干扰反汇编（把 `00` 改 `90` 即可恢复），运行时起线程加载一段每字节 XOR 0x27 的内嵌 ELF；第二层 ELF 同样有花指令，找到 key 字符串与 24 字节密文后，用魔改 RC4 解出一个大数组 `v194`，其每 3 字节是一条 `mem[c] = ~(mem[b] & mem[a])` 的 NAND 电路；用 z3 对 24 字节 flag 建模、按 0x3F0 条三元组执行 NAND、约束前 24 字节等于密文，即可解出 flag。

## 原理

- **花指令**：`chal` 中大量 `00 00` 字节让 IDA 反汇编错位；把这些 `00` 改成 `90`（NOP）后，函数边界与指令流恢复。两段 ELF 都用了同类花指令。
- **内嵌 ELF**：程序创建线程并加载一段数据；交叉引用发现数据被逐字节 XOR 0x27，提取后 XOR 回来得到合法 ELF（`\x7fELF` 头），再用 IDA 分析第二层。
- **魔改 RC4**：第二层里有一个大数组和 key 字符串 `KeyKEyKeYKEykEYKEY!@#$%^`；数组经过魔改 RC4 解密后得到 `v194`。具体魔改点（S 盒初始化/PRGA 细节）需按反编译实现，原文通过 Linux 远程调试直接 dump 解密后的 `v194`。
- **NAND 电路**：`v194` 每 3 字节 `(a,b,c)` 表示 `mem[c] = ~(mem[b] & mem[a])`（8 位按位 NAND）；循环 `0x3F0` 次，相当于一个由 1008 个 NAND 门组成的电路。
- **内存布局**：`mem[0..0x17]` 是 24 字节 flag（未知），`mem[0x18..0x2F]` 是固定尾串 `KeyKEyKeYKEykEYKEY!@#$%^`，`mem[0x30..]` 全 0；电路执行后要求 `mem[0..0x17]` 等于 24 字节密文 `4F 4F 05 5F 54 6A 20 09 00 6F 6C 66 45 16 7C 3D 3F 64 03 18 5B 5E 5D 2F`。
- **为什么用 z3**：NAND 门是位运算，输入字节可建模为 BitVec(8)，1008 条门只是 1008 个位向量表达式，规模很小；z3 可直接求解满足约束的 24 字节。手工逆推电路非常困难，但符号执行/约束求解很自然。
- **约束**：flag 前 5 字节 `flag{`、末字节 `}`、其余可打印（0x20–0x7E）；这些约束能排除多解并加速。

## 触发条件

- 目标是 Linux ELF，含大量 `00` 花指令/内嵌加密 ELF，静态反汇编困难。
- 能提取内嵌 ELF（XOR 0x27 或类似单字节 XOR），并找到 key 与加密数组。
- 能 dump 魔改 RC4 解密后的 `v194`（动态调试或复现算法）。
- 电路是 NAND/AND/OR/XOR 等位运算组合，输入长度小，适合 z3 求解。

## 利用步骤

1. **修复花指令**：用 010/脚本把连续 `00` 改为 `90`，重新用 IDA 反汇编；或按字节模式批量 patch。
2. **提取内嵌 ELF**：定位线程加载的数据与 XOR 0x27 循环，dump 后 XOR 回来，确认 `\x7fELF`；保存为新文件。
3. **分析第二层**：同样修花指令；找 key 字符串 `KeyKEyKeYKEykEYKEY!@#$%^`、24 字节密文与大数组。
4. **还原 v194**：按魔改 RC4 实现解密，或在 Linux 远程调试中在下游断点 dump `v194`（原文用 gdb 远程调试）。
5. **建模 z3**：24 个 8-bit BitVec 表示 flag，前 5 字节/末字节/可打印约束；初始化 mem（flag + 固定尾串 + 0），按 `v194` 的三元组执行 `mem[c] = ~(mem[b] & mem[a])`；约束 `mem[0..23] == CIPH`。
6. **求解**：`Solver().check()`，取 model 的 24 字节；原文得到 `flag{B62o3$cC..*cE70O7?}`。

## PoC

```python
from z3 import *

CIPH = bytes.fromhex("4F 4F 05 5F 54 6A 20 09 00 6F 6C 66 45 16 7C 3D "
                     "3F 64 03 18 5B 5E 5D 2F")
TAIL = bytes.fromhex("4B 65 79 4B 45 79 4B 65 59 4B 45 79 6B 45 59 4B "
                     "45 59 21 40 23 24 25 5E")
V194 = [...]  # 从调试 dump 的字节，按小端解析成 0..N 的整数索引

mem = [None] * (max(V194[:3*0x3F0]) + 1)
flag = [BitVec(f"f{i}", 8) for i in range(24)]
for i in range(24):
    mem[i] = flag[i]
    s.add(flag[i] >= 0x20, flag[i] <= 0x7E)
for i, ch in enumerate(b"flag{"):
    s.add(flag[i] == ch)
s.add(flag[23] == ord("}"))
for j, b in enumerate(TAIL):
    mem[0x18 + j] = BitVecVal(b, 8)
for i in range(0x30, len(mem)):
    mem[i] = BitVecVal(0, 8)

for k in range(0x3F0):
    a, b, c = V194[3*k], V194[3*k+1], V194[3*k+2]
    mem[c] = ~(mem[b] & mem[a])

for i in range(24):
    s.add(mem[i] == BitVecVal(CIPH[i], 8))

assert s.check() == sat
m = s.model()
print(bytes([m.eval(flag[i]).as_long() for i in range(24)]))
```

原文输出：`flag{B62o3$cC..*cE70O7?}`。

## 变体与关联

- 变体：花指令换成跳转/无效前缀/重叠指令；内嵌 ELF 用多字节 XOR/AES；电路用 AND/OR/NOT 组合或带寄存器；输入更长时需要分块/增量求解。
- 关联：[[ctf-reverse-self-modifying-vm-bytecode-z3-symbolic-execution]]（自修改 VM + z3）、[[ctf-reverse-gba-dma-boolean-circuit-unary-input]]（布尔电路约束）、[[ctf-reverse-pe-driver-4byte-xor-repair-chained-xor-z3]]（XOR 修复 + z3）、[[ctf-reverse-custom-stack-vm-bytecode-constraint-recovery]]（栈式 VM 约束恢复）。
- 同题：`LinuxChal` 的 `mem[c]=~(mem[b]&mem[a])` NAND 电路与 24 字节 flag。

## 检测与防御

- **CTF 之外**：花指令/内嵌 ELF 不是安全边界；动态调试 + dump 可绕过。
- **逆向方法**：先批量 patch 花指令、再用 XOR 提取内嵌层；对位运算电路优先考虑 z3/符号执行，而不是手工逆推。
- **检测**：对 ELF 中出现大量 `00`/重叠指令、运行时 `mmap` + XOR 解密后 `\x7fELF` 的行为，按多阶段加载器处理；监控进程创建线程执行匿名内存。
