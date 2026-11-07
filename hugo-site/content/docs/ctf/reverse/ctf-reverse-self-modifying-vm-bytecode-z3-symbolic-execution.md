---
id: ctf-reverse-self-modifying-vm-bytecode-z3-symbolic-execution
title: 自修改 VM 字节码解密 + PATCH/DATAXOR + Z3 符号执行恢复 16 字节输入
type: scenario
domain: ctf
path: ctf/reverse
technique: self-modifying-vm-bytecode-z3-symbolic-execution
tags:
- ctf
- reverse
- vm
- self-modifying
- z3
- symbolic-execution
- bytecode
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:50:59+08:00'
  notes: 已对照原文 SpiralVM 一节核对：BYTECODE_VA=0x1400051A0/len=0x2D2、滚动 key 解密、跳表 opcode（PUSH/IN/LOAD/STORE/XOR/ADD/ROL/EQ/AND/PATCH/DATAXOR/FINAL）、PATCH dst=(bc[pc+1]+pc+3)%LEN、DATAXOR 公式、16 次 PATCH、Z3 16 字节 BitVec、stack[-1]==1、输入 53564d5f... 与 flag 均一致。未验证点：卡内 PoC 为骨架（全文约 130 行在原稿），未在本机复跑；frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-self-modifying-vm-bytecode-z3-symbolic-execution/
draft: false
kb_aliases:
- 自修改 VM
- PATCH 字节码
- VM 符号执行
- Z3 解 VM
- SpiralVM
---

## 一句话结论

当 VM 程序在运行时用 `PATCH` 指令异或修改未来字节码、用 `DATAXOR` 扰动 VM 内存时，静态 dump 的初始字节码会漏掉真正执行路径；正确做法是解密字节码后按跳表还原 opcode，边解释边应用 PATCH/DATAXOR，把 16 字节输入建模为 Z3 位向量，符号执行到 `FINAL` 并约束最终校验，即可解出唯一输入。

## 原理

- **字节码解密**：`.rdata` 中的字节码不是明文，用滚动 key 解密：`plain[i]=enc[i]^(eax&0xff)`，随后 `eax += ecx + 0x3d`、`ecx += 7`、`al=rol(al,3)`、`eax ^= r8`、`r8 -= 0x6f`。解密后才能看到 opcode。
- **跳表还原 opcode**：二进制用 `.rdata` 跳转表（相对偏移）分发 handler；把表项目标地址与 handler 地址匹配，得到 opcode→操作映射（PUSH/IN/LOAD/STORE/XOR/ADD/ROL/EQ/AND/PATCH/DATAXOR/FINAL）。
- **自修改 PATCH**：`PATCH` 读取 `bc[pc+1]`、`bc[pc+2]`，计算 `dst=(bc[pc+1]+pc+3)%LEN`，执行 `bc[dst]^=bc[pc+2]`。这会改变后续指令；必须动态模拟，不能只静态反汇编。本题实际执行 16 次 PATCH。
- **DATAXOR**：`addr=(a+b)&0xff`、`val=rol8((13*a+b)&0xff, a^b)`，对 `mem[addr]` 异或；同样必须动态应用。
- **符号执行**：16 个输入字节为 `BitVec(8)`；VM 内存/栈用位向量表达式；按 opcode 解释，PATCH 修改字节码数组（具体值），DATAXOR 修改内存表达式；到 `FINAL` 时约束栈顶/校验表达式等于成功值（本题 `stack[-1]==1`），Z3 求解得到 16 字节输入。
- **为什么成立**：VM 的所有运算（异或、加、循环移位、比较、与）都可位向量建模；自修改只影响字节码（具体值），不影响输入符号；Z3 可处理 16×8 bit 的约束。
- **边界**：VM 含除法/查表/不可逆哈希时 Z3 可能变慢；PATCH 目标若依赖符号输入，需要更复杂的自修改符号执行；输入过长时约束规模爆炸。

## 触发条件

- 有 VM 解释器与加密字节码；能逆向出解密算法、跳表/opcode 语义。
- VM 支持 IN（读取用户输入）与 FINAL（成功校验），输入长度固定且较短（本题 16 字节）。
- PATCH/DATAXOR 的修改目标是具体地址/具体值，不依赖输入（或可符号化）。
- 有 Z3/pefile 或等价工具；能定位字节码/跳表/常量在文件中的偏移。

## 利用步骤

1. 用 `strings`/`objdump` 定位 VM 入口、字节码地址/长度、跳表地址、输入长度与成功字符串。
2. 按解密算法还原字节码；用跳表把相对偏移映射到 handler，得到 opcode 语义。
3. 实现解释器骨架：栈、内存、pc、输入索引；逐条执行，遇到 PATCH 动态修改 `bc`，遇到 DATAXOR 修改内存。
4. 把 16 个输入字节替换为 `BitVec(8)`；内存/栈元素用位向量表达式；PATCH 的 `dst` 若是具体值则直接改 `bc`。
5. 执行到 `FINAL`，添加成功约束（如 `stack[-1]==1`），Z3 `check()`；取模型字节转 hex。
6. 本题解出 `53564d5f5157425f3230323621402324`（ASCII `SVM_QWB_2026!@#$`），flag 为 `flag{SVM_53564d5f5157425f3230323621402324}`。
7. 用原程序输入验证。

## PoC

```python
import pefile
from z3 import *

BASE = 0x140000000
BYTECODE_VA = 0x1400051A0
JUMPTABLE_VA = 0x140005044
BYTECODE_LEN = 0x2D2

def rol8(x, n):
    n &= 7
    return ((x << n) & 0xFF) | (x >> (8 - n) if n else x)

def sym_rol8(v, c):
    out = RotateLeft(v, 0)
    for n in range(1, 8):
        out = If((c & BitVecVal(7, 8)) == BitVecVal(n, 8), RotateLeft(v, n), out)
    return out

pe = pefile.PE("spiralvm.exe")
def read_va(va, size):
    off = pe.get_offset_from_rva(va - BASE)
    return pe.__data__[off:off + size]

# 1) 解密字节码
enc = read_va(BYTECODE_VA, BYTECODE_LEN)
eax, ecx, r8 = 0xFFFFFFA7, 0, 0
bc = bytearray()
for b in enc:
    bc.append(b ^ (eax & 0xFF))
    eax = (eax + ecx + 0x3D) & 0xFFFFFFFF
    ecx = (ecx + 7) & 0xFFFFFFFF
    eax = (eax & 0xFFFFFF00) | rol8(eax & 0xFF, 3)
    eax ^= r8 & 0xFFFFFFFF
    r8 = (r8 - 0x6F) & 0xFFFFFFFF

# 2) 跳表 -> opcode 语义（handler 地址需按样本核对）
# 3) 符号执行：inp = [BitVec(f"in{i}",8) for i in range(16)]
#    按 PUSH/IN/LOAD/STORE/XOR/ADD/ROL/EQ/AND/PATCH/DATAXOR 解释；
#    PATCH: dst=(bc[pc+1]+pc+3)%LEN; bc[dst]^=bc[pc+2]
#    DATAXOR: addr=(a+b)&0xff; val=rol8((13*a+b)&0xff,a^b); mem[addr]^=val
# 4) FINAL: s.add(stack[-1] == BitVecVal(1,8)); 取模型
```

完整脚本见原文（约 130 行）：用 `pefile` 读取常量、用 `z3` 建模 16 字节输入，动态应用 16 次 PATCH，最终 `stack[-1]==1`。

## 变体与关联

- **变体（PATCH 目标依赖输入）**：需要把字节码也做成符号数组，或枚举 PATCH 参数；复杂度显著上升。
- **变体（VM 加解密）**：字节码可能多层加密/压缩；先静态脱壳再符号执行。
- **变体（其他求解器）**：angr、Triton、Miasm 可自动符号执行；本题手写解释器更可控。
- **关联卡片**：[[ctf-reverse-custom-vmc2-vm-isa-extraction-invertible-arx]]（自定义 VM ISA 提取）、[[ctf-reverse-ransomware-xor-crc32-mt19937-keystream]]（字节码/密钥流）、[[ctf-crypto-z3-short-input-128bit-state-constraint]]（Z3 短输入约束）。
- **边界**：VM 含不可建模操作（系统调用、浮点、查表）时需混合具体/符号执行；输入过长/分支多时 Z3 超时。

## 检测与防御

- **CTF 识别**：看到 `PATCH`、`DATAXOR`、自修改字节码、固定 16 字节输入 + 成功字符串，优先动态解释 + Z3。
- **逆向方法**：不要只静态 dump；先解密，再按跳表还原 opcode，最后边执行边修改字节码。
- **防御**：VM/字节码保护应结合多层加密、控制流平坦化、反调试；但自修改逻辑本身可被动态 trace，不能替代服务端校验。
