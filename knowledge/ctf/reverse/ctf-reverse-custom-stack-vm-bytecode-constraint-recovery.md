---
id: ctf-reverse-custom-stack-vm-bytecode-constraint-recovery
title: 自定义栈式 VM 字节码逆向：跳转表还原 15 条指令，逐字符约束反解 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: custom-stack-vm-bytecode-constraint-recovery
aliases:
- Prescription Pad
- 栈式 VM
- opcode 跳转表
- 字节码逆向
- 逐字符约束
tags:
- ctf
- reverse
- vm
- bytecode
- opcode
- stack
- constraints
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:22:44+08:00'
  notes: 已对照原文核对：jump table target=0x2068+*(int32*)(0x2068+4*(op-0x10))、vm_len=0x29a（666 字节）、0x10/0x20-0x25/0x30/0x31/0x40/0x50/0x60/0x61/0x71/0x72 共 15 条指令、input 越界补 0 的长度检查、逐字符模板（xor+add/mul+xor/rol+xor/acc xor/高低 4bit）与 flag SDG{39475a2a6c1852983d4201d2c9434d6f} 均一致。未验证点：无 ELF 附件，PoC 为骨架未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
---

## 一句话结论

strip ELF 用 jump table 分发 opcode，`.data` 中 666 字节字节码；还原 `push/add/sub/xor/mul/rol/and/load/store/input/cmp/jmp/ok/fail` 15 条指令后，按字节码逐字符解约束得 flag。

## 原理

- **VM 解释器结构**：`pc`、`code`、`stack`、`mem[256]`、`cmpflag`；主循环取 `op = code[pc]`，用 `target = 0x2068 + *(int32*)(0x2068 + 4*(op-0x10))` 跳转。
- **指令集**：`0x10 imm8` push；`0x20-0x25` add/sub/xor/mul/rol/and；`0x30 idx` load mem；`0x31 idx` store mem；`0x40 idx` push input[idx]（越界补 0）；`0x50` 比较并设 cmpflag；`0x60/0x61` 条件跳转；`0x71/0x72` 成功/失败。
- **长度检查技巧**：`PUSH_IN 37; PUSH_IMM 0; CMP_EQ; JFALSE FAIL` 检查第 38 字符不存在；`PUSH_IN 36; PUSH_IMM 0; CMP_EQ; JTRUE FAIL` 检查第 37 字符存在，合起来长度恰好 37。
- **逐字符约束**：字节码按固定模板（xor+add、mul+xor、rol+xor、acc xor、高低 4 bit 分开）校验每个字符；反汇编后逐条解方程即可恢复。
- **为什么不用爆破**：每字符约束独立/可枚举，37 字节空间大但约束强；直接解方程比爆破快。

## 触发条件

- 二进制含 `Unknown opcode 0x%02x`/`Execution limit exceeded` 等 VM 特征字符串。
- 主循环 + jump table + 共享 handler 尾巴；`.data` 有长度字段与字节码。
- 输入通过 `input[idx]` 读取，越界补 0。
- 成功/失败出口为两个独立 opcode。

## 利用步骤

1. `strings` 发现 VM 错误字符串；`objdump` 定位 `vm_len`、`code`、`mem`、`sp`、`cmpflag`、jump table。
2. 提取 `.data` 中 `vm_len` 与字节码；按 opcode 语义写 Python 解释器。
3. 反汇编字节码，识别长度检查与每字符约束模板。
4. 对每个字符按约束枚举可打印字符集（或直接逆运算），得到 37 字节 flag。
5. 用解释器正向跑输入验证 `Correct!`。

## PoC

```python
def rol8(x, n):
    n &= 7
    return ((x << n) | (x >> (8 - n))) & 0xFF if n else x & 0xFF

def run(code, inp):
    mem, st, pc, cmpf = [0] * 256, [], 0, 0
    while pc < len(code):
        op = code[pc]
        if op == 0x10: st.append(code[pc+1]); pc += 2
        elif op == 0x20: b, a = st.pop(), st.pop(); st.append((a+b) & 0xFF); pc += 1
        elif op == 0x22: b, a = st.pop(), st.pop(); st.append(a ^ b); pc += 1
        elif op == 0x23: b, a = st.pop(), st.pop(); st.append((a*b) & 0xFF); pc += 1
        elif op == 0x24: b, a = st.pop(), st.pop(); st.append(rol8(a, b)); pc += 1
        elif op == 0x40: i = code[pc+1]; st.append(ord(inp[i]) if i < len(inp) else 0); pc += 2
        elif op == 0x50: b, a = st.pop(), st.pop(); cmpf = int(a == b); pc += 1
        elif op == 0x60: t = code[pc+1] | (code[pc+2] << 8); pc = t if cmpf else pc+3
        elif op == 0x61: t = code[pc+1] | (code[pc+2] << 8); pc = t if not cmpf else pc+3
        elif op == 0x71: return True
        elif op == 0x72: return False
        else: raise ValueError(hex(op))
    return False
```

## 变体与关联

- **VM 变体**：寄存器 VM、栈方向不同、opcode 加密/掩码、字节码运行时解密；可用 angr/z3 符号执行代替手工反汇编。
- **约束变体**：字符间依赖（acc 滚动）、多字节/CRC、查表；需要按顺序解。
- **关联卡片**：[[ctf-reverse-custom-vm-isa-rol24-xor-base64-inverse]]、[[ctf-reverse-custom-vm-masked-opcode-inverse-witness-recovery]]、[[ctf-reverse-self-modifying-vm-bytecode-z3-symbolic-execution]]。
- **边界**：若 VM 使用真实密码学/哈希，逐字符约束不成立；若字节码被加密且 key 不在二进制中，需动态 dump。

## 检测与防御

- **CTF/验证**：用解释器正向跑恢复的输入应返回 `Correct!`；逐字符约束解应唯一。
- **防御**：客户端校验不可作为安全边界；VM/混淆只提高逆向成本；关键授权放服务端。
- **检测信号**：二进制含 opcode 错误/执行上限字符串；`.data` 有大段高熵字节码；主循环有间接跳转表。
