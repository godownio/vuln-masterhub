---
id: ctf-reverse-custom-vm-tea-like-30round-block-bruteforce
title: 自定义 VM 还原 + TEA-like 30 轮加密：按 4 字节块暴力枚举可见字符解 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: custom-vm-tea-like-block-bruteforce
aliases:
- More_more_Flower
- 自定义 VM 指令集
- TEA-like 30 轮
- delta 0x23251156
- 4 字节块爆破
- VM 字节码还原
tags:
- ctf
- reverse
- vm
- bytecode
- tea
- brute-force
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:37:17+08:00'
  notes: 已对照原文与图37-41核对：VM 11条指令、6个4字节块、30轮delta 0x23251156、KEY表0x42209C与逆序比较、分块爆破flag一致
---

## 一句话结论

PE32 程序用一个自定义 VM 解释 `.rdata` 中的字节码：11 条指令（PUSH/POP/MOV/ADD/SHL/SHR/SUB/OR/XOR/JNZ/RET）先把输入按 4 字节大端拼成 32 位，再做 30 轮 TEA-like 更新 `s += 0x23251156; r += ((r<<5) ^ s ^ (r>>4))`，最后与 24 字节 KEY 表逐字节比较；由于 flag 每 4 字节块只含可见字符，按字符集枚举 `4 字节`（末块固定 `}` 枚举 3 字节）即可反推每个块，拼出完整 flag。

## 原理

- **VM 结构**：`sub_401000` 是解释器，字节码起始 `0x422008`，VM 栈 `0x422A18`，寄存器为全局变量 `0x422C0C/0x422C10/0x422C14/0x422C18/0x422C28/0x422C1C/0x422C20/0x422C24`；`opcode = code[ip]`，`opcode-1` 查跳转表（`0x4026A0`，11 条指令）。
- **指令语义**：
  - `PUSH`（arg 1/7/8）：压入输入字节/32 位寄存器/立即数；
  - `POP`（arg 2/7/8/1）：弹出 1/4 字节到寄存器或隐藏 TMP32（`[ebp-8]`）；
  - `MOV/ADD/SHL/SHR/SUB/OR/XOR`：寄存器/立即数/TMP32/KEY 表操作；
  - `JNZ reg,target`：非零跳转；`RET imm`：返回 0/1。
- **外层逻辑**：栈顶 `stack[0]=6` 作为块计数；每块取 4 字节大端拼成 `R0c`，初始化 `R18=0`、`R14=0x1e`（30 轮）；每轮 `R18 += delta`（delta=0x23251156），`R0c += ((R0c<<5) ^ R18 ^ (R0c>>4))`；30 轮后把 `R0c` 压栈，块计数减 1，跳到下一块。
- **比较阶段**：6 个块处理完后，`R14=0x18`（24 字节），循环 24 次：`POP` 一个字节到 `R0c`，`R18 = KEY[R10]`，`R0c -= (byte)R18`，若非零 `RET 0`；全部为零 `RET 1`。KEY 表在 `0x42209C`，24 字节为 `21 7a 01 1c 33 d3 3e f7 03 78 25 5e 2f b8 8b 3b 93 84 ae 5b de a5 d6 e9`。
- **反推**：VM 栈是 LIFO，比较时 POP 出的顺序与压入顺序相反，因此 6 个块的目标值要按 KEY 的逆序取（`targets = key_words[::-1]`）。每个块只有 4 字节，flag 字符集可限为 `ascii_letters+digits+"{}_"`，枚举 `|charset|² × |charset|²` 的四字节组合，用 TEA-like 加密比对目标；末块已知 `}`，枚举前 3 字节即可。
- **为什么可行**：30 轮 TEA-like 不是密码学安全的 PRP，但暴力 4 字节空间（约 70^4 ≈ 2400 万）在现代机器上可接受；如果直接枚举整个 24 字节 flag 则不可行，分块把复杂度降到 6×O(charset⁴)。
- **边界**：若块数不是 6、字符集更大或轮数/常量不同，需要重新推导；如果比较不是逐字节减 KEY 而是其他变换，需按 VM 字节码重新实现。

## 触发条件

- 目标为 32 位 PE（或类似）包含自定义 VM 解释器，字节码/KEY 表在 `.rdata`，输入为 24 字节左右。
- 能从 VM handler/字节码还原指令语义与加密轮函数（TEA-like、轮数、delta）。
- flag 每 4 字节块由有限字符集组成（可见 ASCII），可暴力枚举。
- 比较阶段逐字节与固定 KEY 表比较，能确定每块目标值。

## 利用步骤

1. **定位 VM**：找 `switch(opcode)` 的解释器、跳转表、字节码/栈/寄存器全局变量；记录 11 条指令的语义。
2. **还原外层**：确认 6 个 4 字节块、30 轮、delta=0x23251156、更新式 `r += ((r<<5)^s^(r>>4))`。
3. **提取 KEY**：从 `0x42209C` 读 24 字节，按 4 字节大端切成 6 个 word，并反转顺序得到 6 个块目标。
4. **实现加密函数**：`enc_word(x)` 按 30 轮更新，注意 32 位截断。
5. **分块爆破**：对前 5 块枚举 `charset` 的 4 字节组合（可用 numpy 向量化/分两半拼接）；末块固定 `}` 枚举 3 字节；比对目标值。
6. **拼接验证**：6 块拼接为 flag，检查格式与 sha256（原文输出 sha256）；若某块无解，扩大字符集/检查字节序。

## PoC

```python
import itertools, string

DELTA, ROUNDS = 0x23251156, 0x1e
KEY = bytes.fromhex("21 7a 01 1c 33 d3 3e f7 03 78 25 5e 2f b8 8b 3b "
                    "93 84 ae 5b de a5 d6 e9")

def enc_word(bs4):
    r = int.from_bytes(bs4, "big"); s = 0
    for _ in range(ROUNDS):
        s = (s + DELTA) & 0xffffffff
        r = (r + (((r << 5) & 0xffffffff) ^ s ^ (r >> 4))) & 0xffffffff
    return r

key_words = [int.from_bytes(KEY[i:i+4], "big") for i in range(0, 24, 4)]
targets = key_words[::-1]
charset = (string.ascii_letters + string.digits + "{}_").encode()

blocks = []
for t in targets[:-1]:
    for a, b, c, d in itertools.product(charset, repeat=4):
        bs = bytes([a, b, c, d])
        if enc_word(bs) == t:
            blocks.append(bs); break
# 末块固定 '}'
for a, b, c in itertools.product(charset, repeat=3):
    bs = bytes([a, b, c]) + b"}"
    if enc_word(bs) == targets[-1]:
        blocks.append(bs); break

print(b"".join(blocks))
```

原文输出：`flag{Fl0weRTeAVM15E3s9!}`。

## 变体与关联

- 变体：TEA-like 轮数/delta/移位常量变化；VM 指令集更多或使用栈式/寄存器式混合；比较可能是 XOR/SUB/查表；块大小 8 字节时需要 meet-in-the-middle/分块。
- 关联：[[ctf-reverse-custom-vm-isa-rol24-xor-base64-inverse]]（自定义 VM ISA 还原）、[[ctf-reverse-cpp-vtable-modified-tea-mask-xor]]（魔改 TEA + 掩码）、[[ctf-reverse-custom-stack-vm-bytecode-constraint-recovery]]（栈式 VM 约束恢复）、[[ctf-reverse-gba-dma-boolean-circuit-unary-input]]（分块/布尔电路约束求解）。
- 同题：`More_more_Flower` 6 个 4 字节块，KEY 表逆序比较。

## 检测与防御

- **CTF 之外**：自定义 VM + 弱分组变换不是安全加密；不要用于真实数据保护。
- **逆向对策**：VM 字节码/KEY 表会被提取；可增加指令混淆、字节码加密、反调试，但最终仍可在动态调试中还原。
- **检测**：对 PE 中出现大段 `switch(opcode)`、跳转表、字节码/栈全局变量的样本，按 VM 保护处理；动态跟踪解释器记录每条 opcode 的语义。
