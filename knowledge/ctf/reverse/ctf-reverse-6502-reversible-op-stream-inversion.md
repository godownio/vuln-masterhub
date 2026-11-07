---
id: ctf-reverse-6502-reversible-op-stream-inversion
title: 6502 超长可逆指令流：模式匹配高层操作后反向执行恢复输入
type: scenario
domain: ctf
path: ctf/reverse
technique: 6502-reversible-op-stream-inversion
aliases:
- Favorite Potato
- 6502 逆向
- 可逆指令流
- 反向执行恢复输入
- 模板匹配反汇编
tags:
- ctf
- reverse
- 6502
- reversible
- pattern-matching
- inversion
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:11:33+08:00'
  notes: 已对照原文 Favorite Potato 段核对：去 2 字节 PRG、9 类可逆操作与模板字节、倒序求逆、carry 0/1 尝试均一致；未跑附件。
---

## 一句话结论

当 6502 程序由 25 万多个重复的可逆小片段组成时，不必逐条逆全部指令：先把字节流模式匹配成高层操作（交换、加法、异或、循环移位），再从最终 `(A,X,Y)` 逆序执行每个操作的逆，即可恢复初始输入。

## 原理

- 题目给 `code.bin.gz`，前两字节是 PRG load address，需去掉后再分析。
- 程序虽长，但由少量模板重复拼接：`swapAX`、`swapAY`、`swapXY`、`addX_A`、`addY_A`、`addA_c`、`xorA_c`、`xorAY`、`rorA_k` 等。
- 每个操作都可逆：交换自逆；`X+=A` 的逆是 `X-=A`；`A+=c` 的逆是 `A-=c`；XOR 自逆；`ROR(A,k)` 的逆是 `ROL(A,k)`。
- 因此只需解析出高层 op 列表，从最终寄存器状态倒序执行逆操作，即可得到输入；ADC 的进位不确定时对初始 carry 0/1 各试一次。
- 难点在模板识别：需要从反汇编中提取每个小片段的固定字节序列，按顺序扫描并处理未匹配字节。

## 触发条件

- 目标是 8 位 CPU（6502）程序，且由大量重复的可逆操作构成。
- 能拿到程序字节流与每轮的最终 `(A,X,Y)`。
- 能识别或推测每个模板的字节模式。

## 利用步骤

1. 解压 `code.bin.gz`，去掉 2 字节 PRG load address。
2. 从反汇编提取模板：`T_SWAP_AX=08488a48bae89a68ca9aaa682828`、`T_ADDX_A=0848e838e901d0fa6828`、`T_ADDY_A=0848c838e901d0fa6828`、`T_SWAP_AY=084898488a48bae8e89a68a8caca9a68aa682828`、`T_SWAP_XY=08488a4898aa68a86828` 等。
3. 按顺序扫描字节流，生成 `(op, arg)` 列表；未匹配则报错并补模板。
4. 从最终 `(A,X,Y)` 倒序执行逆操作；`ADC` 进位不确定时尝试 carry=0/1。
5. 将恢复的 `(A,X,Y)` 依次提交，验证是否通过。

## PoC

```python
def invert_one(out, ops, carry0):
    a, x, y = out
    for name, arg in reversed(ops[:-1]):  # skip rts
        if name == "addA_prefix": a = (a - arg - carry0) & 0xFF
        elif name == "swapAX": a, x = x, a
        elif name == "swapAY": a, y = y, a
        elif name == "swapXY": x, y = y, x
        elif name == "addX_A": x = (x - a) & 0xFF
        elif name == "addY_A": y = (y - a) & 0xFF
        elif name == "xorAY": a ^= y
        elif name == "xorA_c": a ^= arg
        elif name == "addA_c": a = (a - arg) & 0xFF
        elif name == "rorA_k": a = rol8(a, arg)
    return a, x, y
```

## 变体与关联

- 同类思路适用于其他“超长但由可逆小操作拼接”的字节码/指令流。
- 若模板有重叠或变长，可用最长匹配/动态规划切分。
- 关联：[[ctf-reverse-byte-pair-add-rol8-buffer-rotate-inverse]]（逐字节可逆变换）、[[ctf-reverse-upx-vm-rolling-hash-per-char-inversion]]（反向执行）。

## 检测与防御

- 这是逆向题型；防御上可加入不可逆操作、状态依赖分支或模板变形，增加静态切分难度。
- 检测：二进制/字节码中出现大量重复的短指令模板与固定寄存器操作。
