---
id: ctf-reverse-gba-dma-boolean-circuit-unary-input
title: GBA ROM 用 DMA 寄存器当布尔门：unary 按键编码 + 电路反解
type: scenario
domain: ctf
path: ctf/reverse
technique: gba-dma-gate-circuit-unary
tags:
- ctf
- reverse
- gba
- dma
- boolean-circuit
- sat
- unary-encoding
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:11:36+08:00'
  notes: 已对照原文 indirect-memory-access 段核对：unary 编码、字符表 absSRLUDrl、DMA 门、BITS_HEX=8bb6... 经本地按 unary 规则解码得 aSba...bSabas（128 bit，索引和 128）；原文另一处少尾字符 s 为笔误。
url: /docs/ctf/reverse/ctf-reverse-gba-dma-boolean-circuit-unary-input/
draft: false
kb_aliases:
- indirect-memory-access
- GBA DMA 布尔门
- unary 按键编码
- DMA 黑盒门电路
- GBA ROM 逆向
---

## 一句话结论

GBA ROM 把按键 mask `1<<k` 编码成 unary 位流（k 个 0 后跟 1），校验函数则把每两个输入 bit 送进一段用 DMA 控制寄存器副作用实现的 2 输入布尔门，层层组合成一个大型组合电路；静态提取 DAG 并求解 128 个输入 bit，再按 unary 规则映射回字符表 `absSRLUDrl` 即得 flag。

## 原理

- 输入函数 `0x080015b4` 扫描按键（`0x08001b48`、`0x08001bd0`），把按键 mask 一位一位右移，每轮将 `r0 << 15` 的低 16 位写入 `0x030000a0`；因此按键 `1<<k` 变成 `k` 个 0 加一个 1 的 unary 段。
- 字符表在 `0x08008ba4` 为 `absSRLUDrl`，索引 0..9 对应段长 1..10；输入满 128 bit 后调用 `0x08000310` 校验。
- 校验函数结构统一：从 `0x030000a0` 取两个 bit，调用 `0x080015b2`（`bx r5`，`r5=0x03000025`）的黑盒函数，把结果压栈，再组合成下一层。
- IWRAM 中的黑盒代码在启动时从 ROM `0x0800d01c..0x0800d078` 拷入，直接操作 `0x040000ba`、`0x040000c6`、`0x040000de` 等 DMA 控制寄存器；它用 DMA 的行为当 2 输入布尔门。
- 因此整个校验是一个由 DMA 门组成的 DAG；静态提取每个门的数据流，求解最终输出为真的 128 bit 赋值，再按 unary 解码即可。

## 触发条件

- 拿到 GBA ROM，能定位输入函数、校验函数与 IWRAM 拷贝代码。
- ROM 中包含字符表与 `flag is 'bctf{<above chars>}'` 之类的提示。
- 校验逻辑可被建模为布尔电路（无复杂状态/时间依赖）。

## 利用步骤

1. 在 ROM 中搜索 `absSRLUDrl`，确认按键到字符的映射。
2. 反汇编输入循环，确认 unary 编码（`1<<k` → k 个 0 + 1）。
3. 定位 `0x08000310` 校验函数与 `0x03000025` 的 IWRAM 黑盒，确认 DMA 门实现。
4. 把每次 `bl 0x080015b2` 抽象成 2 输入 1 输出门，构建 DAG。
5. 对最终输出做 SAT/反向传播，得到 128 bit 输入；按 unary 切段映射字符。
6. 将字符包进 `bctf{...}`。

## PoC

```python
CHARSET = "absSRLUDrl"
BITS_HEX = "8bb6f59c53e41842e03e0287661d28d9"  # 求出的 128 bit

def decode_unary(bits, charset):
    out, i = [], 0
    while i < len(bits):
        z = 0
        while i < len(bits) and bits[i] == 0:
            z += 1; i += 1
        out.append(charset[z]); i += 1
    return "".join(out)

# 结果: aSbaabababaaabbasaaSbsaaaasLaRRbaaDaaaaDbRaabasaRaabsbSabas
```

## 变体与关联

- 同类硬件副作用门可换成定时器、DMA 通道、内存映射寄存器；核心是把“副作用”抽象成逻辑门。
- 若电路含环或状态，可改用符号执行/模型检查。
- 关联：[[ctf-reverse-custom-vm-masked-opcode-inverse-witness-recovery]]（自定义 VM）、[[ctf-reverse-self-modifying-vm-bytecode-z3-symbolic-execution]]（符号执行）。

## 检测与防御

- 这是逆向题型；防御上可增加状态/时间依赖、隐藏字符表或使用更复杂的硬件副作用。
- 检测：GBA ROM 中出现对 DMA 控制寄存器的异常写入与大量重复的 2 输入门调用。
