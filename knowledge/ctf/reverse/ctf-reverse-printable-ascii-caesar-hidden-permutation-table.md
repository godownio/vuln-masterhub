---
id: ctf-reverse-printable-ascii-caesar-hidden-permutation-table
title: 可打印 ASCII 链式 Caesar + 异或隐藏置换表的 16 轮矩阵变换逆向
type: scenario
domain: ctf
path: ctf/reverse
technique: printable-ascii-chained-caesar-hidden-permutation-table
aliases:
- 如影随形
- OHF3nw
- printable ASCII Caesar
- 置换表异或 0xf5
tags:
- ctf
- reverse
- caesar
- permutation-table
- matrix
- printable-ascii
- rounds
cve: []
severity: low
confidence: low
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:27:00+08:00'
  notes: 已对照原文核对：ISCC{16 字节}、4×4 矩阵、16 轮可打印 ASCII(0x20-0x7e, mod 95)位置相关 Caesar + order[r] 指定格 real_map=kMapXor^0xf5 置换、密文 ;s<b/?vEiC{s"{C9、逆序先逆置换再 i=15..0 逆 Caesar、结果 ISCC{z]"gc'A(8_NWY~s} 均与卡片一致；原文 real_map 为 96 项且含重复值、非严格置换，卡片已标 low 并注明以二进制实际表为准。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

16 字节输入填入 4×4 矩阵后做 16 轮“位置相关 Caesar（模 95）+ 指定格置换表替换”，置换表以 `kMapXor[i] ^ 0xf5` 藏在 `.rdata`；从密文按轮倒序先逆置换、再逆 Caesar（位置键从后往前）即可还原输入。

## 原理

- **矩阵组织**：程序检查 `ISCC{xxxxxxxxxxxxxxxx}`，取花括号内 16 字节按行优先填入 4×4 矩阵，后续变换都作用于矩阵元素。
- **可打印 ASCII Caesar**：变换范围 `0x20..0x7e`，共 95 个字符。第 `r` 轮对位置 `i` 使用 `k=(key[r] + i*3) % 95`，正向 `c = (p - 0x20 + k) % 95 + 0x20`；逆向为 `(c - 0x20 - k) % 95 + 0x20`。键随位置变化，所以不能把整串当成单一 Caesar。
- **链式/顺序敏感**：程序按位置顺序更新矩阵，某些位置的更新会影响后续参数（或至少读取已更新的状态）；逆向必须严格按加密的相反顺序逐位置恢复，不能并行/乱序。
- **隐藏置换表**：`.rdata` 中的 `kMapXor` 不是真实表，真实表 `real_map[i] = kMapXor[i] ^ 0xf5`；每轮对 `order[r]` 指定的格子做一次表替换。逆变换用 `inv_map[real_map[i]] = i`。
- **轮结构**：每轮“先对指定格做置换替换，再对 16 个位置做位置相关 Caesar”；逆序时先逆 Caesar（i 从 15 到 0），再逆置换。若顺序写反，结果会完全错乱。
- **密文比较**：最终 16 字节与数据区常量逐字节比较；把该常量作为起点倒推 16 轮即可。
- **注意原文数据的不一致**：原文给出的 96 项 `real_map` 含重复值（如 `0x3e`、`0x28`、`0x3c` 多次出现），不是严格置换，`inv_map` 会产生覆盖；实际复现应以二进制中 `kMapXor ^ 0xf5` 的结果为准，并确认替换是否只作用于子集或表是否另有索引变换。本卡的方法框架成立，但原文 PoC 的表数据不能直接照抄。

## 触发条件

- 输入格式固定为 `ISCC{16 字节}`，花括号内长度正好 16。
- 反编译中出现 4×4 矩阵、16 轮循环、模 95 的加减、以及 `.rdata` 中一张被常量异或的表。
- 最终比较是 16 字节 `memcmp`，密文可在数据区直接提取。

## 利用步骤

1. 提取 16 字节密文（本例 `;s<b/?vEiC{s"{C9`）。
2. 在 `.rdata` 定位 `kMapXor` 与异或常量（本例 `0xf5`），恢复 `real_map`，建立 `inv_map`。
3. 从反编译提取每轮的 `order[r]`（置换位置）与 `keys[r]`（Caesar 基准键）。
4. 对 `r=15..0`：先对 `state[order[r]]` 做 `inv_map` 替换；再对 `i=15..0` 做 `(state[i]-0x20-(keys[r]+i*3)) % 95 + 0x20`。
5. 得到 16 字节中间串，拼成 `ISCC{...}`；用原程序验证。
6. 若表长度/范围与 95 不符（本例恢复表含 `0x7f`，可能是 96 项），以二进制实际范围为准重新标定 `base/mod`，不要硬套 95。

## PoC

```python
cipher = b';s<b/?vEiC{s"{C9'

# real_map[i] = kMapXor[i] ^ 0xf5；从 .rdata 恢复的 96 项置换表
# 这里省略具体 96 个值，按实际二进制填回
real_map = [...]  # 例如 [0x21, 0x45, 0x6e, ...]
inv_map = [0] * 256
for i, v in enumerate(real_map):
    inv_map[v] = i

def sub_rev(c, key, base=0x20, mod=95):
    return (c - base - key) % mod + base

order = [3, 7, 11, 15, 2, 6, 10, 14, 1, 5, 9, 13, 0, 4, 8, 12]
keys  = [7, 13, 5, 11, 3, 17, 9, 15, 4, 8, 6, 14, 2, 19, 10, 16]

state = list(cipher)
for r in range(15, -1, -1):
    pos = order[r]
    state[pos] = inv_map[state[pos]]              # 先逆置换
    key = keys[r]
    for i in range(15, -1, -1):                   # 再逆位置相关 Caesar
        state[i] = sub_rev(state[i], (key + i * 3) % 95)

middle = bytes(state)
print(b"ISCC{" + middle + b"}")
```

## 变体与关联

- **置换表隐藏方式变体**：异或常量、加减常量、按索引重排、运行时生成；先恢复成 256 项映射，再建逆表。
- **Caesar 变体**：键可能由上一轮状态/上一字符派生（真正链式），此时逆序必须严格从最后位置开始，并用已恢复的后续状态计算键。
- **范围变体**：可打印 ASCII 可能是 95（0x20–0x7e）或 96（0x20–0x7f）；模数、base 必须按实际常量确认。
- **轮数变体**：轮数可能不是 16；先用明密文对或程序循环边界确认，再决定爆破轮数。
- **关联卡片**：[[ctf-reverse-modified-rc4-rounds-sbox]]（S 盒/轮数改动需同步）、[[ctf-crypto-vigenere-caesar-digit-letter-branch-counter-scope]]（位置相关 Caesar/维吉尼亚）、[[ctf-reverse-base64-table-index-mutation]]（换表/索引魔改）。

## 检测与防御

- **检测特征**：4×4 矩阵、16 轮循环、`% 95`/`+ 0x20` 的可打印 ASCII 运算、`.rdata` 中与常量异或的表、最终 16 字节比较。
- **分析建议**：先恢复表并写 `inv_map`；用自造明文跑正向/逆向互验；注意表长度与模数是否一致。
- **防御视角**：置换 + Caesar 只是提高逆向成本；把表藏在 `.rdata` 并异或一个常量不构成保护，调试器 dump 即可还原。
