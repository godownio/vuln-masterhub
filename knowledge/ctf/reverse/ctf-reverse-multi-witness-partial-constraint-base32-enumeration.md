---
id: ctf-reverse-multi-witness-partial-constraint-base32-enumeration
title: 多 witness 残缺约束 + Base32 字符集枚举：32^5 空间恢复 5 个未知字符
type: scenario
domain: ctf
path: ctf/reverse
technique: multi-witness-partial-constraint-base32-enumeration
aliases:
- QuorumGlyph
- witness
- 32^5
- Base32 枚举
- 残缺约束
tags:
- ctf
- reverse
- witness
- base32
- enumeration
- constraint
- modular-arithmetic
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:26:59+08:00'
  notes: 已对照原文核对：总长 42、前缀 ISCC{QRM_、第 15 字符 _、末位 }、未知 5 字符 Base32 集 ABCDEFGHJKLMNPQRSTUVWXYZ23456789、y=0x9b19bd*(val-0xb3ef33) mod 2^24、target_v=0x0c0de5、枚举得 FE6V6、flag ISCC{QRM_FE6V6_3_w1tness_no_single_path!!} 均与卡片一致；hash/check 函数细节原文未展开，卡片已注明。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

当多组校验中“一组是假的、两组只给部分约束、三组在正确 flag 上一致”时，先用那组不完整 witness 恢复出除少数未知字符外的全部内容，再根据程序使用的 Base32 字符集和模运算校验式，在 32^5 空间内枚举补齐即可。

## 原理

- **witness 结构**：程序内有多组独立校验。一组是纯诱饵（对任何输入都不成立或与真实 flag 无关）；一组复杂状态变换只覆盖部分字符（本例能恢复 `ISCC{QRM_....._3_w1tness_no_single_path!!}`，剩下 5 个字符无法确定）；另外几组在正确解上交叉一致。
- **格式约束先行**：程序先检查总长度 42、前缀 `ISCC{QRM_`、第 15 个字符为 `_`、最后一个字符为 `}`，这些条件把未知区间压缩到中间 5 个字符。
- **Base32 字符集**：未知 5 字符只允许 `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`（32 个符号，排除易混淆的 `I/O/0/1`）。把 5 字符按 base-32 累积解码为整数 `val`：`v = v*32 + index(ch)`。
- **模运算校验**：程序对 `val` 做 `y = 0x9b19bd * (val - 0xb3ef33) mod 2^24`，再把 `y` 送入较复杂的 hash/check 函数，要求结果等于 `0xe04cf5339f776142`。哈希不可逆，但逆向可提取中间目标 `target_v = 0x0c0de5`，于是只需枚举满足 `y == target_v` 的 `val`。
- **空间可行**：32^5 ≈ 3355 万，纯 Python 循环可接受；用分块、C 扩展或先解同余式可进一步加速。因为 `0x9b19bd` 与 2^24 互素（奇数），该同余式其实可解析求逆，枚举只是最直接的实现。

## 触发条件

- flag 长度固定、格式约束多，未知字符集合很小（通常 ≤6）。
- 程序使用小字符集（Base32/Base36/十六进制/自定义 32 符号表）解码未知段。
- 校验链中有“可提取的中间值”，避免直接面对不可逆哈希。
- 存在多组 witness，且其中一组只覆盖部分字符。

## 利用步骤

1. 从输入检查中恢复长度、前缀、固定位置字符，确定未知字符的位置与数量。
2. 逆向不完整 witness，恢复其余全部字符；不要试图用诱饵 witness 或不可逆哈希直接反推。
3. 定位未知段的解码逻辑：字符表、累积方式（base-N）、是否大小端/反序。
4. 在哈希/检查函数入口或中间变量处提取目标值（如 `target_v`），把“哈希等于常量”降级为“模运算等于中间值”。
5. 枚举字符集组合，按解码 + 模运算筛选；找到候选后用原程序验证。
6. 若多个候选，叠加其他 witness 的约束或程序输出长度/格式进一步筛选。

## PoC

```python
from itertools import product

charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # Base32，无 I/O/0/1
target_v = 0x0c0de5

def decode_base32(s):
    v = 0
    for c in s:
        v = v * 32 + charset.index(c)
    return v

for chars in product(charset, repeat=5):
    s = "".join(chars)
    dec = decode_base32(s)
    v = (0x9b19bd * ((dec - 0xb3ef33) & 0xffffff)) & 0xffffff
    if v == target_v:
        print("[+] found:", s, "dec =", hex(dec), "v =", hex(v))
        break
# 原文结果：FE6V6
# flag: ISCC{QRM_FE6V6_3_w1tness_no_single_path!!}
```

## 变体与关联

- **解析求逆**：若 `a` 与模数互素，`a*(val-c) ≡ t (mod m)` 可直接解 `val ≡ c + t*a^{-1} (mod m)`，不必枚举；枚举适合模数/字符集不规则或有多条件的情况。
- **空间变大**：未知 10 字符时可拆成两半做 meet-in-the-middle，或按 witness 分段枚举。
- **字符集变体**：Base32/Base36/十六进制/自定义表；注意程序可能先反转字符串或按位重排。
- **witness 变体**：诱饵 witness 可能故意给出“看似可解”的方程；用多组交叉验证排除。
- **关联卡片**：[[ctf-reverse-z3-constraint-equation-solve]]（约束方程求解）、[[ctf-crypto-small-discrete-log-crt-channel-selection]]（小空间枚举/通道筛选）、[[ctf-reverse-custom-vm-masked-opcode-inverse-witness-recovery]]（witness 反向执行）。

## 检测与防御

- **检测特征**：输入检查里出现固定前缀/长度/位置字符；未知段用 32 符号表解码；校验链中先做模乘再进哈希；多组校验函数并存。
- **分析建议**：优先找“不完整 witness”而不是硬碰哈希；在调试器中直接读中间变量往往比逆向哈希函数快。
- **防御视角**：把未知空间压到 32^5 且校验可枚举，等于把安全性降到暴力搜索；应使用足够大的密钥空间与标准 KDF，而不是自定义模运算 + 哈希拼接。
