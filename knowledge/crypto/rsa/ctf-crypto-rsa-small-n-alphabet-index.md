---
id: ctf-crypto-rsa-small-n-alphabet-index
title: RSA 小参数古典题：n=2537/e=13/d=937 解出 0–25 索引后映射字母表得 flag
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-small-n-index-alphabet-mapping
aliases:
- 古典 RSA 题
- Enumerate the alphabet
- 0-25 字母表映射
- n=2537 e=13 d=937
- 小模数 RSA
- RSA 字母编号
tags:
- ctf
- crypto
- rsa
- small-modulus
- alphabet-index
- classical
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V523
  verified_at: '2026-11-11T13:51:21+08:00'
  notes: 已对照原文（第 4 题 古典1，图03 题干）并独立复算：n=2537=43×59，phi=2436，13×937≡1 (mod 2436)，密文分组 0156 0821 1616 0041 0140 2130 1616 0793 解出 [8,11,14,21,4,24,14,20]，按 a=0 字母表映射得 iloveyou，与卡片完全一致；图03 明确 Enumeration 0–25、Public Key 2537 and 13、Private Key 2537 and 937，卡片参数无出入。未修改内容。dedup 候选（m>n 商枚举、已知 p+q 分解、未知 e 等）均为不同题型，非同链；dup-scan 无涉及 pair。原文无组件版本，未设 affected_versions。
---

## 一句话结论

当古典 RSA 题给出极小的 `n`（如 2537=43×59）、`e`、`d` 和一组 4 位十进制密文，并提示“用 0,1,2,…,25 枚举字母表”时，逐段 `m = c^d mod n` 得到的是 0–25 的字母编号而不是 ASCII 码，按 `alphabet[m]`（a=0…z=25）映射后顺序拼接即得 flag（原文 n=2537,e=13,d=937 → flag{iloveyou}）。

## 原理

- **小模数直接分解**：n=2537 可秒分解为 43×59，φ=42×58=2436；e=13 与 φ 互素，d=937 满足 `13×937 ≡ 1 (mod 2436)`。
- **密文是分组编号**：题干把密文写成 `0156 0821 1616 0041 0140 2130 1616 0793`，每组是 0–2537 范围内的整数，分别对应一个明文字母的编号；RSA 一次只加密一个编号。
- **解密结果的范围决定解释方式**：`pow(c,d,n)` 得到 8,11,14,21,4,24,14,20 这类 ≤25 的值，按 `alphabet[index]` 映射即 "iloveyou"；若结果落在可打印 ASCII 区间（如 65–122）才用 `chr()`。
- **为什么不是 ASCII**：若强行 `chr(8)` 等会得到控制字符/乱码，说明题目用的是字母表索引而非 ASCII；这是古典题与常规 pycryptodome 题的关键区别。
- **顺序即明文顺序**：分组列表顺序对应字母顺序，无需重排。

## 触发条件

- 题目给出很小的 n（≤ 5 位十进制或明显可分解）、小 e/d，并提示 alphabet/0–25/古典。
- 密文是若干 4 位左右的分组十进制数。
- 解密结果集中在 0–25 区间。

## 利用步骤

1. 读取 n、e、d（或由 n、e 自行分解求 d）。
2. 把密文按空格拆成整数组。
3. 对每组 `m = pow(int(c), d, n)`。
4. 若 m ≤ 25，用 `'abcdefghijklmnopqrstuvwxyz'[m]`；若 m 在可打印范围，用 `chr(m)`；若不确定，两种都试并看是否形成 flag。
5. 拼接输出。

## PoC

```python
alphabet = 'abcdefghijklmnopqrstuvwxyz'
n, e, d = 2537, 13, 937
cs = '0156 0821 1616 0041 0140 2130 1616 0793'.split()

flag = ''.join(alphabet[pow(int(c), d, n)] for c in cs)
print(flag)          # iloveyou
print('flag{' + flag + '}')
```

## 变体与关联

- 变体：只给 n、e 时先分解 n 求 d（如 n=2537 → 43×59）；或直接用 `d = pow(e, -1, phi)`。
- 变体：编号可能是 1–26 而非 0–25，映射时减 1；也可能把空格/下划线编号一并加密，需要按字符表扩展。
- 变体：多段密文共用 n 的 RSAROLL 型（见 [[ctf-crypto-rsa-roll-multi-ciphertext-concat]]）。
- 边界：m 超过 26 却仍按字母表映射会得到错误字符，应先用少量已知前缀判断编号体系。

## 检测与防御

- 题目识别：n 极小、题干出现 "Enumerate the alphabet"、密文是整齐的 4 位分组——基本锁定字母表索引映射。
- 真实系统防御：RSA 不能这样用（小模数可分解、无填充可字典攻击）；实际系统必须使用 ≥2048 位模数与 OAEP 填充，且不直接加密字符编号。
- 加固：教学/CTF 之外不要使用小模数或无填充 RSA；密钥生成后做模数位数与素性检查。
