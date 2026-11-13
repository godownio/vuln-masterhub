---
id: ctf-reverse-md5-digest-even-xor1-birthday-crack
title: SUCTF 2018 hash 逆向：MD5 摘要偶数位异或 1 还原 + 弱口令 birthday 爆破
type: scenario
domain: ctf
path: ctf/reverse
technique: md5-digest-even-bit-xor-transform-crack
aliases:
- SUCTF 2018 hash
- MD5 摘要 XOR 1 混淆
- md5(birthday)
- 摘要位级变换还原
- 弱口令 MD5 爆破
tags:
- ctf
- reverse
- md5
- hash
- xor
- bruteforce
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V635
  verified_at: '2026-11-13T01:09:09+08:00'
  notes: 已对照原文与 25 张图核对（本题相关 img/01 算法示意图）。独立复算：对常量 bf772f6ed89838b9gb9f7abf3cc09413 偶数下标 XOR 1 得 cf673f7ee88828c9fb8f6acf2cb08403 = md5('birthday')；第二段 chr(ord(c)-2i-1) 得 _ro2k0，均与原文脚本输出一致。已修正原卡一处表述：MD5 输入为 SUCTF{ 之后 8 字符（源串第 6–13 字节），非'输入前 8 个字符'。PoC 未在题目二进制上复现（未取得样题）。dedup：与既有 per-char salted MD5、right-shift md5 等卡非同链；dup-scan 无 pair。
---

## 一句话结论

程序把 `SUCTF{` 之后 8 个字符（源串第 6–13 字节）的 MD5 摘要转成 hex，再对偶数下标字符异或 1，与常量 `bf772f6ed89838b9gb9f7abf3cc09413` 比较；对常量再做一次同样的偶数位异或 1（XOR 自反）就还原出真实摘要 `cf673f7ee88828c9fb8f6acf2cb08403`，爆破/查表得到弱口令 `birthday`；第二段把输入字符按 `+ (2i+1)` 变换后与 `` `ut9t; `` 比较，逐字符减回去得到 `_ro2k0`，最终 flag 为 `flag{birthday_ro2k0}`。

## 原理

- **摘要位级混淆只是可逆变换**：MD5 本身不可逆，但“摘要 hex 的偶数位 ^ 1”是逐字符 XOR，异或自反（`x ^ 1 ^ 1 = x`），把目标常量再异或一次即恢复原始摘要，不需要碰散列算法。
- **还原后回到弱口令问题**：恢复出的 32 位 hex 是 8 字符输入的 MD5，题目的口令是常见单词/生日类弱口令，用字典或短掩码爆破即可，`md5("birthday") = cf673f7ee88828c9fb8f6acf2cb08403`。
- **第二段是逐字符仿射变换**：`for (i=0; i<len; *v4 += v5+1) { v4=&this[i]; v5=2*i++; }` 对第 i 个字符加 `2i+1`，与 `` `ut9t; `` 比较；逆运算即 `chr(ord(c) - 2*i - 1)`，得到 `_ro2k0`。
- **为什么先还原再爆破**：直接对混淆后的常量爆破是错的（不是合法 MD5 目标）；识别出 XOR 自反后先归一化目标，再选 MD5 字典/掩码工具，避免无效计算。
- **边界**：若异或的是奇偶位之外按 2 位/4 位分组、或变换含加法进位，需要逐字节反推；本题是单字节 XOR，最简单的一类。

## 触发条件

- CTF 逆向题中存在“输入摘要 == 常量”的比较，且常量/摘要经过简单逐字节变换（XOR/加减）。
- 输入空间小（8 字符内）或口令为常见弱口令，MD5 可爆破/查表。
- 第二段校验为逐字符可逆变换且无密钥依赖。

## 利用步骤

1. 在反汇编中定位 MD5 常量（`0x67452301/0xefcdab89/0x98badcfe/0x10325476`）或 MD5 调用，确认输入长度与摘要比较。
2. 观察比较前的循环：`if ((i & 1) == 0) Buffer[i] ^= 1;`，说明偶数下标异或 1。
3. 对目标常量执行同样变换还原摘要：`cf673f7ee88828c9fb8f6acf2cb08403`。
4. 用字典/在线 MD5/短掩码爆破得到 `birthday`。
5. 对第二段常量 `` `ut9t; `` 逐字符 `chr(ord(c)-2*i-1)` 得 `_ro2k0`；拼成 `flag{birthday_ro2k0}`。

## PoC

```python
target = 'bf772f6ed89838b9gb9f7abf3cc09413'
real = ''.join(chr(ord(c) ^ 1) if i % 2 == 0 else c for i, c in enumerate(target))
print(real)  # cf673f7ee88828c9fb8f6acf2cb08403 == md5('birthday')

s = '`ut9t;'
print(''.join(chr(ord(c) - 2 * i - 1) for i, c in enumerate(s)))  # _ro2k0
```

```text
# 爆破可用 hashcat -m 0 或在线 md5 查表；本题口令为 birthday。
# flag{birthday_ro2k0}
```

## 变体与关联

- 变体：位级混淆可换成“奇数位 ^ 1”“每字节 + 常量”“hex 字符串反转/置换”，先判断是否可逆并归一化再爆破。
- 变体：第二段可为 `+2i+1`、`-i`、异或 index 等逐字符变换，按反函数还原。
- 关联：[[code-analysis-reverse-crypto-encoding-identification-decrypt]]（Hash 常量识别与爆破路线总览）、[[ctf-reverse-per-char-salted-md5-bruteforce-decoy-path]]（加盐/诱饵 MD5 爆破）、[[ctf-reverse-java-string-hash-8digit-bruteforce]]（短输入 hash 爆破）。

## 检测与防御

- CTF/开发视角：校验逻辑不要把可逆变换当保护；口令哈希必须加盐并使用慢哈希（bcrypt/argon2），禁止 MD5。
- 逆向视角：遇到摘要比较先检查比较前的逐字节变换，归一化后再爆破；不要对混淆值直接跑字典。
