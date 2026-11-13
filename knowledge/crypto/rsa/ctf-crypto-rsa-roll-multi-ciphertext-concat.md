---
id: ctf-crypto-rsa-roll-multi-ciphertext-concat
title: RSA 多段密文（RSAROLL）：同一个 n 下一列 c 逐段解密，按序拼接还原 flag
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-roll-multi-ciphertext-concat
aliases:
- RSAROLL
- RSA roll roll roll
- 多个 c 同一个 n
- 逐段解密拼接
- 按行加密
- 滚动拼接 flag
tags:
- ctf
- crypto
- rsa
- multi-ciphertext
- small-n
- concat
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V523
  verified_at: '2026-11-11T13:51:19+08:00'
  notes: 已对照原文（第 3 题 ROLL，图02 题干 RSA roll! roll! roll!）并独立复算：n=920139713=18443×49891，phi=920071380，逐段解出为可打印 ASCII（49–125），按序拼接得 flag{13212je2ue28fy71w8u87y31r78eu1e2}，与卡片逐段 chr 方案一致。修正：原理中“原文示例解出 b'BJD{...}' 类字符直接 chr”误引了文中共享素数例题的明文，已改为本题复算结果并注明古典题字母表映射的区别。dedup 候选（m>n 商枚举、未知 e、dp 泄露、密文 gcd 等）均为不同题型，非同链；dup-scan 无涉及 pair。原文无组件版本，未设 affected_versions。复算未用 libnum（环境缺失），以 Crypto.Util.number.long_to_bytes 等价代替。未 commit/finalize/index/embed。
---

## 一句话结论

题目给出一个 `{n, e}` 和一长列密文 c（每行一个）时，说明 flag 被按字符/小块分段 RSA 加密、共用同一模数；分解 n 求 d 后对每个 c 做 `m = c^d mod n`，把结果按序拼接（`m ≤ 26` 映射字母表，否则 `chr(m)`）即得 flag（BUU RSAROLL 型）。

## 原理

- **分段加密**：RSA 单次能加密的明文长度受 n 限制；出题人常把 flag 的每个字符（或其编号）分别加密，得到多个 c 共用同一 `n, e`。
- **逐段独立解密**：每段 `c_i = m_i^e mod n`，用同一私钥 `d` 解 `m_i = c_i^d mod n` 即可恢复该段；RSA 的确定性保证结果正确。
- **拼接顺序**：密文列表的顺序就是明文顺序（除非题目另说"rolling"需要按某规则重排）；逐段转字符后顺序拼接。
- **m 的两种解释**：若 `m_i` 是 0–25 的字母编号，用 `alphabet[m_i]` 映射；若 `m_i` 是可打印 ASCII 码（如 65–122），直接 `chr(m_i)`。本题复算逐段解出的是可打印 ASCII，拼接为 `flag{13212je2ue28fy71w8u87y31r78eu1e2}`；另一古典题解出 8,11,14,21,4,24,14,20 这类 ≤25 的值，才映射为 "iloveyou"（`b'BJD{...}'` 是文中共享素数例题的明文，不属于本卡场景）。
- **为什么能分解**：此类题 n 通常很小（几千到几十位），factordb、yafu、sympy 均可秒分解；若 n 大但多组模数，先 gcd。

## 触发条件

- 题目给出单个 `n, e` 与一列密文（常见 30–50 个 c），或提示 "roll/rolling/按行/逐字符"。
- n 可分解（小模数或可查因子库）。
- 明文是 flag 字符序列，逐段可读。

## 利用步骤

1. 解析 `n, e` 和密文列表（注意括号 `{n,e}` 与换行分隔）。
2. 分解 n 得 p、q（小 n 直接试除/factordb/yafu）。
3. `phi=(p-1)(q-1)`、`d=invmod(e,phi)`。
4. 对每个 c 计算 `m = pow(c,d,n)`；根据数值范围选择 `chr(m)` 或 `alphabet[m]`。
5. 按密文顺序拼接输出；检查是否形如 `flag{...}`。

## PoC

```python
import libnum

n = 920139713
e = 19
p, q = 18443, 49891          # 小 n 可直接分解
phi = (p - 1) * (q - 1)
d = libnum.invmod(e, phi)

cs = [704796792, 752211152, 274704164, 18414022, 368270835, 483295235,
      263072905, 459788476, 483295235, 459788476, 663551792, 475206804,
      459788476, 428313374, 475206804, 459788476, 425392137, 704796792,
      458265677, 341524652, 483295235, 534149509, 425392137, 428313374,
      425392137, 341524652, 458265677, 263072905, 483295235, 828509797,
      341524652, 425392137, 475206804, 428313374, 483295235, 475206804,
      459788476, 306220148]

flag = ''.join(chr(pow(c, d, n)) for c in cs)
print(flag)
# 若解出的是 0-25 编号：
# alphabet = 'abcdefghijklmnopqrstuvwxyz'
# flag = ''.join(alphabet[pow(c,d,n)] for c in cs)
```

## 变体与关联

- 变体：古典题直接给 `n, e, d`（如 n=2537,e=13,d=937），密文是 4 位一组的十进制数，解出 0–25 索引后映射字母表（见 [[ctf-crypto-rsa-small-n-alphabet-index]]）。
- 变体：多组不同 n 的 c 需要分别解密；若 n 之间共享素因子，先 gcd（[[ctf-crypto-rsa-shared-prime-batch-gcd]]）。
- 变体：解出的段可能是乱序，需要按题目提示重排（如栅栏、列置换）。
- 边界：若每段明文不是单字符而是长块，需要按字节长度切分；`chr()` 前要确认 m 在可打印范围。

## 检测与防御

- 题目识别：一个 n/e 配一列密文、题干出现 roll/按行/逐字符、密文数量与 flag 长度接近——优先按“逐段解密拼接”处理。
- 真实系统防御：不要用 RSA 直接逐字符加密敏感数据（确定性加密可被字典/重放），应使用带随机填充的混合加密（RSA-OAEP + AES-GCM）。
- 加固：RSA 模数 ≥2048 位并避免小模数；对加密实现做 padding 校验与侧信道防护。
