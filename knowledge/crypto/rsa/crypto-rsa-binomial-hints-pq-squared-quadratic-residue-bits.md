---
id: crypto-rsa-binomial-hints-pq-squared-quadratic-residue-bits
title: RSA n=p·q² 的二项式提示分解 + 二次剩余逐位还原（(p±q)^e 与欧拉判别式）
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-binomial-hints-pq-squared-quadratic-residue-bits
aliases:
- 二项式提示分解 RSA
- n=p*q^2 RSA
- (p+q)^e (p-q)^e 提示
- 二次剩余逐位
- 欧拉判别式恢复密文位
tags:
- rsa
- factoring
- binomial
- quadratic-residue
- euler-criterion
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V511
  verified_at: '2026-11-11T04:57:10+08:00'
  notes: 已通读原文 13424 第一篇并独立数值验证：n=p·q² 时 (p+q)^e+(p−q)^e 的奇次项抵消、k≥2 偶数项含 q² 模 n 为 0，故 gcd(hint1+hint2,n)=p（小素数模拟 101,131,e=65537 验证通过）；z 为模 p/q 非二次剩余，c=secret²·z^m 的欧拉判别在 m=0→1、m=1→−1（50 次随机模拟通过）；ciphertext[0] 为最低十进制位，反转后 int(bits,2) 的位序与原文循环一致。卡中亦指出原文单条 hint 简写 p^e±q^e 不严格、真正成立的是两式相加，判断准确。原文无图片（meta.images=0）。dedup 报告 new，候选（线性组合恢复明文、已知 p+q 分解、p² 模数等）均非同链。
---

## 一句话结论

当 RSA 模数形如 `n = p·q²` 且给出 `hint1=(p+q)^e mod n`、`hint2=(p−q)^e mod n` 时，二项式展开后两式的奇次项相加抵消、含 `q²` 的项在模 n 下消失，因此 `hint1+hint2 ≡ 2p^e (mod n)`，与 n 求 gcd 即得 p，再开方得 q；分解后，对于逐位加密 `c_i = secret_i²·z^{m_i} mod n`（z 是模 p、q 的非二次剩余），用欧拉判别式判断 `c_i` 是否为模 p 的二次剩余即可逐位还原 `m_i`（剩余→0，非剩余→1），最后把二进制串转回字节。

## 原理

- **模数结构**：`n = p·q²`（p、q 为素数，非半素数）。任何含 `q²` 因子的整数模 n 为 0，这是二项式化简的关键。
- **提示展开**：
  - `(p+q)^e = Σ C(e,k) p^{e-k} q^k`，`(p−q)^e = Σ C(e,k) p^{e-k} (−q)^k`。
  - 两者相加时奇次项（k 为奇数）符号相反互相抵消，只剩偶数 k：`hint1+hint2 = 2·Σ_{k even} C(e,k) p^{e-k} q^k`。
  - k=0 项为 `2p^e`；k≥2 的偶数项都含 `q²`（或更高次），模 `n=pq²` 为 0。因此 `hint1+hint2 ≡ 2p^e (mod n)`。
  - 于是 `gcd(hint1+hint2, n)` 包含素因子 p；`2p^e` 不含 q，故 gcd 通常恰为 p（若返回 p 的倍数需按素数性判断）。`q = sqrt(n/p)`。
  - 注意：文章把单条 hint 简写成 `p^e ± q^e` 并不严格（奇次交叉项仍在），真正成立的是“两式相加”的结论；按 gcd 相加式实现即可。
- **二次剩余逐位**：z 的选取保证 `z^((p−1)/2) ≡ −1 (mod p)` 且模 q 同样为 −1，即 z 在模 p、q 下都不是二次剩余。密文 `c_i = secret_i² · z^{m_i} mod n`，其中 `m_i ∈ {0,1}`：
  - 若 `m_i=0`，`c_i ≡ secret_i² (mod p)` 是二次剩余，欧拉判别式 `c_i^((p−1)/2) ≡ 1 (mod p)`；
  - 若 `m_i=1`，`c_i ≡ secret_i²·z (mod p)`，二次剩余乘非剩余仍是非剩余，判别式 `≡ −1 (mod p)`。
  - 因此只需在模 p（或 q）下计算 `pow(c_i,(p−1)//2,p)` 即可恢复每个十进制位。
- **位序与还原**：加密端把 flag 转整数后 `int(bin(m)[2:])` 当成十进制数，再反复 `%10`、`//10` 从最低位逐位加密，所以 `ciphertext[0]` 对应最低位。解密得到的 0/1 串要反转，再 `int(bits[::-1], 2)` 转字节。
- **为什么有效**：模数分解泄露 + 非二次剩余的选择使每位密文的二次剩余性唯一对应明文位；这是“把整数分解信息与二次剩余判定结合”的典型 CTF 构造。

## 触发条件

- 题目/实现给出 `n = p·q²`、指数 e（如 65537）、`hint1=(p+q)^e mod n`、`hint2=(p−q)^e mod n`。
- 另给非二次剩余 z（满足模 p、q 的欧拉判别均为 −1）与逐位密文列表。
- 明文被编码为二进制字符串再当作十进制数逐位加密（每位 0/1）。
- 典型 CTF 场景；真实系统中若密钥生成重复使用素因子或泄露 p±q 的幂，同样会破坏 RSA。

## 利用步骤

1. 计算 `g = gcd(hint1 + hint2, n)`；若 g 不是素数，尝试 `gcd(hint1 − hint2, n)`、对 g 分解或结合 `n/g` 判断。
2. `p = g`，`q = isqrt(n // p)`（验证 `p*q*q == n`）。
3. 对每个密文 `c_i` 计算 `pow(c_i, (p-1)//2, p)`：结果为 1 → 该位 0；结果为 p−1 → 该位 1。
4. 把得到的 0/1 序列反转（ciphertext[0] 是最低位），`int(bits[::-1], 2)` 后 `long_to_bytes`。
5. 若模 p 判别失败（p 选取不对），改用模 q 或重新验证分解。

## PoC

```python
from math import gcd, isqrt
from Crypto.Util.number import long_to_bytes

p = gcd(hint1 + hint2, n)
assert n % (p * p) != 0
q = isqrt(n // p)
assert p * q * q == n

bits = ""
for c in ciphertext:
    if pow(c, (p - 1) // 2, p) == 1:
        bits += "0"
    else:
        bits += "1"

flag = long_to_bytes(int(bits[::-1], 2))
print(flag)
```

## 变体与关联

- **提示形式变体**：给 `(p+q)^e` 与 `(p−q)^e` 的任意线性组合/差值；只要能把奇次项消掉或把 q² 项分离即可。
- **模数变体**：`n=p^2·q`（交换角色）、多素数 `n=p·q^2·r` 等，思路相同：找模 n 下含高次素因子的项。
- **关联卡**：`crypto-rsa-hint-difference-gcd-factorization`（提示差值 GCD）、`crypto-rsa-two-linear-hints-small-coefficient-gcd`（线性 hint 系数抵消）、`crypto-rsa-perfect-square-modulus-p-squared`（p² 模数）、`crypto-rsa-known-prime-sum-quadratic-factorization`（已知 p+q）。
- **边界**：gcd 可能返回 p 的倍数或 1（提示构造退化/计算错误）；z 若不是非二次剩余，逐位判定会失效。

## 检测与防御

- **CTF/实现侧**：RSA 密钥生成不要重复使用素因子（`n` 不能有平方因子）；不要把 `(p±q)^e` 之类的中间值或非二次剩余提示与密文一起输出。
- **密码学审计**：对 n 做平方因子检测（`gcd(n, φ 相关)`、完全平方检测、`isqrt` 验证）；发现 `n=p·q²` 直接判定密钥不安全。
- **防御**：使用标准库生成 RSA 密钥并校验 p≠q、n 无平方因子；敏感参数不出现在日志/调试输出中。
