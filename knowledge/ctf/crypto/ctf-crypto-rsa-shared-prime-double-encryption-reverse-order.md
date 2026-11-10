---
id: ctf-crypto-rsa-shared-prime-double-encryption-reverse-order
title: 六组模数两两共享素因子 + 同一明文被同一指数连乘两层：gcd 分解后必须按「后加密的先解」逆序解密（先 d_2 再 d_1）才能还原
type: scenario
domain: ctf
path: ctf/crypto
technique: rsa-shared-prime-double-encryption-reverse-decrypt
aliases:
- 双重加密 RSA
- 连乘两层 RSA
- 共享素因子 + 双层加密
- c = ((m^e mod n1)^e mod n2)
- 逆序解密
- 三组共享素数
tags:
- crypto
- ctf
- rsa
- shared-prime
- gcd
- double-encryption
- reverse-order
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:35:13+08:00'
  notes: 已对照原文核对；加密侧 c1=pow(mm1,e1,n1) 再 pow(c1,e1,n2)（三组 e=59537/86311/65537，各用两个模数）、exp 侧 p=gcd(n1,n2)/q=n//p/d=invert(e,phi)/先 pow(c1,d2,n2) 再 pow(m1,d1,n1)，与正文脚本和 exp 的运算顺序逐行一致；「后加密的先解」这一核心结论由正文 m1=pow(c1,d2,n2) 后 pow(m1,d1,n1) 直接支撑，回环校验 pow(pow(m,e,na),e,nb)==c 属合理自检；本卡与已验证卡 ctf-crypto-rsa-shared-prime-batch-gcd 的区别（双层连乘逆序 vs 单层 gcd 解密）成立，属增量而非重复；本次核对未读取图片，5 张图未读图核对；文中六组巨量模数与三密文未照抄进卡（以占位符代替），未执行其 exp
---

## 一句话结论

当题目给出 6 组 `(n_i, e_i, c_i)`、且每个 `c` 是「同一明文先 `m^e mod n_a`、再把结果当消息做一次 `^e mod n_b`」的两层连乘，同时 `n_a` 与 `n_b` 又两两共享同一个素因子时，攻击分两步且顺序不能错：先用 `gcd(n_a, n_b)` 把这一对模数同时分解、分别求出两个私钥，然后**先解第二层（用 `n_b` 的 `d_b`）再用第一层（`n_a` 的 `d_a`）** 才能得到明文；顺序颠倒只会得到中间值。

## 原理

- **共享素因子使一对模数同时失效**：`p = gcd(n_a, n_b)`，则 `q_a = n_a/p`、`q_b = n_b/p`，两组的 `φ` 与私钥都能算出。六组模数排成三对，每对共享一个素数，于是三组明文全部可解；这是「密钥批量生成时随机源复用」的典型后果。
- **两层连乘让解密有严格顺序**：加密是 `c = (m^e mod n_1)^e mod n_2`，等价于 `c = m^(e²) mod n_2` 与 `m^e mod n_1` 的嵌套。解密必须从最外层开始：先 `m_mid = c^(d_2) mod n_2`（此时 `m_mid = m^e mod n_1`），再 `m = m_mid^(d_1) mod n_1`。若先做 `mod n_1`，指数与被模数不匹配（`c` 是 `mod n_2` 的结果，可能大于 `n_1`），既解不对也可能直接得到乱码。
- **为什么两层的模数必须共享素因子**：如果不共享，就只能拿到两个独立 RSA 的嵌套，缺少任一层私钥都无法推进；共享因子让「两个私钥」同时可得，双层才有意义。这也是本题设成三对（6 个模数）而不是两对的原因。
- **指数相同不代表可以合并**：有人会想 `e²` 与 `n_2` 组合直接解密，但 `gcd(e², φ(n_2))` 未必为 1，且明文空间受 `n_1` 限制；逐层解、逐层断言 `pow(m, e, n) == c` 才是稳妥做法。
- **解出的字节常常不是最终 flag**：本题明文经过一次字符层变换（删字符 / 双写字符），需要按提示还原；这提示「RSA 解出可读串」不等于结束，要读注释与题面对明文做二次处理。

## 触发条件

- 题目给出偶数个（≥4）模数，且成对出现；两两 `gcd` 不为 1。
- 每个 `c` 都是「同一 `e` 连乘两层」得到，即加密脚本里能看到 `c = pow(pow(m, e, n1), e, n2)` 这种形态。
- 已知每对的 `n_a, n_b, e, c`；能跑大整数 gcd、模逆与模幂。
- 明文相对模数较小（flag 量级），`long_to_bytes` 后应为可打印串。

## 利用步骤

1. 把所有模数配对（题目通常按 `n1/n2`、`n3/n4`、`n5/n6` 给出），对每对算 `p = gcd(n_a, n_b)`；断言 `1 < p < n_a`。
2. 分解：`q_a = n_a // p`、`q_b = n_b // p`，并断言 `p*q_a == n_a`、`p*q_b == n_b`。
3. 分别求 `φ_a = (p-1)(q_a-1)`、`φ_b = (p-1)(q_b-1)`，再 `d_a = e^-1 mod φ_a`、`d_b = e^-1 mod φ_b`（每对的 `e` 可能不同，逐对取）。
4. **逆序解密**：`mid = pow(c, d_b, n_b)` 然后 `m = pow(mid, d_a, n_a)`。
5. 回环校验：`pow(pow(m, e, n_a), e, n_b) == c`，确认没有把顺序搞反（反序会校验失败）。
6. `long_to_bytes(m)` 得到可读串；再按题面提示做字符层还原（删掉某个字符、把某个字符双写等）。
7. 三对分别执行，得到三段明文，按题面顺序拼接成最终 flag。

## PoC

```python
import gmpy2
from Crypto.Util.number import long_to_bytes

# 每对：(n_a, n_b, e, c)，e 为连乘两层的同一个指数
pairs = [(n1, n2, e1, c1), (n3, n4, e2, c2), (n5, n6, e3, c3)]

for na, nb, e, c in pairs:
    p = gmpy2.gcd(na, nb)
    assert 1 < p < na, "该对不共享素因子"
    qa, qb = na // p, nb // p
    assert p * qa == na and p * qb == nb

    da = int(gmpy2.invert(e, (p - 1) * (qa - 1)))
    db = int(gmpy2.invert(e, (p - 1) * (qb - 1)))

    mid = pow(c, db, nb)          # 先解外层（第二个模数）
    m   = pow(mid, da, na)        # 再解内层（第一个模数）
    assert pow(pow(m, e, na), e, nb) == c     # 顺序校验

    print(long_to_bytes(m).decode(errors="replace"))
```

## 变体与关联

- 层数变体：三层连乘就再多一个 `d` 按「后进先出」解；层数与模数对数量必须一致，否则拿不到全部私钥。
- 配对变体：共享因子可能不是整齐配对（`n1` 与 `n3` 共享、`n2` 与 `n5` 共享），此时应先做全部两两 `gcd` 建图，再按「密文与哪两个模数相关」配对解密。
- 明文后处理变体：删字符、字符双写、按位置移位、再套一层古典密码；见 [[crypto-rsa-dp-leak-composite-modulus-power-coppersmith]]（同篇的 Beaufort + 位置移位）。
- 关联：[[ctf-crypto-rsa-shared-prime-batch-gcd]]（只做 gcd 分解与单层解密，本卡补「双层逆序」这一必要步骤）；[[ctf-crypto-rsa-noncoprime-common-modulus-iroot-wiener-chain]]（同一模数、指数不互素时的开根路线，与本卡「不同模数、共享因子」互补）。

## 检测与防御

- **CTF 验证**：解完必须回环 `pow(pow(m,e,na),e,nb) == c`；顺序错时回环必失败，这是最快的自检。
- **真实 RSA 防御**：每对密钥独立生成、RSA 参数不复用；用 `secrets`/`os.urandom` 等 CSPRNG；对批量公钥定期做两两 gcd 扫描（共享因子一旦出现，所有相关密钥同时失效）。
- **协议层**：不要用「同一明文多模数连乘」构造密钥封装，指纹固定且可验证；使用标准 KEM（RSA-OAEP）或直接换 ECC。
- **检测信号**：批量公钥存在非互素对；`c < n_a` 但按 `n_a` 解密得乱码（提示真实模数是配对的另一个）；密文长度与两层模数都不匹配。
