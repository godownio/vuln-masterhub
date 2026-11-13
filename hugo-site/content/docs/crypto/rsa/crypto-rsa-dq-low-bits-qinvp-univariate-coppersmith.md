---
id: crypto-rsa-dq-low-bits-qinvp-univariate-coppersmith
title: dq 低位泄露 + qinvp：用 qinvp·q²−q≡0 mod n 构造一元多项式，枚举 k 恢复 dq 并分解 n
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-dq-low-bits-qinvp-univariate-coppersmith
tags:
- rsa
- coppersmith
- partial-key
- dq-leak
- crt
- lattice
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V531
  verified_at: '2026-11-11T17:09:18+08:00'
  notes: 已对照原文与图07-08核对并本地复算：dq_low=0xc90bcecf1cbab3358585e8a041d1b1为120位；由qinvp*q=1+k2*p两边乘q得t*q^2-q≡0 mod n，代入q=(e*dq-1)/k+1乘k^2得到t*(e*dq-1)^2+k*(2t-1)*(e*dq-1)+k^2*(t-1)≡0，推导无误。用图08输出数值验证：恢复的512位p与q满足p*q=n、qinvp*q mod p=1、dq mod 2^120=dq_low、(e*dq-1) mod (q-1)=0且k=59199与截图一致，数学链完整成立。与库内dp高位二元Coppersmith、dp枚举k等卡输入/多项式不同，非同链；dup-scan无pair。原文无版本。
url: /docs/crypto/rsa/crypto-rsa-dq-low-bits-qinvp-univariate-coppersmith/
draft: false
kb_aliases:
- corrupted_key
- 蓝帽杯2022
- dq 低位泄露
- qinvp
- q 模 p 的逆
- e*dq-1=k(q-1)
- 一元 Coppersmith dq
---

## 一句话结论

已知 `n、e`、`dq` 的低 120 位与 `qinvp = q^{-1} mod p` 时，由 `e·dq ≡ 1 (mod q-1)` 得 `e·dq-1 = k(q-1)`（`0<k<e`），再代入 `qinvp·q² - q ≡ 0 (mod n)`，令 `dq = 2^120·x + dq_low` 并枚举 `k`，可构造关于 `x` 的一元模多项式，用 Coppersmith 小根求出 `dq`，进而 `q=(e·dq-1)/k+1`、`p=n/q` 完成分解。

## 原理

- **dq 与 k 的关系**：`dq = d mod (q-1)`，故 `e·dq ≡ e·d ≡ 1 (mod q-1)`，即 `e·dq - 1 = k·(q-1)`，且 `0 < k < e`（因为 `dq < q-1`）。于是 `q = (e·dq - 1)/k + 1`。
- **qinvp 给出模 n 的等式**：`qinvp = q^{-1} mod p` 即 `qinvp·q ≡ 1 (mod p)`，写成整数 `qinvp·q = 1 + k2·p`；两边乘 `q` 得 `qinvp·q² = q + k2·p·q = q + k2·n`，因此
  `t·q² - q ≡ 0 (mod n)`，其中 `t = qinvp`。
- **消去 q 得到 x 的多项式**：把 `q = (e·dq-1)/k + 1` 代入并两边乘 `k²`，整理得
  `t·(e·dq-1)² + k·(2t-1)·(e·dq-1) + k²·(t-1) ≡ 0 (mod n)`。
  再把 `dq = 2^120·x + dq_low` 代入，得到只含未知 `x` 的二次模多项式（其余量已知）。
- **为什么 x 是小根**：真实 `dq` 使上述等式在模 `n` 下成立，而 `x = (dq - dq_low)/2^120` 是 `dq` 的高位部分，约 `512-120 = 392` 位；`q` 整除 `n`，因此多项式模 `n` 的小根即对应真实 `x`。`k` 未知但只有 `e-1 ≈ 65536` 个，逐个枚举即可。
- **恢复流程**：命中 `k` 后，`dq = 2^120·root + dq_low`，`q = (e·dq-1)//k + 1`，`p = n//q`，验证 `p*q == n`；之后按普通 RSA 解密。

## 触发条件

- 泄露 `dq` 的低若干位（原文 120 bit）与 `qinvp = q^{-1} mod p`，同时给出 `n、e` 与密文；
- `k` 的枚举空间 `0<k<e` 可接受（`e=65537`）；
- 未知 `dq` 高位位数在 Coppersmith 界内（原文 392 bit，`beta=0.5` 可解）；
- 能运行 Sage `small_roots`。

## 利用步骤

1. 计算 `t = qinvp`，确认 `dq_low` 的位数 `L`（原文 120）；
2. 对 `k` 从 `e-1` 递减到 `1`：构造 `dq = 2^L·x + dq_low`，代入
   `f(x) = t·(e·dq-1)² + k·(2t-1)·(e·dq-1) + k²·(t-1) mod n`；
3. `f.monic()` 后调用 `small_roots(X=2^(pbits-L), beta=0.5)`（原文 `kbit=512-120`）；
4. 若返回根，恢复 `dq = 2^L·root[0] + dq_low`、`q = (e·dq-1)//k + 1`、`p = n//q`，验证 `p*q == n`；
5. 命中后计算 `d = e^{-1} mod (p-1)(q-1)` 解密密文；若某 `k` 无根继续下一个。

## PoC

```python
# sage；原文蓝帽杯2022 corrupted_key 参数
t = qinvp
PR.<x> = PolynomialRing(Zmod(n))
dq = 2^120 * x + dq_low
kbit = 512 - 120
for k in range(e, 1, -1):
    f = t * (e*dq - 1)^2 + k * (2*t - 1) * (e*dq - 1) + k^2 * (t - 1)
    f = f.monic()
    root = f.small_roots(X=2^kbit, beta=0.5)
    if root:
        dq = 2^120 * root[0] + dq_low
        q = int((e*dq - 1)//k + 1)
        p = n // q
        if p*q == n:
            print('dq =', dq, 'p =', p, 'q =', q)
            break
```

## 变体与关联

- 对称情形：泄露 `dp` 低位与 `pinvq = p^{-1} mod q` 时，可构造 `pinvq·p² - p ≡ 0 (mod n)` 的同型多项式；
- `k` 范围：`0 < k < e`，`e` 很小时可枚举；`e` 很大时可结合 `k` 的近似值或其它泄露缩小范围；
- 与库内 `crypto-rsa-dp-high-bits-bivariate-coppersmith` 对比：后者用 `e·dp-1=k(p-1)` 构造二元小根（x 与 k 同时求），本卡用 `qinvp` 提供额外模 n 等式，把 k 枚举掉、只留一元 x；
- 与 `crypto-rsa-dp-dq-both-leak-crt-recombine-without-e` 对比：后者是 dp/dq 完整泄露后的 CRT 重组，不涉及 Coppersmith。

## 检测与防御

- 防御侧：不要在任何日志/报错/侧信道中泄露 `dq` 的部分比特或 `q^{-1} mod p`（CRT 中间值）；CRT-RSA 实现应使用盲化（base blinding）与故障注入防护；
- 使用足够大的素数并避免复用密钥；密钥生成后校验 `dp/dq` 未被写入可访问的内存转储/配置；
- 检测侧：看到 `dq_low`、`qinvp`、`corrupted_key` 一类参数组合时，按本卡评估 `e·dq-1=k(q-1)` 与 `qinvp·q²-q≡0` 的可行性。
