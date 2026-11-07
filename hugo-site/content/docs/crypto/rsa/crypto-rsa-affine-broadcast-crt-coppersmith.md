---
id: crypto-rsa-affine-broadcast-crt-coppersmith
title: RSA 广播攻击变种：仿射变换 (a·m+b)^3 与 CRT 合并多项式求小根
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-affine-broadcast-crt-coppersmith
tags:
- rsa
- broadcast-attack
- hastad
- affine
- crt
- coppersmith
- small-roots
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V111
  verified_at: '2026-11-06T01:47:35+08:00'
  notes: 已对照 ScatterRSA 原文与 9 张图片核对：三路 c_i=pow(a_i*m+b_i,3,n_i)、CRT 逐系数合并、Z_N 首一化后 small_roots 逐档 X=2^384..2^1000 并回代验证，与原文 Sage 脚本一致；文章未给出运行输出截图，PoC 未复跑
url: /docs/crypto/rsa/crypto-rsa-affine-broadcast-crt-coppersmith/
draft: false
kb_aliases:
- ScatterRSA
- 低指数广播变种
- 仿射变换 RSA
- CRT 合并多项式
- Coppersmith small_roots
- (a*m+b)^3
---

## 一句话结论

当同一明文 `m` 在多个互素模数下被仿射变换后做低指数加密（`c_i ≡ (a_i*m + b_i)^3 mod n_i`）时，可以先把每个三次多项式 `f_i(x)=(a_i*x+b_i)^3-c_i` 的系数用 CRT 合并成模 `N=∏n_i` 的多项式 `F(x)`，则 `F(m) ≡ 0 mod N`；再用 Coppersmith `small_roots` 求小根即可恢复 `m`，无需同余式完全相同。

## 原理

- 标准 Hastad 广播攻击要求 `c_i ≡ m^e mod n_i`，CRT 合并后开 e 次方；若加密前做了仿射变换，直接开方失效。
- 但 `m` 仍是每个同余式 `f_i(m) ≡ 0 mod n_i` 的根，其中 `f_i(x)=(a_i*x+b_i)^3-c_i`。
- 因为 `n_i` 两两互素，可对 `f_i` 的每个系数（常数项到三次项）分别做 CRT，得到模 `N=∏n_i` 的多项式 `F(x)`；于是 `F(m) ≡ 0 mod N`。
- `F` 的首项系数 `lead` 若与 `N` 互素，可在 `Z_N` 上归一化为首一多项式，再用 Coppersmith 求 `|m| < X` 的小根；`X` 取 `2^384` 到 `2^1000` 逐档尝试。
- 找到根后必须回代每个 `n_i` 验证 `(a_i*m+b_i)^3 ≡ c_i mod n_i`，避免 CRT/多项式构造错误或伪根。
- 本质是把“同明文广播”推广为“同明文的多项式同余”，只要 `m` 足够小且 `e` 小（3 次），Coppersmith 就能解。

## 触发条件

- 使用小公钥指数 `e=3`（或较小 `e`），同一明文 `m` 在至少 `e` 个互素模数下加密。
- 每个模数对应已知仿射变换 `(a_i,b_i)` 与密文 `c_i`。
- `m` 的比特长度小于 `N` 的某个比例（Coppersmith 小根界），案例可到 900–1000 位。
- 首项系数 `lead` 与 `N` 互素（否则 gcd 可能直接给出因子）。

## 利用步骤

1. 收集 `(n_i,a_i,b_i,c_i)`，确认 `gcd(n_i,n_j)=1`。
2. 在 `ZZ` 上展开 `f_i(x)=(a_i*x+b_i)^3-c_i`，得到 4 个系数。
3. 对每个系数用 CRT 合并到模 `N`，得到 `F(x)`；检查 `gcd(lead,N)`，若不为 1 可直接尝试分解。
4. 在 `Z_N` 上把 `F` 归一化为首一多项式（每项乘 `lead^{-1}`）。
5. 对 `X=2^384,2^448,...,2^1000` 调用 `small_roots(X=X, beta=1.0)`。
6. 对每个根 `m` 回代所有 `n_i` 验证；通过后转字节/文本得到 flag。
7. 若失败，检查 `m` 是否比界大、`e` 是否真是 3、多项式展开/CRT 是否有误。

## PoC

```python
# Sage
mods = [Integer(n1), Integer(n2), Integer(n3)]
params = [(Integer(a1), Integer(b1), Integer(c1)),
          (Integer(a2), Integer(b2), Integer(c2)),
          (Integer(a3), Integer(b3), Integer(c3))]
N = prod(mods)

PR.<x> = PolynomialRing(ZZ)
polys = [(a*x + b)^3 - c for a, b, c in params]

coeffs = []
for k in range(4):
    residues = [Integer(polys[i][k]) % mods[i] for i in range(3)]
    coeffs.append(Integer(crt(residues, mods)))

lead = Integer(coeffs[3])
print("gcd(lead,N) =", gcd(lead, N))

ZN = Zmod(N)
R.<y> = PolynomialRing(ZN)
f = y^3 + sum((ZN(coeffs[k]) / ZN(lead)) * y^k for k in range(3))

for xb in [384, 448, 512, 640, 768, 900, 1000]:
    roots = f.small_roots(X=2^xb, beta=1.0)
    for r in roots:
        m = Integer(r)
        if all(power_mod(a*m + b, 3, n) == c % n
               for n, (a, b, c) in zip(mods, params)):
            print(int(m).to_bytes((int(m).bit_length() + 7)//8, "big"))
            raise SystemExit
```

## 变体与关联

- 变体：仿射变换可能是 `a_i*m + b_i`、`m*a_i mod n_i`、分段/线性组合；只要能写成多项式同余即可。
- 变体：`e` 不是 3 而是 5/7 时，多项式次数升高，需要更多模数/更大 `N` 或更强 Coppersmith。
- 变体：若 `gcd(lead,N) != 1`，可能直接得到 `N` 的因子，转为分解攻击。
- 关联：[[ctf-crypto-rsa-hastad-broadcast-e3-crt]]（标准广播）、[[crypto-rsa-e3-small-plaintext-integer-cube-root]]（小明文开方）、[[crypto-rsa-crt-multi-modulus-high-bits-coppersmith-low-bits]]（CRT+Coppersmith）。

## 检测与防御

- 防御：使用 OAEP 等随机化填充，确保同一明文每次加密结果不同；避免小 `e` 与固定线性变换组合。
- 防御：不要用同一明文在多个密钥/模数下加密；对 RSA 使用 2048 位以上模数与标准库。
- 检测：代码中出现 `(a*m+b)^e mod n`、多个模数、CRT 合并多项式；同一明文重复加密。
- 响应：发现广播/仿射泄露后轮换密钥，审计历史密文是否可恢复，改用随机化填充。
