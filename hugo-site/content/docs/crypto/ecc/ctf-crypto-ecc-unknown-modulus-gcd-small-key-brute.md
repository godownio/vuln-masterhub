---
id: ctf-crypto-ecc-unknown-modulus-gcd-small-key-brute
title: 未知模数 ECC：由两点曲线方程 gcd 恢复 p，再用小私钥范围枚举 k 解出乘法隐藏的两段明文
type: scenario
domain: crypto
path: crypto/ecc
technique: ecc-unknown-modulus-gcd-small-private-key-brute
tags:
- crypto
- ecc
- unknown-modulus
- gcd
- small-private-key
- brute-force
- elgamal
- sage
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V312
  verified_at: '2026-11-08T12:50:47+08:00'
  notes: 已对照原文 content.md 与18张图核对：图02 Sage 输出 p=95258468765219141626872797935766803481277588106799359407486570046359762703 与 b'flag{20a87e4e-02d3-11ef-8836-a4b1c1c5a2d2}'，卡片 PoC 的 a/b/G/K/c1/c2/cipher_left/right 数值、k1p/k2p gcd 恢复 p、2^17..2^18 枚举、M=c1-c2*k 与坐标模逆还原两段明文均与原文一致；原文文字仅说『改板子/改爆破范围』，ElGamal 结构（c2=rG,c1=rK+M）是卡片由 exp 反推的解释。dedup 除自身外 related 为 twisted-edwards 映射、RSA dp 枚举、小标量 brute 等，攻击对象与恢复方式不同；dup-scan 无涉及本卡 pair。原子性：未知模数恢复+小私钥枚举+密文还原为同一题的唯一利用链，属一个场景，不拆分。未验证点：未在 Sage 复跑；原文无版本信息，affected_versions 未设；frontmatter 无 sources/source_url。
url: /docs/crypto/ecc/ctf-crypto-ecc-unknown-modulus-gcd-small-key-brute/
draft: false
kb_aliases:
- 未知模数椭圆曲线
- 曲线方程 gcd 求 p
- k1p k2p gcd
- 小私钥爆破
- cipher_left cipher_right
- 春秋杯 ezzzecc
- ElGamal 型 ECC 解密
---

## 一句话结论

题目只给 `a、b` 和曲线点 `G、K、c1、c2` 而不给模数 `p` 时，对每个点计算 `d = x³ + a·x + b − y²`（必然是 p 的倍数），取两个点的 `gcd` 即可恢复 p；随后在 `GF(p)` 上建曲线，利用私钥 k 的取值空间很小（原文 `<1000000`，实际从 `2^17` 开始枚举），对每个候选 k 计算 `M = c1 − k·c2`，再用 `cipher_left·M.x⁻¹`、`cipher_right·M.y⁻¹` 还原两段明文并拼接即可得到 flag。

## 原理

- **点必须满足曲线方程**：曲线 `E: y² = x³ + a·x + b (mod p)` 上的任意点 `(x,y)` 都满足 `x³ + a·x + b − y² ≡ 0 (mod p)`，即 `d(x,y)` 是 p 的整数倍。
- **gcd 恢复 p**：题目给了多个点（原文用公钥点 K 和基点 G），分别算出 `d_K`、`d_G`，两者都是 p 的倍数，`gcd(d_K, d_G)` 就是 p 或 p 的小倍数；若结果是合数，分解出满足所有点曲线方程的素因子即可。原文实测 gcd 直接得到 77 位十进制素数 p。
- **密文结构与私钥消去**：该题是 ElGamal 型 ECC——公钥 `K = kG`，加密时选随机 `r`，`c2 = rG`、`c1 = rK + M`。因为 `rK = r(kG) = k(rG) = k·c2`，所以 `c1 − k·c2 = M`。这就是枚举 k 时用 `M = c1 - c2*k` 的原因。
- **两段明文的乘法隐藏**：明文被拆成两段整数 `m1、m2`，分别乘以点 M 的两个坐标：`cipher_left = m1·M.x mod p`、`cipher_right = m2·M.y mod p`。知道 M 后乘坐标的模逆即可还原 `m1、m2`，转字节后拼接（原文 `flag1 + flag2`）。
- **小私钥是突破口**：k 只有约 20 位（原文从 `2^17` 枚举到 `2^18`），直接逐点做曲线减法即可；每次只用坐标运算，Sage/gmpy2 下 13 万次以内能跑完。

## 触发条件

- CTF ECC 题只给曲线参数 `a、b` 与点 `G、K、c1、c2`、两个大整数 `cipher_left、cipher_right`，没有给 p、曲线阶或私钥。
- 所有给出点确实在同一条短 Weierstrass 曲线上（否则 gcd 无意义）。
- 私钥 k 的搜索空间足够小（原文 `<1000000`），或者能用 BSGS/Pollard-rho 在已知曲线阶上求离散对数。
- 有 SageMath（`EllipticCurve`、`GF`、`inverse`）或等价的模运算代码。

## 利用步骤

1. 对 K、G 分别计算 `d = x³ + a*x + b - y²`（注意模 p 未知，按大整数算）。
2. `p = gcd(d_K, d_G)`；若 p 为合数，对其分解并逐个素因子验证所有点是否满足曲线方程，选出正确的 p。
3. `E = EllipticCurve(GF(p), [a,b])`，把 G、K、c1、c2 转成曲线点。
4. 在私钥范围内枚举 k：`M = c1 - k*c2`；若 M 是无穷远点或某坐标为 0，跳过（下一步求逆会失败）。
5. `m1 = cipher_left * inverse(M[0], p) % p`，`m2 = cipher_right * inverse(M[1], p) % p`；分别 `long_to_bytes` 后拼接。
6. 判断字节串是否包含 `flag{`（或题目要求的格式），命中即输出；没命中则扩大 k 范围、检查 p 是否取错、或改用 BSGS。

## PoC

```python
# SageMath 中运行；^ 在 Sage 预处理器里表示幂而不是 XOR
from Crypto.Util.number import long_to_bytes
import gmpy2

a = 87425770561190618633288232353256495656281438408946725202136726983601884085917
b = 107879772066707091306779801409109036008421651378615140327877558014536331974777
K = (49293150360761418309411209621405185437426003792008480206387047056777011104939,
     43598371886286324285673726736628847559547403221353820773139325027318579443479)
G = (34031022567935512558184471533035716554557378321289293120392294258731566673565,
     74331715224220154299708533566163247663094029276428146274456519014761122295496)
c1 = (3315847183153421424358678117707706758962521458183324187760613108746362414091,
      61422809633368910312843316855658127170184420570309973276760547643460231548014)
c2 = (12838481482175070256758359669437500951915904121998959094172291545942862161864,
      60841550842604234546787351747017749679783606696419878692095419214989669624971)
cipher_left = 75142205156781095042041227504637709079517729950375899059488581605798510465939
cipher_right = 61560856815190247060747741878070276409743228362585436028144398174723191051815

# 1) 恢复未知模数
k1p = (K[0]^3 + a*K[0] + b) - K[1]^2
k2p = (G[0]^3 + a*G[0] + b) - G[1]^2
p = gmpy2.gcd(k1p, k2p)
print("p =", p)

# 2) 建曲线并枚举小私钥
E = EllipticCurve(GF(p), [a, b])
G, K, c1, c2 = E(G), E(K), E(c1), E(c2)
for k in range(2^17, 2^18):          # 原文私钥 k < 1000000，从 2^17 起加速
    M = c1 - c2*k
    if M.is_zero() or M[0] == 0 or M[1] == 0:
        continue
    m1 = cipher_left * inverse(M[0], p) % p
    m2 = cipher_right * inverse(M[1], p) % p
    flag = long_to_bytes(int(m1)) + long_to_bytes(int(m2))
    if b"flag{" in flag:
        print(k, flag)
        break
```

原文运行结果：恢复出 `p = 95258468765219141626872797935766803481277588106799359407486570046359762703`，枚举区间内输出 `b'flag{20a87e4e-02d3-11ef-8836-a4b1c1c5a2d2}'`。

## 变体与关联

- **多个点求 p**：给出的点越多，可两两/连续求 gcd，能消除 p 的小倍数干扰；某个点使 `d=0` 时应跳过。
- **p 为合数**：gcd 可能是 `p·small`，先分解再验证；也可以对所有 d 求 gcd 后再试除小因子。
- **私钥不小时**：改用 `discrete_log`/BSGS/Pollard-rho；若曲线阶光滑则用 Pohlig-Hellman，见 [[crypto-ecc-ecdsa-smooth-order-pohlig-hellman]]。
- **同族未知曲线题**：[[crypto-ecc-unknown-curve-point-halving-recover-flag]]、[[crypto-ecc-unknown-curve-projective-cubic-fit-weierstrass-dlp]] 也是先恢复 p/b 再做点运算，差别在恢复方式（点减半/投影三次拟合）与后续求解目标。
- **关联的小私钥题**：[[crypto-ecc-ecdh-small-nonce-brute-shared-point-key]]、[[crypto-ecc-ecdsa-nonce-reuse-private-key-recovery]]。
- **边界**：本题密文用坐标乘法隐藏明文，若任一坐标为 0 会退化；实际曲线若使用标准曲线且 k 为 256 位全随机，枚举不可行。原文未给出密码库/曲线库版本，代码依赖 Sage 语义。

## 检测与防御

- 本卡是 CTF 数学攻击，防御视角对应真实 ECC 实现：使用标准曲线与标准参数，不要把“模数保密”当作安全边界；模数、曲线参数都应公开且固定。
- 私钥必须由 CSPRNG 生成且长度足够（如 256 位），不能用小范围随机数；加密 nonce 也必须每次新鲜且不可预测。
- ElGamal 型 ECC 若把明文直接乘到点坐标上，需配合消息编码/KDF，避免小私钥或坐标关系导致明文可枚举。
- CTF 场景下仅用于题目环境，对真实目标做密钥恢复需明确授权。
