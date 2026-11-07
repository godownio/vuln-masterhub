---
id: ctf-crypto-quaternion-norm-dlp-bsgs
title: 四元数环离散对数：范数同态降维到素域后 BSGS，MD5(secret) 派生 AES 密钥
type: scenario
domain: ctf
path: ctf/crypto
technique: quaternion-norm-dlp-bsgs
tags:
- ctf
- crypto
- quaternion
- discrete-log
- bsgs
- norm
- aes
- md5
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V238
  verified_at: '2026-11-07T09:10:15+08:00'
  notes: 已对照原文与图核对：四元数乘法/范数 N(Q^k)=N(Q)^k、secret<2^50、m≈2^25 BSGS、MD5(str(secret)).hexdigest() 派生 32 字节 AES-256-ECB 密钥、密文与原文一致。原文代码为 AI 生成风格且未给出 secret 输出，未本机跑 2^25 BSGS，confidence=medium 合理。
url: /docs/ctf/crypto/ctf-crypto-quaternion-norm-dlp-bsgs/
draft: false
kb_aliases:
- 四元数离散对数
- quaternion DLP
- 范数同态
- N(Q^k)=N(Q)^k
- 非交换环降维
- BSGS 2^25
---

## 一句话结论

给定模大素数 `p` 的四元数 `Q`、`R` 且 `R = Q^secret`（`secret < 2^50`），不必在非交换环上直接解离散对数：四元数范数 `N(a,b,c,d)=a²+b²+c²+d²` 满足 `N(Q^k)=N(Q)^k mod p`，先算出 `N(Q)`、`N(R)` 就把问题降为素域 `F_p` 上的 50-bit 离散对数，用 `m≈2^25` 的 BSGS 恢复 `secret`，再用 `MD5(str(secret))` 派生 AES 密钥解密 flag。

## 原理

- **四元数乘法与范数**：四元数 `(a,b,c,d)` 的乘法非交换，但范数 `N(q)=a²+b²+c²+d²` 是可乘的：`N(q1·q2)=N(q1)·N(q2) mod p`。因此 `R=Q^secret` 两边取范数得到 `N(R)=N(Q)^secret mod p`，指数关系被搬到交换的乘法群 `F_p^*` 中。
- **为什么可以降维**：`p` 是大素数，只要 `N(Q) ≠ 0 mod p`，`N(Q)` 就在 `F_p^*` 中可逆，`N(R)` 是它的幂；原本四元数环的四维结构不影响这一个标量方程，而 `secret` 只有 50 bit，标量 DLP 的难度足够低。
- **BSGS**：取 `m=⌈√(2^50)⌉≈2^25`，先存 `h·g^{-j}`（`j=0..m-1`），再枚举 `g^{im}`（`i=0..m`），命中时 `secret=im+j`。时间与空间约 `2^25`；若不存全表可改用 Pollard kangaroo 降低内存，代价是更多次乘法。
- **唯一性**：`F_p^*` 是阶为 `p-1` 的循环群，解只在模 `ord(N(Q))` 意义下唯一。若 `ord(N(Q)) ≥ 2^50`，则区间内只有一个解；若阶较小，会得到多个候选 `secret`，需要用 AES 解密的 PKCS#7 padding 或 flag 前缀逐个验证。
- **密钥派生与解密**：原文用 `key = MD5(str(secret)).hexdigest().encode()` 得到 32 字节 ASCII 十六进制串，作为 AES-256 密钥，`AES.MODE_ECB` 解密后 `unpad` 得明文。密钥长度与模式由题目代码给定，换题时必须重新确认。
- **为什么这条链成立**：题目只暴露了 `Q`、`R` 和 AES 密文，没有暴露四元数指数运算的实现；范数同态是公开的代数性质，攻击者可以完全绕开四元数快速幂，只做一次标量 BSGS。

## 触发条件

- 已知大素数 `p`、四元数 `Q`、`R`，且 `R=Q^secret`，`secret` 有较小的已知上界（本例 `<2^50`）。
- `N(Q) mod p ≠ 0`，且 `N(Q)` 在 `F_p^*` 中的阶不小于上界（否则需要多候选验证）。
- 加密方式与密钥派生已知（本例 AES-256-ECB + `MD5(str(secret))`），密文可获取。
- 有约 `2^25` 次群乘的时间/内存预算（C++/PyPy 更快；Python 纯实现较慢，可用 gmpy2 或编译语言）。

## 利用步骤

1. 读取 `p`、`Q=(a,b,c,d)`、`R=(a',b',c',d')` 和 AES 密文。
2. 计算两个范数：`g = (a²+b²+c²+d²) mod p`、`h = (a'²+b'²+c'²+d'²) mod p`。
3. 在 `F_p` 上做 BSGS：`m=⌈√(bound+1)⌉`；建立 `h·g^{-j} → j` 的表；枚举 `g^{im}` 并查表，得到 `secret=im+j`（只接受 `0 ≤ secret ≤ bound`）。
4. 若 `ord(g)` 小于 `bound`，会得到多个 `secret`；对每个候选派生密钥、解密并检查 PKCS#7 填充与 `flag{` 前缀。
5. 用 `MD5(str(secret)).hexdigest().encode()` 作 AES 密钥，ECB 解密并去填充，得到 flag。

## PoC

```python
from hashlib import md5
from math import isqrt
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

p  = 115792089237316195423570985008687907853269984665640564039457584007913129639747
Q  = (123456789, 987654321, 135792468, 864297531)
R  = (53580504271939954579696282638160058429308301927753139543147605882574336327145,
      79991318245209837622945719467562796951137605212294979976479199793453962090891,
      53126869889181040587037210462276116096032594677560145306269148156034757160128,
      97368024230306399859522783292246509699830254294649668434604971213496467857155)
enc = b'(\xe4IJ\xfd4%\xcf\xad\xb4\x7fi\xae\xdbZux6-\xf4\xd72\x14BB\x1e\xdc\xb7\xb7\xd1\xad#e@\x17\x1f\x12\xc4\xe5\xa6\x10\x91\x08\xd6\x87\x82H\x9e'

def norm(q):
    return sum(x * x for x in q) % p

def bsgs(g, h, bound):
    m = isqrt(bound + 1) + 1
    table = {}
    inv_g = pow(g, -1, p)
    cur = h
    for j in range(m):
        table.setdefault(cur, j)          # h * g^{-j}
        cur = cur * inv_g % p
    giant = pow(g, m, p)
    cur = 1
    for i in range(m + 1):
        if cur in table:                  # g^{im} == h * g^{-j}
            x = i * m + table[cur]
            if x <= bound:
                yield x
        cur = cur * giant % p

for secret in bsgs(norm(Q), norm(R), 2**50):
    key = md5(str(secret).encode()).hexdigest().encode()
    try:
        pt = unpad(AES.new(key, AES.MODE_ECB).decrypt(enc), 16)
    except ValueError:
        continue
    if b'flag' in pt or pt.startswith(b'flag{'):
        print(secret, pt)
        break
```

原文代码用字典存 `h·g^{-j}`、以 `g^m` 做大步，并用 `MD5(str(secret)).hexdigest()` 派生 AES 密钥；以上实现保持同一逻辑，仅把候选验证写成生成器。原文未在本机复跑，`2^25` 规模的 BSGS 需按机器内存调整（可只存哈希或改用 Pollard kangaroo）。

## 变体与关联

- **内存受限**：把 BSGS 换成 Pollard kangaroo/Pollard rho，或分块生成 baby steps；代价是多次群乘。
- **阶不足**：若 `ord(N(Q))` 小于指数上界，单个范数方程只能确定 `secret mod ord`；可结合多个可乘同态（如四元数不同共轭/矩阵表示的行列式、其他二次型）做 CRT，或用明文格式筛选候选。
- **其他非交换结构**：矩阵群、半直积、四元数代数等只要存在可计算的可乘范数/行列式同态，都可能把指数问题降到交换群；这类“同态泄露指数”是设计密码系统时必须排除的。
- 关联：[[ctf-crypto-semidirect-product-small-order-discrete-log]]（非交换/半直积群上的小阶 BSGS）、[[ctf-crypto-small-discrete-log-crt-channel-selection]]（小模数 DLP + CRT 恢复指数）、[[crypto-ecc-invalid-point-secp256k1-bsgs]]（BSGS 基础）。

## 检测与防御

- **CTF 识别**：题目给出“四元数/矩阵/非交换环 + 幂 + 小指数上界”时，先找可乘范数、行列式、迹等标量同态，不要直接实现环上 BSGS 或暴力。
- **防御/设计**：不要用“非交换”本身当作 DLP 难度的保证；选择素数阶群、避免存在高效同态到小群的结构，并确保密钥派生使用足够熵的 secret（本例 secret 仅 50 bit，且由 MD5 直接派生）。
- **检测特征**：大素数模下的范数/行列式计算、`2^25` 量级的哈希表或大量 `pow(g, m, p)` 调用，可能是此类降维攻击的实现。
