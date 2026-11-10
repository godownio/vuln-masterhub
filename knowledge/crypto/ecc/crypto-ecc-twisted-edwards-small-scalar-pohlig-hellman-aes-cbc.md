---
id: crypto-ecc-twisted-edwards-small-scalar-pohlig-hellman-aes-cbc
title: Twisted Edwards 曲线小标量爆破 + 光滑阶 Pohlig–Hellman：余数类枚举恢复 SHA256 派生的 AES-CBC 密钥
type: scenario
domain: crypto
path: crypto/ecc
technique: twisted-edwards-small-scalar-pohlig-hellman-aes-key
aliases:
- BabyCurve
- Edwards 曲线小私钥
- 小标量爆破 ECDLP
- 光滑阶 PH + AES
- sha256 离散对数 AES key
- 余数类枚举
tags:
- crypto
- ecc
- twisted-edwards
- pohlig-hellman
- small-scalar
- aes-cbc
- hash-kdf
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V273
  verified_at: '2026-11-08T01:02:16+08:00'
  notes: 已对照原文 BabyCurve 段核对：a=46,d=20 曲线 range(100) 爆破得 c=35,b=98，p=770311352827455849356512448287 上 a=-35,b=98 的 PH、r 余数类枚举（r+k·L）、sha256(str(r))[:16] AES-CBC 校验与 DASCTF{THe_C0rv!_1s_Aw3s0me@!!} 均一致。原文脚本存在 n = P.order() // factors[-1][0] 的未定义变量/转录错误，卡片按 r+k·L 重写为等价骨架；未在本机 Sage 复跑。
---

## 一句话结论

曲线题先用小范围爆破恢复 Twisted Edwards 曲线上的小标量/小参数，再把曲线转到 Weierstrass 形式并对光滑阶做 Pohlig–Hellman，得到私钥 `r` 模“已处理素因子乘积”的余数；由于 `r` 还差一个大因子的整数倍，而 AES-CBC 密钥由 `sha256(str(r))[:16]` 派生，可枚举候选 `r + k·L`，用 PKCS#7 去填充成功且明文以 `DASCTF{` 开头作为判定，恢复 flag。

## 原理

- **小标量可直接爆破**：Twisted Edwards 曲线的加法公式为 `x3 = (x1y2 + y1x2)/(1 − d·x1²x2²)`、`y3 = ((y1y2 + 2a·x1x2)(1 + d·x1²x2²) + 2d·x1x2(x1² + x2²))/(1 − d·x1²x2²)²`。当私钥/参数范围只有 0..99 时，直接 double-and-add 枚举即可从 `P = c·G`、`Q = b·G` 恢复 `c`、`b`，不需要解一般 ECDLP。
- **转到 Weierstrass**：把曲线写成 `y² = x³ + a·x + b` 后，`EllipticCurve(GF(p), [a,b])` 可计算群阶与基点；不同模型间的映射保持群运算（或按题目给出的映射点直接使用），因此可用标准 Sage 工具做 PH。
- **Pohlig–Hellman 只给出部分余数**：`#E(F_p) = ∏ q_i^{e_i}`，对每个可计算的小素因子幂求出 `r mod q_i^{e_i}`，CRT 合并得到 `r mod M`，其中 `M = ∏` 已处理的小因子幂。若还剩一个大素因子 `L`（`order = M·L`），真实私钥是 `r + k·L`（`k` 未知，范围通常很小）。
- **KDF + 已知明文作为 oracle**：AES 密钥为 `sha256(str(r)).digest()[:16]`，因此每个候选 `r + k·L` 都对应一个不同的 key。用 AES-128-CBC 解密给定的 `iv/cipher`：错误 key 解密后 PKCS#7 去填充大概率抛异常；正确 key 去填充成功且明文以已知 flag 前缀开头。这个“格式校验”把不可见的 DLP 歧义变成可枚举的搜索。
- **为什么成立**：小标量/小参数是第一个弱点；光滑阶让 PH 求出大部分信息；KDF 直接把整数当秘密、且密文带可验证格式，使得剩余大因子造成的少量候选可以被穷举。

## 触发条件

- 题目使用自定义/弱参数曲线（Twisted Edwards/Weierstrass），私钥或曲线参数取值范围很小（如 <100），或曲线阶除一个大因子外都很光滑。
- 攻击者能用 SageMath 计算群阶、分解阶、`discrete_log` 与 `crt`。
- 后续 AES 密钥由离散对数（或其拼接/哈希）派生，且密文可用已知明文前缀/PKCS#7 填充校验。
- 大因子 `L` 造成的候选数 `k` 范围不大（通常由私钥位数或题目范围决定）。

## 利用步骤

1. 按题目曲线模型实现加法/double-and-add；对小范围私钥直接枚举 `c`、`b`，验证 `P == c*G`、`Q == b*G`。
2. 把曲线转换为 `EllipticCurve(GF(p), [a, b])`，计算 `n = E.order()` 并分解；筛选出可计算的小素因子幂（如 `q < 2^30~2^40`，按机器/时间调整）。
3. 对每个可处理因子幂 `mod = q**e`：`t = n // mod`，`dlog = discrete_log(t*Q, t*G, operation='+')`；用 CRT 合并得到 `r`。
4. 计算未处理部分 `L = n // M`（M 为已处理因子幂之积），对 `k = 0..K` 枚举 `r + k*L`：
   - `key = sha256(str(candidate).encode()).digest()[:16]`；
   - `AES.new(key, AES.MODE_CBC, iv).decrypt(cipher)`；
   - 尝试 `unpad`，并检查明文是否以 `DASCTF{`、`flag{` 等已知前缀开头；命中即输出。
5. 若候选顺序/范围不确定，优先用较小 `k`；也可先用 `key` 的哈希或密文长度做快速排除。
6. 得到 flag 后复核离散对数：`candidate * G == Q`（若适用），确认不是填充碰撞。

## PoC

```python
# SageMath + pycryptodome；曲线参数按题目替换
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

p = 770311352827455849356512448287
a, b = -35, 98
E = EllipticCurve(GF(p), [a, b])
G = E(584273268656071313022845392380, 105970580903682721429154563816)
Q = E(401055814681171318348566474726, 293186309252428491012795616690)
n = E.order()

moduli, residues = [], []
M = 1
for q, e in factor(n):
    if q > 2**40:          # 大因子留给后面枚举
        continue
    mod = q**e
    t = n // mod
    residues.append(discrete_log(t*Q, t*G, operation='+'))
    moduli.append(mod)
    M *= mod
r = crt(residues, moduli)
L = n // M

iv = bytes.fromhex("bae1b42f174443d009c8d3a1576f07d6")
ct = bytes.fromhex("ff34da7a65854ed75342fd4ad178bf577bd622df9850a24fd63e1da557b4b8a4")

for k in range(100000):
    candidate = r + k * L
    key = sha256(str(candidate).encode()).digest()[:16]
    try:
        pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
    except ValueError:
        continue
    if pt.startswith(b"DASCTF{"):
        print(candidate, pt.decode())
        break
```

```text
# 输出示例：
# b'DASCTF{THe_C0rv!_1s_Aw3s0me@!!}'
```

## 变体与关联

- **小标量变体**：除逐个枚举外，可用 BSGS 在 `O(√K)` 内求小范围 ECDLP；若私钥是时间戳/用户名派生，可缩小范围。
- **大因子变体**：若 `L` 很大但私钥有已知范围，可在 `r + k·L` 中按范围枚举；若 `L` 也光滑，直接全部 PH；若 `L` 是安全大素数，则只能依赖额外泄露。
- **KDF 变体**：密钥可能是 `sha256(str(r))`、`md5(str(r))`、`r.to_bytes(...)`、`str(r)+salt` 等；按题目代码复刻，逐个候选派生。
- **校验变体**：AES-CBC 用 PKCS#7 填充校验；AES-GCM 可校验 tag；也可用明文前缀、JSON 结构、文件 magic 作为 oracle。
- **关联卡片**：[[crypto-ecc-ecdsa-smooth-order-pohlig-hellman]]（光滑阶 PH 基础）、[[crypto-ecc-twisted-edwards-map-multiplicative-group-dlp]]（Edwards 曲线映射到乘法群）、[[crypto-implementation-small-lwe-secret-bruteforce-aes-key]]（小秘密枚举 + AES key 派生）、[[crypto-ecc-twisted-hessian-curve-weierstrass-pohlig-hellman]]（另一种曲线模型的参数恢复 + PH）。
- **边界**：若曲线阶含两个以上大素因子且私钥范围未知，候选空间爆炸；若 KDF 加了未知盐或 AES 使用 AEAD 且无已知明文，格式 oracle 失效。

## 检测与防御

- **CTF/设计视角**：不要使用自定义小参数曲线或让小私钥进入 KDF；使用标准曲线与 CSPRNG 生成私钥；KDF 加盐并绑定上下文。
- **实现视角**：AES-CBC 缺乏完整性保护，攻击者可利用填充 oracle；应使用 AES-GCM/ChaCha20-Poly1305 并校验 tag；密钥派生使用 HKDF/PBKDF2 而不是 `sha256(str(r))`。
- **检测信号**：曲线阶高度光滑；题目给出 Edwards/Hessian 等非标准模型且参数很小；密文长度是 16 的倍数且无认证标签；解题脚本出现 `factor(E.order())`、`discrete_log`、`crt`、`sha256(str(...))`。
- **取证/审计**：遇到“曲线 + AES”组合题，先检查曲线阶的因子分布与私钥范围，再检查 KDF 是否直接使用离散对数整数；这两个点往往决定是否能从部分 DLP 恢复密钥。
