---
id: ctf-crypto-ntru-xplus1-lll-distinguish-mt
title: NTRU 样本模 x+1 投影 LLL 区分：恢复 coin 位后预测 MT19937 解 AES
type: scenario
domain: ctf
path: ctf/crypto
technique: ntru-xplus1-projection-lll-distinguish-mt
aliases:
- NTRU x+1 因子
- 多项式模 x+1
- LLL 区分小量
- coin 位恢复
- gf2bv
tags:
- ctf
- crypto
- ntru
- lll
- lattice
- mt19937
- aes
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:02:29+08:00'
  notes: 已对照 Blurred 原代码核对：x+1 投影、3×3 格 LLL、阈值 100、20000 bit、gf2bv+SHA256(str(getrandbits(256))) 一致；未复跑远程服务。
---

## 一句话结论

在 `Z_q[x]/(x^n+1)` 中 `x+1` 是 `x^n+1` 的因子；把 NTRU 样本 `f*h_i = g_i` 模 `x+1` 后得到一个小整数方程 `f(-1)*h_i(-1) = g_i(-1)`。用 `[[1,h1,h2],[0,q,0],[0,0,q]]` 做 LLL，短向量范数小于阈值即判定该 hint 是真实样本，从而恢复每轮的 coin 位；收集足够位后用 MT19937 线性系统预测后续随机数，SHA-256 派生 AES key 解密。

## 原理

- 本题 `n=1031` 为奇数，`x=-1` 时 `(-1)^n+1=0`，所以 `x+1 | x^n+1`。在商环 `Z_q[x]/(x+1)` 中 `x` 等价于 `-1`，一个多项式模 `x+1` 就是“系数正负交替求和”，得到一个标量。
- NTRU 关系 `f*h_i ≡ g_i (mod x^n+1)` 模 `x+1` 后仍成立：`f(-1)*h_i(-1) ≡ g_i(-1) (mod q)`。由于 `f`、`g_i` 的系数都很小，`f(-1)` 与 `g_i(-1)` 也是小整数。
- 服务器每轮给出两个 hint `h1,h2`，其中一个是真实 NTRU 公钥样本、另一个是随机值；真实样本存在小向量 `(f(-1), g_1(-1), g_2(-1))`，随机 hint 没有。构造格
  `[[1,h1,h2],[0,q,0],[0,0,q]]`，LLL 后第一行就是该小向量（或它的短组合）；真实样本范数远小于随机样本，用阈值（本题 `<100`）即可判定 coin 位。
- coin 位序列就是 MT19937 的 `getrandbits(1)` 输出。位是状态的线性函数，用 `gf2bv` 的 `LinearSystem` 建立 624×32 个状态位的方程，解出状态后克隆 RNG。
- 后续密钥为 `SHA256(str(rng.getrandbits(256)))`，AES-ECB 解密即可。

## 触发条件

- 题目使用 `x^n+1` 且 `n` 为奇数，因此 `x+1` 是公开的线性因子；攻击者可以把高维 NTRU 样本降到一维小整数方程。
- `f`、`g` 的系数足够小，使 `f(-1)`、`g(-1)` 落在 LLL 能区分的范围内；`q` 足够大。
- 可反复查询，每轮泄漏 1 bit（哪个 hint 为真），且该 bit 来自 MT19937。
- 后续随机数直接用于密钥派生，攻击者知道派生格式。

## 利用步骤

1. 反复向服务查询，每轮拿到两个 hint `h1,h2`。
2. 分别计算 `h1 % (x+1)`、`h2 % (x+1)`（即系数交替和），构造 3×3 格并 LLL。
3. 看 LLL 第一行范数：小于阈值记为 bit 0，否则 bit 1（具体 0/1 方向按题目对应关系标定）。
4. 收集约 20000 个 bit，用 `gf2bv.crypto.mt.MT19937` 建线性系统解出 624 个状态字。
5. 克隆 RNG，按题目顺序取 `getrandbits(256)`，`SHA256(str(...))` 得到 AES key。
6. AES-ECB 解密密文，得到 flag。

## PoC

```python
from sage.all import *
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from gf2bv import LinearSystem
from gf2bv.crypto.mt import MT19937

q, n = 1342261, 1031
PR = PolynomialRing(GF(q), "x")
x = PR.gen()

BITS = []
for _ in range(20000):
    h1, h2 = get_hints()                    # 服务端返回的两个 hint 多项式
    h1_ = GF(q)(h1 % (x + 1))
    h2_ = GF(q)(h2 % (x + 1))
    L = Matrix(ZZ, [[1, h1_, h2_], [0, q, 0], [0, 0, q]]).LLL()
    BITS.append(0 if L[0].norm() < 100 else 1)

# MT19937 状态恢复：每个 bit 一条 GF(2) 方程
lin = LinearSystem([32] * 624)
mt = lin.gens()
rng = MT19937(mt)
zeros = [rng.getrandbits(1) ^ b for b in BITS] + [mt[0] ^ 0]
sol = lin.solve_one(zeros)
rng = MT19937(sol)

key = SHA256.new(str(rng.getrandbits(256)).encode()).digest()
print(AES.new(key, AES.MODE_ECB).decrypt(enc))
```

说明：`get_hints` 与 `enc` 为题目接口/附件，LLL 的 0/1 方向需按实际返回标定；未在本机复跑原题服务。

## 变体与关联

- **其他因子投影**：若 `x^n+1` 有其他小次数因子（如 `x^2+1`），可降到二维/四维格，判别信号更强。
- **NTRU 参数**：`q`、`n`、系数分布变化会改变阈值；阈值应先用已知样本标定。
- **MT19937 相关恢复**：完整输出用 untemper，截断输出用线性系统；见 [[ctf-crypto-mt19937-bitstream-chinese-alignment-state-recovery]]、[[ctf-crypto-mt19937-truncated-output-gf2-linear-recovery]]。
- **LWE/NTRU 格攻击**：同属“把高维小秘密投影到低维后用 LLL 找短向量”的思路。

## 检测与防御

- 不要用 MT19937 生成密钥；使用 CSPRNG，并对随机数输出做密码学哈希。
- NTRU 类协议的采样应避免暴露大量“真/假样本”标签；对查询次数做限制。
- 检测：服务端每轮返回两个 hint 且可用公开因子区分，通常意味着可被投影降维攻击。
