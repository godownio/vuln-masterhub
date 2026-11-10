---
id: ctf-crypto-bsgs-exbsgs-discrete-log-sqrt-n
title: BSGS/EXBSGS 离散对数求解：把 x=kp−q 拆成大小步用哈希表在 O(√n) 内解 a^x≡c (mod n)，gcd(a,n)≠1 时先约简
type: scenario
domain: ctf
path: ctf/crypto
technique: bsgs-exbsgs-discrete-log
tags:
- ctf
- crypto
- discrete-log
- bsgs
- exbsgs
- modular-arithmetic
- python
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V361
  verified_at: '2026-11-09T02:34:23+08:00'
  notes: '已对照原文全文与8张公式图核对：x=kp−q 拆分、a^{kp}≡a^q·c 变形、q/p 范围、O(k+n/k) 与 k=√n 均值不等式、EXBSGS 逐次除 gcd 及 a^{x0}/Πg 逆元修正公式均与图01-08一致。数学核算并本机运行卡内 PoC：bsgs(17,5,23)=19（17^19 mod 23=5）、exbsgs(6,42,58)=3（6^3 mod 58=42）；原文 EXBSGS 代码注释输出 #34 不成立（6^34 mod 58=24），卡内改用回代验证正确的 x=3 并加入 pow(a,x,n)==c 回代校验与''勿盲信脚本注释输出''提示，属合理修正。无组件版本，affected_versions 留空正确。dedup top 候选（半直积小阶 DLP、四元数范数降维、无效曲线 ECDLP、投影 CRT、Pohlig-Hellman 等）均仅把 BSGS 作子步骤，dedup_review 成立。dup-scan.json（2026-11-08 19:10）早于建卡（2026-11-09 01:48），无涉及本卡 pair。未验证点：原文其余代码未逐一运行；frontmatter 无 sources/source_url（全库惯例）。'
url: /docs/ctf/crypto/ctf-crypto-bsgs-exbsgs-discrete-log-sqrt-n/
draft: false
kb_aliases:
- BSGS
- 大步小步算法
- Baby-Step Giant-Step
- EXBSGS
- 扩展 BSGS
- 离散对数求解
- 有限域 DLP
---

## 一句话结论

求解 `a^x ≡ c (mod n)`（`gcd(a,n)=1`）时，把指数拆成 `x = kp − q`，先枚举并缓存"小步" `a^q·c`，再枚举"大步" `(a^k)^p` 查表碰撞，就能在 `O(√n)` 时间与空间内求出 `x`（取 `k=⌈√n⌉`）；当 `gcd(a,n)≠1` 时，先用 EXBSGS 反复除以 `gcd` 把方程约简成互质形式再套 BSGS。

## 原理

- **方程**：`a^x ≡ c (mod n)`，`gcd(a,n)=1` 保证 `a` 在模 `n` 下可逆。令 `x = kp − q`，其中 `0 ≤ q < k`、`0 < p ≤ ⌈n/k⌉`，则 `x` 能覆盖 `[0, n)` 的全部候选。
- **等式变形**：`a^{kp−q} ≡ c` 两边乘 `a^q` 得 `a^{kp} ≡ a^q·c (mod n)`——左边只依赖大步计数 `p`，右边只依赖小步计数 `q`，把"求一个未知指数"变成"两个可枚举序列找相等项"。
- **小步阶段**：对 `q = 0..k−1` 计算 `a^q·c mod n`，存入哈希表（键为结果，值为 `q`）。
- **大步阶段**：预计算 `a^k mod n`，对 `p = 1..⌈n/k⌉` 计算 `(a^k)^p mod n`，在表中查找；命中则 `x = kp − q`。
- **复杂度与 k 的取值**：小步 `O(k)` 次计算与存储、大步最多 `O(n/k)` 次计算与查找，总量 `O(k + n/k)`；由均值不等式在 `k = √n` 时取最小，总复杂度 `O(√n)`（空间也是 `O(√n)`）。
- **为什么比穷举强**：穷举是 `O(n)`；BSGS 是时间-空间的折中（meet-in-the-middle），把 `n` 很大但 `√n` 可承受的场景（如 `n < 2^80`）变成可解。
- **EXBSGS（`gcd(a,n)≠1`）**：设 `g = gcd(a,n)`。若 `g ∤ c` 则无解；否则由 `a^x ≡ c (mod n)` 可推出 `(a/g)·a^{x−1} ≡ c/g (mod n/g)`，继续对新模数求 `gcd` 并重复，直到 `gcd(a', n') = 1`，记录除去的次数 `x0` 与累积因子；把约简后的方程用 BSGS 求出 `y`，最终 `x = y + x0`。
- **解的正确性校验**：BSGS 可能返回非最小解（同一同余类内可有多个解，尤其 EXBSGS 约简后），得到候选后务必用 `pow(a, x, n) == c % n` 回代验证。

## 触发条件

- 已知 `a`、`c`、模数 `n`（或群阶），需要求指数 `x`。
- 解空间 `n` 使 `√n` 的计算与存储在可接受范围（CTF 中常见 `n ≤ 2^80`，视算力而定）。
- `a` 与 `n` 互质；不互质时可用 EXBSGS 约简（约简后仍要满足 BSGS 可行性）。
- 不需要利用模数的结构（对比 Pohlig-Hellman 需要阶的因子全部小）。

## 利用步骤

1. 从题目/协议中确定方程 `a^x ≡ c (mod n)` 与各参数；计算 `g = gcd(a,n)`。
2. 若 `g ≠ 1`：按 EXBSGS 循环——若 `g ∤ c` 判无解；否则 `c ← c/g`、`n ← n/g`、累计 `x0` 与因子 `d ← d·g`，直到 `gcd(a,n)=1`；再用累积因子把 `c` 修正为 `c·(a^{x0}/d)^{-1} mod n`。
3. 取 `k = ⌈√n⌉`，枚举 `q = 0..k−1` 建 `a^q·c mod n → q` 哈希表。
4. 枚举 `p = 1..⌈n/k⌉`，计算 `(a^k)^p mod n` 查表；命中得 `x = kp − q`（EXBSGS 再加 `x0`）。
5. 回代验证 `pow(a, x, n) == c % n`；不成立时检查约简步骤或扩大 `p` 范围（`k` 的取整、`p` 的上界需覆盖 `n`）。

## PoC

```python
import math

def bsgs(a, c, n):
    assert math.gcd(a, n) == 1, "a and n must be coprime"
    k = int(math.ceil(math.sqrt(n)))
    table = {}
    rv = c % n
    for q in range(k):                      # 小步：a^q * c
        table.setdefault(rv, q)             # 保留最小 q
        rv = (rv * a) % n
    ak = pow(a, k, n)
    left = 1
    for p in range(1, k + 2):               # 大步：(a^k)^p
        left = (left * ak) % n
        if left in table:
            x = p * k - table[left]
            if pow(a, x, n) == c % n:       # 回代校验
                return x
    return None

print(bsgs(17, 5, 23))   # 19：17^19 mod 23 == 5

def exbsgs(a, c, n):
    x0, d = 0, 1
    g = math.gcd(a, n)
    while g != 1:
        if c % g != 0:
            return None                     # 无解
        x0 += 1
        c //= g
        n //= g
        d *= g
        g = math.gcd(a, n)
    # a^{x-x0} ≡ (a^{x0}/d)^{-1} * (c/d) (mod n/d)
    coef = pow((pow(a, x0, n) * pow(d, -1, n)) % n, -1, n)
    c2 = c * coef % n
    y = bsgs(a, c2, n)
    return None if y is None else y + x0

x = exbsgs(6, 42, 58)
print(x, pow(6, x, 58))  # 3 42：6^3 mod 58 == 42
```

注意：不同实现对 `p/q` 的起始值、`k` 取整与 EXBSGS 因子修正的处理不同，可能返回同余类里的另一个解；只要回代成立即可作为答案，勿盲目相信脚本注释中的输出。

## 变体与关联

- **ECDLP 上的 BSGS**：把群运算换成椭圆曲线点加/标量乘即可，见 [[crypto-ecc-invalid-point-secp256k1-bsgs]]；同类密钥小空间场景见 [[crypto-protocol-dh-private-key-partial-bits-mitm-table]]（中间相遇建表）。
- **阶光滑时更优**：已知群阶且因子都小时用 Pohlig-Hellman 逐因子求解，再 CRT 合并，见 [[crypto-ecc-ecdsa-smooth-order-pohlig-hellman]]、[[ctf-crypto-matrix-group-dlp-determinant-reduce-pohlig-hellman]]。
- **省内存变体**：Pollard's rho / kangaroo 用 `O(1)` 空间求 `O(√n)` 时间，见 [[crypto-ecc-ecdlp-80bit-prime-order-pollard-rho]]。
- **边界**：`n` 达到密码学规模（大素数群的阶含大素因子）时 `√n` 不可行，BSGS 只能用于 CTF 的小空间或参数缺陷场景；EXBSGS 只能处理整除关系，不能突破大群。

## 检测与防御

- **设计侧（防御 DLP 被 BSGS 打穿）**：使用阶含 ≥256 位大素因子的群（大素数阶子群、安全素数）；避免把私钥/指数限制在小范围或让指数空间暴露；校验生成元阶，避免小子群。
- **审题/利用侧（CTF）**：看到"指数在小范围""模数不大（如 80 位以内）""可精确构造 `a^x`"时应优先尝试 BSGS/EXBSGS；先判 `gcd(a,n)` 选择 BSGS 还是 EXBSGS，解出后必须回代验证。
- **检测线索**：CTF/演练环境之外，进程在本地做大量模幂与哈希表建表（`√n` 级内存与 CPU）可作为破解 DLP 的行为特征；对实际系统而言，只要群参数合规，BSGS 不构成威胁。
