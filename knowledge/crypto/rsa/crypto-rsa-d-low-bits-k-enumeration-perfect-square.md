---
id: crypto-rsa-d-low-bits-k-enumeration-perfect-square
title: RSA 私钥 d 低 530 位泄露：枚举 k 与 d 高位，用 s²−4n 完全平方直接分解 n
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-d-low-bits-k-enumeration-factor
aliases:
- RSA d 低位泄露
- d low bits leak
- k 枚举分解 n
- s^2-4n 完全平方
- 无 Coppersmith 恢复 d
- rsa-dl_leak
tags:
- rsa
- partial-key-exposure
- private-exponent
- factorization
- k-enumeration
- perfect-square
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V242
  verified_at: '2026-11-07T12:47:47+08:00'
  notes: 已对照原文 rsa-dl_leak 段核对：n/e/c/dl、m=530、k 枚举、d=dl+d_high*2^530、phi=(ed-1)/k、s=n+1-phi、s^2-4n 完全平方、p*q 校验均一致；本机执行卡内 PoC，k=22348 解出 Res0lv1ng_the_c0mpos1te_numb3r。原文文字写“d 的高位泄露”与代码矛盾，卡片已按代码注明 dl 为低 530 位。
---

## 一句话结论

已知 RSA 私钥 `d` 的低 `m` 位 `dl`、公钥 `(n,e)` 与密文 `c` 时，不需要 Coppersmith/Sage：对每个 `k∈[1,e−1]`，用 `d ≈ (k·n+1)/e` 估计 `d` 的高位、在 `d = dl + d_high·2^m` 中枚举少量 `d_high`，再用 `φ=(e·d−1)/k`、`s=n+1−φ` 与判别式 `s²−4n` 是否为完全平方直接分解 `n`，最后求 `d_real` 解密。

## 原理

- **RSA 关系**：`e·d ≡ 1 (mod φ(n))`，所以存在整数 `k` 使 `e·d − 1 = k·φ(n)`，且 `1 ≤ k < e`（`e=65537` 时只需枚举 65536 个 `k`）。
- **已知低位**：把 `d` 写成 `d = dl + d_high · 2^m`，其中 `dl = d mod 2^m` 是已知的低 `m` 位（原文 `m=530`，`dl` 的位数为 530，符合 `dl < 2^530`）。
- **高位估计**：`φ(n) = n − (p+q) + 1 ≈ n`，因此 `d = (1 + k·φ)/e ≈ (k·n + 1)/e`。令 `d_approx = (k·n+1)//e`，则 `d_approx − dl ≈ d_high·2^m + (d_approx − d)`。误差项约 `k·(p+q−1)/e ≈ k·2√n/e`，在 1024 位 `n`、`e=65537` 时约 500 多位，小于 `2^530`，所以 `d_high` 落在 `(d_approx−dl)//2^m` 附近一个很小的窗口（原文取 ±10）。
- **过滤**：对每个候选 `d` 先检查 `(e·d − 1) % k == 0`；通过后令 `φ=(e·d−1)/k`、`s=n+1−φ`。因为 `s=p+q`，`p,q` 是二次方程 `x² − s·x + n = 0` 的两根，判别式 `Δ = s² − 4n` 必须是完全平方；`math.isqrt(Δ)` 平方回代即可得到 `p,q`，再验证 `p·q == n`。
- **为什么成立**：低位泄露把 `d` 的自由度压到“高位猜测”，`k` 的枚举把 `φ` 的未知乘数消掉，判别式完全平方是极强的正确性过滤器；一旦分解成功，`φ` 与 `d_real` 都可直接算出，无需恢复原始 `d`。
- **与 Coppersmith 方法的区别**：另一类“d 低位泄露”卡把 `p` 的低位作为未知量，用 `solve_mod` + `small_roots` 恢复 `p`；本方法直接枚举 `d` 的高位并用二次方程判别式分解，纯 Python 即可，不依赖 Sage/格。原文文字写“d 的高位泄露”，但其代码 `d = dl + d_high·2^530` 与 `dl < 2^530` 表明 `dl` 是低 530 位，应以代码/数学为准。

## 触发条件

- 已知 `n`、`e`、`c`，以及 `d` 的连续低 `m` 位 `dl`（`d mod 2^m`）。
- `e` 较小（如 65537），可以枚举 `k=1..e−1`；若 `e` 很大，枚举不可行，需要改用格/Coppersmith。
- `m` 足够大，使高位估计误差落在可接受的窗口内；`m` 太小或误差超过窗口时需要扩大搜索或换方法。
- `d` 的低位必须是真正的二进制低位（`d mod 2^m`），不是十六进制前缀/高位片段。
- 目标使用标准 RSA（`p,q` 为大素数，`φ=(p−1)(q−1)`），无特殊多素数/CRT 变体。

## 利用步骤

1. 确认 `dl` 是 `d mod 2^m`：检查 `dl < 2^m`，并向题目/代码确认 `m`。
2. 对 `k = 1..e−1`：
   - `d_approx = (k*n + 1) // e`；
   - 若 `d_approx < dl`，跳过；
   - `candidate = (d_approx - dl) // 2^m`；
   - 在 `candidate ± 10` 范围内枚举 `d_high`，令 `d = dl + d_high*2^m`；
   - 检查 `(e*d - 1) % k == 0`，不满足则继续。
3. 令 `phi = (e*d - 1) // k`，`s = n + 1 - phi`；计算 `delta = s*s - 4*n`。
4. 若 `delta >= 0` 且 `math.isqrt(delta)**2 == delta`，得到 `p=(s+root)//2`、`q=(s-root)//2`；验证 `p*q == n`。
5. 分解成功后 `d_real = inverse(e, phi)`，`m = pow(c, d_real, n)`，`long_to_bytes(m)` 得到明文/flag。
6. 若所有 `k`/窗口都失败，检查 `m` 是否足够、`dl` 是否确为低位、`e` 是否过大，必要时扩大 `d_high` 窗口或改用 Coppersmith。

## PoC

```python
import math
from Crypto.Util.number import long_to_bytes, inverse

n = 143504495074135116523479572513193257538457891976052298438652079929596651523432364937341930982173023552175436173885654930971376970322922498317976493562072926136659852344920009858340197366796444840464302446464493305526983923226244799894266646253468068881999233902997176323684443197642773123213917372573050601477

c = 141699518880360825234198786612952695897842876092920232629929387949988050288276438446103693342179727296549008517932766734449401585097483656759727472217476111942285691988125304733806468920104615795505322633807031565453083413471250166739315942515829249512300243607424590170257225854237018813544527796454663165076

dl = 1761714636451980705225596515441824697034096304822566643697981898035887055658807020442662924585355268098963915429014997296853529408546333631721472245329506038801
e = 65537
m_bits = 530
shift = 1 << m_bits

for k in range(1, e):
    d_approx = (k * n + 1) // e
    diff = d_approx - dl
    if diff < 0:
        continue
    candidate_high = diff // shift
    for d_high in range(max(0, candidate_high - 10), candidate_high + 11):
        d = dl + d_high * shift
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n + 1 - phi
        delta = s * s - 4 * n
        if delta < 0:
            continue
        root = math.isqrt(delta)
        if root * root != delta:
            continue
        p = (s + root) // 2
        q = (s - root) // 2
        if p * q != n:
            continue
        d_real = inverse(e, phi)
        print(long_to_bytes(pow(c, d_real, n)).decode())
        raise SystemExit

print("not found")
```

说明：原文脚本对每个 `k` 只枚举 `candidate_high ± 10`，在 1024 位 `n`/`e=65537` 下成功恢复；如果目标参数不同，窗口大小需按误差上界调整。PoC 未在本机执行。

## 变体与关联

- 变体：已知 `d` 的高位时，不能用本方法（`d = high·2^k + low` 的低位未知），应使用 Coppersmith/格方法或枚举 `k` 后解 `p` 的低位，见关联卡。
- 变体：`e` 较大时，`k` 的范围可能不是 `1..e−1` 的可枚举规模；可先用 `d ≈ k·n/e` 约束 `k` 的范围或改用部分密钥暴露的格攻击。
- 变体：若同时知道 `d` 的低位和部分 `p`/`q` 信息，可把多个同余条件合并，缩小 `k`/`d_high` 搜索。
- 变体：多素数 RSA 的 `φ` 形式不同，需按 `φ(n)=∏(p_i−1)` 重写 `s`/判别式。
- 关联：[[crypto-rsa-private-exponent-low-bits-partial-p]]（同为 d 低位泄露，但用 solve_mod + Coppersmith 恢复 p）、[[crypto-rsa-d-leak-factor-n-reuse-modulus-new-e]]（完整 d 泄露 + 同模数新 e）、[[crypto-rsa-boneh-durfee-small-private-exponent]]（小 d 的格攻击）。
- 边界：`m` 太小/误差超过窗口、`e` 太大无法枚举、`dl` 并非真正的低位、`d` 不是标准 RSA 私钥指数时，本方法失败或需要换算法。

## 检测与防御

- 防御：私钥 `d` 的任何连续位（尤其是低位）都不得出现在日志、错误信息、调试输出、侧信道或序列化结构中；不要在密钥生成/加载代码里截断打印 `d`。
- 防御：使用 HSM/TPM 保存私钥，启用 RSA blinding 与常量时间实现，降低侧信道泄露；密钥损坏后不要继续使用或部分恢复。
- 检测：审计日志/接口中是否出现 `d & ((1<<m)−1)`、`dl`、`d_low` 等字段；CTF 中看到“已知 d 的低 530 位”即可按本卡尝试。
- 响应：确认私钥部分泄露后视为密钥失陷，立即吊销并轮换模数与密钥，评估历史密文是否已被解密。
