---
id: ctf-crypto-small-discrete-log-crt-channel-selection
title: 小模数离散对数 + CRT 枚举真通道：从 18 条投影中恢复隐藏整数 x
type: scenario
domain: ctf
path: ctf/crypto
technique: small-modulus-discrete-log-crt-channel-selection
tags:
- ctf
- crypto
- discrete-log
- crt
- channel-selection
- brute-force
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:50:33+08:00'
  notes: 已对照原文 torsion_weave 一节核对：18 条通道/9 真、w≈5 万、逐条暴力 DL 得 x mod w、C(18,9)=48620 组合、CRT、layer-05 KDF 与 flag 前缀筛选、good_indexes=0,6,7,8,9,11,13,14,16 与 x 值均一致。未验证点：PoC 未在本机复跑；CTF 题无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/crypto/ctf-crypto-small-discrete-log-crt-channel-selection/
draft: false
kb_aliases:
- 小模数离散对数
- CRT 通道选择
- 部分正确同余
- torsion_weave
- 中国剩余定理枚举
---

## 一句话结论

当服务端给出 18 条投影 `(m_i,w_i,a_i,b_i)`，其中 9 条真的满足 `b_i=a_i^(x mod w_i) mod m_i`、其余 9 条是随机假投影，且 `w_i` 只有约 5 万时，可以逐条暴力离散对数得到 `x mod w_i`，再枚举 `C(18,9)=48620` 个 9 条组合做 CRT，用解密后明文是否以 `flag{` 开头筛出真组合并恢复 `x`。

## 原理

- **真/假投影**：真通道 `b=a^(x mod w) mod m`，给出 `x` 在模 `w` 下的一个同余式；假通道 `b=a^r`（`r` 随机），与 `x` 无关，解出的同余式是噪声。
- **小模数离散对数**：`w≈50000`，直接枚举 `e=0..w-1` 计算 `a^e mod m` 即可（`O(w)` 每通道），不需要 BSGS/Pollard rho。
- **部分正确同余**：18 条中有 9 条真、9 条假；枚举所有 9 条组合，对每个组合用 CRT 合并同余式。真组合的模数乘积足够大，能唯一确定 `x`；假组合得到的 `x` 通常不能通过明文格式校验。
- **筛选**：用候选 `x` 派生 `key=sha256(b"layer-05:"+str(x))`，HMAC-SHA256 计数器流异或 `box`；若明文以 `flag{`/`FLAG{` 开头，则该组合为真。
- **为什么成立**：CRT 要求模数两两互素（本题 `w` 为不同素数/互素），9 个约 5 万的模数乘积约 2^140，足以覆盖 `x` 的范围；错误组合几乎不可能产生合法 flag 明文。
- **复杂度**：18 次 `O(w)` 离散对数 + 48620 次 CRT + 48620 次 HMAC 解密；可接受。

## 触发条件

- 每条通道的 `w` 较小（可暴力），`a,b,m` 已知；`m`/`w` 满足离散对数可解（`a` 在模 `m` 下的阶为 `w` 或可整除）。
- 真通道数量 `good_count` 已知（本题 9），假通道与 `x` 独立。
- 各 `w_i` 两两互素，CRT 可合并；真组合的模数乘积足够大。
- 有明文格式校验（`flag{`）用于筛组合。

## 利用步骤

1. 读取 `shape=[good_count, ...]` 与 `trace` 的 18 条通道。
2. 对每条通道暴力求 `e` 使 `a^e≡b (mod m)`，得到 `(e, w)`；若暴力范围是 `0..w-1`，注意 `x mod w` 的取值。
3. 枚举 `C(18, good_count)` 个组合；对每个组合用 CRT 合并 `(e_i, w_i)` 得到候选 `x`。
4. 用 `x` 派生密钥解密 `box`，检查明文前缀/可打印性；命中则输出 flag。
5. 本题 `good_indexes=0,6,7,8,9,11,13,14,16`，`x=400318507202697887552674729281844692814892`。
6. 若 CRT 模数不互素，改用广义 CRT/合并同余；若 `x` 有多个候选，增加真通道或明文校验。

## PoC

```python
import hashlib
import hmac
import itertools

def discrete_log_small(a, b, m, order):
    cur = 1
    for exp in range(order):
        if cur == b:
            return exp
        cur = (cur * a) % m
    raise ValueError("no discrete log")

def crt_pair(a1, m1, a2, m2):
    t = ((a2 - a1) % m2) * pow(m1, -1, m2) % m2
    return a1 + m1 * t, m1 * m2

def crt(congruences):
    x, mod = 0, 1
    for residue, modulus in congruences:
        x, mod = crt_pair(x, mod, residue, modulus)
    return x

def stream(key, n):
    out, ctr = b"", 0
    while len(out) < n:
        out += hmac.new(key, ctr.to_bytes(4, "big"), hashlib.sha256).digest()
        ctr += 1
    return out[:n]

residues = [
    (discrete_log_small(ch["a"], ch["b"], ch["m"], ch["w"]), ch["w"])
    for ch in trace
]
good_count = shape[0]
box = bytes.fromhex(box_hex)

for indexes in itertools.combinations(range(len(residues)), good_count):
    x = crt(residues[i] for i in indexes)
    key = hashlib.sha256(b"layer-05:" + str(x).encode()).digest()
    flag = bytes(a ^ b for a, b in zip(box, stream(key, len(box))))
    if flag.startswith((b"flag{", b"FLAG{")):
        print(indexes, x, flag.decode())
        break
```

## 变体与关联

- **变体（真通道数未知）**：枚举 `good_count` 的多个可能值，用明文格式/CRT 一致性筛选。
- **变体（模数不互素）**：用广义 CRT，冲突时丢弃组合；或先分解 `w` 用素数幂合并。
- **变体（离散对数较大）**：`w` 到 2^40 时改用 BSGS/Pollard rho；本题 `w` 小，暴力即可。
- **关联卡片**：[[crypto-ecc-ecdlp-80bit-prime-order-pollard-rho]]（大群离散对数）、[[ctf-crypto-rsa-hastad-broadcast-e3-crt]]（CRT 广播）、[[ctf-crypto-sparse-error-linear-system-nullspace-enumeration]]（部分错误枚举）。
- **边界**：`a` 的阶不等于 `w` 时离散对数可能无解/多解；假通道组合偶尔也可能产生合法前缀，需要二次验证。

## 检测与防御

- **CTF 识别**：看到 18 条 `(m,w,a,b)`、`w` 约 5 万、真通道数已知，优先小模数 DL + CRT 枚举。
- **密码设计**：不要用“多条小模数投影 + 部分正确”构造秘密共享；使用标准门限方案/纠错码。
- **实现**：暴力 DL 注意 `a` 的阶；CRT 前检查模数互素；用明文格式校验避免误判。
