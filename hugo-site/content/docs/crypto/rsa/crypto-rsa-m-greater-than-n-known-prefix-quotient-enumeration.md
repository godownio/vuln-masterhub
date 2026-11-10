---
id: crypto-rsa-m-greater-than-n-known-prefix-quotient-enumeration
title: RSA 解密值 m>n：用已知 flag 前缀/后缀限定商 k，枚举 n 的倍数恢复真实明文
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-m-greater-than-n-known-prefix-quotient-enumeration
tags:
- crypto
- rsa
- known-plaintext
- prefix
- quotient
- enumeration
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V273
  verified_at: '2026-11-08T01:02:25+08:00'
  notes: 已对照原文 RSA_loss 段核对：newm 字节串转十六进制 58ee1e...8115、p/q、DASCTF{ 前缀与 } 后缀、k 枚举 + 后缀 0x7d 时 +256n 跳跃均一致；用卡内 PoC 实跑得 DASCTF{o0p5_m3ssaGe_to0_b1g_nv93nd0}，与原文一致。
url: /docs/crypto/rsa/crypto-rsa-m-greater-than-n-known-prefix-quotient-enumeration/
draft: false
kb_aliases:
- RSA_loss
- 解密结果大于模数
- m 大于 n
- 商 k 枚举
- RSA 已知前缀枚举
- 明文长度超过模数
---

## 一句话结论

RSA 解密 `pow(c, d, n)` 只能得到 `m mod n`；当明文长度超过模数、即真实 `m > n` 时，返回的只是余数 `r`，真实明文为 `r + k·n`。若已知 flag 前缀（如 `DASCTF{`）和结尾 `}`，可按明文长度算出 `k` 的上下界，逐个枚举候选并做字符集/前后缀校验，即可恢复完整明文。

## 原理

- **RSA 解密的数学语义是模运算**：加密 `c = m^e mod n`，解密 `m' = c^d mod n = m mod n`。当 `m < n` 时 `m'=m`；当 `m ≥ n` 时，`m' = m − k·n`，只保留了余数。许多题直接给出 `newm = pow(c, d, n)`，攻击者拿到的是 `m mod n`，不是明文本身。
- **已知格式给出 k 的边界**：设明文为 `prefix || body || suffix`，body 长度 `l` 未知。最小可能值 `m_min = bytes_to_long(prefix + b"\x00"*l + suffix)`，最大可能值 `m_max = bytes_to_long(prefix + b"\xff"*l + suffix)`。因为 `m = r + k·n`，所以 `k ∈ [m_min // n, m_max // n]`；对每个候选长度 `l` 枚举这个区间即可。
- **校验函数筛选**：flag 字符集通常限制为 `[0-9A-Za-z_{}]`，且必须以前缀开头、以 `}` 结尾。候选 `long_to_bytes(r + k·n)` 只要不满足任一条件就跳过；满足的即真实明文。
- **为什么可行**：`k` 的范围由“明文长度”决定，而明文长度通常只有几十字节；`n` 是 1024/2048 位时，`k` 区间很小（往往几十到几千），枚举成本可忽略。已知前缀越长、长度越确定，区间越窄。
- **低位优化**：若目标明文必须以 `}`（0x7D）结尾，则只有 `m mod 256 == 0x7D` 的候选才可能正确。由于 `n` 为奇数（两个奇素数之积），`m + n` 会改变最低字节；此时可改为 `m + 256·n`、`k += 256`，跳过 255 个不可能命中后缀的候选。注意该优化依赖“后缀必须为 `}`”这一约束，校验时也要显式检查后缀，避免把恰好全字符集合法但结尾不对的候选误判。

## 触发条件

- 明文消息长度大于模数 `n`（例如 flag 较长而 `n` 只有 1024 位以下，或题目把多个块拼在一起加密）。
- 题目/服务端泄露 `c^d mod n` 的结果（如直接给出 `newm`），攻击者不需要私钥也能拿到余数。
- 已知明文格式：固定前缀、固定后缀或字符集；且明文长度在可枚举范围内。
- `n` 已知，`k` 的候选区间足够小（通常成立）。

## 利用步骤

1. 确认拿到的是 `m mod n` 而不是完整明文：若 `long_to_bytes(m)` 长度接近 `n` 的字节长度且内容不可读，怀疑 `m > n`。
2. 记录已知前缀 `prefix`、后缀 `suffix` 和允许字符集；对每个可能的 body 长度 `l`（从 0 到合理上限，如 64）计算 `m_min`、`m_max`。
3. `k_lo = m_min // n`，`k_hi = m_max // n`；从 `k_lo` 开始枚举 `m = r + k·n`。
4. `long_to_bytes(m)`，检查长度、前缀、后缀、字符集；命中即输出。
5. 若区间较大，利用后缀约束做 `k += 256` 跳跃，或按前缀高位做二分/分块；若仍不可行，考虑 Coppersmith 等部分已知明文攻击。
6. 若多个长度 `l` 都可能，按题目提示的长度范围排序尝试；命中后可用 `pow(m, e, n) == c` 复核（若 `c` 是原始密文）。

## PoC

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse

e = 65537
c = 356435791209686635044593929546092486613929446770721636839137
p = 898278915648707936019913202333
q = 814090608763917394723955024893
r = bytes_to_long(bytes.fromhex("58ee1e7988016458f669918068f41f21a7220c9a06c8068115"))  # pow(c, d, n) 的余数

n = p * q
prefix, suffix = b"DASCTF{", b"}"

def recover(r, n, max_len=64):
    for l in range(max_len):
        lo = bytes_to_long(prefix + b"\x00" * l + suffix) // n
        hi = bytes_to_long(prefix + b"\xff" * l + suffix) // n
        k = lo
        m = r + k * n
        while k <= hi:
            b = long_to_bytes(m)
            if (b.startswith(prefix) and b.endswith(suffix)
                    and all(chr(x) in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_{}" for x in b)):
                return b, k
            # 后缀必须为 0x7d 时，+n 会改变低字节，+256*n 才能保持
            if m % 256 == ord("}"):
                m += 256 * n
                k += 256
            else:
                m += n
                k += 1
    return None, None

flag, k = recover(r, n)
print(flag, k)
```

```text
# 输出：
# b'DASCTF{o0p5_m3ssaGe_to0_b1g_nv93nd0}'
```

## 变体与关联

- **已知前缀/后缀变体**：只知前缀时，用 `m_max` 估计长度上界；只知后缀/字符集时，用全字符集约束筛选；多个候选格式逐一尝试。
- **长度未知变体**：若 `l` 范围很大，`k` 区间随之增大；可按 `k` 的分块并行、用前缀高位二分缩小，或转成“部分已知明文”的 Coppersmith 问题。
- **加密方变体**：若加密方先 `m^e mod n`，再泄露 `d` 或 `c^d mod n`，同样只剩余数；若泄露的是完整 `m^e`（未取模），则直接开 e 次根。
- **关联卡片**：[[crypto-rsa-small-message-polynomial-root]]（小明文/多项式结构恢复）、[[crypto-rsa-e3-known-prefix-suffix-coppersmith]]（已知前后缀的 Coppersmith）、[[ctf-crypto-rsa-unknown-e-rail-fence-filter]]（未知 e + 明文字符集筛选）。
- **边界**：若明文长度不可估计、`k` 区间极大且无结构，枚举不可行；若前缀/后缀未知且字符集宽松，可能产生大量候选，需要额外约束（如哈希校验、重复加密比对）。

## 检测与防御

- **实现视角**：RSA 加密前应确认 `m < n`；长消息使用混合加密（随机对称密钥 + KEM），不要把超过模数的数据直接 `pow`；解密方不应把 `m mod n` 当作明文返回或泄露。
- **CTF/审计视角**：看到 `pow(c,d,n)` 结果长度接近模数、内容不可读时，优先怀疑 `m > n`；检查题目是否给前缀/后缀/字符集，构造 `k` 枚举。
- **检测信号**：RSA 密文对应的模数过小；服务端返回的“解密结果”长度异常；同一明文分段加密/拼接；flag 格式已知且长度超过 `n` 的字节长度。
