---
id: crypto-protocol-dh-private-key-partial-bits-mitm-table
title: Diffie-Hellman 私钥含少量未知比特：两半枚举建表中间相遇恢复共享密钥
type: scenario
domain: crypto
path: crypto/protocol
technique: dh-private-key-partial-bits-mitm-recovery
tags:
- crypto
- diffie-hellman
- mitm
- partial-key
- meet-in-the-middle
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W2
  verified_at: '2026-11-08T12:28:34+08:00'
  notes: 已对照原文核对：p 1024bit、g 1020bit、bob_secret=getPrime(1020) 但内存 dump 里约 44 位被 ? 遮住（已实测原文模板 1033 字符含 44 个 ?）、AES key=SHA256(long_to_bytes(pow(alice_pub,bob_secret,p)))，exp 先按 idx 记录 ? 位置再二等分、g^{-aa}*y 建表 + g^{bb} 查表、用 ictf 前缀判定命中；卡片按原文写法修正了 PoC 的 idx 反转/idx.append(-1) 哨兵/两半拼接细节（原文 idx 反转后 append(-1) 并据此按 2^(idx+1) 累加前缀基数），未设 affected_versions；未复跑（2^22 建表需较大内存，本机未执行）
url: /docs/crypto/protocol/crypto-protocol-dh-private-key-partial-bits-mitm-table/
draft: false
kb_aliases:
- Cold Case
- DH 私钥部分比特
- g^a 建表 中间相遇
- 哈希表匹配 DH 私钥
- 共享密钥恢复
---

## 一句话结论

Diffie-Hellman 的私钥 `a` 只剩约 44 个比特不确定（内存 dump 里被 `?` 遮住）时，不必做 2^44 全枚举：把 `a` 拆成两半各 22 bit，先枚举前半算出 `g^{-a_left}·y mod p` 建哈希表，再枚举后半算 `g^{a_right} mod p` 查表，2×2^22（约 840 万次模幂）即可恢复完整私钥，再算共享密钥解 AES。

## 原理

- **DH 会话密钥的可分解性**：`y = g^a mod p`，`K = g^{ab} mod p`，`AES key = SHA256(long_to_bytes(K))`。恢复 `a` 就等价于恢复 `K`。
- **未知比特的结构**：给定 `a` 的二进制模板（`?` 表示未知位），把未知位按位置分成左、右两组，则 `a = a_left + a_right`，其中 `a_left` 是高位未知位贡献、`a_right` 是低位未知位贡献，且两者数值可通过已知段偏移拼出。
- **中间相遇**：`y = g^{a_left}·g^{a_right} mod p`，因此 `g^{-a_left}·y = g^{a_right} mod p`。枚举 `a_left` 的所有取值（2^22）算出左边并存进字典；再枚举 `a_right` 的所有取值（2^22）算右边，命中字典即得两半。
- **为什么比全枚举快**：全枚举是 `2^44 ≈ 1.7e13` 次模幂，中间相遇是 `2·2^22 ≈ 8.4e6` 次，加速约 `2^21` 倍，用时从不可行降到 tqdm 可见的范围。
- **为什么拆成两半要按“位”而非按“段”**：`?` 在模板里是散落的，按位置索引分组（原文先记录每个 `?` 的位下标，再二等分下标列表）才能保证左右两半的数值各自只需枚举自己那段未知位；按字符串 `split('?')` 分段也能拼出同样的数值，只要下标与倍率对齐。
- **哈希用 `SHA256(long_to_bytes(K))`**：`K` 是整数，`long_to_bytes` 的长度随数值变化，但比对时是把 `K` 同一路径再算一遍，所以只要 `a` 正确，`AES key` 必然一致。

## 触发条件

- 拿到 DH 参数 `p`、`g`，以及某一方的公钥 `y = g^a mod p`（或能算出共享密钥的对端关系）。
- 私钥 `a` 的二进制模板已知，未知位数足够小：两半各 ≤ 24 bit（哈希表 2^24 条约 1~2 GB 内存、可行）时稳；44 bit 是舒适区。
- 有密文（AES-ECB 等）可做最终验证，或能拿到 flag 前缀用于判定。
- 目标 `p` 约 1024 bit，单次模幂用 `pow` 或 `gmpy2.powmod` 都在微秒~毫秒级。

## 利用步骤

1. 从内存 dump / 抓包中取 `p`、`g`、`y`（被扫描方公钥）与另一方的公钥。
2. 把 `a` 的模板字符串（含 `?`）记录下来，统计未知位数 `n_unknown`。
3. 反转字符串按下标记录每处 `?` 的位置，把下标列表二等分；同时对已知段按 `2^(idx+1)` 累加得到两半的固定基数。
4. 建表阶段：枚举前半未知位（`product('01', repeat=n_unknown//2)`），`aa = base_left + bits`，算 `y * inverse(g^aa, p) mod p`，存 `table[value] = bits`。
5. 查表阶段：枚举后半，`bb = base_right + bits`，算 `g^bb mod p`，命中 `table` 即拼出完整 `a`（用所有 `?` 位置的下标还原）。
6. 用 `a` 算 `K = pow(y_peer, a, p)`（或 `pow(g, a*b, p)`），`SHA256(long_to_bytes(K))` 得 AES key，解密密文并用 flag 开头（如 `ictf`）判定命中。

## PoC

```python
from itertools import product
from Crypto.Util.number import inverse, long_to_bytes
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from gmpy2 import powmod

p, g, y, AES_data, tmp = ...   # tmp 是含 '?' 的私钥模板（'?' 表示未知位）

# '?' 在二进制表示里的下标（tmp[::-1] 的第 i 位 = 权重 2^i）
idx = [i for i, ch in enumerate(tmp[::-1]) if ch == '?']
idx = idx[::-1]            # 反转后下标与“高位在前”的分段顺序对齐（原文写法）
idx.append(-1)             # 末段权重 2^0 的哨兵，缺它 idx2 会越界
unknown = tmp.count('?')
idx1, idx2 = idx[:len(idx) // 2], idx[len(idx) // 2:]
parts = tmp.split('?')
p1, p2 = parts[:len(parts) // 2], parts[len(parts) // 2:]

base_left = sum(int(p1[i], 2) * 2 ** (idx1[i] + 1) for i in range(len(p1)) if p1[i])
base_right = sum(int(p2[i], 2) * 2 ** (idx2[i] + 1) for i in range(len(p2)) if p2[i])

table = {}
for bits in product('01', repeat=unknown // 2):
    aa = base_left + sum(int(bits[k]) * 2 ** idx1[k] for k in range(len(bits)))
    table[y * inverse(powmod(g, aa, p), p) % p] = bits

for bits in product('01', repeat=unknown - unknown // 2):
    bb = base_right + sum(int(bits[k]) * 2 ** idx2[k] for k in range(len(bits)))
    if powmod(g, bb, p) in table:
        left = table[powmod(g, bb, p)]
        full = list(left) + list(bits)          # 两半按原顺序拼接
        secret = sum(int(parts[i], 2) * 2 ** (idx[i] + 1) for i in range(len(parts)) if parts[i])
        secret += sum(int(full[k]) * 2 ** idx[k] for k in range(unknown))
        K = powmod(y, secret, p)                # y 为对端公钥，等价于 g^(ab)
        key = SHA256.new(long_to_bytes(K)).digest()
        flag = AES.new(key, AES.MODE_ECB).decrypt(AES_data)
        if b'ictf' in flag:
            print(secret, flag)
            break
```

## 变体与关联

- 变体：未知位分布在两端（如私钥只缺高位一段）时，中间相遇退化为“枚举高位 + 用 `g^{-a}·y` 检查剩余”，实现更简单。
- 变体：若 `a` 是很小的数（`g^a` 未模约减）则直接整数开方/离散对数小范围搜索即可，无需建表。
- 变体：`p` 只有 64~80 bit 时可直接跑 Pollard rho / BSGS 求完整离散对数，不必利用部分比特。
- 关联：[[crypto-ecc-ecdh-small-nonce-brute-shared-point-key]]（ECDH 侧的小 nonce 枚举）、[[crypto-prng-truncated-lcg-coppersmith-lattice-cvp]]（另一类“部分比特已知”的格方法）。

## 检测与防御

- 防御：私钥不得以任何形式落入可读内存镜像、core dump、swap 或日志；对长期私钥使用 HSM/TEE 或至少 `mlock`/`MADV_DONTDUMP` 并保证退出时清零（见 [[crypto-implementation-madv-dontdump-mlock-key-pages]]、[[crypto-implementation-memset-dead-store-elimination-key-wipe]]）。
- 防御：DH 私钥长度要足够（≥ 256 bit 随机），不要用带固定结构的模板生成私钥；`p` 必须是安全素数，避免小子群攻击。
- 检测：进程内存出现明文私钥比特、`gmpy2.powmod` 高频调用、CPU 长时间单核满载（枚举建表的典型特征）。
- 响应：私钥可能泄露的会话一律视为已解密，轮换长期密钥并更换 `g`/`p` 参数。
