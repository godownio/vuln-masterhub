---
id: ctf-crypto-aes-gcm-tag-fault-mt19937-linear-recovery
title: AES-GCM tag 低 64 位被 GHASH^MT19937 污染：线性方程恢复 H 与种子
type: scenario
domain: ctf
path: ctf/crypto
technique: gcm-tag-fault-mt-linear-recovery
aliases:
- manytags
- GCM tag 污染
- GHASH 线性方程
- MT19937 种子恢复
- fault tag
tags:
- ctf
- crypto
- aes-gcm
- ghash
- mt19937
- linear-algebra
- seed-recovery
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:11:18+08:00'
  notes: 已对照原文 manytags 段核对：construct_tag 高 64 位保留/低 64 位 GHASH^fault、单块 GHASH=C·H^2⊕L·H、624 次查询 39936 方程/20096 未知量、H=8652aad2... 与 key=f7459e92... 均与原文一致；线性系统求解未本机复现。
---

## 一句话结论

当服务返回的 GCM tag 高 64 位保留真实值、低 64 位被替换为 `low64(GHASH(H,C)) ^ r`，且 `r` 来自以 master_key 为种子的 MT19937 时，单块 GHASH 对 H 是 GF(2) 线性的；收集 624 次以上查询可建立约 4 万条线性方程，解出 H 与 MT 状态，再 untemper/逆向种子得到 master_key，最后解密 flag。

## 原理

- 单块密文、空 AAD 时 `GHASH(H,C) = C·H^2 ⊕ L·H`；GF(2) 上 `H -> H^2` 是线性的，因此整个表达式对 H 的 128 个 bit 线性。
- 返回 tag 的低 64 位是 `low64(GHASH(H,C)) ⊕ r`，其中 `r = (rng.getrandbits(32) << 32) | rng.getrandbits(32)`，`rng = random.Random(int.from_bytes(master_key, "big"))`。
- MT19937 的每次输出对其 624 个 32-bit 内部状态字也是线性的；因此每条查询的低 64 位给出 64 条关于“H 的 128 bit + MT 状态的 19968 bit”的 GF(2) 线性方程。
- 624 次查询产生 39936 条方程，未知量 20096 个，方程数足够；解线性系统可同时恢复 H 和这 624 次查询对应的 1248 个 32-bit MT 输出。
- 对 624 个 32-bit 输出做 `untemper` 恢复 MT 内部状态；再逆向 twist 与 Python `random.seed(int)` 的大整数 `init_by_array` 初始化，取回 256-bit 种子，即 master_key。
- flag 本身是正常 AES-GCM 加密，未污染；拿到 master_key 后直接 `AESGCM(key).decrypt(nonce, ciphertext+tag, None)`。

## 触发条件

- 服务泄露 `flag_nonce`、`flag_ciphertext`、`flag_tag`，并提供有限次（≥624）的查询接口。
- 每次查询返回随机 nonce、随机单块密文、被污染的 tag（高 64 位真实、低 64 位 GHASH^PRNG）。
- PRNG 以 master_key 为种子，且每次查询消耗固定数量的 32-bit 输出。
- 查询预算 ≥ MT19937 状态字数（624），本例为 704。

## 利用步骤

1. 收集 624+ 次查询的 `(nonce, ciphertext, tag)`，取 tag 低 64 位。
2. 对每次查询构造 GHASH 关于 H 的线性表达式（单块：`C·H^2 ⊕ L·H`），与 MT 输出的线性表达式联立。
3. 建立 GF(2) 线性方程组（约 39936×20096），高斯消元求解。
4. 从解中取 H 与 1248 个 32-bit MT 输出；untemper 恢复 624 字状态。
5. 逆向 twist 与 `random.seed(int)` 的初始化，恢复 master_key。
6. 用 master_key 对 flag 的 nonce/ciphertext/tag 做 AES-GCM 解密。

## PoC

```text
# 文章给出的恢复结果（用于校验）
H   = 8652aad2987cb769df7357dccf7d2d97
key = f7459e92e4e56bb1c1b6a93a8d6629516ec756057ec291f83b5ffda10410ae5a
# 解密
AESGCM(key).decrypt(flag_nonce, flag_ciphertext + flag_tag, None)
```

## 变体与关联

- 污染位可换成高 64 位或任意线性组合；只要方程仍对 H/状态线性即可。
- PRNG 可换成 LFSR、xorshift 等其他线性生成器；恢复方法相应变化。
- 关联：[[ctf-crypto-aes-gcm-nonce-reuse-ghash-subkey-root]]（GCM 子密钥恢复）、[[crypto-prng-mt19937-untemper-state-recovery-predict]]（MT untemper）、[[crypto-prng-mt19937-seed-recovery-lfsr-noise-batch-alignment]]（种子恢复）。

## 检测与防御

- 不要用密钥派生/种子化 PRNG 生成认证标签中的掩码；使用 CSPRNG。
- 不要返回被“故障注入”的 tag；GCM 标签必须完整校验。
- 检测：同一密钥下大量查询、tag 低 64 位分布异常、查询次数接近 MT19937 状态长度。
