---
id: ctf-crypto-single-byte-seed-recurrence-stream-cipher-bruteforce
title: 单字节种子递推流密码：已知明文前缀爆破 256 个种子
type: scenario
domain: ctf
path: ctf/crypto
technique: single-byte-seed-recurrence-stream-cipher
aliases:
- 单字节种子爆破
- 递推密钥流
- Six Seven
- 已知明文前缀过滤
- 自定义流密码
tags:
- ctf
- crypto
- stream-cipher
- bruteforce
- known-plaintext
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:25:04+08:00'
  notes: 已对照原文 Six Seven 核对：os.urandom(1) 种子、gen 递推、ct=key xor flag、用 DawgCTF{ 前缀遍历 256 种子；gen 公式与密文与原文一致；未实际运行。
---

## 一句话结论

自定义流密码只用 1 字节随机种子初始化密钥流，后续字节由确定性递推 `key[i]=gen(key[i-1])` 生成，再与明文异或；由于种子空间只有 256，攻击者用已知明文前缀 `DawgCTF{` 遍历所有种子、生成密钥流并异或，即可筛出正确明文。

## 原理

- 加密逻辑：`start = os.urandom(1)`，`key[0]=start`，`key[i]=gen(key[i-1])`，`ct = key xor flag`。`gen` 是一个模 255 的非线性递推，但完全确定。
- 密钥流的全部不确定性来自 `key[0]`，只有 256 种可能；给定密文长度，攻击者可以枚举 256 个种子，各自生成同样长度的密钥流并异或，得到 256 个候选明文。
- 题目/协议通常已知明文前缀（如 `DawgCTF{`）或格式约束，用前缀过滤即可唯一确定种子；若没有前缀，可用可打印率、语言模型或文件头特征筛选。
- 该攻击与递推函数的具体形式无关，只要种子空间小且密钥流确定；即使 `gen` 很复杂，256 次枚举仍然可行。
- 变体：种子为 2 字节（65536 次）、种子来自时间戳/进程 ID（可预测）、递推可逆（可由密钥流反推种子）。

## 触发条件

- 加密使用单字节/小空间种子初始化流密码，且种子未与密钥或随机数组合。
- 攻击者已知密文，且知道或能猜测明文前缀/格式。
- 密钥流生成函数完全确定、无外部随机性。
- 加密实现没有使用标准 CSPRNG 或认证加密。

## 利用步骤

1. 从题目代码/二进制中还原 `gen` 函数与密钥流生成顺序。
2. 读取密文 `ct`，确定长度。
3. 对 `start` 从 0 到 255：生成 `key[0..len(ct)-1]`，计算 `pt = ct xor key`。
4. 用已知前缀（如 `DawgCTF{`）过滤候选；若多个候选，增加已知明文或检查可打印率。
5. 输出匹配的明文，提取 flag。

## PoC

```python
from binascii import unhexlify

ct = bytes.fromhex(
    "9f2eadbd998e9ca1aab6bfbba9bf85afa9bf85a9bfb9a8bfaea985b3b485a3b5"
    "afa885a9aea8bfbbb785b9b3aab2bfa8a985ece3b8bcbfebe3eebbbceee9bcea"
    "b9bea7"
)

def gen(start):
    return (((6 * 7) * (start - 6) * 7) + ((start * 6) - 7) * (start ^ 6)) % 255

known = b"DawgCTF{"

for s in range(256):
    key = bytearray([s])
    for i in range(1, len(ct)):
        key.append(gen(key[i - 1]))
    pt = bytes(c ^ k for c, k in zip(ct, key))
    if pt.startswith(known):
        print(pt.decode())
        break
```

## 变体与关联

- 变体：种子为 2 字节或多字节但可枚举；种子来自 `time()`、PID、`rand()` 等可预测源。
- 变体：递推可逆时，可由已知密钥流片段反推种子，而不必枚举。
- 变体：密钥流与明文/位置相关（如 `key[i] = gen(key[i-1], i)`），仍可按种子枚举。
- 关联：[[ctf-crypto-xor-keystream-reuse-known-plaintext]]（密钥流重用）、[[ctf-crypto-lfsr-known-plaintext-state-recovery]]（LFSR 状态恢复）、[[crypto-prng-time-seeded-rand-rc4-auth-forge]]（时间种子）。

## 检测与防御

- 防御：不要用 1 字节种子或可预测值初始化流密码；使用 CSPRNG（`secrets`、`os.urandom`）生成足够长的密钥。
- 防御：使用标准 AEAD（AES-GCM/ChaCha20-Poly1305），并对密文做完整性校验；不要自定义递推流密码。
- 检测：代码中出现 `os.urandom(1)`、单字节种子、`key[i]=gen(key[i-1])`、`ct=key xor flag` 等模式。
- 响应：确认密钥空间过小后，视为加密失效，轮换密钥并重新加密历史数据。
