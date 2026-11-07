---
id: crypto-rsa-desmedt-odlyzko-signature-forgery
title: Desmedt-Odlyzko 签名伪造：用签名预言机线性组合伪造目标消息的 RSA 签名
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-desmedt-odlyzko-signature-forgery
aliases:
- Desmedt-Odlyzko
- 选定明文签名伪造
- RSA 签名伪造
- 签名预言机
- 乘法同态签名
tags:
- rsa
- signature-forgery
- chosen-message
- signing-oracle
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:10:34+08:00'
  notes: 已对照原文核对：乘法同态 s(m1)s(m2)=s(m1m2)、哈希指数向量线性组合/负指数用模逆、crypto-attacks 的 desmedt_odlyzko.attack 桥接与原文一致；原文只给交互桥接未给核心分解实现，卡片已注明。未验证点：未端到端复跑；原文无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

RSA 签名满足乘法同态：`s(m1)·s(m2) mod n = s(m1·m2 mod n)`。如果攻击者能获得任意消息的签名，就可以选择一组消息，使其哈希值的乘积（或带整数指数的线性组合）等于目标消息哈希，再把对应签名相乘/求逆，伪造出目标消息的合法签名。

## 原理

- 教科书 RSA 签名：`s = H(m)^d mod n`，验证为 `s^e mod n == H(m)`。由于指数运算的乘法性质，`s(m1)·s(m2) ≡ (H(m1)H(m2))^d ≡ s(H(m1)H(m2) mod n) (mod n)`。
- 更一般地，若 `H(m_target) ≡ ∏ H(m_i)^{a_i} (mod n)`（`a_i` 可为负整数），则 `s_target ≡ ∏ s_i^{a_i} (mod n)`，负指数用模逆实现。
- 攻击的核心是找一组“可签名消息”，使其哈希值在模 `n` 下生成目标哈希。常用做法是把哈希值分解到小素数基上，把每个哈希表示成指数向量；用线性代数/LLL 找到整数系数组合，使组合后的指数向量等于目标哈希的指数向量。哈希不光滑时，换一批消息或调整目标，直到找到可解关系。
- 因此该攻击不破坏 RSA 本身，而是利用“签名接口对任意消息开放 + 哈希不是随机预言/没有域分离”这一组合。若签名方案使用 RSA-PSS 或对消息做随机化/域分离，乘法关系不再直接对应到目标哈希，攻击失效。

## 触发条件

- 服务端提供签名预言机，允许攻击者对任意（或大量可控）消息请求签名。
- 签名是教科书式 `H(m)^d mod n` 或等价的无域分离哈希签名，验证只比较 `s^e == H(m)`。
- 目标消息的哈希可以表示为所查询消息哈希的整数系数乘积（模 `n`）；通常要求哈希值对小素数基光滑或能通过格方法找到关系。
- 攻击者能离线计算与服务端一致的哈希函数，并能提交伪造签名。

## 利用步骤

1. 确认签名方案：获取 `n`、`e`，确认验证式为 `pow(s,e,n) == H(m)`，且 `H` 与签名接口一致。
2. 实现 `hash_oracle(m_int)`，必须与服务端逐字节一致（编码、哈希算法、是否截断）。
3. 实现 `sign_oracle(m_int)`，通过菜单/协议获取任意消息的签名。
4. 调用 Desmedt-Odlyzko 攻击实现（如 crypto-attacks 的 `desmedt_odlyzko.attack(hash_oracle, sign_oracle, N, e, target_m)`）：对目标哈希与候选消息哈希做小素数分解/线性组合，求整数系数。
5. 用系数组合签名：正指数直接乘，负指数取模逆后乘，得到 `s_target`。
6. 本地验证 `pow(s_target,e,N) == H(target)`，通过后提交给服务端校验接口。

## PoC

```python
from pwn import *
import hashlib
from Crypto.Util.number import bytes_to_long
from desmedt_odlyzko import attack   # crypto-attacks 项目实现

HOST = '10.0.0.1'
PORT = 1337
N = 0x...
E = 65537
TARGET_MESSAGE = b"Transfer 1000000 to Hacker's Account"

io = remote(HOST, PORT)

def my_hash_oracle(m_int):
    # 必须与服务端一致：编码方式、哈希算法、截断规则
    m_bytes = str(m_int).encode()
    return bytes_to_long(hashlib.sha256(m_bytes).digest())

def my_sign_oracle(m_int):
    io.sendlineafter(b"Choice: ", b"1")
    io.sendlineafter(b"Message (hex): ", hex(m_int)[2:].encode())
    io.recvuntil(b"Signature: ")
    return int(io.recvline().strip(), 16)

target_m_int = bytes_to_long(TARGET_MESSAGE)
forgery = attack(
    hash_oracle=my_hash_oracle,
    sign_oracle=my_sign_oracle,
    N=N,
    e=E,
    target_m=target_m_int,
)
assert pow(forgery, E, N) == my_hash_oracle(target_m_int)

io.sendlineafter(b"Choice: ", b"2")
io.sendlineafter(b"Message: ", TARGET_MESSAGE.hex().encode())
io.sendlineafter(b"Signature: ", hex(forgery)[2:].encode())
print(io.recvall().decode())
```

> 说明：核心的哈希分解/线性组合算法在 `desmedt_odlyzko.attack` 中；原文只提供交互桥接。若攻击过程中光滑界 `B` 过大导致分解困难，需要调整候选消息或目标消息。

## 变体与关联

- 变体：目标哈希不光滑时，可以收集更多消息签名，或用 LLL 在指数向量格中寻找更短的关系。
- 变体：若签名前有固定填充但填充可预测，仍可能构造乘法关系；RSA-PSS 的随机盐会破坏该关系。
- 变体：ElGamal/ECDSA 等签名方案不具备同样的乘法同态，需不同的伪造思路。
- 关联：[[crypto-rsa-bleichenbacher-pkcs1v15-padding-oracle]]（RSA 填充预言机）、[[crypto-rsa-lsb-parity-oracle]]（解密预言机）、[[crypto-rsa-common-modulus]]（同模数下的 RSA 代数关系）。

## 检测与防御

- 防御：使用 RSA-PSS 或带域分离的签名方案，避免教科书式 `H(m)^d`。
- 防御：签名接口不要对任意攻击者可控消息开放；加入认证、速率限制、消息白名单与审计。
- 检测：日志中出现大量签名请求、请求消息呈随机/小素数构造特征、同一账号短时间内获取大量签名。
- 响应：确认签名预言机被滥用后，吊销相关密钥、作废已签发签名，并审计历史签名记录。
