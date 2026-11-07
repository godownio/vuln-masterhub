---
id: ctf-crypto-rsa-ciphertext-gcd-factor-leak
title: RSA 密文与模数不互素：gcd(N, c) 直接分解模数并解出 AES key
type: scenario
domain: ctf
path: ctf/crypto
technique: rsa-ciphertext-gcd-factor-leak
tags:
- ctf
- crypto
- rsa
- gcd
- modular-arithmetic
- aes-cbc
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:02:25+08:00'
  notes: 已对照原文 check-little 代码核对：p=gcd(N,c)、e=3、AES-CBC 解密主线一致；未在本地复跑原题附件。
url: /docs/ctf/crypto/ctf-crypto-rsa-ciphertext-gcd-factor-leak/
draft: false
kb_aliases:
- gcd(N,c)
- 密文与模数公约数
- RSA 密文共享因子
- check-little
---

## 一句话结论

当 RSA 明文整数 `m` 恰好是模数 `N` 的某个素因子 `p` 的倍数时，密文 `c = m^e mod N` 也能被 `p` 整除，于是 `gcd(N, c)` 直接返回 `p`；分解 `N` 后按常规私钥指数解密即可恢复 `m`，截取前 16 字节作为 AES key 解开 CBC 密文。

## 原理

- 设 `N = p*q`，`c = m^e mod N`，即存在整数 `k` 使 `c = m^e - k*N`。
- 若 `p | m`，则 `p | m^e`，又 `p | N` 所以 `p | k*N`，两项相减得 `p | c`。因此 `gcd(N, c)` 至少含 `p`；只要 `q` 不也整除 `c`，结果正好是 `p`。
- 分解后 `d = e^{-1} mod (p-1)(q-1)`。即使 `gcd(m, N) != 1`，`c^d mod N` 仍能还原 `m`：模 `p` 一侧 `c ≡ 0`、`m ≡ 0`；模 `q` 一侧 `gcd(m, q)=1`，欧拉定理给出 `c^d ≡ m^(e*d) ≡ m (mod q)`；由中国剩余定理，`m` 是唯一同时满足这两个同余的模 `N`  residue。
- `m` 的字节串前 16 字节被用作 AES key，题目另外给出 IV 与密文，因此分解模数后即可完成整条解密。

## 触发条件

- 题目同时给出 RSA 模数 `N`、密文 `c`（以及已知的 `e`），且明文整数与 `N` 不互素，例如出题人把明文构造成 `p` 的倍数。
- `c < N`，`gcd(N, c)` 非 1。
- 真正需要的秘密（如 AES key）由 `m` 的字节前缀派生，并且已知 AES 的 IV/密文。

## 利用步骤

1. 计算 `p = gcd(N, c)`；若结果为 1，说明明文与模数互素，本方法不适用。
2. `q = N // p`，用 `p*q == N` 确认分解正确。
3. 由 `phi = (p-1)*(q-1)` 求 `d = inverse(e, phi)`。
4. `m = pow(c, d, N)`，`long_to_bytes(m)` 取前 16 字节作为 AES key。
5. 用题目给出的 IV 做 AES-CBC 解密，去 PKCS#7 填充得到 flag。

## PoC

```python
from math import gcd
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

p = gcd(N, c)
assert p not in (1, N)
q = N // p
assert p * q == N

e = 3
d = pow(e, -1, (p - 1) * (q - 1))
m = pow(c, d, N)
aes_key = long_to_bytes(m)[:16]

pt = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(bytes.fromhex(ciphertext_hex))
print(unpad(pt, 16).decode())
```

说明：`N/c/iv/ciphertext_hex` 为题目输入；本卡只保留分解与解密主线，未在本地复跑原题附件。

## 变体与关联

- **批量共享素因子**：多组 `N` 两两 `gcd`，见 [[ctf-crypto-rsa-shared-prime-batch-gcd]]；本卡是“单个模数与密文”的变体。
- **小指数无模约减**：若 `m^e < N`，`c` 就是精确的 `m^e`，直接整数开方即可；不需要 `gcd`。
- **签名/密钥交换**：任何“输出是模数因子倍数”的构造都可能泄漏 `gcd`，可迁移到 RSA 签名、CRT 参数错误等场景。
- 分解后若 `gcd(m,N) != 1` 导致直接欧拉解密异常，可分别模 `p`、`q` 解密再 CRT。

## 检测与防御

- RSA 加密前检查 `gcd(m, N) == 1`，并在生产中使用 OAEP 等带随机化的填充，不要直接对结构化整数做裸 RSA。
- 不要构造与模数因子相关的明文；密钥派生应采用 KDF，而不是直接截取 RSA 明文字节。
- 检测思路：对证书/协议流量中的 `(N, c)` 计算 `gcd(N, c)`，非 1 即为模数泄漏信号。
