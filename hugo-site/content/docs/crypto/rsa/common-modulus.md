---
id: crypto-rsa-common-modulus
title: RSA 共模攻击
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-common-modulus
tags:
- crypto
- rsa
- common-modulus
- gcd
cve: []
severity: high
confidence: high
status: draft
created: '2026-11-04'
updated: '2026-11-04'
url: /docs/crypto/rsa/common-modulus/
draft: false
kb_aliases:
- common modulus attack
- 共模攻击
---

## 一句话结论

同一明文用同一模数 `n`、不同互素指数 `e1/e2` 加密两次时，攻击者无需私钥即可通过扩展欧几里得算法恢复明文。

## 原理

已知 `c1 = m^e1 mod n`、`c2 = m^e2 mod n`，且 `gcd(e1,e2)=1`，可求 `a,b` 使 `a*e1 + b*e2 = 1`，于是 `m = c1^a * c2^b mod n`。负指数用模逆处理。

## 触发条件

- 相同模数 `n` 被复用；
- 两个公钥指数互素；
- 攻击者拿到两份密文。

## 利用步骤

1. 确认两份密文使用同一 `n`；
2. 计算 `gcd(e1,e2)`，确认互素；
3. 用扩展欧几里得求 `a,b`；
4. 处理负指数并计算明文。

## PoC

```python
from math import gcd
def egcd(a,b):
    if b == 0: return (a,1,0)
    g,x,y = egcd(b, a % b)
    return (g, y, x - (a//b)*y)
g,a,b = egcd(e1,e2)
m = pow(c1,a,n) * pow(c2,b,n) % n
```

## 变体与关联

- 变体：低指数广播攻击、Related Message 攻击；
- 关联：RSA 填充与实现缺陷。

## 检测与防御

- 检测：证书/公钥复用同一模数；
- 防御：每次生成独立密钥、避免模数复用。
