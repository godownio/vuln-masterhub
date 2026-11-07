---
id: ctf-crypto-self-referential-key-tea-variant
title: 自参考密钥分组密码：先逆可逆混合层取回密钥，再解 TEA 变体
type: scenario
domain: ctf
path: ctf/crypto
technique: self-referential-key-tea-variant
tags:
- ctf
- crypto
- tea
- block-cipher
- self-referential-key
- invertible-mixing
- known-structure
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:44:44+08:00'
  notes: 已对照原文核对；原文自述 flag 未获平台回执，本地明文恢复与往返加密闭合
url: /docs/ctf/crypto/ctf-crypto-self-referential-key-tea-variant/
draft: false
kb_aliases:
- 自参考密钥
- 密钥取自明文
- TEA 变体
- enc2 逆运算
- 分组密码自密钥
---

## 一句话结论

当分组密码把“同一明文块的第 2–5 个字”直接当作密钥时，不需要爆破：先逆向可逆的混合函数 `enc2` 得到后四个字（同时就是密钥），再用它解 TEA 变体 `enc1` 得到前两个字，整块明文即可逐块恢复。

## 原理

- **自参考结构把密钥变成未知明文的一部分**：`key = [flag[i+2] for i in range(4)]`，`e1 = enc1((flag[0], flag[1]), key)`，`e2 = enc2(*key)`。密文同时给出 `e1` 与 `e2`，而 `enc2` 是四个 32 位字上的双射，逆回去就得到密钥本身。
- **enc2 是顺序混合的双射**：`a=((a+b)^c)`、`b=((b-c)^d)`、`c=((c+d)^a)`、`d=((d-a)^b)`，每步都可逆；按相反顺序做逆运算即可恢复输入。
- **TEA 变体只改常数不改结构**：DELTA 从 `0x9E3779B9` 换成 `0x87654321`，两个 8 轮循环的 `sum` 连续累加，等价于 16 轮单循环；解密只需按轮次逆序、`sum` 从 `DELTA*16` 递减，并先解 `v1` 再解 `v0`。
- **为什么成立**：分组密码的安全性依赖密钥保密；这里密钥由明文派生且可逆层独立，攻击者不需要知道密钥就能还原它，等价于密钥公开。
- **验证方式**：把恢复的明文重新走一遍加密，密文必须逐字节一致；TEA 解密顺序写错不会报错，只会得到另一串随机数，往返校验是必需步骤。

## 触发条件

- 加密脚本把同一块明文的部分字直接作为密钥（或密钥可由密文/明文结构直接推出）。
- 混合/置换层是双射，可逆运算明确。
- 分组长度、字序（big-endian）、轮数与常数已知或可从脚本读出。
- 攻击者拿到加密脚本与密文（CTF 附件典型形态）。

## 利用步骤

1. 读脚本确认分块方式（示例 24 字节一块、6 个 big-endian 32 位字）与密钥来源（第 2–5 个字）。
2. 读 `enc2`，按相反顺序写 `dec2`：`d=((d^b)+a)`、`c=((c^a)-d)`、`b=((b^d)+c)`、`a=((a^c)-b)`，每步 `& 0xFFFFFFFF`。
3. 对每行密文的后四个字跑 `dec2`，得到该块后四个明文字，同时作为 `enc1` 的密钥。
4. 用该密钥解 `enc1`（TEA 变体），得到前两个明文字；按同样字序拼接所有块。
5. 用原加密函数对恢复明文重新加密，逐块比对密文；全部一致才确认。

## PoC

```python
MASK = 0xFFFFFFFF
DELTA = 0x87654321

def dec2(v):
    a, b, c, d = v
    d = ((d ^ b) + a) & MASK
    c = ((c ^ a) - d) & MASK
    b = ((b ^ d) + c) & MASK
    a = ((a ^ c) - b) & MASK
    return [a, b, c, d]

def dec1(v, k):
    v0, v1 = v
    s = (DELTA * 16) & MASK
    for _ in range(8):
        v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + s) ^ ((v0 >> 5) + k[3]))) & MASK
        v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + s) ^ ((v1 >> 5) + k[1]))) & MASK
        s = (s - DELTA) & MASK
    for _ in range(8):
        v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + s) ^ ((v0 >> 5) + k[3]))) & MASK
        v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + s) ^ ((v1 >> 5) + k[1]))) & MASK
        s = (s - DELTA) & MASK
    return [v0, v1]

def decrypt_block(e1, e2):
    key = dec2(e2)                 # 后四个字 = 密钥
    return dec1(e1, key) + key     # 前两个字 + 后四个字
```

原文说明：flag 字符串未获得平台回执，但本地明文恢复经三层独立验证、往返加密闭合。

## 变体与关联

- **结构变体**：密钥取明文其他位置、密钥取上一块密文（类 CBC）、密钥由明文哈希派生；先找“密钥是否可由已知量推出”。
- **混合层变体**：加/减/异或/旋转的组合，只要每步双射就可逆；若层不可逆，则退回爆破或中途相遇。
- **算法变体**：TEA/XTEA/XXTEA、自定义 DELTA、轮数拆分；DELTA 改变不影响可解性，轮数与 Feistel 结构才是安全边界。
- **关联卡片**：[[ctf-crypto-rsa-shared-prime-batch-gcd]]（同篇 CTF 的确定性缺陷思路）、[[crypto-implementation-single-round-spn-chosen-plaintext-key-recovery]]（结构缺陷导致密钥恢复）。
- **边界**：若加密脚本不公开、字序/轮数未知，需要先逆向；若混合层或密钥派生含不可逆操作，不能直接解。

## 检测与防御

- **CTF 验证**：恢复后必须用原加密函数往返比对；只看到可打印字符不足以证明正确。
- **真实密码设计**：密钥必须来自独立随机源/KDF，绝不能取自明文或可预测量；使用标准算法与经过审计的实现。
- **检测信号**：代码中出现 `key = plaintext[...]`、`enc(plaintext, plaintext)` 这类自参考结构；密钥派生与加密数据同源。
- **复盘**：把“密钥来源”作为审题第一动作；先确认密钥能否由密文/明文结构推出，再决定是否爆破。
