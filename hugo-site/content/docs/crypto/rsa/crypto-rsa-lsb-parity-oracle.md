---
id: crypto-rsa-lsb-parity-oracle
title: RSA LSB 奇偶预言机：乘 2^e 查询 m mod 2 二分恢复明文
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-lsb-oracle
tags:
- rsa
- lsb-oracle
- parity-oracle
- chosen-ciphertext
- padding-oracle
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:10:36+08:00'
  notes: 已对照原文核对：c_i=c·2^{e·i}、返回 m_i mod 2、q_i=floor(2^i·m/n) 的奇偶即 m/n 第 i 位、区间 [0,n] 二分 n.bit_length() 次，与原文脚本一致。原文脚本 with pb = iter_progress(...) 有语法笔误，卡片 PoC 已改为可运行形式。未验证点：PoC 未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
url: /docs/crypto/rsa/crypto-rsa-lsb-parity-oracle/
draft: false
kb_aliases:
- LSB Oracle
- 奇偶预言机
- Parity Oracle
- RSA 最低位泄露
- 二分恢复明文
---

## 一句话结论

如果服务端对任意 RSA 密文返回其解密结果的最低位（奇偶性），攻击者可以反复提交 `c·2^{e·i} mod n`，每次让明文翻倍并观察是否越过 `n`，用二分法在约 `n.bit_length()` 次查询内恢复完整明文。

## 原理

- 设原始密文 `c ≡ m^e (mod n)`。构造 `c_i = c·2^{e·i} mod n`，则其解密结果为 `m_i ≡ m·2^i (mod n)`。
- 服务端只返回 `m_i mod 2`。因为 `n` 是奇数，`m_i = 2^i·m - q_i·n` 的奇偶性等于 `q_i mod 2`，其中 `q_i = floor(2^i·m / n)`。
- `q_i` 的二进制表示正是 `m/n` 的前 `i` 位小数；`q_i mod 2` 就是第 `i` 位。因此每次查询给出明文在 `[0,n)` 区间中的一个二分方向。
- 维护区间 `[L,U]`（初始 `[0,n]`）：若最低位为 0，说明 `2^i·m mod n` 落在当前区间的下半部分，令 `U=(L+U)//2`；否则令 `L=(L+U)//2`。
- 迭代 `n.bit_length()` 次后区间宽度小于 1，`U` 即为明文整数 `m`。
- 该攻击只要求“最低位”这一个比特的泄露；错误信息、调试接口、侧信道都可能提供它。查询次数远少于 Bleichenbacher。

## 触发条件

- 服务端对任意密文解密并返回明文的奇偶性（或可区分奇偶的行为）。
- 攻击者已知 `n`、`e`、`c`，能反复提交任意密文。
- 没有速率限制或查询次数足够（约 1024/2048 次）。
- 明文在 `[0,n)` 内按标准 RSA 表示；若明文有填充，恢复的是填充后的整数，需要再解析。

## 利用步骤

1. 确认 oracle 返回的是 `m mod 2`，并确定其 True/False 与奇偶的对应关系。
2. 预计算 `multiplier = pow(2, e, n)`，避免每次重复计算。
3. 初始化 `L=0`、`U=n`、`cur=c`；循环 `n.bit_length()` 次：
   - `cur = cur * multiplier % n`
   - 查询 `oracle(cur)`；为 0 则 `U=(L+U)//2`，为 1 则 `L=(L+U)//2`。
4. 循环结束返回 `U`，转字节得到明文。
5. 用 `pow(U,e,n)==c` 校验；若失败，检查 oracle 极性、是否每次连接重置状态、是否返回的是字节而非比特。

## PoC

```python
from pwn import *
from sage.all import ZZ
from Crypto.Util.number import long_to_bytes

HOST = 'target.example.com'
PORT = 1337
N = ...
E = 65537
C = ...

def get_oracle(fake_cipher):
    # 按题目协议实现：返回 0 表示明文为偶数，1 表示奇数
    io = remote(HOST, PORT, level='error')
    io.recvuntil(b"Give me cipher: ")
    io.sendline(hex(fake_cipher).encode())
    response = io.recvall()
    io.close()
    return 0 if b"Even" in response else 1

def lsb_oracle_attack(N, e, c, oracle):
    N = ZZ(N)
    left, right = ZZ(0), N
    cur = ZZ(c)
    multiplier = pow(2, e, N)
    for i in range(N.bit_length()):
        cur = (cur * multiplier) % N
        lsb = oracle(cur)
        if lsb == 0:
            right = (left + right) // 2
        else:
            left = (left + right) // 2
    return int(right)

m_int = lsb_oracle_attack(N, E, C, get_oracle)
print(long_to_bytes(m_int))
```

## 变体与关联

- 变体：oracle 返回 `m mod 2^k` 的多个低位时，可一次缩小 `2^k` 倍区间，查询次数大幅减少。
- 变体：oracle 返回“明文是否小于 n/2”而不是奇偶性，等价于最高位泄露，可直接二分。
- 变体：RSA-OAEP 的首字节零检查对应 Manger 攻击；PKCS#1 v1.5 填充合法性对应 Bleichenbacher 攻击。
- 关联：[[crypto-rsa-manger-oaep-first-byte-oracle]]、[[crypto-rsa-bleichenbacher-pkcs1v15-padding-oracle]]、[[crypto-rsa-rabin-random-square-root-oracle]]（其他解密预言机）。

## 检测与防御

- 防御：不要返回明文任何比特或可用于推断比特的行为；解密接口统一返回固定格式、恒定时间。
- 防御：使用 RSA-OAEP 并加入完整性校验，避免对任意密文解密；对解密接口做认证与速率限制。
- 检测：同一来源大量提交不同密文、每次仅改变最低位相关结构、查询次数接近模数位数。
- 响应：确认 LSB 泄露后下线接口、轮换密钥，并审计历史解密请求。
