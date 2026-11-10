---
id: crypto-rsa-small-message-unknown-exponent-plus-n-root-brute
title: 只给 c 与 n 的小明文攻击：对候选指数 e 与 k∈[0,10) 枚举 c+k·n 的完全 e 次方根
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-small-message-unknown-e-k-n-enumeration-integer-root
aliases:
- 小明文攻击
- 未知 e 的爆破解密
- iroot(c+i*n, e) 枚举
- c + k*n 开方
tags:
- crypto
- rsa
- small-message
- integer-root
- unknown-exponent
- brute-force
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:13:41+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。原文 2.7 节小明文攻击代码为 e 从 2 起按 nextprime 递增、i<10 枚举 iroot(c+i*n, e) 命中完全根后 unhexlify，卡片 PoC 与之一致；原文该段说明文字部分被截断，卡片依可见代码归纳。未复算。
---

## 一句话结论

题目只给出密文 `c` 和模数 `n`（连 `e` 都没有）时，如果明文是一个很短的小整数，那么 `c = m^e mod n` 里可能只发生了很少次模约减；对候选指数 `e`（从 2 起的素数序列）枚举 `k = 0..9` 逐个计算 `c + k·n` 的整数 `e` 次根，命中完全 `e` 次方的那个就是 `m`，随后十六进制转字节即得明文。

## 原理

- **明文短则约减少**：若 `m^e < n`，`c` 就是精确整数幂，直接开根即可；明文稍大时 `c = m^e - k·n`，于是 `m^e = c + k·n` 对小整数 `k` 成立，枚举 `k` 就能把「模运算后的密文」还回「精确整数幂」。
- **指数未知也能枚举**：`e` 通常不大且常取素数，用 `sympy.nextprime` 从 2 递增遍历（2、3、5、7、11…）即可覆盖；每命中一次完全根就停。
- **为什么 `k` 范围很小**：`k ≈ m^e / n`，当 `m` 只有几字节、`e` 是两位数以内、`n` 是 1024 位时 `k` 往往为 0 或个位数；`k` 上限取 10 已覆盖多数出的题，必要时可放大。
- **判定标准是「完全根」**：`gmpy2.iroot(x, e)` 返回 `(root, is_exact)`，只有 `is_exact` 为真才是整数解；再用 `binascii.unhexlify(hex(m)[2:])` 或 `long_to_bytes` 转字节，按可打印性/格式筛选，避免把巧合的完全根误判为答案。
- **与低指数攻击的关系**：这是低指数攻击的「双未知」推广——指数未知、模约减次数也未知，靠穷举两者的笛卡尔积把搜索空间压到可接受范围。

## 触发条件

- 只有 `c` 与 `n`，缺 `e`（或 `e` 只知范围）。
- 明文 `m` 很短（几字节到十几字节），使 `m^e / n` 的商很小。
- `n` 无法分解或无需分解（本链不依赖分解）。

## 利用步骤

1. 确认输入只有 `c`、`n`，且 `c < n`、明文预期很短（常见于只给 `flag = <大整数>` 与 `n` 的题）。
2. 从 `e = 2` 开始按素数递增；对每个 `e`，在 `k = 0..9` 内计算 `gmpy2.iroot(c + k*n, e)`。
3. 命中 `is_exact == True` 时记录 `(e, k, root)`，转字节并检查是否为可打印字符串/符合 flag 格式。
4. 若有多个候选，优先选字节串语义合理的那个；必要时扩大 `k` 上限或扩展 `e` 的上界（如到 2^10）。

## PoC

```python
from gmpy2 import iroot
import sympy, binascii

c = 0x...   # 密文
n = 0x...   # 模数

def small_m_atk(c, n):
    e = 2
    while e < 2 ** 10:
        for k in range(10):
            root, exact = iroot(c + k * n, e)
            if exact:
                print("hit", e, k)
                return int(root)
        e = sympy.nextprime(e)

m = small_m_atk(c, n)
print(binascii.unhexlify(hex(m)[2:]))
```

## 变体与关联

- **已知 `e` 且很小**：直接判断 `m^e < n` 后开根，见 [[crypto-rsa-e3-small-plaintext-integer-cube-root]]。
- **未知 `e` 的另一路线**：小范围暴力解密 + 明文字符集筛选 + 栅栏还原，见 [[ctf-crypto-rsa-unknown-e-rail-fence-filter]]。
- **小明文 + 多项式**：`c = m^3 + a2m^2 + a1m + a0` 时改用高精度求根/爆破，见 [[crypto-rsa-small-message-polynomial-root]]。
- **多个模数下同一小明文**：改用 CRT 广播攻击，见 [[ctf-crypto-rsa-hastad-broadcast-e3-crt]]。

## 检测与防御

- **检测（红队视角的启发）**：只要发现系统接受无填充 RSA 且明文长度可控，就应测试低指数/小明文路径；对只暴露 `(n, c)` 的接口尤其注意。
- **防御**：使用带随机填充的标准方案（OAEP/PKCS#1 v1.5），保证 `m` 与 `n` 同量级，使 `m^e mod n` 必然发生约减；`e` 取 65537；禁止对外暴露裸 `(n, c)` 结构。
