---
id: ctf-crypto-rsa-structured-prime-class-group-factor
title: RSA 结构化素数 p=(D·V²+1)/4：Jacobi 选判别式后用二次型/类群分解 n
type: scenario
domain: ctf
path: ctf/crypto
technique: rsa-structured-prime-class-group-factorization
tags:
- ctf
- crypto
- rsa
- class-group
- quadratic-forms
- jacobi-symbol
- sage
- structured-prime
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V216
  verified_at: '2026-11-07T04:44:10+08:00'
  notes: 已对照原文 easycry 与图14/16/18核对：D列表[35,51,91,115,123,187,235,267,403,427]、4p=DV²+1、(−D|p)=+1、(−D|q)约半数为−1、(−D|n)=−1、类群/二次型分解思路均一致。PoC与原文Sage代码一致，但原文实际主要调用 n.factor(proof=False) 而未手写类群分解，故 confidence=medium；卡已如实标注。未验证点：未在本机Sage复跑；原文“V 2048位/n 4096位”表述互相不一致，卡按原文保留4096位说法；非组件漏洞无版本；frontmatter无sources/source_url。
url: /docs/ctf/crypto/ctf-crypto-rsa-structured-prime-class-group-factor/
draft: false
kb_aliases:
- easycry
- 类群分解 RSA
- 二次型分解 n
- p=(D V^2+1)/4
- 虚二次域类群
- Cornacchia 算法
---

## 一句话结论

当 RSA 的素数 p 被构造为 `p = (D·V² + 1) / 4` 时，`4p − D·V² = 1` 说明 −D 是模 p 的二次剩余；而随机素数 q 约有 1/2 概率使 (−D|q) = −1。选一个使 (−D|n) = −1 的小判别式 D，n 在虚二次域 Q(√−D) 的类群中会分裂成与 p、q 对应的不同理想类，用二次型/类群运算（或 Sage 的类群分解）即可在多项式时间内求出 p 并分解这个 4096 位模数。

## 原理

- 由 `p = (D·V² + 1)/4` 得 `4p − D·V² = 1`，即 `D·V² ≡ −1 (mod p)`，所以 `(−D|p) = +1`：−D 是模 p 的二次剩余，p 可被二次型 `x² + D·y²`（等价地判别式 −4D 的正定二次型）表示。
- q 是随机素数，与 D 无关，因此 `(−D|q)` 约为 +1 或 −1 各半。若 `(−D|q) = −1`，则 `(−D|n) = (−D|p)·(−D|q) = (+1)·(−1) = −1`。
- 在这种判别式下，`n = p·q` 在虚二次域 Q(√−D) 的理想类群中对应两个不同的理想类：p 相关的是主理想（因为 p 可表示成 x²+Dy²），q 相关的是非主理想。类群运算（或等价的二次型合成/约化）能把这两种结构区分开，从而找出 p 的非平凡因子。
- 直观上，这不是暴力分解 4096 位 n，而是利用 p 的代数结构把分解问题降到与 D 的类数/判别式规模相关的计算；文章用 Sage 的 `QuadraticField`/类群接口配合 `n.factor(proof=False)` 完成，并强调判别式选择正确时 Sage 会尝试类群分解路径。
- 边界：文章给出的 Sage 代码主要依赖 `n.factor(proof=False)`，并未手写完整的类群分解；不同 Sage 版本/算法后端可能失败，因此置信度取 medium。数学原理成立，但复现需要较新的 Sage 或自行实现二次型约化/Cornacchia。

## 触发条件

- RSA 模数 n 的某个素因子 p 满足 `p = (D·V² + 1)/4`，D 来自一个小集合（如 35、51、91、115、123、187、235、267、403、427），V 为大整数。
- q 为随机素数；e 常为 65537，已知 c。
- 能计算 Jacobi/Kronecker 符号 `(−D|n)`，并能使用 Sage 的二次域/类群/二次型工具。
- 有足够时间运行类群运算；判别式不能太大，否则类群计算成本上升。

## 利用步骤

1. 从小集合中筛 D：计算 `kronecker(-D, n)`，保留结果为 −1 的候选（这些 D 对应 p 可表示、q 不可表示的情形）。
2. 对每个候选 D，在 Sage 中构造虚二次域 `K = QuadraticField(-D)` 与其类群 `C = K.class_group()`；利用 p 的主理想表示（二次型 x²+Dy²/Cornacchia）或类群分解例程寻找 n 的非平凡因子。
3. 若使用 Sage 的通用分解，直接 `n.factor(proof=False)`，在正确判别式下可能触发类群/二次型路径；分解成功后验证 `p*q == n`。
4. 得到 p、q 后计算 φ(n)、d，标准 RSA 解密得到 flag。
5. 验证 p 确实满足 `4p = D·V² + 1`（可反推 V² 是否为完全平方），确认攻击路径正确。

## PoC

```python
# Sage 示意：先选判别式，再交给类群/二次型分解
Ds = [35, 51, 91, 115, 123, 187, 235, 267, 403, 427]
cand = [D for D in Ds if kronecker(-D, n) == -1]
print("candidate D:", cand)

for D in cand:
    K = QuadraticField(-D, 'w')
    C = K.class_group()          # 类群
    fac = n.factor(proof=False)  # 判别式合适时 Sage 可走类群/二次型路径
    if len(fac) == 2 and all(m == 1 for _, m in fac):
        p, q = int(fac[0][0]), int(fac[1][0])
        break

phi = (p - 1) * (q - 1)
d = inverse_mod(e, phi)
m = pow(c, d, n)
flag = Integer(m).to_bytes((Integer(m).nbits() + 7) // 8, 'big').lstrip(b'\x00')
print(flag)
```

## 变体与关联

- 变体：其他结构化素数形式 `p = s² + s + 3`（Hasse/模方程恢复）、`p = a·V² + b`、ROCA 指纹素数；可用 ECM、Pollard p−1、Fermat（p、q 接近）等专用分解。
- 变体：若 (−D|n) 全为 +1，可换更多 D 或对 n 做小因子剥离后再试；也可用二次型约化直接求 p 的表示。
- 关联：[[ctf-crypto-structured-prime-squares-plus-s-tonelli-aes-ctr]]（另一种结构化素数恢复）、[[ctf-crypto-rsa-unknown-e-rail-fence-filter]]（e 未知但 n 可分解）、[[ctf-crypto-rsa-noncoprime-common-modulus-iroot-wiener-chain]]（共享素数/小指数/Wiener 组合）。
- 边界：类群分解依赖判别式选择与 Sage 后端；D 集合太小时可能找不到合适判别式；代码未在本机执行，复现需实测。

## 检测与防御

- **检测（CTF）**：看到 `p = (D*V^2+1)/4`、D 来自固定小列表、n 为 4096 位时，先算 `kronecker(-D,n)` 选 D，再用 Sage 类群/二次型分解；不要直接硬跑通用分解。
- **修复（真实设计）**：RSA 素数必须由标准库随机生成，禁止任何 `f(V)` 结构化形式；密钥生成后做素数性/结构检查。
- **加固**：使用 FIPS 186-5/RSA-OAEP 等标准参数；对私钥素数做随机性审计；避免在证书/协议中泄露素数结构或额外关系。
