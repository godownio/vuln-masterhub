---
id: crypto-rsa-high-bits-insufficient-brute-epsilon-tuning
title: Coppersmith p 高位攻击不满足界：按 unknown/p_bits≈0.44 判界，爆破邻近 8-10 位并下调 epsilon=0.015 强行求解
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-high-bits-insufficient-brute-force-epsilon-tuning
aliases:
- Coppersmith 高位不够
- small_roots 调参
- epsilon=0.015
- p 高位爆破
- 0.44 比值
- beta=0.4
- 高位攻击不达标
tags:
- rsa
- coppersmith
- small-roots
- partial-key
- lattice
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V531
  verified_at: '2026-11-11T17:09:16+08:00'
  notes: 已对照原文与图03-06核对：第一例256bit p已知136位/未知120位比值0.46875，需144位已知(0.4375)故爆破8位；第二例HGAME 1024bit N、p已知259位、未知253位、253/512=0.494需降到225/512=0.439；本地复算leak=7245...116为259位且leak<<10等于文中常量0x1907927e...f7000(269位)，kbits=512-269=243，截图p_root=12899...903为237位，与X=2^243和epsilon=0.015流程一致；图06显示解出flag b'now_you_know_how_to_use_coppersmith'。修正PoC循环为原文range(800,1,-1)并更正步骤2候选表述。dedup候选(prime-bit-chunks/crt-multi-modulus/multiprime)均related/new非同链；dup-scan无pair。原文无版本。
---

## 一句话结论

已知 `p` 的高位但未知低位比例超过经验阈值（约 `p_unknown_bits / p_bits > 0.44`）时，默认参数 `small_roots` 会返回空；可先爆破已知高位紧邻的 8–10 位（把已知高位延长、未知低位缩短），再用 `small_roots(X=2^kbits, beta=0.4, epsilon=0.015)` 逐候选求根，原文用该法解出 512-bit p 只差 253 位未知的 HGAME 题。

## 原理

- 一元 Coppersmith 的界：`f(x) = p_high + x` 在 `Zmod(n)` 上有小根 `x = p - p_high`；NTL 的 `small_roots` 返回 `|x| < X` 的根，`X` 默认取 `ceil(1/2·N^{β²/δ-ε})`。当 `p ≈ N^{1/2}`、`δ=1`、`β=0.4` 时，理论界约 `N^{0.16}`；未知位数超过界就不返回根。
- 经验比值：原文总结 `p_unknown_bits / p_bits ≤ 0.44` 时（`beta=0.4`）可直接尝试；超过则需先缩短未知区间。
- 缩短未知区间的两种手段：
  1. **爆破**：在已知高位之后、未知低位之前猜若干位（等价于把 `p_high` 右移 `g` 位后再左移并加上候选 `i`），未知低位长度减少 `g`；
  2. **调小 `epsilon`**：`epsilon` 越小，格维数/插值多项式次数越大，可行界越宽，但计算越慢。原文在爆破 10 位后把 `epsilon` 设为 `0.015`（默认 `β/8=0.05`），成功解出 243 位未知低位。
- 为什么能成功：爆破把真实 `p` 固定到某个候选的“已知高位”上，剩余未知量是连续低位，仍是一元小根；`epsilon` 调小使 LLL 构造的界覆盖该长度。失败时 `roots` 为空，循环继续下一个候选；一旦 `p*q==n` 即命中。
- 注意 `leak_p` 的低位补零必须与位移位数严格对应；`kbits = pbits - leak_p.nbits()` 动态计算，避免手工算错。

## 触发条件

- RSA 泄露 `p` 的连续高位，但未知低位位数超过 `beta`/`epsilon` 默认能处理的范围（如 512-bit p 未知 253 位）；
- 未知低位紧接在已知高位之后，且可承受 `2^8–2^12` 级别的爆破；
- 能运行 Sage 的 `small_roots`（NTL 实现），可接受单次 LLL 数分钟级耗时。

## 利用步骤

1. 由 `leak_p = p >> k` 还原已知高位，计算 `p_bits`、`p_unknown_bits` 与比值，判断是否超过 ~0.44；
2. 选择爆破位数 `g`（原文 10 位，循环 `i=800..2` 共 799 个候选），把 `leak_p` 左移 `g` 位得到延长后的已知高位；
3. 对每个候选 `i`：`leak_i = (leak_p << g) + i`，`kbits = pbits - leak_i.nbits()`，`p_high = leak_i << kbits`；
4. 构造 `f = p_high + x`，调用 `f.small_roots(X=2^kbits, beta=0.4, epsilon=0.015)`；
5. 若返回根，`p = p_high + root[0]`，验证 `p*q == n`；
6. 恢复 `d = e^{-1} mod φ(n)`，解密密文；若所有候选都失败，增大 `g` 或进一步调小 `epsilon`（如 0.01），并核对位数/位移是否正确。

## PoC

```python
# sage；原文示例：512-bit p，leak=p>>253
pbits = 512
base = leak << 10                      # 先猜 p 高位之后紧邻的 10 位
for i in range(800, 1, -1):            # 原文循环范围 800..2，也可扩到 2^10
    leak_p = base + int(hex(i), 16)
    kbits = pbits - leak_p.nbits()
    p_high = leak_p << kbits
    PR.<x> = PolynomialRing(Zmod(n))
    f = p_high + x
    roots = f.small_roots(X=2^kbits, beta=0.4, epsilon=0.015)
    if roots:
        p = p_high + int(roots[0])
        q = n // int(p)
        if p * q == n:
            d = inverse(e, (p - 1) * (q - 1))
            print(long_to_bytes(int(pow(c, d, n))))
            break
```

## 变体与关联

- 爆破位置可以放在已知高位与未知低位之间（延长已知段），也可以先固定低位若干位再用 `X=2^{k-g}`；关键是让剩余未知量连续且小于调参后的界；
- `beta` 与 `epsilon` 可联合调整：`beta` 更接近 0.5 能利用“p 是 n 的大因子”，`epsilon` 更小则格更大；
- 与库内 `crypto-rsa-prime-bit-chunks-multivariate-coppersmith-tiered`（缺一段连续比特的一元档）、`crypto-rsa-crt-multi-modulus-high-bits-coppersmith-low-bits`（高位分片+CRT，epsilon=0.02）互补：本卡专讲“未知位超界时如何用爆破+epsilon 把问题拉回可解范围”；
- 若爆破空间过大（如原文若直接按公式补 28 位需 2^28），应优先调 `epsilon`/增大格维数，或寻找更多泄露比特。

## 检测与防御

- 防御侧：RSA 密钥生成/使用不得泄露素数高位、低位或任何部分比特；实现中避免把 `p` 掩码后的值写入日志、报错或调试接口；
- 使用 2048-bit 以上模数并确保随机填充（OAEP），使部分明文/密钥泄露不直接可行；
- 检测侧：CTF/审计中看到 `p >> k << k`、`p & ((1<<k)-1)`、`leak_p` 等模式即按本卡评估 Coppersmith 可行性。
