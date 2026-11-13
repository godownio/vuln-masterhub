---
id: ctf-crypto-ecdh-lowbits-bivariate-coppersmith-flatter
title: ECDH 协商点 x/y 低 211 位泄露：曲线方程构造双变量多项式，Coppersmith 求小根恢复完整坐标
type: scenario
domain: ctf
path: ctf/crypto
technique: ecdh-lowbits-bivariate-coppersmith-small-roots
tags:
- ctf
- crypto
- ecc
- ecdh
- coppersmith
- bivariate
- small-roots
- lattice
- flatter
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V483
  verified_at: '2026-11-10T20:58:55+08:00'
  notes: 已对照原文核对：x/y 低 211 位泄露、M=2^211、双变量多项式、Jochemsz-May 构造、flatter m=7/t=1 约 25s 均一致；原文未贴代码未复算；基域约 256 位/未知约 45 位为卡片条件性补充
url: /docs/ctf/crypto/ctf-crypto-ecdh-lowbits-bivariate-coppersmith-flatter/
draft: false
kb_aliases:
- BabyDH 1
- ECDH 坐标低位泄露
- 双变量 Coppersmith
- Jochemsz-May 构造
- flatter 格归约
- 椭圆曲线小根
---

## 一句话结论

ECDH 协商点的 x、y 坐标各自泄露低 211 位（`M=2^211`）时，把完整坐标写成 `X=Mx+x'`、`Y=My+y'`，代入椭圆曲线方程得到双变量多项式 `f(x,y)=(My+y')²−((Mx+x')³+a(Mx+x')+b)`，其未知高比特 `x,y` 只有约 45 位，属于小根；用 Jochemsz-May 类双变量 Coppersmith 构造（flatter 快速格归约，参数 m=7、t=1）即可恢复完整坐标。

## 原理

- **泄露模型**：服务端完成一次 ECDH 后，攻击者作为第三方与 Alice 再次协商，Oracle 返回协商点 x、y 坐标的低 211 位；目标是把该点还原。
- **多项式构造**：设完整坐标为 `X = M·x + x'`、`Y = M·y + y'`，其中 `x',y'` 是已知低 211 位，`x,y` 是未知高位；点必须在曲线上，故 `f(x,y) = (M y + y')² − ((M x + x')³ + a(M x + x') + b) = 0` 在整数上成立（曲线参数 a、b、模数已知）。
- **小根条件**：若曲线基域约 256 位，未知高位只有约 45 位，远小于 M=2^211 的尺度，满足 Coppersmith 小根前提；`|x|,|y| < M`。
- **双变量 Coppersmith**：单元 Coppersmith 处理一个未知数；这里两个未知数需要双变量构造（Jochemsz-May 等），通过选取平移多项式与幂次构造格，LLL/BKZ 约简后从短向量恢复小根。
- **参数与工具**：本题可采用 `m=7、t=1` 的构造，用 flatter（优化的格归约实现）在 1 核 Ubuntu 上约 25s 有概率解出；多试几组随机化参数可提高成功率。

## 触发条件

- 能获得曲线的 a、b、p 与 Alice/Bob 公钥，且能与 Alice 完成一次 ECDH 协商。
- Oracle 泄露协商点 x、y 的低 211 位（或等价的低位比特数）。
- 曲线基域位数与泄露位数之差足够大，使未知高位构成“小根”。
- 有格归约工具（flatter/fpylll）与足够的计算时间。

## 利用步骤

1. 获取曲线参数与公钥，完成与 Alice 的 ECDH，拿到协商点坐标低 211 位 `x',y'`。
2. 构造 `f(x,y)=(M y+y')²−((M x+x')³+a(M x+x')+b)`，确认 `f(x,y)≡0` 且未知量上界小于 M。
3. 按 Jochemsz-May 双变量小根构造生成平移多项式集合与格基（参数 m、t 可调）。
4. 用 flatter 对格基做约简，取短向量转成多项式，求根得到候选 `(x,y)`。
5. 复原 `X=Mx+x'`、`Y=My+y'`，验证点在曲线上并与协商点一致；据此计算共享密钥/还原明文。

## PoC

无完整脚本（原文未贴求解代码）。核心多项式：

```python
M = 1 << 211
# x', y' 为泄露的低位
f = (M*y + yp)**2 - ((M*x + xp)**3 + a*(M*x + xp) + b)
# Jochemsz-May 构造 + flatter, 参数 m=7, t=1
```

## 变体与关联

- 变体：只泄露 x 低位时可用单元 Coppersmith 结合曲线方程消元；泄露高低位组合时可转成 HNP。
- 变体：泄露位数较少/未知量较大时，需要更大格或更多样本，耗时显著上升。
- 关联：ECDH 高位泄露构造 HNP 的案例见 [[crypto-ecc-ecdh-double-high-bit-leak-hnp-bsgs]]；RSA 单变量 Coppersmith 基础见 [[crypto-rsa-partial-plaintext-high-bits-coppersmith]]。
- 边界：双变量 Coppersmith 不是总能保证成功，依赖参数选择与格维数；原文只给参数与工具，未提供完整实现。

## 检测与防御

- 修复：不要向第三方泄露协商点坐标的任何比特；ECDH 使用固定/校验过的公钥，避免把共享点坐标直接返回给不可信方。
- 加固：使用 x-only ECDH（如 X25519）减少坐标泄露面；对 Oracle 做访问限制与速率限制。
- 检测：同一会话被多次协商/探测低位、异常格计算资源消耗（防守侧意义有限）。
