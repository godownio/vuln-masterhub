---
id: ctf-crypto-ecdh-echnp-multi-lowbit-lattice-flatter
title: ECHNP 椭圆曲线隐藏数问题：多次 x 坐标低位泄露恢复 ECDH 共享密钥（低比特改造 + flatter）
type: scenario
domain: ctf
path: ctf/crypto
technique: ecc-hidden-number-problem-multi-lowbit-lattice
aliases:
- BabyDH 2
- ECHNP
- 椭圆曲线隐藏数问题
- ECDH 低位泄露恢复私钥
- 多次 Oracle 泄露 x 坐标
- 2022 亚密会 ECHNP
tags:
- ctf
- crypto
- ecc
- ecdh
- hnp
- echnp
- lattice
- flatter
- low-bits
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V483
  verified_at: '2026-11-10T20:58:58+08:00'
  notes: 已对照原文核对：多次 Oracle x 低位泄露、ECHNP、2022 亚密会论文、低比特改造、flatter n=5/d=3/t=2 约 18s 均一致；与 BabyDH1 卡（单次 x/y 泄露双变量 Coppersmith）技术路线不同非重复；原文未贴格构造代码未复算
---

## 一句话结论

攻击者可多次与 Alice 做 ECDH，Oracle 每次泄露协商点 x 坐标的低比特时，问题等价于椭圆曲线隐藏数问题（ECHNP）：把每个样本写成“未知私钥 × 已知点 + 小误差”的线性关系，按 2022 年亚密会给出的 ECHNP 格构造求解；原论文针对高位泄露，低比特泄露需对格基做相应改造，本题用 flatter 在参数 n=5、d=3、t=2 下约 18s 可解。

## 原理

- **ECHNP 定义**：给定椭圆曲线上多个点 `R_i = k_i·G`（或 `r_i·A`）以及每个点 x 坐标的部分比特，恢复隐藏的标量/共享密钥；它把 ECDH 的“共享点”转化为带误差的线性方程，是隐藏数问题（HNP）在椭圆曲线上的类比。
- **样本构造**：攻击者选择随机 `r_i` 与 Alice 的静态公钥 `A = a·G` 协商，得到 `R_i = r_i·A = (r_i·a)·G`；Oracle 泄露 `x(R_i)` 的低比特，等价于知道 `x_i = X_i mod 2^l`，未知部分是一个小量。
- **低比特 vs 高比特**：常见 HNP 论文讨论“已知高位”（`X = 已知高位·2^k + 小误差`）；本题泄露低位，需要把关系改写为 `X - x_i = 2^l · u_i`（u_i 小），并在格构造中调整平移/缩放，原论文的构造不能直接照搬。
- **格求解**：把多个样本的误差关系堆成格，未知的私钥/共享密钥与各误差作为短向量；LLL/BKZ 约简后从短向量恢复。样本数 n、格维数 d、参数 t 需要与泄露位数匹配。
- **flatter**：对中小维格，flatter 比 fpylll 更快；本题实测 n=5、d=3、t=2 在 1 核 Ubuntu 上约 18s 完成。

## 触发条件

- 能与 Alice 进行多次 ECDH，且每次 Oracle 返回协商点 x 坐标的低比特。
- 泄露位数与样本数满足格构造的可解条件（样本越多、泄露越多越容易）。
- 曲线参数、生成元与 Alice 公钥已知；有 flatter/fpylll 与足够算力。

## 利用步骤

1. 反复与 Alice 协商，记录每次攻击者随机数 `r_i` 与 Oracle 泄露的 `x(R_i)` 低位。
2. 把每个样本整理成 `X_i = 2^l·u_i + x_i`，其中 `X_i` 是 `R_i` 的完整 x 坐标，`u_i` 为小未知量。
3. 结合曲线方程 `Y_i² = X_i³ + aX_i + b` 消去 `Y_i`，或直接用 ECHNP 论文的线性化构造，建立格基。
4. 按低比特场景调整格基（平移量、缩放因子、样本权重），用 flatter 约简。
5. 从短向量恢复候选 `a` 或共享密钥 `a·B`，用已知点验证 `a·G == A`。
6. 用恢复的共享密钥解密会话/得到 flag。

## PoC

无完整脚本（原文只给论文与参数）。关键参数：`n=5, d=3, t=2`，工具 flatter，1 核约 18s。

## 变体与关联

- 变体：若泄露的是高位而非低位，可直接套用经典 HNP 构造；低位泄露需改写为 `X_i - x_i = 2^l u_i`。
- 变体：样本数不足时可结合格枚举/BDD 或增加 Oracle 查询次数。
- 关联：ECDH 双值高位泄露的 HNP 实现见 [[crypto-ecc-ecdh-double-high-bit-leak-hnp-bsgs]]；单点 x/y 低位泄露的双变量 Coppersmith 解法见 [[ctf-crypto-ecdh-lowbits-bivariate-coppersmith-flatter]]。
- 边界：原文未给出格构造细节与代码，只说明基于 2022 亚密会论文并做低比特改造；实际复现需按论文公式推导。

## 检测与防御

- 修复：ECDH 协商点坐标不向不可信方返回任何比特；对同一公钥的重复协商做限制。
- 加固：使用 x-only ECDH（X25519）与临时密钥（ECDHE），避免静态私钥被多次采样。
- 检测：同一客户端对同一服务端公钥的高频 ECDH 协商；异常的低位查询模式。
