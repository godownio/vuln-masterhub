# 椭圆曲线

## 这层是什么

ECDSA nonce、曲线参数、无效曲线攻击。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [80 位素数阶椭圆曲线离散对数：Pollard rho 并行求解 ECDLP](crypto-ecc-ecdlp-80bit-prime-order-pollard-rho.md) | verified | high | 2026-11-06 |
| [ECC 等差点列 + 已知 flag 前缀：反推每字节乘数恢复明文](crypto-ecc-arithmetic-progression-known-prefix-recovery.md) | verified | high | 2026-11-07 |
| [ECDH 小 nonce 暴力：从 R=kG 枚举 k，S=kQ 的 x 坐标 SHA256 派生 XOR 密钥](crypto-ecc-ecdh-small-nonce-brute-shared-point-key.md) | verified | high | 2026-11-06 |
| [ECDSA nonce 复用：同一 k 签两条消息直接恢复私钥](crypto-ecc-ecdsa-nonce-reuse-private-key-recovery.md) | verified | high | 2026-11-06 |
| [ECDSA 反常曲线：E.order()==p 时 Smart attack 线性时间求私钥](crypto-ecc-anomalous-curve-smart-attack.md) | verified | high | 2026-11-06 |
| [ECDSA 可预测 nonce：由公开种子确定性派生 k 后直接恢复私钥](crypto-ecc-ecdsa-predictable-nonce-public-seed-recovery.md) | verified | high | 2026-11-06 |
| [ECDSA 弱曲线：基点阶光滑时用 Pohlig-Hellman 分解 ECDLP](crypto-ecc-ecdsa-smooth-order-pohlig-hellman.md) | verified | high | 2026-11-06 |
| [ECDSA 时间侧信道：两种 k 位长 + HNP 格 CVP 恢复私钥并伪造 token](crypto-ecc-ecdsa-time-side-channel-hnp.md) | verified | medium | 2026-11-06 |
| [ECDSA 私钥由公开字符串 SHA-512 模曲线阶派生：直接计算恢复私钥](crypto-ecc-ecdsa-private-key-public-constant-derivation.md) | verified | high | 2026-11-06 |
| [ECDSA 部分 nonce 泄露：k=h+l 线性关系用 LLL/CVP 恢复私钥](crypto-ecc-ecdsa-partial-nonce-leak-lattice.md) | verified | high | 2026-11-06 |
| [奇异三次曲线（尖点）上的 ECDLP 退化：参数化把群运算化为有限域加法](crypto-ecc-singular-cubic-cusp-additive-group.md) | verified | high | 2026-11-06 |
| [扭曲爱德华曲线 DLP 归约：Add 即 F_p(√D) 乘法，映射到 F_p^* 后用 discrete_log 恢复共享密钥](crypto-ecc-twisted-edwards-map-multiplicative-group-dlp.md) | verified | high | 2026-11-07 |
| [无效点攻击：G 不在题给曲线上仍按公式标量乘，小 k 用 BSGS 解 ECDLP](crypto-ecc-invalid-point-secp256k1-bsgs.md) | verified | medium | 2026-11-06 |
| [未知曲线参数 + 点减半：由 2P、P+Q、2Q 恢复 p/b 并反推 P、Q](crypto-ecc-unknown-curve-point-halving-recover-flag.md) | verified | high | 2026-11-06 |
| [黑盒群未知椭圆曲线恢复：采样点射影三次拟合 + Weierstrass 化 + 有界 DLP](crypto-ecc-unknown-curve-projective-cubic-fit-weierstrass-dlp.md) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
