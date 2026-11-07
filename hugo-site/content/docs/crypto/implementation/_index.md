---
title: 实现缺陷
weight: 1
---

# 实现缺陷

## 这层是什么

常量时间、内存安全、密钥管理。

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
| [5G-AKA 期望响应值 XRES* 写入 INFO 日志并复用未消费认证上下文完成确认](crypto-implementation-5g-aka-xres-star-log-leak/) | verified | medium | 2026-11-05 |
| [ElGamal 长期私钥出现在 DEBUG 日志：恢复共享秘密并解密任意密文](crypto-implementation-elgamal-private-key-debug-log-leak/) | verified | high | 2026-11-05 |
| [MADV_DONTDUMP + mlock + PR_SET_DUMPABLE：把密钥页从 core 与 swap 泄露面移除](crypto-implementation-madv-dontdump-mlock-key-pages/) | verified | high | 2026-11-05 |
| [memset 安全清零被 dead store elimination 删除：explicit_bzero、memset_s 与 volatile 函数指针](crypto-implementation-memset-dead-store-elimination-key-wipe/) | verified | high | 2026-11-05 |
| [ML-DSA/Dilithium 签名 nonce 泄露：z-r=c·s1-noise 最小二乘恢复私钥](crypto-implementation-mldsa-nonce-leak-least-squares-key-recovery/) | verified | high | 2026-11-06 |
| [Python gmssl SM2 公钥 lstrip("04") 前缀剥离错误与 hex 大小写导致的签名不匹配](crypto-implementation-gmssl-sm2-publickey-lstrip-hex-case/) | verified | high | 2026-11-05 |
| [加权狄利克雷前缀和隐藏参数：h(n)=Σ d·w(d) 的递推反演还原密钥流](crypto-implementation-dirichlet-convolution-parameter-inversion/) | verified | high | 2026-11-05 |
| [单轮 SPN 白盒式选择明文攻击：逐字节线性差分表恢复 k0，中间相遇解目标密文](crypto-implementation-single-round-spn-chosen-plaintext-key-recovery/) | verified | high | 2026-11-05 |
| [小参数 LWE 暴力枚举：n=6、s∈{0..3}、噪声±1 直接搜 secret 并派生 AES key](crypto-implementation-small-lwe-secret-bruteforce-aes-key/) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
