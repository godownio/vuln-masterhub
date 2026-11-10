---
title: 侧信道
weight: 1
---

# 侧信道

## 这层是什么

时序、功耗、缓存与故障注入。

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
| [AES-128 CPA 相关功耗分析：汉明重量模型逐字节恢复密钥](crypto-side-channel-aes-cpa-hamming-weight/) | verified | high | 2026-11-06 |
| [Sage is_prime 计时侧信道：用小于 103 的小素因子快速失败分支做“整除预言机”，CRT 恢复明文](crypto-side-channel-sage-is-prime-timing-oracle-crt/) | verified | medium | 2026-11-08 |
| [白盒 AES 差分故障分析：第 8 轮列混淆注入 + phoenixAES 恢复轮密钥](crypto-side-channel-whitebox-aes-dfa-round8-fault/) | verified | high | 2026-11-07 |
| [白盒 AES 查表实现指纹识别 + Frida 自动采样故障密文做 DFA 恢复主密钥](crypto-side-channel-whitebox-aes-table-fingerprint-frida-dfa/) | verified | medium | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
