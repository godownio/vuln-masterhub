---
title: 古典密码
weight: 1
---

# 古典密码

## 这层是什么

替换、维吉尼亚、栅栏等。

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
| [Hill 密码 3×3 矩阵求逆模 26 解密](crypto-classical-hill-cipher-3x3-matrix-inverse-mod26/) | verified | high | 2026-11-06 |
| [关键字替换密码（keyword cipher）密钥未知：按首字母枚举候选密钥 + 词频/可读性打分自动定位](crypto-classical-keyword-cipher-first-letter-brute-frequency/) | verified | medium | 2026-11-08 |
| [幂数加密（power-sum 数字编码）还原：以 0 作字母分隔符，把每段数字按 2 的幂次值相加得到字母序号（4442→14→N），据此还原文中短串](crypto-classical-power-sum-digit-encoding-zero-separator-reverse/) | verified | high | 2026-11-09 |
| [打表替换（汉字映射表）加密只是单表替换：按编码单位切分后查逆表即可还原，多字节映射还需按 3 字节分组](crypto-classical-lookup-table-multibyte-substitution-reverse/) | verified | high | 2026-11-08 |
| [猪圈密码变体与三列栅栏：符号按表映射后逐列还原明文](crypto-classical-pigpen-variant-fence-column-decode/) | verified | high | 2026-11-06 |
| [简单替换密码（单表替换）：用词频/字典搜索工具秒解，再用已知前缀反推整张映射表提 flag](crypto-classical-monoalphabetic-substitution-frequency-tool/) | verified | high | 2026-11-08 |
| [逐列竖读的换位密文 + 凯撒平移：先按列重排还原置换，再暴力 25 种移位读 flag](crypto-classical-column-transpose-vertical-read-caesar-shift/) | verified | high | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
