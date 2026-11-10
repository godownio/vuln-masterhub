---
title: 竞争条件
weight: 1
---

# 竞争条件

## 这层是什么

并发竞态、TOCTOU、限次绕过。

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
| [优惠券领取接口并发竞态：同券重复领取 + 横向枚举高面额券 ID 实现无限叠加](web-generic-race-condition-coupon-concurrent-claim-stack/) | verified | medium | 2026-11-07 |
| [先落盘后审计的 TOCTOU：并发覆盖 pickle 绕过审计 RCE](web-generic-race-condition-pickle-audit-save-before-check-toctou/) | verified | high | 2026-11-06 |
| [打赏接口并发竞态：负余额刷声望→reviewer→导出 token→featured 读公告 flag](web-generic-race-condition-tip-reputation-role-escalation/) | verified | high | 2026-11-06 |
| [注册先写入宽松状态再异步收紧的竞态窗口：窗口内并发登录绕过 verified 校验](web-generic-race-condition-register-verified-login-window/) | verified | high | 2026-11-08 |
| [订单提交并发复用优惠券：20 并发请求各自成单，每单都减 100](web-generic-race-condition-coupon-order-submit-reuse/) | verified | high | 2026-11-07 |
| [转账结算 TOCTOU 竞争：confirm 与结算间隙篡改 status/amount 绕过单笔限额放大转账](web-generic-race-condition-transaction-status-toctou-limit-bypass/) | verified | high | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
