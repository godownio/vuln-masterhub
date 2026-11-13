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
| [单端点条件竞争：并发改邮箱令管理员确认邮件改投攻击者，绑定内部域名邮箱提权](web-generic-race-condition-single-endpoint-email-change-confirm-misdelivery/) | verified | high | 2026-11-12 |
| [多端点条件竞争：校验与扣款之间并发换货，10 元礼品卡订单夹带 1337 元夹克（加/删商品、用券、结算同组并行）](web-generic-race-condition-multi-endpoint-cart-item-swap-checkout/) | verified | high | 2026-11-12 |
| [打赏接口并发竞态：负余额刷声望→reviewer→导出 token→featured 读公告 flag](web-generic-race-condition-tip-reputation-role-escalation/) | verified | high | 2026-11-06 |
| [找回密码并发替换目标邮箱：同一会话同时向受害邮箱与攻击者邮箱发码，验证码与待重置账号绑定混乱导致他人密码可被重置](web-generic-race-condition-password-reset-email-swap-code-confusion/) | verified | low | 2026-11-12 |
| [时间戳派生重置 token 的并发碰撞：同一时刻请求得到相同 token 重置任意用户密码](web-generic-race-condition-time-based-reset-token-collision/) | verified | high | 2026-11-12 |
| [注册先写入宽松状态再异步收紧的竞态窗口：窗口内并发登录绕过 verified 校验](web-generic-race-condition-register-verified-login-window/) | verified | high | 2026-11-08 |
| [登录图形验证码并发复用（一码多用）：HTTP/2 单包攻击让多个口令请求同时通过验证码校验实现口令爆破](web-generic-race-condition-captcha-one-time-multi-use-login-bruteforce/) | verified | high | 2026-11-12 |
| [登录失败次数限制并发绕过：单包攻击同时提交多个不同口令，每用户 3 次限制被突破并命中口令](web-generic-race-condition-login-rate-limit-single-packet-bypass/) | verified | medium | 2026-11-12 |
| [短信发送接口并发绕过频控：同号多请求与多号同发同时通过验证与计数检查，造成纵向与横向短信轰炸](web-generic-race-condition-sms-rate-limit-concurrency-bypass/) | verified | medium | 2026-11-12 |
| [订单提交并发复用优惠券：20 并发请求各自成单，每单都减 100](web-generic-race-condition-coupon-order-submit-reuse/) | verified | high | 2026-11-07 |
| [购物车优惠券 apply 接口并发重复提交：同一张一次性券在单笔订单上重复叠加，1337 元商品 24.07 元成交](web-generic-race-condition-coupon-apply-endpoint-discount-stack/) | verified | high | 2026-11-12 |
| [转账结算 TOCTOU 竞争：confirm 与结算间隙篡改 status/amount 绕过单笔限额放大转账](web-generic-race-condition-transaction-status-toctou-limit-bypass/) | verified | high | 2026-11-08 |
| [部分构造竞态：注册对象创建与确认 token 赋值间隙，空数组 token 绕过邮箱激活](web-generic-race-condition-register-confirm-uninitialized-token-array/) | verified | high | 2026-11-12 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
