---
id: web-generic-auth-weak-security-question-reset
title: 密保问题弱设计：学号/幸运数字可猜且无尝试限制，重置任意账号
type: scenario
domain: web
path: web/generic/auth
technique: weak-security-question-password-reset
tags:
- web
- auth
- password-reset
- security-question
- weak-authentication
- account-takeover
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V72
  verified_at: '2026-11-05T16:53:30+08:00'
  notes: 已对照原文与图36-37核对：密保问题为学号与您的幸运数字是多少（示例填9），原文称错误次数无限制、可猜解后重置。未本地复现
url: /docs/web/generic/auth/web-generic-auth-weak-security-question-reset/
draft: false
kb_aliases:
- 密保问题绕过
- 学号密保
- 幸运数字密保
- 密保问题爆破
- 知识型认证弱口令
---

## 一句话结论

统一身份认证的“忘记密码”如果使用密保问题，而问题答案是学号、幸运数字等低熵/公开信息，且没有错误次数限制，攻击者可从奖学金名单等公开材料获得学号、或直接枚举 0-10 的幸运数字，通过验证后重置并接管账号。

## 原理

- 密保问题属于知识型认证（KBA），安全性取决于答案的熵、保密性和不可猜测性。学号、姓名、生日、学校、幸运数字等答案通常能从公开名单、社交资料或极小空间枚举得到，不能作为账号归属证明。
- 案例一的问题直接是“学号”，而学号与姓名常出现在奖学金/评审/录取公示中，搜索引擎可批量获得；案例二的问题是“您的幸运数字是多少”，答案空间通常只有 0-10，且系统未限制错误次数，可直接逐个尝试或爆破。
- 系统把“答对密保问题”当作重置密码的充分条件，后续不再要求短信/邮箱验证或旧密码；一旦答对，攻击者即可设置新密码并登录。
- 与静态身份字段（学号+身份证）不同，密保问题看似个性化，但实际答案分布高度集中，且用户常填写真实但公开的信息；没有限速时，低熵答案可被枚举。
- 根因是“低熵知识因子 + 无尝试限制 + 作为唯一重置凭证”。

## 触发条件

- 找回密码流程提供密保问题验证；
- 问题答案低熵（数字、学号、生日、姓名、学校、宠物名等）或可从公开信息获得；
- 系统对密保答案错误次数没有限制/锁定，或限制阈值高于答案空间；
- 重置成功后不需要额外验证（短信、邮箱、人工审核）。

## 利用步骤

1. 在登录页点击“忘记密码”，输入目标账号，观察密保问题内容。
2. 若问题是学号/工号/姓名等：从学校奖学金名单、评审公示、录取名单、GitHub/语雀等公开材料收集答案。
3. 若问题是幸运数字/生日/年份等小空间：写脚本或手工逐个尝试；先试 0-10、出生年份、常见数字。
4. 答对后进入设置新密码页面，设置攻击者已知密码。
5. 用新密码登录目标账号，确认权限与可访问数据；若失败，检查是否有账号锁定/验证码/多因素。

## PoC

```http
POST /uaa/checkSecurityQuestion HTTP/1.1
Host: target.edu.cn
Content-Type: application/x-www-form-urlencoded

account=<学号/工号>&questionId=1&answer=<学号或幸运数字>
```

```text
# 密保问题示例：
# 1) 您的学号是？        -> 答案来自公开奖学金名单
# 2) 您的幸运数字是多少？ -> 答案空间 0-10，可枚举
# 答对后返回 success，进入设置新密码页面
```

```http
POST /uaa/resetPasswordByQuestion HTTP/1.1
Host: target.edu.cn
Content-Type: application/x-www-form-urlencoded

account=<学号/工号>&newPassword=<新密码>
```

## 变体与关联

- 变体：密保问题为“母亲姓名”“出生地”“班主任姓名”“宠物名”等，可通过社工/公开资料获得；答案大小写、空格、全半角处理不一致也可能绕过。
- 变体：密保答案错误次数限制只按 IP 不按账号，可通过代理池绕过；或限制在客户端，清 cookie 即重置。
- 关联：[[web-generic-auth-freshman-reset-id-last6-public-pii]]（静态身份字段重置）、[[web-generic-auth-password-reset-response-tampering-sms-bypass]]（前端响应篡改）、[[web-generic-auth-password-reset-username-tampering]]（重置表单篡改）。
- 边界：密保答案为用户自设的高熵短语、错误次数严格限制、答对后仍需短信/邮箱验证时，本路径不成立。

## 检测与防御

- 修复：不要用密保问题作为唯一重置凭证；改用绑定手机/邮箱一次性验证码、旧密码或人工审核；若保留密保，限制为高熵自设问题并加二次验证。
- 加固：密保答案错误次数限制与锁定（按账号+IP）、验证码、重置后通知账号属主并强制下线。
- 检测：同一账号/ IP 对密保问题的多次错误尝试；重置后立即登录的异常行为；密保问题答案分布统计（大量账号答案相同/为学号）。
