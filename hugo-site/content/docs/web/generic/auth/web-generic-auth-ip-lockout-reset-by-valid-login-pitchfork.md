---
id: web-generic-auth-ip-lockout-reset-by-valid-login-pitchfork
title: IP 登录失败封禁绕过：用自己账号成功登录重置计数器 + Pitchfork 交替字典
type: scenario
domain: web
path: web/generic/auth
technique: ip-lockout-counter-reset-pitchfork
tags:
- auth
- bruteforce
- rate-limit
- lockout
- bypass
- pitchfork
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V600
  verified_at: '2026-11-12T17:08:33+08:00'
  notes: 已对照原文与全部55张截图核对：3次失败锁IP提示(05)、自己账号成功登录后计数器重置(06)、Pitchfork交替字典命中carlos:soccer 302/209(07)均与卡片一致；与cookie-xff换源卡机制不同非同链；未验证点：未在真实靶场复现
url: /docs/web/generic/auth/web-generic-auth-ip-lockout-reset-by-valid-login-pitchfork/
draft: false
kb_aliases:
- IP 封禁重置
- 登录锁定绕过
- 成功登录清零失败计数
- Pitchfork 交替爆破
- 3 次失败锁 IP 绕过
- 解锁 Key 字典
---

## 一句话结论

当站点按 IP 统计登录失败次数（例如 3 次失败封禁 1 分钟）且任意一次成功登录会把该 IP 的失败计数清零时，攻击者可以把自己的有效登录与对受害者的口令猜测交替发送（Burp Pitchfork 一一配对），每猜一两次就用自己账号“解锁”，从而绕过封禁持续爆破密码。

## 原理

- 常见的 IP 限速实现是：同一源 IP 连续登录失败 N 次后封禁/延迟；登录成功时把该 IP 的失败计数清零。
- 如果计数键是“IP”而不是“账号+IP”，成功登录的清零动作会连带清掉攻击者对受害者账号造成的失败次数。攻击者拥有任意一个可用账号，就获得了一个可反复使用的“解锁 Key”。
- 攻击者按 `自己的账号 → 受害者账号 → 自己的账号 → 受害者账号` 的顺序提交，并在每次自己登录时使用正确密码；服务端每次成功登录都重置计数，受害者的猜测始终达不到封禁阈值。
- Burp Intruder 的 Pitchfork 模式从多个 payload 列表按索引一一取值，正好把“用户名列表”和“密码列表”按上述交替顺序配对；线程数必须为 1，保证请求严格按字典顺序发送。

## 触发条件

- 登录失败封禁按源 IP 计数，且成功登录会把计数清零（或重置为未封禁状态）。
- 攻击者拥有至少一个可正常登录的账号。
- 目标用户名已知（可先做用户名枚举）。
- 攻击者能控制请求顺序（单线程）并可观察到 302/响应长度等成功标志。

## 利用步骤

1. 正常输错 3 次，确认返回“You have made too many incorrect login attempts. Please try again in 1 minute(s).”之类的 IP 封禁提示。
2. 用自己的账号成功登录一次，再用受害者的错误口令尝试，观察封禁提示消失/计数重置，证明“成功登录即解锁”。
3. 构造两个等长 payload 列表并按索引配对（Pitchfork）：
   - 用户名：`own, victim, own, victim, ...`
   - 密码：`own_password, guess1, own_password, guess2, ...`
4. 在 Burp Intruder 中选择 Pitchfork，线程数设为 1，按顺序发送。
5. 过滤 `302` 或长度异常的响应（受害者的正确口令会返回 302 并跳转 `/my-account?id=victim`），取得口令。
6. 用命中的口令登录受害者账号，停止测试并清理。

## PoC

交替字典（Pitchfork，两个列表索引一一对应）：

```text
# Payload 1: 用户名
own_user
victim
own_user
victim
own_user
victim

# Payload 2: 密码
own_password
guess_1
own_password
guess_2
own_password
guess_3
```

```text
# Burp 观察点：受害者条目中命中口令的响应为
HTTP/1.1 302 Found
Location: /my-account?id=victim
```

- 原文实测：payload1 `wiener/carlos` 与 payload2 `peter/soccer` 交替时，`carlos:soccer` 的那条请求返回 302（长度 209），其余为 200。
- 线程数必须为 1；并发会导致“解锁”和“猜测”顺序错乱，计数可能再次触发封禁。

## 变体与关联

- 若成功登录不解锁，可改试会话 Cookie 轮换或伪造 `X-Forwarded-For` 绕过，见 [[web-generic-auth-login-rate-limit-bypass-cookie-xff]]。
- 若封禁按“账号”而不是 IP，本方法无效，需要换目标账号或利用锁定阈值内的高频口令优先策略。
- 与用户名枚举组合：先按 [[web-generic-auth-error-message-username-enumeration]] 等方式筛出有效用户名，再做交替爆破。
- 边界：部分系统同时按账号计数，交替解锁只能绕过 IP 维度；若账号维度锁定严格，仍需控制每个账号的失败次数。

## 检测与防御

- 检测：同一 IP 出现“成功登录—失败登录—成功登录—失败登录”的规律性交替；短时间内在多个账号间切换；单账号失败次数低但全局失败次数高的模式。
- 防御：失败计数按“账号 + IP”双维度统计，成功登录只清零该账号+IP 的计数；对频繁切换账号的成功/失败交替行为做风控；对高价值账号强制 MFA 与登录提醒。
