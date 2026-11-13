---
id: web-generic-auth-2fa-code-bruteforce-macro-relogin-session-rule
title: 2FA 验证码爆破绕过“错误即注销”：Burp 宏自动重登与重发码，单线程跑 0000-9999
type: scenario
domain: web
path: web/generic/auth
technique: 2fa-code-bruteforce-via-burp-macro-session-rule
aliases:
- 2FA 验证码爆破
- 错误两次注销绕过
- Session handling rule macro
- Burp 宏 2FA
- mfa-code 0000-9999
- 多步骤自动重登
tags:
- auth
- 2fa
- mfa
- bruteforce
- burp
- macro
- session
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V600
  verified_at: '2026-11-12T17:08:37+08:00'
  notes: 已对照原文与截图核对：Session Handling Rule+Macro三步GET /login 200/POST /login 302/get /login2 200(34-37图)、Numbers 0-9999四位(38)、命中302长度178失败3057/3293(31/40/41)均与卡片一致；与2fa-user-parameter-tampering卡场景不同非同链；未验证点：未复现
---

## 一句话结论

当 2FA 在连续输错几次验证码后强制注销会话、但注销只是清除 Cookie 而没有按账号/验证码累计尝试次数时，可用 Burp 的 Session Handling Rule + Macro，在每个爆破请求前自动执行“登录→进入 2FA→重新发码”，让每次尝试都在新会话中完成，从而用单线程跑完 0000–9999 完成账户接管。

## 原理

- “错误 N 次即注销”只是会话层惩罚：服务端销毁/要求重新登录，但并未锁定该账号，也没有让已发出的验证码失效；攻击者重新登录后又能获得新的尝试机会。
- 验证码通常是 4 位数字（10,000 种）。若没有按“账号+验证码”维度的失败计数、延迟或一次性作废，理论上可在有限次数内穷举。
- Burp Session Handling Rule 可在每个 Intruder 请求发出前运行 Macro：Macro 依次重放 `GET /login`（获取 cookie/CSRF）、`POST /login`（提交口令，拿到已认证会话）、`GET /login2`（进入 2FA 页面/触发重新发码），并把新的 Cookie 与 CSRF token 写回攻击请求。
- Intruder 线程数设为 1，保证宏与攻击请求严格串行；结果中 302 且长度异常的条目即为命中的验证码，浏览器打开跳转 URL 即完成登录。

## 触发条件

- 2FA 错误若干次后仅注销会话，不锁定账号、不作废已验证码、不引入递增延迟。
- 登录与 2FA 发码可通过固定请求序列（宏）重放；存在 CSRF token 时能在宏中提取并复用。
- 攻击者已掌握第一因子（口令）或可先用其他方式登录到 2FA 阶段。
- 验证码为 4–6 位数字且未做过期/一次性严格校验（或在有效期内可反复发码）。

## 利用步骤

1. 用目标账号登录，进入 2FA 页面；故意输错两次，确认会被注销（返回登录页/错误提示）。
2. 在 Burp 中打开 `Project options → Sessions → Session handling rules`，添加规则并勾选 `Include all URLs`。
3. 添加 `Run a macro`，在 Macro Editor 中按顺序录制：
   - `GET /login`（取 CSRF/cookie）
   - `POST /login`（提交 `username`/`password`，得到 session）
   - `GET /login2`（进入 2FA 页面并触发重新发码）
   使用 Macro Tester 验证三条请求依次返回 200/302/200。
4. 将 `POST /login2` 的验证码请求发送到 Intruder，把 `mfa-code` 设为变量。
5. Payloads 选 Numbers：From 0、To 9999、Step 1、4 位十进制（不足补零）。
6. 线程数设为 1，开始攻击；按 `302` 与响应长度（命中通常明显不同，如 178，失败 3057/3293）筛选。
7. 浏览器打开命中请求的跳转地址，即以目标账号身份登录。

## PoC

```text
# Macro（按序重放）
1. GET  /login                                       -> 200（取 csrf）
2. POST /login   username=<victim>&password=<pass>   -> 302（新 session）
3. GET  /login2                                      -> 200（触发验证码/取 csrf）

# Intruder
POST /login2
Cookie: session=<macro 更新后的会话>; verify=<victim>
csrf=<macro 派生的 token>
mfa-code=§0000§

Payload: Numbers 0..9999, decimal, 4 digits, sequential
Threads: 1
```

```text
# 命中特征示例
HTTP/1.1 302 Found
Location: /my-account?id=<victim>
Content-Length: 178
```

- 原文实测在错误两次被注销后，通过上述宏+单线程爆破得到 302 响应，随后浏览器打开即登录目标账号。

## 变体与关联

- 若注销后验证码失效，可在宏中加入“重新发送验证码”的完整流程；若每次发码有冷却，可放慢速率或换取码接口绕过。
- Turbo Intruder 可用 Python 脚本实现同样的“重登+爆破”循环，速度更快但更易触发风控。
- 参数篡改型 2FA 绕过见 [[web-generic-auth-2fa-user-parameter-tampering-code-bruteforce]]；直接跳过第二步见 [[web-generic-auth-2fa-first-factor-direct-dashboard-bypass]]。
- 边界：若服务端按账号锁定验证码尝试或使码一次性失效，本方法无效。

## 检测与防御

- 检测：同一账号短时间内出现“登录成功→2FA 失败→再次登录”的高频循环；大量 4 位验证码尝试；验证码错误率异常。
- 防御：验证码尝试次数按账号 + 会话 + IP 统计并锁定/指数退避；注销后使已发码立即失效；限制重新发码频率；对高风险登录强制 MFA 推送确认而非可穷举的数字码。
