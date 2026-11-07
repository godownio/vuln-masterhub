---
id: web-generic-auth-2fa-user-parameter-tampering-code-bruteforce
title: 2FA 绕过：验证接口 username 参数篡改与 4 位验证码爆破
type: scenario
domain: web
path: web/generic/auth
technique: 2fa-username-tampering-and-code-bruteforce
aliases:
- 2FA 绕过
- 二次验证绕过
- 验证码爆破
- mfa-code 爆破
- 2FA 用户参数篡改
- account.php username IDOR
tags:
- auth
- 2fa
- mfa
- bruteforce
- idor
- parameter-tampering
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T01:13:31+08:00'
  notes: 已对照 Level 14 account.php?username=administrator 越权与 Level 19 login2.php?verify=administrator + 0000-9999 爆破（0268 命中）截图核对；未验证点：未在本机复现，两个关卡合并为参数篡改+验证码爆破一类
---

## 一句话结论

当 2FA 验证页或发码接口把 `username` 作为客户端可控参数（URL、隐藏字段或 JSON body），且验证码未与服务端会话/用户绑定、又没有尝试次数限制时，可以把 username 改成受害者账户，让验证码发到受害者或直接进入其账户，并对 4 位数字验证码做 0000–9999 爆破完成登录。

## 原理

- 正常的 2FA 应把“待验证用户”绑定在服务端会话中（登录第一步成功后在 session 里记录 user id），第二步只校验验证码。
- 如果第二步从请求参数读取 `username`/`verify`，并用它定位用户、生成/校验验证码，攻击者就可以在第一步用自己的账号通过密码校验，第二步把 username 改为 `administrator`，服务端便将验证码发给/校验于管理员账户。
- 4 位数字验证码只有 10,000 种；若没有按会话/用户/IP 的尝试次数限制，或限制可绕过，Burp Intruder 可以在很短时间内穷举。成功响应通常与失败响应在长度/状态码/跳转上不同。
- 有些实现甚至在修改 username 后直接返回目标账户页面（缺少二次校验），形成认证绕过而不需要爆破验证码。

## 触发条件

- 登录流程分两步，第二步页面/接口接受客户端提交的 `username`、`verify`、`user` 等参数。
- 服务端未把 2FA 状态与登录会话绑定，或未校验提交的 username 与 session 用户一致。
- 验证码为 4–6 位数字，且没有有效的尝试次数限制/过期/一次性校验。
- 攻击者能到达 2FA 页面（用自己的账号登录第一步，或直接访问验证页）。

## 利用步骤

1. 用自己的账号完成密码登录，进入 2FA 验证页；抓取验证请求。
2. 观察请求中是否有 `username`/`verify` 参数；将其改为目标账户（如 `administrator`），观察验证码发送提示和页面变化。
3. 若修改后直接进入目标账户，则已完成 2FA 绕过；若仍需验证码，先触发一次“发送验证码”，再把验证码参数作为爆破点。
4. 用 Burp Intruder 的 Numeric 模式生成 0000–9999，或按实际位数生成；过滤失败响应，找成功响应。
5. 成功后保存会话 Cookie，验证是否为目标账户；如目标是管理员，继续评估权限。
6. 若验证码有次数限制，尝试更换会话/用户名/IP 或利用竞态；限制严格时回到步骤 2 的参数篡改路径。

## PoC

修改 URL 参数让验证码发给管理员：

```http
GET /Expert/level7/login2.php?verify=administrator HTTP/1.1
Host: target
Cookie: PHPSESSID=<own-session>
```

验证请求中的 username 篡改：

```http
POST /Expert/level7/login2.php?verify=admin HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<own-session>

verify=administrator&mfa-code=1234
```

4 位验证码爆破（Burp Intruder）：

```text
Attack type: Sniper
Payload position: mfa-code=§0000§
Payload type: Numbers
From: 0  To: 9999  Step: 1  Min integer digits: 4
Filter: exclude responses containing "Incorrect security code"
```

## 变体与关联

- 变体：username 放在隐藏字段、JSON body、cookie 或自定义头中；逐一测试。
- 变体：修改 `account.php?username=` 等账户页参数，直接读取目标账户资料或绕过 2FA 步骤。
- 变体：验证码可复用、不过期、与用户不绑定；同一验证码可用于多个账号。
- 变体：验证码位数更短（4 位）或无尝试限制时优先爆破；位数长时优先找参数篡改/逻辑绕过。
- 关联：[[web-generic-auth-login-bruteforce-response-payload]]（响应判读与过滤）。
- 关联：[[web-generic-auth-password-reset-username-tampering]]（密码重置流程的同类 username 篡改）。
- 注意：不要对生产账号进行大规模验证码爆破；测试时使用自己的账号和授权范围，并控制请求量。

## 检测与防御

- 防御：2FA 状态必须绑定服务端会话/用户 ID；第二步不接受客户端提交的 username，所有查询以 session 用户为准。
- 防御：验证码一次有效、短过期（如 5 分钟）、与用户+会话绑定；限制每个会话/用户/IP 的尝试次数，超过即失效并要求重新登录。
- 防御：验证码错误响应统一文案/长度/状态码；对 2FA 失败做告警与账号保护。
- 检测：同一会话在短时间内提交大量 4/6 位验证码；2FA 请求中的 username 与会话用户不一致；验证码发送目标与登录用户不一致；`mfa-code` 高频枚举特征。
