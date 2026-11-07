---
id: web-generic-auth-login-rate-limit-bypass-cookie-xff
title: 登录限速/封禁绕过：丢弃会话 Cookie 与伪造 X-Forwarded-For
type: scenario
domain: web
path: web/generic/auth
technique: login-rate-limit-bypass-cookie-xff
aliases:
- 登录限速绕过
- PHPSESSID 限速绕过
- X-Forwarded-For 伪造 IP
- 爆破 IP 封禁绕过
- Pitchfork 攻击
tags:
- auth
- bruteforce
- rate-limit
- x-forwarded-for
- cookie
- session
- bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T01:13:27+08:00'
  notes: 已对照 Level 13 丢弃 PHPSESSID 与 Level 17 XFF+Pitchfork 截图核对；未验证点：未在本机复现，XFF 生效依赖目标信任该头
---

## 一句话结论

当登录接口按 `PHPSESSID` 等会话 Cookie 或按客户端 IP 计数限速/封禁时，可以通过每次请求丢弃或轮换 Cookie 获得新会话，或伪造 `X-Forwarded-For` 等代理头让服务端看到不同源 IP，从而继续爆破；用 Pitchfork 模式让 IP 与密码一一配对可避免重复计数。

## 原理

- 很多 PHP 应用用 `session_start()` 创建 `PHPSESSID`，并把失败次数存在 session 里。删除请求中的 `Cookie` 头后，服务端每次都会新建 session，计数器归零，限速失效。
- IP 封禁常基于 `REMOTE_ADDR`，也可能直接读取 `X-Forwarded-For`、`X-Real-IP`、`Client-IP`、`Forwarded` 等头。如果应用没有可信代理校验，攻击者可以给每个请求填不同的伪造 IP，服务端按伪造值分桶，封禁被绕过。
- Burp Intruder 的 Pitchfork 模式从多个 payload 列表按索引一一取值；把 IP 列表和密码列表配对，可以让每次请求使用不同 IP 和不同密码，避免同一 IP/同一密码组合被计数。
- 若限速同时按账号计数，伪造 IP 只能绕过 IP 维度，账号维度仍会触发锁定；此时需要结合账号枚举、分布式来源或换目标账号。

## 触发条件

- 登录接口存在可观测的限速/封禁（429、`请求过于频繁`、`账号已锁定`、连接重置等）。
- 限速键是会话 Cookie 或可被客户端影响的 IP 头，而不是服务端可信的账号+IP 组合。
- Cookie 丢弃后服务端不会强制要求已有会话，或会话校验不严。
- 代理头被应用/框架信任（未校验可信代理、未覆盖客户端传入值）。

## 利用步骤

1. 先正常爆破若干次，观察限速响应（状态码、提示文本、封禁时长）。
2. 删除请求中的 `Cookie` 头（尤其是 `PHPSESSID`），继续发送；若限速消失，说明按会话计数。
3. 若仍被限速，添加 `X-Forwarded-For: 192.168.5.1` 等头，逐步变化最后一段；观察是否恢复。
4. 用 Pitchfork 模式：Payload 1 为 IP 列表（如 `192.168.5.1`…`192.168.5.255`），Payload 2 为密码字典，按索引配对。
5. 若同时有账号锁定，切换到其他有效用户名或先做用户名枚举，避免把目标账号锁死。
6. 成功后记录请求与响应，停止爆破。

## PoC

丢弃会话 Cookie：

```http
POST /login.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

username=admin&password=<payload>
```

（不发送 `Cookie: PHPSESSID=...`）

伪造 XFF：

```http
POST /login.php HTTP/1.1
Host: target
X-Forwarded-For: 192.168.5.23
Content-Type: application/x-www-form-urlencoded

username=admin&password=<payload>
```

Burp Intruder Pitchfork 配置：

```text
Attack type: Pitchfork
Payload 1 (X-Forwarded-For): 192.168.5.1 .. 192.168.5.255
Payload 2 (password): 123456, password, 12345678, ...
```

## 变体与关联

- 变体：轮换 `PHPSESSID`/其他会话 Cookie，或每次先请求首页获取新 session。
- 变体：尝试 `X-Real-IP`、`Client-IP`、`Forwarded: for=...`、`X-Originating-IP` 等头。
- 变体：限速按用户名计数时，用多个有效用户名分摊；或利用大小写/Unicode 归一化差异。
- 关联：[[web-generic-auth-login-bruteforce-response-payload]]（爆破响应判读与 payload 变换）。
- 关联：[[web-generic-auth-username-enumeration-timing-lockout]]（账号锁定作为枚举 oracle）。
- 注意：伪造 XFF 只在应用信任该头时有效；有可信代理/WAF 覆盖该头时无效，需重新评估限速键。

## 检测与防御

- 防御：不要信任客户端传入的 `X-Forwarded-For`；只从可信代理链的最右/最左可信值取真实 IP，并在入口覆盖/清洗该头。
- 防御：限速键使用服务端会话 + 账号 + 真实 IP + 设备指纹的组合；不要只按 `PHPSESSID` 计数。
- 防御：对同一账号的失败次数做独立锁定/告警；对分布式来源做风控与验证码；登录成功后重置计数。
- 检测：大量请求缺少 Cookie 或 Cookie 每次不同；同一账号来自大量不同 XFF；`X-Forwarded-For` 值异常密集/递增；429/403 比例异常；WAF 记录高频登录失败。
