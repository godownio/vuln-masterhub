---
id: web-generic-auth-cookie-login-response-splice-username-cookie
title: 后台登录仅凭 cookieUsername 明文 Cookie，拼接他站成功响应绕过登录
type: scenario
domain: web
path: web/generic/auth/cookie
technique: login-response-splice-username-cookie-forgery
tags:
- web
- auth
- cookie
- session
- identity-forgery
- response-replacement
- weak-password
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-42
  verified_at: '2026-11-05T06:24:21+08:00'
  notes: '已对照原文与14张截图（01-10、12-15，11缺失）核对：登录框、Intruder 1042条弱口令爆破、响应拦截改 ok 失败、看雪插件发现 layuiadmin/lib/admin 路径、ajax.js 仅判 status==200、同系统另一实例成功响应含 Set-Cookie: cookieUsername=admin 且正文 ok、替换后进入预约系统后台、分页总数 10584/219701/672845 均与卡片一致。小瑕疵：卡片把成功响应样本标为“原文图9”，实际是 img/10.png；不影响结论。产品未具名、ASP.NET 自研系统，无版本可设。直接伪造 Cookie 的最小利用已在卡内标注为原文未验证的推断，边界清楚。未在本机复现。'
url: /docs/web/generic/auth/cookie/web-generic-auth-cookie-login-response-splice-username-cookie/
draft: false
kb_aliases:
- 登录响应替换绕过
- cookieUsername 身份伪造
- 克隆成功登录响应
- 前端登录校验绕过
- 弱口令横向复用进后台
---

## 一句话结论

目标后台的 `login.ashx` 成功时只返回 HTTP 200、正文 `ok` 和 `Set-Cookie: cookieUsername=admin; path=/`，前端只判断状态码与响应文本；攻击者从同一套系统的另一个实例（已知弱口令）抓一份成功登录响应，用 Burp 替换目标响应，浏览器就在目标域写入 `cookieUsername=admin`，随后后台按该 Cookie 认定身份，直接进入管理端并读取大量游客身份证数据。

## 原理

- 登录请求形如 `POST /.../login.ashx?login=login&username=admin&password=...`，成功响应：
  ```http
  HTTP/1.1 200 OK
  Set-Cookie: cookieUsername=admin; path=/
  Content-Length: 2

  ok
  ```
  响应里没有服务端会话 ID、没有签名 token，身份只由 `cookieUsername` 这个明文 Cookie 表示。
- 前端 `ajax.js` 的逻辑是：
  ```js
  if (xhr.readyState == 4) {
      if (xhr.status == 200) { oncuess(xhr.responseText); }
      else { alert("AJAX数据返回错误"); }
  }
  ```
  成功与否完全由客户端根据状态码/文本决定，攻击者可以修改响应让前端继续。
- 只把响应正文改成 `ok` 不够（原文图 5-7 失败），因为浏览器没有拿到身份 Cookie。原文从另一个同系统实例（存在弱口令）抓到了完整成功响应，其中包含 `Set-Cookie: cookieUsername=admin`；将整段响应替换到目标登录请求后，Cookie 被写入目标域，前端进入管理端，后续接口也接受该 Cookie。
- 这说明服务端把 `cookieUsername` 当作可信身份凭据，没有做会话绑定、签名或二次校验；因此除了“替换响应”这种利用方式，理论上也可直接伪造该 Cookie（原文未单独演示该最小请求，属于推断）。
- 第一杀中的弱口令本身不是新技术，但它为第二杀提供了“成功响应样本”和同产品部署的对照，体现了同一套系统多实例之间的凭据/响应复用风险。

## 触发条件

- 登录成功标志完全由客户端判断（状态码 + 固定文本），服务端没有独立的会话令牌。
- 身份由明文、未签名、未加密的 Cookie（如 `cookieUsername=<用户名>`）承载，且未设置/校验 HttpOnly 与完整性。
- 后端接口只检查该 Cookie 的值，不校验它是否来自真实登录、是否与当前会话绑定。
- 攻击者能获取同系统另一实例的成功登录响应（弱口令、默认口令、测试环境、历史备份等），或能直接设置该 Cookie。
- 目标后台存在敏感数据/功能（本例为预约系统的游客身份证信息）。

## 利用步骤

1. 找到登录请求，观察成功响应：状态码、正文、`Set-Cookie` 字段、是否有 token。
2. 先尝试直接改响应正文为成功文本，确认前端是否放行；若后端仍要求 Cookie，则寻找同产品其他实例。
3. 在同产品的另一实例上用弱口令/默认口令登录，抓取完整成功响应（尤其是 `Set-Cookie: cookieUsername=...`）。
4. 在 Burp 中配置 `Proxy → Options → Match and Replace` 或拦截目标登录响应，把目标响应整体替换为抓到的成功响应（保留目标域）。
5. 放行后浏览器在目标域写入 `cookieUsername=admin`，前端跳转管理端；访问记录管理/数据汇总等接口确认权限。
6. 若已确认后端只信 Cookie，可直接构造 `Cookie: cookieUsername=admin` 访问后台接口，省去响应替换。

## PoC

成功响应样本（原文图 9）：

```http
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: text/html; charset=utf-8
Server: Microsoft-IIS/10.0
X-AspNet-Version: 4.0.30319
Set-Cookie: cookieUsername=admin; path=/
X-Powered-By: ASP.NET
Content-Length: 2

ok
```

Burp 响应替换（概念）：

```text
拦截 POST /.../login.ashx?login=login&username=admin&password=<任意>
将整个响应替换为上面的 200 + Set-Cookie + ok 样本
```

推断的最小直接利用（原文未单独验证）：

```http
GET /.../admin/index HTTP/1.1
Host: target
Cookie: cookieUsername=admin
```

原文结果：进入“预约系统”后台，记录管理分页显示 10584、219701、672845 条等数据，并出现大量游客身份证信息（原文称 100w+）。

## 变体与关联

- 变体：成功响应中的身份字段换成 `role=admin`、`isLogin=true`、JWT（未验签）等；核心都是客户端可写、服务端直接信任。
- 变体：不替换响应，直接修改请求后的 Cookie/本地存储；或用 XSS 写入同名字段。
- 关联：[[web-generic-auth-cookie-base64-identity-forgery]]（Base64 Cookie 身份伪造）、[[web-generic-auth-myblog-hardcoded-aes-cookie-forgery]]（可伪造的记住我 Cookie）、[[web-generic-auth-hardcoded-des-session-forgery]]（弱结构会话伪造）。
- 关联：弱口令/默认口令是获取“成功响应样本”的常见来源，多实例同产品部署时应视为同一攻击面。
- 边界：后端若校验服务端 Session、Cookie 签名或登录时间戳，响应替换只能骗过前端，无法访问数据接口；HttpOnly 会阻止 JS 读取但不阻止响应替换写入。

## 检测与防御

- 检测：同一账号在无对应登录成功记录的情况下访问后台；登录响应被代理修改（客户端侧无法直接检测，需结合服务端日志）。
- 检测：`cookieUsername` 等身份 Cookie 出现在请求中但服务端无对应会话；同一 Cookie 值在多个来源 IP 使用；短时间大量分页拉取游客数据。
- 防御：登录成功后在服务端创建会话并下发随机、签名、HttpOnly、Secure、SameSite 的会话 Cookie；身份从服务端会话读取，绝不信任客户端提交的用户名/角色字段。
- 防御：所有后台接口统一做服务端鉴权与权限校验，不能只靠前端路由或响应文本判断。
- 防御：登录响应不要返回可复用的身份凭据；多实例部署避免共用默认/弱口令，统一改密并启用多因素。
- 加固：对敏感数据接口做访问审计、分页速率限制与数据脱敏；发现异常批量拉取时告警。
