---
id: web-generic-csrf-icecms-square-delete-form
title: IceCMS 广场内容删除 CSRF（CVE-2023-42188）：无 CSRF Token 的跨站表单借管理员会话删帖
type: scenario
domain: web
path: web/generic/csrf
technique: icecms-square-delete-csrf
aliases:
- IceCMS CSRF
- CVE-2023-42188
- DelectSquareById CSRF
- 跨站删除广场内容
- 表单 CSRF
tags:
- csrf
- icecms
- missing-token
- form
- session
- delete
- java
- vue
cve:
- CVE-2023-42188
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
affected_versions: Thecosy IceCMS 2.0.1
verification:
  verified_by: verifier-V442
  verified_at: '2026-11-09T23:09:59+08:00'
  notes: 已对照原文核对：文章第二处漏洞给出 <form action=http://localhost:9528/square/DelectSquareById/264> 的跨站表单并称管理员点击后删除成功，CVE-2023-42188 在图1 VulDB 记录中确为 IceCMS v2.0.1 CSRF；卡片补充了 SameSite/GET 导航限制。未验证点：原文图12实际截图为后台用户管理列表（ID 264 仍可见），未给出跨站表单执行前后对比，端点归属与实测细节无法独立确认；若该端点鉴权依赖 Authorization 头，纯表单 CSRF 可能不成立，建议作者保留此不确定性说明。
---

## 一句话结论

IceCMS 的广场内容删除接口 `/square/DelectSquareById/{id}` 只依赖浏览器会话（Cookie/JWT 由前端附带）鉴权，不校验 CSRF Token/Origin；攻击者构造一个自动向该 URL 发起请求的 HTML 页面，诱导已登录的管理员访问并提交，即以管理员身份删除指定 ID 的广场内容（CVE-2023-42188）。

## 原理

- **CSRF 成立条件**：服务端仅凭会话 Cookie（或前端自动带的凭据）识别用户，状态变更接口没有不可预测的 CSRF Token，也不校验 `Origin`/`Referer`；浏览器会自动把目标站 Cookie 附加到跨站请求上，服务端无法区分请求是受害者本人在站内发起还是第三方页面伪造。
- **端点**：`/square/DelectSquareById/{id}` 用路径中的 ID 指定删除对象，ID 可从广场公开列表直接读取；删除成功后返回表示成功的布尔值。
- **为什么先拿管理员**：任意已登录用户的会话都可被 CSRF，但管理员通常对全站内容有删除权限，借管理员会话可删任意 ID；payload 页面只需让管理员点击一次（自动提交可免点击，取决于浏览器 SameSite 策略）。
- **实际影响**：攻击者无需知道管理员密码即可批量删除/破坏内容，属于完整的跨站状态变更攻击。
- **限制**：若目标 Cookie 设置了 `SameSite=Lax/Strict` 且请求为跨站 POST，浏览器可能不携带 Cookie；删除接口若为 GET 且导航类请求，Lax 策略仍可能放行，需实测。

## 触发条件

- 目标为 IceCMS 2.0.1（CVE-2023-42188）。
- 攻击者能将恶意 HTML 放到管理员可访问的位置（外站、论坛、客服消息等），或诱导管理员访问。
- 管理员已登录目标系统，且浏览器/服务端 Cookie 策略允许跨站携带会话。
- 删除接口对 ID 无额外校验（或管理员拥有删除权限），目标内容 ID 已知。

## 利用步骤

1. 以管理员身份登录，进入后台内容管理页面，记录删除请求的 URL 形态：`/square/DelectSquareById/{id}`。
2. 在广场列表中找到想删除的内容 ID（如 264）。
3. 构造恶意页面：一个隐藏表单，`action` 指向 `http://目标:9528/square/DelectSquareById/264`，页面加载或诱导点击时提交。
4. 诱导已登录管理员打开页面，浏览器带会话发起请求，内容被删除。

## PoC

```html
<html>
  <body>
    <script>history.pushState('', '', '/')</script>
    <form action="http://target:9528/square/DelectSquareById/264" method="GET">
      <input type="submit" value="Submit request" />
    </form>
    <script>document.forms[0].submit()</script>
  </body>
</html>
```

实测以管理员会话访问该页面后，ID 264 的广场内容被删除。

## 变体与关联

- 变体：把 `method` 改为 POST、把参数改为表单字段，适配 POST 型删除接口；用 `fetch(..., {mode:'no-cors', credentials:'include'})` 自动提交。
- 变体：若目标校验 Referer，可通过同站开放重定向/上传点托管页面绕过。
- 关联：[[web-generic-csrf-missing-token-state-changing-endpoint]]（无 CSRF Token 状态变更接口通用原理）；[[web-generic-auth-icecms-delete-by-id-idor]]（同一删除接口的越权视角）。

## 检测与防御

- 检测：删除等状态变更接口出现无 `Origin`/`Referer` 或外部来源的请求；同一会话短时间内大量删除不同 ID；返回成功但无对应站内操作。
- 防御：所有状态变更接口加 CSRF Token 并校验；校验 `Origin`/`Referer`；Cookie 设置 `SameSite=Lax/Strict`；敏感删除改用 POST 并二次确认；对删除操作记审计日志。
