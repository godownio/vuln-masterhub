---
id: web-generic-auth-interceptor-login-prefix-dotdot-bypass
title: 拦截器用 startsWith 放行 /admin/login，/admin/login/../ 跳出到后台删除接口
type: scenario
domain: web
path: web/generic/auth
technique: interceptor-login-prefix-dotdot-bypass
tags:
- auth-bypass
- access-control
- java
- spring
- interceptor
- path-traversal
- uri-normalization
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V21
  verified_at: '2026-11-05T02:39:42+08:00'
  notes: 已对照原文并逐张核对9张图：图03/07拦截器 uri.startsWith("/admin")&&!startsWith("/admin/login")&&user==null 逻辑、图04/05 getLoginUser、图06 getCookieUid、图08正常删除请求、图09去掉Cookie后 POST /admin/login/../article/delete 成功删除（响应success:false但文章已消失）均与卡一致；卡内规范化后路径/admin/article/delete正确（原文正文写成/admin/login/article/delete系笔误）。未验证点：未本机复跑；原文未给MyBlog/Tomcat/Spring版本；Cookie AES伪造仅注释未验证，卡内已标为关联风险；frontmatter无sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-interceptor-login-prefix-dotdot-bypass/
draft: false
kb_aliases:
- 登录前缀绕过
- admin/login 路径穿越绕过
- HandlerInterceptor 鉴权绕过
- startsWith 鉴权绕过
- MyBlog 未授权删除
- 原始 URI 与路由路径差异
---

## 一句话结论

Spring 拦截器用 `uri.startsWith("/admin") && !uri.startsWith("/admin/login") && user == null` 判断是否跳转登录页时，请求 `/admin/login/../article/delete` 既满足“以 /admin/login 开头”而放行，又被容器/Tomcat 规范化为 `/admin/article/delete` 路由到受保护接口，未登录即可执行后台删除。

## 原理

- 鉴权代码通过 `request.getRequestURI()` 拿到的是**原始请求目标**，Tomcat 不会把 `..`、`.`、`//`、`;` 等规范化后再交给它；而 Servlet 映射/Spring MVC 路由使用的是规范化后的路径。
- 开发者想“放行登录页、保护其余后台接口”，写成了 `!uri.startsWith("/admin/login")`。这个排除规则只看字符串前缀，不考虑路径语义：`/admin/login/../article/delete` 的前缀确实是 `/admin/login`，于是被当作登录页放行。
- 容器在映射前对 `/../` 做跨目录拼接：`/admin/login/../article/delete` → `/admin/article/delete`，正好命中后台删除接口的 `@RequestMapping("/delete")`。
- 结果：未登录用户（无 session）可以调用 `/admin` 下所有接口；本例以 `cid=4` 删除文章验证，响应 `success:false` 但数据库记录确实被删除，说明业务方法已执行。
- 同类根因还有 `startsWith`/`endsWith`/`contains`/`equals` 等字符串判断与路由规范化不一致；`;` 路径参数、URL 编码、`//`、尾部 `/` 也可产生类似差异。
- 该实现另一处风险是把 Cookie 中的 userid 解密后直接 `queryUserById` 并写入 session（`Tools.deAes(cookie, WebConst.AES_SALT)`）；如果 AES 密钥硬编码/可预测，还能伪造任意用户登录，但本文未验证这一点，仅作为关联风险记录。

## 触发条件

- 使用 Filter/HandlerInterceptor/AOP 做鉴权，判断依据是 `getRequestURI()` 等原始路径字符串。
- 放行规则是“受保护前缀 + 排除某个子路径”的形式（如 `startsWith("/admin") && !startsWith("/admin/login")`）。
- 容器/框架会对 `..` 做规范化，且规范化后的路径能匹配到受保护接口。
- 受保护接口自身没有再校验角色/会话（仅靠拦截器）。

## 利用步骤

1. 找到鉴权拦截器，确认它用哪个方法取路径、用什么字符串比较、放行/排除规则是什么。
2. 确认受保护前缀与放行子路径，例如 `/admin` 保护、`/admin/login` 放行。
3. 构造“前缀命中放行路径、规范化后命中受保护接口”的 URL：`/admin/login/../article/delete`。
4. 去掉 Cookie/会话，发送原本需要登录的请求体（如 `cid=4`）。
5. 观察响应与后端状态：即使返回业务失败，也要通过列表/数据库确认操作是否生效。
6. 若 `..` 被容器拒绝，尝试 `;` 路径参数、`%2e%2e`、`//`、尾部 `/` 等变体。

## PoC

```http
POST /admin/login/../article/delete HTTP/1.1
Host: target:8081
Content-Type: application/x-www-form-urlencoded
Cookie:

cid=4
```

```text
# 预期：不再 302 到 /admin/login，而是进入 /admin/article/delete 的业务逻辑；
# 文章中响应 success:false，但目标文章确实被删除（以列表/数据库复核为准）。
```

## 变体与关联

- 变体：`/admin/login/..;/article/delete`、`/admin/login/%2e%2e/article/delete`、`/admin/login/..%2farticle/delete`（取决于容器解码顺序）。
- 变体：`startsWith("/api/public")` 放行、受保护接口在 `/api/` 下，用 `/api/public/../admin` 跳出。
- 变体：`endsWith(".js")`/后缀白名单用 `;.js` 或尾部 `/` 绕过。
- 关联：[[web-java-framework-spring-custom-auth-path-parsing-bypass]]（同一根因的系统性总结：getRequestURI 与 Spring 路由解析差异、startsWith/contains/endsWith 绕过、context-path 与 `;` 变体）。
- 关联：[[web-java-framework-shiro-spring-path-auth-bypass]]（Shiro 与 Spring 路径解析差异）。
- 边界：若拦截器使用规范化后的路径（`getServletPath()` 并解析 `..`）、或受保护接口在 Controller 层再次校验角色、或容器直接拒绝含 `..` 的请求，绕过不成立。

## 检测与防御

- 修复：鉴权不要用原始 URI 做字符串前缀/后缀判断；使用框架路由匹配（Spring Security `MvcRequestMatcher`、`AntPathMatcher`）或规范化后的路径。
- 修复：对路径做统一规范化（解码、删除 `;` 参数、解析 `.`/`..`、折叠 `//`）后再比较；无法规范化则拒绝。
- 修复：放行登录页应使用精确路径 + HTTP 方法，不要用 `!startsWith` 这种排除式规则；受保护接口在 Controller/Service 层再次校验角色。
- 加固：引入 Spring Security `StrictHttpFirewall`，默认拦截 `;`、`%2e`、`//`、反斜杠等；生产环境避免把应用部署在可被 `..` 绕过的旧容器组合上。
- 检测：请求路径含 `..`、`;`、`%2e`、`//`、异常尾部 `/`；同一接口正常路径 302 而变体 200；未登录请求命中 `/admin` 业务方法；删除/修改操作与登录状态不一致。
