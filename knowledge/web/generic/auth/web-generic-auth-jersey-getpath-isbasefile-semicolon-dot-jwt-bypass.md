---
id: web-generic-auth-jersey-getpath-isbasefile-semicolon-dot-jwt-bypass
title: Jersey getUriInfo().getPath() + 「含点即文件」判断：用 /api/xxx;. 绕过 JWT 鉴权
type: scenario
domain: web
path: web/generic/auth
technique: jersey-getpath-semicolon-dot-auth-bypass
aliases:
- Jersey 鉴权绕过
- getUriInfo getPath 绕过
- isBaseFile 文件判断绕过
- 分号矩阵参数绕过
- JAX-RS 未授权访问
tags:
- jersey
- jax-rs
- auth-bypass
- jwt
- path-parsing
- matrix-parameter
- semicolon
- preMatching
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-3
  verified_at: '2026-11-07T21:30:48+08:00'
  notes: 已对照原文核对；图 01 AuthenticationFilter 源码(getUriInfo().getPath()、isBaseFile、WHITELIST、@PreMatching)、图 02 调试器 path=testConnect;.、图 03 GET 返回 405(非 401，证明绕过 JWT 到达 testConnect)、图 18 POST /api/testConnect;. 带 jdbcUrl 触发后续 RCE、图 19 cat /flag 得 flag 均与卡一致；dedup 除草稿自身 exact duplicate 外候选(JWT role 只校验、jku 劫持、OA JSF 分号、newbeemall 分号、sobey 白名单)结论均为不同链，dedup_review 成立；被 reject 的 H2 RCE 草稿依据的 3 张现有卡(IN\IT 转义、AUTHZPWD=\ 吞并 FORBID_CREATION、INIT CREATE ALIAS)均 verified 且 conclusion 覆盖同 sink，reject 理由成立。未验证点：CTF 特定环境、原文未标注组件受影响版本与 CVE 号，卡 cve 为空、未设置 affected_versions(不猜)；frontmatter 无违规 sources/source，路径 web/generic/auth 合法。
---

## 一句话结论

JAX-RS（Jersey）的 `@PreMatching` 过滤器若用 `ContainerRequestContext.getUriInfo().getPath()` 取路径，并用 `isBaseFile(path) = !path.contains("/") && path.contains(".")` 这类「含点即静态文件」的启发式来跳过 JWT 校验，攻击者请求 `/api/testConnect;.` 即可让 `getPath()` 返回 `testConnect;.`（相对路径、不含 `/`、含 `.`）使 `isBaseFile` 为 true、整块跳过鉴权；Jersey 路由又会把 `;` 后的矩阵参数剥离、仍匹配 `@Path("/testConnect")`，从而未授权访问受保护路由。

## 原理

- `UriInfo.getPath()` 返回的是相对当前应用/servlet 的**解码后路径**，不带前导 `/`，且保留 `;` 矩阵参数（path parameters）；请求 `/api/testConnect;.` 时它得到 `testConnect;.`，既不含 `/` 又含 `.`。
- `isBaseFile` 的本意是放行 `xxx.js` / `xxx.css` 等静态资源，用「不含斜杠 + 含点」近似判断；分号注入的 `.` 让它把受保护接口误判为文件。
- 鉴权条件形如 `if (!isBaseFile(path) && !WHITELIST.contains(path)) { ...校验 Authorization: Bearer 与 JwtValidator.verifyJwt... }`：只要 `isBaseFile(path)` 为 true，整个 JWT 校验块被跳过（连白名单都不再比较），也不 `abortWithUnauthorized`。
- 路由侧：JAX-RS/Jersey 在匹配资源时会忽略路径段中 `;` 之后的矩阵参数，因此 `testConnect;.` 被归入 `testConnect` 资源；容器不会因 `;.` 返回 404。
- 根因是「鉴权看框架解码后的字符串、路由看去掉矩阵参数的资源路径」两者语义不一致，属于路径解析差异型鉴权绕过；`@PreMatching` 让过滤器在资源匹配前运行，进一步放大了差异。

## 触发条件

- Jersey / JAX-RS 应用，前置 `ContainerRequestFilter`（尤其 `@PreMatching`）使用 `getUriInfo().getPath()` 做鉴权判断。
- 放行逻辑依赖 `isBaseFile` 之类的「含点即文件」启发式，或白名单精确/子串匹配，且**未在判断前对 `;` 矩阵参数做剥离与路径归一化**。
- 存在受 JWT 保护的路由（如 `/api/testConnect`），且框架路由会忽略 `;` 后的矩阵参数。
- 攻击者无需任何账号或 token；只需能发 HTTP 请求。

## 利用步骤

1. 从 `web.xml` / 反编译源码确认 servlet 映射（如 `/api/*`）、过滤器白名单（如 `""`, `test`, `login`, `register`）与 `isBaseFile` 实现。
2. 确认 `filter()` 首行取路径的方式为 `containerRequestContext.getUriInfo().getPath()`，且 JWT 校验被 `isBaseFile`/白名单条件包裹。
3. 构造 `/api/<受保护路由>;.`（如 `/api/testConnect;.`）发 GET 试探：返回 405「HTTP 方法不被允许」而非 401，说明已绕过 JWT 且路由命中（405 只因方法不是 POST）。
4. 改成 POST 并带上业务表单参数（如 `jdbcUrl=...`），在**不带 Authorization 头**的情况下调用受保护接口，进入后续业务逻辑。

## PoC（最小化）

```http
GET /api/testConnect;. HTTP/1.1
Host: <target>
（无 Authorization 头）
→ 405「p请求的 HTTP 方法不被允许」，证明绕过 JWT 已到达 testConnect

POST /api/testConnect;. HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

jdbcUrl=<payload>
```

原文图 03 为 `GET /api/testConnect;. HTTP/1.1` 返回 405 页面，图 18 为 `POST /api/testConnect;.` 携带 `jdbcUrl` 成功触发后续 RCE；PoC 为通用最小形式。

## 变体与关联

- 同家族：`..;/` 归一化绕过白名单 `contains`（汉王 e 脸通）、`;common.js` 路径子串绕过（OA DownloadFilter/ProtectFilter）、Spring 自定义鉴权按原始 URI 判断、jshERP 前缀白名单 + Tomcat 分号路径参数归一化。区别在于本文不是白名单子串命中，而是 `getUriInfo().getPath()` 的框架 API 语义（相对路径、保留矩阵参数）叠加 `isBaseFile` 文件启发式。
- 与 H2 JDBC RCE 链组合：必须先绕过 JWT 才能访问 `/testConnect` 提交 `jdbcUrl`，是完整利用链的前置鉴权步骤。
- 其它 JAX-RS 实现（RESTEasy、CXF）或不同容器对 `;` 的处理需实测；也可用 `;a.js`、`;.`、`;%2e` 等变体试探。

## 检测与防御

- 鉴权判断前先规范化路径：剥离 `;` 矩阵参数、URL 解码、归一化 `.`/`..`、统一前导斜杠，再与白名单做**精确匹配**；不要用 `contains(".")` 之类启发式放行。
- 用 `getRequestURI()`/容器规范化结果与框架路径双重校验，或在资源方法上用注解/角色做二次鉴权，不依赖单一前置过滤器。
- 网关/WAF 拦截含 `;` 与 `/.` 的异常路径；监控「无 Authorization 头却访问受保护接口且返回非 401」的请求。
