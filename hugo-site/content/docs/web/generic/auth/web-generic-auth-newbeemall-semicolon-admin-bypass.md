---
id: web-generic-auth-newbeemall-semicolon-admin-bypass
title: NewBeeMall 后台拦截器用 getRequestURI 前缀判断：/;/admin/index 分号绕过进入后台
type: scenario
domain: web
path: web/generic/auth
technique: getrequesturi-semicolon-admin-path-bypass
tags:
- auth-bypass
- java
- spring
- interceptor
- path-confusion
- semicolon
- newbee-mall
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V51
  verified_at: '2026-11-05T09:08:32+08:00'
  notes: 已对照原文与32张图核对：图05/06 直接 GET /admin/index 返回 302 到 /admin/login；GET /;/admin/index 返回 200 后台 HTML（newbee-mall 后台管理系统），图07 breakpoint 显示 uri=/;/admin/upload/file 且 startsWith(/admin) 为 false 放行，与卡一致。未验证点：未本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-newbeemall-semicolon-admin-bypass/
draft: false
kb_aliases:
- NewBeeMall 后台绕过
- 分号绕过 admin 鉴权
- getRequestURI 路径判断绕过
- /;/admin/index
- AdminLoginInterceptor 绕过
- Spring MVC 权限绕过
---

## 一句话结论

NewBeeMall 的 `AdminLoginInterceptor` 用 `request.getRequestURI()` 的原始字符串做 `startsWith("/admin")` 判断，而 Tomcat/Spring 会把路径参数分号 `;` 归一化后映射到真实路由；请求 `GET /;/admin/index` 的原始 URI 不以 `/admin` 开头，拦截器直接放行，Spring 却把它路由到后台首页，未登录即可进入后台。

## 原理

- 拦截器代码：`String uri = request.getRequestURI(); if (uri.startsWith("/admin") && null == request.getSession().getAttribute("loginUser")) { ... redirect /admin/login; return false; } else { return true; }`。
- 缺陷：`getRequestURI()` 返回客户端请求行中的原始路径，不做归一化；而 Servlet 容器在路由前会处理路径参数（`;` 之后到下一个 `/` 之前的内容）和重复斜杠等。两者对“同一个请求”的路径理解不一致。
- 绕过：请求 `GET /;/admin/index`。原始 URI 是 `/;/admin/index`，`startsWith("/admin")` 为 false，拦截器返回 true；Tomcat 去掉空路径段/分号参数后，Spring MVC 把请求映射到 `/admin/index`，返回后台页面（文章实测 200 与后台 HTML）。
- 对照：直接 `GET /admin/index` 原始 URI 以 `/admin` 开头，未登录时返回 302 跳转 `/admin/login`（文章截图）。
- 危害：未登录访问全部后台路由（商品管理、订单管理、上传等），配合后台文件上传/后台 SQL 注入可进一步 getshell 或拖库。
- 同类思路：`//admin/index`、`/admin/..;/admin/index`、`/.;/admin/index` 等路径混淆变体，取决于容器归一化行为。

## 触发条件

- 目标为 NewBeeMall（或同款 Spring MVC 代码），`AdminLoginInterceptor` 按 `getRequestURI().startsWith("/admin")` 鉴权。
- 容器/框架对 `;` 路径参数或重复斜杠做归一化，使原始 URI 与最终路由不一致。
- 后台路由实际存在（如 `/admin/index`、`/admin/goods/list`、`/admin/upload/file`）。

## 利用步骤

1. 直接访问 `/admin/index`，确认未登录 302 到 `/admin/login`。
2. 访问 `/;/admin/index`，观察是否 200 并返回后台首页 HTML。
3. 将同样的前缀混淆用于其他后台接口，如 `/;/admin/goods/list?...`、`/;/admin/upload/file`。
4. 结合后台功能进一步利用（上传、SQL 注入、订单操作等）。

## PoC

```http
GET /admin/index HTTP/1.1
Host: target.example:28089
```

```text
# 预期（未登录）：HTTP/1.1 302，Location: http://target/admin/login
```

```http
GET /;/admin/index HTTP/1.1
Host: target.example:28089
```

```text
# 预期：HTTP/1.1 200，返回 newbee-mall 后台管理系统 HTML（含 /admin/dist/... 静态资源）。
# 原始 URI "/;/admin/index" 不以 /admin 开头，拦截器放行；容器归一化后路由到 /admin/index。
```

## 变体与关联

- 变体：`//admin/index`（重复斜杠）、`/admin/..;/admin/index`、`/.;/admin/index` 等，按目标容器归一化规则测试。
- 变体：同类 `getRequestURI` + `startsWith` 判断在前后台其他拦截器中也存在，可一并绕过。
- 关联：[[web-generic-auth-jeewms-authinterceptor-whitelist-regex-contains-bypass]]（拦截器路径匹配缺陷）；[[web-generic-auth-oa-jsf-sessionfilter-loginjsf-semicolon-bypass]]（分号绕过登录过滤器）；[[web-generic-auth-xiahuia-erp-logcostfilter-contains-path-bypass]]（路径包含判断绕过）。
- 边界：文章在本地 NewBeeMall 环境实测 `/;/admin/index` 返回后台页面；未给出目标版本号。

## 检测与防御

- 检测：审计所有用 `getRequestURI()`/`getServletPath()` 原始字符串做前缀/包含判断的鉴权代码；日志中关注含 `;`、`//`、`..;` 的 URI 与后台路由的组合。
- 修复：不要用原始 URI 做鉴权；改用容器归一化后的 `getServletPath()` 并做规范化（去除路径参数、解码、折叠斜杠）后再比较；或用 Spring Security 的 `AntPathRequestMatcher`/`MvcRequestMatcher` 统一鉴权。
- 加固：在反向代理/WAF 层拒绝含异常路径参数的请求；后台路由与前台分域；对所有后台接口做服务端角色校验，不只依赖拦截器前缀。
