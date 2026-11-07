---
id: web-java-framework-shiro-static-suffix-anon-pathvariable-bypass
title: Shiro /**/*.js 匿名规则与 Spring @PathVariable 语义差异：伪造静态后缀绕过 JWT
type: scenario
domain: web
path: web/java/framework/shiro
technique: shiro-static-suffix-anon-pathvariable-bypass
aliases:
- JeecgBoot 未授权
- .js 权限绕过
- /**/*.js 绕过
- 静态资源后缀绕过
- AntPathMatcher PathVariable 差异
- getDictItems 未授权
tags:
- java
- shiro
- spring
- spring-mvc
- auth-bypass
- path-matching
- antpathmatcher
- pathvariable
- jeecgboot
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: JeecgBoot ≤ 3.9.3（修复 v3.9.5）
verification:
  verified_by: verifier-V26
  verified_at: '2026-11-05T02:54:48+08:00'
  notes: 已对照原文与6张图核对：Shiro /**/*.js anon 与 Spring @PathVariable 语义差异、dictCode 后缀并入参数与正文一致；原路径 401 token 为空，追加 .js 后进入控制器（图02 实际为 code:500 操作失败，卡内已按非 401/进入业务逻辑表述，未把 500 当失败）；受影响 ≤3.9.3、修复 v3.9.5 与原文一致。未复跑 PoC。
---

## 一句话结论

Shiro 用 AntPathMatcher 的通配规则 `/**/*.js`（任意深度、以 `.js` 结尾即匿名放行）做鉴权，而 Spring MVC 的 `@RequestMapping("/getDictItems/{dictCode}")` 会把 URL 末尾的 `.js` 当成路径参数的一部分；攻击者在 `@PathVariable` 接口后追加 `.js`，Shiro 命中 anon 规则跳过 JWT 过滤器，Spring 仍路由到控制器，形成未授权访问。

## 原理

- Shiro 的 `filterChainDefinitionMap` 按 Ant 风格通配符匹配请求路径。`/**/*.js => anon` 的语义是“任意目录层级 + 以 `.js` 结尾”，因此 `/sys/dict/getDictItems/sys_user,realname,id.js` 命中 anon，`JwtFilter` 完全不执行。
- Spring MVC 的 `@RequestMapping("/getDictItems/{dictCode}")` 按路径变量匹配，`{dictCode}` 可以包含点号，于是同一个 URL 被路由到 `getDictItems`，`dictCode` 的值是 `sys_user,realname,id.js`。
- 两侧对“URL 是什么”的判定不一致：Shiro 看到的是“静态 JS 文件”，Spring 看到的是“带参数的业务接口”。鉴权与路由的语义差异就是根因，`.js` 只是让两者产生差异的载体。
- 该绕过只要求接口使用 `@PathVariable` 且 Shiro 存在全局后缀放行规则；不依赖 `;`、编码或版本级 CVE。
- 后缀被并入业务参数后，可能让下游 SQL/解析失败（响应 `code:500` 而非 401），这已足以证明请求进入控制器；若要让下游逻辑成功执行，还需用注释等方式消化后缀（见关联的 JeecgBoot filterSql 注入卡）。

## 触发条件

- 应用使用 Shiro 做认证，且 `filterChainDefinitionMap` 中存在 `/**/*.js`、`/**/*.css`、`/**/*.png`、`/**/*.html` 等全局后缀 anon 规则。
- 受保护接口使用 Spring MVC `@PathVariable`（或能容忍路径末尾多余后缀的映射）。
- 接口自身没有在 Controller/Service 层再次校验会话或角色。
- 目标版本未采用按目录放行的修复（如 JeecgBoot ≤ 3.9.3）。

## 利用步骤

1. 确认目标使用 Shiro：`rememberMe=deleteMe`、登录跳转、Shiro 错误页等特征。
2. 找一个未登录访问返回 401/302 的 `@PathVariable` 接口，例如字典接口 `/sys/dict/getDictItems/{dictCode}`。
3. 在路径末尾追加 `.js`（或其他被全局放行的后缀），保持参数内容不变。
4. 对比响应：原路径返回 `token为空`/401，追加后缀后不再返回 401，而是进入控制器（可能是业务错误、空结果或正常数据）。
5. 若进入控制器但业务因后缀失败，尝试用 `#`、`;`、`%00` 等让下游忽略后缀；或改用其他不解析后缀的接口。
6. 成功后匿名调用该接口，结合接口能力读取/操作数据。

## PoC

```http
# 未绕过：JWT 拦截
GET /jeecg-boot/sys/dict/getDictItems/sys_user,realname,id HTTP/1.1
Host: target:8080
# => {"success":false,"message":"token为空!","code":401}

# 追加 .js：Shiro 命中 /**/*.js anon，Spring 仍路由到 getDictItems
GET /jeecg-boot/sys/dict/getDictItems/sys_user,realname,id.js HTTP/1.1
Host: target:8080
# => 不再返回 401；请求进入控制器（示例响应 code:500，因 .js 被拼进下游 SQL）
```

```text
# 判断标准：响应从“token为空/401”变为业务响应（200/500 均可），
# 且响应体不再包含 JWT 拦截信息。
```

## 变体与关联

- 变体：`/**/*.css`、`/**/*.png`、`/**/*.html` 等其它全局后缀规则同样可被利用；后缀不一定是 `.js`。
- 变体：`@PathVariable` 之外的接口若把末尾段当普通参数（如 `/{name}`、`/*`），也可能容忍伪造后缀。
- 变体：配合 `#` 注释吞掉后缀，使下游 SQL/表达式继续执行（见关联卡）。
- 关联：[[web-java-framework-jeecgboot-dict-filter-sql-injection]]（同一组合链的 SQL 注入半边）。
- 关联：[[web-java-framework-shiro-spring-path-auth-bypass]]（同一“Shiro 与 Spring 路径语义不一致”家族，但那条卡讲 `;`、编码与 trim 差异；本条是通配后缀规则与 `@PathVariable` 的差异，机制不同）。
- 边界：若 Shiro 规则改为按目录精确放行（`/static/**`、`/js/**`），或接口在 Controller 内二次鉴权，该绕过不成立。

## 检测与防御

- 修复：不要用 `/**/*.js` 这类全局后缀做匿名放行；改为按目录精确放行（`/static/**`、`/assets/**`），并确保放行目录下不存在业务接口。
- 修复：鉴权匹配与 Spring 路由使用同一套路径解析语义；对 `@PathVariable` 接口做后缀白名单/规范化，拒绝路径参数中的 `.js`、`.css` 等静态后缀。
- 加固：Controller/Service 层对敏感接口二次校验会话与角色；Shiro 过滤器链对未知路径默认拒绝（fail-closed）。
- 检测：同一接口在追加 `.js`/`.css` 后从 401 变为 200/500；`@PathVariable` 参数中出现静态文件后缀；匿名请求命中本应受保护的控制器；Shiro 日志中 anon 放行与 Spring 路由日志不一致。
