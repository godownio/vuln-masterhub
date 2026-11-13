---
id: web-java-framework-spring-security-regexmatchers-query-trailing-slash-bypass
title: Spring Security regexMatchers 正则未覆盖查询串与末尾斜杠：/admin? 与 /admin/ 绕过授权
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-security-regexmatchers-query-trailing-slash-bypass
aliases:
- regexMatchers 空查询串绕过
- /admin? 绕过 Spring Security
- regexMatchers 正则不完整
- 尾斜杠 regex 绕过
- Spring Security 正则匹配不完整
tags:
- java
- spring
- spring-security
- auth-bypass
- regexmatchers
- path-matching
- query-string
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V611
  verified_at: '2026-11-12T19:46:59+08:00'
  notes: 已对照原文全文与37张图核对：图02/03为antMatchers("/admin")+"/**"配置与控制器，图05/06为/admin 403与/admin/ 200；图07截图实为regexMatchers("/admin")+regexMatchers("/**").permitAll()，正文代码块误写成/manager+anonymous，卡片按截图与实测编写；图08/09/10为/admin 403、/admin? 200、/admin/ 200。已修正两处：RegexRequestMatcher追加条件应为查询串非null（空串也追加）而非“非空”；移除指向已reject草稿的悬空链接antmatchers-trailing-slash。dedup：候选regexmatchers-crlf（CVE-2022-22978，依赖%0d与版本区间）与antmatcher-single-star（Ant单星号层级）均非同链，本卡不依赖CVE版本，独立成卡成立。affected_versions未设（配置类）。frontmatter无sources/source_url。未复跑靶场/PoC。
---

## 一句话结论

当 Spring Security 用 `regexMatchers("/admin").access("hasRole('ADMIN')")` 这类未覆盖路径变体的正则保护路由，并在后面用 `regexMatchers("/**").permitAll()` 兜底时，请求 `/admin?`（空查询串）或 `/admin/`（末尾斜杠）不会匹配受保护正则、落入 permitAll，而 Spring MVC 仍会把它们路由到 `/admin` 控制器，从而匿名获得管理员功能。

## 原理

- `RegexRequestMatcher` 构造用于匹配的字符串时，会把 `servletPath + pathInfo` 与查询串拼在一起：查询串非 null 时追加 `"?" + query`（空串也会追加）。请求 `/admin?` 的查询串为空字符串（非 null），参与匹配的字符串成为 `/admin?`。
- 正则 `/admin` 只匹配字面 `/admin`；`/admin?` 与 `/admin/` 都不匹配，因此该请求不命中受保护规则，落到后面的 `regexMatchers("/**").permitAll()`。
- Spring MVC 路由时只看路径部分（查询串不参与），并按尾斜杠匹配把 `/admin/` 规范化到 `/admin`；于是被保护的处理方法被匿名调用。
- 根因同样是“安全匹配器看到的字符串”与“MVC 路由使用的路径”不一致；与 CVE-2022-22978 的 `%0d` 换行绕过同属 RegexRequestMatcher 路径差异，但本场景是正则本身写死而未覆盖变体，不依赖特定漏洞版本。
- 修复：把正则写完整（如 `/admin.*`）、使用 `mvcMatchers`/`requestMatchers`，并避免用 `/**` 全放行兜底。

## 触发条件

- 配置使用精确正则 `regexMatchers("/admin")` 等，而不是 `/admin.*`。
- 后面存在 `regexMatchers("/**")` 或 `antMatchers("/**").permitAll()` 兜底。
- Spring MVC 开启尾斜杠匹配，且控制器映射为 `/admin`。
- 攻击者可未认证访问目标路径。

## 利用步骤

1. 从源码确认 `regexMatchers("/admin")` 与兜底 permitAll 的配置形态。
2. 正常访问 `/admin` 确认 403。
3. 依次请求 `/admin?`、`/admin/`，观察是否返回 200 与管理员内容。
4. 成功后按后台功能继续操作；必要时尝试 `%0a/%0d` 等其他路径变体（对应 CVE-2022-22978）。

## PoC

```java
// 存在问题的配置
http.csrf().disable()
    .authorizeRequests()
    .regexMatchers("/admin").access("hasRole('ADMIN')")
    .regexMatchers("/**").permitAll();
```

```http
GET /admin HTTP/1.1
Host: target
# 403 Access Denied

GET /admin? HTTP/1.1
Host: target
# 200 hello admin（空查询串使正则不匹配）

GET /admin/ HTTP/1.1
Host: target
# 200 hello admin（尾斜杠使正则不匹配）
```

## 变体与关联

- 变体：`%0a`/`%0d` 换行同样让 RegexRequestMatcher 不匹配而 MVC 仍路由，见 CVE-2022-22978 卡。
- 变体：antMatchers 精确路径遇末尾斜杠、低版本 suffixPatternMatch 的 `/admin.`，同属“匹配器与路由语义差异”。
- 关联：[[web-java-framework-spring-security-regexmatchers-crlf-path-bypass]]、[[web-java-framework-spring-security-antmatcher-single-star-path-bypass]]；antMatchers 精确路径 + 末尾斜杠 `/admin/` 属同一“匹配器未覆盖变体”原语，未单独建卡。
- 边界：正则完整覆盖变体、使用 `mvcMatchers`/`requestMatchers`、兜底为 `denyAll()` 或关闭尾斜杠匹配时不成立。

## 检测与防御

- 检测：受保护路径出现带空查询串或尾斜杠的请求并返回 200；同一路径变体与规范路径的状态码不一致。
- 防御：正则写成完整匹配并在末尾锚定；优先使用 `mvcMatchers`/`requestMatchers`；末尾使用 `anyRequest().authenticated()`/`denyAll()` 兜底；升级并关闭尾斜杠匹配。
