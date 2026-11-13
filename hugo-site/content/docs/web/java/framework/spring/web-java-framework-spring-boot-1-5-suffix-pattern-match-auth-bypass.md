---
id: web-java-framework-spring-boot-1-5-suffix-pattern-match-auth-bypass
title: Spring Boot ≤1.5.22 / Spring MVC ≤4.3.25 useSuffixPatternMatch 默认开启：/admin. 与 /admin.随机串 绕过 Spring Security 授权
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-mvc-suffix-pattern-match-auth-bypass
tags:
- java
- spring
- spring-mvc
- spring-security
- auth-bypass
- suffix-pattern
- version-specific
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
affected_versions: Spring Boot <= 1.5.22.RELEASE（对应 Spring MVC <= 4.3.25，原文实测）
verification:
  verified_by: verifier-V611
  verified_at: '2026-11-12T19:47:01+08:00'
  notes: 已对照原文全文与37张图核对：图13红框Spring Boot 1.5.22.RELEASE、图14 spring-webmvc 4.3.25.RELEASE、图15反编译getMatchingPattern显示useSuffixPatternMatch=true且lookupPath=/admin.123456789、图19配置antMatchers("/admin/**")+"/test/**"permitAll、图20控制器/admin、图21/22 /admin与/admin/均403、图23/24 /admin.与/admin.123456789均200 hello admin。原文明确写“需要满足条件：springboot <= 1.5.22.RELEASE”与“mvc <= 4.3.25”，affected_versions按原文设置。已修正原文/卡片与截图不一致处：5.2.15截图框架字段为true而正文称默认False，原理句改为“原文实测该变体不可利用+注明截图字段为true及Boot配置影响”；边界句改为“Spring Boot 2.x实测不可用；Spring MVC 5.3+默认关闭”；移除悬空链接。dedup候选均related非同链。未复跑靶场/PoC。
url: /docs/web/java/framework/spring/web-java-framework-spring-boot-1-5-suffix-pattern-match-auth-bypass/
draft: false
kb_aliases:
- suffixPatternMatch 权限绕过
- /admin. 绕过
- Spring Boot 1.5.22 绕过
- Spring MVC 4.3.25 后缀匹配
- 点号后缀路由绕过
---

## 一句话结论

在 Spring Boot ≤1.5.22.RELEASE（Spring MVC ≤4.3.25）中，`RequestMappingHandlerMapping.useSuffixPatternMatch` 默认为 true：映射为 `/admin` 的控制器会同时匹配 `/admin.`、`/admin.123456789` 等带点后缀的路径；而 Spring Security 的 `antMatchers("/admin/**")` 不匹配这些点号变体，未命中规则后请求被放行，匿名即可调用管理员接口。

## 原理

- Spring MVC 旧版本的 `RequestMappingHandlerMapping` 默认 `useSuffixPatternMatch=true`：当映射模式不含 `.` 时，会尝试用 `pattern + ".*"` 再去匹配请求路径（源码中 `getMatchingPattern` 逻辑），于是 `/admin` 的处理器也接受 `/admin.` 与 `/admin.<任意字符>`。
- Spring Security 的 `antMatchers("/admin/**")` 用 Ant 模式匹配原始请求路径，点号后缀路径不属于 `/admin/**`，因此不落入 ADMIN 规则。
- 规则按顺序匹配；若没有其他命中规则（或后置 `/**` 放行），未匹配请求被放行/落入低权限分支，而 MVC 随后把该请求交给 `/admin` 处理器，造成越权。
- 版本边界很重要：原文在 spring-webmvc 5.2.15（Spring Boot 2.3.12）与 5.0.4 环境实测该后缀变体无法利用（作者据此判断 `useSuffixPatternMatch` 默认已关；其截图显示 5.2.15 框架字段仍为 true，实际是否生效还取决于 Spring Boot 的路径匹配配置），只有 Spring Boot ≤1.5.22.RELEASE（Spring MVC ≤4.3.25）组合可复现；网上“<5.3 即为 true”的说法不准确。
- 修复是升级版本；或显式关闭 `useSuffixPatternMatch`，并让安全规则采用与 MVC 一致的 matcher。

## 触发条件

- 目标使用 Spring Boot ≤1.5.22.RELEASE / Spring MVC ≤4.3.25（或其他 `useSuffixPatternMatch` 默认为 true 的旧组合）。
- 安全配置按规范路径保护（如 `antMatchers("/admin/**")`），未覆盖点号后缀变体。
- 控制器映射为不带点号的路径（如 `@RequestMapping("/admin")`）。
- 未配置 `anyRequest().authenticated()` 等兜底规则，或兜底为放行。

## 利用步骤

1. 确认 Spring Boot / Spring MVC 版本（pom、actuator、报错页、依赖树）。
2. 正常访问 `/admin`，确认被 403/302 拦截。
3. 请求 `/admin.` 或 `/admin.123456789`，若返回管理员内容说明绕过成功。
4. 继续访问后台接口；删除 Spring Security 对同一路径的拦截日志可辅助验证。

## PoC

```xml
<!-- 可复现的旧版本组合 -->
<properties>
  <spring-boot.version>1.5.22.RELEASE</spring-boot.version>
</properties>
<!-- 依赖树中 spring-webmvc <= 4.3.25.RELEASE -->
```

```http
GET /admin HTTP/1.1
Host: target
# 403 Access Denied

GET /admin.123456789 HTTP/1.1
Host: target
# 200 hello admin（MVC 后缀匹配路由到 /admin，安全规则未命中）
```

## 变体与关联

- 变体：`/admin.`、`/admin.任意后缀` 均可；不同 Spring 版本的 suffix 匹配行为不同，需实测确认。
- 变体：同属“匹配器与路由语义差异”的还有 antMatchers 末尾斜杠、regexMatchers 空查询串、`%0d`（CVE-2022-22978）。
- 关联：[[web-java-framework-spring-security-antmatcher-single-star-path-bypass]]、[[web-java-framework-spring-security-regexmatchers-query-trailing-slash-bypass]]；antMatchers 精确路径 + 末尾斜杠 `/admin/` 属同一“匹配器未覆盖变体”原语，未单独建卡。
- 边界：Spring Boot 2.x 环境实测不可用（5.0.4/5.2.15）；Spring MVC 5.3+ 默认关闭该特性；配置了 `anyRequest().authenticated()` 兜底或显式关闭后缀匹配时不成立。

## 检测与防御

- 检测：受保护路径出现带点号后缀的请求并返回 200；`/admin.xxx` 与 `/admin` 状态码不一致；旧版本 Spring Boot 应用日志中出现异常后缀路径。
- 防御：升级 Spring Boot/Spring MVC；显式设置 `useSuffixPatternMatch=false`、`useRegisteredSuffixPatternMatch=true`；受保护路径使用 `/**` 或 `mvcMatchers`/`requestMatchers`，并以 `anyRequest().authenticated()` 兜底。
