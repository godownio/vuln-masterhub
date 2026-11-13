---
id: web-java-framework-spring-security-regexmatchers-crlf-path-bypass
title: Spring Security regexMatchers 正则授权遇 %0d 换行绕过：matcher 不匹配而 MVC 仍路由到 /admin/*（CVE-2022-22978）
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-security-regexmatcher-crlf-bypass
aliases:
- regexMatchers 绕过
- RegexRequestMatcher 换行绕过
- '%0d 权限绕过'
- CVE-2022-22978
- Spring Security 授权绕过
tags:
- java
- spring
- spring-security
- auth-bypass
- regex
- crlf
- url-encoding
cve:
- CVE-2022-22978
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: Spring Security 5.6.3（原文明确：完全符合漏洞版本；CVE-2022-22978 影响 5.6.x < 5.6.4、5.5.x < 5.5.7）
verification:
  verified_by: verifier-V512
  verified_at: '2026-11-11T11:28:01+08:00'
  notes: 已对照原文与全部28张图（图14 pom、图15 AuthConfig 用 regexMatchers({"/admin/.*"}).authenticated()、图16 直接 POST /admin/user 302→/login、图17 POST /admin/user%0d 未认证 200 WellDone、图18 /login 取得 JSESSIONID、图19 带 JSESSIONID 亦 200、图20 /admin/{name} 控制器）核对：%0d 换行使 RegexRequestMatcher 正则不匹配而 MVC 仍路由到 /admin/{name} 的授权绕过与截图一致；原文只写 Spring Security 5.6.3『完全符合漏洞版本』并未点名 CVE-2022-22978，CVE 编号为 worker 依特征补充，经核对与公开 CVE-2022-22978（RegexRequestMatcher 换行绕过，影响 5.5.x<5.5.7、5.6.x<5.6.4）一致，可保留；verifier 将 PoC 由 GET 改回原文一致的 POST+data 请求。affected_versions 已按原文明确『5.6.3 属漏洞版本』及 CVE 范围设置。dedup 唯一 related 为 Shiro+Spring 路径解析差异卡，框架与触发字符不同，非同链。frontmatter 无 sources/source_url。未验证点：未复跑 Spring 靶场；CVE 影响区间来自公开 CVE 信息而非原文。
---

## 一句话结论

Spring Security 在受影响版本（原文环境 5.6.3；CVE-2022-22978 影响 5.5.x < 5.5.7、5.6.x < 5.6.4）中用 `regexMatchers("^/admin/.*")` 一类正则做路径授权时，在受保护路径后追加解码为回车/换行的 `%0d`（或 `%0d%0a`）：Java 正则 `.` 默认不匹配行终结符，`RegexRequestMatcher` 判定不匹配、授权规则被跳过，而 Servlet 容器与 Spring MVC 仍将请求路由到受保护控制器，形成未授权访问。

## 原理

- `authorizeRequests().regexMatchers(...)`/`RegexRequestMatcher` 用 `Pattern` 对请求 URI 做整体匹配；路径授权规则通常写成 `^/admin/.*` 这类依赖 `.` 覆盖全路径的正则。
- Java 正则的 `.` 在默认（无 `DOTALL`）模式下不匹配 `\n`、`\r` 等行终结符。URL 中的 `%0d` 被解码为 CR 后，`/admin/user%0d` 的匹配串包含换行，`^/admin/.*` 无法整体匹配，matcher 返回 false。
- 规则未命中即不执行该条授权约束（配置模型是"匹配哪条规则就应用哪条"），请求继续向下传递；Servlet 容器/Spring MVC 在路由阶段对路径做自身解析（对尾部控制字符截断或规范化），最终仍映射到 `/admin/user` 的控制器方法。
- 危害成立的关键是"授权层与路由层对同一 URL 的解析不一致"：安全层认为它不是 /admin 路径，业务层却按 /admin 路径处理。

## 触发条件

- 应用使用 Spring Security 的 `regexMatchers`（或直接使用 `RegexRequestMatcher`）做路径授权，且正则依赖 `.`/`.*` 匹配路径。
- 版本在 CVE-2022-22978 影响范围：Spring Security 5.6.x < 5.6.4、5.5.x < 5.5.7（原文环境 5.6.3）。
- 前端容器/WAF 未拒绝路径中的 `%0d`/`%0a` 编码，且路由时对控制字符做截断或忽略处理。

## 利用步骤

1. 识别受 Spring Security 保护的路径前缀（如 `/admin/`）与被 `regexMatchers` 保护的模式。
2. 确认 Spring Security 版本在受影响范围（可从错误页、依赖信息或指纹判断）。
3. 构造 `%0d` 加在受保护路径之后、或用 `%0d%0a` 包裹：`POST /admin/user%0d HTTP/1.1`（原请求同时带 `data=` 参数）。
4. 未认证/低权限请求该 URL：matcher 不匹配跳过授权，MVC 仍进入 `/admin/user` 控制器，返回业务数据（原文明示返回 `WellDone`）。

## PoC

```http
POST /admin/user%0d HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 21
Connection: close

# data = URL 编码后的 base64(JSON)，此处 base64('{"a":1}') = eyJhIjoxfQ==
data=eyJhIjoxfQ%3D%3D
```

原环境为 JDK 8 + Spring Security 5.6.3：直接访问 `/admin/user` 返回 302 跳登录，而 `/admin/user%0d` 未登录即返回控制器结果；使用普通账号登录后带 JSESSIONID 同样可复现。

## 变体与关联

- 变体：`%0a`、`%0d%0a` 混合；不同 Servlet 容器对尾部控制字符的截断/保留行为不同，需按目标容器调整。
- 变体：`RegexRequestMatcher` 被直接用于自定义 Filter 时同样受影响。
- 关联：[[web-java-framework-spring-custom-auth-path-parsing-bypass]]（自定义鉴权按原始 URI 判断导致的路径解析差异，根因同为"授权层与路由层解析不一致"）；[[web-java-framework-shiro-spring-path-auth-bypass]]（其他框架的路径授权绕过）。
- 限制：修复版本（5.6.4+/5.5.7+）对匹配做了加固；使用 AntPathRequestMatcher 或严格防火墙的应用可能不受影响。

## 检测与防御

- 升级 Spring Security 至 5.6.4/5.5.7 或更高版本。
- 避免用正则匹配路径做授权：优先使用规范化后的路径匹配（`requestMatchers` + Ant/MVC matcher），并对路径统一做规范化后再判断。
- 在网关/WAF 层拒绝 URL 路径中的 `%0d`、`%0a` 及裸控制字符；启用 Spring Security 的 `StrictHttpFirewall` 并验证其对编码换行的拒绝行为。
- 检测：审计日志中出现带 `%0d`/`%0a` 的 200 响应请求；对同一路径的编码变体做回归测试。
