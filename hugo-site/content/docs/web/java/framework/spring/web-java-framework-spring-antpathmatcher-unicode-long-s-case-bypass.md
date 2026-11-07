---
id: web-java-framework-spring-antpathmatcher-unicode-long-s-case-bypass
title: Spring AntPathMatcher 大小写不敏感 + Unicode ſ：路由命中 suctf、拦截器却漏判
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-antpathmatcher-unicode-long-s-case-bypass
tags:
- java
- spring
- spring-mvc
- auth-bypass
- unicode
- case-folding
- path-matcher
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V123
  verified_at: '2026-11-06T04:22:35+08:00'
  notes: 已对照原文与23张图核对：WebConfig 设置 AntPathMatcher.setCaseSensitive(false)、matchStrings 走 equalsIgnoreCase、ſ(U+017F).toUpperCase()=S、拦截器 toLowerCase/ASCII 正则不识别 ſ，请求 /api/connection/%C5%BFuctf 命中 @PostMapping(/suctf) 并绕过 403，均与原文/截图一致。原文未给 Spring 版本，未设置 versions；frontmatter 无 sources/source_url。未验证点：本库未复跑该 CTF 环境。
url: /docs/web/java/framework/spring/web-java-framework-spring-antpathmatcher-unicode-long-s-case-bypass/
draft: false
kb_aliases:
- Spring 路由大小写绕过
- Unicode long s 绕过
- ſuctf 鉴权绕过
- AntPathMatcher caseSensitive false
- equalsIgnoreCase 与 toLowerCase 差异
---

## 一句话结论

Spring MVC 把 `AntPathMatcher` 设为 `caseSensitive=false` 后，路由匹配用 `equalsIgnoreCase`（Unicode 大小写折叠，`ſ`→`S`），而拦截器黑名单用 `toLowerCase()`/ASCII 正则（`ſ` 不会变成 `s`）；请求 `/api/connection/ſuctf` 既能命中受保护路由，又能绕过只认 `suctf` 的鉴权拦截器。

## 原理

- 路由注册：`WebConfig` 中 `AntPathMatcher.setCaseSensitive(false)`，并注册 `PathInterceptor` 拦截 `/**`。受保护接口为 `POST /api/connection/suctf`。
- 路由匹配：`AntPathMatcher.matchStrings` 在 `caseSensitive=false` 时调用 `String.equalsIgnoreCase`；`equalsIgnoreCase` 先按原字符比较，失败后依次比较 `Character.toUpperCase` 和 `toLowerCase`。Unicode 字符 `ſ`（U+017F LATIN SMALL LETTER LONG S）的 `toUpperCase` 是 `S`，因此 `ſuctf` 与 `suctf` 在路由层相等。
- 拦截器判断：
  ```java
  servletPath.matches("(?i).*s\\W*u\\W*c\\W*t\\W*f.*")
    || servletPath.toLowerCase().contains("suctf")
    || servletPath.toLowerCase().replaceAll("[^a-z0-9]", "").contains("suctf")
  ```
  - `toLowerCase()` 把 `ſ` 保持为 `ſ`，不产生 `s`，`contains("suctf")` 为 false；
  - `replaceAll("[^a-z0-9]", "")` 会把非 ASCII 的 `ſ` 删掉，剩下 `uctf`，仍不含 `suctf`；
  - `(?i)` 默认只做 ASCII 大小写折叠（未加 `UNICODE_CASE`），`s` 不匹配 `ſ`，正则也失败。
- 结果：路由层认为路径是 `suctf`，鉴权层认为不是，形成“同一路径两种解释”的 parser differential，绕过拦截器访问受保护接口。
- 为什么可行：大小写不敏感路由扩大了等价字符集；而黑名单只针对 ASCII 小写形式，未做 Unicode 归一化/一致的大小写折叠。

## 触发条件

- Spring MVC 使用 `AntPathMatcher` 且 `setCaseSensitive(false)`（或等价的大小写不敏感路由）。
- 鉴权/拦截器用 `toLowerCase()`、ASCII 正则或 `replaceAll("[^a-z0-9]")` 等只处理 ASCII 的黑名单。
- 受保护路由路径包含被黑名单匹配的关键字（如 `suctf`），且攻击者可控制请求路径。
- 容器/URL 解码允许 `%C5%BF` 等 Unicode 字符进入 `servletPath`。

## 利用步骤

1. 找到被拦截器保护的路由（如 `/api/connection/suctf`），确认拦截器规则只匹配 ASCII `suctf`。
2. 确认路由匹配大小写不敏感（尝试 `/api/connection/SUCTF` 是否仍命中）。
3. 用 Unicode long s 替换 `s`：`/api/connection/ſuctf`，URL 编码为 `/api/connection/%C5%BFuctf`。
4. 发送请求；若路由命中且拦截器未 403，即绕过成功。
5. 继续利用该接口（如 JDBC 连接测试）完成后续攻击。
6. 若 `ſ` 被容器/代理拒绝，尝试其他大小写折叠字符或编码变体。

## PoC

```http
POST /api/connection/%C5%BFuctf HTTP/1.1
Host: target:8080
Content-Type: application/json

{"urlType":"jdbcUrl","driver":"com.kingbase8.Driver","jdbcUrl":"jdbc:kingbase8:127.0.0.1:54321/test","username":"postgres","password":"x"}
```

说明：PoC 为原文请求的结构化复现，未在本机执行；原文用 `%C5%BFuctf` 绕过 `PathInterceptor` 后进入 JDBC 连接测试接口。

## 变体与关联

- 变体（字符）：`ſ`（U+017F）、开尔文符号 `K`、全角字母、土耳其无点 `ı`、其他 Unicode 大小写折叠字符；取决于路由/拦截器使用的折叠规则。
- 变体（匹配器）：`AntPathMatcher` vs `PathPatternParser`、`caseSensitive=false`、后缀匹配、矩阵参数/分号；不同版本的归一化行为不同。
- 关联：[[web-generic-auth-interceptor-login-prefix-dotdot-bypass]]（拦截器前缀/`..` 绕过）；[[web-generic-auth-newbeemall-semicolon-admin-bypass]]（分号路径绕过）；[[web-java-framework-shiro-static-suffix-anon-pathvariable-bypass]]（Shiro 与 Spring 路径语义差异）。
- 边界：路由大小写敏感、拦截器做 Unicode 归一化/统一大小写折叠、容器拒绝非 ASCII 路径、或鉴权在路由层而非拦截器时，本方法不成立。

## 检测与防御

- 检测：请求路径中出现非 ASCII 大小写变体（`ſ`、`K`、全角字母）且命中受保护路由；同一路由的 403 与 200 响应差异；拦截器日志中出现原始路径与规范化路径不一致。
- 防御：鉴权不要依赖路径黑名单；在路由层做统一鉴权（Spring Security `authorizeHttpRequests`/方法级注解），而不是拦截器字符串匹配。
- 加固：路径先做 Unicode NFKC 归一化并统一大小写折叠，再同时检查原始路径与归一化路径；路由保持 `caseSensitive=true`；对非 ASCII 路径做拒绝/告警。
