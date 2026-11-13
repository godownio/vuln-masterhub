---
id: web-java-framework-spring-security-antmatcher-single-star-path-bypass
title: Spring Security antMatchers("/admin/*") 只匹配单层路径：深层 /admin/xxx/yyy 落入 anyRequest().permitAll() 未授权访问
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-security-antmatcher-single-star-path-bypass
tags:
- java
- spring
- spring-security
- auth-bypass
- antmatcher
- path-pattern
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V519
  verified_at: '2026-11-11T13:00:55+08:00'
  notes: 已对照原文与截图核对：img36 配置为 .antMatchers(new String[]{"/admin/*"}).hasRole("ADMIN").anyRequest().permitAll()，与卡中 PoC 一致；img37 显示 AdminController 类级 @RequestMapping("/admin") 且 /admin 根路由未直接映射；img38 无凭证 GET /admin/user/hello 返回 200 hello admin，绕过成立。已修正原文/卡片中一处误述：AntPathMatcher 的 /admin/* 只能匹配 /admin/ 下一层单段路径，/admin.do 与 /admin 因无斜杠子段并不匹配（已同步修改库内卡与 staging）。dedup 候选 regexMatchers-CRLF 为正则换行机制，非同链。原文未给版本区间，affected_versions 留空。
url: /docs/web/java/framework/spring/web-java-framework-spring-security-antmatcher-single-star-path-bypass/
draft: false
kb_aliases:
- antMatchers 单星号绕过
- antMatcher 只匹配一层
- Spring Security 路径匹配绕过
- /admin/* 权限绕过
- anyRequest permitAll 风险
---

## 一句话结论

Spring Security 配置 `.antMatchers("/admin/*").hasRole("ADMIN")` 时，Ant 风格单个 `*` 只匹配一层路径段，无法匹配 `/admin/user/hello` 这类多级子路径；若后面跟了 `.anyRequest().permitAll()`（或其它放行规则），受保护前缀下的深层路由会完全跳过权限校验，未认证用户可直接访问管理功能。

## 原理

- **Ant 通配符语义**：`AntPathMatcher` 中 `?` 匹配单字符，`*` 匹配零或多个字符但**不跨越 `/`**，`**` 才匹配任意层目录。因此 `/admin/*` 只能匹配 `/admin/` 下一层的单段路径（如 `/admin/user`），不匹配 `/admin/user/hello`；`/admin`、`/admin.do` 这类没有斜杠子段的路径同样不匹配。要覆盖整个前缀必须写 `/admin/**`。
- **Security 规则与 MVC 路由是两套匹配**：Spring Security 用请求匹配器（`antMatchers` 对应 `AntPathRequestMatcher`/`AntPathMatcher`）判断是否进入某条授权规则；Spring MVC 用 `RequestMappingHandlerMapping` 把类级 `@RequestMapping("/admin")` 与方法级 `/user/hello` 拼成 `/admin/user/hello` 并交给控制器。两套匹配对「层级」的理解不一致：Security 认为 `/admin/user/hello` 不在 `/admin/*` 内，MVC 认为它属于 `/admin` 控制器。
- **规则顺序决定后果**：Spring Security 按声明顺序匹配，前面的规则不命中就继续往后；若末尾是 `.anyRequest().permitAll()`（或无其它拦截），深层路径直接放行。即使末尾是 `authenticated()`，也只是要求登录而非管理员角色，仍构成垂直权限绕过。
- **根路由陷阱**：如果 `/admin` 本身没有直接映射（只有子路径映射），团队常只配 `/admin/*` 以为覆盖，实际深层接口全部漏保护；这是典型的配置语义错误，而非框架漏洞。

## 触发条件

- Spring Security 使用 `.antMatchers("/前缀/*")`（单 `*`）做保护，而非 `/前缀/**`。
- 应用存在 `/前缀/xxx/yyy` 形式的多级路由（类级 `@RequestMapping` + 方法级子路径）。
- 兜底规则为 `permitAll()` 或 `authenticated()`（后者仍可绕过角色限制）。
- 未额外使用 `mvcMatchers`/`MvcRequestMatcher` 或过滤器做二次校验。

## 利用步骤

1. 识别目标使用的 Spring Security 版本与配置风格（`antMatchers`/`mvcMatchers`/`requestMatchers`）。
2. 枚举受保护前缀下的深层路由：管理控制器常有类级 `@RequestMapping("/admin")`，方法级 `/user/hello`、`/user/list`、`/config` 等；结合静态资源、前端 JS、Swagger 与报错信息收集。
3. 构造请求 `GET /admin/<子路径>/<更深子路径>`（例如 `/admin/user/hello`），不带 Cookie 或使用低权限账号访问。
4. 若返回正常业务内容（而非 401/403/登录跳转），确认绕过；对写操作接口可进一步验证越权效果。

## PoC

```java
// 有缺陷的配置：单星号只匹配一层，anyRequest().permitAll() 兜底放行其余路径
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/admin/*").hasRole("ADMIN")
            .anyRequest().permitAll()
            .and().formLogin();
    }
}
```

```text
GET /admin/user/hello HTTP/1.1
Host: target
（无会话）

HTTP/1.1 200 OK
hello admin
```

`/admin/user/hello` 不匹配 `/admin/*`，落入 `anyRequest().permitAll()`，无需登录；而 `/admin/user` 会被拦截，可作为对照。

## 变体与关联

- **修复写法**：改为 `.antMatchers("/admin/**").hasRole("ADMIN")`；Spring Security 6 中 `requestMatchers("/admin/**")` 默认使用 `MvcRequestMatcher`，行为更贴近 MVC 路由，但仍需注意规则顺序。
- **同类语义陷阱**：`*.do`、`/api/*/user` 等单星号模式同样只覆盖单层；正则匹配器与 PathPattern 解析差异也可导致鉴权与路由不一致。
- **关联**：路径解析差异类绕过（`;`、编码、`..`、后缀）原理不同但常组合使用；见 [[web-generic-auth-hanvon-eface-whitelist-contains-semicolon-path-bypass]]、[[web-generic-auth-interceptor-login-prefix-dotdot-bypass]]。
- **兜底策略**：`anyRequest().permitAll()` 是放大因素；更安全的是默认拒绝（`anyRequest().denyAll()` 或 `authenticated()`）。

## 检测与防御

- **检测**：代码审计搜索 `antMatchers(`、`antMatcher(`、`requestMatchers(` 中出现单 `*` 且未 `/**` 的前缀规则，对照 Controller 映射检查是否存在更深层级；黑盒测试对受保护前缀逐层加路径段观察响应差异。
- **防御**：保护前缀一律使用 `/**`；使用 `mvcMatchers`/`MvcRequestMatcher` 或 PathPattern 保持与 MVC 路由一致的匹配语义；兜底采用默认拒绝；对管理接口增加方法级 `@PreAuthorize` 或过滤器二次校验；上线前用自动化用例验证未认证访问所有管理路由。
