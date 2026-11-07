---
id: web-generic-auth-tmall-adminpermissionfilter-contains-login-account-bypass
title: Tmall_demo AdminPermissionFilter 用 contains 放行 /admin/login 与 /admin/account，/admin/login/../../tmall/ 穿越未授权访问后台
type: scenario
domain: web
path: web/generic/auth
technique: filter-contains-login-path-context-dotdot-bypass
tags:
- java
- spring
- filter
- auth-bypass
- path-traversal
- uri-normalization
- whitelist
- tmall
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V240
  verified_at: '2026-11-07T10:34:13+08:00'
  notes: 对照原文 img/01-06：AdminPermissionFilter @WebFilter("/admin/*") 以 getRequestURI().contains("/admin/login")||contains("/admin/account") 放行；img/05 退出后直接访问 /tmall/admin/user 被跳登录，img/06 GET /admin/login/../../tmall/admin/user 返回后台用户列表。与 interceptor-login-prefix-dotdot-bypass（HandlerInterceptor+startsWith）、xiahuia LogCostFilter（/* 映射、/doc.html 放行串）差异成立。原文无版本信息。
url: /docs/web/generic/auth/web-generic-auth-tmall-adminpermissionfilter-contains-login-account-bypass/
draft: false
kb_aliases:
- Tmall_demo 鉴权绕过
- AdminPermissionFilter 绕过
- contains 放行登录接口
- /admin/login/../../ 穿越
- 天猫商城后台未授权
---

## 一句话结论

Tmall_demo 的 `AdminPermissionFilter`（`@WebFilter(urlPatterns={"/admin/*"})`）只要 `getRequestURI()` 中包含 `/admin/login` 或 `/admin/account` 就直接放行，未登录请求 `/admin/login/../../tmall/admin/user` 既让过滤器看到白名单子串，又经容器规范化（两个 `..` 退回根后再进入 `/tmall` 上下文）路由到受保护的 `/admin/user` 后台用户列表，直接读取全部用户信息。

## 原理

- 唯一的后台鉴权点在 `src/main/java/com/xq/tmall/filter/AdminPermissionFilter.java`：

  ```java
  @WebFilter(filterName = "adminPermissionFilter", urlPatterns = {"/admin/*"})
  public class AdminPermissionFilter implements Filter {
      @Override
      public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
              throws IOException, ServletException {
          HttpServletRequest servletRequest = (HttpServletRequest) request;
          // 如果是登录界面、登录态失效界面，直接放行
          if (servletRequest.getRequestURI().contains("/admin/login") ||
                  servletRequest.getRequestURI().contains("/admin/account")) {
              chain.doFilter(request, response);
          } else {
              Object o = servletRequest.getSession().getAttribute("adminId");
              if (o == null) {
                  request.getRequestDispatcher("/admin/login").forward(request, response);
              } else {
                  chain.doFilter(request, response);
              }
          }
      }
  }
  ```

- 过滤器的放行规则是**原始请求目标字符串的子串包含**，不是规范化后的路由匹配。开发者想放行登录页和账户相关页面，实际放行的是“URI 里任何位置出现 `/admin/login` 或 `/admin/account`”的请求。
- Tomcat 在映射到 Servlet/Controller 前会对请求路径做规范化：`/admin/login/../../tmall/admin/user` 中的两个 `..` 依次消去 `login` 和 `admin`，回到根 `/`，再拼上 `/tmall/admin/user`；应用上下文正是 `/tmall`，规范化后上下文内路径为 `/admin/user`，命中后台用户管理 Controller。
- 过滤器 pattern `/admin/*` 也按上下文内路径匹配 `/admin/user`，因此过滤链会执行；但它看到的 `getRequestURI()` 仍包含 `/admin/login`（原文实测行为），于是走 `chain.doFilter`，跳过 session 里的 `adminId` 判空。
- 受保护的 `/admin/user` Controller 自身不再校验登录/角色，只依赖这个 Filter，因此未登录即可拿到用户列表（用户名、昵称、姓名、出生日期、性别等）。
- 关键点不是“随机路径穿越”，而是**放行判断与路由规范化使用了不同的路径表示**：`contains` 命中的是未规范化的原始目标，真正被路由的是规范化后的路径。两个 `..` 还有一个作用是把请求从上下文外部带回 `/tmall` 上下文，属于跨上下文前缀的构造；`/admin/account` 同样可作为放行子串。

## 触发条件

- 目标为 Tmall_demo（Spring Boot + 内嵌 Tomcat，前台 `/tmall`，后台 `/tmall/admin`）。
- `AdminPermissionFilter` 是后台唯一鉴权手段，`/admin/*` 下的 Controller 不再二次校验 session/角色。
- 放行规则用 `getRequestURI()` 做 `contains`/`startsWith` 等字符串判断，且放行串是 `/admin/login`、`/admin/account` 这类可直接出现在路径中间的片段。
- 容器会对 `..` 做规范化，且规范化后的路径能命中受保护接口（本例为 `/tmall/admin/user`）。

## 利用步骤

1. 正常登录后台，访问“用户管理”，抓取 `GET /tmall/admin/user` 确认接口返回用户列表；退出登录后再次直接访问，确认被跳转到登录页。
2. 构造 `GET /admin/login/../../tmall/admin/user`：`/admin/login` 满足 Filter 的 `contains` 放行；两个 `..` 让规范化路径变成 `/tmall/admin/user`。
3. 带上任意有效或过期的 JSESSIONID（无需 `adminId`），发送请求；若返回用户列表则绕过成功。
4. 把同一前缀套到其它后台接口：`/admin/login/../../tmall/admin/<功能路径>`；若目标接口有参数，照常附带。
5. 若 `/admin/login` 被其它规则拦截，换用放行串 `/admin/account`，即 `/admin/account/../../tmall/admin/<功能路径>`；也可尝试 `..;/`、`%2e%2e` 等容器变体。

## PoC

```http
GET /admin/login/../../tmall/admin/user HTTP/1.1
Host: 127.0.0.1:8080
Cookie: JSESSIONID=<未登录或已退出的会话>
```

```text
# 原文实测：返回 200 及后台用户管理页面，包含 a120/MRJIANG/test/test01/admin 等用户记录；
# 对照：直接 GET /tmall/admin/user 会被 forward 到 /admin/login。
```

`/admin/account` 变体：

```http
GET /admin/account/../../tmall/admin/user HTTP/1.1
Host: 127.0.0.1:8080
```

## 变体与关联

- 放行串变体：`contains("/admin/login")` 与 `contains("/admin/account")` 是两个独立入口，任一命中即可放行；若开发者只删除其中一个，另一个仍可利用。
- 路径变体：`..;/`、`%2e%2e/`、`//`、尾部 `/` 等取决于 Tomcat 版本与 `StrictHttpFirewall` 配置；本例跨上下文需要两级 `..`，少一级只会落到 `/admin/user` 之外的路径。
- 关联：[[web-generic-auth-interceptor-login-prefix-dotdot-bypass]]（同为“登录前缀 + `..`”，但该卡是 Spring `HandlerInterceptor` + `startsWith` 排除式规则、同级 `/admin/login/../article/delete`，没有跨上下文构造）；[[web-generic-auth-xiahuia-erp-logcostfilter-contains-path-bypass]]（同为 Filter + `contains`，但放行串是 `/doc.html` 等静态/文档路径，利用面是用户列表/重置密码/删除用户）。
- 关联：[[web-generic-auth-403-resource-suffix-path-dictionary-bypass]]（静态后缀与路径规范化差异的通用总结）。
- 边界：若 Filter 改用规范化后的 `getServletPath()`、或后台 Controller 在方法层再次校验 `adminId`/角色、或容器直接拒绝含 `..` 的请求，绕过不成立。

## 检测与防御

- 修复：不要用 `getRequestURI()` 的 `contains`/`startsWith` 做鉴权；使用 Spring Security 的 `MvcRequestMatcher`、`AntPathMatcher` 或规范化后的 `servletPath` 做精确路由匹配。
- 修复：放行登录页应使用精确路径与 HTTP 方法，不能用“包含登录串就放行”的排除式规则；对路径先解码、去 `;` 参数、解析 `.`/`..`、折叠 `//`，无法规范化就拒绝。
- 修复：后台敏感接口在 Controller/Service 层再次校验 `adminId` 与角色，避免单点 Filter 失效即全盘失守。
- 加固：启用 `StrictHttpFirewall`，拒绝 `;`、`%2e`、`//`、反斜杠与编码后的 `..`。
- 检测：请求路径同时包含 `/admin/login`/`/admin/account` 与 `..`、`;`、`%2e`、`//`；未登录会话访问 `/admin/*` 敏感接口返回 200；同一接口正常路径跳登录而变体返回业务数据。
